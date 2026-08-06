// PostgreSQL-backed ReceiveLandingStore.
//
// One DB-TX for the landing; the receiver lease stays held.
// Schema: src/schema/receive-external-landing.sql.
//
// DRIVER-AGNOSTIC: never imports `pg`. The composition root injects an executor that can run
// multi-statement transactions (PoolClient or a test double).
//
// Atomicity: BEGIN → guarded status CAS → proof-header INSERT → ordered path INSERTs →
// event INSERT → lease presence check → signed dual-chain append → COMMIT. Any failure rolls
// back. The deferred path-completeness constraint fires at COMMIT, so a short or broken path
// aborts the whole transaction rather than leaving a landing without its evidence.
//
// the slice-local `receive_landing_events` row is NOT the authoritative event. The
// node-global `node_events` chain and the tenant `implementer_events` chain are what signed
// pull and SSE consumers read, so `receive.landed` is appended to both here, on this
// same transaction. Until this existed a receive could sit durably RECEIVE_LANDED
// while no consumer ever saw an authoritative terminal event — the Byte-exact hole this store closes.
//
// The dual-chain append is the LAST statement before COMMIT deliberately: it takes the
// node-global seq counter row lock, which serializes every concurrent append on this node, so
// it is held for the shortest possible slice of the transaction. Same transaction is what
// makes it atomic; last position is only what makes it cheap.
//
// There is no code path here that DELETEs, UPDATEs or re-INSERTs wallet_active_leases: the
// receiver lease row is byte-identical across the transition.

import {
  appendTerminalLandedEvent,
  type DualChainEventQuota,
  type NodeEventSigner,
} from "../event-log/dual-chain-appender.js";

import {
  RECEIVE_LANDED_EVENT,
  RECEIVE_LANDED_STATUS,
  RECEIVER_PATH_ROLE,
  LANDED_VERIFIED_PHASE,
  SETTLED_BODY_PERSISTED_PHASE,
  type CommitReceiveLandingCommand,
  type ReceiveLandingConflictReason,
  type ReceiveLandingStore,
} from "./landing-commit.js";
import type { SqlExecutor, SqlTxFactory } from "./sql-store.js";

/** Raised by the deferred completeness trigger in receive-external-landing.sql. */
export const PATH_INCOMPLETE_MESSAGES = [
  "RECEIVE_LANDING_PATH_HEADER_MISSING",
  "RECEIVE_LANDING_PATH_INCOMPLETE",
  "RECEIVE_LANDING_PATH_NOT_CONTIGUOUS",
  "RECEIVE_LANDING_PATH_EXPECTED_ANCHOR_MISMATCH",
  "RECEIVE_LANDING_PATH_HEAD_ANCHOR_MISMATCH",
  "RECEIVE_LANDING_PATH_BACKLINK_BROKEN",
] as const;

export const SQLSTATE_UNIQUE_VIOLATION = "23505";
export const RECEIVE_LANDED_EVENT_UNIQUE_INDEX = "receive_landing_events_one_per_operation";

export const RECEIVE_LANDING_STATEMENTS = {
  // The CAS: status AND row_version must both still be what the caller read (step 4's
  // row_version discipline, applied to the transition). A concurrent land bumps
  // row_version, so the loser matches zero rows even inside the same status.
  // terminal_at is stamped at commit time; the operations CHECK requires terminal_at >= created_at,
  // and a landed_at supplied by a caller's clock carries no such guarantee.
  // node_id / implementer_id / receiver_wallet_id come back from the CAS itself rather than a
  // second SELECT: the dual-chain append below must be scoped to exactly the row this
  // statement transitioned, and a separate read could observe a different one.
  UPDATE_STATUS:
    "UPDATE operations SET status = $2, " +
    "row_version = row_version + 1, " +
    "terminal_observation_id = $3::uuid, " +
    "verification_material_available_until = to_timestamp($4 / 1000.0), " +
    "terminal_at = now(), updated_at = now() " +
    "WHERE id = $1::uuid AND kind = 'RECEIVE_EXTERNAL' " +
    "AND status = $5 AND row_version = $6::bigint " +
    "RETURNING id, row_version, node_id::text AS node_id, " +
    "implementer_id::text AS implementer_id, " +
    "receiver_wallet_id::text AS receiver_wallet_id",

  INSERT_PROOF:
    "INSERT INTO receive_landing_proofs (" +
    "operation_id, attempt_phase, public_execution_phase, path_role, wallet_public_key, " +
    "t0_observation_id, fresh_head_observation_id, terminal_observation_id, " +
    "expected_completed_transaction_sha256, fresh_head_completed_transaction_sha256, " +
    "verdict, body_count, path_depth, path_manifest_text, path_manifest_sha256, " +
    "landed_at, verification_material_available_until" +
    ") VALUES (" +
    "$1::uuid, $2, $3, $4, $5, $6::uuid, $7::uuid, $8::uuid, $9, $10, $11, " +
    "$12::bigint, $13::bigint, $14, $15, to_timestamp($16 / 1000.0), to_timestamp($17 / 1000.0)" +
    ") RETURNING operation_id",

  INSERT_PATH_BODY:
    "INSERT INTO receive_landing_path_bodies (" +
    "operation_id, path_index, source_kind, completed_transaction_text, " +
    "completed_transaction_sha256, completed_transaction_octets, wallet_role, " +
    "s_signature, p_signature, b_amount, inner_preimage_text, inner_sha256, " +
    "step_1_signature, step_2_signature" +
    ") VALUES (" +
    "$1::uuid, $2::bigint, $3, $4, $5, $6::bigint, $7, $8, $9, $10, $11, $12, $13, $14" +
    ") RETURNING path_index",

  INSERT_EVENT:
    "INSERT INTO receive_landing_events (" +
    "operation_id, event_type, terminal_observation_id, landed_at, data_text" +
    ") VALUES ($1::uuid, $2, $3::uuid, to_timestamp($4 / 1000.0), $5) " +
    "RETURNING operation_id",

  // Presence check only — never DELETE / UPDATE / re-INSERT the lease.
  SELECT_LEASE:
    "SELECT wallet_id FROM wallet_active_leases WHERE wallet_id = " +
    "(SELECT receiver_wallet_id FROM operations WHERE id = $1::uuid)",

  SELECT_CURRENT_STATUS: "SELECT status FROM operations WHERE id = $1::uuid",

  // keep admission-table status in lockstep with operations on land so
  // receive_operations is not left READY after RECEIVE_LANDED (GET join + diagnostics).
  SYNC_RECEIVE_OPERATIONS_LANDED:
    "UPDATE receive_operations SET status = 'RECEIVE_LANDED' " +
    "WHERE operation_id = $1::uuid AND status = 'READY'",
} as const;

interface StatusRow {
  readonly id: string;
  readonly row_version: string;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly receiver_wallet_id: string | null;
}

/** Map a driver error to the conflict reason it represents, or null when it is not ours. */
export function classifyLandingError(error: unknown): ReceiveLandingConflictReason | null {
  const message = error instanceof Error ? error.message : String(error);
  const code = (error as { code?: unknown } | null)?.code;
  if (code === SQLSTATE_UNIQUE_VIOLATION && message.includes(RECEIVE_LANDED_EVENT_UNIQUE_INDEX)) {
    return "ALREADY_LANDED";
  }
  if (PATH_INCOMPLETE_MESSAGES.some((marker) => message.includes(marker))) {
    return "PATH_INCOMPLETE";
  }
  return null;
}

class LeaseMissingError extends Error {
  constructor(operationId: string) {
    super(`receiver lease missing for operation ${operationId} during landing commit`);
    this.name = "LeaseMissingError";
  }
}

export class SqlReceiveLandingStore implements ReceiveLandingStore {
  /**
   * `signer` is required, not optional: a landing that cannot be proved must not commit
   * (Byte-exact). A node with no EVENT_SIGNING key has no business landing money, which is why
   * there is no "append if we can" branch anywhere below.
   */
  constructor(
    private readonly txFactory: SqlTxFactory,
    private readonly signer: NodeEventSigner,
    private readonly quota?: DualChainEventQuota,
  ) {}

  async commitLanding(command: CommitReceiveLandingCommand): Promise<{
    readonly applied: boolean;
    readonly reason?: ReceiveLandingConflictReason;
    readonly receiverLeaseStillHeld: boolean;
  }> {
    const { proof, path, event } = command;

    return this.txFactory
      .withTransaction(async (tx: SqlExecutor) => {
        // 1. Guarded CAS. The database is the arbiter; a loser matches zero rows.
        const updated = await tx.query<StatusRow>(RECEIVE_LANDING_STATEMENTS.UPDATE_STATUS, [
          command.operationId,
          RECEIVE_LANDED_STATUS,
          proof.terminalObservationId,
          proof.verificationMaterialAvailableUntilMs,
          command.expectedStatus,
          command.expectedRowVersion,
        ]);
        if (updated.rows.length === 0) {
          const current = await tx.query<{ status: string }>(
            RECEIVE_LANDING_STATEMENTS.SELECT_CURRENT_STATUS,
            [command.operationId],
          );
          const status = current.rows[0]?.status;
          return {
            applied: false,
            reason:
              status === RECEIVE_LANDED_STATUS
                ? ("ALREADY_LANDED" as const)
                : ("STATUS_GUARD_MISMATCH" as const),
            receiverLeaseStillHeld: true,
          };
        }

        // 2. Proof header at SETTLED_BODY_PERSISTED / LANDED_VERIFIED.
        await tx.query(RECEIVE_LANDING_STATEMENTS.INSERT_PROOF, [
          proof.operationId,
          SETTLED_BODY_PERSISTED_PHASE,
          LANDED_VERIFIED_PHASE,
          RECEIVER_PATH_ROLE,
          proof.walletPublicKey,
          proof.t0ObservationId,
          proof.freshHeadObservationId,
          proof.terminalObservationId,
          proof.expectedCompletedTransactionSha256,
          proof.freshHeadCompletedTransactionSha256,
          proof.verdict,
          proof.bodyCount,
          proof.pathDepth,
          proof.pathManifestText,
          proof.pathManifestSha256,
          proof.landedAtMs,
          proof.verificationMaterialAvailableUntilMs,
        ]);

        // 3. The full ordered path, one row per hop. Completeness is re-checked by the
        // deferred constraint trigger at COMMIT, not here.
        for (const body of path) {
          await tx.query(RECEIVE_LANDING_STATEMENTS.INSERT_PATH_BODY, [
            proof.operationId,
            body.pathIndex,
            body.sourceKind,
            body.completedTransactionText,
            body.completedTransactionSha256,
            body.completedTransactionOctets,
            body.walletRole,
            body.sSignature,
            body.pSignature,
            body.bAmount,
            body.innerPreimageText,
            body.innerSha256,
            body.step1Signature,
            body.step2Signature,
          ]);
        }

        // 4. Append receive.landed.
        await tx.query(RECEIVE_LANDING_STATEMENTS.INSERT_EVENT, [
          event.operationId,
          RECEIVE_LANDED_EVENT,
          event.terminalObservationId,
          event.landedAtMs,
          event.dataText,
        ]);

        // 5. The receiver lease must still be present — never released by this path.
        const lease = await tx.query<{ wallet_id: string }>(
          RECEIVE_LANDING_STATEMENTS.SELECT_LEASE,
          [command.operationId],
        );
        if (lease.rows.length === 0) {
          // Abort the whole TX: a land without a held lease is a custody breach.
          throw new LeaseMissingError(command.operationId);
        }

        // 5b. mirror RECEIVE_LANDED onto receive_operations (admission status).
        await tx.query(RECEIVE_LANDING_STATEMENTS.SYNC_RECEIVE_OPERATIONS_LANDED, [
          command.operationId,
        ]);

        // 6. The authoritative terminal event, on both signed chains, on THIS transaction.
        // `event.dataText` is the payload the caller already built and the
        // slice-local row above already stored — it crosses this seam verbatim so both
        // surfaces digest byte-identical data (the byte-exact signing rule).
        const landed = updated.rows[0]!;
        await appendTerminalLandedEvent(
          async (text, values) => (await tx.query<Record<string, unknown>>(text, values)).rows,
          {
            nodeId: landed.node_id,
            implementerId: landed.implementer_id,
            operationId: command.operationId,
            walletId: landed.receiver_wallet_id,
            eventType: RECEIVE_LANDED_EVENT,
            dataText: event.dataText,
            createdAt: new Date(event.landedAtMs).toISOString(),
            signer: this.signer,
            ...(this.quota !== undefined ? { quota: this.quota } : {}),
          },
        );

        return { applied: true, receiverLeaseStillHeld: true };
      })
      .catch((err: unknown) => {
        if (err instanceof LeaseMissingError) {
          return { applied: false, reason: "LEASE_MISSING" as const, receiverLeaseStillHeld: false };
        }
        const classified = classifyLandingError(err);
        if (classified !== null) {
          return { applied: false, reason: classified, receiverLeaseStillHeld: true };
        }
        throw err;
      });
  }
}

/** In-memory store for unit tests — same atomicity semantics, no sockets. */
export class InMemoryReceiveLandingStore implements ReceiveLandingStore {
  readonly operations = new Map<
    string,
    {
      status: string;
      rowVersion: number;
      receiverWalletId: string;
      terminalObservationId: string | null;
      verificationMaterialAvailableUntilMs: number | null;
    }
  >();
  readonly leases = new Set<string>();
  readonly proofs: CommitReceiveLandingCommand["proof"][] = [];
  readonly pathBodies: CommitReceiveLandingCommand["path"][] = [];
  readonly events: CommitReceiveLandingCommand["event"][] = [];
  /** When true, commitLanding simulates a store that illegally drops the receiver lease. */
  releaseLeaseOnLand = false;

  seed(
    operationId: string,
    status: string,
    receiverWalletId: string,
    rowVersion = 1,
    leaseHeld = true,
  ): void {
    this.operations.set(operationId, {
      status,
      rowVersion,
      receiverWalletId,
      terminalObservationId: null,
      verificationMaterialAvailableUntilMs: null,
    });
    if (leaseHeld) this.leases.add(receiverWalletId);
  }

  async commitLanding(command: CommitReceiveLandingCommand): Promise<{
    readonly applied: boolean;
    readonly reason?: ReceiveLandingConflictReason;
    readonly receiverLeaseStillHeld: boolean;
  }> {
    const op = this.operations.get(command.operationId);
    if (op === undefined) {
      return { applied: false, reason: "STATUS_GUARD_MISMATCH", receiverLeaseStillHeld: true };
    }
    if (op.status === RECEIVE_LANDED_STATUS) {
      return { applied: false, reason: "ALREADY_LANDED", receiverLeaseStillHeld: true };
    }
    if (op.status !== command.expectedStatus || op.rowVersion !== command.expectedRowVersion) {
      return { applied: false, reason: "STATUS_GUARD_MISMATCH", receiverLeaseStillHeld: true };
    }
    // The deferred completeness trigger, in memory: a path shorter than the header declares
    // never commits.
    if (command.path.length !== command.proof.bodyCount) {
      return { applied: false, reason: "PATH_INCOMPLETE", receiverLeaseStillHeld: true };
    }
    if (!this.leases.has(op.receiverWalletId)) {
      return { applied: false, reason: "LEASE_MISSING", receiverLeaseStillHeld: false };
    }

    // Atomic: all mutations below succeed together or not at all (single-threaded store).
    op.status = RECEIVE_LANDED_STATUS;
    op.rowVersion += 1;
    op.terminalObservationId = command.proof.terminalObservationId;
    op.verificationMaterialAvailableUntilMs = command.proof.verificationMaterialAvailableUntilMs;
    this.proofs.push(command.proof);
    this.pathBodies.push(command.path);
    this.events.push(command.event);

    if (this.releaseLeaseOnLand) {
      this.leases.delete(op.receiverWalletId);
      return { applied: true, receiverLeaseStillHeld: false };
    }
    return { applied: true, receiverLeaseStillHeld: true };
  }
}
