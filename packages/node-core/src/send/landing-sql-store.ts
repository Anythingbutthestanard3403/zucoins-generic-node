// PostgreSQL-backed ExternalSendLandingStore.
//
// schema: src/schema/send-external-landing.sql.
//
// DRIVER-AGNOSTIC: never imports `pg`. The composition root injects an executor that
// can run multi-statement transactions (PoolClient or a test double).
//
// Atomicity: BEGIN → status UPDATE (guarded) → landing INSERT → event INSERT →
// lease presence check → (optional NODE_VERIFIED release) → signed dual-chain append →
// COMMIT. Any failure rolls back. INDEPENDENT keeps the source lease held; NODE_VERIFIED
// mints EXTERNAL_SEND_LANDED proof + releaseLease in the same TX (ZTR-1304).
//
// `external_send_landing_events` is a slice-local record, not the authoritative
// event. Signed pull (09-operations-recovery.md) and SSE consumers read `node_events` and the
// tenant `implementer_events` chain, so `external_send.landed` is appended to both here, on
// this same transaction ("appended in the same
// transaction"). Without it a send could sit durably EXTERNAL_SEND_LANDED while no consumer
// ever saw an authoritative terminal event — the Byte-exact hole this store closes.
//
// The dual-chain append is the LAST statement before COMMIT deliberately: it takes the
// node-global seq counter row lock, which serializes every concurrent append on this node, so
// it is held for the shortest possible slice of the transaction. Same transaction is what
// makes it atomic; last position is only what makes it cheap.

import { createHash, randomUUID } from "node:crypto";

import { RELEASED_NODE_VERIFIED } from "@zucoins/generic-node-contracts/operations";

import {
  appendTerminalLandedEvent,
  type DualChainEventQuota,
  type NodeEventSigner,
} from "../event-log/dual-chain-appender.js";
import {
  completeGroupOperation,
  mintReleaseProof,
  releaseLease,
} from "../leases/repository.js";

import type { SqlExecutor } from "./sql-store.js";
import {
  EXTERNAL_SEND_LANDED_EVENT,
  EXTERNAL_SEND_LANDED_STATUS,
  LANDED_VERIFIED_PHASE,
  SETTLED_BODY_PERSISTED_PHASE,
  buildLandedEvent,
  buildLandingRecord,
  type CommitExternalSendLandingCommand,
  type ExternalSendLandingStore,
  type ExternalSendLandedEvent,
  type ExternalSendLandingRecord,
} from "./landing-commit.js";

/** Executor that can open a transaction. PoolClient satisfies this; Pool does not. */
export interface SqlTxExecutor extends SqlExecutor {
  query<R>(text: string, params?: readonly unknown[]): Promise<{ rows: R[] }>;
}

export interface SqlTxFactory {
  /** Run `fn` inside BEGIN/COMMIT; ROLLBACK on throw. */
  withTransaction<T>(fn: (tx: SqlTxExecutor) => Promise<T>): Promise<T>;
}

export const LANDING_STATEMENTS = {
  // Status guard: only AWAITING_REDEMPTION or NEEDS_ATTENTION may land, and only when
  // the caller-expected entry status matches (both entry points are legal; the CAS is
  // on the specific status the verifier observed so a concurrent NEEDS_ATTENTION park
  // cannot race an AWAITING_REDEMPTION land without the store seeing it).
  // attention_required and attention_reason clear together (co-presence CHECK;
  // send-external-expiry.sql enforces the same on send_operations).
  UPDATE_STATUS:
    "UPDATE send_operations SET status = $2, attention_required = false, " +
    "attention_reason = NULL, " +
    "row_version = row_version + 1, " +
    "verification_material_available_until = to_timestamp($3 / 1000.0), " +
    "landed_at = to_timestamp($4 / 1000.0), " +
    "terminal_observation_id = $5::uuid " +
    "WHERE operation_id = $1::uuid AND status = $6 " +
    // node_id / implementer_id / source_wallet_id come back from the CAS itself rather than a
    // second SELECT: the dual-chain append below must be scoped to exactly the row this
    // statement transitioned, and a separate read could observe a different one.
    "RETURNING operation_id, status, node_id::text AS node_id, " +
    "implementer_id::text AS implementer_id, " +
    "source_wallet_id::text AS source_wallet_id",

  INSERT_LANDING_RECORD:
    "INSERT INTO external_send_landing_records (" +
    "operation_id, attempt_phase, public_execution_phase, " +
    "completed_transaction_text, completed_transaction_sha256, " +
    "terminal_observation_id, source_path_kind, source_path_depth, " +
    "landed_at, verification_material_available_until, entry_status" +
    ") VALUES (" +
    "$1::uuid, $2, $3, $4, $5, $6::uuid, $7, $8, " +
    "to_timestamp($9 / 1000.0), to_timestamp($10 / 1000.0), $11" +
    ") RETURNING operation_id",

  INSERT_EVENT:
    "INSERT INTO external_send_landing_events (" +
    "operation_id, event_type, terminal_observation_id, landed_at, data_text" +
    ") VALUES ($1::uuid, $2, $3::uuid, to_timestamp($4 / 1000.0), $5) " +
    "RETURNING operation_id",

  // Presence check only — never DELETE / UPDATE the lease.
  // B3/One-in-flight: bind the persisted sign-intent's lease_group_id + lease_epoch, not just the
  // wallet row. A lease row that does not match the exact group+epoch the send was formed
  // under is a different lease (a takeover or a stale epoch) and must abort the landing.
  SELECT_LEASE:
    "SELECT l.wallet_id FROM wallet_active_leases l " +
    "JOIN external_send_sign_intents i ON i.operation_id = $1::uuid " +
    "WHERE l.wallet_id = i.source_wallet_id " +
    "AND l.lease_group_id = i.lease_group_id " +
    "AND l.lease_epoch = i.lease_epoch",

  SELECT_ALREADY_LANDED:
    "SELECT status FROM send_operations WHERE operation_id = $1::uuid",

  // Mode + lease-group identity for the ZTR-1304 release branch. Read after CAS so we
  // observe the same row the status transition locked. Prefer operations.verification_mode
  // (universal mirror) joined to the active SEND_SOURCE lease for this operation.
  LOAD_RELEASE_CONTEXT:
    "SELECT o.verification_mode::text AS verification_mode, " +
    "o.source_wallet_id::text AS source_wallet_id, " +
    "l.membership_id::text AS membership_id, " +
    "l.lease_group_id::text AS lease_group_id, " +
    "l.lease_epoch::text AS lease_epoch, " +
    "l.owner_instance_id::text AS owner_instance_id " +
    "FROM operations o " +
    "JOIN wallet_active_leases l " +
    "  ON l.wallet_id = o.source_wallet_id AND l.operation_id = o.id " +
    "WHERE o.id = $1::uuid AND o.kind = 'SEND_EXTERNAL'",

  // Forensic stamp on receive_release_status (shared column; RELEASED_NODE_VERIFIED admitted).
  // operations.status is still the pre-land entry status here: the composition root
  // mirrors EXTERNAL_SEND_LANDED from send_operations AFTER this store returns. Stamp
  // only on receive_release_status IS NULL so the forensic mark co-commits with release.
  SET_RELEASE_STATUS_NODE_VERIFIED:
    "UPDATE operations SET receive_release_status = $2, " +
    "row_version = row_version + 1, updated_at = now() " +
    "WHERE id = $1::uuid " +
    "AND kind = 'SEND_EXTERNAL' " +
    "AND receive_release_status IS NULL " +
    "RETURNING receive_release_status",
} as const;

/** Forensic release_reason on wallet_lease_memberships for NODE_VERIFIED send landing close. */
export const NODE_VERIFIED_SEND_LANDING_RELEASE_REASON = "NODE_VERIFIED_LANDING" as const;

/**
 * Byte-stable proof digest for NODE_VERIFIED send landing release. Same injection-safe
 * length-prefixed shape as receive's computeNodeVerifiedLandingReleaseDigest (nvland1).
 */
export function computeNodeVerifiedSendLandingReleaseDigest(fields: {
  readonly operationId: string;
  readonly walletId: string;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: bigint;
  readonly terminalObservationId: string;
}): string {
  const field = (value: string): string =>
    `${new TextEncoder().encode(value).length}:${value}`;
  const text =
    field(fields.operationId) +
    field(fields.walletId) +
    field(fields.membershipId) +
    field(fields.leaseGroupId) +
    field(fields.leaseEpoch.toString()) +
    field(fields.terminalObservationId);
  return createHash("sha256").update(`nvland1:${text}`, "utf8").digest("hex");
}

interface SendReleaseContextRow {
  readonly verification_mode: string;
  readonly source_wallet_id: string;
  readonly membership_id: string;
  readonly lease_group_id: string;
  readonly lease_epoch: string;
  readonly owner_instance_id: string;
}

interface StatusRow {
  readonly operation_id: string;
  readonly status: string;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly source_wallet_id: string | null;
}

export class SqlExternalSendLandingStore implements ExternalSendLandingStore {
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

  async commitLanding(command: CommitExternalSendLandingCommand): Promise<{
    readonly applied: boolean;
    readonly reason?: "STATUS_GUARD_MISMATCH" | "ALREADY_LANDED" | "LEASE_MISSING";
    readonly record?: ExternalSendLandingRecord;
    readonly event?: ExternalSendLandedEvent;
    readonly sourceLeaseStillHeld: boolean;
  }> {
    const record = buildLandingRecord(command);
    const event = buildLandedEvent(command);

    return this.txFactory.withTransaction(async (tx) => {
      // 1. Status transition (guarded).
      const updated = await tx.query<StatusRow>(LANDING_STATEMENTS.UPDATE_STATUS, [
        command.operationId,
        EXTERNAL_SEND_LANDED_STATUS,
        record.verificationMaterialAvailableUntilMs,
        record.landedAtMs,
        command.terminalObservationId,
        command.expectedEntryStatus,
      ]);
      if (updated.rows.length === 0) {
        const current = await tx.query<{ status: string }>(LANDING_STATEMENTS.SELECT_ALREADY_LANDED, [
          command.operationId,
        ]);
        const status = current.rows[0]?.status;
        if (status === EXTERNAL_SEND_LANDED_STATUS) {
          return { applied: false, reason: "ALREADY_LANDED" as const, sourceLeaseStillHeld: true };
        }
        return {
          applied: false,
          reason: "STATUS_GUARD_MISMATCH" as const,
          sourceLeaseStillHeld: true,
        };
      }

      // 2. Settled body + terminal observation at SETTLED_BODY_PERSISTED / LANDED_VERIFIED.
      await tx.query(LANDING_STATEMENTS.INSERT_LANDING_RECORD, [
        record.operationId,
        SETTLED_BODY_PERSISTED_PHASE,
        LANDED_VERIFIED_PHASE,
        record.completedTransactionText,
        record.completedTransactionSha256,
        record.terminalObservationId,
        record.sourcePathKind,
        record.sourcePathDepth,
        record.landedAtMs,
        record.verificationMaterialAvailableUntilMs,
        record.entryStatus,
      ]);

      // 3. Append external_send.landed.
      await tx.query(LANDING_STATEMENTS.INSERT_EVENT, [
        event.operationId,
        EXTERNAL_SEND_LANDED_EVENT,
        event.terminalObservationId,
        event.landedAtMs,
        event.dataText,
      ]);

      // 4. Lease must still be present at land time (both modes).
      const lease = await tx.query<{ wallet_id: string }>(LANDING_STATEMENTS.SELECT_LEASE, [
        command.operationId,
      ]);
      if (lease.rows.length === 0) {
        // Abort the whole TX: a land without a held lease is a custody breach.
        throw new LeaseMissingError(command.operationId);
      }

      // 4b. NODE_VERIFIED → same-TX custody release (ZTR-1304).
      // INDEPENDENT never releases here. Park paths never reach this store.
      let sourceLeaseStillHeld = true;
      const ctx = await tx.query<SendReleaseContextRow>(
        LANDING_STATEMENTS.LOAD_RELEASE_CONTEXT,
        [command.operationId],
      );
      const releaseCtx = ctx.rows[0];
      if (releaseCtx !== undefined && releaseCtx.verification_mode === "NODE_VERIFIED") {
        const leaseEpoch = BigInt(releaseCtx.lease_epoch);
        const proofId = randomUUID();
        const proofDigest = computeNodeVerifiedSendLandingReleaseDigest({
          operationId: command.operationId,
          walletId: releaseCtx.source_wallet_id,
          membershipId: releaseCtx.membership_id,
          leaseGroupId: releaseCtx.lease_group_id,
          leaseEpoch,
          terminalObservationId: command.terminalObservationId,
        });
        await completeGroupOperation(tx, {
          leaseGroupId: releaseCtx.lease_group_id,
          operationId: command.operationId,
        });
        await mintReleaseProof(tx, {
          proofId,
          walletId: releaseCtx.source_wallet_id,
          operationId: command.operationId,
          membershipId: releaseCtx.membership_id,
          leaseGroupId: releaseCtx.lease_group_id,
          leaseEpoch,
          proofKind: "EXTERNAL_SEND_LANDED",
          proofDigest,
        });
        await releaseLease(tx, {
          walletId: releaseCtx.source_wallet_id,
          ownerInstanceId: releaseCtx.owner_instance_id,
          operationId: command.operationId,
          membershipId: releaseCtx.membership_id,
          leaseGroupId: releaseCtx.lease_group_id,
          leaseEpoch,
          releaseProofId: proofId,
          releaseReason: NODE_VERIFIED_SEND_LANDING_RELEASE_REASON,
        });
        const stamped = await tx.query<{ receive_release_status: string }>(
          LANDING_STATEMENTS.SET_RELEASE_STATUS_NODE_VERIFIED,
          [command.operationId, RELEASED_NODE_VERIFIED],
        );
        if (stamped.rows.length !== 1) {
          throw new Error(
            `NODE_VERIFIED send receive_release_status CAS failed: ${command.operationId}`,
          );
        }
        sourceLeaseStillHeld = false;
      }

      // 5. The authoritative terminal event, on both signed chains, on THIS transaction.
      // `event.dataText` is the payload buildLandedEvent already produced and the
      // slice-local row above already stored — it crosses this seam verbatim so both
      // surfaces digest byte-identical data (the byte-exact signing rule).
      const landed = updated.rows[0]!;
      await appendTerminalLandedEvent(
        async (text, values) => (await tx.query<Record<string, unknown>>(text, values)).rows,
        {
          nodeId: landed.node_id,
          implementerId: landed.implementer_id,
          operationId: command.operationId,
          walletId: landed.source_wallet_id,
          eventType: EXTERNAL_SEND_LANDED_EVENT,
          dataText: event.dataText,
          createdAt: new Date(event.landedAtMs).toISOString(),
          signer: this.signer,
          ...(this.quota !== undefined ? { quota: this.quota } : {}),
        },
      );

      return {
        applied: true,
        record,
        event,
        sourceLeaseStillHeld,
      };
    }).catch((err: unknown) => {
      if (err instanceof LeaseMissingError) {
        return {
          applied: false,
          reason: "LEASE_MISSING" as const,
          sourceLeaseStillHeld: false,
        };
      }
      throw err;
    });
  }
}

class LeaseMissingError extends Error {
  constructor(operationId: string) {
    super(`source lease missing for operation ${operationId} during landing commit`);
    this.name = "LeaseMissingError";
  }
}

/** In-memory store for unit tests — same atomicity semantics, no sockets. */
export class InMemoryExternalSendLandingStore implements ExternalSendLandingStore {
  readonly operations = new Map<
    string,
    {
      status: string;
      sourceWalletId: string;
      verificationMaterialAvailableUntilMs: number | null;
      landedAtMs: number | null;
      terminalObservationId: string | null;
      verificationMode: "INDEPENDENT" | "NODE_VERIFIED";
      receiveReleaseStatus: string | null;
    }
  >();
  readonly leases = new Set<string>();
  readonly records: ExternalSendLandingRecord[] = [];
  readonly events: ExternalSendLandedEvent[] = [];
  /**
   * When true, commitLanding simulates an illegal mid-commit lease drop that the
   * production store would never report as applied:true on INDEPENDENT. Kept for
   * negative unit coverage of accidental release.
   */
  releaseLeaseOnLand = false;

  seed(
    operationId: string,
    status: "AWAITING_REDEMPTION" | "NEEDS_ATTENTION" | "EXTERNAL_SEND_LANDED" | "CREATED",
    sourceWalletId: string,
    leaseHeld = true,
    opts: { readonly verificationMode?: "INDEPENDENT" | "NODE_VERIFIED" } = {},
  ): void {
    this.operations.set(operationId, {
      status,
      sourceWalletId,
      verificationMaterialAvailableUntilMs: null,
      landedAtMs: null,
      terminalObservationId: null,
      verificationMode: opts.verificationMode ?? "INDEPENDENT",
      receiveReleaseStatus: null,
    });
    if (leaseHeld) this.leases.add(sourceWalletId);
  }

  async commitLanding(command: CommitExternalSendLandingCommand): Promise<{
    readonly applied: boolean;
    readonly reason?: "STATUS_GUARD_MISMATCH" | "ALREADY_LANDED" | "LEASE_MISSING";
    readonly record?: ExternalSendLandingRecord;
    readonly event?: ExternalSendLandedEvent;
    readonly sourceLeaseStillHeld: boolean;
  }> {
    const op = this.operations.get(command.operationId);
    if (op === undefined) {
      return { applied: false, reason: "STATUS_GUARD_MISMATCH", sourceLeaseStillHeld: true };
    }
    if (op.status === EXTERNAL_SEND_LANDED_STATUS) {
      return { applied: false, reason: "ALREADY_LANDED", sourceLeaseStillHeld: true };
    }
    if (op.status !== command.expectedEntryStatus) {
      return { applied: false, reason: "STATUS_GUARD_MISMATCH", sourceLeaseStillHeld: true };
    }
    if (!this.leases.has(op.sourceWalletId)) {
      return { applied: false, reason: "LEASE_MISSING", sourceLeaseStillHeld: false };
    }

    const record = buildLandingRecord(command);
    const event = buildLandedEvent(command);

    // Atomic: all mutations below succeed together or not at all (single-threaded store).
    op.status = EXTERNAL_SEND_LANDED_STATUS;
    op.verificationMaterialAvailableUntilMs = record.verificationMaterialAvailableUntilMs;
    op.landedAtMs = record.landedAtMs;
    op.terminalObservationId = record.terminalObservationId;
    this.records.push(record);
    this.events.push(event);

    // Illegal drop wins for the negative unit path (simulates a broken INDEPENDENT store).
    if (this.releaseLeaseOnLand) {
      this.leases.delete(op.sourceWalletId);
      return { applied: true, record, event, sourceLeaseStillHeld: false };
    }

    // ZTR-1304: NODE_VERIFIED releases in the same commit.
    if (op.verificationMode === "NODE_VERIFIED") {
      this.leases.delete(op.sourceWalletId);
      op.receiveReleaseStatus = RELEASED_NODE_VERIFIED;
      return { applied: true, record, event, sourceLeaseStillHeld: false };
    }
    return { applied: true, record, event, sourceLeaseStillHeld: true };
  }
}
