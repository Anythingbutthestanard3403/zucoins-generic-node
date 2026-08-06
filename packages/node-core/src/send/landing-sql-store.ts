// PostgreSQL-backed ExternalSendLandingStore.
//
// schema: src/schema/send-external-landing.sql.
//
// DRIVER-AGNOSTIC: never imports `pg`. The composition root injects an executor that
// can run multi-statement transactions (PoolClient or a test double).
//
// Atomicity: BEGIN → status UPDATE (guarded) → landing INSERT → event INSERT →
// lease presence check → signed dual-chain append → COMMIT. Any failure rolls back. There is
// no code path that DELETEs or UPDATEs wallet_active_leases.
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

import {
  appendTerminalLandedEvent,
  type DualChainEventQuota,
  type NodeEventSigner,
} from "../event-log/dual-chain-appender.js";

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
} as const;

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

      // 4. Lease must still be present — never released by this path.
      const lease = await tx.query<{ wallet_id: string }>(LANDING_STATEMENTS.SELECT_LEASE, [
        command.operationId,
      ]);
      if (lease.rows.length === 0) {
        // Abort the whole TX: a land without a held lease is a custody breach.
        throw new LeaseMissingError(command.operationId);
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
        sourceLeaseStillHeld: true,
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
    }
  >();
  readonly leases = new Set<string>();
  readonly records: ExternalSendLandingRecord[] = [];
  readonly events: ExternalSendLandedEvent[] = [];
  /** When true, commitLanding simulates a store that illegally drops the lease. */
  releaseLeaseOnLand = false;

  seed(
    operationId: string,
    status: "AWAITING_REDEMPTION" | "NEEDS_ATTENTION" | "EXTERNAL_SEND_LANDED" | "CREATED",
    sourceWalletId: string,
    leaseHeld = true,
  ): void {
    this.operations.set(operationId, {
      status,
      sourceWalletId,
      verificationMaterialAvailableUntilMs: null,
      landedAtMs: null,
      terminalObservationId: null,
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

    if (this.releaseLeaseOnLand) {
      this.leases.delete(op.sourceWalletId);
      return { applied: true, record, event, sourceLeaseStillHeld: false };
    }

    return { applied: true, record, event, sourceLeaseStillHeld: true };
  }
}
