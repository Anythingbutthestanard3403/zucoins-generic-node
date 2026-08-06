// DurableReportingRequestStore, the multi-process Postgres adapter for the
// ReportingRequestStore seam (packages/node-core/src/reporting/store.ts). It mirrors the
// in-memory reference adapter's outcomes, but the burn's atomicity comes from ONE short
// transaction whose AUTHORITY is the frozen reporting_lock_and_assert_admission function:
// the store calls that function and maps its errors to outcomes — it
// does NOT replicate the lock/recheck logic in TypeScript.
//
// The store is written against an injected ReportingQueryClient (pg-client.ts) so the money path
// is unit-testable without a socket; createPoolReportingClient wires the production pg Pool.

import { randomUUID } from "node:crypto";

import {
  ReportingStoreError,
  type BurnNonceOutcome,
  type BurnNonceRequest,
  type CommitMutationWithCompletedIdempotencyOutcome,
  type CompletedIdempotencyDraft,
  type CompletedIdempotencyRecord,
  type InsertCompletedIdempotencyOutcome,
  type ReportingAdmissionSnapshot,
  type ReportingMutationTx,
  type ReportingNonceEvidence,
  type ReportingRegistration,
  type ReportingRequestStore,
} from "@zucoins/node-core";
import type { Pool } from "pg";

import {
  isAdmissionStateError,
  isNoDataFound,
  isRestoreHoldMessage,
  isUniqueViolation,
  pgErrorConstraint,
  type ReportingQueryClient,
  type ReportingQueryFn,
} from "./pg-client.js";
import {
  mapAdmissionSnapshotRow,
  mapCompletedIdempotencyRow,
  mapNonceEvidenceRow,
  mapRegistrationRow,
  nonceEvidenceParams,
  NONCE_EVIDENCE_COLUMNS,
} from "./row-mappers.js";

// Auto-generated Postgres constraint names on the frozen reporting-persistence tables
// (0000_reporting_persistence.sql is byte-frozen, so these names are deterministic). Verified
// against a real migrated Postgres in durable-store.test.ts's real-PG suite. Postgres truncates
// generated names to 63 bytes — the idempotency-key guard loses its trailing "y" ("idempotenc"),
// so these MUST be read from the database, never guessed. A 23505 is discriminated by name: only
// the guards below are benign outcomes; every other unique violation surfaces.
const NONCE_REPLAY_GUARD = "reporting_request_nonces_node_id_implementer_id_nonce_key";
const IDEMPOTENCY_KEY_GUARD = "reporting_mutation_idempotenc_node_id_implementer_id_route__key";
const FINGERPRINT_GUARD = "reporting_mutation_guarded_fingerprint_uq";
// PK uniqueness on reporting_mutation_idempotency.id — race or reuse maps to CONFLICT (not 500).
const IDEMPOTENCY_PK_GUARD = "reporting_mutation_idempotency_pkey";
// A savepoint that scopes the burn-sequence allocation so a replay rolls it back (gapless).
const BURN_ALLOC_SAVEPOINT = "reporting_burn_alloc";

export class DurableReportingRequestStore implements ReportingRequestStore {
  constructor(private readonly client: ReportingQueryClient) {}

  findRegistration(nodeId: string, reportingKeyId: string): Promise<ReportingRegistration | null> {
    return this.runSingle(
      `SELECT id, node_id, implementer_id, public_key
         FROM implementer_reporting_keys
        WHERE node_id = $1 AND id = $2`,
      [nodeId, reportingKeyId],
      mapRegistrationRow,
    );
  }

  // The unlocked pre-burn snapshot. restore_hold defaults to true when the node has no
  // restore-state row (fail-closed, matching the reference adapter); a missing lifecycle head
  // yields null (nothing admitted). The presented key's state is its latest lifecycle state row.
  readAdmissionSnapshot(
    nodeId: string,
    implementerId: string,
    reportingKeyId: string,
  ): Promise<ReportingAdmissionSnapshot | null> {
    return this.runSingle(
      `SELECT
           COALESCE(rs.restore_hold, true) AS restore_hold,
           h.epoch,
           h.auth_hold,
           h.current_key_id,
           h.prior_key_id,
           h.overlap_expires_at,
           e.committed_at AS successor_committed_at,
           ks.state AS presented_key_state,
           ks.state_changed_at AS presented_key_state_changed_at
         FROM reporting_key_lifecycle_heads h
         LEFT JOIN reporting_restore_state rs ON rs.node_id = h.node_id
         LEFT JOIN reporting_key_lifecycle_events e ON e.id = h.lifecycle_event_id
         LEFT JOIN reporting_key_lifecycle_states ks ON ks.id = (
           SELECT s.id FROM reporting_key_lifecycle_states s
            WHERE s.node_id = h.node_id
              AND s.implementer_id = h.implementer_id
              AND s.reporting_key_id = $3
              AND s.lifecycle_epoch = (
                SELECT max(s2.lifecycle_epoch)
                  FROM reporting_key_lifecycle_states s2
                 WHERE s2.node_id = s.node_id
                   AND s2.implementer_id = s.implementer_id
                   AND s2.reporting_key_id = s.reporting_key_id
              )
            LIMIT 1
         )
        WHERE h.node_id = $1 AND h.implementer_id = $2`,
      [nodeId, implementerId, reportingKeyId],
      mapAdmissionSnapshotRow,
    );
  }

  // Advisory pre-burn replay peek; the burn's unique insert remains the authoritative guard.
  async peekNonceBurned(nodeId: string, implementerId: string, nonce: string): Promise<boolean> {
    const rows = await this.client.query(
      `SELECT 1 FROM reporting_request_nonces
        WHERE node_id = $1 AND implementer_id = $2 AND nonce = $3
        LIMIT 1`,
      [nodeId, implementerId, nonce],
    );
    return rows.length > 0;
  }

  burnNonceAtomically(request: BurnNonceRequest): Promise<BurnNonceOutcome> {
    const { evidence } = request;
    // Seed the node-wide burn counter outside the burn transaction: ON CONFLICT DO NOTHING makes
    // it idempotent, and doing it first keeps the short transaction below free of the seed write.
    return this.client
      .query(
        `INSERT INTO reporting_nonce_burn_counters (node_id)
         VALUES ($1)
         ON CONFLICT (node_id) DO NOTHING`,
        [evidence.nodeId],
      )
      .then(() => this.runBurn(request));
  }

  private runBurn(request: BurnNonceRequest): Promise<BurnNonceOutcome> {
    const { evidence } = request;
    return this.client.transact(async (query) => {
      // Existence probes for P0002 disambiguation only (NOT an admission recheck): the admission
      // function's SELECT..INTO STRICT raises no_data_found for either a missing restore-state
      // row (HOLD) or a missing lifecycle head (LIFECYCLE_RECHECK_FAILED), and the SQLSTATE alone
      // cannot say which. The function below remains the sole admission authority.
      const restoreExists = await rowExists(
        query,
        `SELECT 1 FROM reporting_restore_state WHERE node_id = $1`,
        [evidence.nodeId],
      );
      const headExists = await rowExists(
        query,
        `SELECT 1 FROM reporting_key_lifecycle_heads WHERE node_id = $1 AND implementer_id = $2`,
        [evidence.nodeId, evidence.implementerId],
      );

      try {
        await query(
          `SELECT reporting_lock_and_assert_admission($1, $2, $3, $4, $5)`,
          [
            evidence.nodeId,
            evidence.implementerId,
            request.expectedEpoch.toString(),
            evidence.reportingKeyId,
            new Date(evidence.receivedAtMs).toISOString(),
          ],
        );
      } catch (err) {
        if (isAdmissionStateError(err)) {
          return {
            kind: isRestoreHoldMessage(err) ? "HOLD" : "LIFECYCLE_RECHECK_FAILED",
          } as BurnNonceOutcome;
        }
        if (isNoDataFound(err)) {
          return { kind: restoreExists || !headExists ? "LIFECYCLE_RECHECK_FAILED" : "HOLD" };
        }
        throw err;
      }

      // Allocate the node-wide burn sequence inside a savepoint. On a replay (the nonce is
      // already burned) the sequence insert violates the replay guard; rolling back to this
      // savepoint un-does the increment so a replay consumes NO sequence value and the counter
      // stays gapless/contiguous (the counter table exists precisely
      // so a rolled-back allocation leaves no gap). This matches the in-memory reference adapter,
      // which decides REPLAY before it ever allocates.
      // ponytail: one SAVEPOINT per burn; fine — burns already serialize per node on the
      // admission FOR UPDATE, so this is not a throughput path.
      await query(`SAVEPOINT ${BURN_ALLOC_SAVEPOINT}`);
      const allocated = await query(
        `UPDATE reporting_nonce_burn_counters
            SET next_burn_sequence = next_burn_sequence + 1
          WHERE node_id = $1
          RETURNING next_burn_sequence - 1 AS nonce_burn_sequence`,
        [evidence.nodeId],
      );
      if (allocated.length === 0) {
        throw new ReportingStoreError("missing reporting nonce burn counter after seed");
      }
      const nonceBurnSequence = BigInt(String(allocated[0].nonce_burn_sequence));

      try {
        const rowId = randomUUID();
        const inserted = await query(
          buildNonceInsert(),
          nonceEvidenceParams(rowId, evidence, nonceBurnSequence),
        );
        const row = inserted[0];
        if (row === undefined) {
          throw new ReportingStoreError("nonce burn insert returned no row");
        }
        const burned: ReportingNonceEvidence = mapNonceEvidenceRow(row, evidence);
        return { kind: "BURNED", evidence: burned } as BurnNonceOutcome;
      } catch (err) {
        // Discriminate the 23505 by constraint. ONLY the replay guard
        // UNIQUE(node_id, implementer_id, nonce) is a benign REPLAY: roll the allocation back to
        // the savepoint (gapless) and return REPLAY. A 23505 on the sequence guard
        // UNIQUE(node_id, nonce_burn_sequence) — reachable on PITR / logical restore / counter
        // rewind — or any other constraint is a real money-path integrity failure: rethrow so
        // transact ROLLBACKs and the caller sees an error (never a false REPLAY).
        if (isUniqueViolation(err) && pgErrorConstraint(err) === NONCE_REPLAY_GUARD) {
          await query(`ROLLBACK TO SAVEPOINT ${BURN_ALLOC_SAVEPOINT}`);
          return { kind: "REPLAY" } as BurnNonceOutcome;
        }
        throw err;
      }
    });
  }

  findCompletedIdempotency(
    nodeId: string,
    implementerId: string,
    routeId: string,
    idempotencyKey: string,
  ): Promise<CompletedIdempotencyRecord | null> {
    return this.runSingle(
      `SELECT id, node_id, implementer_id, route_id, idempotency_key, reporting_nonce_id,
              child_record_id, method, raw_target, body_sha256, logical_fingerprint,
              response_status, response_bytes, completed_at
         FROM reporting_mutation_idempotency
        WHERE node_id = $1 AND implementer_id = $2 AND route_id = $3 AND idempotency_key = $4`,
      [nodeId, implementerId, routeId, idempotencyKey],
      mapCompletedIdempotencyRow,
    );
  }

  async insertCompletedIdempotency(
    record: CompletedIdempotencyRecord,
  ): Promise<InsertCompletedIdempotencyOutcome> {
    // Autocommit path retained for store-level tests and recovery tooling. The request path
    // uses commitMutationWithCompletedIdempotency so the child + parent share one transaction.
    return this.insertCompletedVia(this.client.query.bind(this.client), record);
  }

  // ONE Postgres transaction: persistChild then completed idempotency parent.
  // Deferred parent/child constraints fire at COMMIT. A throw rolls BOTH back
  // (together-or-neither). Nonce burn stays outside this transaction.
  // Benign CONFLICT is rethrown as a sentinel so createPoolReportingClient ROLLBACKs
  // (dropping the in-flight child) rather than COMMITting an aborted txn.
  async commitMutationWithCompletedIdempotency(input: {
    readonly persistChild: (
      tx: ReportingMutationTx,
      completedIdempotencyId: string,
    ) => Promise<string>;
    readonly record: CompletedIdempotencyDraft;
  }): Promise<CommitMutationWithCompletedIdempotencyOutcome> {
    try {
      return await this.client.transact(async (query) => {
        const tx: ReportingMutationTx = { query };
        const childRecordId = await input.persistChild(tx, input.record.id);
        if (childRecordId.length === 0) {
          throw new ReportingStoreError("persistChild returned an empty childRecordId");
        }
        const outcome = await this.insertCompletedVia(query, {
          ...input.record,
          childRecordId,
        });
        if (outcome.kind === "CONFLICT") {
          throw new IdempotencyConflictInTxError();
        }
        return { kind: "INSERTED" as const, childRecordId };
      });
    } catch (err) {
      if (err instanceof IdempotencyConflictInTxError) return { kind: "CONFLICT" };
      throw err;
    }
  }

  private async insertCompletedVia(
    query: ReportingQueryFn,
    record: CompletedIdempotencyRecord,
  ): Promise<InsertCompletedIdempotencyOutcome> {
    assertMandatoryCompletionFields(record);
    try {
      await query(
        `INSERT INTO reporting_mutation_idempotency
           (id, node_id, implementer_id, route_id, idempotency_key, reporting_nonce_id,
            child_record_id, method, raw_target, body_sha256, response_status, response_bytes,
            completed_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [
          record.id,
          record.nodeId,
          record.implementerId,
          record.routeId,
          record.idempotencyKey,
          record.reportingNonceId,
          record.childRecordId,
          record.method,
          record.rawTarget,
          record.bodySha256,
          record.responseStatus,
          record.responseBytes,
          new Date(record.completedAtMs).toISOString(),
          new Date(record.completedAtMs).toISOString(),
        ],
      );
      return { kind: "INSERTED" };
    } catch (err) {
      // CONFLICT for idempotency / fingerprint keys and the parent PK; other 23505s rethrow.
      if (isUniqueViolation(err)) {
        const constraint = pgErrorConstraint(err);
        if (
          constraint === IDEMPOTENCY_KEY_GUARD ||
          constraint === FINGERPRINT_GUARD ||
          constraint === IDEMPOTENCY_PK_GUARD
        ) {
          return { kind: "CONFLICT" };
        }
      }
      throw err;
    }
  }

  private async runSingle<T>(
    text: string,
    params: readonly unknown[],
    map: (row: Record<string, unknown>) => T,
  ): Promise<T | null> {
    const rows = await this.client.query(text, params);
    const row = rows[0];
    return row === undefined ? null : map(row);
  }
}

async function rowExists(
  query: ReportingQueryFn,
  text: string,
  params: readonly unknown[],
): Promise<boolean> {
  const rows = await query(text, params);
  return rows.length > 0;
}

function buildNonceInsert(): string {
  const columns = [...NONCE_EVIDENCE_COLUMNS];
  const placeholders = columns.map((_, i) => `$${i + 1}`);
  return `INSERT INTO reporting_request_nonces (${columns.join(", ")})
          VALUES (${placeholders.join(", ")})
          RETURNING id, nonce_burn_sequence, logical_fingerprint`;
}

// Sentinel: benign parent uniqueness race — forces outer ROLLBACK, maps to CONFLICT.
class IdempotencyConflictInTxError extends Error {
  constructor() {
    super("idempotency conflict inside mutation unit-of-work");
    this.name = "IdempotencyConflictInTxError";
  }
}

// Mirrors the reference adapter's mandate gate: a missing mandatory completion field is a
// programming error (rejected promise), never a request outcome.
function assertMandatoryCompletionFields(record: CompletedIdempotencyRecord): void {
  const invalid =
    !Number.isInteger(record.responseStatus) ||
    record.responseStatus < 100 ||
    record.responseStatus > 599 ||
    !Number.isSafeInteger(record.completedAtMs) ||
    record.idempotencyKey.length === 0 ||
    record.reportingNonceId.length === 0 ||
    record.childRecordId.length === 0;
  if (invalid) {
    throw new ReportingStoreError("completed idempotency record misses a mandatory completion field");
  }
}

// Production wiring: a ReportingQueryClient over the pg Pool. Plain queries run autocommit;
// transact pins ONE client for BEGIN/COMMIT (ROLLBACK on error) so the burn is atomic. The error
// object is propagated verbatim so the store's SQLSTATE mapping sees the driver's `code`.
export function createPoolReportingClient(pool: Pool): ReportingQueryClient {
  const query: ReportingQueryFn = async (text, params) => {
    const result = await pool.query(text, params as unknown[]);
    return result.rows as readonly Record<string, unknown>[];
  };
  const transact = async <T>(body: (q: ReportingQueryFn) => Promise<T>): Promise<T> => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await body(async (text, params) => {
        const inner = await client.query(text, params as unknown[]);
        return inner.rows as readonly Record<string, unknown>[];
      });
      await client.query("COMMIT");
      return result;
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  };
  return { query, transact };
}
