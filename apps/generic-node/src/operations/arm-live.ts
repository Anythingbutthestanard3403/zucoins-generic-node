// LIVE composition for `POST /v1/operations/:operation_id/armed`.
//
// The arm barrier: auth is the signed reporting credential only; the
// recovery-verification, sealed-ceremony and first-episode rules apply.
//
// This module is the only place that turns the fail-closed `operation_armed` port into a
// code-releasing one. It binds:
//   * a tenant-scoped durable-T0 loader   (operations.t0_observation_id ⋈ gateway_observations)
//   * the SQL wallet gate                 (createPoolArmWalletGate — SELECT … FOR UPDATE)
//   * the SQL arm store                   (receive_arms, insert on the held lock TX only)
//   * the tx-bound operation state        (operation row lock, AWAITING_ARM→RELEASED, CAS)
//
// Arm-contract atomicity: "arm transition atomically commits [the] mutation [and the] completed
// idempotency row [with] exact status [and] response-body bytes." The reporting runtime's own
// `commitMutationWithCompletedIdempotency` runs in a SECOND transaction, after the wallet-lock
// TX has already committed the code release — so it cannot carry that promise, and the
// `receive_arms.mutation_idempotency_id` FK would have no parent at arm-commit time.
// Therefore this composition writes `reporting_mutation_idempotency` itself, on the wallet-lock
// TX, immediately after the release, and returns `persistChild: null` so the runtime does not
// write a second parent. Replays are then served by the runtime's own completed-idempotency
// lookup from the row committed here (frozen status + exact bytes).
//
// Re-arm rule: an `already_armed` outcome must NOT re-serve the code on the strength of a
// fresh, unsigned Idempotency-Key. An armed operation already has exactly one completion parent
// (`receive_arms.mutation_idempotency_id` is NOT NULL and FKs it), so the only lawful 200 is a
// replay of that same request's frozen bytes; every other re-arm is 409 idempotency_conflict.
// Without that gate this route is a state-unchecked, expiry-unchecked transfer_code retrieval
// oracle whose "replay" row_version drifts (LOAD_RELEASED_CODE reads row_version live).
//
// Never released without success: any refusal after `RELEASE_RECEIVE_CODE` throws, which
// ROLLBACKs the wallet-lock TX (createPoolArmTxFactory), so no code byte can commit behind a
// non-2xx response. Plaintext transfer_code appears only in the arm response body — never in
// a log line, never in an evidence artifact (sha256 only).
//
// Connection discipline: every statement this module issues goes through `poolQuery`, which
// reuses the pinned wallet-lock client whenever one is held. Acquiring a SECOND pool client
// inside withWalletLocked deadlocks the process-wide pool under concurrent arms.
//
// Boundary: apps/generic-node depends on the node-core package only (no subpaths).

import { randomUUID } from "node:crypto";
import type { Pool } from "pg";

import {
  activeArmTx,
  apiErrorResponse,
  buildArmSuccessResponse,
  createSqlArmStore,
  createSqlTxBoundOperationState,
  reportingErrorResponse,
  requireActiveArmSqlTx,
  type ArmAuditEntry,
  type ArmAuditLog,
  type ArmOperationState,
  type ArmPreopenDurableT0Port,
  type ArmT0Projection,
  type NodeDurableT0,
  type ReportingHandlerResult,
  type ReportingHttpResponse,
  type ReportingRouteHandler,
  type SqlArmInsertEnvelope,
  type VerifiedReportRequest,
} from "@zucoins/node-core";

import { isUniqueViolation } from "../reporting/pg-client.js";
import { createArmCommitHook } from "./arm-commit.js";
import { createArmRouteHandler } from "./arm-route.js";
import { createPoolArmWalletGate } from "./arm-wallet-gate.js";

/**
 * Closed `attention_reason` vocabulary value used when the arm-time
 * recovery/standing recheck refuses: the leased receiver wallet is no longer eligible to
 * hold the receive it is leased for. Hard-coded because the generic-node-contracts package
 * is a dev dependency of `apps/generic-node` and is absent from the shipped runtime.
 */
const ARM_STANDING_ATTENTION_REASON = "LEASE_INVARIANT_VIOLATION";

export const ARM_LIVE_SQL = {
  /**
   * Node-owned durable RECEIVER_T0 (arm-binding NodeDurableT0), tenant-scoped.
   * A consumer observation can never be returned here: the join starts from the operation row's
   * own `t0_observation_id`.
   */
  LOAD_NODE_T0:
    "SELECT o.t0_observation_id::text AS observation_id, " +
    "g.s_signature AS s, g.p_signature AS p, g.b_amount AS b_zkz " +
    "FROM operations o " +
    "INNER JOIN gateway_observations g ON g.id = o.t0_observation_id " +
    "WHERE o.id = $1::uuid AND o.node_id = $2::uuid AND o.implementer_id = $3::uuid " +
    "AND o.kind = 'RECEIVE_EXTERNAL'",
  LOAD_OPERATION_STATE:
    "SELECT status::text AS state FROM operations WHERE id = $1::uuid",
  /** Receive-side receiver wallet — same column the arm gate locks (receive_codes). */
  LOAD_RECEIVER_WALLET:
    "SELECT receiver_wallet_id::text AS wallet_id FROM receive_codes WHERE operation_id = $1::uuid",
  /** Tenant-scoped variant used before any mutation is attempted. */
  LOAD_RECEIVER_WALLET_SCOPED:
    "SELECT c.receiver_wallet_id::text AS wallet_id " +
    "FROM receive_codes c INNER JOIN operations o ON o.id = c.operation_id " +
    "WHERE c.operation_id = $1::uuid AND o.node_id = $2::uuid AND o.implementer_id = $3::uuid",
  /**
   * First attention episode wins; a later recheck never overwrites the reason.
   * RETURNING so a 0-row update is observable (missing op vs. already-flagged).
   */
  MARK_ATTENTION:
    "UPDATE operations SET attention_required = true, attention_reason = $2, " +
    "attention_detail = $3, updated_at = now() " +
    "WHERE id = $1::uuid AND attention_required = false " +
    "RETURNING id::text AS id",
  /** Probe used when MARK_ATTENTION RETURNS 0 rows — distinguish first-wins from missing. */
  LOAD_ATTENTION_FLAG:
    "SELECT attention_required FROM operations WHERE id = $1::uuid",
  /** Completed idempotency row, written on the wallet-lock TX with the exact bytes. */
  INSERT_COMPLETED_IDEMPOTENCY:
    "INSERT INTO reporting_mutation_idempotency (" +
    "id, node_id, implementer_id, route_id, idempotency_key, reporting_nonce_id, " +
    "child_record_id, method, raw_target, body_sha256, response_status, response_bytes, " +
    "completed_at, created_at" +
    ") VALUES (" +
    "$1::uuid, $2::uuid, $3::uuid, $4, $5, $6::uuid, " +
    "$7::uuid, $8, $9, $10, $11::int, $12::bytea, " +
    "$13::timestamptz, $13::timestamptz)",
  /**
   * Idempotency lookup for THIS Idempotency-Key — same keying as the reporting runtime's
   * `findCompletedIdempotency`. Primary same-key completed replay is served at
   * request-handler resolveCompleted (before this module runs). This query remains for the
   * in-panel already_armed gate: after findByOperation sees an arm row, only THIS key's
   * frozen bytes may 200; any other key (or fingerprint miss) is 409. Concurrent same-key
   * losers that race past resolveCompleted also land here.
   */
  FIND_COMPLETED_IDEMPOTENCY:
    "SELECT response_status::int AS response_status, response_bytes, " +
    "method, raw_target, body_sha256 " +
    "FROM reporting_mutation_idempotency " +
    "WHERE node_id = $1::uuid AND implementer_id = $2::uuid " +
    "AND route_id = $3 AND idempotency_key = $4",
} as const;

/** Marker recorded on the production surface so the mount is greppable + assertable. */
export const LIVE_ARM_ENGINE = Object.freeze({
  routeId: "operation_armed" as const,
  handler: "createArmRouteHandler + createArmCommitHook (SQL arm stores, wallet gate, T0 load)",
  ticket: "live ARM composition releases transfer_code after reporting pre-open",
});

/** Thrown after the release UPDATE to force a ROLLBACK — no code commits behind a refusal. */
class ArmCommitRefused extends Error {
  constructor(readonly reason: "version_conflict" | "not_armable" | "expired") {
    super(`arm commit refused: ${reason}`);
    this.name = "ArmCommitRefused";
  }
}

function apiToReporting(api: {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}): ReportingHttpResponse {
  return {
    status: api.status,
    headers: api.headers,
    bodyBytes: new TextEncoder().encode(api.body),
  };
}

type PoolQuery = <R>(
  text: string,
  params?: readonly unknown[],
) => Promise<{ rows: R[] }>;

/**
 * Query runner that reuses the pinned wallet-lock client whenever `withWalletLocked` holds one.
 *
 * A second `pool.connect()` inside the lock is a process-wide deadlock, not a slow path: the
 * pool is shared with the money workers and the durable reporting store, one client is
 * permanently checked out for the leadership advisory lock (main.ts), and concurrent arms each
 * hold a client while blocking on the wallet row. The lock holder then waits forever for a
 * client the blocked arms will never release. Reading through `activeArmTx()` also gives the
 * refusal paths (markAttention, findByOperation, loadReleasedCode) the lock's own snapshot.
 */
function poolQuery(pool: Pool): PoolQuery {
  return async <R>(text: string, params?: readonly unknown[]) => {
    const heldTx = activeArmTx();
    if (heldTx !== undefined) return heldTx.query<R>(text, params);
    const result = await pool.query(text, params as unknown[] | undefined);
    return { rows: result.rows as R[] };
  };
}

/** Tenant-scoped durable-T0 port for `runArmPreopen`. */
export function createSqlArmDurableT0(pool: Pool): ArmPreopenDurableT0Port {
  const query = poolQuery(pool);
  return {
    async getNodeDurableT0(input): Promise<NodeDurableT0 | null> {
      const result = await query<{
        observation_id: string;
        s: string | null;
        p: string | null;
        b_zkz: string | null;
      }>(ARM_LIVE_SQL.LOAD_NODE_T0, [input.operationId, input.nodeId, input.implementerId]);
      const row = result.rows[0];
      if (row === undefined || row.b_zkz === null) return null;
      return {
        observationId: row.observation_id,
        projection: { s: row.s ?? "", p: row.p ?? "", b_zkz: row.b_zkz },
      };
    },
  };
}

/**
 * Pre-lock reads for the arm mutation service. `lockAndReadGate` / `transitionToArmed` are
 * supplied by `createSqlTxBoundOperationState`, which issues them on the held wallet-lock TX.
 *
 * Advisory-reads note: getState / getAssignedWallet / getT0 below are **advisory pre-lock reads**.
 * The ArmOperationState port only takes `operationId` (no tenant), so they cannot be
 * tenant-scoped at this layer. They sped-fail obvious refuses before acquiring the wallet
 * lock. They are **not** an authorization surface: the post-lock CAS
 * (`lockAndReadGate` / `transitionToArmed` / RELEASE_RECEIVE_CODE) and the scoped
 * `LOAD_RECEIVER_WALLET_SCOPED` / `LOAD_NODE_T0` paths re-check under the held TX and are
 * authoritative. Do not copy these unscoped SELECTs into a new mutation path without an
 * equivalent post-lock pin.
 */
function createBaseOperationState(
  pool: Pool,
): Pick<ArmOperationState, "getState" | "getAssignedWallet" | "getT0" | "markAttention"> {
  const query = poolQuery(pool);
  return {
    async getState(operationId: string): Promise<string | null> {
      // Advisory pre-lock (F8) — unscoped by ArmOperationState port shape; CAS under lock wins.
      const result = await query<{ state: string }>(ARM_LIVE_SQL.LOAD_OPERATION_STATE, [
        operationId,
      ]);
      return result.rows[0]?.state ?? null;
    },
    async getAssignedWallet(operationId: string): Promise<string | null> {
      // Advisory pre-lock (F8). Commit path uses LOAD_RECEIVER_WALLET_SCOPED under tenant.
      const result = await query<{ wallet_id: string }>(ARM_LIVE_SQL.LOAD_RECEIVER_WALLET, [
        operationId,
      ]);
      return result.rows[0]?.wallet_id ?? null;
    },
    async getT0(operationId: string): Promise<ArmT0Projection | null> {
      // Advisory pre-lock (F8). Durable T0 binding for pre-open uses tenant-scoped LOAD_NODE_T0.
      const result = await query<{
        observation_id: string;
        s: string | null;
        p: string | null;
        b_zkz: string | null;
      }>(
        "SELECT o.t0_observation_id::text AS observation_id, " +
          "g.s_signature AS s, g.p_signature AS p, g.b_amount AS b_zkz " +
          "FROM operations o INNER JOIN gateway_observations g ON g.id = o.t0_observation_id " +
          "WHERE o.id = $1::uuid",
        [operationId],
      );
      const row = result.rows[0];
      if (row === undefined || row.b_zkz === null) return null;
      return {
        observationId: row.observation_id,
        s0: row.s ?? "",
        p0: row.p ?? "",
        b0: row.b_zkz,
      };
    },
    async markAttention(operationId: string, reason: string): Promise<void> {
      // Durable audit lives on operations.attention_* (first-wins) + receive_arms /
      // reporting_mutation_idempotency — not the process-local audit ring (F4).
      const updated = await query<{ id: string }>(ARM_LIVE_SQL.MARK_ATTENTION, [
        operationId,
        ARM_STANDING_ATTENTION_REASON,
        reason,
      ]);
      if (updated.rows[0] !== undefined) return;
      // 0-row: first-episode already set, or missing row — never silent.
      const existing = await query<{ attention_required: boolean }>(
        ARM_LIVE_SQL.LOAD_ATTENTION_FLAG,
        [operationId],
      );
      if (existing.rows[0]?.attention_required === true) return;
      throw new Error(
        `MARK_ATTENTION: operation ${operationId} missing or not updatable (0-row)`,
      );
    },
  };
}

/**
 * Wrap the tx-bound operation state so that the completed-idempotency row is written on
 * the SAME transaction as the code release, and so that any post-release refusal rolls back.
 */
function withCompletionFreeze(
  bound: ArmOperationState,
  request: VerifiedReportRequest,
  envelope: SqlArmInsertEnvelope,
  nowMs: () => number,
  /** Called once the completion row for THIS request is on the wallet-lock TX. */
  onFrozen: () => void,
): ArmOperationState {
  return {
    ...bound,
    async transitionToArmed(operationId, session, expectedRowVersion) {
      const outcome = await bound.transitionToArmed(operationId, session, expectedRowVersion);
      // A refusal reached here only AFTER RELEASE_RECEIVE_CODE ran on this TX. Returning it
      // would COMMIT a released code behind a 409 — throw so the TX rolls back instead.
      if (!outcome.ok) throw new ArmCommitRefused(outcome.reason);

      const tx = requireActiveArmSqlTx(session);
      // Byte-identical to the body arm-commit.ts returns (same builder, same JSON.stringify) —
      // Byte-exact: the frozen bytes and the wire bytes are one serialization, not two.
      const bodyText = JSON.stringify(
        buildArmSuccessResponse({ operationId, release: outcome.release }),
      );
      await tx.query(ARM_LIVE_SQL.INSERT_COMPLETED_IDEMPOTENCY, [
        envelope.mutationIdempotencyId,
        envelope.nodeId,
        envelope.implementerId,
        request.route.routeId,
        request.idempotencyKey,
        envelope.reportingNonceId,
        envelope.armId,
        request.fingerprint.method,
        envelope.rawTarget,
        envelope.requestBodySha256,
        200,
        Buffer.from(bodyText, "utf8"),
        new Date(nowMs()).toISOString(),
      ]);
      onFrozen();
      return outcome;
    },
  };
}

export interface LiveArmDeps {
  readonly pool: Pool;
  readonly newRequestId: () => string;
  readonly nowMs: () => number;
  /** Structured audit sink. Receives operation/wallet/outcome — never code bytes. */
  readonly auditLog?: ArmAuditLog;
}

/**
 * Process-local telemetry only (ring dies with the process). **Not** the production audit.
 *
 * Design decision: the durable arm audit trail is the reporting store rows already
 * written on the arm path —
 *   * `receive_arms` (one row per successful arm; mutation_idempotency_id FK)
 *   * `reporting_mutation_idempotency` (frozen status + response bytes)
 * * `operations.attention_*` (standing refusal; first episode wins)
 * Live ops reconciles arm outcomes from those tables. This ring is optional session color
 * for tests/injectable sinks and must not be treated as an ops audit source.
 */
function defaultAuditLog(): ArmAuditLog {
  const entries: ArmAuditEntry[] = [];
  return {
    async append(entry: ArmAuditEntry): Promise<void> {
      entries.push(entry);
      if (entries.length > 256) entries.shift();
    },
  };
}

/**
 * The live `operation_armed` reporting handler. Ports are rebuilt per request because the
 * receive_arms envelope (arm id, reporting nonce id, idempotency parent id) is request-scoped.
 */
export function createLiveArmRouteHandler(deps: LiveArmDeps): ReportingRouteHandler {
  const durableT0 = createSqlArmDurableT0(deps.pool);
  const walletGate = createPoolArmWalletGate(deps.pool);
  const base = createBaseOperationState(deps.pool);
  const query = poolQuery(deps.pool);
  const auditLog = deps.auditLog ?? defaultAuditLog();
  const clock = { now: () => new Date(deps.nowMs()).toISOString() };

  return async (request: VerifiedReportRequest): Promise<ReportingHandlerResult> => {
    const envelope: SqlArmInsertEnvelope = {
      armId: randomUUID(),
      nodeId: request.binding.nodeId,
      implementerId: request.binding.implementerId,
      rawTarget: request.fingerprint.rawTarget,
      requestBodySha256: request.fingerprint.bodySha256,
      // The durable burned-nonce row id (reporting_request_nonces.id) — never the client nonce.
      reportingNonceId: request.nonceEvidence.id,
      mutationIdempotencyId: randomUUID(),
    };

    const armStore = createSqlArmStore({
      queryOutsideLock: query,
      envelopeFor: () => envelope,
    });
    // Set only by the first-write path (transitionToArmed froze the completion row on the
    // wallet-lock TX). A 2xx WITHOUT it is an `already_armed` re-arm, which still owes the
    // guarded uniqueness rule before any code byte is re-served.
    let completionFrozen = false;
    const operationState = withCompletionFreeze(
      createSqlTxBoundOperationState(base),
      request,
      envelope,
      deps.nowMs,
      () => {
        completionFrozen = true;
      },
    );

    /**
     * already_armed gate helper (not the primary same-key replay path).
     * request-handler.resolveCompleted intercepts completed same-key same-fingerprint
     * relationships before this handler runs. This walks FIND_COMPLETED_IDEMPOTENCY when
     * the arm panel has already released and we must decide 200-replay vs 409 without
     * re-serving a drifted live body.
     */
    const replayForThisKey = async (): Promise<ReportingHttpResponse | null> => {
      const found = await query<{
        response_status: number;
        response_bytes: Buffer;
        method: string;
        raw_target: string;
        body_sha256: string;
      }>(ARM_LIVE_SQL.FIND_COMPLETED_IDEMPOTENCY, [
        envelope.nodeId,
        envelope.implementerId,
        request.route.routeId,
        request.idempotencyKey,
      ]);
      const row = found.rows[0];
      if (row === undefined) return null;
      // Same key, different request fingerprint is a conflict, not a replay.
      if (
        row.method !== request.fingerprint.method ||
        row.raw_target !== request.fingerprint.rawTarget ||
        row.body_sha256 !== request.fingerprint.bodySha256
      ) {
        return null;
      }
      return {
        status: Number(row.response_status),
        headers: { "content-type": "application/json", "idempotency-replayed": "true" },
        bodyBytes: new Uint8Array(row.response_bytes),
      };
    };

    /**
     * `already_armed` handling. The arm already has its one completion parent
     * (`receive_arms.mutation_idempotency_id` is NOT NULL and FKs it), so the only lawful 200
     * here is a replay of THIS key's own frozen bytes. Everything else — a fresh key, or the
     * same key with any input changed — is `409 idempotency_conflict`. Nothing is written, and
     * the freshly-built body (whose `row_version` is read live and therefore drifts) is
     * discarded rather than served.
     *
     * Stricter than deferring to `reporting_mutation_guarded_fingerprint_uq` alone: that index
     * keys on `body_sha256`, so a retry with a different `opened_cursor` would not collide with
     * it and would re-serve the code.
     */
    const alreadyArmedResponse = async (requestId: string): Promise<ReportingHttpResponse> =>
      (await replayForThisKey()) ?? reportingErrorResponse("idempotency_conflict", requestId);

    const commitArm = createArmCommitHook({
      walletGate,
      armStore,
      operationState,
      auditLog,
      clock,
      nowMs: deps.nowMs,
      newRequestId: deps.newRequestId,
      armChildIdFor: () => envelope.armId,
      async resolveReceiverWalletId(input) {
        const result = await query<{ wallet_id: string }>(
          ARM_LIVE_SQL.LOAD_RECEIVER_WALLET_SCOPED,
          [input.operationId, input.nodeId, input.implementerId],
        );
        return result.rows[0]?.wallet_id ?? null;
      },
    });

    const handler = createArmRouteHandler({
      durableT0,
      newRequestId: deps.newRequestId,
      async commitArm(preopen): Promise<ReportingHandlerResult> {
        const requestId = deps.newRequestId();
        try {
          const result = await commitArm(preopen);
          if (!completionFrozen && result.response.status === 200) {
            // `already_armed` — an earlier request released this code. Only that request's own
            // idempotency evidence may see it again; nothing here re-serves it.
            return { response: await alreadyArmedResponse(requestId), persistChild: null };
          }
          // The completed-idempotency parent is written on the arm TX, so the reporting
          // runtime must not write a second one — persistChild stays null on every outcome.
          return { response: result.response, persistChild: null };
        } catch (err) {
          if (err instanceof ArmCommitRefused) {
            return {
              response: apiToReporting(
                apiErrorResponse(
                  err.reason === "version_conflict"
                    ? "operation_version_conflict"
                    : "operation_not_armable",
                  requestId,
                ),
              ),
              persistChild: null,
            };
          }
          if (isUniqueViolation(err)) {
            // Concurrent same-key loser may 23505 on the completion/arm insert after the
            // winner committed — prefer frozen replay of THIS key before 409 (adversarial probe 1).
            const replay = await replayForThisKey();
            if (replay !== null) {
              return { response: replay, persistChild: null };
            }
            // Same logical arm under different unsigned evidence (guarded uniqueness).
            return {
              response: reportingErrorResponse("idempotency_conflict", requestId),
              persistChild: null,
            };
          }
          throw err;
        }
      },
    });

    return handler(request);
  };
}
