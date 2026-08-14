// SQL ArmWalletGate — production composition for the receive arm barrier and receive-gate enforcement.
//
// Atomicity: BEGIN → SELECT wallets FOR UPDATE → body (live standing re-reads + operation
// row lock + tryInsert + AWAITING_ARM→RELEASED + row_version CAS on the **same**
// SqlTxExecutor) → COMMIT. The row lock is held for the entire callback.
// ArmCommitSession.kind==="sql" carries that executor; bound ports call
// assertSqlArmCommitSession(session, activeArmTx()) before any DML.
//
// Composition root (generic-node ActionRouteStore / reporting operation_armed handler):
// const txFactory = createPoolArmTxFactory(pool);
// const walletGate = createSqlArmWalletGate(txFactory);
// const armStore = createSqlArmStore({ queryOutsideLock: pool.query.bind(pool), envelopeFor });
// const operationState = createSqlTxBoundOperationState(baseOperationState);
// const service = createArmMutationService({ ..., walletGate, armStore, operationState });

import { AsyncLocalStorage } from "node:async_hooks";
import {
  assertSqlArmCommitSession,
  expiresAtFromUnixSecs,
  isArmableWalletStanding,
  type ArmCommitSession,
  type ArmOperationGateSnapshot,
  type ArmRecord,
  type ArmReleasePayload,
  type ArmSqlTxRef,
  type ArmStore,
  type ArmOperationState,
  type ArmWalletGate,
  type ArmWalletLockHandle,
  type ArmWalletStanding,
  type ArmWalletState,
} from "./arm-mutation.js";

/** Driver-agnostic single-statement executor (one pinned client / connection). */
export interface SqlTxExecutor {
  query<R>(text: string, params?: readonly unknown[]): Promise<{ rows: R[] }>;
}

export interface SqlQueryResult<R> {
  readonly rows: R[];
}

/** Opens BEGIN/COMMIT around a body that receives the pinned executor. */
export interface SqlTxFactory {
  withTransaction<T>(fn: (tx: SqlTxExecutor) => Promise<T>): Promise<T>;
}

/**
 * Canonical arm-path SQL against the frozen data-model / custody schema surfaces.
 *
 * Arm ack is `receive_arms` — NOT a fictional receive_arm_acknowledgements.
 * Post-arm durable effect is `receive_codes.code_status` AWAITING_ARM→RELEASED plus
 * `operations.row_version` bump while status stays READY (no operation_status 'ARMED').
 * LOCK uses custody wallets PK `id` (custody schema PK spelling); alias AS wallet_id for the TS row mapper (receive arm barrier (3)).
 */
export const ARM_SQL_STATEMENTS = {
  LOCK_WALLET_STANDING:
    "SELECT id::text AS wallet_id, state::text AS state, " +
    "recovery_verified_at::text AS recovery_verified_at, " +
    "allow_external_receive " +
    "FROM wallets WHERE id = $1::uuid FOR UPDATE",
  /**
   * Operation + withheld code under the wallet-lock TX.
   * Locks the operation row so expiry races resolve under the same lock as arm.
   */
  LOCK_OPERATION_GATE:
    "SELECT o.id::text AS operation_id, o.status::text AS state, " +
    "o.row_version::int AS row_version, " +
    "c.expiry_unix_time_secs::text AS expiry_unix_time_secs, " +
    "c.receiver_wallet_id::text AS receiver_wallet_id, " +
    "c.code_status::text AS code_status, " +
    "c.transfer_code_text AS transfer_code, " +
    "c.transfer_code_sha256 AS transfer_code_sha256 " +
    "FROM operations o " +
    "INNER JOIN receive_codes c ON c.operation_id = o.id " +
    "WHERE o.id = $1::uuid FOR UPDATE OF o, c",
  /**
   * Idempotent arm acknowledgement — receive_arms, UNIQUE(operation_id).
   * Reporting envelope columns (node/implementer/nonce/fingerprint inputs) come from
   * SqlArmInsertEnvelope; defaults cover route_id/purpose/class/method.
   */
  INSERT_ARM_ACK:
    "INSERT INTO receive_arms (" +
    "id, operation_id, node_id, implementer_id, " +
    "raw_target, node_t0_observation_id, " +
    "acknowledged_s, acknowledged_p, acknowledged_b, opened_cursor, " +
    "request_body_sha256, reporting_nonce_id, mutation_idempotency_id, armed_at" +
    ") VALUES (" +
    "$1::uuid, $2::uuid, $3::uuid, $4::uuid, " +
    "$5, $6::uuid, " +
    "$7, $8, $9, $10::bigint, " +
    "$11, $12::uuid, $13::uuid, $14::timestamptz" +
    ") ON CONFLICT (operation_id) DO NOTHING " +
    "RETURNING operation_id::text AS operation_id",
  /** Lookup joined to receive_codes for receiver_wallet_id (not stored on receive_arms). */
  FIND_ARM_BY_OPERATION:
    "SELECT a.operation_id::text AS operation_id, " +
    "c.receiver_wallet_id::text AS wallet_id, " +
    "a.node_t0_observation_id::text AS node_t0_observation_id, " +
    "a.acknowledged_s, a.acknowledged_p, a.acknowledged_b, " +
    "a.opened_cursor::text AS opened_cursor, a.armed_at::text AS armed_at " +
    "FROM receive_arms a " +
    "INNER JOIN receive_codes c ON c.operation_id = a.operation_id " +
    "WHERE a.operation_id = $1::uuid",
  /**
   * Code release under the wallet lock. Authority is receive_codes
   * code_status, not operations.status.
   */
  RELEASE_RECEIVE_CODE:
    "UPDATE receive_codes SET code_status = 'RELEASED', " +
    "released_at = $2::timestamptz " +
    "WHERE operation_id = $1::uuid AND code_status = 'AWAITING_ARM' " +
    "RETURNING operation_id::text AS operation_id, " +
    "transfer_code_text AS transfer_code, " +
    "transfer_code_sha256 AS transfer_code_sha256, " +
    "expiry_unix_time_secs::text AS expiry_unix_time_secs",
  /**
   * row_version CAS; status remains READY until RECEIVE_LANDED.
   * expected_row_version is the caller's CAS token.
   */
  BUMP_OPERATION_ROW_VERSION:
    "UPDATE operations SET row_version = row_version + 1 " +
    "WHERE id = $1::uuid AND status = 'READY' AND row_version = $2::int " +
    "RETURNING id::text AS operation_id, row_version::int AS row_version",
  /** Idempotent re-arm load of already-released code bytes. */
  LOAD_RELEASED_CODE:
    "SELECT c.transfer_code_text AS transfer_code, " +
    "c.transfer_code_sha256 AS transfer_code_sha256, " +
    "c.expiry_unix_time_secs::text AS expiry_unix_time_secs, " +
    "o.row_version::int AS row_version " +
    "FROM receive_codes c " +
    "INNER JOIN operations o ON o.id = c.operation_id " +
    "WHERE c.operation_id = $1::uuid AND c.code_status = 'RELEASED'",
} as const;

/** Reporting / identity envelope required by receive_arms NOT NULL columns. */
export interface SqlArmInsertEnvelope {
  readonly armId: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly rawTarget: string;
  readonly requestBodySha256: string;
  readonly reportingNonceId: string;
  readonly mutationIdempotencyId: string;
}

interface WalletStandingRow {
  readonly wallet_id: string;
  readonly state: string;
  readonly recovery_verified_at: string | null;
  readonly allow_external_receive: boolean | string;
}

interface OperationGateRow {
  readonly operation_id: string;
  readonly state: string;
  readonly row_version: number;
  readonly expiry_unix_time_secs: string;
  readonly receiver_wallet_id: string;
  readonly code_status: string;
  readonly transfer_code: string;
  readonly transfer_code_sha256: string;
}

const KNOWN_WALLET_STATES: ReadonlySet<string> = new Set([
  "AVAILABLE",
  "PINNED",
  "QUARANTINED",
  "RETIRED",
]);

function pgBool(value: unknown): boolean {
  return value === true || value === "t" || value === "true" || value === "1";
}

function mapStanding(row: WalletStandingRow): ArmWalletStanding {
  const state = KNOWN_WALLET_STATES.has(row.state)
    ? (row.state as ArmWalletState)
    : // Unknown enum member fails closed under the receive-gate enforcement allowlist (not AVAILABLE/PINNED).
      ("RETIRED" as ArmWalletState);
  return {
    walletId: row.wallet_id,
    state,
    recoveryVerifiedAt: row.recovery_verified_at,
    allowExternalReceive: pgBool(row.allow_external_receive),
  };
}

function mapGate(row: OperationGateRow): ArmOperationGateSnapshot {
  return {
    state: row.state,
    rowVersion: Number(row.row_version),
    expiryUnixTimeSecs: row.expiry_unix_time_secs,
    receiverWalletId: row.receiver_wallet_id,
    codeStatus: row.code_status,
    transferCode: row.transfer_code,
    transferCodeSha256: row.transfer_code_sha256,
  };
}

/** Active arm DB-TX — set for the duration of withWalletLocked so bound ports share it. */
const armTxStorage = new AsyncLocalStorage<SqlTxExecutor>();

/** The wallet-lock transaction currently held by createSqlArmWalletGate, if any. */
export function activeArmTx(): SqlTxExecutor | undefined {
  return armTxStorage.getStore();
}

async function readStandingOn(
  tx: SqlTxExecutor,
  walletId: string,
): Promise<ArmWalletStanding | null> {
  const result = await tx.query<WalletStandingRow>(ARM_SQL_STATEMENTS.LOCK_WALLET_STANDING, [
    walletId,
  ]);
  const row = result.rows[0];
  return row === undefined ? null : mapStanding(row);
}

/**
 * SQL ArmWalletGate: holds `SELECT ... FOR UPDATE` on the wallet row for the full
 * duration of `body`. `requireCommitSession` returns `{ kind: "sql", sqlTx }` bound to
 * the same executor published via `activeArmTx` (receive arm barrier).
 */
export function createSqlArmWalletGate(txFactory: SqlTxFactory): ArmWalletGate {
  return {
    async withWalletLocked<T>(
      walletId: string,
      body: (lock: ArmWalletLockHandle) => Promise<T>,
    ): Promise<T> {
      return txFactory.withTransaction(async (tx) => {
        return armTxStorage.run(tx, async () => {
          // Initial lock acquisition — subsequent readStanding reuses the held row lock.
          await readStandingOn(tx, walletId);
          let open = true;
          const lock: ArmWalletLockHandle = {
            readStanding: () => {
              if (!open) {
                throw new Error("readStanding after wallet lock released");
              }
              return readStandingOn(tx, walletId);
            },
            requireCommitSession: (): ArmCommitSession => {
              if (!open) {
                throw new Error("requireCommitSession after wallet lock released");
              }
              // Identity equality with activeArmTx is the store-side invariant.
              return { kind: "sql", sqlTx: tx };
            },
          };
          try {
            return await body(lock);
          } finally {
            open = false;
          }
        });
      });
    },
  };
}

/**
 * Unit-of-work helper for composition roots that own the full arm commit themselves
 * (e.g. ActionRouteStore.arm). Lock → standing allowlist → commit callback under lock.
 * Prefer this when ports take an explicit `tx` rather than ArmCommitSession.
 */
export async function commitArmUnderWalletLock<T>(
  txFactory: SqlTxFactory,
  walletId: string,
  commit: (tx: SqlTxExecutor, standing: ArmWalletStanding) => Promise<T>,
): Promise<
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly reason: string }
> {
  return txFactory.withTransaction(async (tx) => {
    return armTxStorage.run(tx, async () => {
      const standing = await readStandingOn(tx, walletId);
      if (standing === null) {
        return { ok: false as const, reason: "assigned wallet not found" };
      }
      const check = isArmableWalletStanding(standing);
      if (!check.ok) {
        return { ok: false as const, reason: check.reason };
      }
      // Live re-read immediately before commit — same discipline as createArmMutationService.
      const fresh = await readStandingOn(tx, walletId);
      if (fresh === null) {
        return { ok: false as const, reason: "assigned wallet not found" };
      }
      const freshCheck = isArmableWalletStanding(fresh);
      if (!freshCheck.ok) {
        return { ok: false as const, reason: freshCheck.reason };
      }
      const value = await commit(tx, fresh);
      return { ok: true as const, value };
    });
  });
}

/**
 * Resolve the live wallet-lock TX from an ArmCommitSession. Fail-closed when unbound.
 * Composition roots and SQL ArmStore implementations share this guard.
 */
export function requireActiveArmSqlTx(session: ArmCommitSession): SqlTxExecutor {
  return assertSqlArmCommitSession(session, activeArmTx()) as SqlTxExecutor;
}

/**
 * SQL ArmStore: INSERT into receive_arms on the held wallet-lock TX only.
 * `findByOperation` / `loadReleasedCode` may run outside the lock; tryInsert never does.
 * `envelopeFor` supplies reporting columns the domain ArmRecord does not carry.
 */
export function createSqlArmStore(deps: {
  /** Used for findByOperation / loadReleasedCode outside the lock window. */
  readonly queryOutsideLock: SqlTxExecutor["query"];
  /** Map domain arm record → receive_arms envelope (node/implementer/nonce/…). */
  readonly envelopeFor: (record: ArmRecord) => SqlArmInsertEnvelope;
}): ArmStore {
  return {
    async findByOperation(operationId: string): Promise<ArmRecord | null> {
      const result = await deps.queryOutsideLock<{
        operation_id: string;
        wallet_id: string;
        node_t0_observation_id: string;
        acknowledged_s: string;
        acknowledged_p: string;
        acknowledged_b: string;
        opened_cursor: string;
        armed_at: string;
      }>(ARM_SQL_STATEMENTS.FIND_ARM_BY_OPERATION, [operationId]);
      const row = result.rows[0];
      if (row === undefined) return null;
      return {
        operationId: row.operation_id,
        walletId: row.wallet_id,
        nodeT0ObservationId: row.node_t0_observation_id,
        acknowledgedS: row.acknowledged_s,
        acknowledgedP: row.acknowledged_p,
        acknowledgedB: row.acknowledged_b,
        openedCursor: BigInt(row.opened_cursor),
        armedAt: row.armed_at,
      };
    },
    async loadReleasedCode(operationId: string): Promise<ArmReleasePayload | null> {
      const result = await deps.queryOutsideLock<{
        transfer_code: string;
        transfer_code_sha256: string;
        expiry_unix_time_secs: string;
        row_version: number;
      }>(ARM_SQL_STATEMENTS.LOAD_RELEASED_CODE, [operationId]);
      const row = result.rows[0];
      if (row === undefined) return null;
      return {
        transferCode: row.transfer_code,
        transferCodeSha256: row.transfer_code_sha256,
        expiresAt: expiresAtFromUnixSecs(row.expiry_unix_time_secs),
        rowVersion: Number(row.row_version),
      };
    },
    async tryInsert(record: ArmRecord, session: ArmCommitSession): Promise<ArmRecord | null> {
      const tx = requireActiveArmSqlTx(session);
      const env = deps.envelopeFor(record);
      const inserted = await tx.query<{ operation_id: string }>(ARM_SQL_STATEMENTS.INSERT_ARM_ACK, [
        env.armId,
        record.operationId,
        env.nodeId,
        env.implementerId,
        env.rawTarget,
        record.nodeT0ObservationId,
        record.acknowledgedS,
        record.acknowledgedP,
        record.acknowledgedB,
        record.openedCursor.toString(),
        env.requestBodySha256,
        env.reportingNonceId,
        env.mutationIdempotencyId,
        record.armedAt,
      ]);
      if (inserted.rows.length === 0) return null;
      return record;
    },
  };
}

/**
 * Wrap a base ArmOperationState so lockAndReadGate / transitionToArmed issue DML on the
 * wallet-lock TX. Pre-lock reads (getState / getAssignedWallet / getT0 / getVerificationMode)
 * stay on the base.
 */
export function createSqlTxBoundOperationState(
  base: Pick<ArmOperationState, "getState" | "getAssignedWallet" | "getT0"> &
    Partial<Pick<ArmOperationState, "markAttention" | "getVerificationMode">>,
): ArmOperationState {
  return {
    getState: (id) => base.getState(id),
    getAssignedWallet: (id) => base.getAssignedWallet(id),
    getT0: (id) => base.getT0(id),
    getVerificationMode: base.getVerificationMode?.bind(base),
    markAttention: base.markAttention?.bind(base),
    async lockAndReadGate(
      operationId: string,
      session: ArmCommitSession,
    ): Promise<ArmOperationGateSnapshot | null> {
      const tx = requireActiveArmSqlTx(session);
      const result = await tx.query<OperationGateRow>(ARM_SQL_STATEMENTS.LOCK_OPERATION_GATE, [
        operationId,
      ]);
      const row = result.rows[0];
      return row === undefined ? null : mapGate(row);
    },
    async transitionToArmed(
      operationId: string,
      session: ArmCommitSession,
      expectedRowVersion: number,
    ) {
      const tx = requireActiveArmSqlTx(session);
      const releasedAt = new Date().toISOString();
      // Arm ack + code-release marker commit together (same TX).
      const released = await tx.query<{
        operation_id: string;
        transfer_code: string;
        transfer_code_sha256: string;
        expiry_unix_time_secs: string;
      }>(ARM_SQL_STATEMENTS.RELEASE_RECEIVE_CODE, [operationId, releasedAt]);
      if (released.rows.length === 0) {
        return { ok: false as const, reason: "not_armable" as const };
      }
      const bumped = await tx.query<{ operation_id: string; row_version: number }>(
        ARM_SQL_STATEMENTS.BUMP_OPERATION_ROW_VERSION,
        [operationId, expectedRowVersion],
      );
      if (bumped.rows.length === 0) {
        return {
          ok: false as const,
          reason: "version_conflict" as const,
          currentRowVersion: expectedRowVersion,
        };
      }
      const code = released.rows[0]!;
      const row = bumped.rows[0]!;
      const release: ArmReleasePayload = {
        transferCode: code.transfer_code,
        transferCodeSha256: code.transfer_code_sha256,
        expiresAt: expiresAtFromUnixSecs(code.expiry_unix_time_secs),
        rowVersion: Number(row.row_version),
      };
      return { ok: true as const, release };
    },
  };
}

/**
 * Fail-closed ActionRouteStore.arm stub until the operation engine injects the full
 * gate + tx-bound store. Callers that mount routes without wiring get operation_not_armable
 * rather than a silent unbound path.
 */
export function createFailClosedArmHandler(reason =
  "arm path not wired: ActionRouteStore must inject createSqlArmWalletGate + tx-bound ArmStore",
): (operationId: string) => Promise<never> {
  return async (operationId: string): Promise<never> => {
    const err = new Error(reason);
    err.name = "OperationNotArmableError";
    (err as Error & { reason: string }).reason = `${reason} (operation ${operationId})`;
    throw err;
  };
}

// Re-export ArmSqlTxRef alias for package consumers that type against arm-sql.
export type { ArmSqlTxRef };
