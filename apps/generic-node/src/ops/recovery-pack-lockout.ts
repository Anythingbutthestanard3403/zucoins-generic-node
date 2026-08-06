// Durable per-operator prove lockout for recovery pack.
// After 5 failed decrypt/prove attempts in a rolling window → 15 min hard lock.
// Generic errors only — no decrypt oracle.

import {
  RECOVERY_PACK_PROVE_FAIL_THRESHOLD,
  RECOVERY_PACK_PROVE_LOCKOUT_MS,
  RECOVERY_PACK_PROVE_WINDOW_MS,
} from "./recovery-pack.js";

export interface RecoveryPackLockoutSnapshot {
  readonly failCount: number;
  readonly windowStartMs: number;
  readonly lockedUntilMs: number | null;
}

export interface RecoveryPackLockoutStore {
  load(nodeId: string, operatorId: string): Promise<RecoveryPackLockoutSnapshot | null>;
  save(
    nodeId: string,
    operatorId: string,
    snap: RecoveryPackLockoutSnapshot,
  ): Promise<void>;
}

export interface RecoveryPackLockoutSqlExecutor {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

export function createMemoryRecoveryPackLockoutStore(): RecoveryPackLockoutStore {
  const map = new Map<string, RecoveryPackLockoutSnapshot>();
  const key = (n: string, o: string) => `${n}:${o}`;
  return {
    async load(nodeId, operatorId) {
      const row = map.get(key(nodeId, operatorId));
      return row ? { ...row } : null;
    },
    async save(nodeId, operatorId, snap) {
      map.set(key(nodeId, operatorId), { ...snap });
    },
  };
}

export function createSqlRecoveryPackLockoutStore(
  sql: RecoveryPackLockoutSqlExecutor,
): RecoveryPackLockoutStore {
  return {
    async load(nodeId, operatorId) {
      const { rows } = await sql.query(
        `SELECT fail_count, window_start_ms, locked_until_ms
           FROM operator_recovery_pack_prove_lockout
          WHERE node_id = $1::uuid AND operator_id = $2
          LIMIT 1`,
        [nodeId, operatorId],
      );
      const row = rows[0];
      if (!row) return null;
      const failCount = Number(row["fail_count"] ?? 0);
      const windowStartMs = Number(row["window_start_ms"] ?? 0);
      const lockedRaw = row["locked_until_ms"];
      const lockedUntilMs =
        lockedRaw === null || lockedRaw === undefined ? null : Number(lockedRaw);
      if (!Number.isFinite(failCount) || !Number.isFinite(windowStartMs)) return null;
      return {
        failCount,
        windowStartMs,
        lockedUntilMs:
          lockedUntilMs !== null && Number.isFinite(lockedUntilMs) ? lockedUntilMs : null,
      };
    },
    async save(nodeId, operatorId, snap) {
      await sql.query(
        `INSERT INTO operator_recovery_pack_prove_lockout (
           node_id, operator_id, fail_count, window_start_ms, locked_until_ms, updated_at
         ) VALUES ($1::uuid, $2, $3, $4, $5, now())
         ON CONFLICT (node_id, operator_id) DO UPDATE SET
           fail_count = EXCLUDED.fail_count,
           window_start_ms = EXCLUDED.window_start_ms,
           locked_until_ms = EXCLUDED.locked_until_ms,
           updated_at = now()`,
        [
          nodeId,
          operatorId,
          snap.failCount,
          snap.windowStartMs,
          snap.lockedUntilMs,
        ],
      );
    },
  };
}

export function isProveLocked(
  snap: RecoveryPackLockoutSnapshot | null,
  nowMs: number,
): boolean {
  if (snap?.lockedUntilMs == null) return false;
  return snap.lockedUntilMs > nowMs;
}

/**
 * Record a failed prove. Returns whether the operator is now hard-locked.
 * Clears window when expired; keeps lock until lockedUntilMs.
 */
export async function recordProveFailure(
  store: RecoveryPackLockoutStore,
  nodeId: string,
  operatorId: string,
  nowMs: number,
): Promise<{ locked: boolean; failCount: number }> {
  const existing = await store.load(nodeId, operatorId);
  if (existing?.lockedUntilMs != null && existing.lockedUntilMs > nowMs) {
    return { locked: true, failCount: existing.failCount };
  }

  let failCount = 1;
  let windowStartMs = nowMs;
  if (
    existing &&
    nowMs - existing.windowStartMs < RECOVERY_PACK_PROVE_WINDOW_MS &&
    (existing.lockedUntilMs == null || existing.lockedUntilMs <= nowMs)
  ) {
    failCount = existing.failCount + 1;
    windowStartMs = existing.windowStartMs;
  }

  const locked = failCount >= RECOVERY_PACK_PROVE_FAIL_THRESHOLD;
  const snap: RecoveryPackLockoutSnapshot = {
    failCount,
    windowStartMs,
    lockedUntilMs: locked ? nowMs + RECOVERY_PACK_PROVE_LOCKOUT_MS : null,
  };
  await store.save(nodeId, operatorId, snap);
  return { locked, failCount };
}

/** Clear fail counters after a successful prove (lock already expired or never set). */
export async function clearProveFailures(
  store: RecoveryPackLockoutStore,
  nodeId: string,
  operatorId: string,
  nowMs: number,
): Promise<void> {
  await store.save(nodeId, operatorId, {
    failCount: 0,
    windowStartMs: nowMs,
    lockedUntilMs: null,
  });
}
