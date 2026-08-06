import { computeProvisioningTarget, computeMintBatch } from "./sizing.js";

// the named concern — scale-up serialization contract. Frozen data + a pure model of the serialized mint
// decision; no DB code. One scaler per node mints at a time under an advisory lock, re-reading the
// wallet count UNDER the lock before computing the batch, so concurrent scalers cannot double-mint
// past cap (the frozen rule CAS; the receive-queue backpressure rule rules 2-4).

// Advisory-lock namespace for scale-up serialization. the DB-domains concern binds it to pg_advisory_xact_lock.
export const SCALE_UP_ADVISORY_LOCK_NAMESPACE = "pool_scale_up" as const;

// Count query re-read UNDER the advisory lock. Cap counts ALL non-deleted wallets (the receive-queue backpressure rule 2);
// DELETE is grant-revoked, so every row counts. Contract-level SQL text (frozen DATA; bindable).
export const CAP_COUNT_UNDER_LOCK_SQL = "SELECT count(*) AS cap_count FROM wallets";

// Demand-side composition of `open_sessions` (the receive-queue backpressure rule 1), the driver of the provisioning
// target, is frozen in its own module (`open-sessions.ts`) symmetric with this module's own
// CAP_COUNT_UNDER_LOCK_SQL supply-side count — see that module for `OPEN_SESSIONS_COUNT_SQL` /
// `OPEN_SESSIONS_COMPONENTS` / `OPEN_SESSIONS_EXCLUDED_COMPONENTS`. Re-read UNDER the same
// advisory lock as CAP_COUNT_UNDER_LOCK_SQL so demand and supply are consistent at the mint
// decision.

// Pure model of the serialized scale-up decision, evaluated with the count re-read under the lock.
// Because the count is re-read under the lock, a second serialized scaler observes the first's mint
// and never exceeds cap (see the naive-vs-serialized invariant in the tests).
export function planScaleUp(input: {
  readonly openSessions: number;
  readonly capCountUnderLock: number;
  readonly poolCap: number;
}): number {
  const target = computeProvisioningTarget(input.openSessions, input.poolCap);
  return computeMintBatch(target, input.capCountUnderLock, input.poolCap);
}
