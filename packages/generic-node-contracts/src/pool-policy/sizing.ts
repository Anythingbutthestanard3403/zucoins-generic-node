import {
  POOL_FLOOR,
  HEADROOM_NUMERATOR,
  HEADROOM_DENOMINATOR,
  MINT_BATCH_LIMIT,
} from "./constants.js";

// Exact integer ceil-division. Operands are non-negative safe integers (counts bounded by
// pool_cap), so `Math.floor` + remainder is exact — this is the whole point of the frozen rule: never the
// float `open_sessions * 1.10`, whose representation error over-mints a permanent key.
function ceilDiv(numerator: number, denominator: number): number {
  const quotient = Math.floor(numerator / denominator);
  return numerator % denominator === 0 ? quotient : quotient + 1;
}

// Proportional-headroom provisioning TARGET as a total (the receive-queue backpressure rule 1):
// needed = ceil(open_sessions * 11 / 10); target = clamp(needed, POOL_FLOOR, pool_cap).
// The v2 free `POOL_TARGET_AVAILABLE` idle-spare knob is deleted (it over-mints at low load).
export function computeProvisioningTarget(openSessions: number, poolCap: number): number {
  const needed = ceilDiv(openSessions * HEADROOM_NUMERATOR, HEADROOM_DENOMINATOR);
  return Math.min(Math.max(needed, POOL_FLOOR), poolCap);
}

// Keypairs to mint THIS cycle (the receive-queue backpressure rule 3): bounded by the deficit to target, the remaining
// cap headroom (minting STOPS at cap — fail-closed, rule 4), and MINT_BATCH_LIMIT. `capCount`
// counts ALL non-deleted wallets (rule 2). Never negative. Minting alone never closes the
// AVAILABLE deficit — replenishment is the recovery ceremony (the recovery-gated eligibility rule); this only bounds key mint.
export function computeMintBatch(target: number, capCount: number, poolCap: number): number {
  const deficitToTarget = target - capCount;
  const capHeadroom = poolCap - capCount;
  return Math.max(0, Math.min(deficitToTarget, capHeadroom, MINT_BATCH_LIMIT));
}
