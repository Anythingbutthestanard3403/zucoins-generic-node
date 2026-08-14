import {
  POOL_FLOOR,
  SEND_POOL_FLOOR,
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

export type PoolMintRole = "SEND_ONLY" | "RECEIVE_ONLY";

/**
 * Shared-cap planner: two demand signals, one lifetime key count.
 * Deficits are per-role (send-capable vs receive-capable). Cap headroom is
 * still `poolCap - capCount` over ALL wallet rows. Send deficit is minted
 * first (live 503). Receive next. Batch still ≤ MINT_BATCH_LIMIT.
 */
export function planSharedCapMint(input: {
  readonly receiveOpenSessions: number;
  readonly sendOpenSessions: number;
  readonly receiveWalletCount: number;
  readonly sendWalletCount: number;
  readonly capCount: number;
  readonly poolCap: number;
  readonly receiveFloor?: number;
  readonly sendFloor?: number;
}): { readonly sendMint: number; readonly receiveMint: number } {
  const receiveFloor = input.receiveFloor ?? POOL_FLOOR;
  const sendFloor = input.sendFloor ?? SEND_POOL_FLOOR;
  const recvTarget = computeProvisioningTargetWithFloor(
    input.receiveOpenSessions,
    input.poolCap,
    receiveFloor,
  );
  const sendTarget = computeProvisioningTargetWithFloor(
    input.sendOpenSessions,
    input.poolCap,
    sendFloor,
  );
  const sendDeficit = Math.max(0, sendTarget - input.sendWalletCount);
  const receiveDeficit = Math.max(0, recvTarget - input.receiveWalletCount);
  const remainingCap = Math.max(0, input.poolCap - input.capCount);
  let budget = Math.min(remainingCap, MINT_BATCH_LIMIT);
  const sendMint = Math.min(budget, sendDeficit);
  budget -= sendMint;
  const receiveMint = Math.min(budget, receiveDeficit);
  return { sendMint, receiveMint };
}

function computeProvisioningTargetWithFloor(
  openSessions: number,
  poolCap: number,
  floor: number,
): number {
  const needed = ceilDiv(openSessions * HEADROOM_NUMERATOR, HEADROOM_DENOMINATOR);
  return Math.min(Math.max(needed, floor), poolCap);
}
