// Frozen protocol/pool constants for the v2 generic node.
//
// These values are frozen protocol constants, NOT operator
// configuration knobs. They are exported here so the schema, the scaler, and
// the Docker/deployment manifests read them from one place.
//
// - Pool sizing and backpressure.
// - The single immutable external-send redemption window,
//   byte-frozen into signed inners at sign-intent formation time.

export const POOL_FLOOR = 5;
export const POOL_CAP_CEILING = 500;
export const POOL_CAP_DEFAULT = 50;
export const MINT_BATCH_LIMIT = 5;

export const RECEIVE_QUEUE_MAX_WAIT_DEFAULT_SECONDS = 30;
export const RECEIVE_QUEUE_MAX_WAIT_MIN_SECONDS = 5;
export const RECEIVE_QUEUE_MAX_WAIT_MAX_SECONDS = 3600;

export const SEND_REDEMPTION_WINDOW_SECONDS = 300;

// Defaults for the RECEIVE_EXTERNAL payer-code TTL policy fields
// RECEIVE_TTL_DEFAULT_SECS / _MIN_SECS / _MAX_SECS. 300 s is the published
// API default; 3600 s is the conservative operating margin under the SplitChain future-time
// SplitChain future-time ceiling (which bounds all three, enforced in env-schema.ts);
// 60 s is the smallest window a human payer can realistically redeem in. All three are
// frozen at boot so a formed code's expiry is derived under the policy that formed it.
export const RECEIVE_TTL_DEFAULT_SECS_DEFAULT = 300;
export const RECEIVE_TTL_MIN_SECS_DEFAULT = 60;
export const RECEIVE_TTL_MAX_SECS_DEFAULT = 3600;

// Proof access is available until
// `verification_material_available_until`, default terminal plus 30 days.
export const PROOF_ACCESS_WINDOW_DEFAULT_SECONDS = 30 * 24 * 60 * 60;
export const PROOF_ACCESS_WINDOW_MIN_SECONDS = 60 * 60;

// Default push-notification relay base. Staging may override via
// ZUCOINS_PUSH_API_BASE; the schema validates the override at boot (ZTR-1182).
export const DEFAULT_PUSH_API_BASE = "https://wallet.zucoins.com/api__v1/";

// Pool target is derived, never a free knob. The v2 draft's
// `POOL_TARGET_AVAILABLE` was DELETED; the target is the canonical
// proportional headroom over live demand, floored and capped:
//   needed = ceil((open_sessions * 11) / 10)   (exact integer form, never the float)
//   pool_target_total = min(max(needed, POOL_FLOOR), pool_cap)
// `openSessions` = live RECEIVE-pinned pool wallets + unassigned CREATED
// receives in queue; send-side source pins excluded.
export function poolTargetTotal(openSessions: number, poolCapTotal: number): number {
  if (!Number.isInteger(openSessions) || openSessions < 0) {
    throw new RangeError("poolTargetTotal: openSessions must be a non-negative integer");
  }
  if (!Number.isInteger(poolCapTotal) || poolCapTotal < POOL_FLOOR) {
    throw new RangeError(`poolTargetTotal: poolCapTotal must be an integer >= ${POOL_FLOOR}`);
  }
  const needed = Math.floor((openSessions * 11 + 9) / 10);
  return Math.min(Math.max(needed, POOL_FLOOR), poolCapTotal);
}
