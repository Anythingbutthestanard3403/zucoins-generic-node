// Receive-pool sizing / retirement policy constants. Frozen per the receive-queue
// backpressure rule, its dual-run addendum, and the recovery-gated eligibility refinement. Native
// integer/count values only — this concern uses NO bignumber and no cross-concern import; pool
// policy is exact integer arithmetic over small counts.

export const POOL_FLOOR = 5;
export const POOL_CAP_DEFAULT = 50;
export const POOL_CAP_CEILING = 500;
export const MINT_BATCH_LIMIT = 5;

// 10% proportional headroom as an EXACT integer ratio, never the float `open_sessions * 1.10`
// target = ceil(open_sessions * 11 / 10).
export const HEADROOM_NUMERATOR = 11;
export const HEADROOM_DENOMINATOR = 10;

// Operative queue max-wait (backpressure rule 4). 30s is the weakest-anchored constant; the dual-run
// recommends ~120s (see POOL_POLICY_FLAGS in manifest.ts). The operative value stays 30s pending
// an operator confirmation.
export const RECEIVE_QUEUE_MAX_WAIT_MS = 30_000;

// Retry-After (seconds) for the 503 receive_queue_full reject (backpressure rule 4). DERIVED, not an
// independent magic number: it is the max-wait window, the soonest a queued receive expires and
// frees a slot, so a retry earlier than this cannot be admitted. Tracks RECEIVE_QUEUE_MAX_WAIT_MS
// (if operator raises the max-wait to ~120s, Retry-After follows).
export const RECEIVE_QUEUE_RETRY_AFTER_SECONDS = RECEIVE_QUEUE_MAX_WAIT_MS / 1000;
