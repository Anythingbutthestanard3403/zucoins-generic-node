// the named concern — receive expiry lifecycle. Frozen states, terminality, and the pre/post-boundary
// expiry legality (the receive-expiry rule stricter branch: PREVENT terminal expiry after the durable-candidate
// boundary). Data + pure predicates; no DB code.

export const RECEIVE_STATES = [
  "CREATED",
  "READY",
  "EXPIRED",
  "RECEIVE_LANDED",
  "INDETERMINATE",
] as const;
export type ReceiveState = (typeof RECEIVE_STATES)[number];

// The ONE new vocabulary member introduced by the receive-expiry rule — an attention_reason. No new state, event
// or TTL is added.
export const POST_EXPIRY_RECONCILING = "POST_EXPIRY_RECONCILING" as const;

// Terminal states carry a terminal timestamp; non-terminal states stay open indefinitely. EXPIRED
// (only reachable pre-boundary) and RECEIVE_LANDED are terminal; CREATED / READY / INDETERMINATE
// are non-terminal (a post-boundary receive stays READY and reconciles indefinitely).
export const TERMINAL_RECEIVE_STATES = ["EXPIRED", "RECEIVE_LANDED"] as const;

export function isTerminalReceiveState(state: ReceiveState): boolean {
  return (TERMINAL_RECEIVE_STATES as readonly string[]).includes(state);
}

// Terminal expiry (-> EXPIRED) is legal ONLY before the durable-candidate boundary. Post-boundary,
// CREATED / READY -> EXPIRED is forbidden (this is the hole the receive-expiry rule closes).
export function isExpiryToExpiredLegal(from: ReceiveState, pastBoundary: boolean): boolean {
  if (pastBoundary) return false;
  return from === "CREATED" || from === "READY";
}

export type PostBoundaryExpiryOutcome = {
  readonly state: "READY";
  readonly attentionReason: typeof POST_EXPIRY_RECONCILING;
  readonly leaseHeld: true;
  readonly appendsNeedsAttention: true;
  readonly appendsExpiredEvent: false;
};

// Post-boundary, an expiry attempt keeps the receive READY, holds the lease (the one-in-flight-per-wallet rule), and
// appends operation.needs_attention with POST_EXPIRY_RECONCILING — NEVER operation.expired.
export const POST_BOUNDARY_EXPIRY_OUTCOME: PostBoundaryExpiryOutcome = {
  state: "READY",
  attentionReason: POST_EXPIRY_RECONCILING,
  leaseHeld: true,
  appendsNeedsAttention: true,
  appendsExpiredEvent: false,
};

// Event sequencing: pre-boundary expiry appends the terminal operation.expired; post-boundary appends
// operation.needs_attention and NEVER operation.expired.
export function receiveExpiryEvents(pastBoundary: boolean): {
  readonly appendsExpired: boolean;
  readonly appendsNeedsAttention: boolean;
} {
  if (pastBoundary) return { appendsExpired: false, appendsNeedsAttention: true };
  return { appendsExpired: true, appendsNeedsAttention: false };
}
