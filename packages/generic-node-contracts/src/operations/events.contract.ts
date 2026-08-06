/**
 * The frozen state-event reference: durable public events and attention reasons.
 *
 * Transcribed verbatim. The durable public event set is closed at exactly nine values.
 */
export const DURABLE_EVENTS = [
  "receive.ready",
  "receive.landed",
  "internal_move.created",
  "internal_move.landed",
  "external_send.created",
  "external_send.awaiting_redemption",
  "external_send.landed",
  "operation.needs_attention",
  "operation.expired",
] as const;

export type DurableEvent = (typeof DURABLE_EVENTS)[number];

/** The closed `attention_reason` vocabulary. */
export const ATTENTION_REASONS = [
  "GATEWAY_RESPONSE_INVALID",
  "GATEWAY_UNAVAILABLE_BEYOND_BUDGET",
  "UNEXPECTED_HEAD_CHANGE",
  "LINEAGE_GAP",
  "SUBMIT_OUTCOME_AMBIGUOUS",
  "SIGNING_OUTCOME_AMBIGUOUS",
  "DESTINATION_NO_LONGER_BLESSED",
  "T0_RELEASE_MISMATCH",
  "VERIFICATION_REJECTED",
  "VERIFICATION_INDETERMINATE",
  "VERIFICATION_RESOURCE_EXHAUSTED",
  "LEASE_INVARIANT_VIOLATION",
  "EXACT_BYTES_UNAVAILABLE",
  "OPERATOR_PARKED",
  "POST_EXPIRY_RECONCILING",
] as const;

export type AttentionReason = (typeof ATTENTION_REASONS)[number];

/**
 * Event names that must never appear as Layer-1 public events (legacy product-projection
 * vocabulary).
 */
export const FORBIDDEN_EVENT_ALIASES = [
  "transfer.confirmed",
  "transfer.finalised", // contract-allow:forbidden-alias-citation
  "sweep.settled", // contract-allow:forbidden-alias-citation
  "outbound.settled", // contract-allow:forbidden-alias-citation
] as const;

export const SOURCE = "state-event reference: events, attention reasons, forbidden aliases" as const;
