import type { DurableEvent } from "./events.contract.ts";

/**
 * The frozen state-event reference: per-kind operation states and transitions.
 *
 * Transcribed verbatim. Execution phase is a derived diagnostic, explicitly "not a stored
 * `operations` column" — it is not a Layer-1 operation state and is intentionally absent
 * from this file.
 */
export const RECEIVE_EXTERNAL_STATES = ["CREATED", "READY", "RECEIVE_LANDED", "EXPIRED"] as const;

export const MOVE_INTERNAL_STATES = ["CREATED", "INTERNAL_MOVE_LANDED", "NEEDS_ATTENTION"] as const;

export const SEND_EXTERNAL_STATES = [
  "CREATED",
  "APPROVED",
  "AWAITING_REDEMPTION",
  "EXTERNAL_SEND_LANDED",
  "REJECTED",
  "NEEDS_ATTENTION",
] as const;

export type ReceiveExternalState = (typeof RECEIVE_EXTERNAL_STATES)[number];
export type MoveInternalState = (typeof MOVE_INTERNAL_STATES)[number];
export type SendExternalState = (typeof SEND_EXTERNAL_STATES)[number];

export const OPERATION_STATES = {
  RECEIVE_EXTERNAL: RECEIVE_EXTERNAL_STATES,
  MOVE_INTERNAL: MOVE_INTERNAL_STATES,
  SEND_EXTERNAL: SEND_EXTERNAL_STATES,
} as const;

/**
 * Values that must never appear as Layer-1 operation states (legacy product-projection
 * vocabulary, including business-status framings of protocol facts).
 */
export const FORBIDDEN_STATE_ALIASES = [
  "RESERVED",
  "OBSERVED",
  "CONFIRMED",
  "FINALISED", // contract-allow:forbidden-alias-citation
  "PAID",
  "HELD",
  "REFUNDED", // contract-allow:forbidden-alias-citation
  "SUBMITTED",
  "FAILED",
  "SETTLED",
] as const;

/**
 * Some guarded transitions fire no durable public event but are still operator-audited; the
 * transition tables spell out which audit variant verbatim ("none", "none; audit only",
 * "none; operator audit only") rather than collapsing them to one marker.
 */
export const NO_EVENT_MARKERS = ["none", "none; audit only", "none; operator audit only"] as const;

export type NoEventMarker = (typeof NO_EVENT_MARKERS)[number];

export interface StateTransition<S extends string> {
  readonly from: S | null;
  readonly to: S;
  readonly guard: string;
  readonly event: DurableEvent | NoEventMarker;
  readonly precondition?: string;
}

/**
 * The landing-proof contract provides an any-depth LANDING oracle but explicitly NO generic
 * `PROVEN_NOT_LANDED` oracle. Transitions carrying this precondition require a positive
 * non-landing proof/oracle that does not exist at launch, so they are reserved capacity:
 * they remain in the census but cannot fire at runtime.
 */
export const PROVEN_NOT_LANDED_ORACLE_REQUIRED = "PROVEN_NOT_LANDED_ORACLE_REQUIRED" as const;

/** RECEIVE_EXTERNAL transitions. `from: null` represents no prior state (creation). */
export const RECEIVE_EXTERNAL_TRANSITIONS: readonly StateTransition<ReceiveExternalState>[] = [
  { from: null, to: "CREATED", guard: "Idempotent request accepted.", event: "none" },
  {
    from: "CREATED",
    to: "READY",
    guard:
      "Receiver lease held; validated T0 observation, exact code hash, artifact, expiry, and verification material committed atomically.",
    event: "receive.ready",
  },
  {
    from: "CREATED",
    to: "EXPIRED",
    guard: "Queue wait exceeded before wallet assignment.",
    event: "operation.expired",
  },
  {
    from: "READY",
    to: "RECEIVE_LANDED",
    guard:
      "Persisted inbound attempt is connected to a fresh authoritative receiver observation and economic predicate passes.",
    event: "receive.landed",
  },
  {
    from: "READY",
    to: "EXPIRED",
    guard:
      "TTL passed without a landed attempt. Assigned wallet stays leased until exact T0 release proof.",
    event: "operation.expired",
  },
] as const;

/** MOVE_INTERNAL transitions. */
export const MOVE_INTERNAL_TRANSITIONS: readonly StateTransition<MoveInternalState>[] = [
  {
    from: null,
    to: "CREATED",
    guard: "Source and destination references pass static validation.",
    event: "internal_move.created",
  },
  {
    from: "CREATED",
    to: "INTERNAL_MOVE_LANDED",
    guard:
      "Exact persisted attempt is verified on authoritative lineage and both economic projections pass.",
    event: "internal_move.landed",
  },
  {
    from: "CREATED",
    to: "NEEDS_ATTENTION",
    guard: "Outcome cannot be safely classified within the retry budget.",
    event: "operation.needs_attention",
  },
  {
    from: "NEEDS_ATTENTION",
    to: "INTERNAL_MOVE_LANDED",
    guard: "Later reconciliation verifies the same exact attempt landed.",
    event: "internal_move.landed",
  },
  {
    from: "NEEDS_ATTENTION",
    to: "CREATED",
    guard:
      "Operator requests rebuild and the node has positive non-landing proof for the archived attempt.",
    event: "none; audit only",
    precondition: PROVEN_NOT_LANDED_ORACLE_REQUIRED,
  },
] as const;

/** SEND_EXTERNAL transitions. */
export const SEND_EXTERNAL_TRANSITIONS: readonly StateTransition<SendExternalState>[] = [
  {
    from: null,
    to: "CREATED",
    guard: "Idempotent request accepted; no lease or partial exists.",
    event: "external_send.created",
  },
  {
    from: "CREATED",
    to: "APPROVED",
    guard:
      "Fresh single-use TOTP authenticates the guarded approval and consumes the current exact challenge. When device signing is enabled, a valid device signature is required in addition to TOTP.",
    event: "none; operator audit only",
  },
  {
    from: "CREATED",
    to: "REJECTED",
    guard: "Operator rejects before approval.",
    event: "none; operator audit only",
  },
  {
    from: "APPROVED",
    to: "AWAITING_REDEMPTION",
    guard:
      "Source lease held; T0, exact preimage, deterministic step-1 signature, partial bytes, and delivery hash are durable.",
    event: "external_send.awaiting_redemption",
  },
  {
    from: "APPROVED",
    to: "NEEDS_ATTENTION",
    guard: "First formation cannot be proven never-started or exact durable bytes are unavailable.",
    event: "operation.needs_attention",
  },
  {
    from: "APPROVED",
    to: "REJECTED",
    guard:
      "Operator closes an approval for which durable phase/audit evidence proves signing never started and no partial exists.",
    event: "none; operator audit only",
  },
  {
    from: "AWAITING_REDEMPTION",
    to: "EXTERNAL_SEND_LANDED",
    guard: "The exact partial's completed transaction is verified on authoritative source lineage.",
    event: "external_send.landed",
  },
  {
    from: "AWAITING_REDEMPTION",
    to: "NEEDS_ATTENTION",
    guard: "Head movement, expiry, or evidence gap cannot be classified safely.",
    event: "operation.needs_attention",
  },
  {
    from: "NEEDS_ATTENTION",
    to: "AWAITING_REDEMPTION",
    guard:
      "Operator chooses continue-wait/redeliver and the node can serve the identical persisted partial.",
    event: "none; audit only",
  },
  {
    from: "NEEDS_ATTENTION",
    to: "EXTERNAL_SEND_LANDED",
    guard: "Later reconciliation verifies the exact attempt landed.",
    event: "external_send.landed",
  },
  {
    from: "NEEDS_ATTENTION",
    to: "REJECTED",
    guard:
      "Exact partial is protocol-expired and the positive non-landing oracle proves it did not land and cannot still land.",
    event: "none; operator audit only",
    precondition: PROVEN_NOT_LANDED_ORACLE_REQUIRED,
  },
] as const;

export const SOURCE = "state-event reference: states, transitions, forbidden aliases" as const;
