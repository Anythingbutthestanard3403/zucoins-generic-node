/**
 * Candidate intake and gateway transport + submit-ack semantics. Frozen: form transport +
 * response shape, the receiver-channel action literals, and status:true as receipt-only.
 *
 * Freezes the candidate-intake surface (the SplitChain-compatible receiver channel that delivers an
 * external-sender step-1 partial into a RECEIVE_EXTERNAL) and the official gateway form transport + single
 * submit. CONTRACT_FREEZE: no gateway client, network, DB, or keys — frozen literals and pure
 * validators only.
 */

/**
 * The candidate-intake channel is an internal protocol adapter, NOT a fourth public money-operation
 * endpoint. The node's own public route/auth/rate-limit for that adapter is a runtime seam
 * and is deliberately not frozen by v2 — see this package's PR description for the reported gap.
 */
export const CANDIDATE_INTAKE_IS_PUBLIC_OPERATION_ENDPOINT = false;

/**
 * Raw-capture rule: the candidate's exact `inner_preimage_text` and `step_1_signature`
 * bytes are captured BEFORE any parse, so the external-sender step-1 signature is verified over the
 * exact captured inner text (never a reserialized object).
 */
export const CANDIDATE_RAW_CAPTURE_FIELDS = ["inner_preimage_text", "step_1_signature"] as const;

/**
 * Locate keys: a candidate is bound to its receive by these fields; candidates for an
 * unarmed operation are refused, and exactly one candidate may win the unique receive-attempt slot
 *.
 */
export const CANDIDATE_LOCATE_KEYS = [
  "receiver_pubkey",
  "discriminator",
  "expiry",
  "active_lease",
] as const;

export const REFUSE_CANDIDATE_WHEN_UNARMED = true;
export const SINGLE_CANDIDATE_WINS_RECEIVE_ATTEMPT = true;

/**
 * Wallet-compatible receiver-channel transport (frozen action literals). A real wallet delivers an external-sender
 * partial as this action carrying the encoded sender code; the adapter accepts these exact literals. `zp1:`,
 * `zupay`, and these `zucoin_wallet_*__v1` names are frozen compatibility literals.
 */
export const RECEIVER_CHANNEL_ACTION_NAME = "zucoin_wallet_sender_partial_transfer_code__v1";
export const RECEIVER_CHANNEL_ACTION_DATA_FIELD = "sender_transfer_code_encoded";

/**
 * Official gateway form transport (frozen form transport). The request body is exactly
 * `v=<encodeURIComponent(JSON.stringify({action_name, action_data}))>`, with the action object's two
 * fields in this exact sequence. Read retry is bounded/jittered and only for transport ambiguity;
 * submit is single-shot per authorized attempt.
 */
export const GATEWAY_FORM_BODY_PARAM = "v";
export const GATEWAY_ACTION_FIELDS = ["action_name", "action_data"] as const;
export const GATEWAY_FORM_BODY_TEMPLATE =
  "v=<encodeURIComponent(JSON.stringify({action_name,action_data}))>" as const;

/**
 * Gateway response envelope (frozen response shape): `{status, code, message, data}`. The complete HTTP response body
 * is captured as raw bytes with its SHA-256 BEFORE decoding or JSON parsing; it is evidence,
 * not a signed blob.
 */
export const GATEWAY_RESPONSE_FIELDS = ["status", "code", "message", "data"] as const;
export const GATEWAY_RESPONSE_CAPTURED_RAW_BEFORE_DECODE = true;

/**
 * Single submit. `submit_transaction__v1` is never blind-retried; a read failure, timeout, malformed
 * reply, or ambiguous head creates no submit authority.
 */
export const SUBMIT_ACTION_NAME = "submit_transaction__v1";
export const SUBMIT_IS_SINGLE_SHOT = true;
export const SUBMIT_BLIND_RETRY_ALLOWED = false;

/**
 * Submit-acknowledgement semantics (receipt-only). A `status:true`
 * acknowledgement is receipt-only and NEVER settlement — a fresh signature-verified chain observation
 * is required before a landed state.
 */
export const SUBMIT_ACK_STATUS_TRUE_MEANS_SETTLED = false;

/**
 * The closed set of submit outcome categories. Only the two verified-landing categories mark a
 * transaction landed; a receipt acknowledgement does not.
 */
export const SUBMIT_OUTCOME_CATEGORIES = [
  "deterministic_rejection",
  "receipt_acknowledgement",
  "indeterminate_transport",
  "verified_exact_landing",
  "verified_complete_path_landing",
  "incomplete_or_conflicting_or_resource_exhausted",
  "regression_or_gap_or_unrelated_or_unverifiable",
] as const;

export type SubmitOutcomeCategory = (typeof SUBMIT_OUTCOME_CATEGORIES)[number];

export const SUBMIT_LANDED_OUTCOME_CATEGORIES = [
  "verified_exact_landing",
  "verified_complete_path_landing",
] as const;

/**
 * Expiry byte fields on the intake/submit surface use the same seconds unit as the transfer-code and
 * the SplitChain inner (field 13; A.8). The inner `expiry__unix_time_secs` precedes `message`
 * when present. The unit is seconds, never milliseconds.
 */
export const INTAKE_EXPIRY_FIELD = "expiry__unix_time_secs";
export const INTAKE_EXPIRY_UNIT = "seconds";

export const SOURCE =
  "candidate intake; gateway transport and submit-ack semantics; form-transport; submit-ack-receipt-only; receiver-channel-literals" as const;
