/**
 * SOURCE: the API contract, error envelope.
 *
 * The exact HTTP status codes and their meanings from the error envelope specification.
 * Every non-2xx JSON response uses the envelope: { error: { code, message, request_id, details } }.
 * `message` is diagnostic, not stable. Clients branch only on `code`.
 */

export interface HttpStatusEntry {
  readonly status: number;
  readonly meaning: string;
}

/** The closed HTTP status vocabulary for non-2xx responses. */
export const HTTP_ERROR_STATUSES: readonly HttpStatusEntry[] = [
  { status: 400, meaning: "Malformed JSON, invalid scalar, unknown field, or impossible shape." },
  { status: 401, meaning: "Missing/invalid/expired authentication or TOTP (scope denial collapses to the same generic 401; no 403)." },
  { status: 404, meaning: "Object is absent or outside the authenticated tenant." },
  {
    status: 409,
    meaning: "Idempotency, state-version, active-lease, T0, or other concurrent-state conflict.",
  },
  {
    status: 410,
    meaning: "Verification-material access window has expired. The underlying ledger is not deleted.",
  },
  { status: 422, meaning: "Well-formed request fails a custody/protocol predicate." },
  { status: 429, meaning: "Principal rate limit exceeded." },
  {
    status: 503,
    meaning:
      "Bounded queue is full, signer leadership unavailable, or required gateway evidence cannot currently be obtained.",
  },
] as const;

/** The exact error envelope field names. */
export const ERROR_ENVELOPE_FIELDS = ["code", "message", "request_id", "details"] as const;

/** Named error codes cited in the API contract (non-exhaustive but frozen as cited). */
export const CITED_ERROR_CODES = [
  "wallet_busy",
  "unknown_field",
  "receive_queue_full",
  "t0_mismatch",
  "operation_version_conflict",
  "operation_not_armable",
  "verification_material_not_ready",
  "verification_material_expired",
  "cursor_mismatch",
] as const;

export type CitedErrorCode = (typeof CITED_ERROR_CODES)[number];

export const SOURCE = "api-contract: error vocabulary" as const;
