//  / UP-09 — Frozen reporting rejection taxonomy (code → HTTP status).
//
// The error envelope contract (clients branch
// only on `code`; 401 for every authentication-class failure, never 403 — no cross-tenant
// existence oracle) and the operations-recovery reporting-rejection rules. The platform dark-period detector keys on
// `reporting_auth_hold`.
//
// Lives here so the platform imports from `@zucoins/generic-node-contracts` rather than
// retyping strings or reaching into node-core. node-core re-exports the same frozen set.

export const REPORTING_REJECTION_CODES = [
  "missing_reporting_headers",
  "invalid_reporting_headers",
  "invalid_request_target",
  "not_found",
  "request_too_large",
  "invalid_idempotency_key",
  "unsupported_content_encoding",
  "rate_limited",
  "invalid_reporting_window",
  "reporting_request_expired",
  "reporting_request_not_yet_valid",
  "unknown_reporting_key",
  "tenant_binding_mismatch",
  "reporting_key_not_active",
  "reporting_auth_hold",
  "invalid_signature",
  "nonce_replay",
  "idempotency_conflict",
  "internal_error",
] as const;

export type ReportingRejectionCode = (typeof REPORTING_REJECTION_CODES)[number];

export const REJECTION_STATUS: Readonly<Record<ReportingRejectionCode, number>> = {
  missing_reporting_headers: 401,
  invalid_reporting_headers: 400,
  invalid_request_target: 400,
  not_found: 404,
  request_too_large: 400,
  invalid_idempotency_key: 400,
  unsupported_content_encoding: 400,
  rate_limited: 429,
  invalid_reporting_window: 401,
  reporting_request_expired: 401,
  reporting_request_not_yet_valid: 401,
  unknown_reporting_key: 401,
  tenant_binding_mismatch: 401,
  reporting_key_not_active: 401,
  reporting_auth_hold: 401,
  invalid_signature: 401,
  nonce_replay: 401,
  idempotency_conflict: 409,
  internal_error: 500,
};
