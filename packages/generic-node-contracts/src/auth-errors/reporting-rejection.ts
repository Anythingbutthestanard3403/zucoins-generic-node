//  / UP-09 — Frozen reporting rejection taxonomy (code → HTTP status).
//
// The error envelope contract (clients branch
// only on `code`; 401 for every authentication-class failure, never 403 — no cross-tenant
// existence oracle) and the operations-recovery reporting-rejection rules. The platform dark-period detector keys on
// `reporting_auth_hold`.
//
// Lives here so the platform imports from `@zucoins/generic-node-contracts` rather than
// retyping strings or reaching into node-core. node-core re-exports the same frozen set.
//
// The code set below is the INTERNAL vocabulary. What each code is allowed to put on the wire
// is `reportingWireCode()` at the foot of this file: the six credential-state codes collapse to
// the single CANONICAL_AUTH_FAILURE_CODE that AUTH_CLASS_POLICY.REPORTING_CREDENTIAL freezes,
// and the specific reason is kept server-side against the request_id instead.

import { CANONICAL_AUTH_FAILURE_CODE } from "./codes.js";

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

// The credential-state slice of the taxonomy. Each of these is decided by looking up the
// presented key's registration, its lifecycle head, its signature, or its burnt nonce — so the
// code itself answers "is this key id registered here / does it belong to me / is it live" for
// a caller holding nothing but a guess. Strung together across attempts that is a key-and-tenant
// enumeration channel, on the tenant-scoped multi-implementer surface where it matters most.
// AUTH_CLASS_POLICY.REPORTING_CREDENTIAL freezes the class as `nonOracularFrozen`, so all six
// render as one opaque code; `firstReportingTaxonomyLeak()` in route-policy/verifier.ts holds
// the two contracts together. The strings stay in REPORTING_REJECTION_CODES because they remain
// the internal vocabulary of the server-side record.
export const REPORTING_CREDENTIAL_REJECTION_CODES = [
  "unknown_reporting_key",
  "tenant_binding_mismatch",
  "reporting_key_not_active",
  "reporting_auth_hold",
  "invalid_signature",
  "nonce_replay",
] as const satisfies readonly ReportingRejectionCode[];

// The remaining 401s. Each is decided from the caller's OWN submitted bytes — bounded shape,
// then the signed time window — strictly before the registration lookup, so it discloses
// nothing about which keys exist on this node and stays distinguishable for diagnosability.
// Every 401 code must sit in exactly one of these two arrays; the verifier fails a 401 that
// sits in neither, so a reject reason added later cannot land undeclared.
export const REPORTING_REQUEST_SHAPE_401_CODES = [
  "missing_reporting_headers",
  "invalid_reporting_window",
  "reporting_request_expired",
  "reporting_request_not_yet_valid",
] as const satisfies readonly ReportingRejectionCode[];

const CREDENTIAL_REJECTIONS: ReadonlySet<string> = new Set(REPORTING_CREDENTIAL_REJECTION_CODES);

// The code a rejection is permitted to put on the wire: the canonical non-oracular failure code
// for every credential-state rejection, the code itself otherwise. This is the SERVED mapping —
// node-core's reporting error emitter renders through it and route-policy's
// `firstReportingTaxonomyLeak()` verifies it, so the two frozen contracts read the same
// function instead of restating each other. A reject reason added later inherits the collapse
// by construction rather than by discipline.
export function reportingWireCode(code: ReportingRejectionCode): string {
  return CREDENTIAL_REJECTIONS.has(code) ? CANONICAL_AUTH_FAILURE_CODE : code;
}
