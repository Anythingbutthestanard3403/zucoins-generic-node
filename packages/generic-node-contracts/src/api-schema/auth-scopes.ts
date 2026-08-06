/**
 * SOURCE: the API contract, authentication classes.
 *
 * The closed auth-scope vocabulary. Implementer bearer keys carry resource:action scopes;
 * other auth classes (signed reporting, subscription handle, operator session) are
 * characterized by their capabilities rather than named scopes.
 */

/** Implementer bearer key scopes (resource:action pairs). */
export const IMPLEMENTER_SCOPES = [
  "receive:create",
  "receive:read",
  "move:create",
  "move:read",
  "send:create",
  "send:read",
  "destination:create",
  "destination:read",
] as const;

export type ImplementerScope = (typeof IMPLEMENTER_SCOPES)[number];

/** The four authentication classes. */
export const AUTH_CLASSES = [
  "implementer_bearer",
  "signed_reporting_credential",
  "subscription_handle",
  "operator_session",
] as const;

export type AuthClass = (typeof AUTH_CLASSES)[number];

/** The five mandatory signed-reporting headers. */
export const REPORTING_HEADERS = [
  "X-ZP-Reporting-Key-Id",
  "X-ZP-Reporting-Timestamp",
  "X-ZP-Reporting-Expires-At",
  "X-ZP-Reporting-Nonce",
  "X-ZP-Reporting-Signature",
] as const;

/** Capabilities bearer keys explicitly cannot perform. */
export const BEARER_KEY_EXCLUSIONS = [
  "read_raw_verification_material",
  "arm",
  "acknowledge_verification",
  "approve_send",
  "bless_destination",
  "resolve_attention",
] as const;

export const SOURCE = "api-contract: authentication classes" as const;
