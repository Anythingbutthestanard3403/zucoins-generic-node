// the auth-errors/route-policy concern.1 — Public surface of the auth-errors concern. This concern-local barrel is owned
// by the auth-errors slice; it is NOT the package index (src/index.ts, owned by the concern-manifest registry).
// the auth-errors/route-policy concern.2 (middleware/route alignment) and the auth-errors/route-policy concern.3 (credential/error matrix) consume this.

export {
  type AuthErrorCode,
  type AuthErrorCodeName,
  AUTH_ERROR_CODES,
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_NOT_FOUND_CODE,
  REJECTED_AUTH_ERROR_CODES,
  HTTP_STATUS_BY_AUTH_ERROR_CODE,
} from "./codes.js";

export {
  type ReportingRejectionCode,
  REPORTING_REJECTION_CODES,
  REJECTION_STATUS,
  REPORTING_CREDENTIAL_REJECTION_CODES,
  REPORTING_REQUEST_SHAPE_401_CODES,
  reportingWireCode,
} from "./reporting-rejection.js";

export {
  type ErrorEnvelope,
  ERROR_ENVELOPE_FIELD_ORDER,
  REQUEST_ID_PLACEHOLDER,
  CANONICAL_AUTH_FAILURE_MESSAGE,
  CANONICAL_NOT_FOUND_MESSAGE,
  buildAuthErrorBody,
  CANONICAL_AUTH_FAILURE_BODY,
  CANONICAL_NOT_FOUND_BODY,
  CANONICAL_AUTH_ERROR_HEADERS,
} from "./envelope.js";

export {
  type AuthFailureState,
  AUTH_FAILURE_STATE_TO_CODE,
  AUTH_CHECK_ORDER,
} from "./classes.js";

export {
  type WireResponse,
  normalizeRequestId,
  canonicalizeHeaders,
  indistinguishable,
  firstOracleDivergence,
  isNonOracular,
} from "./non-oracular.js";

export { SHA256_AUTH_FAILURE_BODY, SHA256_NOT_FOUND_BODY } from "./digests.js";

export {
  type AuthErrorsManifest,
  authErrorsConcernManifest,
  buildAuthErrorsManifest,
} from "./manifest.js";
