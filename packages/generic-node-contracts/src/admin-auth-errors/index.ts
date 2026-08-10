/**
 * Public subpath `@zucoins/generic-node-contracts/admin-auth-errors`.
 *
 * Deferred OPERATOR_SESSION admin-auth error taxonomy (auth-classes.ts J2 /
 * ZTR-1196). Parallel to the public API_ERROR_CODES table — same envelope
 * shape (code, message, request_id, details), distinct code enum.
 */

export {
  type AdminErrorCodeEntry,
  type AdminErrorCode,
  ADMIN_ERROR_CODES,
  ADMIN_ERROR_CODE_SET,
  isAdminErrorCode,
} from "./codes.js";

export {
  ADMIN_ERROR_ENVELOPE_FIELD_ORDER,
  AdminErrorCodeSchema,
  AdminErrorEnvelopeSchema,
  type AdminErrorEnvelope,
  AdminLabReceiveErrorEnvelopeSchema,
  type AdminLabReceiveErrorEnvelope,
  buildAdminErrorBody,
  buildAdminLabReceiveErrorBody,
  coerceAdminErrorCode,
} from "./envelope.js";

export {
  ADMIN_AUTH_ERRORS_CONCERN_MANIFEST,
  buildAdminAuthErrorsManifest,
  type AdminAuthErrorsManifest,
} from "./manifest.js";
