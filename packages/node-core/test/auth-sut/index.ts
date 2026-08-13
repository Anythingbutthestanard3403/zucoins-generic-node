/**
 * Non-frozen auth product surface for HTTP auth fuzz + abuse suites.
 *
 * Relocated so packages/node-core tests never import apps/node.
 * Independent reference oracles live in http-auth-fuzz-oracles.ts; this kit is
 * the SUT measured against those oracles.
 */
export { errorBody, type ErrorEnvelopeBody } from "./errors.js";
export {
  ACTION_KEY_KINDS,
  REPORTING_KEY_KINDS,
  SESSION_KEY_KINDS,
  authenticateApiKey,
  verifyApiKey,
  type ApiKeyDb,
  type AuthenticatedApiKey,
} from "./verify.js";
export {
  KEY_SCHEME_PREFIX,
  SITE_KEY_LOOKUP_PREFIX_LENGTH,
  generateApiKey,
  kindForToken,
  lookupPrefix,
  sha256Hex,
  sha256Matches,
  type ApiKeyKind,
  type GeneratedApiKey,
} from "./keygen.js";
export {
  requireCsrf,
  requireCsrfUnlessActionKey,
  requirePasswordChanged,
  requireTotpConfirmed,
  type AuthMode,
  type AuthUser,
  type GateContext,
  type GateHandler,
  type GateNext,
} from "./middleware-gates.js";
export {
  changePasswordSchema,
  confirmTotpSchema,
  enrolTotpSchema,
  loginSchema,
  type ChangePasswordInput,
  type ConfirmTotpInput,
  type EnrolTotpInput,
  type LoginInput,
} from "./schemas.js";

export {
  IP_LOCK_DURATION_MS,
  IP_LOCK_THRESHOLD,
  IP_LOCK_WINDOW_MS,
  _resetIpLockoutForTests,
  clearIpFailures,
  isIpPairLocked,
  registerIpFailure,
  withIpPairGate,
  type IpFailureResult,
} from "../../src/http/ip-lockout.js";

export { hashPassword, verifyPassword, DUMMY_PASSWORD_HASH } from "../../src/http/password.js";
