export { checkCsrf, checkCsrfWithApiBypass } from "./csrf.js";
export type { CsrfConfig, CsrfOutcome, CsrfRequest } from "./csrf.js";

export {
  guardedMutation,
  TotpConsumptionLog,
  InMemoryTotpBurnStore,
  verifyTotp,
  matchTotp,
} from "./totp-chain.js";
export type {
  TotpConfig,
  TotpVerifyOutcome,
  TotpVerifyRequest,
  TotpMatchOutcome,
  TotpBurnStore,
} from "./totp-chain.js";
export {
  SqlTotpBurnStore,
  createPoolTotpBurnExecutor,
} from "../totp/burn-store.js";
export type { TotpBurnSqlExecutor } from "../totp/burn-store.js";
export { parseAdminTotpSecret } from "../totp/parse-secret.js";
export {
  decodeBase32,
  encodeBase32,
  generateTotpSecret,
  otpauthUri,
  totpSecretBytes,
} from "../totp/secret.js";

// node-origin admin session substrate.
export {
  ADMIN_SESSION_COOKIE,
  ADMIN_SESSION_IDLE_MS,
  ADMIN_SESSION_TTL_MS,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  assertSecureSessionCookie,
  buildSessionSetCookie,
  createAdminSessionService,
  extractSessionIdFromCookie,
  newAdminUserId,
  requireAdminSession,
  requireActiveTotpFactor,
  requirePasswordChanged,
  requireSessionCsrf,
  requireTotpEnrolled,
  safeEqual,
} from "./admin-session.js";
export type {
  AdminSession,
  AdminSessionConfig,
  AdminSessionService,
  AdminSessionStore,
  AdminSessionStoreSnapshot,
  AdminTotpFactorState,
  AdminUser,
  AdminUserStore,
  AdminUserStoreSnapshot,
  AuthGateOutcome,
  AuthRequest,
  CreateSessionInput,
  CreatedSession,
  SessionCookieOptions,
  SessionRejectionReason,
  SessionValidationResult,
} from "./admin-session.js";

export {
  SqlAdminUserStore,
  VaultSealingNotArmedError,
  createPoolAdminUserExecutor,
} from "./admin-user-sql-store.js";
export type { AdminUserSqlExecutor, TotpVaultRootKey } from "./admin-user-sql-store.js";

export {
  TOTP_SECRET_ENVELOPE_PREFIX,
  TOTP_SECRET_HKDF_LABEL,
  TotpOpenError,
  TotpSealError,
  buildTotpSecretAad,
  buildTotpSecretDekInfo,
  openTotpSecret,
  sealTotpSecret,
  rewrapTotpSecretStore,
  migrateTotpSecretsAtRest,
} from "../totp/index.js";
export type {
  TotpSecretRewrapInput,
  TotpSecretRewrapRow,
  TotpPlaintextMigrationExecutor,
  TotpPlaintextMigrationResult,
} from "../totp/index.js";

export {
  ADMIN_SESSION_SQL,
  SqlAdminSessionStore,
  createPoolAdminSessionExecutor,
  ipForDb,
} from "./admin-session-sql-store.js";
export type { AdminSessionSqlExecutor } from "./admin-session-sql-store.js";

export {
  DEFAULT_ADMIN_USERNAME,
  MIN_PASSWORD_LENGTH,
  bootstrapInitialAdmin,
} from "./admin-bootstrap.js";
export type {
  BootstrapAdminEnv,
  BootstrapAdminLogger,
  BootstrapOutcome,
} from "./admin-bootstrap.js";

export {
  DUMMY_PASSWORD_HASH,
  hashPassword,
  verifyPassword,
} from "./password.js";

// primary pair lock — relocated (was apps/node only).
export {
  IP_LOCK_DURATION_MS,
  IP_LOCK_THRESHOLD,
  IP_LOCK_WINDOW_MS,
  _resetIpLockoutForTests,
  clearIpFailures,
  isIpPairLocked,
  registerIpFailure,
} from "./ip-lockout.js";
export type { IpFailureResult } from "./ip-lockout.js";

// Per-source-IP login volume throttle — the spray-facing complement to the pair lock above.
export {
  LOGIN_RATE_MAX_REQUESTS,
  LOGIN_RATE_WINDOW_MS,
  _resetLoginRateLimitForTests,
  consumeLoginAttempt,
} from "./login-rate-limit.js";

export {
  gateMoneyMutation,
  isUsableLabTotp,
  handleAdminChangePassword,
  handleAdminConfirmTotp,
  handleAdminEnrolTotp,
  handleAdminLogin,
  handleAdminLogout,
  handleAdminMe,
  resolveOperatorTotpConfig,
  rotateSessionsOnTotpReenrolment,
} from "./admin-auth-handlers.js";
export type {
  AdminAuthAudit,
  AuthHttpResult,
  ChangePasswordBody,
  ChangePasswordDeps,
  ConfirmTotpBody,
  ConfirmTotpDeps,
  EnrolTotpBody,
  EnrolTotpDeps,
  GateMoneyMutationOptions,
  LoginBody,
  LoginDeps,
} from "./admin-auth-handlers.js";

export {
  AUTH_FACTOR_FAILURE,
  runGuardedAdminMutation,
} from "./admin-mutation-chain.js";
export type {
  BodyValidationResult,
  GuardedAdminMutationInput,
  GuardedAdminMutationOutcome,
} from "./admin-mutation-chain.js";

export {
  DEFAULT_ADMIN_CORS,
  adminCorsFromAllowlist,
  decideAdminCors,
} from "./admin-cors.js";
export type { AdminCorsConfig, CorsDecision } from "./admin-cors.js";

export { createMetricsRoute, METRICS_CONTENT_TYPE } from "./metrics-route.js";
export type {
  MetricsRouteConfig,
  MetricsRouteHandler,
  MetricsRouteResponse,
} from "./metrics-route.js";

// security headers + CORS emission (two-tier CSP).
export {
  ADMIN_CORS_ALLOW_HEADERS,
  ADMIN_CORS_ALLOW_METHODS,
  ADMIN_CSP,
  HSTS_VALUE,
  NODE_PERMISSIONS_POLICY,
  NODE_SECURITY_HEADERS,
  adminCorsResponseHeaders,
  buildCheckoutCsp,
  computeSecurityHeaders,
  emitAdminCorsHeaders,
  isCheckoutFrameAllowed,
} from "./security-headers.js";
export type {
  SecurityHeadersConfig,
  SecurityHeadersResult,
  SecurityRouteClass,
} from "./security-headers.js";
