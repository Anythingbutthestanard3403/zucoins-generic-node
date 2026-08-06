// browser and API security headers for the generic node.
// Framework-agnostic pure functions. CORS decision logic lives in ./admin-cors.ts; cookie
// SameSite/HttpOnly/Secure lives in ./admin-session.ts — this module owns CSP tiers,
// HSTS/hardening headers, and header-bag assembly per route class.

import {
  decideAdminCors,
  type AdminCorsConfig,
  type CorsDecision,
} from "./admin-cors.js";

/** Route classes that select CSP / framing policy (ticket AC: per-route-class). */
export type SecurityRouteClass = "admin" | "public_api" | "checkout_embed";

export const HSTS_VALUE = "max-age=31536000; includeSubDomains";

export const ADMIN_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

/**
 * Checkout/embed tier: frame-ancestors is merchant-scoped only. // contract-allow:checkout,merchant:frozen structural vocabulary
 * Never emits a wildcard `*`. Empty allowlist → `'self'` only.
 */
export function buildCheckoutCsp(
  merchantFrameAncestors: readonly string[] = [],
): string {
  const ancestors = ["'self'"];
  for (const origin of merchantFrameAncestors) {
    if (origin === "*" || origin.includes("*")) {
      throw new Error("checkout CSP refuses wildcard frame-ancestors"); // contract-allow:checkout:frozen structural vocabulary
    }
    if (origin.length === 0) continue;
    if (!ancestors.includes(origin)) ancestors.push(origin);
  }
  return [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "object-src 'none'",
    `frame-ancestors ${ancestors.join(" ")}`,
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
}

export const NODE_PERMISSIONS_POLICY = [
  "camera=()",
  "microphone=()",
  "geolocation=()",
  "usb=()",
  "magnetometer=()",
  "gyroscope=()",
  "accelerometer=()",
  "ambient-light-sensor=()",
  "autoplay=()",
  "fullscreen=(self)",
  "picture-in-picture=(self)",
].join(", ");

/** Admin/platform baseline (no frame-ancestors wildcard, no external script). */
export const NODE_SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "Content-Security-Policy": ADMIN_CSP,
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": HSTS_VALUE,
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": NODE_PERMISSIONS_POLICY,
});

export interface SecurityHeadersConfig {
  readonly newRequestId?: () => string;
  /** Merchant origins allowed to embed checkout (checkout_embed class only). */ // contract-allow:checkout,merchant:frozen structural vocabulary
  readonly merchantFrameAncestors?: readonly string[];
}

export interface SecurityHeadersResult {
  readonly headers: Readonly<Record<string, string>>;
  readonly requestId: string;
  readonly routeClass: SecurityRouteClass;
}

/**
 * Build the hardened header bag for a route class.
 * HSTS is always present (including for error responses — shell applies unconditionally).
 */
export function computeSecurityHeaders(
  routeClass: SecurityRouteClass = "admin",
  existingRequestId?: string,
  config?: SecurityHeadersConfig,
): SecurityHeadersResult {
  const requestId = existingRequestId ?? (config?.newRequestId ?? defaultRequestId)();
  const base: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": HSTS_VALUE,
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": NODE_PERMISSIONS_POLICY,
    "X-Request-Id": requestId,
  };

  if (routeClass === "checkout_embed") {
    base["Content-Security-Policy"] = buildCheckoutCsp(config?.merchantFrameAncestors ?? []);
    // frame-ancestors owns framing; omit X-Frame-Options so CSP wins for embed allowlist.
  } else if (routeClass === "public_api") {
    base["Content-Security-Policy"] = ADMIN_CSP;
    base["X-Frame-Options"] = "DENY";
  } else {
    // admin
    base["Content-Security-Policy"] = ADMIN_CSP;
    base["X-Frame-Options"] = "DENY";
  }

  return {
    headers: Object.freeze(base),
    requestId,
    routeClass,
  };
}

/**
 * Emit CORS response headers for the admin surface from a CorsDecision.
 * Adversarial Origin not on the allowlist yields NO Access-Control-Allow-Origin
 * and never Access-Control-Allow-Credentials (event stream design).
 *
 * Auth/replay-relevant request headers must survive preflight allowlists:
 * Idempotency-Key + the five X-ZP-Reporting-* headers.
 */
export const ADMIN_CORS_ALLOW_HEADERS = Object.freeze([
  "Content-Type",
  "Authorization",
  "Idempotency-Key",
  "X-ZP-Reporting-Credential-Id",
  "X-ZP-Reporting-Timestamp",
  "X-ZP-Reporting-Nonce",
  "X-ZP-Reporting-Signature",
  "X-ZP-Reporting-Key-Id",
  "X-CSRF-Token",
] as const);

export const ADMIN_CORS_ALLOW_METHODS = Object.freeze([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
] as const);

export function emitAdminCorsHeaders(
  decision: CorsDecision,
): Readonly<Record<string, string>> {
  if (!decision.ok || decision.allowOrigin === null) {
    return Object.freeze({});
  }
  const headers: Record<string, string> = {
    "Access-Control-Allow-Origin": decision.allowOrigin,
    "Access-Control-Allow-Methods": ADMIN_CORS_ALLOW_METHODS.join(", "),
    "Access-Control-Allow-Headers": ADMIN_CORS_ALLOW_HEADERS.join(", "),
    Vary: "Origin",
  };
  // Credentials deliberately OFF even when origin matches unless decision says otherwise.
  // Default admin surface: no credentials (ticket AC). When config enables credentials
  // AND origin matches, allowCredentials may be true — but still never with wildcard.
  if (decision.allowCredentials) {
    headers["Access-Control-Allow-Credentials"] = "true";
  }
  return Object.freeze(headers);
}

/** Convenience: decide + emit in one pure call. */
export function adminCorsResponseHeaders(
  config: AdminCorsConfig,
  requestOrigin: string | undefined,
): Readonly<Record<string, string>> {
  return emitAdminCorsHeaders(decideAdminCors(config, requestOrigin));
}

/**
 * Whether an embed Origin is permitted under checkout frame-ancestors allowlist. // contract-allow:checkout:frozen structural vocabulary
 * Exact-string equality (never reflect).
 */
export function isCheckoutFrameAllowed(
  requestOrigin: string | undefined,
  merchantFrameAncestors: readonly string[],
): boolean {
  if (requestOrigin === undefined || requestOrigin === "") return false;
  if (merchantFrameAncestors.includes("*")
    || merchantFrameAncestors.some((o) => o.includes("*"))
  ) {
    return false;
  }
  return merchantFrameAncestors.includes(requestOrigin);
}

function defaultRequestId(): string {
  return crypto.randomUUID();
}
