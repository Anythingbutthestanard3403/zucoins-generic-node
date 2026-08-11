// browser and API security headers for the generic node.
// Framework-agnostic pure functions. CORS decision logic lives in ./admin-cors.ts; cookie
// SameSite/HttpOnly/Secure lives in ./admin-session.ts — this module owns CSP tiers,
// HSTS/hardening headers, and header-bag assembly per route class.

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


function defaultRequestId(): string {
  return crypto.randomUUID();
}
