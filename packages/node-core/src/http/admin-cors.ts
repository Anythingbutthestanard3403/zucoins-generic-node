// Node admin CORS defaults:
// - no cross-origin access by default
// - allowed origins are explicit exact origins
// - never `*` with credentials
//
// This module is the checkable configuration surface for the admin origin
// policy. Full CORS header emission is shell wiring; the invariants live here
// so a reviewer can grep that no wildcard-with-credentials configuration exists.

export interface AdminCorsConfig {
  /** Exact origins permitted. Empty = no cross-origin access (the default). */
  readonly allowedOrigins: readonly string[];
  /**
   * When true, emit Access-Control-Allow-Credentials. ONLY valid when
   * allowedOrigins is a non-empty explicit list — never with `*`.
   */
  readonly allowCredentials: boolean;
}

/** Default: no cross-origin access, no credentials. */
export const DEFAULT_ADMIN_CORS: AdminCorsConfig = Object.freeze({
  allowedOrigins: Object.freeze([]) as readonly string[],
  allowCredentials: false,
});

export type CorsDecision =
  | { readonly ok: true; readonly allowOrigin: string | null; readonly allowCredentials: boolean }
  | { readonly ok: false; readonly reason: "origin_not_allowed" | "wildcard_with_credentials" };

/**
 * Decide CORS for an inbound Origin. Rejects the illegal `*` + credentials
 * combination structurally — a misconfigured caller cannot produce it.
 */
export function decideAdminCors(
  config: AdminCorsConfig,
  requestOrigin: string | undefined,
): CorsDecision {
  // Structural ban: never allow credentials with a wildcard origin list entry.
  if (config.allowedOrigins.includes("*")) {
    if (config.allowCredentials) {
      return { ok: false, reason: "wildcard_with_credentials" };
    }
    // Bare `*` without credentials is still refused on the admin surface —
    // admin CORS is exact-origin only.
    return { ok: false, reason: "origin_not_allowed" };
  }

  if (requestOrigin === undefined || requestOrigin === "") {
    // No Origin header (same-origin navigations, non-browser clients) — no
    // ACAO header needed; treat as allowed without advertising an origin.
    return { ok: true, allowOrigin: null, allowCredentials: false };
  }

  if (!config.allowedOrigins.includes(requestOrigin)) {
    return { ok: false, reason: "origin_not_allowed" };
  }

  return {
    ok: true,
    allowOrigin: requestOrigin,
    allowCredentials: config.allowCredentials,
  };
}

/** Build a config from an explicit allow-list. Credentials default on when non-empty. */
export function adminCorsFromAllowlist(
  allowedOrigins: readonly string[],
  allowCredentials = allowedOrigins.length > 0,
): AdminCorsConfig {
  if (allowedOrigins.includes("*") && allowCredentials) {
    throw new Error(
      "admin CORS refuses wildcard origin with credentials",
    );
  }
  if (allowedOrigins.includes("*")) {
    throw new Error("admin CORS refuses wildcard origin (exact origins only)");
  }
  return {
    allowedOrigins: Object.freeze([...allowedOrigins]),
    allowCredentials,
  };
}
