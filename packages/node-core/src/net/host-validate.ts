// Host / Origin validation against the node's configured identity.
// Applied on admin and streaming (SSE) routes. Exact-string equality; never reflect.

export interface NodeIdentityConfig {
  /** Canonical public hostname(s) the node answers for (Host header), lowercased. */
  readonly allowedHosts: readonly string[];
  /**
   * Exact browser Origin values permitted (admin + SSE). Empty = same-origin only
   * (no Origin header required / Origin optional for non-browser clients).
   */
  readonly allowedOrigins: readonly string[];
}

export type HostValidationOutcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: "host_not_allowed" | "origin_not_allowed" };

function normalizeHost(host: string | undefined): string | null {
  if (host === undefined || host === "") return null;
  // Strip port for comparison when present.
  const bare = host.trim().toLowerCase();
  const withoutPort = bare.includes("]")
    ? bare // ipv6 host:port forms unused here; treat whole string after lowercasing
    : bare.split(":")[0] ?? bare;
  return withoutPort;
}

/**
 * Validate Host (required for browser + reverse-proxy leg) and optional Origin.
 * Missing Host → fail closed on admin/SSE surfaces.
 */
export function validateHostAndOrigin(
  config: NodeIdentityConfig,
  headers: { readonly host?: string; readonly origin?: string },
): HostValidationOutcome {
  const allowedHosts = new Set(
    config.allowedHosts.map((h) => normalizeHost(h)).filter((h): h is string => h !== null),
  );
  if (allowedHosts.size === 0) {
    return { ok: false, reason: "host_not_allowed" };
  }

  const host = normalizeHost(headers.host);
  if (host === null || !allowedHosts.has(host)) {
    return { ok: false, reason: "host_not_allowed" };
  }

  const origin = headers.origin;
  if (origin === undefined || origin === "") {
    // Non-browser / same-origin navigation without Origin is fine once Host matches.
    return { ok: true };
  }

  if (config.allowedOrigins.includes("*")) {
    return { ok: false, reason: "origin_not_allowed" };
  }
  if (!config.allowedOrigins.includes(origin)) {
    return { ok: false, reason: "origin_not_allowed" };
  }
  return { ok: true };
}
