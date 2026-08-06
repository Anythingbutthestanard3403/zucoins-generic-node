// trusted-proxy client IP derivation.
// Pure + runtime-neutral. Env wiring for TRUST_PROXY_HOPS / TRUST_PROXY_DIRECT_EXPOSURE
// is process configuration resolved by the adapter; this module owns the classifier.

export const DEFAULT_TRUST_PROXY_HOPS = 1;

/**
 * Derive client IP from X-Forwarded-For, trusting the rightmost `trustedHops`
 * entries (proxy-appended). Preceding entries are attacker-controlled.
 * Returns null when the header is absent/empty or shorter than trusted hops.
 */
export function clientIpFromXff(
  xff: string | null | undefined,
  trustedHops = DEFAULT_TRUST_PROXY_HOPS,
): string | null {
  if (!xff) return null;
  const hops = Number.isFinite(trustedHops) && trustedHops >= 1
    ? Math.floor(trustedHops)
    : DEFAULT_TRUST_PROXY_HOPS;
  const parts = xff
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length < hops) return null;
  return parts[parts.length - hops] ?? null;
}

export interface ResolveClientIpOptions {
  readonly trustedHops?: number;
  readonly socketPeer?: string | null;
  /** Explicit opt-in: no reverse proxy; trust raw socket peer when XFF absent. */
  readonly directExposure?: boolean;
}

export function resolveClientIp(
  xff: string | null | undefined,
  options: ResolveClientIpOptions = {},
): string | null {
  const {
    trustedHops = DEFAULT_TRUST_PROXY_HOPS,
    socketPeer = null,
    directExposure = false,
  } = options;
  const fromXff = clientIpFromXff(xff, trustedHops);
  if (fromXff) return fromXff;
  if (directExposure && socketPeer) return socketPeer;
  return null;
}

/**
 * Parse TRUST_PROXY_HOPS env. Invalid/missing → safe default 1 (never crash).
 */
export function parseTrustProxyHops(raw: string | undefined | null): number {
  if (raw === undefined || raw === null || raw.trim() === "") {
    return DEFAULT_TRUST_PROXY_HOPS;
  }
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_TRUST_PROXY_HOPS;
  return n;
}

/** Parse TRUST_PROXY_DIRECT_EXPOSURE (truthy: 1/true/yes). */
export function parseTrustProxyDirectExposure(
  raw: string | undefined | null,
): boolean {
  if (raw === undefined || raw === null) return false;
  const v = raw.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

/** Build options from process env bag (adapter calls with process.env fragment). */
export function trustProxyOptionsFromEnv(env: {
  readonly TRUST_PROXY_HOPS?: string;
  readonly TRUST_PROXY_DIRECT_EXPOSURE?: string;
}): { readonly trustedHops: number; readonly directExposure: boolean } {
  return {
    trustedHops: parseTrustProxyHops(env.TRUST_PROXY_HOPS),
    directExposure: parseTrustProxyDirectExposure(env.TRUST_PROXY_DIRECT_EXPOSURE),
  };
}
