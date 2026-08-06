// Secret-safe effective-config read model.
//
// Explicit allowlist DTO for GET /admin/v1/settings. Never dump process.env.
// Operators use this to confirm which node they are on before approve.
//
// Deny-by-default outward surface: an explicit allowlist, nothing else.

/**
 * Wire shape for GET /admin/v1/settings.
 * Keys are the ONLY fields that may ever appear on the wire.
 */
export interface EffectiveConfigDto {
  readonly public_base_url: string;
  readonly node_id: string;
  /** Hostnames only — never gateway auth material. */
  readonly gateway_hosts: readonly string[];
  /** node-core package version string when available. */
  readonly version: string;
  readonly backup_schedule_enabled: boolean;
  /** True when Web Push was composed at boot (endpoint base reachable). Never VAPID keys. */
  readonly push_configured: boolean;
}

/** Closed key set — used by tests to reject any extra serialization. */
export const EFFECTIVE_CONFIG_ALLOWLIST_KEYS = [
  "public_base_url",
  "node_id",
  "gateway_hosts",
  "version",
  "backup_schedule_enabled",
  "push_configured",
] as const satisfies readonly (keyof EffectiveConfigDto)[];

export type EffectiveConfigAllowlistKey = (typeof EFFECTIVE_CONFIG_ALLOWLIST_KEYS)[number];

/**
 * Substrings / patterns that must never appear as JSON object keys on this
 * surface (case-insensitive). Used by the schema/fuzz test — not by the
 * builder (the builder never reads env dumps).
 */
export const SECRET_KEY_DENY_PATTERNS: readonly RegExp[] = [
  /password/i,
  /secret/i,
  /token/i,
  /private/i,
  /master.?key/i,
  /vapid/i,
  /^ik_/i,
  /^sh_/i,
  /api.?key/i,
  /totp/i,
  /seed/i,
  /kek/i,
  /vault_master/i,
  /backup_master/i,
  /database_url/i,
  /credential/i,
];

export interface BuildEffectiveConfigInput {
  readonly publicBaseUrl: string;
  readonly nodeId: string;
  /** Full gateway endpoint URLs from SPLITCHAIN_GATEWAY_URLS — hostnames extracted. */
  readonly gatewayUrls: readonly string[];
  readonly version: string;
  readonly backupScheduleEnabled: boolean;
  readonly pushConfigured: boolean;
}

/** Extract hostname (or host:port when non-default) from a gateway URL. */
export function gatewayHostname(url: string): string | null {
  try {
    const u = new URL(url);
    return u.host !== "" ? u.host : null;
  } catch {
    return null;
  }
}

/**
 * Build the allowlisted DTO. Only named inputs are read — never process.env.
 * Extra properties on the input object are ignored.
 */
export function buildEffectiveConfig(input: BuildEffectiveConfigInput): EffectiveConfigDto {
  const hosts: string[] = [];
  for (const raw of input.gatewayUrls) {
    const host = gatewayHostname(raw);
    if (host !== null && !hosts.includes(host)) hosts.push(host);
  }
  return {
    public_base_url: input.publicBaseUrl,
    node_id: input.nodeId,
    gateway_hosts: Object.freeze(hosts) as readonly string[],
    version: input.version,
    backup_schedule_enabled: input.backupScheduleEnabled,
    push_configured: input.pushConfigured,
  };
}

/**
 * Serialize to a plain JSON object with ONLY allowlisted keys.
 * Defends against accidental spread of a wider record into the response.
 */
export function serializeEffectiveConfig(dto: EffectiveConfigDto): Record<string, unknown> {
  return {
    public_base_url: dto.public_base_url,
    node_id: dto.node_id,
    gateway_hosts: [...dto.gateway_hosts],
    version: dto.version,
    backup_schedule_enabled: dto.backup_schedule_enabled,
    push_configured: dto.push_configured,
  };
}

/** True when a JSON object key looks secret-shaped (deny-list). */
export function isSecretShapedKey(key: string): boolean {
  return SECRET_KEY_DENY_PATTERNS.some((re) => re.test(key));
}

/**
 * Walk a JSON value and collect every object key that is either outside the
 * allowlist (at the top level) or secret-shaped anywhere in the tree.
 */
export function findForbiddenKeys(
  value: unknown,
  opts: { readonly topLevelAllowlist?: ReadonlySet<string> } = {},
): readonly string[] {
  const found: string[] = [];
  const walk = (v: unknown, atTop: boolean): void => {
    if (v === null || typeof v !== "object") return;
    if (Array.isArray(v)) {
      for (const item of v) walk(item, false);
      return;
    }
    for (const key of Object.keys(v as Record<string, unknown>)) {
      if (atTop && opts.topLevelAllowlist && !opts.topLevelAllowlist.has(key)) {
        found.push(key);
      }
      if (isSecretShapedKey(key)) {
        found.push(key);
      }
      walk((v as Record<string, unknown>)[key], false);
    }
  };
  walk(value, true);
  return found;
}
