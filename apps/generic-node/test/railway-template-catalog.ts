// Railway one-click template configuration for the v2 generic node
// (apps/generic-node).
//
// This is NOT a file Railway auto-detects or parses. Railway composes a
// one-click "Template" via its dashboard/API from a live deployed project --
// there is no repo-committed manifest format Railway consumes directly. This
// module is the reviewable, change-controlled source of truth for what that
// template's variables must be: whoever configures the real Railway template
// reads this instead of re-deriving the list from the spec docs by hand.
//
// The v1 node template lives in packages/shared/src/railway-template.ts (for
// apps/node). This module covers the v2 generic node (apps/generic-node)
// whose env schema (apps/generic-node/src/config/env-schema.ts) has a
// different required-field set (NODE_ID, VAULT_MASTER_KEY, BACKUP_MASTER_KEY,
// etc.).

export const GENERIC_NODE_RAILWAY_REFERRAL_CODE = "zupayments";

/**
 * Where a template env var's value comes from at deploy time. There is
 * deliberately no "platform" source: the platform must never see a node
 * secret. Every `secret: true` entry must resolve to "generator" or
 * "postgres-plugin" -- enforced by
 * `assertGenericNodeNoPlatformMintedSecrets`.
 */
export type GenericNodeRailwayEnvVarSource =
  | "generator" // Railway ${{secret(...)}} template function
  | "postgres-plugin" // Railway Postgres plugin variable reference
  | "service-domain" // Railway-assigned service domain reference
  | "static-default"; // non-secret, checked-in default value

export interface GenericNodeRailwayTemplateEnvVar {
  key: string;
  source: GenericNodeRailwayEnvVarSource;
  /** Railway template value expression, e.g. "${{secret(64)}}", or a literal default. */
  value: string;
  secret: boolean;
  description: string;
}

/**
 * The generic-node template's declared env vars.
 *
 * Every hard-required env var from the frozen config schema
 * (apps/generic-node/src/config/env-schema.ts) is accounted for:
 *
 *   - DATABASE_URL: from the Postgres plugin. The template MUST wire the
 *     direct-session URL (not the pooled endpoint). db/migrate.ts
 *     assertDirectSessionDatabaseUrl rejects poolers because the migration
 *     overlap probe and signer leadership lock require session-scoped
 *     advisory locks, which a pooler silently breaks.
 *
 *   - SPLITCHAIN_GATEWAY_URLS: static default = the live production gateway.
 *     The schema deliberately has no code default;
 *     the template carries the production URL so one-click deploys boot
 *     against the real chain.
 *
 *   - PUBLIC_BASE_URL: NOT declared -- derived at boot from Railway's
 *     RAILWAY_PUBLIC_DOMAIN. The template cannot interpolate it at
 *     variable-definition time.
 *
 *   - NODE_ID: generated random hex. The schema requires lowercase canonical
 *     UUID format (8-4-4-4-12 hex); the operator must insert dashes into the
 *     generated 32-char hex string before boot. Railway template functions
 *     cannot produce formatted UUIDs (no string manipulation).
 *
 *   - VAULT_MASTER_KEY: generated 64-char random hex (≥32 required by schema).
 *
 *   - INITIAL_ADMIN_PASSWORD: generated 32-char random hex (≥12 required).
 *
 *   - BACKUP_MASTER_KEY: generated 64-char random hex (≥32 required when
 *     BACKUP_SCHEDULE_ENABLED=true).
 *
 *   - BACKUP_SCHEDULE_ENABLED: static "true" (the production template always
 *     enables the encrypted backup schedule).
 *
 *   - BACKUP_OUTPUT_DIR: static "/var/lib/generic-node/backups" (must not
 *     be under /tmp — /tmp is ephemeral, so a pod replace would destroy the
 *     only recovery-point evidence).
 */
export const GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS: readonly GenericNodeRailwayTemplateEnvVar[] = [
  {
    key: "DATABASE_URL",
    source: "postgres-plugin",
    value: "${{Postgres.DATABASE_URL}}",
    secret: true,
    description:
      "Wired from the template's Postgres plugin service. MUST be the direct-session " +
      "URL (not pooled) -- assertDirectSessionDatabaseUrl rejects poolers because " +
      "the migration overlap probe and signer leadership lock need session-scoped " +
      "advisory locks.",
  },
  {
    key: "VAULT_MASTER_KEY",
    source: "generator",
    value: "${{secret(64)}}",
    secret: true,
    description:
      "Unwraps the node's key vault. Auto-generated 64-char random hex (≥32 required).",
  },
  {
    key: "NODE_ID",
    source: "generator",
    value: '${{secret(32, "abcdef0123456789")}}',
    secret: true,
    description:
      "Node identity for audit log entries. Auto-generated 32-char random hex. " +
      "The schema requires lowercase canonical UUID format (8-4-4-4-12 hex); " +
      "the operator must insert dashes to convert the generated hex to UUID form " +
      "before boot (Railway template functions cannot produce formatted UUIDs).",
  },
  {
    key: "INITIAL_ADMIN_PASSWORD",
    source: "generator",
    value: "${{secret(32)}}",
    secret: true,
    description:
      "First-boot admin credential. Auto-generated 32-char random hex (≥12 required).",
  },
  {
    key: "BACKUP_MASTER_KEY",
    source: "generator",
    value: "${{secret(64)}}",
    secret: true,
    description:
      "Dedicated backup KEK, deliberately separate from the vault/signing key so " +
      "a backup leak never exposes signing custody. Auto-generated 64-char random " +
      "hex (≥32 required). Required because BACKUP_SCHEDULE_ENABLED=true.",
  },
  {
    key: "SPLITCHAIN_GATEWAY_URLS",
    source: "static-default",
    value: "https://gateway-entry-1-q2whsu3jlj.splitchain.com/",
    secret: false,
    description:
      "SplitChain transaction gateway (the live production chain). " +
      "The schema deliberately has no code default; the template carries the " +
      "production URL so one-click deploys boot green.",
  },
  {
    key: "BACKUP_SCHEDULE_ENABLED",
    source: "static-default",
    value: "true",
    secret: false,
    description:
      "Enables the encrypted backup schedule. Production template always " +
      "enables this.",
  },
  {
    key: "BACKUP_OUTPUT_DIR",
    source: "static-default",
    value: "/var/lib/generic-node/backups",
    secret: false,
    description:
      "Durable backup sink directory. Must not be under /tmp (ephemeral; " +
      "a pod replace would destroy the only recovery-point evidence).",
  },
  {
    key: "NODE_ENV",
    source: "static-default",
    value: "production",
    secret: false,
    description: "Deployment mode. Production template always sets this.",
  },
] as const;

/** Sources a secret env var may legitimately come from: Railway itself, never
 * a human or a checked-in static value. */
const GENERIC_NODE_RAILWAY_CONTROLLED_SOURCES: readonly GenericNodeRailwayEnvVarSource[] = [
  "generator",
  "postgres-plugin",
];

/**
 * Review guard: no security-critical env var is ever sourced from a static
 * default or service-domain reference. Every `secret: true` entry must be
 * sourced from Railway itself (a template generator or the Postgres plugin).
 * Throws naming the offending key on violation.
 */
export function assertGenericNodeNoPlatformMintedSecrets(
  vars: readonly GenericNodeRailwayTemplateEnvVar[] = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS,
): void {
  for (const v of vars) {
    if (v.secret && !GENERIC_NODE_RAILWAY_CONTROLLED_SOURCES.includes(v.source)) {
      throw new Error(
        `${v.key} is marked secret but sourced from "${v.source}", which is not Railway-controlled`,
      );
    }
  }
}

function parseTemplateCode(templateCode: string): string {
  const code = templateCode.trim();
  if (code.length === 0) {
    throw new Error("template code is required");
  }
  if (!/^[A-Za-z0-9_-]+$/.test(code)) {
    throw new Error(
      "template code must be alphanumeric (Railway template codes only use [A-Za-z0-9_-])",
    );
  }
  return code;
}

/**
 * Builds the "Deploy Generic Node" deep-link:
 * `https://railway.com/deploy/<template-code>?referralCode=zupayments`.
 *
 * Takes the current published template code as an argument rather than a
 * hardcoded constant -- callers must source it from the live template
 * catalog, so the deep-link always resolves to the correct current version.
 */
export function buildGenericNodeRailwayDeployUrl(templateCode: string): string {
  const code = parseTemplateCode(templateCode);
  const url = new URL(`https://railway.com/deploy/${code}`);
  url.searchParams.set("referralCode", GENERIC_NODE_RAILWAY_REFERRAL_CODE);
  return url.toString();
}
