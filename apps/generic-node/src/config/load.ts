// Boot entry point for the frozen configuration schema.
// Parsed once at boot, cached after the first successful parse (same boot
// contract as the lifted Zukaz config). Missing or blank critical
// configuration fails boot with a structured, diagnosable list — never a
// silent default. No error message ever echoes a secret value.

import { createHash, timingSafeEqual } from "node:crypto";

import { NODE_ENV_CONFIG_SCHEMA, type NodeConfig } from "./env-schema.js";
import { formatZodIssuePath } from "./issues.js";
import { assertNoPlaceholderConfiguration } from "./placeholders.js";

export class NodeConfigurationError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`Invalid node configuration:\n${issues.map((issue) => `  - ${issue}`).join("\n")}`);
    this.name = "NodeConfigurationError";
    this.issues = issues;
  }
}

// Env vars that LOOK like configuration but name knobs that do not exist in
// the frozen schema. Setting one must fail boot loudly — silently ignoring it
// would let an operator believe they are tuning the node when they are not.
// - POOL_TARGET_AVAILABLE: deleted; the pool target is derived from
//   live demand (poolTargetTotal), never a free knob.
// - RECEIVE_QUEUE_CAP: derived as exactly POOL_CAP_TOTAL; set that.
// - CALLBACK_URL: callbacks were removed from the generic node; the
//   node initiates no callback surface, so this variable can never take effect.
// - REPORTING_CLOCK_SKEW_SECONDS: clock skew is frozen at zero; the consumer
//   owes the whole margin, so this is not a configuration knob.
export const DELETED_ENV_VARS: Readonly<Record<string, string>> = {
  POOL_TARGET_AVAILABLE:
    "POOL_TARGET_AVAILABLE was deleted — the receive-pool target is derived from live demand (poolTargetTotal), not configured. Remove this variable; set POOL_CAP_TOTAL if you need to change pool sizing.",
  RECEIVE_QUEUE_CAP:
    "RECEIVE_QUEUE_CAP is not configurable — it is derived as exactly POOL_CAP_TOTAL. Remove this variable; set POOL_CAP_TOTAL instead.",
  CALLBACK_URL:
    "CALLBACK_URL has no effect — generic event callbacks were removed from the node (the signed pull stream is the sole authoritative channel). Remove this variable.",
  REPORTING_CLOCK_SKEW_SECONDS:
    "REPORTING_CLOCK_SKEW_SECONDS is not configurable — REPORT_REQUEST_CLOCK_SKEW_MS is frozen at 0. The consumer owes the whole margin (clock discipline, request latency, the signed window); the node grants no skew budget. Remove this variable.",
};

function assertNoDeletedEnvVars(source: Readonly<Record<string, string | undefined>>): void {
  const issues = Object.entries(DELETED_ENV_VARS)
    .filter(([name]) => source[name] !== undefined)
    .map(([name, reason]) => `${name}: ${reason}`);
  if (issues.length > 0) {
    throw new NodeConfigurationError(issues);
  }
}

// Railway always populates RAILWAY_PUBLIC_DOMAIN at runtime, but the
// template cannot interpolate it into PUBLIC_BASE_URL at variable-definition
// time for every deploy flow. When PUBLIC_BASE_URL is unset or blank and
// RAILWAY_PUBLIC_DOMAIN is present, derive `https://<domain>` for parsing. Any
// non-blank explicit PUBLIC_BASE_URL — even a malformed one — always wins over
// the derived value; when neither is present the schema's required_error
// still fails boot closed (unchanged).
function withPublicBaseUrlFallback(
  source: Readonly<Record<string, string | undefined>>,
): Readonly<Record<string, string | undefined>> {
  const explicit = source.PUBLIC_BASE_URL;
  if (explicit !== undefined && explicit.trim() !== "") {
    return source;
  }
  const domain = source.RAILWAY_PUBLIC_DOMAIN;
  if (domain === undefined || domain.trim() === "") {
    return source;
  }
  return { ...source, PUBLIC_BASE_URL: `https://${domain.trim()}` };
}

// Railway's template generates NODE_ID as `${{secret(32)}}` — a raw
// 32-char hex string without dashes. The schema requires canonical UUID format
// (8-4-4-4-12). This function inserts dashes at the canonical positions when
// given a raw 32-char hex string, and passes through already-canonical UUIDs
// unchanged.
const RAW_HEX_NODE_ID = /^[0-9a-f]{32}$/i;

export function withCanonicalNodeId(
  source: Readonly<Record<string, string | undefined>>,
): Readonly<Record<string, string | undefined>> {
  const nodeId = source.NODE_ID;
  if (nodeId === undefined) return source;
  // Already canonical (8-4-4-4-12 with dashes) — pass through.
  if (nodeId.includes("-")) return source;
  // Raw 32-char hex — insert dashes at positions 8-4-4-4-12.
  if (RAW_HEX_NODE_ID.test(nodeId)) {
    const lower = nodeId.toLowerCase();
    const canonical =
      `${lower.slice(0, 8)}-${lower.slice(8, 12)}-${lower.slice(12, 16)}-${lower.slice(16, 20)}-${lower.slice(20)}`;
    return { ...source, NODE_ID: canonical };
  }
  // Neither canonical nor raw hex — leave untouched so the schema regex rejects
  // it with the standard error message.
  return source;
}

let cachedConfig: NodeConfig | null = null;

export function loadNodeConfig(
  source: Readonly<Record<string, string | undefined>> = process.env,
  warn: (message: string) => void = console.warn,
): NodeConfig {
  if (cachedConfig !== null && source === process.env) {
    return cachedConfig;
  }

  assertNoDeletedEnvVars(source);

  const parsed = NODE_ENV_CONFIG_SCHEMA.safeParse(
    withCanonicalNodeId(withPublicBaseUrlFallback(source)),
  );
  if (!parsed.success) {
    const issues = parsed.error.issues.map(
      (issue) => `${formatZodIssuePath(issue.path)}: ${issue.message}`,
    );
    throw new NodeConfigurationError(issues);
  }

  assertNoPlaceholderConfiguration(parsed.data, warn);

  if (source === process.env) {
    cachedConfig = parsed.data;
  }
  return parsed.data;
}

export type CustodyNodeConfig = NodeConfig & { readonly VAULT_MASTER_KEY: string };

/** Canonical Stage-2 boundary: ordinary config plus custody-domain invariants. */
export function loadCustodyNodeConfig(
  source: Readonly<Record<string, string | undefined>> = process.env,
  warn: (message: string) => void = console.warn,
): CustodyNodeConfig {
  const config = loadNodeConfig(source, warn);
  // Canonicalize both roots exactly as the vault/backup consumers do before
  // value-level comparison. Neither value is ever included in diagnostics.
  const vaultMasterKey = source.VAULT_MASTER_KEY?.trim();
  const issues: string[] = [];
  if (vaultMasterKey === undefined || vaultMasterKey.length < 32) {
    issues.push("VAULT_MASTER_KEY: must be at least 32 characters");
  } else if (config.BACKUP_MASTER_KEY !== undefined) {
    const vaultDigest = createHash("sha256").update(vaultMasterKey).digest();
    const backupDigest = createHash("sha256").update(config.BACKUP_MASTER_KEY).digest();
    if (timingSafeEqual(vaultDigest, backupDigest)) {
      issues.push(
        "BACKUP_MASTER_KEY: must differ from VAULT_MASTER_KEY (separate custody domains)",
      );
    }
  }
  if (issues.length > 0) throw new NodeConfigurationError(issues);
  return Object.freeze({ ...config, VAULT_MASTER_KEY: vaultMasterKey! });
}

export function _resetNodeConfigCacheForTests(): void {
  cachedConfig = null;
}
