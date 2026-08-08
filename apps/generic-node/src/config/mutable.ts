// The first-boot vs mutable split, structurally enforced.
//
// First-boot-only fields gate irreversible or deployment-topology state:
// initial admin bootstrap, database connection, gateway endpoints/TLS pins,
// public base URL, listen address. They are read
// from process.env at boot and can change only via a redeploy.
//
// Mutable fields are safe to change on a running node: pool/queue limits,
// proof windows, metrics scrape token, worker and
// reconciliation budgets, and the admin CORS allowlist. Not every TTL qualifies —
// the RECEIVE_TTL_*_SECS policy is first-boot because its value is frozen
// into signed transfer-code bytes. v2's mutable-settings
// store is not yet fixed in canon (the ticket leaves storage to implementer
// judgment), so the enforcement lives HERE, in the write-path contract every
// future store must pass through:
//
// 1. compile-time — MutableNodeSettingsPatch is a Pick over exactly the
//    mutable keys, so a typed caller cannot even name a first-boot field;
// 2. runtime — validateMutableSettingsPatch rejects any key outside the
//    mutable set (first-boot keys get a dedicated error; unknown keys get
//    another), then validates values against the SAME field schemas the boot
//    path uses.
//
// The partition below must cover every NodeConfig key exactly once; the
// type-level assertion at the bottom fails compilation if a field is ever
// added to the schema without being classified.

import { z } from "@zucoins/node-core";

import { CONFIG_FIELD_SCHEMAS, type NodeConfig } from "./env-schema.js";
import { formatZodIssuePath } from "./issues.js";
import { isSingleRepeatedChar, PLACEHOLDER_METRICS_SCRAPE_TOKEN } from "./placeholders.js";

export const FIRST_BOOT_CONFIG_FIELDS = [
  "NODE_ENV",
  "PORT",
  "BIND_HOST",
  "DATABASE_URL",
  "SPLITCHAIN_GATEWAY_URLS",
  "GATEWAY_TLS_CERT_SHA256_PINS",
  "PUBLIC_BASE_URL",
  "NODE_ID",
  "INITIAL_ADMIN_USERNAME",
  "INITIAL_ADMIN_PASSWORD",
  // The RECEIVE payer-code TTL policy is first-boot despite being a TTL. Its
  // value is derived into an absolute expiry that is byte-frozen into a signed transfer
  // code; a running node must not be able to form two codes under two policies.
  "RECEIVE_TTL_DEFAULT_SECS",
  "RECEIVE_TTL_MIN_SECS",
  "RECEIVE_TTL_MAX_SECS",
  // The most first-boot field in the schema. The vault root-KDF salt is pinned to the row
  // persisted beside the envelopes at first vault-unlock and is insert-only from then on;
  // changing it on a running node would derive a root key that opens nothing (ZTR-1159).
  "VAULT_ROOT_SALT_B64",
  "BACKUP_SCHEDULE_ENABLED",
  "BACKUP_MASTER_KEY",
  "BACKUP_OUTPUT_DIR",
  "BACKUP_CONTINUITY_MARKERS_PATH",
  "BACKUP_RETENTION_DAYS",
  "BACKUP_SCHEDULE_INTERVAL_MS",
  "BACKUP_DRILL_TEMPLATE_URL",
  // deployment-platform healthcheck timeout — tied to railway.json,
  // not a runtime knob. Changing it requires a redeploy to match.
  "RAILWAY_HEALTHCHECK_TIMEOUT_MS",
] as const satisfies readonly (keyof NodeConfig)[];

export const MUTABLE_CONFIG_FIELDS = [
  "POOL_CAP_TOTAL",
  "RECEIVE_QUEUE_MAX_WAIT",
  "PROOF_ACCESS_WINDOW_SECONDS",
  "METRICS_SCRAPE_TOKEN",
  "GATEWAY_READ_RETRY_MAX_ATTEMPTS",
  "GATEWAY_READ_BACKOFF_MAX_MS",
  "GATEWAY_READ_FAILURE_BUDGET",
  "WORKER_CLAIM_TTL_MS",
  "RECONCILIATION_POLL_INTERVAL_MS",
  "SIGNER_LEADERSHIP_RETRY_MAX_MS",
  "ADMIN_CORS_ALLOWED_ORIGINS",
] as const satisfies readonly (keyof NodeConfig)[];

export type FirstBootConfigField = (typeof FIRST_BOOT_CONFIG_FIELDS)[number];
export type MutableConfigField = (typeof MUTABLE_CONFIG_FIELDS)[number];

type UnclassifiedFields = Exclude<keyof NodeConfig, FirstBootConfigField | MutableConfigField>;
const _partitionIsComplete: UnclassifiedFields extends never ? true : never = true;
void _partitionIsComplete;

// A null token clears the configured scrape token (route unmounts on next
// settings application) — the "present or not mounted" model applied to the
// write path. Every non-token field reuses its boot-time schema unchanged, and
// METRICS_SCRAPE_TOKEN additionally re-applies the boot path's fail-closed
// placeholder refusal (placeholders.ts): a value equal to the .env.example
// placeholder or a single repeated character is rejected here exactly as boot
// rejects it. The mutable write path therefore can never accept a value the
// boot path would reject.
const MUTABLE_PATCH_SCHEMA = z
  .object({
    POOL_CAP_TOTAL: CONFIG_FIELD_SCHEMAS.POOL_CAP_TOTAL,
    RECEIVE_QUEUE_MAX_WAIT: CONFIG_FIELD_SCHEMAS.RECEIVE_QUEUE_MAX_WAIT,
    PROOF_ACCESS_WINDOW_SECONDS: CONFIG_FIELD_SCHEMAS.PROOF_ACCESS_WINDOW_SECONDS,
    METRICS_SCRAPE_TOKEN: z
      .string()
      .min(32, "METRICS_SCRAPE_TOKEN must be at least 32 characters when set")
      .refine(
        (token) => token !== PLACEHOLDER_METRICS_SCRAPE_TOKEN && !isSingleRepeatedChar(token),
        "METRICS_SCRAPE_TOKEN must not be the .env.example placeholder or a single repeated " +
          "character — such a token would mount /metrics with effectively no authentication. " +
          "Provide a real high-entropy token, or null to unmount /metrics.",
      )
      .nullable(),
    GATEWAY_READ_RETRY_MAX_ATTEMPTS: CONFIG_FIELD_SCHEMAS.GATEWAY_READ_RETRY_MAX_ATTEMPTS,
    GATEWAY_READ_BACKOFF_MAX_MS: CONFIG_FIELD_SCHEMAS.GATEWAY_READ_BACKOFF_MAX_MS,
    GATEWAY_READ_FAILURE_BUDGET: CONFIG_FIELD_SCHEMAS.GATEWAY_READ_FAILURE_BUDGET,
    WORKER_CLAIM_TTL_MS: CONFIG_FIELD_SCHEMAS.WORKER_CLAIM_TTL_MS,
    RECONCILIATION_POLL_INTERVAL_MS: CONFIG_FIELD_SCHEMAS.RECONCILIATION_POLL_INTERVAL_MS,
    SIGNER_LEADERSHIP_RETRY_MAX_MS: CONFIG_FIELD_SCHEMAS.SIGNER_LEADERSHIP_RETRY_MAX_MS,
    ADMIN_CORS_ALLOWED_ORIGINS: CONFIG_FIELD_SCHEMAS.ADMIN_CORS_ALLOWED_ORIGINS,
  })
  .partial();

export type MutableNodeSettingsPatch = Partial<
  Omit<Pick<NodeConfig, MutableConfigField>, "METRICS_SCRAPE_TOKEN"> & {
    METRICS_SCRAPE_TOKEN: string | null;
  }
>;

export class NodeSettingsClassificationError extends Error {
  readonly fields: readonly string[];

  constructor(fields: readonly string[], message: string) {
    super(message);
    this.name = "NodeSettingsClassificationError";
    this.fields = fields;
  }
}

export class NodeMutableSettingsValidationError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`Invalid mutable settings patch:\n${issues.map((issue) => `  - ${issue}`).join("\n")}`);
    this.name = "NodeMutableSettingsValidationError";
    this.issues = issues;
  }
}

const FIRST_BOOT_SET: ReadonlySet<string> = new Set(FIRST_BOOT_CONFIG_FIELDS);
const MUTABLE_SET: ReadonlySet<string> = new Set(MUTABLE_CONFIG_FIELDS);

export function validateMutableSettingsPatch(
  patch: Readonly<Record<string, unknown>>,
): MutableNodeSettingsPatch {
  const keys = Object.keys(patch);
  if (keys.length === 0) return {};

  const unknownKeys = keys.filter((key) => !MUTABLE_SET.has(key) && !FIRST_BOOT_SET.has(key));
  if (unknownKeys.length > 0) {
    throw new NodeSettingsClassificationError(
      unknownKeys,
      `Unknown configuration field(s): ${unknownKeys.join(", ")}. ` +
        "Mutable settings writes only accept the frozen mutable field set.",
    );
  }

  const firstBootKeys = keys.filter((key) => FIRST_BOOT_SET.has(key));
  if (firstBootKeys.length > 0) {
    throw new NodeSettingsClassificationError(
      firstBootKeys,
      `First-boot-only field(s) cannot be changed at runtime: ${firstBootKeys.join(", ")}. ` +
        "These fields gate irreversible state or deployment topology and change only via redeploy.",
    );
  }

  const parsed = MUTABLE_PATCH_SCHEMA.safeParse(patch);
  if (!parsed.success) {
    const issues = parsed.error.issues.map(
      (issue) => `${formatZodIssuePath(issue.path)}: ${issue.message}`,
    );
    throw new NodeMutableSettingsValidationError(issues);
  }
  return parsed.data;
}
