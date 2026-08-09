// The frozen deployment configuration schema for the v2
// generic node: a single Zod schema parsed once at boot from
// process.env; safeParse failure produces a structured list of exactly which
// fields are missing or malformed.
//
// Contract this schema enforces:
// - Gateway endpoint configuration is mandatory: no silent production gateway
//   default and no sandbox fallback.
// - Bounded gateway read retries with a configured maximum interval;
//   readiness degraded when the failure budget is exceeded.
// - Proof-access window default (terminal + 30 days).
// - Admin CORS defaults to no cross-origin access, exact origins only, never `*`.
// - Pool sizing and the redemption window are frozen constants; callbacks were
//   removed, so this schema carries no callback fields by design.
//
// No-sandbox discipline (C-06): there is deliberately no sandbox/mode flag in
// this schema. Every configured gateway is a real production gateway by
// definition; no default value here can enable a live-submit-capable path
// without explicit gateway configuration.
//
// Error-message discipline: every validation message
// names the FIELD and the CONSTRAINT, never the rejected value. Messages are
// custom-set on fields whose Zod defaults could echo input (enums), and
// secret fields use non-echoing constraints throughout.

import {
  DUAL_CONTROL_MODES,
  SPLITCHAIN_FUTURE_TIME_CEILING_SECS,
  UUID_PATTERN,
  z,
  type ReceiveTtlBounds,
} from "@zucoins/node-core";


import {
  POOL_CAP_CEILING,
  POOL_CAP_DEFAULT,
  POOL_FLOOR,
  PROOF_ACCESS_WINDOW_DEFAULT_SECONDS,
  PROOF_ACCESS_WINDOW_MIN_SECONDS,
  RECEIVE_QUEUE_MAX_WAIT_DEFAULT_SECONDS,
  RECEIVE_QUEUE_MAX_WAIT_MAX_SECONDS,
  RECEIVE_QUEUE_MAX_WAIT_MIN_SECONDS,
  RECEIVE_TTL_DEFAULT_SECS_DEFAULT,
  RECEIVE_TTL_MAX_SECS_DEFAULT,
  RECEIVE_TTL_MIN_SECS_DEFAULT,
} from "./constants.js";
import {
  commaSeparatedOptional,
  endpointUrl,
  isExactHttpOrigin,
  isHttpsOrLoopbackHttp,
  splitCommaSeparated,
} from "./env-fields.js";

// The three RECEIVE_TTL_*_SECS fields share one shape — a positive integer
// number of seconds that no policy could honour above the SplitChain future-time ceiling.
function receiveTtlSeconds(field: string) {
  return z.coerce
    .number()
    .int(`${field} must be an integer number of seconds`)
    .min(1, `${field} must be at least 1 second`)
    .max(
      SPLITCHAIN_FUTURE_TIME_CEILING_SECS,
      `${field} must not exceed the SplitChain future-time ceiling of ${SPLITCHAIN_FUTURE_TIME_CEILING_SECS} seconds`,
    );
}

// Field schemas are named individually so mutable.ts can reuse the exact same
// validation for the runtime-settings write path — one source of truth for
// type + bounds per field.
export const CONFIG_FIELD_SCHEMAS = {
  NODE_ENV: z
    .enum(["development", "test", "production"], {
      message: "NODE_ENV must be one of development, test, production",
    })
    .default("development"),
  PORT: z.coerce
    .number({ invalid_type_error: "PORT must be an integer between 1 and 65535" })
    .int("PORT must be an integer between 1 and 65535")
    .min(1, "PORT must be an integer between 1 and 65535")
    .max(65535, "PORT must be an integer between 1 and 65535")
    .default(8080),
  BIND_HOST: z.string().min(1, "BIND_HOST must not be blank").default("::"),

  // Database — required secret, first-boot only. Used verbatim by the node
  // database adapter; never echoed in any error.
  DATABASE_URL: z
    .string({
      required_error:
        "DATABASE_URL is required: the node cannot boot without a database connection string",
    })
    .trim()
    .min(1, "DATABASE_URL must not be blank")
    .refine(
      (value) => /^postgres(ql)?:\/\//.test(value),
      "DATABASE_URL must be a postgres connection URL (postgres:// or postgresql:// scheme)",
    ),


  // Gateway — mandatory, at least one well-formed endpoint, no default and no
  // placeholder default. Failover iterates this list.
  SPLITCHAIN_GATEWAY_URLS: z
    .string({
      required_error:
        "SPLITCHAIN_GATEWAY_URLS is required: at least one SplitChain gateway endpoint must be configured; there is no silent default and no sandbox fallback",
    })
    .transform(splitCommaSeparated)
    .pipe(
      z
        .array(endpointUrl("SPLITCHAIN_GATEWAY_URLS"))
        .min(1, "SPLITCHAIN_GATEWAY_URLS must name at least one gateway endpoint"),
    ),

  // TLS certificate pins for the gateway endpoints — optional; when present
  // each entry is one lowercase-hex SHA-256 pin.
  GATEWAY_TLS_CERT_SHA256_PINS: commaSeparatedOptional(
    z
      .string()
      .regex(
        /^[0-9a-f]{64}$/,
        "GATEWAY_TLS_CERT_SHA256_PINS entries must be 64 lowercase hex characters (SHA-256)",
      ),
  ),

  PUBLIC_BASE_URL: z
    .string({
      required_error:
        "PUBLIC_BASE_URL is required: the node's externally reachable base URL must be configured explicitly",
    })
    .trim()
    .url("PUBLIC_BASE_URL must be a well-formed URL")
    .refine(
      isHttpsOrLoopbackHttp,
      "PUBLIC_BASE_URL must be an https URL (http is accepted only for loopback addresses)",
    ),

  // Initial admin bootstrap — gates irreversible genesis state; first-boot only.
  INITIAL_ADMIN_USERNAME: z
    .string()
    .trim()
    .min(3, "INITIAL_ADMIN_USERNAME must be at least 3 characters")
    .default("admin"),
  INITIAL_ADMIN_PASSWORD: z
    .string()
    .min(12, "INITIAL_ADMIN_PASSWORD must be at least 12 characters when set")
    .optional(),

  // Node identity — UUID primary key on nodes(id); money FKs require lowercase canonical form.
  NODE_ID: z
    .string({
      required_error:
        "NODE_ID is required: the node must have a stable identity for audit log entries",
    })
    .trim()
    .regex(
      new RegExp(UUID_PATTERN),
      "NODE_ID must be a lowercase canonical UUID (8-4-4-4-12 hex)",
    ),

  // Pool/queue limits — POOL_CAP_TOTAL is the only free pool knob;
  // RECEIVE_QUEUE_CAP is derived from it (see receiveQueueCap), the pool
  // target is derived by poolTargetTotal, and POOL_FLOOR / POOL_CAP_CEILING /
  // MINT_BATCH_LIMIT are frozen constants.
  POOL_CAP_TOTAL: z.coerce
    .number()
    .int("POOL_CAP_TOTAL must be an integer")
    .min(POOL_FLOOR, `POOL_CAP_TOTAL must be between ${POOL_FLOOR} and ${POOL_CAP_CEILING}`)
    .max(
      POOL_CAP_CEILING,
      `POOL_CAP_TOTAL must be between ${POOL_FLOOR} and ${POOL_CAP_CEILING}`,
    )
    .default(POOL_CAP_DEFAULT),
  RECEIVE_QUEUE_MAX_WAIT: z.coerce
    .number()
    .int("RECEIVE_QUEUE_MAX_WAIT must be an integer number of seconds")
    .min(
      RECEIVE_QUEUE_MAX_WAIT_MIN_SECONDS,
      `RECEIVE_QUEUE_MAX_WAIT must be between ${RECEIVE_QUEUE_MAX_WAIT_MIN_SECONDS} and ${RECEIVE_QUEUE_MAX_WAIT_MAX_SECONDS} seconds`,
    )
    .max(
      RECEIVE_QUEUE_MAX_WAIT_MAX_SECONDS,
      `RECEIVE_QUEUE_MAX_WAIT must be between ${RECEIVE_QUEUE_MAX_WAIT_MIN_SECONDS} and ${RECEIVE_QUEUE_MAX_WAIT_MAX_SECONDS} seconds`,
    )
    .default(RECEIVE_QUEUE_MAX_WAIT_DEFAULT_SECONDS),

  // The RECEIVE_EXTERNAL payer-code TTL policy. Each field is individually
  // bounded by the SplitChain future-time ceiling here; the ordering invariant
  // min <= default <= max is enforced cross-field in NODE_ENV_CONFIG_SCHEMA below.
  RECEIVE_TTL_DEFAULT_SECS: receiveTtlSeconds("RECEIVE_TTL_DEFAULT_SECS").default(
    RECEIVE_TTL_DEFAULT_SECS_DEFAULT,
  ),
  RECEIVE_TTL_MIN_SECS: receiveTtlSeconds("RECEIVE_TTL_MIN_SECS").default(
    RECEIVE_TTL_MIN_SECS_DEFAULT,
  ),
  RECEIVE_TTL_MAX_SECS: receiveTtlSeconds("RECEIVE_TTL_MAX_SECS").default(
    RECEIVE_TTL_MAX_SECS_DEFAULT,
  ),

  // TTLs and proof windows.
  PROOF_ACCESS_WINDOW_SECONDS: z.coerce
    .number()
    .int("PROOF_ACCESS_WINDOW_SECONDS must be an integer")
    .min(
      PROOF_ACCESS_WINDOW_MIN_SECONDS,
      `PROOF_ACCESS_WINDOW_SECONDS must be at least ${PROOF_ACCESS_WINDOW_MIN_SECONDS} (one hour)`,
    )
    .default(PROOF_ACCESS_WINDOW_DEFAULT_SECONDS),
  // Metrics scrape auth — optional for boot. Absent means the /metrics route
  // is NOT mounted (fail-closed-by-non-mounting); never "absent means
  // an open unauthenticated route".
  METRICS_SCRAPE_TOKEN: z
    .string()
    .min(32, "METRICS_SCRAPE_TOKEN must be at least 32 characters when set")
    .optional(),

  // Worker / reconciliation budgets — bounded retries with a
  // configured maximum interval; short worker-claim leases.
  GATEWAY_READ_RETRY_MAX_ATTEMPTS: z.coerce
    .number()
    .int("GATEWAY_READ_RETRY_MAX_ATTEMPTS must be an integer")
    .min(1, "GATEWAY_READ_RETRY_MAX_ATTEMPTS must be between 1 and 20")
    .max(20, "GATEWAY_READ_RETRY_MAX_ATTEMPTS must be between 1 and 20")
    .default(5),
  GATEWAY_READ_BACKOFF_MAX_MS: z.coerce
    .number()
    .int("GATEWAY_READ_BACKOFF_MAX_MS must be an integer")
    .min(1000, "GATEWAY_READ_BACKOFF_MAX_MS must be between 1000 and 600000")
    .max(600000, "GATEWAY_READ_BACKOFF_MAX_MS must be between 1000 and 600000")
    .default(30000),
  GATEWAY_READ_FAILURE_BUDGET: z.coerce
    .number()
    .int("GATEWAY_READ_FAILURE_BUDGET must be an integer")
    .min(1, "GATEWAY_READ_FAILURE_BUDGET must be between 1 and 100")
    .max(100, "GATEWAY_READ_FAILURE_BUDGET must be between 1 and 100")
    .default(3),
  WORKER_CLAIM_TTL_MS: z.coerce
    .number()
    .int("WORKER_CLAIM_TTL_MS must be an integer")
    .min(5000, "WORKER_CLAIM_TTL_MS must be between 5000 and 300000")
    .max(300000, "WORKER_CLAIM_TTL_MS must be between 5000 and 300000")
    .default(30000),
  RECONCILIATION_POLL_INTERVAL_MS: z.coerce
    .number()
    .int("RECONCILIATION_POLL_INTERVAL_MS must be an integer")
    .min(1000, "RECONCILIATION_POLL_INTERVAL_MS must be between 1000 and 300000")
    .max(300000, "RECONCILIATION_POLL_INTERVAL_MS must be between 1000 and 300000")
    .default(15000),

  // Bounded wait for the boot-lane signer-leadership step during
  // rolling-deploy overlap, when the outgoing container still holds the
  // advisory lock. Must stay well inside the Railway healthcheckTimeout
  // (railway.json, 120000 ms) alongside every other sequential boot step;
  // 60000 ms ceiling leaves headroom for migrations/vault-unlock before it
  // and boot-recovery/gateway-read after it. Fail-closed is preserved: once
  // this wait is exhausted, the lane still throws exactly as a one-shot
  // try-lock would.
  SIGNER_LEADERSHIP_RETRY_MAX_MS: z.coerce
    .number()
    .int("SIGNER_LEADERSHIP_RETRY_MAX_MS must be an integer")
    .min(1000, "SIGNER_LEADERSHIP_RETRY_MAX_MS must be between 1000 and 60000")
    .max(60000, "SIGNER_LEADERSHIP_RETRY_MAX_MS must be between 1000 and 60000")
    .default(15000),

  // The deployment-platform healthcheck timeout, in milliseconds.
  // Must exceed SIGNER_LEADERSHIP_RETRY_MAX_MS so the bounded signer-leadership
  // retry cannot consume the entire healthcheck window (which would reproduce
  // the earlier failed-deploy symptom). Defaults to 150 000 ms, matching
  // railway.json healthcheckTimeout=150. An operator who changes the Railway
  // timeout MUST set this env var to the same value.
  RAILWAY_HEALTHCHECK_TIMEOUT_MS: z.coerce
    .number()
    .int("RAILWAY_HEALTHCHECK_TIMEOUT_MS must be an integer")
    .min(1000, "RAILWAY_HEALTHCHECK_TIMEOUT_MS must be at least 1000 ms")
    .default(150_000),

  // ── Vault root-key derivation ─────────────────────────────────────
  // The PBKDF2 salt the vault root key is derived under. Not secret, but it must be the
  // same value on every path that derives that key — and until ZTR-1159 it was read raw
  // from process.env by the master-key rotation CLI alone, validated nowhere, while boot
  // and both recovery ceremonies used a hardcoded literal. An operator who supplied a
  // different value here re-sealed every envelope under a root key no other path could
  // reproduce, and found out at the next boot or at the recovery ceremony.
  //
  // Optional on purpose: unset means the pre-ZTR-1159 literal, so an existing node keeps
  // deriving exactly the key it derives today (vault/root-kdf-salt.ts). Once set it is
  // pinned against the salt persisted beside the envelopes (`vault_root_kdf_salt`); a
  // disagreement refuses the boot rather than deriving a key that opens nothing.
  VAULT_ROOT_SALT_B64: z
    .string()
    .trim()
    .min(1, "VAULT_ROOT_SALT_B64 must not be blank when set")
    .refine(
      (value) => Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64").length >= 8,
      "VAULT_ROOT_SALT_B64 must be base64 (standard or URL-safe) decoding to at least 8 bytes",
    )
    .optional(),

  // ── Disaster recovery (dedicated-KEK scheduled backups) ───────────
  // Schema default remains false so rollback/dev boots stay green (rollback-safe default
  // heritage). The *reference production deploy* (deploy/deployment.yaml +
  // stage1-main) requires the scheduler ON with a dedicated KEK and a durable
  // sink outside emptyDir /tmp. Backup bytes never traverse HTTP (the key-custody rule).
  BACKUP_SCHEDULE_ENABLED: z
    .enum(["true", "false"], {
      message: "BACKUP_SCHEDULE_ENABLED must be 'true' or 'false'",
    })
    .default("false")
    .transform((v) => v === "true"),
  BACKUP_MASTER_KEY: z
    .string()
    .trim()
    .min(32, "BACKUP_MASTER_KEY must be at least 32 characters when set")
    .optional(),
  BACKUP_OUTPUT_DIR: z
    .string()
    .trim()
    .min(1, "BACKUP_OUTPUT_DIR must not be blank when set")
    .refine(
      (value) => value !== "/tmp" && !value.startsWith("/tmp/"),
      "BACKUP_OUTPUT_DIR must not be under /tmp (ephemeral; pod replace destroys RPO evidence)",
    )
    .optional(),
  BACKUP_CONTINUITY_MARKERS_PATH: z
    .string()
    .trim()
    .min(1, "BACKUP_CONTINUITY_MARKERS_PATH must not be blank when set")
    .optional(),
  BACKUP_RETENTION_DAYS: z.coerce
    .number()
    .int("BACKUP_RETENTION_DAYS must be an integer")
    .min(1, "BACKUP_RETENTION_DAYS must be between 1 and 90")
    .max(90, "BACKUP_RETENTION_DAYS must be between 1 and 90")
    .default(14),
  BACKUP_SCHEDULE_INTERVAL_MS: z.coerce
    .number()
    .int("BACKUP_SCHEDULE_INTERVAL_MS must be an integer")
    .min(3_600_000, "BACKUP_SCHEDULE_INTERVAL_MS must be between 3600000 (1h) and 86400000 (24h)")
    .max(86_400_000, "BACKUP_SCHEDULE_INTERVAL_MS must be between 3600000 (1h) and 86400000 (24h)")
    .default(86_400_000),
  BACKUP_DRILL_TEMPLATE_URL: z
    .string()
    .trim()
    .min(1, "BACKUP_DRILL_TEMPLATE_URL must not be blank when set")
    .refine(
      (value) => /^postgres(ql)?:\/\//.test(value),
      "BACKUP_DRILL_TEMPLATE_URL must be a postgres connection URL",
    )
    .optional(),

  // Dual-control approval policy for SEND_EXTERNAL — 01-system-overview.md §4.2:
  // optional node policy must fail closed. Unset is the "deployment added no
  // optional policy" case and yields single_operator; a value that is present but
  // not an exact mode literal (`two-human`, `TWO_HUMAN`, `" two_human"`, `""`) is a
  // boot refusal here, never a silent downgrade to the weaker mode — an operator
  // who typos this must find out at boot, not from a send only one human approved.
  DUAL_CONTROL_MODE: z
    .enum(DUAL_CONTROL_MODES, {
      message: `DUAL_CONTROL_MODE must be one of ${DUAL_CONTROL_MODES.join(", ")}`,
    })
    .default("single_operator"),

  // Admin CORS origin allowlist — 07-signing-custody-security.md: defaults to
  // no cross-origin access; explicit exact origins; `*` is rejected outright.
  ADMIN_CORS_ALLOWED_ORIGINS: commaSeparatedOptional(
    z
      .string()
      .refine((value) => value !== "*", "ADMIN_CORS_ALLOWED_ORIGINS entries must never be '*'")
      .refine(
        isExactHttpOrigin,
        "ADMIN_CORS_ALLOWED_ORIGINS entries must be exact origins (scheme://host[:port], no path or trailing slash)",
      ),
  ),
} as const;

export const NODE_ENV_CONFIG_SCHEMA = z.object(CONFIG_FIELD_SCHEMAS).superRefine((config, ctx) => {
  // an unordered TTL policy would clamp every request to a window the operator
  // never meant to allow, so it is a boot refusal, not a silent reordering.
  if (config.RECEIVE_TTL_MIN_SECS > config.RECEIVE_TTL_MAX_SECS) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["RECEIVE_TTL_MIN_SECS"],
      message: "RECEIVE_TTL_MIN_SECS must not exceed RECEIVE_TTL_MAX_SECS",
    });
  }
  if (
    config.RECEIVE_TTL_DEFAULT_SECS < config.RECEIVE_TTL_MIN_SECS ||
    config.RECEIVE_TTL_DEFAULT_SECS > config.RECEIVE_TTL_MAX_SECS
  ) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["RECEIVE_TTL_DEFAULT_SECS"],
      message:
        "RECEIVE_TTL_DEFAULT_SECS must lie between RECEIVE_TTL_MIN_SECS and RECEIVE_TTL_MAX_SECS",
    });
  }
  if (config.BACKUP_SCHEDULE_ENABLED) {
    if (config.BACKUP_MASTER_KEY === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["BACKUP_MASTER_KEY"],
        message:
          "BACKUP_MASTER_KEY is required when BACKUP_SCHEDULE_ENABLED is true (dedicated backup KEK; not the vault master key)",
      });
    }
    if (config.BACKUP_OUTPUT_DIR === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["BACKUP_OUTPUT_DIR"],
        message:
          "BACKUP_OUTPUT_DIR is required when BACKUP_SCHEDULE_ENABLED is true (local artifact directory; backup bytes never traverse HTTP)",
      });
    }
  }

  // The signer-leadership retry cap must stay strictly inside the
  // deployment healthcheck window. If cap >= healthcheck, the bounded retry
  // can consume the entire window, reproducing the earlier failed-deploy
  // symptom (deploy FAILED, old container keeps serving). Not custody-unsafe
  // (never two live signers), but a hard operational regression.
  if (config.SIGNER_LEADERSHIP_RETRY_MAX_MS >= config.RAILWAY_HEALTHCHECK_TIMEOUT_MS) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["SIGNER_LEADERSHIP_RETRY_MAX_MS"],
      message:
        "SIGNER_LEADERSHIP_RETRY_MAX_MS must be strictly less than RAILWAY_HEALTHCHECK_TIMEOUT_MS " +
        "(the signer-leadership retry cap must fit inside the deployment healthcheck window)",
    });
  }

});

export type NodeConfig = z.infer<typeof NODE_ENV_CONFIG_SCHEMA>;

// The boot-frozen TTL policy, in the shape protocol/receive-ttl.ts consumes.
export function receiveTtlBounds(
  config: Pick<
    NodeConfig,
    "RECEIVE_TTL_DEFAULT_SECS" | "RECEIVE_TTL_MIN_SECS" | "RECEIVE_TTL_MAX_SECS"
  >,
): ReceiveTtlBounds {
  return {
    defaultSecs: config.RECEIVE_TTL_DEFAULT_SECS,
    minSecs: config.RECEIVE_TTL_MIN_SECS,
    maxSecs: config.RECEIVE_TTL_MAX_SECS,
  };
}


// RECEIVE_QUEUE_CAP is derived, never configured — it equals the pool
// cap. Exported as a function so no code path is tempted to read it from env.
export function receiveQueueCap(config: Pick<NodeConfig, "POOL_CAP_TOTAL">): number {
  return config.POOL_CAP_TOTAL;
}

// the metrics route is mounted only when a scrape token is configured.
export function metricsMounted(config: Pick<NodeConfig, "METRICS_SCRAPE_TOKEN">): boolean {
  return config.METRICS_SCRAPE_TOKEN !== undefined;
}
