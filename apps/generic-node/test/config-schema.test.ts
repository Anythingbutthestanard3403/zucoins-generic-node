import { clampReceiveTtlSecs, SPLITCHAIN_FUTURE_TIME_CEILING_SECS } from "@zucoins/node-core";
import { describe, expect, it } from "vitest";

import {
  CONFIG_FIELD_SCHEMAS,
  DEFAULT_PUSH_API_BASE,
  FIRST_BOOT_CONFIG_FIELDS,
  loadNodeConfig,
  MUTABLE_CONFIG_FIELDS,
  metricsMounted,
  MINT_BATCH_LIMIT,
  NodeConfigurationError,
  POOL_CAP_CEILING,
  POOL_FLOOR,
  poolTargetTotal,
  receiveQueueCap,
  receiveTtlBounds,
  SEND_REDEMPTION_WINDOW_SECONDS,
  validateMutableSettingsPatch,
  type NodeConfig,
} from "../src/config/index.js";
import { computeProvisioningTarget } from "../../../packages/generic-node-contracts/src/pool-policy/sizing.ts";

const VALID_MASTER_KEY = "f3a9c1d82b4e6f05a1c3d5e7b9f20486a0c1e2d3b4f50617a8c9d0e1f2a3b4c5";

function validEnv(
  overrides: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
  return {
    NODE_ENV: "development",
    DATABASE_URL: "postgresql://node:db-secret@db.internal:5432/zunode",
    SPLITCHAIN_GATEWAY_URLS: "https://gateway-entry-1.internal.example/",
    PUBLIC_BASE_URL: "https://node.internal.example/",
    NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    VAULT_MASTER_KEY: VALID_MASTER_KEY,
    ...overrides,
  };
}

function loadIssues(env: Record<string, string | undefined>): readonly string[] {
  try {
    loadNodeConfig(env);
  } catch (error) {
    expect(error).toBeInstanceOf(NodeConfigurationError);
    return (error as NodeConfigurationError).issues;
  }
  throw new Error("expected loadNodeConfig to fail boot");
}

describe("frozen configuration schema — happy path", () => {
  it("parses a minimal valid env and applies frozen defaults", () => {
    const config = loadNodeConfig(validEnv());
    expect(config.NODE_ENV).toBe("development");
    expect(config.PORT).toBe(8080);
    expect(config.POOL_CAP_TOTAL).toBe(50);
    expect(config.RECEIVE_QUEUE_MAX_WAIT).toBe(30);
    expect(config.PROOF_ACCESS_WINDOW_SECONDS).toBe(2_592_000);
    expect(config.GATEWAY_READ_RETRY_MAX_ATTEMPTS).toBe(5);
    expect(config.GATEWAY_READ_BACKOFF_MAX_MS).toBe(30_000);
    expect(config.GATEWAY_READ_FAILURE_BUDGET).toBe(3);
    expect(config.WORKER_CLAIM_TTL_MS).toBe(30_000);
    expect(config.RECONCILIATION_POLL_INTERVAL_MS).toBe(15_000);
    expect(config.GATEWAY_TLS_CERT_SHA256_PINS).toEqual([]);
    expect(config.ADMIN_CORS_ALLOWED_ORIGINS).toEqual([]);
    expect(config.INITIAL_ADMIN_USERNAME).toBe("admin");
    expect(config.SPLITCHAIN_GATEWAY_URLS).toEqual([
      "https://gateway-entry-1.internal.example/",
    ]);
    expect(config.BACKUP_SCHEDULE_ENABLED).toBe(false);
    expect(config.DUAL_CONTROL_MODE).toBe("single_operator");
    expect(config.ZUCOINS_PUSH_API_BASE).toBe(DEFAULT_PUSH_API_BASE);
    // Runtime pool + money-path statement bound defaults (ZTR-1156).
    expect(config.DB_POOL_MAX).toBe(20);
    expect(config.DB_POOL_CONNECTION_TIMEOUT_MS).toBe(5_000);
    expect(config.DB_POOL_IDLE_TIMEOUT_MS).toBe(30_000);
    expect(config.DB_POOL_KEEPALIVE_INITIAL_DELAY_MS).toBe(10_000);
    expect(config.MONEY_PATH_STATEMENT_TIMEOUT_MS).toBe(15_000);
    expect(config.SIGNER_LEADERSHIP_OWNERSHIP_ASSERT_INTERVAL_MS).toBe(2_000);
  });

  // ZTR-1182 — push relay base is a schema field, not a raw process.env read.
  it("defaults ZUCOINS_PUSH_API_BASE to the production relay when unset or blank", () => {
    expect(loadNodeConfig(validEnv()).ZUCOINS_PUSH_API_BASE).toBe(DEFAULT_PUSH_API_BASE);
    expect(loadNodeConfig(validEnv({ ZUCOINS_PUSH_API_BASE: undefined })).ZUCOINS_PUSH_API_BASE).toBe(
      DEFAULT_PUSH_API_BASE,
    );
    expect(loadNodeConfig(validEnv({ ZUCOINS_PUSH_API_BASE: "   " })).ZUCOINS_PUSH_API_BASE).toBe(
      DEFAULT_PUSH_API_BASE,
    );
    expect(DEFAULT_PUSH_API_BASE).toBe("https://wallet.zucoins.com/api__v1/");
  });

  it("accepts an explicit https push relay override", () => {
    const config = loadNodeConfig(
      validEnv({ ZUCOINS_PUSH_API_BASE: "https://push.staging.example/api__v1/" }),
    );
    expect(config.ZUCOINS_PUSH_API_BASE).toBe("https://push.staging.example/api__v1/");
  });

  it("accepts a loopback http push relay for local development", () => {
    const config = loadNodeConfig(
      validEnv({ ZUCOINS_PUSH_API_BASE: "http://127.0.0.1:8787/api__v1/" }),
    );
    expect(config.ZUCOINS_PUSH_API_BASE).toBe("http://127.0.0.1:8787/api__v1/");
  });

  it.each([
    ["http://push.example.com/api__v1/", "non-loopback http"],
    ["https://user:pass@push.example.com/api__v1/", "embedded credentials"],
    ["not-a-url", "malformed URL"],
    ["ftp://push.example.com/api__v1/", "non-http(s) scheme"],
  ])("rejects ZUCOINS_PUSH_API_BASE=%s (%s)", (value) => {
    const issues = loadIssues(validEnv({ ZUCOINS_PUSH_API_BASE: value }));
    expect(issues.some((issue) => issue.startsWith("ZUCOINS_PUSH_API_BASE:"))).toBe(true);
    // Error-message discipline: name the field and the constraint, never echo input.
    expect(issues.join("\n")).not.toContain(value);
  });

  it("requires KEK + durable sink when backup schedule is enabled; rejects /tmp sink", () => {
    const issues = loadIssues(
      validEnv({
        BACKUP_SCHEDULE_ENABLED: "true",
      }),
    );
    expect(issues.some((i) => i.includes("BACKUP_MASTER_KEY"))).toBe(true);
    expect(issues.some((i) => i.includes("BACKUP_OUTPUT_DIR"))).toBe(true);

    const tmpIssues = loadIssues(
      validEnv({
        BACKUP_SCHEDULE_ENABLED: "true",
        BACKUP_MASTER_KEY: VALID_MASTER_KEY,
        BACKUP_OUTPUT_DIR: "/tmp/backups",
      }),
    );
    expect(tmpIssues.join("\n")).toMatch(/must not be under \/tmp/);

    const ok = loadNodeConfig(
      validEnv({
        BACKUP_SCHEDULE_ENABLED: "true",
        BACKUP_MASTER_KEY: VALID_MASTER_KEY,
        BACKUP_OUTPUT_DIR: "/var/lib/generic-node/backups",
      }),
    );
    expect(ok.BACKUP_SCHEDULE_ENABLED).toBe(true);
    expect(ok.BACKUP_OUTPUT_DIR).toBe("/var/lib/generic-node/backups");
  });

  // ZTR-1148 / doc 01 §4.2. The regression: every one of these once resolved to
  // single_operator inside the mount, so a deployment could believe it had
  // two-human approval, not have it, and get no error and no log line.
  it.each(["two-human", "TWO_HUMAN", " two_human", "", "enabled"])(
    "refuses to boot on an unrecognised DUAL_CONTROL_MODE (%j) rather than downgrade",
    (value) => {
      const issues = loadIssues(validEnv({ DUAL_CONTROL_MODE: value }));
      expect(issues.some((i) => i.startsWith("DUAL_CONTROL_MODE:"))).toBe(true);
      // Error-message discipline: name the field and the constraint, never echo input.
      expect(issues.join("\n")).toContain("must be one of single_operator, two_human");
    },
  );

  it("accepts both exact dual-control modes", () => {
    expect(loadNodeConfig(validEnv({ DUAL_CONTROL_MODE: "two_human" })).DUAL_CONTROL_MODE).toBe(
      "two_human",
    );
    expect(
      loadNodeConfig(validEnv({ DUAL_CONTROL_MODE: "single_operator" })).DUAL_CONTROL_MODE,
    ).toBe("single_operator");
  });

  it("parses multiple gateway endpoints in failover order", () => {
    const config = loadNodeConfig(
      validEnv({
        SPLITCHAIN_GATEWAY_URLS: " https://a.example/ , https://b.example/ ",
      }),
    );
    expect(config.SPLITCHAIN_GATEWAY_URLS).toEqual([
      "https://a.example/",
      "https://b.example/",
    ]);
  });

  it("derives RECEIVE_QUEUE_CAP from POOL_CAP_TOTAL exactly", () => {
    const config = loadNodeConfig(validEnv({ POOL_CAP_TOTAL: "75" }));
    expect(config.POOL_CAP_TOTAL).toBe(75);
    expect(receiveQueueCap(config)).toBe(75);
  });

  it("computes the pool target in exact integer form, floored and capped", () => {
    expect(poolTargetTotal(0, 50)).toBe(POOL_FLOOR);
    expect(poolTargetTotal(1, 50)).toBe(POOL_FLOOR);
    expect(poolTargetTotal(9, 50)).toBe(10);
    expect(poolTargetTotal(10, 50)).toBe(11);
    expect(poolTargetTotal(45, 50)).toBe(50);
    expect(poolTargetTotal(46, 500)).toBe(51);
    expect(poolTargetTotal(10_000, 50)).toBe(50);
    expect(poolTargetTotal(10_000, POOL_CAP_CEILING)).toBe(POOL_CAP_CEILING);
    expect(() => poolTargetTotal(-1, 50)).toThrow(RangeError);
    expect(() => poolTargetTotal(1.5, 50)).toThrow(RangeError);
  });

  it("computes the same pool target as the frozen pool-policy contract over the whole domain", () => {
    for (let openSessions = 0; openSessions <= 120; openSessions += 1) {
      for (const cap of [POOL_FLOOR, 20, 50, POOL_CAP_CEILING]) {
        expect(poolTargetTotal(openSessions, cap)).toBe(
          computeProvisioningTarget(openSessions, cap),
        );
      }
    }
  });

  it("freezes the protocol constants", () => {
    expect(POOL_FLOOR).toBe(5);
    expect(POOL_CAP_CEILING).toBe(500);
    expect(MINT_BATCH_LIMIT).toBe(5);
    expect(SEND_REDEMPTION_WINDOW_SECONDS).toBe(300);
  });
});

describe("boot-failure matrix — missing or blank critical configuration fails boot", () => {
  const CRITICAL_FIELDS = [
    "DATABASE_URL",
    "SPLITCHAIN_GATEWAY_URLS",
    "PUBLIC_BASE_URL",
  ] as const;

  for (const field of CRITICAL_FIELDS) {
    it(`fails boot when ${field} is omitted`, () => {
      const issues = loadIssues(validEnv({ [field]: undefined }));
      expect(issues.some((issue) => issue.startsWith(`${field}:`))).toBe(true);
    });

    it(`fails boot when ${field} is blank`, () => {
      const issues = loadIssues(validEnv({ [field]: "   " }));
      expect(issues.some((issue) => issue.startsWith(`${field}:`))).toBe(true);
    });
  }

});

describe("validation bounds", () => {
  it.each([
    ["4", "below the pool floor"],
    ["501", "above the pool ceiling"],
    ["abc", "not a number"],
    ["50.5", "not an integer"],
  ])("rejects POOL_CAP_TOTAL=%s (%s)", (value) => {
    const issues = loadIssues(validEnv({ POOL_CAP_TOTAL: value }));
    expect(issues.some((issue) => issue.startsWith("POOL_CAP_TOTAL:"))).toBe(true);
  });

  it.each([["4"], ["3601"], ["abc"]])("rejects RECEIVE_QUEUE_MAX_WAIT=%s", (value) => {
    const issues = loadIssues(validEnv({ RECEIVE_QUEUE_MAX_WAIT: value }));
    expect(issues.some((issue) => issue.startsWith("RECEIVE_QUEUE_MAX_WAIT:"))).toBe(true);
  });

  it("rejects a non-postgres DATABASE_URL scheme", () => {
    const issues = loadIssues(validEnv({ DATABASE_URL: "mysql://db.internal/zunode" }));
    expect(issues.some((issue) => issue.startsWith("DATABASE_URL:"))).toBe(true);
  });

  it("rejects non-UUID NODE_ID (must be lowercase canonical UUID)", () => {
    const issues = loadIssues(validEnv({ NODE_ID: "config-schema-local-dryrun" }));
    expect(issues.some((issue) => issue.startsWith("NODE_ID:"))).toBe(true);
    expect(
      loadIssues(validEnv({ NODE_ID: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE" })).some((issue) =>
        issue.startsWith("NODE_ID:"),
      ),
    ).toBe(true);
    const ok = loadNodeConfig(
      validEnv({ NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }),
    );
    expect(ok.NODE_ID).toBe("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
  });

  it("rejects a non-https non-loopback gateway endpoint", () => {
    const issues = loadIssues(
      validEnv({ SPLITCHAIN_GATEWAY_URLS: "http://gateway.internal.example/" }),
    );
    expect(issues.some((issue) => issue.startsWith("SPLITCHAIN_GATEWAY_URLS"))).toBe(true);
  });

  it("accepts a loopback http gateway endpoint", () => {
    const config = loadNodeConfig(
      validEnv({ SPLITCHAIN_GATEWAY_URLS: "http://127.0.0.1:8545/" }),
    );
    expect(config.SPLITCHAIN_GATEWAY_URLS).toEqual(["http://127.0.0.1:8545/"]);
  });

  it("rejects a malformed TLS pin and accepts a 64-hex pin", () => {
    expect(
      loadIssues(validEnv({ GATEWAY_TLS_CERT_SHA256_PINS: "not-a-pin" })).some((issue) =>
        issue.startsWith("GATEWAY_TLS_CERT_SHA256_PINS"),
      ),
    ).toBe(true);
    const pin = "a".repeat(64);
    const config = loadNodeConfig(validEnv({ GATEWAY_TLS_CERT_SHA256_PINS: pin }));
    expect(config.GATEWAY_TLS_CERT_SHA256_PINS).toEqual([pin]);
  });

  it("rejects a wildcard admin CORS origin outright", () => {
    const issues = loadIssues(validEnv({ ADMIN_CORS_ALLOWED_ORIGINS: "*" }));
    expect(issues.some((issue) => issue.startsWith("ADMIN_CORS_ALLOWED_ORIGINS"))).toBe(true);
  });

  it("rejects admin CORS origins with a path and accepts exact origins", () => {
    expect(
      loadIssues(validEnv({ ADMIN_CORS_ALLOWED_ORIGINS: "https://console.example/path" })).some(
        (issue) => issue.startsWith("ADMIN_CORS_ALLOWED_ORIGINS"),
      ),
    ).toBe(true);
    const config = loadNodeConfig(
      validEnv({ ADMIN_CORS_ALLOWED_ORIGINS: "https://console.example" }),
    );
    expect(config.ADMIN_CORS_ALLOWED_ORIGINS).toEqual(["https://console.example"]);
  });

  it("rejects a short metrics scrape token", () => {
    const issues = loadIssues(validEnv({ METRICS_SCRAPE_TOKEN: "too-short" }));
    expect(issues.some((issue) => issue.startsWith("METRICS_SCRAPE_TOKEN:"))).toBe(true);
  });
});

describe("deleted and removed knobs fail boot loudly", () => {
  it("rejects POOL_TARGET_AVAILABLE, citing the derived pool target", () => {
    const issues = loadIssues(validEnv({ POOL_TARGET_AVAILABLE: "10" }));
    expect(issues.some((issue) => issue.includes("POOL_TARGET_AVAILABLE"))).toBe(true);
    expect(issues.some((issue) => issue.includes("derived from live demand"))).toBe(true);
  });

  it("rejects RECEIVE_QUEUE_CAP, citing the derived cap", () => {
    const issues = loadIssues(validEnv({ RECEIVE_QUEUE_CAP: "25" }));
    expect(issues.some((issue) => issue.includes("RECEIVE_QUEUE_CAP"))).toBe(true);
    expect(issues.some((issue) => issue.includes("derived as exactly POOL_CAP_TOTAL"))).toBe(true);
  });

  it("rejects CALLBACK_URL, citing the removal of callbacks", () => {
    const issues = loadIssues(validEnv({ CALLBACK_URL: "https://consumer.example/hook" }));
    expect(issues.some((issue) => issue.includes("CALLBACK_URL"))).toBe(true);
    expect(issues.some((issue) => issue.includes("the signed pull stream is the sole authoritative channel"))).toBe(true);
  });

  it("rejects REPORTING_CLOCK_SKEW_SECONDS — REPORT_REQUEST_CLOCK_SKEW_MS is frozen at 0", () => {
    const issues = loadIssues(validEnv({ REPORTING_CLOCK_SKEW_SECONDS: "5" }));
    expect(issues.some((issue) => issue.includes("REPORTING_CLOCK_SKEW_SECONDS"))).toBe(true);
    expect(issues.some((issue) => issue.includes("frozen at 0"))).toBe(true);
  });
});

describe("no-sandbox defaults", () => {
  it("exposes no sandbox-shaped configuration field", () => {
    const config = loadNodeConfig(validEnv());
    const sandboxKeys = Object.keys(config).filter((key) => /sandbox/i.test(key));
    expect(sandboxKeys).toEqual([]);
  });

  it("cannot boot into any state without explicit gateway configuration", () => {
    const issues = loadIssues(validEnv({ SPLITCHAIN_GATEWAY_URLS: undefined }));
    expect(issues.some((issue) => issue.startsWith("SPLITCHAIN_GATEWAY_URLS:"))).toBe(true);
  });

  it("mounts /metrics only when a scrape token is configured", () => {
    expect(metricsMounted(loadNodeConfig(validEnv()))).toBe(false);
    const withToken = loadNodeConfig(
      validEnv({ METRICS_SCRAPE_TOKEN: VALID_MASTER_KEY }),
    );
    expect(metricsMounted(withToken)).toBe(true);
  });
});

describe("no secret value ever appears in an error message", () => {
  it("names the field, not the rejected DATABASE_URL value", () => {
    const sentinel = "S3NTIN3L-db-secret-value";
    let message = "";
    try {
      loadNodeConfig(validEnv({ DATABASE_URL: sentinel }));
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).not.toBe("");
    expect(message).toContain("DATABASE_URL");
    expect(message).not.toContain(sentinel);
  });

  it("names the field, not the rejected METRICS_SCRAPE_TOKEN value", () => {
    const sentinel = "S3NTIN3L-metrics-secret";
    let message = "";
    try {
      loadNodeConfig(validEnv({ METRICS_SCRAPE_TOKEN: sentinel }));
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).not.toBe("");
    expect(message).toContain("METRICS_SCRAPE_TOKEN");
    expect(message).not.toContain(sentinel);
  });

  it("never drags master-key material into an unrelated boot failure", () => {
    const sentinel = "S3NTIN3L-master-key-material";
    let message = "";
    try {
      loadNodeConfig(
        validEnv({ DATABASE_URL: "", VAULT_MASTER_KEY: sentinel }),
      );
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).not.toBe("");
    expect(message).toContain("DATABASE_URL");
    expect(message).not.toContain(sentinel);
  });
});

describe("schema surface", () => {
  it("classifies every schema field exactly once (first-boot vs mutable partition)", () => {
    const classified = [...FIRST_BOOT_CONFIG_FIELDS, ...MUTABLE_CONFIG_FIELDS].sort();
    expect(classified).toEqual(Object.keys(CONFIG_FIELD_SCHEMAS).sort());
    expect(new Set(classified).size).toBe(classified.length);
  });

  it("leaves optional fields out of the parsed config when unset", () => {
    const config = loadNodeConfig(validEnv());
    expect("METRICS_SCRAPE_TOKEN" in config).toBe(false);
    expect("VAULT_MASTER_KEY_FILE" in config).toBe(false);
    expect("INITIAL_ADMIN_PASSWORD" in config).toBe(false);
  });

  it("keeps the schema keys aligned with the NodeConfig type", () => {
    const keys: readonly (keyof NodeConfig)[] = FIRST_BOOT_CONFIG_FIELDS;
    expect(keys.length).toBeGreaterThan(0);
  });
});

// The RECEIVE_EXTERNAL payer-code TTL policy, frozen at boot.
describe("RECEIVE TTL policy", () => {
  it("applies the published defaults", () => {
    const config = loadNodeConfig(validEnv());
    // 300 s is the published API default; 60/3600 the policy window.
    expect(config.RECEIVE_TTL_DEFAULT_SECS).toBe(300);
    expect(config.RECEIVE_TTL_MIN_SECS).toBe(60);
    expect(config.RECEIVE_TTL_MAX_SECS).toBe(3600);
    expect(receiveTtlBounds(config)).toEqual({ defaultSecs: 300, minSecs: 60, maxSecs: 3600 });
  });

  it("feeds the clamp contract the operator's window, not the shipped one", () => {
    const config = loadNodeConfig(
      validEnv({
        RECEIVE_TTL_MIN_SECS: "120",
        RECEIVE_TTL_DEFAULT_SECS: "600",
        RECEIVE_TTL_MAX_SECS: "1800",
      }),
    );
    expect(clampReceiveTtlSecs(undefined, receiveTtlBounds(config))).toBe(600);
    expect(clampReceiveTtlSecs(30, receiveTtlBounds(config))).toBe(120);
    expect(clampReceiveTtlSecs(86_400, receiveTtlBounds(config))).toBe(1800);
  });

  it.each([["0"], ["-1"], ["1.5"], ["abc"], ["59999881"]])(
    "refuses RECEIVE_TTL_MAX_SECS=%s at boot",
    (value) => {
      const issues = loadIssues(validEnv({ RECEIVE_TTL_MAX_SECS: value }));
      expect(issues.some((issue) => issue.startsWith("RECEIVE_TTL_MAX_SECS:"))).toBe(true);
    },
  );

  it("refuses a maximum above the SplitChain future-time ceiling", () => {
    const issues = loadIssues(
      validEnv({ RECEIVE_TTL_MAX_SECS: String(SPLITCHAIN_FUTURE_TIME_CEILING_SECS + 1) }),
    );
    expect(issues.join("\n")).toContain("future-time ceiling");
  });

  it("refuses an unordered window instead of silently reordering it", () => {
    const issues = loadIssues(
      validEnv({ RECEIVE_TTL_MIN_SECS: "3600", RECEIVE_TTL_MAX_SECS: "60" }),
    );
    expect(
      issues.some((issue) => issue.startsWith("RECEIVE_TTL_MIN_SECS:")),
      issues.join("\n"),
    ).toBe(true);
  });

  it("refuses a default outside the window", () => {
    for (const value of ["30", "7200"]) {
      const issues = loadIssues(validEnv({ RECEIVE_TTL_DEFAULT_SECS: value }));
      expect(
        issues.some((issue) => issue.startsWith("RECEIVE_TTL_DEFAULT_SECS:")),
        `${value}: ${issues.join("\n")}`,
      ).toBe(true);
    }
  });

  it("refuses a runtime change — the policy is frozen at boot", () => {
    // A running node must not form two codes under two policies.
    expect(() => validateMutableSettingsPatch({ RECEIVE_TTL_MAX_SECS: "1800" })).toThrow(
      /RECEIVE_TTL_MAX_SECS/,
    );
  });
});

// Prolonged-wait warn threshold (ZPAY-252) — no longer coupled to healthcheck.
describe("signer-leadership prolonged-wait threshold + healthcheck mirror", () => {
  it("defaults RAILWAY_HEALTHCHECK_TIMEOUT_MS to 150000 and prolonged-wait to 30000", () => {
    const config = loadNodeConfig(validEnv());
    expect(config.RAILWAY_HEALTHCHECK_TIMEOUT_MS).toBe(150_000);
    expect(config.SIGNER_LEADERSHIP_RETRY_MAX_MS).toBe(30_000);
  });

  it("accepts SIGNER_LEADERSHIP_RETRY_MAX_MS above RAILWAY_HEALTHCHECK_TIMEOUT_MS (warn-only)", () => {
    const config = loadNodeConfig(
      validEnv({
        SIGNER_LEADERSHIP_RETRY_MAX_MS: "60000",
        RAILWAY_HEALTHCHECK_TIMEOUT_MS: "30000",
      }),
    );
    expect(config.SIGNER_LEADERSHIP_RETRY_MAX_MS).toBe(60_000);
    expect(config.RAILWAY_HEALTHCHECK_TIMEOUT_MS).toBe(30_000);
  });

  it("accepts independent prolonged-wait and healthcheck values", () => {
    const config = loadNodeConfig(
      validEnv({
        SIGNER_LEADERSHIP_RETRY_MAX_MS: "60000",
        RAILWAY_HEALTHCHECK_TIMEOUT_MS: "120000",
      }),
    );
    expect(config.SIGNER_LEADERSHIP_RETRY_MAX_MS).toBe(60_000);
    expect(config.RAILWAY_HEALTHCHECK_TIMEOUT_MS).toBe(120_000);
  });

  it("classifies RAILWAY_HEALTHCHECK_TIMEOUT_MS as first-boot (not mutable at runtime)", () => {
    expect(FIRST_BOOT_CONFIG_FIELDS).toContain("RAILWAY_HEALTHCHECK_TIMEOUT_MS");
    expect(MUTABLE_CONFIG_FIELDS).not.toContain("RAILWAY_HEALTHCHECK_TIMEOUT_MS");
    expect(() =>
      validateMutableSettingsPatch({ RAILWAY_HEALTHCHECK_TIMEOUT_MS: "120000" }),
    ).toThrow(/RAILWAY_HEALTHCHECK_TIMEOUT_MS/);
  });
});

