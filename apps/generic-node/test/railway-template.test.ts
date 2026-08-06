// Railway deploy template integration test for the v2 generic node.
//
// Validates that railway.json carries the correct deploy configuration for a
// one-click template deploy: healthcheckTimeout raised to 150s (readiness
// needs a live gateway round-trip, bounded retry ~150s worst case), and the
// template variable catalog (./railway-template-catalog.ts) declares every
// hard-required env var from the frozen config schema.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS,
  assertGenericNodeNoPlatformMintedSecrets,
} from "./railway-template-catalog.js";

describe("Railway deploy template (railway.json + variable catalog)", () => {
  it("railway.json sets healthcheckTimeout to 150s (readiness needs live gateway round-trip)", () => {
    const railwayJsonPath = fileURLToPath(
      new URL("../railway.json", import.meta.url),
    );
    const railwayConfig = JSON.parse(readFileSync(railwayJsonPath, "utf8"));
    expect(railwayConfig.deploy.healthcheckTimeout).toBe(150);
  });

  it("railway.json healthcheckPath is /health/ready", () => {
    const railwayJsonPath = fileURLToPath(
      new URL("../railway.json", import.meta.url),
    );
    const railwayConfig = JSON.parse(readFileSync(railwayJsonPath, "utf8"));
    expect(railwayConfig.deploy.healthcheckPath).toBe("/health/ready");
  });

  it("railway.json restart policy is ON_FAILURE with bounded retries", () => {
    const railwayJsonPath = fileURLToPath(
      new URL("../railway.json", import.meta.url),
    );
    const railwayConfig = JSON.parse(readFileSync(railwayJsonPath, "utf8"));
    expect(railwayConfig.deploy.restartPolicyType).toBe("ON_FAILURE");
    expect(railwayConfig.deploy.restartPolicyMaxRetries).toBeGreaterThan(0);
  });

  it("template catalog declares every hard-required env var", () => {
    const keys = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.map((v) => v.key);
    // Hard-required by the frozen schema:
    // DATABASE_URL, SPLITCHAIN_GATEWAY_URLS, NODE_ID, VAULT_MASTER_KEY
    // Plus conditional: BACKUP_MASTER_KEY (when BACKUP_SCHEDULE_ENABLED=true)
    // Plus first-boot: INITIAL_ADMIN_PASSWORD
    for (const required of [
      "DATABASE_URL",
      "SPLITCHAIN_GATEWAY_URLS",
      "NODE_ID",
      "VAULT_MASTER_KEY",
      "INITIAL_ADMIN_PASSWORD",
      "BACKUP_MASTER_KEY",
    ]) {
      expect(keys, `template must declare ${required}`).toContain(required);
    }
  });

  it("template catalog passes the no-platform-minted-secrets guard", () => {
    expect(() => assertGenericNodeNoPlatformMintedSecrets()).not.toThrow();
  });

  it("DATABASE_URL is wired from the Postgres plugin (direct-session, not pooled)", () => {
    const dbUrl = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "DATABASE_URL",
    );
    expect(dbUrl?.source).toBe("postgres-plugin");
    expect(dbUrl?.value).toContain("Postgres.DATABASE_URL");
  });

  it("SPLITCHAIN_GATEWAY_URLS is prefilled with the production gateway (not a placeholder)", () => {
    const gw = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "SPLITCHAIN_GATEWAY_URLS",
    );
    expect(gw?.value).not.toContain("example.invalid");
    expect(gw?.value).toContain("splitchain.com");
  });

  it("PUBLIC_BASE_URL is NOT declared (derived from RAILWAY_PUBLIC_DOMAIN at boot)", () => {
    const keys = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.map((v) => v.key);
    expect(keys).not.toContain("PUBLIC_BASE_URL");
  });

  it("backup schedule is enabled with a non-tmp output dir", () => {
    const sched = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "BACKUP_SCHEDULE_ENABLED",
    );
    expect(sched?.value).toBe("true");

    const outDir = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "BACKUP_OUTPUT_DIR",
    );
    expect(outDir?.value).not.toMatch(/^\/tmp/);
    expect(outDir?.value).toContain("backups");
  });

  it("all secret vars are sourced from Railway (generator or postgres-plugin)", () => {
    const secrets = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.filter((v) => v.secret);
    for (const s of secrets) {
      expect(["generator", "postgres-plugin"]).toContain(s.source);
    }
  });
});
