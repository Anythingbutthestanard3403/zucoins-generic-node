import { describe, it, expect } from "vitest";
import {
  GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS,
  assertGenericNodeNoPlatformMintedSecrets,
  buildGenericNodeRailwayDeployUrl,
} from "./railway-template-catalog.js";

describe("GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS", () => {
  it("never sources a secret from a static default or non-Railway source", () => {
    expect(() => assertGenericNodeNoPlatformMintedSecrets()).not.toThrow();
  });

  it("flags a secret sourced from a static default", () => {
    expect(() =>
      assertGenericNodeNoPlatformMintedSecrets([
        { key: "X", source: "static-default", value: "x", secret: true, description: "" },
      ]),
    ).toThrow(/X/);
  });

  it("flags a secret sourced from service-domain", () => {
    expect(() =>
      assertGenericNodeNoPlatformMintedSecrets([
        { key: "Y", source: "service-domain", value: "y", secret: true, description: "" },
      ]),
    ).toThrow(/Y/);
  });

  it("declares every hard-required env var from the frozen config schema", () => {
    const keys = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.map((v) => v.key);
    for (const required of [
      "DATABASE_URL",
      "SPLITCHAIN_GATEWAY_URLS",
      "NODE_ID",
      "VAULT_MASTER_KEY",
      "INITIAL_ADMIN_PASSWORD",
      "BACKUP_MASTER_KEY",
    ]) {
      expect(keys, `missing ${required}`).toContain(required);
    }
  });

  it("wires DATABASE_URL from the Postgres plugin (direct-session, not pooled)", () => {
    const dbUrl = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "DATABASE_URL",
    );
    expect(dbUrl).toBeDefined();
    expect(dbUrl?.source).toBe("postgres-plugin");
    expect(dbUrl?.value).toBe("${{Postgres.DATABASE_URL}}");
    expect(dbUrl?.secret).toBe(true);
  });

  it("prefills SPLITCHAIN_GATEWAY_URLS with the production gateway endpoint", () => {
    const gw = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "SPLITCHAIN_GATEWAY_URLS",
    );
    expect(gw).toBeDefined();
    expect(gw?.source).toBe("static-default");
    expect(gw?.secret).toBe(false);
    expect(gw?.value).toBe("https://gateway-entry-1-q2whsu3jlj.splitchain.com/");
  });

  it("does NOT declare PUBLIC_BASE_URL (derived from RAILWAY_PUBLIC_DOMAIN at boot)", () => {
    const keys = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.map((v) => v.key);
    expect(keys).not.toContain("PUBLIC_BASE_URL");
  });

  it("generates VAULT_MASTER_KEY as a Railway secret (>=32 chars)", () => {
    const vmk = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "VAULT_MASTER_KEY",
    );
    expect(vmk).toBeDefined();
    expect(vmk?.source).toBe("generator");
    expect(vmk?.secret).toBe(true);
    expect(vmk?.value).toBe("${{secret(64)}}");
  });

  it("generates NODE_ID as a Railway secret with hex alphabet", () => {
    const nid = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "NODE_ID",
    );
    expect(nid).toBeDefined();
    expect(nid?.source).toBe("generator");
    expect(nid?.secret).toBe(true);
    // Pinned exact value: MUST use hex alphabet so withCanonicalNodeId's
    // /^[0-9a-f]{32}$/i regex matches. Default secret(32) uses 62-char
    // alphanumeric which never matches and crash-loops the node.
    expect(nid?.value).toBe('${{secret(32, "abcdef0123456789")}}');
    // Verify the template expression references a hex-only charset
    expect(nid?.value).toMatch(/secret\(32,\s*"abcdef0123456789"\)/);
  });

  it("generates INITIAL_ADMIN_PASSWORD as a Railway secret (>=12 chars)", () => {
    const iap = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "INITIAL_ADMIN_PASSWORD",
    );
    expect(iap).toBeDefined();
    expect(iap?.source).toBe("generator");
    expect(iap?.secret).toBe(true);
    expect(iap?.value).toBe("${{secret(32)}}");
  });

  it("generates BACKUP_MASTER_KEY as a Railway secret (>=32 chars)", () => {
    const bmk = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "BACKUP_MASTER_KEY",
    );
    expect(bmk).toBeDefined();
    expect(bmk?.source).toBe("generator");
    expect(bmk?.secret).toBe(true);
    expect(bmk?.value).toBe("${{secret(64)}}");
  });

  it("enables the backup schedule and sets a non-tmp output dir", () => {
    const sched = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "BACKUP_SCHEDULE_ENABLED",
    );
    expect(sched?.value).toBe("true");

    const outDir = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "BACKUP_OUTPUT_DIR",
    );
    expect(outDir?.value).toBe("/var/lib/generic-node/backups");
    expect(outDir?.value).not.toMatch(/^\/tmp/);
  });

  it("sets NODE_ENV=production", () => {
    const nodeEnv = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.find(
      (v) => v.key === "NODE_ENV",
    );
    expect(nodeEnv?.value).toBe("production");
  });

  it("declares all merchant-entered fields as non-secret", () => {
    const nonSecrets = GENERIC_NODE_RAILWAY_TEMPLATE_ENV_VARS.filter(
      (v) => !v.secret,
    );
    for (const v of nonSecrets) {
      expect(["static-default", "service-domain"]).toContain(v.source);
    }
  });
});

describe("buildGenericNodeRailwayDeployUrl", () => {
  it("builds the documented deep-link format", () => {
    expect(buildGenericNodeRailwayDeployUrl("generic-v1")).toBe(
      "https://railway.com/deploy/generic-v1?referralCode=zupayments",
    );
  });

  it("always uses the caller-supplied template code, never a hardcoded one", () => {
    expect(buildGenericNodeRailwayDeployUrl("code-a")).toContain("/deploy/code-a");
    expect(buildGenericNodeRailwayDeployUrl("code-b")).toContain("/deploy/code-b");
  });

  it("rejects an empty template code", () => {
    expect(() => buildGenericNodeRailwayDeployUrl("")).toThrow();
  });

  it("rejects a template code with invalid characters", () => {
    expect(() => buildGenericNodeRailwayDeployUrl("has a space")).toThrow();
  });
});
