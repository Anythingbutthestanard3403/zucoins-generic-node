// Secret-safe effective config allowlist.
// Fails closed if secret-shaped keys ever appear on the serialized DTO.

import { describe, expect, it } from "vitest";

import {
  buildEffectiveConfig,
  EFFECTIVE_CONFIG_ALLOWLIST_KEYS,
  findForbiddenKeys,
  gatewayHostname,
  isSecretShapedKey,
  serializeEffectiveConfig,
  type EffectiveConfigDto,
} from "./effective-config.js";

const ALLOW = new Set<string>(EFFECTIVE_CONFIG_ALLOWLIST_KEYS);

describe("buildEffectiveConfig", () => {
  it("emits only allowlisted keys matching process inputs", () => {
    const dto = buildEffectiveConfig({
      publicBaseUrl: "https://node.example",
      nodeId: "11111111-1111-4111-8111-111111111111",
      gatewayUrls: [
        "https://gw-a.splitchain.example/v1",
        "https://gw-b.splitchain.example:8443/",
        "https://gw-a.splitchain.example/other", // de-dupe host
      ],
      version: "0.0.0",
      backupScheduleEnabled: true,
      pushConfigured: false,
    });

    expect(dto).toEqual({
      public_base_url: "https://node.example",
      node_id: "11111111-1111-4111-8111-111111111111",
      gateway_hosts: ["gw-a.splitchain.example", "gw-b.splitchain.example:8443"],
      version: "0.0.0",
      backup_schedule_enabled: true,
      push_configured: false,
    });

    const wire = serializeEffectiveConfig(dto);
    expect(Object.keys(wire).sort()).toEqual([...EFFECTIVE_CONFIG_ALLOWLIST_KEYS].sort());
    expect(findForbiddenKeys(wire, { topLevelAllowlist: ALLOW })).toEqual([]);
  });

  it("never copies extra properties from a polluted input object", () => {
    const polluted = {
      publicBaseUrl: "https://node.example",
      nodeId: "11111111-1111-4111-8111-111111111111",
      gatewayUrls: ["https://gw.example"],
      version: "1.2.3",
      backupScheduleEnabled: false,
      pushConfigured: true,
      // Would-be secrets an accidental env dump might inject:
      BACKUP_MASTER_KEY: "super-secret-master-key-material-xxxx",
      DATABASE_URL: "postgres://user:password@db/zucoins",
      METRICS_SCRAPE_TOKEN: "t".repeat(40),
      VAULT_MASTER_KEY: "vault-master-should-never-leak",
      password: "admin-password",
      ik_seed: "ik_abcdef",
    } as unknown as Parameters<typeof buildEffectiveConfig>[0];

    const wire = serializeEffectiveConfig(buildEffectiveConfig(polluted));
    const forbidden = findForbiddenKeys(wire, { topLevelAllowlist: ALLOW });
    expect(forbidden).toEqual([]);
    expect(JSON.stringify(wire)).not.toMatch(/super-secret|password@db|vault-master|ik_abcdef|admin-password/i);
    for (const secretKey of [
      "BACKUP_MASTER_KEY",
      "DATABASE_URL",
      "METRICS_SCRAPE_TOKEN",
      "VAULT_MASTER_KEY",
      "password",
      "ik_seed",
    ]) {
      expect(wire).not.toHaveProperty(secretKey);
    }
  });

  it("gatewayHostname extracts host only", () => {
    expect(gatewayHostname("https://user:pass@gw.example:443/path?q=1")).toBe("gw.example");
    expect(gatewayHostname("not a url")).toBeNull();
  });
});

describe("secret-key deny list", () => {
  it("flags secret-shaped keys", () => {
    for (const k of [
      "PASSWORD",
      "admin_password",
      "SECRET",
      "client_secret",
      "TOKEN",
      "access_token",
      "PRIVATE_KEY",
      "private",
      "BACKUP_MASTER_KEY",
      "VAULT_MASTER",
      "vapid_private_key",
      "ik_foo",
      "sh_bar",
      "API_KEY",
      "totp_seed",
      "DATABASE_URL",
      "kek_material",
    ]) {
      expect(isSecretShapedKey(k), k).toBe(true);
    }
  });

  it("allows support-useful keys", () => {
    for (const k of EFFECTIVE_CONFIG_ALLOWLIST_KEYS) {
      expect(isSecretShapedKey(k), k).toBe(false);
    }
  });

  it("fuzz: random secret-looking keys never survive serialization", () => {
    const secretCandidates = [
      "PASSWORD",
      "INITIAL_ADMIN_PASSWORD",
      "SECRET",
      "SESSION_SECRET",
      "TOKEN",
      "METRICS_SCRAPE_TOKEN",
      "PRIVATE",
      "NODE_IDENTITY_SEED",
      "BACKUP_MASTER_KEY",
      "VAULT_MASTER_KEY",
      "VAPID_PRIVATE_KEY",
      "ik_abc123",
      "sh_xyz789",
      "GATEWAY_API_KEY",
      "TOTP_SEED",
      "DATABASE_URL",
      "credential_hash",
    ];

    // Simulate a buggy serializer that spreads env + dto.
    const dto: EffectiveConfigDto = buildEffectiveConfig({
      publicBaseUrl: "https://node.example",
      nodeId: "22222222-2222-4222-8222-222222222222",
      gatewayUrls: ["https://gw.example"],
      version: "0.0.0",
      backupScheduleEnabled: false,
      pushConfigured: false,
    });
    const correct = serializeEffectiveConfig(dto);

    // Correct path is clean.
    expect(findForbiddenKeys(correct, { topLevelAllowlist: ALLOW })).toEqual([]);

    // Buggy path would fail the same assertion — documents the contract.
    const buggy: Record<string, unknown> = { ...correct };
    for (const k of secretCandidates) {
      buggy[k] = `leaked-value-for-${k}`;
    }
    const leaks = findForbiddenKeys(buggy, { topLevelAllowlist: ALLOW });
    expect(leaks.length).toBeGreaterThan(0);
    for (const k of secretCandidates) {
      expect(leaks).toContain(k);
    }
  });
});
