import { describe, expect, it } from "vitest";
import {
  assertVaultNeBackup,
  formatEnvFile,
  generateSecretSet,
  setupWizardUrl,
} from "./generate-secrets.mjs";

describe("generate-secrets", () => {
  it("produces vault KEK ≠ backup KEK", () => {
    for (let i = 0; i < 20; i++) {
      const s = generateSecretSet();
      expect(s.VAULT_MASTER_KEY).not.toBe(s.BACKUP_MASTER_KEY);
      assertVaultNeBackup(s);
      expect(s.VAULT_MASTER_KEY.length).toBeGreaterThanOrEqual(32);
      expect(s.BACKUP_MASTER_KEY.length).toBeGreaterThanOrEqual(32);
      expect(s.NODE_ID).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
      expect(s.INITIAL_ADMIN_PASSWORD.length).toBeGreaterThanOrEqual(12);
    }
  });

  it("assertVaultNeBackup throws on equal keys", () => {
    expect(() =>
      assertVaultNeBackup({
        VAULT_MASTER_KEY: "a".repeat(64),
        BACKUP_MASTER_KEY: "a".repeat(64),
      }),
    ).toThrow(/must not equal/);
  });

  it("setup wizard URL is PUBLIC_BASE_URL/setup", () => {
    expect(setupWizardUrl("https://node.example.com/")).toBe("https://node.example.com/setup");
    expect(setupWizardUrl("http://127.0.0.1:8787")).toBe("http://127.0.0.1:8787/setup");
  });

  it("env file never embeds a second copy of vault into backup", () => {
    const s = generateSecretSet();
    const body = formatEnvFile(s, { SETUP_URL: setupWizardUrl("http://localhost:8787") });
    expect(body).toMatch(/DO NOT COMMIT/);
    expect(body).toContain(`VAULT_MASTER_KEY=${s.VAULT_MASTER_KEY}`);
    expect(body).toContain(`BACKUP_MASTER_KEY=${s.BACKUP_MASTER_KEY}`);
    expect(body).toContain("SETUP_URL=http://localhost:8787/setup");
    // secrets not equal
    const vaultLine = body.split("\n").find((l) => l.startsWith("VAULT_MASTER_KEY="));
    const backupLine = body.split("\n").find((l) => l.startsWith("BACKUP_MASTER_KEY="));
    expect(vaultLine).not.toBe(backupLine);
  });
});
