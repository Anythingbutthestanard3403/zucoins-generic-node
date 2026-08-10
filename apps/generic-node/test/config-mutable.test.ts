import { describe, expect, it } from "vitest";

import {
  FIRST_BOOT_CONFIG_FIELDS,
  MUTABLE_CONFIG_FIELDS,
  NodeMutableSettingsValidationError,
  NodeSettingsClassificationError,
  PLACEHOLDER_METRICS_SCRAPE_TOKEN,
  validateMutableSettingsPatch,
} from "../src/config/index.js";

describe("first-boot vs mutable split", () => {
  it("names every expected first-boot and mutable field", () => {
    expect(FIRST_BOOT_CONFIG_FIELDS).toEqual([
      "NODE_ENV",
      "PORT",
      "BIND_HOST",
      "DATABASE_URL",
      "SPLITCHAIN_GATEWAY_URLS",
      "GATEWAY_TLS_CERT_SHA256_PINS",
      "PUBLIC_BASE_URL",
      "ZUCOINS_PUSH_API_BASE",
      "NODE_ID",
      "INITIAL_ADMIN_USERNAME",
      "INITIAL_ADMIN_PASSWORD",
      // first-boot despite being TTLs — the derived expiry is byte-frozen into a
      // signed transfer code, so a running node must not form two codes under
      // two policies.
      "RECEIVE_TTL_DEFAULT_SECS",
      "RECEIVE_TTL_MIN_SECS",
      "RECEIVE_TTL_MAX_SECS",
      // the vault root-KDF salt is pinned to the row persisted beside the envelopes at
      // first vault-unlock and is insert-only thereafter; changing it on a running node
      // would derive a root key that opens nothing.
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
      // read once at boot into the dual-control policy port; nothing re-applies a
      // changed value to a running node, so mutable would be a lie (ZTR-1148).
      "DUAL_CONTROL_MODE",
    ]);
    expect(MUTABLE_CONFIG_FIELDS).toEqual([
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
    ]);
  });

  it("accepts a valid patch and coerces values through the same bounds as boot", () => {
    const patch = validateMutableSettingsPatch({
      POOL_CAP_TOTAL: "75",
      RECEIVE_QUEUE_MAX_WAIT: 60,
    });
    expect(patch).toEqual({ POOL_CAP_TOTAL: 75, RECEIVE_QUEUE_MAX_WAIT: 60 });
  });

  it("does not leak defaults into an untouched field", () => {
    const patch = validateMutableSettingsPatch({ RECEIVE_QUEUE_MAX_WAIT: 60 });
    expect(Object.keys(patch)).toEqual(["RECEIVE_QUEUE_MAX_WAIT"]);
  });

  it("accepts an empty patch", () => {
    expect(validateMutableSettingsPatch({})).toEqual({});
  });

  it("structurally refuses a first-boot-only field, naming it", () => {
    expect(() => validateMutableSettingsPatch({ DATABASE_URL: "postgresql://x/y" })).toThrow(
      NodeSettingsClassificationError,
    );
    try {
      validateMutableSettingsPatch({ DATABASE_URL: "postgresql://x/y" });
    } catch (error) {
      const classification = error as NodeSettingsClassificationError;
      expect(classification.fields).toEqual(["DATABASE_URL"]);
      expect(classification.message).toContain("First-boot-only");
    }
  });

  it.each([
    "DATABASE_URL",
    "SPLITCHAIN_GATEWAY_URLS",
    "PUBLIC_BASE_URL",
    "INITIAL_ADMIN_PASSWORD",
    "PORT",
  ])("refuses the first-boot field %s through the mutable write path", (field) => {
    expect(() => validateMutableSettingsPatch({ [field]: "anything" })).toThrow(
      NodeSettingsClassificationError,
    );
  });

  it("refuses a patch mixing valid mutable and first-boot fields", () => {
    try {
      validateMutableSettingsPatch({ POOL_CAP_TOTAL: 60, PUBLIC_BASE_URL: "https://x.example" });
      throw new Error("expected refusal");
    } catch (error) {
      expect(error).toBeInstanceOf(NodeSettingsClassificationError);
      expect((error as NodeSettingsClassificationError).fields).toEqual(["PUBLIC_BASE_URL"]);
    }
  });

  it("rejects unknown keys rather than silently dropping them", () => {
    expect(() => validateMutableSettingsPatch({ POOL_TARGET_AVAILABLE: 10 })).toThrow(
      /Unknown configuration field/,
    );
    expect(() => validateMutableSettingsPatch({ SANDBOX_MODE: true })).toThrow(
      NodeSettingsClassificationError,
    );
  });

  it("rejects out-of-bounds values with the boot-path bounds", () => {
    expect(() => validateMutableSettingsPatch({ POOL_CAP_TOTAL: 4 })).toThrow(
      NodeMutableSettingsValidationError,
    );
    expect(() => validateMutableSettingsPatch({ POOL_CAP_TOTAL: 501 })).toThrow(
      NodeMutableSettingsValidationError,
    );
    expect(() => validateMutableSettingsPatch({ ADMIN_CORS_ALLOWED_ORIGINS: "*" })).toThrow(
      NodeMutableSettingsValidationError,
    );
  });

  it("accepts a null metrics token (unmount) and a real high-entropy token", () => {
    expect(validateMutableSettingsPatch({ METRICS_SCRAPE_TOKEN: null })).toEqual({
      METRICS_SCRAPE_TOKEN: null,
    });
    // A legitimately operator-generated token: mixed characters, well over 32,
    // not the .env.example placeholder and not a single repeated character.
    const realToken = "aB3dEf6gHj9kLm2nPq5rStUvWxYz-01-mNbVcXz";
    expect(validateMutableSettingsPatch({ METRICS_SCRAPE_TOKEN: realToken })).toEqual({
      METRICS_SCRAPE_TOKEN: realToken,
    });
  });

  it("fail-closed: rejects a placeholder / no-entropy metrics token exactly as boot does, without echoing it", () => {
    // Boot/mutable parity (placeholders.ts assertNoPlaceholderConfiguration):
    // the exact .env.example placeholder AND any single-repeated-character token
    // have no entropy and would mount /metrics with effectively no auth.
    // Both must be refused on the mutable write path, not only at boot.
    for (const token of [PLACEHOLDER_METRICS_SCRAPE_TOKEN, "b".repeat(48)]) {
      let error: unknown;
      try {
        validateMutableSettingsPatch({ METRICS_SCRAPE_TOKEN: token });
      } catch (caught) {
        error = caught;
      }
      expect(error).toBeInstanceOf(NodeMutableSettingsValidationError);
      const message = (error as Error).message;
      expect(message).toContain("METRICS_SCRAPE_TOKEN");
      expect(message).not.toContain(token);
    }
  });

  it("rejects a too-short metrics token without echoing it", () => {
    const sentinel = "S3NTIN3L-short-token";
    let message = "";
    try {
      validateMutableSettingsPatch({ METRICS_SCRAPE_TOKEN: sentinel });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("METRICS_SCRAPE_TOKEN");
    expect(message).not.toContain(sentinel);
  });
});
