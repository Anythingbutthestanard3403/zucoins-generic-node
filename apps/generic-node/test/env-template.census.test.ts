// Template↔schema traceability census (ZTR-1176). The shipped deployment
// template apps/generic-node/.env.example is the first file a self-hoster
// touches; every uncommented assignment in it must name a live configuration
// key. Two failure classes are gated here:
//   1. The template assigns a var in DELETED_ENV_VARS — loadNodeConfig treats
//      presence as fatal, so `cp .env.example .env` would guarantee exit 1.
//   2. The template assigns a key the frozen NODE_ENV_CONFIG_SCHEMA does not
//      know (and no other loader claims via the allow-list below) — the
//      operator would believe they are tuning a knob that does not exist.
// DELETED_ENV_VARS is imported, never re-listed, so the two cannot drift.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

import { NODE_ENV_CONFIG_SCHEMA } from "../src/config/env-schema.js";
import {
  DELETED_ENV_VARS,
  loadCustodyNodeConfig,
  loadNodeConfig,
  NodeConfigurationError,
} from "../src/config/load.js";
import { loadStage1Config } from "../src/stage1-config.js";

// Keys the template may assign even though they are absent from
// NODE_ENV_CONFIG_SCHEMA, because a different loader reads them from the
// environment. Empty today; every addition must carry a comment naming the
// module that consumes the key.
const TEMPLATE_KEYS_OUTSIDE_SCHEMA: ReadonlySet<string> = new Set([]);

// An assignment is a line whose first character starts the key — commented
// examples (`# VAULT_MASTER_KEY=`) are documentation, not assignments.
const ASSIGNMENT_LINE = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/;

function templateAssignments(): ReadonlyMap<string, string> {
  const templatePath = fileURLToPath(new URL("../.env.example", import.meta.url));
  const assignments = new Map<string, string>();
  for (const line of readFileSync(templatePath, "utf8").split("\n")) {
    const match = ASSIGNMENT_LINE.exec(line);
    if (match !== null) assignments.set(match[1], match[2]);
  }
  return assignments;
}

describe("deployment template census — apps/generic-node/.env.example", () => {
  it("assigns no variable named in DELETED_ENV_VARS (presence is fatal at boot)", () => {
    const offenders = [...templateAssignments().keys()].filter(
      (key) => DELETED_ENV_VARS[key] !== undefined,
    );
    expect(offenders).toEqual([]);
  });

  it("assigns only keys of NODE_ENV_CONFIG_SCHEMA or the explicit allow-list", () => {
    const schemaKeys = new Set(Object.keys(NODE_ENV_CONFIG_SCHEMA.innerType().shape));
    const unknown = [...templateAssignments().keys()].filter(
      (key) => !schemaKeys.has(key) && !TEMPLATE_KEYS_OUTSIDE_SCHEMA.has(key),
    );
    expect(unknown).toEqual([]);
  });

  it("a copied template passes loadNodeConfig validation", () => {
    // Template ships NODE_ENV=development (ZTR-1206). Production placeholder
    // refusal (placeholders.ts) is a separate gate covered in
    // config-placeholders.test.ts; this census proves the frozen schema
    // accepts every shipped value as-is.
    const env = Object.fromEntries(templateAssignments());
    const warn = vi.fn();
    expect(loadNodeConfig(env, warn)).toBeDefined();
  });

  it("local-dev posture: NODE_ENV=development + BACKUP_SCHEDULE_ENABLED=false (ZTR-1206)", () => {
    // Durable-backup gate stays fail-closed for production+backup-off
    // (stage1-production.test.ts). The template must not ship that pair.
    const assignments = templateAssignments();
    expect(assignments.get("NODE_ENV")).toBe("development");
    expect(assignments.get("BACKUP_SCHEDULE_ENABLED")).toBe("false");
    const templatePath = fileURLToPath(new URL("../.env.example", import.meta.url));
    const template = readFileSync(templatePath, "utf8");
    // AC3: both vars document that production must enable the backup schedule.
    expect(template).toContain(
      "MUST set NODE_ENV=production AND BACKUP_SCHEDULE_ENABLED=true",
    );
    expect(template).toContain(
      "stage-1 refuses NODE_ENV=production + this=false",
    );
  });

  it("copied template stage-1 config loads without durable-backup refusal", () => {
    // AC1: after cp .env.example .env (+ filling CHANGE_ME secrets elsewhere),
    // stage-1 must not refuse on the NODE_ENV + BACKUP_SCHEDULE_ENABLED pair.
    const env = Object.fromEntries(templateAssignments());
    const config = loadStage1Config(env);
    expect(config.nodeEnv).toBe("development");
    expect(config.backup).toBeUndefined();
  });

  it("custody load still fails closed on the template's unset VAULT_MASTER_KEY", () => {
    const env = Object.fromEntries(templateAssignments());
    let error: unknown;
    try {
      loadCustodyNodeConfig(env, vi.fn());
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(NodeConfigurationError);
    expect((error as Error).message).toContain(
      "VAULT_MASTER_KEY: must be at least 32 characters",
    );
  });

  it("ships no value for VAULT_MASTER_KEY and documents how to generate one", () => {
    const templatePath = fileURLToPath(new URL("../.env.example", import.meta.url));
    const template = readFileSync(templatePath, "utf8");
    expect(templateAssignments().has("VAULT_MASTER_KEY")).toBe(false);
    expect(template).toContain("openssl rand -base64 48");
  });
});
