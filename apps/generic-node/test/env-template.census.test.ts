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
    // NODE_ENV is forced to development because the production placeholder
    // refusal (placeholders.ts) is a separate, deliberate gate with its own
    // coverage in config-placeholders.test.ts; this census proves the frozen
    // schema itself accepts every shipped value.
    const env = {
      ...Object.fromEntries(templateAssignments()),
      NODE_ENV: "development",
    };
    const warn = vi.fn();
    expect(loadNodeConfig(env, warn)).toBeDefined();
  });

  it("custody load still fails closed on the template's unset VAULT_MASTER_KEY", () => {
    const env = {
      ...Object.fromEntries(templateAssignments()),
      NODE_ENV: "development",
    };
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
