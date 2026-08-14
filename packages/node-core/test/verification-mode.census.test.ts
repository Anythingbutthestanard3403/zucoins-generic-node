// Census: binds verification-mode.contract.ts invariants to the literal ALTER SQL
// (ZTR-1300). Peer of wallet-money-capability.census / dual-control-policy.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION,
  ALLOW_NODE_VERIFIED_SETTING_KEY,
  DEFAULT_VERIFICATION_MODE,
  RELEASED_NODE_VERIFIED,
  VERIFICATION_MODES,
} from "@zucoins/generic-node-contracts/operations";

import {
  VERIFICATION_MODE_SCHEMA_EXECUTION_OBLIGATIONS,
  VERIFICATION_MODE_SCHEMA_FILE,
  VERIFICATION_MODE_SCHEMA_INVARIANTS,
} from "../src/schema/verification-mode.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", VERIFICATION_MODE_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const sqlBody = sql.replace(/--.*$/gm, "");

describe("verification-mode schema census (ZTR-1300)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = VERIFICATION_MODE_SCHEMA_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("extends operations / receive_operations / send_operations — no CREATE TABLE", () => {
    expect(sqlBody).toMatch(/ALTER TABLE operations\b/);
    expect(sqlBody).toMatch(/ALTER TABLE receive_operations\b/);
    expect(sqlBody).toMatch(/ALTER TABLE send_operations\b/);
    expect(sqlBody).not.toMatch(/CREATE TABLE\b/);
  });

  it("closes verification_mode against the two frozen contract labels + default", () => {
    for (const mode of VERIFICATION_MODES) {
      expect(sqlBody).toContain(`'${mode}'`);
    }
    expect(DEFAULT_VERIFICATION_MODE).toBe("INDEPENDENT");
    expect(sqlBody).toContain("DEFAULT 'INDEPENDENT'");
    expect(sqlBody).toContain("chk_operations_verification_mode");
    expect(sqlBody).toContain("chk_receive_verification_mode");
    expect(sqlBody).toContain("chk_send_verification_mode");
  });

  it("widens receive_release_status with RELEASED_NODE_VERIFIED", () => {
    expect(RELEASED_NODE_VERIFIED).toBe("RELEASED_NODE_VERIFIED");
    expect(sqlBody).toContain("'RELEASED_NODE_VERIFIED'");
    expect(sqlBody).toContain("'RELEASED_T0_UNCHANGED'");
    expect(sqlBody).toContain("'RELEASED_PROVEN_NOT_STARTED'");
    expect(sqlBody).toContain("'RELEASED_OPERATOR_ACCEPTED_RISK'");
  });

  it("installs immutability triggers on all three mode carriers", () => {
    expect(sqlBody).toContain("VERIFICATION_MODE_IMMUTABLE");
    expect(sqlBody).toContain("operations_verification_mode_immutable");
    expect(sqlBody).toContain("receive_operations_verification_mode_immutable");
    expect(sqlBody).toContain("send_operations_verification_mode_immutable");
  });

  it("pins policy key / audit action to contracts vocabulary (no seed)", () => {
    expect(ALLOW_NODE_VERIFIED_SETTING_KEY).toBe("ops.allow_node_verified");
    expect(ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION).toBe(
      "ops.allow_node_verified_changed",
    );
    expect(sql).toMatch(/does NOT seed a row/i);
    expect(sqlBody).not.toMatch(/INSERT\s+INTO\s+node_settings/i);
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(VERIFICATION_MODE_SCHEMA_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
    for (const obligation of VERIFICATION_MODE_SCHEMA_EXECUTION_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });

  it("mutation negative: removing an anchored clause is caught by the census", () => {
    const mutated = sql.replaceAll("chk_operations_verification_mode", "-- removed");
    const missing = VERIFICATION_MODE_SCHEMA_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["OPERATIONS_MODE_CLOSED"]);
  });
});
