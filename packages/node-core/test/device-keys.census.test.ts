// Device-keys census: binds the frozen enrolled-device invariant inventory to the
// literal SQL contract text so the truth carriers (contract inventory and SQL text)
// cannot drift apart silently. Live-database execution is a separate live-database obligation,
// inventoried in the contract, not silently omitted.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  DEVICE_KEYS_INVARIANTS,
  DEVICE_KEYS_SCHEMA_FILE,
  SCHEMA_DEVICE_KEYS_OBLIGATIONS,
} from "../src/schema/device-keys.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", DEVICE_KEYS_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("device-keys schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = DEVICE_KEYS_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("the public key column uses the padded_base64url_pubkey domain, NOT NULL", () => {
    expect(sql).toContain("CREATE DOMAIN padded_base64url_pubkey AS text");
    expect(sql).toContain("public_key padded_base64url_pubkey NOT NULL");
  });

  it("mutation negative: dropping NOT NULL from the public key is caught", () => {
    const removed = sql.replace(
      "public_key padded_base64url_pubkey NOT NULL,",
      "public_key padded_base64url_pubkey,",
    );
    expect(removed).not.toBe(sql);
    const missing = DEVICE_KEYS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("DEVICE_KEY_DOMAIN");
  });

  it("mutation negative: dropping the per-node uniqueness constraint is caught", () => {
    const removed = sql.replace("  UNIQUE (node_id, public_key)\n", "");
    expect(removed).not.toBe(sql);
    const missing = DEVICE_KEYS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("DEVICE_KEY_UNIQUE_PER_NODE");
  });

  it("mutation negative: making revocation NOT NULL (always-revoked) is caught", () => {
    const removed = sql.replace(
      "revoked_at timestamptz,",
      "revoked_at timestamptz NOT NULL,",
    );
    expect(removed).not.toBe(sql);
    const missing = DEVICE_KEYS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("DEVICE_KEY_REVOCATION_NULLABLE");
  });

  it("execution obligations are inventoried, including the label-validation locus", () => {
    expect(SCHEMA_DEVICE_KEYS_OBLIGATIONS.length).toBeGreaterThanOrEqual(4);
    for (const obligation of SCHEMA_DEVICE_KEYS_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
    expect(
      SCHEMA_DEVICE_KEYS_OBLIGATIONS.some((obligation) => obligation.includes("label denylist")),
    ).toBe(true);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
