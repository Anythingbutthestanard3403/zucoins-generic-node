// Inventory census gate: proves the repository-wide retained-literal inventory is a closed
// well-formed set, with the mandatory negative path — a fabricated purpose is absent.
//
// This module's `literal` fields are all imported from `compat-literals.contract.ts`
// (never retyped), so there is no separate artifacts cross-check needed here — the three
// expected-artifact purposes are already this concern's own byte authority for the bare
// purpose strings.
import { describe, expect, it } from "vitest";

import { assertClosedSet, expectRejects } from "../testkit/freeze.ts";
import { LITERAL_KINDS } from "./kinds.ts";
import { COMPATIBILITY_LITERAL_INVENTORY, COMPATIBILITY_LITERAL_VALUES } from "./inventory.contract.ts";
import { isKnownCompatibilityLiteral, findCompatibilityLiteralCaseInsensitive } from "./verify.ts";
import { ZP_V1_PURPOSES, ZP_HEADER_FAMILY, ZUPAY_NODE_DISCOVERY_PATH } from "./compat-literals.contract.ts";
import { PUBLIC_ROUTES } from "../operations/routes.contract.ts";

describe("compatibility-literal inventory census", () => {
  it("freezes the closed kind set to exactly the four retained-literal clauses", () => {
    assertClosedSet(LITERAL_KINDS, ["signed-purpose", "wire-prefix", "header", "name"]);
  });

  it("has no duplicate literal strings (one row per retained literal)", () => {
    expect(new Set(COMPATIBILITY_LITERAL_VALUES).size).toBe(COMPATIBILITY_LITERAL_VALUES.length);
  });

  it("every entry declares a non-empty kind, definingContract, and machineFrozenAt", () => {
    for (const entry of COMPATIBILITY_LITERAL_INVENTORY) {
      expect(LITERAL_KINDS).toContain(entry.kind);
      expect(entry.definingContract.length).toBeGreaterThan(0);
      expect(entry.machineFrozenAt.length).toBeGreaterThan(0);
      expect(typeof entry.caseSensitive).toBe("boolean");
      expect(typeof entry.byteSensitive).toBe("boolean");
    }
  });

  it("freezes the exact per-kind membership counts", () => {
    const countOf = (kind: string) => COMPATIBILITY_LITERAL_INVENTORY.filter((e) => e.kind === kind).length;
    expect(countOf("signed-purpose")).toBe(11);
    expect(countOf("wire-prefix")).toBe(1);
    expect(countOf("header")).toBe(9);
    expect(countOf("name")).toBe(8);
    expect(COMPATIBILITY_LITERAL_INVENTORY).toHaveLength(29);
  });

  it("contains every ZP_V1_PURPOSES member and every ZP_HEADER_FAMILY member (single source of truth)", () => {
    for (const purpose of ZP_V1_PURPOSES) {
      expect(isKnownCompatibilityLiteral(purpose)).toBe(true);
    }
    for (const header of ZP_HEADER_FAMILY) {
      expect(isKnownCompatibilityLiteral(header)).toBe(true);
    }
  });

  it("cross-checks /.well-known/zupay-node against the v2 PUBLIC_ROUTES (single source of truth)", () => {
    const inventoryEntry = COMPATIBILITY_LITERAL_INVENTORY.find((e) => e.literal === ZUPAY_NODE_DISCOVERY_PATH);
    const liveRoute = PUBLIC_ROUTES.find((route) => route.path === ZUPAY_NODE_DISCOVERY_PATH);
    expect(inventoryEntry).toBeDefined();
    expect(liveRoute).toBeDefined();
    expect(liveRoute?.authMode).toBe("public");
  });

  it("flags every entry whose construction has no owning code yet (docs-only gap)", () => {
    const gaps = COMPATIBILITY_LITERAL_INVENTORY.filter((e) => e.machineFrozenAt.startsWith("docs-only"));
    const gapLiterals = gaps.map((e) => e.literal).sort();
    // The census reports these as findings rather than guessing an owner. The three
    // expected-artifact purposes are a DIFFERENT kind of gap (owned by the artifacts concern —
    // not "no code has claimed it") and deliberately do not appear here.
    expect(gapLiterals).toEqual(
      [
        "zp-send-external-approval-v1",
        "zp-destination-bless-v1",
        "zp-device-enrol-v1",
        "zp-wallet-head-fingerprint-v1",
      ].sort(),
    );
  });

  it("accepts every frozen literal exactly (positive path)", () => {
    for (const literal of COMPATIBILITY_LITERAL_VALUES) {
      expect(isKnownCompatibilityLiteral(literal)).toBe(true);
    }
  });

  it("rejects a fabricated zp-fake-v1 purpose (negative path)", () => {
    const assertKnownLiteral = (candidate: string): void => {
      expect(isKnownCompatibilityLiteral(candidate)).toBe(true);
    };
    expect(isKnownCompatibilityLiteral("zp-fake-v1")).toBe(false);
    expectRejects(() => "zp-fake-v1", assertKnownLiteral);
  });

  it("rejects a lowercase x-zp-totp header variant even though a case-insensitive lookup finds it (negative path)", () => {
    expect(isKnownCompatibilityLiteral("x-zp-totp")).toBe(false);
    expect(isKnownCompatibilityLiteral("X-ZP-TOTP")).toBe(true);
    // Proves the miss above is a deliberate exact-case gate, not a broken lookup.
    expect(findCompatibilityLiteralCaseInsensitive("x-zp-totp")?.literal).toBe("X-ZP-TOTP");
  });

  it("rejects a case-mutated zp1: prefix (negative path, on-chain byte-sensitive family)", () => {
    expect(isKnownCompatibilityLiteral("ZP1:")).toBe(false);
    expect(isKnownCompatibilityLiteral("zp1:")).toBe(true);
  });
});
