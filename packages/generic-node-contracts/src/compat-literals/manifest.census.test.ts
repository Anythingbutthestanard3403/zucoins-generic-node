import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { COMPAT_LITERALS_CONCERN_MANIFEST } from "./manifest.ts";

const FROZEN_KEYS = [
  "ZP_V1_PURPOSES",
  "ZP1_RECEIVE_MESSAGE_PREFIX",
  "ZP1_RECEIVE_MESSAGE_PATTERN_DESCRIPTION",
  "REPORTING_HEADER_NAMES",
  "TOTP_HEADER_NAME",
  "ZP_HEADER_FAMILY",
  "ZUPAY_COMPAT_NAME",
  "ZUPAYMENTS_COMPAT_NAME",
  "ZUPAY_NODE_DISCOVERY_PATH",
  "ZUPAYMENTS_SDK_ROUTE_PATH",
  "ZUPAYMENTS_PACKAGE_SCOPE_PREFIX",
  "LEGACY_REPORTING_DOMAIN_PREFIXES",
  "LEGACY_ZUPAY_HEADER_NAMES",
  "WALLET_SECRET_AAD_DOMAIN",
  "FORBIDDEN_STATE_ALIASES",
  "FORBIDDEN_EVENT_ALIASES",
  "FORBIDDEN_EVENT_GLOBS",
  "FORBIDDEN_ALIAS_EXCEPTIONS",
  "LITERAL_KINDS",
  "REPLACEMENT_POLICY",
  "COMPATIBILITY_LITERAL_INVENTORY",
  "LITERAL_CONSTRUCTION_SITES",
  "CANONICAL_VERSION_FOR_PURPOSE",
  "CANONICAL_VERSION_V1",
] as const;

describe("COMPAT_LITERALS_CONCERN_MANIFEST (concern-manifest registry leave-behind)", () => {
  it("declares the compat-literals concern and its canonical decision refs", () => {
    expect(COMPAT_LITERALS_CONCERN_MANIFEST.concernId).toBe("compat-literals");
    expect(COMPAT_LITERALS_CONCERN_MANIFEST.decisionRefs).toContain("compat-literal-preservation");
  });

  it("carries the scan rules and the compat-literal-preservation source citation", () => {
    expect(COMPAT_LITERALS_CONCERN_MANIFEST.scanRules).toContain(
      "forbidden-terms:packages/generic-node-contracts/src",
    );
    expect(COMPAT_LITERALS_CONCERN_MANIFEST.sourceDocCitations).toContain("compat-literal-preservation");
  });

  it("carries every frozen const by name, none dropped from the manifest", () => {
    assertFieldOrder(Object.keys(COMPAT_LITERALS_CONCERN_MANIFEST.frozenValues), [...FROZEN_KEYS]);
  });

  it("declares no golden refs (CONTRACT_FREEZE literal data only, no SplitChain/suite goldens)", () => {
    expect(COMPAT_LITERALS_CONCERN_MANIFEST.goldenRefs).toEqual([]);
  });

  it("rejects a manifest with a frozen key silently dropped (negative path)", () => {
    expectRejects(
      () => Object.keys(COMPAT_LITERALS_CONCERN_MANIFEST.frozenValues).filter((key) => key !== "ZP_V1_PURPOSES"),
      (mutated) => assertFieldOrder(mutated, [...FROZEN_KEYS]),
    );
  });
});
