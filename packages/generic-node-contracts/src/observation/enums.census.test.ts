import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import {
  OBSERVER_DOMAINS,
  OBSERVATION_PARSE_RESULTS,
  VERIFIED_PARSE_RESULTS,
  OBSERVATION_RELATIONSHIPS,
  WALLET_OBSERVATION_ROLES,
  OBSERVATION_ANOMALY_KINDS,
  isVerifiedParseResult,
} from "./enums.contract.ts";

describe("observation enum vocabularies are frozen (the observation dedup freeze; data-model CHECK domains)", () => {
  it("observer_domain", () => {
    assertFieldOrder(OBSERVER_DOMAINS, ["NODE", "PLATFORM"]);
  });

  it("observation_parse_result — exact members and sequence", () => {
    assertFieldOrder(OBSERVATION_PARSE_RESULTS, [
      "VERIFIED_GENESIS",
      "VERIFIED_HEAD",
      "TRANSPORT_ERROR",
      "MALFORMED_ENVELOPE",
      "MALFORMED_TRANSACTION",
      "UNVERIFIED_SIGNATURE",
      "WALLET_ROLE_INVALID",
    ]);
  });

  it("verified parse results are exactly the two VERIFIED_* members", () => {
    assertFieldOrder(VERIFIED_PARSE_RESULTS, ["VERIFIED_GENESIS", "VERIFIED_HEAD"]);
    for (const value of VERIFIED_PARSE_RESULTS) {
      expect(OBSERVATION_PARSE_RESULTS).toContain(value);
    }
  });

  it("observation_relationship — exact members and sequence", () => {
    assertFieldOrder(OBSERVATION_RELATIONSHIPS, [
      "FIRST",
      "SUCCESSOR",
      "COMPLETE_PATH_SUCCESSOR",
      "DUPLICATE",
      "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
      "REGRESSION",
      "UNEXPLAINED_JUMP",
      "GENESIS_AFTER_HISTORY",
      "SIGNATURE_COLLISION",
      "NOT_APPLICABLE",
    ]);
  });

  it("gateway_observations.wallet_role domain", () => {
    assertFieldOrder(WALLET_OBSERVATION_ROLES, ["sender", "receiver", "genesis"]);
  });

  it("observation_anomalies.kind — exact members and sequence", () => {
    assertFieldOrder(OBSERVATION_ANOMALY_KINDS, [
      "TRANSPORT_ERROR",
      "MALFORMED_ENVELOPE",
      "MALFORMED_TRANSACTION",
      "UNVERIFIED_SIGNATURE",
      "WALLET_ROLE_INVALID",
      "REGRESSION",
      "UNEXPLAINED_JUMP",
      "GENESIS_AFTER_HISTORY",
      "SIGNATURE_COLLISION",
    ]);
  });

  it("anomaly kinds are exactly the non-verified parse results plus the four anomalous relationships", () => {
    const nonVerifiedParse = OBSERVATION_PARSE_RESULTS.filter(
      (value) => !isVerifiedParseResult(value),
    );
    const anomalousRelationships = [
      "REGRESSION",
      "UNEXPLAINED_JUMP",
      "GENESIS_AFTER_HISTORY",
      "SIGNATURE_COLLISION",
    ];
    expect([...OBSERVATION_ANOMALY_KINDS].sort()).toEqual(
      [...nonVerifiedParse, ...anomalousRelationships].sort(),
    );
  });

  it("isVerifiedParseResult accepts verified and rejects everything else (negative path)", () => {
    expect(isVerifiedParseResult("VERIFIED_HEAD")).toBe(true);
    expect(isVerifiedParseResult("VERIFIED_GENESIS")).toBe(true);
    expect(isVerifiedParseResult("MALFORMED_ENVELOPE")).toBe(false);
    expect(isVerifiedParseResult("VERIFIED_FOO")).toBe(false);
  });
});
