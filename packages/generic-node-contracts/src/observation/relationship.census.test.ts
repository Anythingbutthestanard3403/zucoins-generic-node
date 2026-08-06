import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import { OBSERVATION_RELATIONSHIPS } from "./enums.contract.ts";
import {
  COMPARISON_LADDER,
  RELATIONSHIP_CLASSIFICATION_RULES,
  CLASSIFIER_OUTPUT_RELATIONSHIPS,
  NON_CLASSIFIER_RELATIONSHIPS,
  STATE_UNCHANGED_RELATIONSHIP,
} from "./relationship.contract.ts";

describe("relationship classification table is frozen (the observation concern.2)", () => {
  it("comparison ladder sequence — the observation dedup freeze bytes then the semantic layer", () => {
    expect(COMPARISON_LADDER).toHaveLength(3);
    expect(COMPARISON_LADDER[0]).toContain("byte-dedup primitive");
    expect(COMPARISON_LADDER[1]).toContain("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
  });

  it("classification rules — condition sequence is the frozen evaluation precedence", () => {
    assertFieldOrder(
      RELATIONSHIP_CLASSIFICATION_RULES.map((rule) => rule.conditionId),
      [
        "NO_PRIOR",
        "SEMANTIC_FINGERPRINT_EQUAL",
        "BACKLINK_TO_PRIOR",
        "SAME_S_FINGERPRINT_DIFFERS",
        "GENESIS_AFTER_HISTORY",
        "RECURRENCE_OF_OLDER_S",
        "DIFFERENT_S_NO_BACKLINK",
      ],
    );
  });

  it("each rule maps to its frozen relationship and state_changed", () => {
    assertFieldOrder(
      RELATIONSHIP_CLASSIFICATION_RULES.map((rule) => [rule.relationship, rule.stateChanged]),
      [
        ["FIRST", true],
        ["EQUIVALENT_STATE_DIFFERENT_ENVELOPE", false],
        ["SUCCESSOR", true],
        ["SIGNATURE_COLLISION", true],
        ["GENESIS_AFTER_HISTORY", true],
        ["REGRESSION", true],
        ["UNEXPLAINED_JUMP", true],
      ],
    );
  });

  it("EQUIVALENT_STATE_DIFFERENT_ENVELOPE is the only state-unchanged classifier output (negative path)", () => {
    expect(STATE_UNCHANGED_RELATIONSHIP).toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
    const unchanged = RELATIONSHIP_CLASSIFICATION_RULES.filter((rule) => !rule.stateChanged);
    expect(unchanged.map((rule) => rule.relationship)).toEqual([
      "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
    ]);
  });

  it("classifier outputs plus non-classifier members exactly cover the observation dedup freeze relationship enum", () => {
    const nonClassifierKeys = Object.keys(NON_CLASSIFIER_RELATIONSHIPS);
    expect([...CLASSIFIER_OUTPUT_RELATIONSHIPS, ...nonClassifierKeys].sort()).toEqual(
      [...OBSERVATION_RELATIONSHIPS].sort(),
    );
  });

  it("the three non-classifier members are documented as such", () => {
    expect(Object.keys(NON_CLASSIFIER_RELATIONSHIPS).sort()).toEqual([
      "COMPLETE_PATH_SUCCESSOR",
      "DUPLICATE",
      "NOT_APPLICABLE",
    ]);
  });
});
