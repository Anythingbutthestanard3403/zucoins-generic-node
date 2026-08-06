import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  FIELDS_CONTRACT_VERSION,
  SPLITCHAIN_INNER_FIELD_SEQUENCE,
  SPLITCHAIN_INNER_FIXED_LITERALS,
  SPLITCHAIN_INNER_OPTIONAL_FIELDS,
  SPLITCHAIN_INNER_PROHIBITIONS,
  SPLITCHAIN_INNER_REQUIRED_FIELD_SEQUENCE,
  SPLITCHAIN_PREIMAGE_CONSTRUCTION,
  SPLITCHAIN_SETTLED_TEXT_FIELD_SEQUENCE,
  SPLITCHAIN_STATE_OBJECT_FIELD_SEQUENCE,
  SPLITCHAIN_STEP_2_PREIMAGE_FIELD_SEQUENCE,
} from "./fields.contract.ts";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Top-level key sequence of a committed golden JSON file (the A.8.1 receive chain). */
const goldenKeySequence = (relativePath: string): string[] =>
  Object.keys(JSON.parse(readFileSync(join(packageRoot, relativePath), "utf8")) as object);

describe("fields census (the fixture-provenance purposes census, protocol rule 3; A.1.2)", () => {
  it("freezes the exact 14-position inner field sequence", () => {
    assertFieldOrder(SPLITCHAIN_INNER_FIELD_SEQUENCE, [
      "type",
      "version",
      "unix_time_secs",
      "signer_steps",
      "step_1_signer",
      "step_2_signer",
      "step_1_key_public__base64urlsafe",
      "step_2_key_public__base64urlsafe",
      "step_1_state",
      "step_2_state",
      "previous_step_1_state_signature",
      "previous_step_2_state_signature",
      "expiry__unix_time_secs",
      "message",
    ]);
  });

  it("splits required (12) and optional (2, trailing) fields", () => {
    expect(SPLITCHAIN_INNER_REQUIRED_FIELD_SEQUENCE).toHaveLength(12);
    assertFieldOrder(SPLITCHAIN_INNER_REQUIRED_FIELD_SEQUENCE, [
      ...SPLITCHAIN_INNER_FIELD_SEQUENCE.slice(0, 12),
    ]);
    assertFieldOrder(SPLITCHAIN_INNER_OPTIONAL_FIELDS, ["expiry__unix_time_secs", "message"]);
  });

  it("freezes the fixed inner literals — seconds-string time, never ms", () => {
    expect(SPLITCHAIN_INNER_FIXED_LITERALS).toEqual({
      type: "unique_combinable",
      version: "2",
      signerSteps: 2,
      step1Signer: "sender",
      step2Signer: "receiver",
      unixTimeSecsUnit: "seconds",
    });
  });

  it("freezes the state-object, settled-text, and step-2-preimage sequences", () => {
    assertFieldOrder(SPLITCHAIN_STATE_OBJECT_FIELD_SEQUENCE, ["amount", "metadata"]);
    assertFieldOrder(SPLITCHAIN_SETTLED_TEXT_FIELD_SEQUENCE, [
      "inner",
      "step_1_signature",
      "step_2_signature",
    ]);
    assertFieldOrder(SPLITCHAIN_STEP_2_PREIMAGE_FIELD_SEQUENCE, ["inner", "step_1_signature"]);
  });

  it("freezes the native preimage constructions (no prefix/newline/hash/canonical-JSON pass)", () => {
    expect(SPLITCHAIN_PREIMAGE_CONSTRUCTION.step1PreimageText).toBe("JSON.stringify(inner)");
    expect(SPLITCHAIN_PREIMAGE_CONSTRUCTION.step2PreimageText).toBe(
      "JSON.stringify({inner,step_1_signature})",
    );
    expect(SPLITCHAIN_PREIMAGE_CONSTRUCTION.noPrefixNewlineHashCanonicalJsonOrWhitespace).toBe(true);
    expect(SPLITCHAIN_PREIMAGE_CONSTRUCTION.suitePrefixUsed).toBe(false);
  });

  it("freezes the construction prohibitions", () => {
    expect(SPLITCHAIN_INNER_PROHIBITIONS.objectSpreadOnSigningPath).toBe(false);
    expect(SPLITCHAIN_INNER_PROHIBITIONS.alphabeticalSorting).toBe(false);
    expect(SPLITCHAIN_INNER_PROHIBITIONS.parseRebuildCycles).toBe(false);
    expect(SPLITCHAIN_INNER_PROHIBITIONS.jsonbReconstruction).toBe(false);
  });

  it("the A.8.1 golden step-1 inners carry exactly the frozen field sequence", () => {
    // Target inner: all 14 fields (both optionals present). Predecessor inner: the 12 required.
    assertFieldOrder(
      goldenKeySequence("src/receive-golden/gen/target.step-1.json"),
      [...SPLITCHAIN_INNER_FIELD_SEQUENCE],
    );
    assertFieldOrder(
      goldenKeySequence("src/receive-golden/gen/predecessor.step-1.json"),
      [...SPLITCHAIN_INNER_REQUIRED_FIELD_SEQUENCE],
    );
  });

  it("the A.8.1 golden step-2 and settled texts carry the frozen wrapper sequences", () => {
    assertFieldOrder(
      goldenKeySequence("src/receive-golden/gen/target.step-2.json"),
      [...SPLITCHAIN_STEP_2_PREIMAGE_FIELD_SEQUENCE],
    );
    assertFieldOrder(
      goldenKeySequence("src/receive-golden/gen/target.settled.json"),
      [...SPLITCHAIN_SETTLED_TEXT_FIELD_SEQUENCE],
    );
    assertFieldOrder(
      goldenKeySequence("src/receive-golden/gen/predecessor.settled.json"),
      [...SPLITCHAIN_SETTLED_TEXT_FIELD_SEQUENCE],
    );
  });

  it("the golden state objects carry amount-then-(no)metadata", () => {
    const target = JSON.parse(
      readFileSync(join(packageRoot, "src/receive-golden/gen/target.step-1.json"), "utf8"),
    ) as { step_1_state: object; step_2_state: object };
    assertFieldOrder(Object.keys(target.step_1_state), ["amount"]);
    assertFieldOrder(Object.keys(target.step_2_state), ["amount"]);
  });

  it("rejects a reordered inner field sequence (negative path)", () => {
    expectRejects(
      () => [...SPLITCHAIN_INNER_FIELD_SEQUENCE].reverse(),
      (mutated) => assertFieldOrder(mutated, SPLITCHAIN_INNER_FIELD_SEQUENCE),
    );
  });

  it("rejects a dropped required field (negative path)", () => {
    expectRejects(
      () => SPLITCHAIN_INNER_FIELD_SEQUENCE.filter((field) => field !== "unix_time_secs"),
      (mutated) => assertFieldOrder(mutated, SPLITCHAIN_INNER_FIELD_SEQUENCE),
    );
  });

  it("rejects an unexpected top-level field (negative path)", () => {
    expectRejects(
      () => [...SPLITCHAIN_INNER_FIELD_SEQUENCE, "memo"],
      (mutated) => assertFieldOrder(mutated, SPLITCHAIN_INNER_FIELD_SEQUENCE),
    );
  });

  it("rejects optionals in the wrong placement (negative path)", () => {
    expectRejects(
      () => ["message", "expiry__unix_time_secs"],
      (mutated) => assertFieldOrder(mutated, SPLITCHAIN_INNER_OPTIONAL_FIELDS),
    );
  });

  it("pins the manifest version", () => {
    expect(FIELDS_CONTRACT_VERSION).toBe(1);
  });
});
