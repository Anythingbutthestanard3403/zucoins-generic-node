import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import { GOLDEN_SEQUENCES, SEQUENCE_PROPERTIES } from "./sequences.contract.ts";

describe("golden observation sequence expectations are frozen (the observation concern.3)", () => {
  it("golden sequence names and sequence", () => {
    assertFieldOrder(
      GOLDEN_SEQUENCES.map((sequence) => sequence.name),
      [
        "AA_BYTE_IDENTICAL",
        "AA_PRIME_WRAPPER",
        "ABCA_REGRESSION",
        "MALFORMED_XX",
        "DIGEST_COLLISION",
      ],
    );
  });

  it("each golden expectation freezes its row, anomaly, sighting counts and relationships", () => {
    const byName = Object.fromEntries(GOLDEN_SEQUENCES.map((sequence) => [sequence.name, sequence]));
    expect(byName.AA_BYTE_IDENTICAL).toMatchObject({
      appendedRows: 1,
      anomalyRows: 0,
      suppressedSightings: 1,
      relationships: ["FIRST"],
    });
    expect(byName.ABCA_REGRESSION).toMatchObject({
      appendedRows: 4,
      anomalyRows: 1,
      suppressedSightings: 0,
      relationships: ["FIRST", "SUCCESSOR", "SUCCESSOR", "REGRESSION"],
    });
    expect(byName.MALFORMED_XX).toMatchObject({
      appendedRows: 2,
      anomalyRows: 2,
      suppressedSightings: 0,
    });
  });

  it("relationship count equals appended-row count for every golden", () => {
    for (const sequence of GOLDEN_SEQUENCES) {
      expect(sequence.relationships).toHaveLength(sequence.appendedRows);
    }
  });

  it("the three sequence properties are frozen", () => {
    expect(SEQUENCE_PROPERTIES).toHaveLength(3);
    expect(SEQUENCE_PROPERTIES[0]).toContain("restart");
    expect(SEQUENCE_PROPERTIES[1]).toContain("concurrent");
    expect(SEQUENCE_PROPERTIES[2]).toContain("append-only");
  });
});
