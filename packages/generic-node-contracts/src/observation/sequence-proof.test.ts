import { describe, expect, it } from "vitest";

import { GOLDEN_SEQUENCES } from "./sequences.contract.ts";
import {
  runObservationSequence,
  appendedRelationships,
  EMPTY_CURSOR,
  type SequenceCapture,
} from "./sequence-driver.ts";

const bytes = (...values: number[]): Uint8Array => new Uint8Array(values);

const head = (
  raw: Uint8Array,
  sSignature: string,
  pSignature: string,
  semanticFingerprint: string,
  rawResponseSha256Override?: string,
): SequenceCapture => ({
  parseResult: "VERIFIED_HEAD",
  rawResponseBytes: raw,
  isGenesis: false,
  sSignature,
  pSignature,
  semanticFingerprint,
  ...(rawResponseSha256Override === undefined ? {} : { rawResponseSha256Override }),
});

const malformed = (raw: Uint8Array): SequenceCapture => ({
  parseResult: "MALFORMED_ENVELOPE",
  rawResponseBytes: raw,
  isGenesis: false,
  sSignature: "",
  pSignature: "",
  semanticFingerprint: "",
});

const A = head(bytes(1, 1, 1, 1), "sigA", "", "fpA");
const A_ID = head(bytes(1, 1, 1, 1), "sigA", "", "fpA");
const A_PRIME = head(bytes(1, 1, 1, 9), "sigA", "", "fpA");
const B = head(bytes(2, 2, 2, 2), "sigB", "sigA", "fpB");
const C = head(bytes(3, 3, 3, 3), "sigC", "sigB", "fpC");
const A_RET = head(bytes(1, 1, 1, 1), "sigA", "", "fpA");
const X = malformed(bytes(9, 9));
const COL1 = head(bytes(1, 1, 1, 1), "sigA", "", "fpA", "collide");
const COL2 = head(bytes(1, 1, 1, 2), "sigA", "", "fpA", "collide");

const GOLDEN_INPUTS: Record<string, readonly SequenceCapture[]> = {
  AA_BYTE_IDENTICAL: [A, A_ID],
  AA_PRIME_WRAPPER: [A, A_PRIME],
  ABCA_REGRESSION: [A, B, C, A_RET],
  MALFORMED_XX: [X, malformed(bytes(9, 9))],
  DIGEST_COLLISION: [COL1, COL2],
};

describe("golden observation sequences reproduce their frozen outcome (the observation concern.3)", () => {
  it.each(GOLDEN_SEQUENCES)("$name: $description", (golden) => {
    const result = runObservationSequence(GOLDEN_INPUTS[golden.name]);
    const suppressed = result.events.filter((e) => e.decision === "SUPPRESS_AS_SIGHTING").length;
    expect(result.cursor.rowCount).toBe(golden.appendedRows);
    expect(result.cursor.anomalyCount).toBe(golden.anomalyRows);
    expect(suppressed).toBe(golden.suppressedSightings);
    expect(appendedRelationships(result)).toEqual(golden.relationships);
  });

  it("appended rows carry contiguous wallet_seq starting at 1", () => {
    const result = runObservationSequence(GOLDEN_INPUTS.ABCA_REGRESSION);
    const seqs = result.events.filter((e) => e.decision === "APPEND").map((e) => e.walletSeq);
    expect(seqs).toEqual([1, 2, 3, 4]);
  });
});

describe("restart cursor restoration (the observation concern.3)", () => {
  it("resuming from a returned cursor yields the identical continuation", () => {
    const whole = runObservationSequence([A, B, C, A_RET]);
    const part1 = runObservationSequence([A, B]);
    const part2 = runObservationSequence([C, A_RET], part1.cursor);
    expect([...appendedRelationships(part1), ...appendedRelationships(part2)]).toEqual(
      appendedRelationships(whole),
    );
    expect(part2.cursor.nextWalletSeq).toBe(whole.cursor.nextWalletSeq);
    expect(part2.cursor.rowCount).toBe(whole.cursor.rowCount);
  });

  it("resuming from a lost (empty) cursor diverges — the negative (the observation concern.3)", () => {
    const part1 = runObservationSequence([A, B]);
    const restored = runObservationSequence([C, A_RET], part1.cursor);
    const lost = runObservationSequence([C, A_RET], EMPTY_CURSOR);
    expect(lost.events[0]?.walletSeq).toBe(1);
    expect(restored.events[0]?.walletSeq).toBe(3);
    // Losing the cursor misclassifies: C reads as FIRST (its predecessor B is gone) and the
    // recurring A reads as UNEXPLAINED_JUMP because the accepted-state history was lost.
    expect(appendedRelationships(lost)).toEqual(["FIRST", "UNEXPLAINED_JUMP"]);
    expect(appendedRelationships(restored)).toEqual(["SUCCESSOR", "REGRESSION"]);
  });
});

describe("concurrent per-stream serialization (the observation concern.3)", () => {
  it("each stream folds an independent cursor with its own contiguous wallet_seq", () => {
    const streamOne = runObservationSequence([A, B]);
    const streamTwo = runObservationSequence([C]);
    expect(streamOne.events.map((e) => e.walletSeq)).toEqual([1, 2]);
    expect(streamTwo.events.map((e) => e.walletSeq)).toEqual([1]);
  });

  it("a shared cursor would leak sequence across streams — the negative (the observation concern.3)", () => {
    const streamOne = runObservationSequence([A, B]);
    const leaked = runObservationSequence([C], streamOne.cursor);
    expect(leaked.events[0]?.walletSeq).toBe(3);
  });
});

describe("permanence and per-class negatives (the observation concern.3)", () => {
  it("byte-identical suppresses, but a byte-different envelope or non-verified pair appends", () => {
    expect(runObservationSequence([A, A_ID]).cursor.rowCount).toBe(1);
    expect(runObservationSequence([A, A_PRIME]).cursor.rowCount).toBe(2);
    expect(runObservationSequence([X, malformed(bytes(9, 9))]).cursor.rowCount).toBe(2);
  });

  it("a byte-different-head row is a state transition, never EQUIVALENT", () => {
    const result = runObservationSequence([A, B]);
    const second = result.events[1];
    expect(second?.relationship).toBe("SUCCESSOR");
    expect(second?.stateChanged).toBe(true);
  });

  it("a non-recurring fourth state is UNEXPLAINED_JUMP, not REGRESSION", () => {
    const D = head(bytes(4, 4, 4, 4), "sigD", "sigUnknown", "fpD");
    const result = runObservationSequence([A, B, C, D]);
    expect(appendedRelationships(result)).toEqual([
      "FIRST",
      "SUCCESSOR",
      "SUCCESSOR",
      "UNEXPLAINED_JUMP",
    ]);
  });

  it("identical malformed bytes always append two anomalies, never suppressed", () => {
    const result = runObservationSequence([X, malformed(bytes(9, 9))]);
    expect(result.cursor.anomalyCount).toBe(2);
    expect(result.events.every((e) => e.decision === "APPEND")).toBe(true);
    expect(appendedRelationships(result)).toEqual(["NOT_APPLICABLE", "NOT_APPLICABLE"]);
  });

  it("a digest collision with differing bytes appends, but a true byte-identical repeat suppresses", () => {
    expect(runObservationSequence([COL1, COL2]).cursor.rowCount).toBe(2);
    const trueRepeat = head(bytes(1, 1, 1, 1), "sigA", "", "fpA", "collide");
    const result = runObservationSequence([COL1, trueRepeat]);
    expect(result.cursor.rowCount).toBe(1);
    expect(result.events[1]?.decision).toBe("SUPPRESS_AS_SIGHTING");
  });

  it("the recurrence of an older state is retained (no global deduplication)", () => {
    const result = runObservationSequence([A, B, C, A_RET]);
    expect(result.cursor.rowCount).toBe(4);
    expect(result.events[3]?.relationship).toBe("REGRESSION");
  });
});
