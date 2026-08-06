// the events concern.2 — Executable rollback/concurrency/restart/rotation vectors. Drives every case in
// __vectors__/commit.vectors.json through its class verifier and asserts the required verdict. This
// is the canonical "publish rollback/concurrency vectors" deliverable; the events concern.3 consumes the same
// verifiers for the exhaustive runtime race/crash/replay proof.
//
// Governing contract: node_events data model; event signing; event serving; the pull-cursor authority decision.
import { describe, expect, it } from "vitest";

import vectorsDoc from "./__vectors__/commit.vectors.json" with { type: "json" };
import {
  type ConcurrencyShape,
  type DdlConstraintShape,
  type KeyRotationShape,
  type RestartCommitShape,
  concurrentWritersOneWinnerGapless,
  ddlEnforcesAtomicCommit,
  keyRotationPreservesChain,
  preimageBindsCurrentHead,
  restartResumesGaplessAndRedelivers,
  rollbackBurnsNoSeq,
  unitBindsStateTransition,
} from "./index.js";
import { type AtomicityShape } from "./verifier.js";

type Vector = {
  readonly id: string;
  readonly class: string;
  readonly expect: boolean;
  readonly model: Record<string, unknown>;
};

// One verifier per vector class. Each returns the boolean verdict the vector's `expect` is checked
// against; an unknown class throws so a new class can never silently pass unverified.
function verdictFor(v: Vector): boolean {
  switch (v.class) {
    case "concurrency":
      return concurrentWritersOneWinnerGapless(v.model as unknown as ConcurrencyShape);
    case "rollback":
      return rollbackBurnsNoSeq(v.model as unknown as AtomicityShape);
    case "restart":
      return restartResumesGaplessAndRedelivers(v.model as unknown as RestartCommitShape);
    case "rotation":
      return keyRotationPreservesChain(v.model as unknown as KeyRotationShape);
    case "ddl":
      return ddlEnforcesAtomicCommit(v.model as unknown as DdlConstraintShape);
    case "state_transition":
      return unitBindsStateTransition(v.model.unit as readonly string[]);
    case "previous_hash":
      return preimageBindsCurrentHead(
        v.model.builtOnHash as string | null,
        v.model.chainHeadHash as string | null,
      );
    default:
      throw new Error(`unknown vector class: ${v.class}`);
  }
}

describe("the events concern.2 rollback/concurrency vectors", () => {
  const vectors = vectorsDoc.vectors as readonly Vector[];

  it("the vector document is non-empty and every id is unique", () => {
    expect(vectors.length).toBeGreaterThan(0);
    expect(new Set(vectors.map((v) => v.id)).size).toBe(vectors.length);
  });

  it("covers every required test class (concurrent writers, rollback, restart, key-rotation) plus negatives", () => {
    const classes = new Set(vectors.map((v) => v.class));
    for (const required of ["concurrency", "rollback", "restart", "rotation", "state_transition", "previous_hash"]) {
      expect(classes).toContain(required);
    }
    // Each class carries at least one negative-path vector (a rejecting case).
    for (const cls of classes) {
      expect(vectors.some((v) => v.class === cls && v.expect === false)).toBe(true);
    }
  });

  for (const v of vectorsDoc.vectors as readonly Vector[]) {
    it(`${v.class}: ${v.id} -> ${v.expect}`, () => {
      expect(verdictFor(v)).toBe(v.expect);
    });
  }
});
