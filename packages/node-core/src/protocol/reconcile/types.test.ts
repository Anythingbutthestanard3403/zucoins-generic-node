// closed-union proofs for the shared reconcile-outcome vocabulary.

import { describe, expect, it } from "vitest";

import { assertUnreachable, RECONCILE_CLASSIFICATION_KINDS, type ReconcileClassificationKind } from "./types.js";
import { type ReceiveReconcileOutcome } from "./receive.js";
import { type MoveReconcileOutcome } from "./move.js";
import { type SendReconcileOutcome } from "./send.js";

// Compile-time set-equality check: errors (via the `never` branches below) unless A and B are
// the exact same union, in either direction — no member of one may be absent from the other.
type AssertExactUnion<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never;

// The union of every `kind` literal the three operation-specific outcome unions can produce
// must equal RECONCILE_CLASSIFICATION_KINDS exactly — the "closed reconcile outcome union"
// this module exists to build, proven at compile time, not merely documented.
type AllOutcomeKinds = ReceiveReconcileOutcome["kind"] | MoveReconcileOutcome["kind"] | SendReconcileOutcome["kind"];
const _closedUnionProof: AssertExactUnion<AllOutcomeKinds, ReconcileClassificationKind> = true;
void _closedUnionProof;

describe("closed reconcile outcome vocabulary", () => {
  it("is exactly the five recovery classification names, in their canonical sequence", () => {
    expect(RECONCILE_CLASSIFICATION_KINDS).toEqual([
      "LANDED_VERIFIED",
      "PROVEN_NOT_STARTED",
      "WAITING",
      "INDETERMINATE",
      "INVARIANT_BREACH",
    ]);
  });

  it("has no boolean isLanded-style member and no sixth PROVEN_NOT_LANDED member", () => {
    // "There is no generic PROVEN_NOT_LANDED verdict." A closed 5-member array is itself
    // the proof surface; this assertion pins the count so a future edit accidentally adding a
    // 6th member (or collapsing to a boolean) fails loudly here.
    expect(RECONCILE_CLASSIFICATION_KINDS).toHaveLength(5);
    expect(RECONCILE_CLASSIFICATION_KINDS).not.toContain("PROVEN_NOT_LANDED");
    expect(RECONCILE_CLASSIFICATION_KINDS).not.toContain("SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING");
  });

  it("exhaustive switch over every kind compiles only while all five are handled", () => {
    // Mirrors the `assertUnreachable` pattern every classify* function in this concern uses:
    // deleting a branch here, or RECONCILE_CLASSIFICATION_KINDS gaining a member without a
    // matching branch, is a `tsc -b` compile error, not a silent runtime gap.
    const describeKind = (kind: ReconcileClassificationKind): string => {
      switch (kind) {
        case "LANDED_VERIFIED":
          return "terminal success; never resubmit";
        case "PROVEN_NOT_STARTED":
          return "continue the first formation/submission; not a retry";
        case "WAITING":
          return "continue read reconciliation; optional exact redelivery only";
        case "INDETERMINATE":
          return "park/attention; no retry/rebuild/resubmit/release";
        case "INVARIANT_BREACH":
          return "stop money engines; quarantine; page operator";
        default:
          return assertUnreachable(kind);
      }
    };
    for (const kind of RECONCILE_CLASSIFICATION_KINDS) {
      expect(typeof describeKind(kind)).toBe("string");
    }
  });

  it("MOVE_INTERNAL's outcome union has no WAITING member (no external partial exists)", () => {
    // @ts-expect-error — "WAITING" is not assignable to MoveReconcileOutcome["kind"]; move.ts's
    // union genuinely omits it (see move.ts header), this is not just an unused case.
    const bad: MoveReconcileOutcome["kind"] = "WAITING";
    expect(bad).toBeDefined();
  });

  it("RECEIVE_EXTERNAL's outcome union has no WAITING member (the node itself submits)", () => {
    // @ts-expect-error — same reasoning as above, for receive.ts.
    const bad: ReceiveReconcileOutcome["kind"] = "WAITING";
    expect(bad).toBeDefined();
  });

  it("SEND_EXTERNAL is the only operation kind whose union includes WAITING", () => {
    const waiting: SendReconcileOutcome["kind"] = "WAITING";
    expect(waiting).toBe("WAITING");
  });
});
