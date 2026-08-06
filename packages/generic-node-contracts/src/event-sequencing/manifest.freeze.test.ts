// Freeze + census gate for the gapless event-sequence allocation contract.
// Consumes the reporting concerns' frozen sequence model, event field layout, and event-stream
// behaviour. Proves: (a) the manifest matches the golden; (b) the naive identity posture is
// rejected and the frozen allocation is rollback-safe/gapless; (c) binding (counter + previous
// hash) precedes signing over the signed node-event fields; (d) the cursor/restart/gap-detection
// facts align with the reporting concerns (which win on any conflict); and (e) a negative per
// fact class.
import { describe, expect, it } from "vitest";

import golden from "./gen/event-sequencing.json" with { type: "json" };
import { NODE_EVENT_FIELD_ORDER, SEQUENCE_MODEL, EVENT_HASH_RULE } from "../reporting-tuples/index.js";
import { evaluateChainAppend, evaluateTenantSeq } from "../reporting-behavior/index.js";
import {
  ALLOCATION_MODEL,
  ALLOCATION_STEP_ORDER,
  CURSOR_CONTRACT,
  GAP_DETECTION,
  RESTART_INVARIANTS,
  bindsBeforeSign,
  gapDetectorIsHashChain,
  isCanonicalAllocationOrder,
  isMonotonicCursorAdvance,
  isRejectedAllocation,
  isRollbackSafeAllocation,
  restartResumesGapless,
} from "./index.js";
import { buildEventSequencingManifest } from "./manifest.js";

describe("event-sequencing manifest freeze", () => {
  it("serialized manifest matches the committed golden snapshot", () => {
    expect(buildEventSequencingManifest()).toEqual(golden);
  });
});

describe("allocation resolution: identity rejected, dedicated counter canon", () => {
  it("the frozen allocation is rollback-safe and gapless", () => {
    expect(isRollbackSafeAllocation(ALLOCATION_MODEL)).toBe(true);
    expect(ALLOCATION_MODEL.gapless).toBe(true);
    expect(ALLOCATION_MODEL.rollbackSafe).toBe(true);
  });

  it("the GENERATED ALWAYS AS IDENTITY posture is explicitly rejected", () => {
    expect(isRejectedAllocation("generated_always_as_identity")).toBe(true);
    expect(isRejectedAllocation("bigserial")).toBe(true);
    expect(isRejectedAllocation("serial")).toBe(true);
    // The frozen source is never one of the rejected mechanisms.
    expect(isRejectedAllocation(ALLOCATION_MODEL.source)).toBe(false);
  });
});

describe("bind-before-sign over the signed node-event fields", () => {
  it("counter increment and previous-hash read precede signing", () => {
    expect(bindsBeforeSign(ALLOCATION_STEP_ORDER)).toBe(true);
    expect(isCanonicalAllocationOrder(ALLOCATION_STEP_ORDER)).toBe(true);
  });

  it("seq and previous_event_hash are inside the node-event signed preimage", () => {
    // Both fields live in the node-event tuple layout, so signing after binding covers them (they
    // cannot be re-sequenced post-signature). reporting-tuples owns this layout; this concern depends on it.
    expect(NODE_EVENT_FIELD_ORDER.indexOf("seq")).toBe(4);
    expect(NODE_EVENT_FIELD_ORDER.indexOf("previous_event_hash")).toBe(9);
  });
});

describe("cursor / restart contract", () => {
  it("freezes the events-cursor contract and monotonic advance", () => {
    expect(CURSOR_CONTRACT.requestCursorField).toBe("after_seq");
    expect(CURSOR_CONTRACT.requestCursorExclusive).toBe(true);
    expect(CURSOR_CONTRACT.tracks).toBe("dedicated_gapless_sequence");
    expect(isMonotonicCursorAdvance(5n, 9n)).toBe(true);
  });

  it("restart resumes gaplessly from the durable high-water", () => {
    expect(restartResumesGapless(RESTART_INVARIANTS)).toBe(true);
  });
});

describe("alignment with the reporting concerns (which win on any conflict)", () => {
  it("the allocation source matches reporting-tuples' frozen SEQUENCE_MODEL", () => {
    expect(ALLOCATION_MODEL.source).toBe(SEQUENCE_MODEL.source);
    expect(ALLOCATION_MODEL.countersPerNode).toBe(SEQUENCE_MODEL.countersPerNode);
    expect(GAP_DETECTION.skippedSeqMeaning).toBe(SEQUENCE_MODEL.skippedSeqMeaning);
  });

  it("the authoritative gap detector is the reporting hash chain, consistent with its behaviour", () => {
    expect(gapDetectorIsHashChain(GAP_DETECTION)).toBe(true);
    expect(EVENT_HASH_RULE).toBe("SHA256(preimage_bytes || signature_bytes)");
    // A sparse jump is an advance (not a gap); a chain break is a hard stop — reporting-behavior's rule.
    expect(evaluateTenantSeq(5n, 9n)).toBe("ACCEPT_ADVANCE");
    expect(evaluateChainAppend("a".repeat(64), "b".repeat(64))).toBe("HARD_STOP_CHAIN_BREAK");
  });
});

describe("negative path (one per fact class)", () => {
  it("rollback-gap: an identity-style model is not rollback-safe", () => {
    expect(isRollbackSafeAllocation({ ...ALLOCATION_MODEL, rollbackSafe: false, gapless: false })).toBe(false);
    expect(isRejectedAllocation("uuid_or_random")).toBe(true);
  });

  it("bind-sequence: signing before binding is rejected", () => {
    expect(bindsBeforeSign(["sign", "lock_and_increment_counter", "read_previous_event_hash"])).toBe(false);
  });

  it("cursor: a backwards advance is rejected", () => {
    expect(isMonotonicCursorAdvance(9n, 5n)).toBe(false);
  });

  it("restart: resetting the counter (seq reuse) is rejected", () => {
    expect(restartResumesGapless({ ...RESTART_INVARIANTS, resetsToZero: true })).toBe(false);
    expect(restartResumesGapless({ ...RESTART_INVARIANTS, reusesSeq: true })).toBe(false);
  });

  it("gap-detector: treating seq contiguity as the gap detector is rejected", () => {
    expect(gapDetectorIsHashChain({ ...GAP_DETECTION, seqContiguityIsGapDetector: true })).toBe(false);
  });
});
