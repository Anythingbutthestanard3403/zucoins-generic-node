// Sequence-recovery concern manifest: the serialized concurrency/recovery matrix the freeze gate snapshots.
// buildSequenceRecoveryManifest() aggregates the outcome matrix and its dimensions;
// manifest.freeze.test.ts diffs it against gen/sequence-recovery.json.

import { buildSequenceRecoveryMatrix } from "./matrix.js";

export const sequenceRecoveryConcernManifest = {
  concern: "sequence-recovery",
  ticket: "events.3",
  frozen: ["SEQUENCE_RECOVERY_MATRIX", "RECOVERY_DIMENSIONS"],
} as const;

export const RECOVERY_DIMENSIONS = ["concurrency", "crash", "restart", "rotation", "redelivery"] as const;

export function buildSequenceRecoveryManifest() {
  return {
    concern: sequenceRecoveryConcernManifest.concern,
    ticket: sequenceRecoveryConcernManifest.ticket,
    governing: {
      spec: "event-ledger data model; signed event tuple A.6; event-serving rules",
      // The pull-cursor authority rule governs the event-key rotation dimension (v2 zp-node-event-v1: prior key retired by
      // seq-cursor, key_id outside the signed object). The reporting bootstrap enrolment supplies the chain-append rule the
      // rotation cells consume.
      decisions: ["signed-event-log", "sealed-store", "reporting-channel"],
    },
    dimensions: [...RECOVERY_DIMENSIONS],
    matrix: buildSequenceRecoveryMatrix(),
  } as const;
}

export type SequenceRecoveryManifest = ReturnType<typeof buildSequenceRecoveryManifest>;
