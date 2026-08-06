// Concern manifest: the serialized surface the freeze gate snapshots.
// buildEventSequencingManifest() aggregates the frozen allocation / cursor / restart facts;
// manifest.freeze.test.ts diffs it against gen/event-sequencing.json.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  ALLOCATION_MODEL,
  ALLOCATION_STEP_ORDER,
  BIND_STEPS,
  COHERENT_UNIT,
  REJECTED_ALLOCATIONS,
  SIGN_STEP,
} from "./allocation.js";
import { CURSOR_CONTRACT, GAP_DETECTION, RESTART_INVARIANTS } from "./cursor.js";

export const eventSequencingConcernManifest = {
  concern: "event-sequencing",
  frozen: [
    "ALLOCATION_MODEL",
    "REJECTED_ALLOCATIONS",
    "ALLOCATION_STEP_ORDER",
    "COHERENT_UNIT",
    "CURSOR_CONTRACT",
    "RESTART_INVARIANTS",
    "GAP_DETECTION",
  ],
} as const;

export function buildEventSequencingManifest() {
  return {
    concern: eventSequencingConcernManifest.concern,
    governing: {
      spec: "data-model node_events; signed node-event tuple; events cursor api",
      decisions: ["gapless-counter-allocation", "cursor-tracks-dedicated-sequence"],
      dependsOn: "reporting-tuples",
    },
    allocation: {
      model: { ...ALLOCATION_MODEL },
      rejected: REJECTED_ALLOCATIONS.map((r) => ({ mechanism: r.mechanism, reason: r.reason })),
      stepOrder: [...ALLOCATION_STEP_ORDER],
      bindSteps: [...BIND_STEPS],
      signStep: SIGN_STEP,
      coherentUnit: [...COHERENT_UNIT],
    },
    cursor: { ...CURSOR_CONTRACT },
    restart: { ...RESTART_INVARIANTS },
    gapDetection: { ...GAP_DETECTION },
  } as const;
}

export type EventSequencingManifest = ReturnType<typeof buildEventSequencingManifest>;

/**
 * The event-sequencing concern's self-registered ConcernManifest (the concern-manifest
 * registry leave-behind shape; see testkit/concernManifest.ts). Wraps the exact
 * `buildEventSequencingManifest()` output — the same call the freeze gate diffs against
 * `gen/event-sequencing.json` — byte-identically under the canonical shape;
 * `eventSequencingConcernManifest` above is the provisional form it supersedes.
 * Registration export only — the registry assembly is `src/registry.ts`.
 */
export const EVENT_SEQUENCING_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "event-sequencing",
  decisionRefs: ["gapless-counter-allocation", "cursor-tracks-dedicated-sequence"],
  frozenValues: { eventSequencing: buildEventSequencingManifest() },
  goldenRefs: [
    {
      path: "src/event-sequencing/gen/event-sequencing.json",
      sha256: "38fc86c2559f1d9d6e3be8a9b8141e60e0d72069a410468774fe302466a8a3bc",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "data-model node_events",
    "signed node-event tuple",
    "events cursor api",
    "gapless-counter-allocation",
    "cursor-tracks-dedicated-sequence",
  ],
});
