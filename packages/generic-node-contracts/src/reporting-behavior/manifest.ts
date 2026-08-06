// the reporting bootstrap enrolment — Concern manifest: the serialized replay/rotation behaviour matrix the freeze gate
// snapshots (the behavioural evidence the ticket mandates). buildReportingBehaviorManifest()
// aggregates the frozen outcome matrix and its dimensions; manifest.freeze.test.ts diffs it against
// gen/reporting-behavior.json.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import { REQUEST_CLOCK_SKEW_MS, REQUEST_MAX_WINDOW_MS } from "./decisions.js";
import { buildReplayMatrix } from "./matrix.js";

export const reportingBehaviorConcernManifest = {
  concern: "reporting-behavior",
  ticket: "reporting.3",
  frozen: ["REPLAY_MATRIX", "BEHAVIOUR_DIMENSIONS"],
} as const;

// The six behavioural dimensions the matrix covers.
export const BEHAVIOUR_DIMENSIONS = [
  "request",
  "rotation",
  "event_stream",
  "restore",
  "cutover",
] as const;

export function buildReportingBehaviorManifest() {
  return {
    concern: reportingBehaviorConcernManifest.concern,
    ticket: reportingBehaviorConcernManifest.ticket,
    governing: {
      spec: "canonical-fields: register tuple, event signing; api-contract: signed reporting",
      decisions: ["reporting-ingest-auth", "signed-event-log", "sealed-store", "reporting-channel"],
      dependsOn: ["reporting.1", "reporting.2"],
    },
    requestMaxWindowMs: REQUEST_MAX_WINDOW_MS,
    requestClockSkewMs: REQUEST_CLOCK_SKEW_MS,
    dimensions: [...BEHAVIOUR_DIMENSIONS],
    matrix: buildReplayMatrix(),
  } as const;
}

export type ReportingBehaviorManifest = ReturnType<typeof buildReportingBehaviorManifest>;

/**
 * the reporting bootstrap enrolment's self-registered ConcernManifest (the concern-manifest registry
 * leave-behind"). Wraps the exact `buildReportingBehaviorManifest()` output — the same call
 * the freeze gate diffs against `gen/reporting-behavior.json` — byte-identically under the
 * canonical shape; `reportingBehaviorConcernManifest` above is the provisional form
 * supersedes. Registration export only — the concern-manifest registry assembles `src/registry.ts`.
 */
export const REPORTING_BEHAVIOR_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "reporting",
  decisionRefs: ["reporting-ingest-auth", "signed-event-log", "sealed-store", "reporting-channel"],
  frozenValues: { reportingBehavior: buildReportingBehaviorManifest() },
  goldenRefs: [
    {
      path: "src/reporting-behavior/gen/reporting-behavior.json",
      sha256: "af0c0254c56cd39effc1cd982bb224f6e2c4c2e86f1244fbbf0f1098de0481d0",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "canonical-fields: register tuple, event signing",
    "api-contract: signed reporting",
    "decision: reporting-ingest-auth",
    "decision: signed-event-log",
    "decision: sealed-store",
    "decision: reporting-channel",
  ],
});
