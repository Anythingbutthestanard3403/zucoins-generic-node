// the events concern.2 — Concern manifest: the serialized surface the freeze gate snapshots.
// buildEventCommitManifest() aggregates the atomic-commit + outbox + concurrency/recovery/rotation +
// DDL-constraint facts; manifest.freeze.test.ts diffs it against gen/event-commit.json.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  ATOMICITY,
  COMMIT_STEP_ORDER,
  COMMIT_UNIT,
  INSERT_EVENT_STEP,
  SIGN_STEP,
} from "./commit.js";
import { IDEMPOTENT_REDELIVERY, OUTBOX_DECOUPLING } from "./outbox.js";
import { CONCURRENCY } from "./concurrency.js";
import { KEY_ROTATION, RESTART_COMMIT } from "./recovery.js";
import { DDL_CONSTRAINTS } from "./ddl.js";

export const eventCommitConcernManifest = {
  concern: "event-commit",
  ticket: "events.2",
  frozen: [
    "COMMIT_STEP_ORDER",
    "COMMIT_UNIT",
    "ATOMICITY",
    "OUTBOX_DECOUPLING",
    "IDEMPOTENT_REDELIVERY",
    "CONCURRENCY",
    "RESTART_COMMIT",
    "KEY_ROTATION",
    "DDL_CONSTRAINTS",
  ],
} as const;

export function buildEventCommitManifest() {
  return {
    concern: eventCommitConcernManifest.concern,
    ticket: eventCommitConcernManifest.ticket,
    governing: {
      spec: "data-model: node_events; canonical-fields: event signing; state-event reference: event serving; api-contract: event pull",
      decisions: ["signed-event-log", "sealed-store", "reporting-channel"],
      dependsOn: "events.1",
    },
    commit: {
      stepOrder: [...COMMIT_STEP_ORDER],
      signStep: SIGN_STEP,
      insertEventStep: INSERT_EVENT_STEP,
      unit: [...COMMIT_UNIT],
      atomicity: { ...ATOMICITY },
    },
    outbox: {
      decoupling: { ...OUTBOX_DECOUPLING },
      idempotentRedelivery: {
        dedupKeys: [...IDEMPOTENT_REDELIVERY.dedupKeys],
        redeliveryReSigns: IDEMPOTENT_REDELIVERY.redeliveryReSigns,
        redeliveryReSequences: IDEMPOTENT_REDELIVERY.redeliveryReSequences,
        consumerDedup: IDEMPOTENT_REDELIVERY.consumerDedup,
      },
    },
    concurrency: { ...CONCURRENCY },
    restart: { ...RESTART_COMMIT },
    keyRotation: { ...KEY_ROTATION },
    ddlConstraints: { ...DDL_CONSTRAINTS },
  } as const;
}

export type EventCommitManifest = ReturnType<typeof buildEventCommitManifest>;

/**
 * the events concern.2's self-registered ConcernManifest (the concern-manifest registry
 * leave-behind shape). Wraps the exact `buildEventCommitManifest()` output — the same call the
 * freeze gate diffs against `gen/event-commit.json` — byte-identically under the canonical
 * shape; `eventCommitConcernManifest` above is the provisional form supersedes.
 * Registration export only — the concern-manifest registry assembles `src/registry.ts`.
 */
export const EVENT_COMMIT_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "events",
  decisionRefs: ["signed-event-log", "sealed-store", "reporting-channel"],
  frozenValues: { eventCommit: buildEventCommitManifest() },
  goldenRefs: [
    {
      path: "src/event-commit/gen/event-commit.json",
      sha256: "c740a432c5329df66c5ebb7ece429169fef8b7c2e794c6e23a15d32c6995b8d6",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "data-model: node_events",
    "canonical-fields: event signing",
    "state-event reference: event serving",
    "api-contract: event pull",
    "decision: signed-event-log",
    "decision: sealed-store",
    "decision: reporting-channel",
  ],
});
