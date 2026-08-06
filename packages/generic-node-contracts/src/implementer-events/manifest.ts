// Concern manifest: the serialized surface the freeze gate snapshots.
// TEST-ONLY: A.8 seed keys are TEST-ONLY and MUST never be used with live ZKZ.
//
// buildImplementerEventsManifest() aggregates the frozen implementer-event, checkpoint, and
// keyrotation tuple facts and their goldens into one JSON-serializable object;
// manifest.freeze.test.ts diffs it against gen/implementer-events.json.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  IMPLEMENTER_EVENT_CANONICAL_VERSION,
  IMPLEMENTER_EVENT_FIELD_ORDER,
  IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE,
  IMPLEMENTER_EVENT_GOLDEN_B_PREIMAGE,
  IMPLEMENTER_EVENT_PURPOSE,
  IMPLEMENTER_SEQ_MODEL,
  NODE_EVENT_HASH_INVERTIBILITY,
  NODE_EVENT_HASH_RULE,
} from "./implementer-event-tuple.js";
import {
  CHECKPOINT_ANTI_ROLLBACK,
  IMPLEMENTER_CHECKPOINT_CANONICAL_VERSION,
  IMPLEMENTER_CHECKPOINT_FIELD_ORDER,
  IMPLEMENTER_CHECKPOINT_GOLDEN_PREIMAGE,
  IMPLEMENTER_CHECKPOINT_PURPOSE,
} from "./implementer-checkpoint.js";
import {
  IMPLEMENTER_KEYROTATION_CANONICAL_VERSION,
  IMPLEMENTER_KEYROTATION_FIELD_ORDER,
  IMPLEMENTER_KEYROTATION_GOLDEN_PREIMAGE,
  IMPLEMENTER_KEYROTATION_PURPOSE,
  KEYROTATION_COSIGN_STATUS,
  KEYROTATION_CURSOR_MODEL,
} from "./implementer-keyrotation.js";
import {
  IMPLEMENTER_CHECKPOINT_SHA256,
  IMPLEMENTER_CHECKPOINT_SIGNATURE,
  IMPLEMENTER_EVENT_A_EVENT_HASH,
  IMPLEMENTER_EVENT_A_SHA256,
  IMPLEMENTER_EVENT_A_SIGNATURE,
  IMPLEMENTER_EVENT_B_EVENT_HASH,
  IMPLEMENTER_EVENT_B_SHA256,
  IMPLEMENTER_EVENT_B_SIGNATURE,
  IMPLEMENTER_KEYROTATION_SHA256,
  IMPLEMENTER_KEYROTATION_SIGNATURE,
  NODE_EVENT_KEY_PUBKEY,
} from "./digests.js";

export const implementerEventsConcernManifest = {
  concern: "implementer-events",
  ticket: "implementer-events",
  frozen: [
    "IMPLEMENTER_EVENT_TUPLE",
    "IMPLEMENTER_CHECKPOINT_TUPLE",
    "IMPLEMENTER_KEYROTATION_TUPLE",
    "IMPLEMENTER_SEQ_MODEL",
    "NODE_EVENT_HASH_RULE",
    "CHECKPOINT_ANTI_ROLLBACK",
  ],
} as const;

export function buildImplementerEventsManifest() {
  return {
    concern: implementerEventsConcernManifest.concern,
    ticket: implementerEventsConcernManifest.ticket,
    governing: {
      spec: "canonical serialization A.1.1; implementer events A.6; goldens A.8-A.9; closed event set; dual continuity",
      decisions: ["reporting-channel", "reporting-key-enrolment", "pull-cursor-authority", "checkpoint-anti-rollback"],
    },
    implementerEvent: {
      purpose: IMPLEMENTER_EVENT_PURPOSE,
      canonicalVersion: IMPLEMENTER_EVENT_CANONICAL_VERSION,
      fieldOrder: [...IMPLEMENTER_EVENT_FIELD_ORDER],
      seqModel: { ...IMPLEMENTER_SEQ_MODEL },
      nodeEventHashRule: NODE_EVENT_HASH_RULE,
      nodeEventHashInvertibility: NODE_EVENT_HASH_INVERTIBILITY,
      nodeEventKeyPubkey: NODE_EVENT_KEY_PUBKEY,
      goldenA: {
        preimage: IMPLEMENTER_EVENT_GOLDEN_A_PREIMAGE,
        sha256: IMPLEMENTER_EVENT_A_SHA256,
        signature: IMPLEMENTER_EVENT_A_SIGNATURE,
        eventHash: IMPLEMENTER_EVENT_A_EVENT_HASH,
      },
      goldenB: {
        preimage: IMPLEMENTER_EVENT_GOLDEN_B_PREIMAGE,
        sha256: IMPLEMENTER_EVENT_B_SHA256,
        signature: IMPLEMENTER_EVENT_B_SIGNATURE,
        eventHash: IMPLEMENTER_EVENT_B_EVENT_HASH,
      },
    },
    implementerCheckpoint: {
      purpose: IMPLEMENTER_CHECKPOINT_PURPOSE,
      canonicalVersion: IMPLEMENTER_CHECKPOINT_CANONICAL_VERSION,
      fieldOrder: [...IMPLEMENTER_CHECKPOINT_FIELD_ORDER],
      antiRollback: { ...CHECKPOINT_ANTI_ROLLBACK },
      nodeEventKeyPubkey: NODE_EVENT_KEY_PUBKEY,
      golden: {
        preimage: IMPLEMENTER_CHECKPOINT_GOLDEN_PREIMAGE,
        sha256: IMPLEMENTER_CHECKPOINT_SHA256,
        signature: IMPLEMENTER_CHECKPOINT_SIGNATURE,
      },
    },
    implementerKeyRotation: {
      purpose: IMPLEMENTER_KEYROTATION_PURPOSE,
      canonicalVersion: IMPLEMENTER_KEYROTATION_CANONICAL_VERSION,
      fieldOrder: [...IMPLEMENTER_KEYROTATION_FIELD_ORDER],
      cursorModel: { ...KEYROTATION_CURSOR_MODEL },
      cosignStatus: KEYROTATION_COSIGN_STATUS,
      nodeEventKeyPubkey: NODE_EVENT_KEY_PUBKEY,
      golden: {
        preimage: IMPLEMENTER_KEYROTATION_GOLDEN_PREIMAGE,
        sha256: IMPLEMENTER_KEYROTATION_SHA256,
        signature: IMPLEMENTER_KEYROTATION_SIGNATURE,
      },
    },
  } as const;
}

export type ImplementerEventsManifest = ReturnType<typeof buildImplementerEventsManifest>;

export const IMPLEMENTER_EVENTS_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "events",
  decisionRefs: ["reporting-channel", "reporting-key-enrolment", "pull-cursor-authority", "checkpoint-anti-rollback"],
  frozenValues: { implementerEvents: buildImplementerEventsManifest() },
  goldenRefs: [
    {
      path: "src/implementer-events/gen/implementer-events.json",
      sha256: "5a5bccbb9b69dbaac5a9ee557f67ec4cb8d94a75cb0c413debd11c3f7624a640",
    },
    {
      path: "src/implementer-events/gen/zp-implementer-event-v1.golden-a.preimage.txt",
      sha256: "78c8dd8155acec6e4750079e206a6b9733bbcd92c35cc43b64a433d86db803b2",
    },
    {
      path: "src/implementer-events/gen/zp-implementer-event-v1.golden-b.preimage.txt",
      sha256: "eee07e39a4bebb8de9880323934d10492cf46980e25e7d084424405eb0691c70",
    },
    {
      path: "src/implementer-events/gen/zp-implementer-checkpoint-v1.preimage.txt",
      sha256: "55faede68dee05b764943804b19042c765ea1737df9f3fb98fb9e63887a0e29d",
    },
    {
      path: "src/implementer-events/gen/zp-implementer-keyrotation-v1.preimage.txt",
      sha256: "5bf01bd4f011179e5560b38f8ef16b2bbd103ee17e0108d13836e23589fddbdb",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "canonical serialization A.1.1; implementer events A.6; goldens A.8-A.9",
    "closed event set",
    "dual continuity and implementer_seq encoding",
    "reporting-channel",
    "reporting-key-enrolment",
    "pull-cursor-authority",
    "checkpoint-anti-rollback",
  ],
});
