import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  AUTOMATIC_SINK_CONJUNCTS,
  COMPOSITION_SINK_STATES,
  CUSTODY_BINDING_OBLIGATIONS,
  CUSTODY_DENIAL_REASONS,
  CUSTODY_EVIDENCE_REQUIREMENTS,
  DESTINATION_STATES,
  INTERNAL_CUSTODY_CONJUNCTS,
  WALLET_KEY_ORIGINS,
  WALLET_STATES,
  WORKER_SINK_CONJUNCTS,
} from "./predicates.contract.ts";

export const CUSTODY_CONTRACT = {
  predicates: {
    INTERNAL_CUSTODY_CONJUNCTS,
    AUTOMATIC_SINK_CONJUNCTS,
    WORKER_SINK_CONJUNCTS,
    COMPOSITION_SINK_STATES,
  },
  vocabulary: { WALLET_KEY_ORIGINS, DESTINATION_STATES, WALLET_STATES, CUSTODY_DENIAL_REASONS },
  evidence: CUSTODY_EVIDENCE_REQUIREMENTS,
  bindingObligations: CUSTODY_BINDING_OBLIGATIONS,
} as const;

export const CUSTODY_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "custody",
  decisionRefs: ["custody-classification-policy", "custody-evidence-requirements", "custody-binding-obligations"],
  frozenValues: {
    INTERNAL_CUSTODY_CONJUNCTS,
    AUTOMATIC_SINK_CONJUNCTS,
    WORKER_SINK_CONJUNCTS,
    COMPOSITION_SINK_STATES,
    WALLET_KEY_ORIGINS,
    DESTINATION_STATES,
    WALLET_STATES,
    CUSTODY_DENIAL_REASONS,
    CUSTODY_EVIDENCE_REQUIREMENTS,
    CUSTODY_BINDING_OBLIGATIONS,
  },
  goldenRefs: [{ path: "gen/custody.json", sha256: "b74f25616ce033c3a950f314b7481d62701a6e2674ba821370494c4d9e8df6fe" }],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "custody data model",
    "signing/custody/security invariants",
    "custody-classification-policy",
    "custody-evidence-requirements",
    "custody-binding-obligations",
  ],
});
