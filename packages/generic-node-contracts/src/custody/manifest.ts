import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  AUTOMATIC_SINK_CONJUNCTS,
  CUSTODY_BINDING_OBLIGATIONS,
  CUSTODY_DENIAL_REASONS,
  CUSTODY_EVIDENCE_REQUIREMENTS,
  DESTINATION_STATES,
  INTERNAL_CUSTODY_CONJUNCTS,
  WALLET_KEY_ORIGINS,
  WALLET_STATES,
} from "./predicates.contract.ts";

export const CUSTODY_CONTRACT = {
  predicates: { INTERNAL_CUSTODY_CONJUNCTS, AUTOMATIC_SINK_CONJUNCTS },
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
    WALLET_KEY_ORIGINS,
    DESTINATION_STATES,
    WALLET_STATES,
    CUSTODY_DENIAL_REASONS,
    CUSTODY_EVIDENCE_REQUIREMENTS,
    CUSTODY_BINDING_OBLIGATIONS,
  },
  goldenRefs: [{ path: "gen/custody.json", sha256: "7e192a00a51b5e3e0f70a93ec917657998b796f408cd1d3cae0f91c130add5ba" }],
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
