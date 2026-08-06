import { defineConcernManifest } from "../testkit/concernManifest.ts";
import { SCENARIO_CLASSES, SCENARIO_MATRIX } from "./scenario-matrix.contract.ts";

/**
 * The aggregated two-instance handoff proof matrix. gen/handoff-proof.json is a
 * review-diff snapshot of exactly this object (tier 2, never byte authority); the `.contract.ts`
 * `as const` source is authority. gen-sync.test.ts fails if the two diverge. Data only — the proof
 * functions live in proof.ts and are exercised by the census tests, not serialised here.
 */
export const HANDOFF_PROOF_CONTRACT = {
  scenarios: {
    SCENARIO_CLASSES,
    SCENARIO_MATRIX,
  },
} as const;

/**
 * The handoff-proof concern's self-registered ConcernManifest (concern dir src/handoff-proof/).
 * Sibling of readiness and engine-startup. Registration export only — the registry assembly
 * is src/registry.ts.
 */
export const HANDOFF_PROOF_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "handoff-proof",
  decisionRefs: ["two-instance-handoff-backstop", "vault-storage-envelope", "boot-recovery-lease-survival"],
  frozenValues: {
    SCENARIO_CLASSES,
    SCENARIO_MATRIX,
  },
  goldenRefs: [
    {
      path: "gen/handoff-proof.json",
      sha256: "28234953278707bdd4234fc78fee34cf5a2b92d79670eda6c96abb285cd400e1",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "node-core wallet leases",
    "node-core leadership lock",
    "operations-recovery boot recovery",
    "two-instance-handoff-backstop",
    "vault-storage-envelope",
  ],
});
