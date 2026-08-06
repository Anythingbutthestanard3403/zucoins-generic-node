import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  ANCESTRY_INDEX_KEY_FIELDS,
  ANCESTRY_INDEX_ENTRY_FIELDS,
  INDEXABILITY_RULE,
} from "./index-fields.contract.ts";
import {
  LINKAGE_RULE,
  EXACT_BODY_RULE,
  COLLISION_RULE,
  INGEST_OUTCOMES,
  WALK_OUTCOMES,
  WALK_COMPLETENESS,
  WALK_STEP_BUDGET_DEFAULT,
} from "./linkage.contract.ts";
import { LANDING_PROOF_FIXTURES } from "./fixtures.contract.ts";
import {
  LANDING_PROOF_MANIFEST_VERSION,
  LANDING_CLASSIFICATIONS,
  REQUIRED_PER_BODY_PREDICATES,
  ECONOMIC_EVALUATION_BASIS,
  DEPTH_SEMANTICS,
  REVERIFICATION_PREDICATE,
  MANIFEST_RETENTION,
  OPERATION_IDENTITY_FIELDS,
  CLAIMED_LANDED_FIELDS,
  HEAD_READ_PROVENANCE_FIELDS,
  MANIFEST_HOP_FIELDS,
  VERIFICATION_SEMANTICS_FIELDS,
  SINGLE_PATH_MANIFEST_FIELDS,
  MOVE_PROOF_MANIFEST_FIELDS,
  MANIFEST_REVERIFY_FAILURES,
  REVERIFY_VERDICTS,
} from "./proof-manifest.contract.ts";
import { LANDING_PROOF_GOLDEN_MANIFESTS } from "./proof-manifest.golden.contract.ts";
import {
  LANDING_DETERMINATIONS,
  INDETERMINATE_CAUSES,
  INDETERMINATE_CAUSE_TAXONOMY,
  FRESH_HEAD_STATUSES,
  DETERMINATION_AUTHORITY,
  REWALK_SEMANTICS,
  FAIL_CLOSED_INVARIANTS,
  LANDING_WIRE_CLASSIFICATIONS,
  LANDING_DETERMINATION_TO_WIRE,
  DEPTH_ONE_LANDING_IS_LANDED_COMPLETE_PATH,
  WIRE_INDETERMINATE_REASONS,
  INDETERMINATE_CAUSE_TO_WIRE_REASON,
} from "./fail-closed.contract.ts";

/**
 * The aggregated frozen landing-proof (the landing-proof concern) contract — seeded by the landing-proof index/walk (index/walk), extended
 * by the landing-proof manifest builder (proof manifests), closed by the landing-proof e2e (fail-closed determination). gen/landing-proof.json
 * is a review-diff snapshot of exactly this object (tier 2, never byte authority); the `.contract.ts`
 * `as const` sources are the authority. gen-sync.test.ts fails if the two diverge.
 */
export const LANDING_PROOF_CONTRACT = {
  index: {
    ANCESTRY_INDEX_KEY_FIELDS,
    ANCESTRY_INDEX_ENTRY_FIELDS,
    INDEXABILITY_RULE,
  },
  linkage: {
    LINKAGE_RULE,
    EXACT_BODY_RULE,
    COLLISION_RULE,
    INGEST_OUTCOMES,
    WALK_OUTCOMES,
    WALK_COMPLETENESS,
    WALK_STEP_BUDGET_DEFAULT,
  },
  manifest: {
    LANDING_PROOF_MANIFEST_VERSION,
    LANDING_CLASSIFICATIONS,
    REQUIRED_PER_BODY_PREDICATES,
    ECONOMIC_EVALUATION_BASIS,
    DEPTH_SEMANTICS,
    REVERIFICATION_PREDICATE,
    MANIFEST_RETENTION,
    OPERATION_IDENTITY_FIELDS,
    CLAIMED_LANDED_FIELDS,
    HEAD_READ_PROVENANCE_FIELDS,
    MANIFEST_HOP_FIELDS,
    VERIFICATION_SEMANTICS_FIELDS,
    SINGLE_PATH_MANIFEST_FIELDS,
    MOVE_PROOF_MANIFEST_FIELDS,
    MANIFEST_REVERIFY_FAILURES,
    REVERIFY_VERDICTS,
  },
  failClosed: {
    LANDING_DETERMINATIONS,
    INDETERMINATE_CAUSES,
    INDETERMINATE_CAUSE_TAXONOMY,
    FRESH_HEAD_STATUSES,
    DETERMINATION_AUTHORITY,
    REWALK_SEMANTICS,
    FAIL_CLOSED_INVARIANTS,
    LANDING_WIRE_CLASSIFICATIONS,
    LANDING_DETERMINATION_TO_WIRE,
    DEPTH_ONE_LANDING_IS_LANDED_COMPLETE_PATH,
    WIRE_INDETERMINATE_REASONS,
    INDETERMINATE_CAUSE_TO_WIRE_REASON,
  },
  goldenFixtures: LANDING_PROOF_FIXTURES,
  goldenManifests: LANDING_PROOF_GOLDEN_MANIFESTS,
} as const;

/**
 * the landing-proof concern's self-registered ConcernManifest (concern dir src/landing-proof/). Seeded by the landing-proof index/walk
 * (exact-body signature ancestry index), extended by the landing-proof manifest builder (any-depth proof manifests), and closed
 * by the landing-proof e2e (fail-closed on incomplete or bounded walks). Registration export only — the concern-manifest registry assembles
 * src/registry.ts. The goldenRef sha256 pins gen/landing-proof.json and is regenerated with it.
 */
export const LANDING_PROOF_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "landing-proof",
  decisionRefs: ["complete-path-adjudication"],
  frozenValues: {
    ANCESTRY_INDEX_KEY_FIELDS,
    ANCESTRY_INDEX_ENTRY_FIELDS,
    INDEXABILITY_RULE,
    LINKAGE_RULE,
    EXACT_BODY_RULE,
    COLLISION_RULE,
    INGEST_OUTCOMES,
    WALK_OUTCOMES,
    WALK_COMPLETENESS,
    WALK_STEP_BUDGET_DEFAULT,
    LANDING_PROOF_FIXTURES,
    LANDING_PROOF_MANIFEST_VERSION,
    LANDING_CLASSIFICATIONS,
    REQUIRED_PER_BODY_PREDICATES,
    ECONOMIC_EVALUATION_BASIS,
    DEPTH_SEMANTICS,
    REVERIFICATION_PREDICATE,
    MANIFEST_RETENTION,
    OPERATION_IDENTITY_FIELDS,
    CLAIMED_LANDED_FIELDS,
    HEAD_READ_PROVENANCE_FIELDS,
    MANIFEST_HOP_FIELDS,
    VERIFICATION_SEMANTICS_FIELDS,
    SINGLE_PATH_MANIFEST_FIELDS,
    MOVE_PROOF_MANIFEST_FIELDS,
    MANIFEST_REVERIFY_FAILURES,
    REVERIFY_VERDICTS,
    LANDING_PROOF_GOLDEN_MANIFESTS,
    LANDING_DETERMINATIONS,
    INDETERMINATE_CAUSES,
    INDETERMINATE_CAUSE_TAXONOMY,
    FRESH_HEAD_STATUSES,
    DETERMINATION_AUTHORITY,
    REWALK_SEMANTICS,
    FAIL_CLOSED_INVARIANTS,
    LANDING_WIRE_CLASSIFICATIONS,
    LANDING_DETERMINATION_TO_WIRE,
    DEPTH_ONE_LANDING_IS_LANDED_COMPLETE_PATH,
    WIRE_INDETERMINATE_REASONS,
    INDETERMINATE_CAUSE_TO_WIRE_REASON,
  },
  goldenRefs: [
    {
      path: "gen/landing-proof.json",
      sha256: "ab5959c3ec8d2d38cada04e183997edaffe368c9763adbb73783b6b058194ab8",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "complete-path-adjudication: any-depth complete-path landing proof anchored at a fresh head",
    "protocol foundation: chain-link, signing, and settlement rules",
    "operation flows: landing checkpoints per operation kind",
    "observation-verification: complete-path walk, anomaly classes, retention",
    "operations-recovery: landing determination in recovery flows",
  ],
});
