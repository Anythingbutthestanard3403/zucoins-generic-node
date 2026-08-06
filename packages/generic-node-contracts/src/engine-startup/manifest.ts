import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  ENGINE_REGISTRY,
  LEADER_GATED_ENGINE_IDS,
  FOLLOWER_SAFE_ENGINE_IDS,
} from "./engines.contract.ts";
import {
  EXPANDED_BOOT_STAGE,
  ENGINE_STARTUP_SEQUENCE,
  STARTUP_INVARIANTS,
  LEADERSHIP_LOSS_SHUTDOWN_SEQUENCE,
  SHUTDOWN_INVARIANTS,
} from "./startup-sequence.contract.ts";
import { NO_SPLIT_BRAIN_INVARIANT, TAKEOVER_BOUNDARY } from "./split-brain.contract.ts";

/**
 * The aggregated leader-gated engine-startup contract (the named concern). gen/engine-startup.json is a
 * review-diff snapshot of exactly this object (tier 2, never byte authority); the `.contract.ts`
 * `as const` sources are authority. gen-sync.test.ts fails if the two diverge. Data only.
 */
export const ENGINE_STARTUP_CONTRACT = {
  engines: {
    ENGINE_REGISTRY,
    LEADER_GATED_ENGINE_IDS,
    FOLLOWER_SAFE_ENGINE_IDS,
  },
  startup: {
    EXPANDED_BOOT_STAGE,
    ENGINE_STARTUP_SEQUENCE,
    STARTUP_INVARIANTS,
    LEADERSHIP_LOSS_SHUTDOWN_SEQUENCE,
    SHUTDOWN_INVARIANTS,
  },
  splitBrain: {
    NO_SPLIT_BRAIN_INVARIANT,
    TAKEOVER_BOUNDARY,
  },
} as const;

/**
 * the named concern's self-registered ConcernManifest (concern dir src/engine-startup/). Sibling of the
 * the named concern readiness concern under the named concern group; distinct concernId so the concern-manifest registry assembles both
 * without collision. Registration export only — the concern-manifest registry owns src/registry.ts.
 */
export const ENGINE_STARTUP_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "engine-startup",
  decisionRefs: ["startup-sequence", "vault-storage-model", "leadership-lease"],
  frozenValues: {
    ENGINE_REGISTRY,
    LEADER_GATED_ENGINE_IDS,
    FOLLOWER_SAFE_ENGINE_IDS,
    ENGINE_STARTUP_SEQUENCE,
    STARTUP_INVARIANTS,
    LEADERSHIP_LOSS_SHUTDOWN_SEQUENCE,
    SHUTDOWN_INVARIANTS,
    NO_SPLIT_BRAIN_INVARIANT,
    TAKEOVER_BOUNDARY,
  },
  goldenRefs: [
    {
      path: "gen/engine-startup.json",
      sha256: "e0e9a41eda82b46a1be4719615b1af308bc24eed067f57b1fcbd196947c39c93",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "node-core: runtime components",
    "operations-recovery: boot recovery",
    "operations-recovery: leadership",
    "decision: startup-sequence",
    "decision: vault-storage-model",
    "decision: leadership-lease",
  ],
});
