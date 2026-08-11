import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  READINESS_CHECKS,
  GATING_CHECK_IDS,
  NON_GATING_CHECK_IDS,
  READINESS_LEADERSHIP_SEPARATION,
  RECONCILIATION,
  RESTORE_HOLD_READINESS,
} from "./readiness-checks.contract.ts";
import {
  BOOT_SEQUENCE,
  LEADERSHIP_PREREQUISITE_SEQUENCE,
  BOOT_SEQUENCE_INVARIANTS,
  SHUTDOWN_SEQUENCE,
  SHUTDOWN_SEQUENCE_INVARIANTS,
} from "./boot-sequence.contract.ts";
import {
  NODE_OPERATION_CLASSES,
  LEADER_ONLY_OPERATION_CLASSES,
  NODE_MODES,
} from "./degraded-modes.contract.ts";
import {
  WALLET_SEQUENCING_AUTHORITY,
  CONSUMED_VAULT_LEADERSHIP,
  FAIL_CLOSED_RULES,
  LEADERSHIP_LOSS_HANDLING,
  LEADERSHIP_LOCK_EXIT,
} from "./fail-closed.contract.ts";

/**
 * The aggregated readiness/leadership contract (the named concern). gen/readiness.json is a review-diff
 * snapshot of exactly this object (tier 2, never byte authority); the `.contract.ts` `as const`
 * sources are authority. gen-sync.test.ts fails if the two diverge. Data only — no functions.
 */
export const READINESS_CONTRACT = {
  checks: {
    READINESS_CHECKS,
    GATING_CHECK_IDS,
    NON_GATING_CHECK_IDS,
    READINESS_LEADERSHIP_SEPARATION,
    RECONCILIATION,
    RESTORE_HOLD_READINESS,
  },
  boot: {
    BOOT_SEQUENCE,
    LEADERSHIP_PREREQUISITE_SEQUENCE,
    BOOT_SEQUENCE_INVARIANTS,
    SHUTDOWN_SEQUENCE,
    SHUTDOWN_SEQUENCE_INVARIANTS,
  },
  modes: {
    NODE_OPERATION_CLASSES,
    LEADER_ONLY_OPERATION_CLASSES,
    NODE_MODES,
  },
  failClosed: {
    WALLET_SEQUENCING_AUTHORITY,
    CONSUMED_VAULT_LEADERSHIP,
    FAIL_CLOSED_RULES,
    LEADERSHIP_LOSS_HANDLING,
    LEADERSHIP_LOCK_EXIT,
  },
} as const;

/**
 * the named concern's self-registered ConcernManifest (concern dir src/readiness/). Registration export
 * only — the concern-manifest registry assembles src/registry.ts. The goldenRef sha256 pins gen/readiness.json and is
 * regenerated with it. decisionRefs anchor the readiness-leadership decoupling rule (the readiness/leadership decoupling), the wallet-vault envelope freeze
 * (the vault leadership facts consumed), and the readiness-leadership decoupling rule (the non-gating-check precedent).
 */
export const READINESS_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "readiness",
  decisionRefs: [
    "startup-sequence",
    "vault-storage-model",
    "leadership-lease",
  ],
  frozenValues: {
    READINESS_CHECKS,
    GATING_CHECK_IDS,
    NON_GATING_CHECK_IDS,
    READINESS_LEADERSHIP_SEPARATION,
    RECONCILIATION,
    RESTORE_HOLD_READINESS,
    BOOT_SEQUENCE,
    LEADERSHIP_PREREQUISITE_SEQUENCE,
    BOOT_SEQUENCE_INVARIANTS,
    SHUTDOWN_SEQUENCE,
    SHUTDOWN_SEQUENCE_INVARIANTS,
    NODE_OPERATION_CLASSES,
    LEADER_ONLY_OPERATION_CLASSES,
    NODE_MODES,
    WALLET_SEQUENCING_AUTHORITY,
    CONSUMED_VAULT_LEADERSHIP,
    FAIL_CLOSED_RULES,
    LEADERSHIP_LOSS_HANDLING,
    LEADERSHIP_LOCK_EXIT,
  },
  goldenRefs: [
    {
      path: "gen/readiness.json",
      sha256: "d8612ffcaf51cc2506a1fdcca54dd7447c3d082725067d8a3282ff2da447ec03",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "node-core: runtime components and the readiness sentence",
    "operations-recovery: boot recovery and degraded operation",
    "startup-sequence: readiness is decoupled from signer-lock ownership",
    "vault-storage-model: the vault leadership facts this concern consumes",
    "leadership-lease: the non-gating-check precedent",
  ],
});
