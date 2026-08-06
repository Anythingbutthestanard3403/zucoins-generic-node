/**
 * SOURCE: the observation-verification spec (complete-path walk) and the complete-path
 * landing-proof rule. the landing-proof manifest builder — the pure, stateless landing-proof manifest: build one from a
 * the landing-proof index/walk, and re-verify one from the manifest ALONE, trusting nothing the producing node
 * asserts (every hop recomputed and byte-compared, the chain re-walked structurally). No
 * storage/network/worker/keys; the only external call is `node:crypto` SHA-256 to recompute a hop
 * body digest for the byte-exact check — a pure transform, as the landing-proof index/walk's ancestry-index.ts does it.
 */

import { createHash } from "node:crypto";

import { type OperationKind } from "../operations/operations.contract.ts";
import { type WalkResult } from "./ancestry-index.ts";
import {
  LANDING_PROOF_MANIFEST_VERSION,
  ECONOMIC_EVALUATION_BASIS,
  REQUIRED_PER_BODY_PREDICATES,
  type LandingClassification,
  type ManifestReverifyFailure,
  type PerBodyPredicate,
  type ReverifyVerdict,
} from "./proof-manifest.contract.ts";

export interface OperationIdentity {
  readonly operation_id: string;
  readonly operation_kind: OperationKind;
  readonly queried_wallet_public_key: string;
  readonly wallet_role: "sender" | "receiver";
}

export interface ClaimedLanded {
  readonly step_2_signature: string;
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
  readonly depth: number;
}

export interface HeadReadProvenance {
  readonly source_observation_id: string;
  readonly observer_id: string;
  readonly endpoint_fingerprint: string;
  readonly wallet_seq: number;
  readonly observed_at: string;
  readonly head_step_2_signature: string;
  readonly head_completed_transaction_sha256: string;
  readonly head_body_matches_authoritative_read: boolean;
}

export interface ManifestHop {
  readonly depth: number;
  readonly wallet_public_key: string;
  readonly wallet_role: "sender" | "receiver";
  readonly step_2_signature: string;
  readonly s_signature: string;
  readonly p_signature: string;
  readonly step_1_signature: string;
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
}

export interface VerificationSemantics {
  readonly economic_evaluation_basis: string;
  readonly head_anchored_at_verification_time: boolean;
  readonly intermediate_bodies_untrusted_until_verified: boolean;
  readonly declared_per_body_predicates: readonly PerBodyPredicate[];
}

export interface SinglePathProofManifest {
  readonly manifest_version: string;
  readonly operation: OperationIdentity;
  readonly classification: LandingClassification;
  readonly claimed_landed: ClaimedLanded;
  readonly head_read: HeadReadProvenance;
  readonly hop_chain: readonly ManifestHop[];
  readonly verification: VerificationSemantics;
}

export interface MoveProofManifest {
  readonly manifest_version: string;
  readonly operation: OperationIdentity;
  readonly classification: LandingClassification;
  readonly move_step_2_signature: string;
  readonly source_path: SinglePathProofManifest;
  readonly destination_path: SinglePathProofManifest;
  readonly verification: VerificationSemantics;
}

export interface ReverifyResult {
  readonly verdict: ReverifyVerdict;
  readonly failures: readonly ManifestReverifyFailure[];
}

const sha256hex = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

/**
 * Map a classification plus the structural failures found to a re-verify result. A clean structural
 * re-verify yields a `STRUCTURALLY_REVERIFIED_LANDED_*` verdict — it attests manifest structure only,
 * never the deferred Ed25519 / economic crypto (the landing-proof e2e gates a landing on those separately).
 */
const verdictOf = (
  classification: LandingClassification,
  failures: readonly ManifestReverifyFailure[],
): ReverifyResult => {
  if (failures.length > 0) return { verdict: "REJECTED", failures };
  const verdict: ReverifyVerdict =
    classification === "LANDED_EXACT"
      ? "STRUCTURALLY_REVERIFIED_LANDED_EXACT"
      : "STRUCTURALLY_REVERIFIED_LANDED_COMPLETE_PATH";
  return { verdict, failures };
};

/**
 * Build a single-path proof manifest from the landing-proof index/walk by truncating the walk chain at the
 * claimed body's depth (head at depth 0 down to and including the claimed body). Returns null when
 * the claimed body is not present in the supplied walk chain — no manifest is produced (interpreting
 * that absence as INDETERMINATE-with-no-authority is the landing-proof e2e's, not this constructor's). The
 * classification is derived: depth 0 is LANDED_EXACT, any deeper claim is LANDED_COMPLETE_PATH.
 */
export const buildProofManifest = (args: {
  readonly operation: OperationIdentity;
  readonly walk: WalkResult;
  readonly claimedStepTwoSignature: string;
  readonly headProvenance: {
    readonly source_observation_id: string;
    readonly observer_id: string;
    readonly endpoint_fingerprint: string;
    readonly wallet_seq: number;
    readonly observed_at: string;
    readonly head_body_matches_authoritative_read: boolean;
  };
  readonly declaredPerBodyPredicates?: readonly PerBodyPredicate[];
}): SinglePathProofManifest | null => {
  const { chain } = args.walk;
  if (chain.length === 0) return null;

  const claimedIndex = chain.findIndex((s) => s.entry.step_2_signature === args.claimedStepTwoSignature);
  if (claimedIndex === -1) return null;

  const proofSteps = chain.slice(0, claimedIndex + 1);
  const hop_chain: readonly ManifestHop[] = proofSteps.map((s) => ({
    depth: s.depth,
    wallet_public_key: s.entry.wallet_public_key,
    wallet_role: s.entry.wallet_role,
    step_2_signature: s.entry.step_2_signature,
    s_signature: s.entry.s_signature,
    p_signature: s.entry.p_signature,
    step_1_signature: s.entry.step_1_signature,
    completed_transaction_text: s.entry.completed_transaction_text,
    completed_transaction_sha256: s.entry.completed_transaction_sha256,
  }));

  const head = chain[0].entry;
  const claimed = chain[claimedIndex].entry;
  const classification: LandingClassification =
    claimedIndex === 0 ? "LANDED_EXACT" : "LANDED_COMPLETE_PATH";

  return {
    manifest_version: LANDING_PROOF_MANIFEST_VERSION,
    operation: args.operation,
    classification,
    claimed_landed: {
      step_2_signature: claimed.step_2_signature,
      completed_transaction_text: claimed.completed_transaction_text,
      completed_transaction_sha256: claimed.completed_transaction_sha256,
      depth: claimedIndex,
    },
    head_read: {
      source_observation_id: args.headProvenance.source_observation_id,
      observer_id: args.headProvenance.observer_id,
      endpoint_fingerprint: args.headProvenance.endpoint_fingerprint,
      wallet_seq: args.headProvenance.wallet_seq,
      observed_at: args.headProvenance.observed_at,
      head_step_2_signature: head.step_2_signature,
      head_completed_transaction_sha256: head.completed_transaction_sha256,
      head_body_matches_authoritative_read: args.headProvenance.head_body_matches_authoritative_read,
    },
    hop_chain,
    verification: {
      economic_evaluation_basis: ECONOMIC_EVALUATION_BASIS,
      head_anchored_at_verification_time: true,
      intermediate_bodies_untrusted_until_verified: true,
      declared_per_body_predicates:
        args.declaredPerBodyPredicates ?? [...REQUIRED_PER_BODY_PREDICATES],
    },
  };
};

/** True iff every required per-body predicate class is declared. */
const declaresAllPredicates = (declared: readonly PerBodyPredicate[]): boolean =>
  REQUIRED_PER_BODY_PREDICATES.every((required) => declared.includes(required));

/**
 * Re-verify a single-path manifest from the manifest ALONE, trusting nothing the producing node
 * asserts. Returns every structural failure found (empty ⇒ a clean re-verify). A broken chain is
 * rejected whole — no contiguous prefix is ever accepted as a partial landing.
 */
export const reVerifyProofManifest = (manifest: SinglePathProofManifest): ReverifyResult => {
  const failures: ManifestReverifyFailure[] = [];
  const chain = manifest.hop_chain;

  if (manifest.manifest_version !== LANDING_PROOF_MANIFEST_VERSION) {
    failures.push("UNKNOWN_MANIFEST_VERSION");
  }
  if (chain.length === 0) {
    failures.push("EMPTY_HOP_CHAIN");
    return { verdict: "REJECTED", failures };
  }

  const seenStepTwo = new Set<string>();
  const seenState = new Set<string>();
  for (let i = 0; i < chain.length; i += 1) {
    const hop = chain[i];
    if (hop.depth !== i) failures.push("NON_CONTIGUOUS_DEPTHS");
    if (sha256hex(hop.completed_transaction_text) !== hop.completed_transaction_sha256) {
      failures.push("HOP_DIGEST_MISMATCH");
    }
    if (seenStepTwo.has(hop.step_2_signature) || seenState.has(hop.s_signature)) {
      failures.push("DUPLICATE_OR_CYCLE_HOP");
    }
    seenStepTwo.add(hop.step_2_signature);
    seenState.add(hop.s_signature);
  }

  for (let i = 0; i < chain.length - 1; i += 1) {
    const shallower = chain[i];
    const deeper = chain[i + 1];
    if (
      shallower.wallet_public_key !== deeper.wallet_public_key ||
      shallower.wallet_role !== deeper.wallet_role ||
      shallower.p_signature === "" ||
      shallower.p_signature !== deeper.s_signature
    ) {
      failures.push("BROKEN_BACKLINK");
    }
  }

  const head = chain[0];
  if (
    head.step_2_signature !== manifest.head_read.head_step_2_signature ||
    head.completed_transaction_sha256 !== manifest.head_read.head_completed_transaction_sha256
  ) {
    failures.push("HEAD_ANCHOR_MISMATCH");
  }
  if (!manifest.head_read.head_body_matches_authoritative_read) {
    failures.push("HEAD_NOT_AUTHORITATIVE");
  }

  const deepest = chain[chain.length - 1];
  if (
    manifest.claimed_landed.step_2_signature !== deepest.step_2_signature ||
    manifest.claimed_landed.completed_transaction_text !== deepest.completed_transaction_text ||
    manifest.claimed_landed.completed_transaction_sha256 !== deepest.completed_transaction_sha256 ||
    manifest.claimed_landed.depth !== deepest.depth
  ) {
    failures.push("CLAIMED_BODY_NOT_CHAIN_TERMINAL");
  }

  const exactShape = chain.length === 1 && manifest.claimed_landed.depth === 0;
  if (manifest.classification === "LANDED_EXACT" && !exactShape) failures.push("CLASSIFICATION_MISMATCH");
  if (manifest.classification === "LANDED_COMPLETE_PATH" && chain.length < 2) {
    failures.push("CLASSIFICATION_MISMATCH");
  }

  if (manifest.verification.economic_evaluation_basis !== ECONOMIC_EVALUATION_BASIS) {
    failures.push("ECONOMIC_BASIS_NOT_EXPECTED_BODY_T0");
  }
  if (!declaresAllPredicates(manifest.verification.declared_per_body_predicates)) {
    failures.push("INCOMPLETE_PER_BODY_PREDICATES");
  }

  return verdictOf(manifest.classification, failures);
};

/**
 * Re-verify a MOVE_INTERNAL dual-path manifest: both single-path proofs independently, plus the
 * shared-anchor and role bindings (source = sender role-view, destination = receiver role-view, both
 * claimed bodies carrying the same expected-move step-2 signature). The move re-verifies only when
 * both paths do and both bindings hold.
 */
export const reVerifyMoveProofManifest = (manifest: MoveProofManifest): ReverifyResult => {
  const failures: ManifestReverifyFailure[] = [];

  const source = reVerifyProofManifest(manifest.source_path);
  const destination = reVerifyProofManifest(manifest.destination_path);
  for (const f of [...source.failures, ...destination.failures]) failures.push(f);

  if (
    manifest.source_path.operation.wallet_role !== "sender" ||
    manifest.source_path.hop_chain.some((h) => h.wallet_role !== "sender") ||
    manifest.destination_path.operation.wallet_role !== "receiver" ||
    manifest.destination_path.hop_chain.some((h) => h.wallet_role !== "receiver")
  ) {
    failures.push("MOVE_PATH_ROLE_MISMATCH");
  }

  if (
    manifest.source_path.claimed_landed.step_2_signature !== manifest.move_step_2_signature ||
    manifest.destination_path.claimed_landed.step_2_signature !== manifest.move_step_2_signature
  ) {
    failures.push("MOVE_ANCHOR_MISMATCH");
  }

  return verdictOf(manifest.classification, failures);
};
