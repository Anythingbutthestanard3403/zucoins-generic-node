/**
 * SOURCE: the observation-verification spec (complete-path walk) and the complete-path
 * landing-proof rule. the landing-proof manifest builder test anchors — frozen golden landing-proof manifests built
 * from the landing-proof index/walk's 3-hop fixture chain (genesis -> A depth 2 -> B depth 1 -> C fresh head depth 0)
 * and its MOVE fixture T (observed under both role-views).
 *
 * These are projections of the frozen fixtures, NOT of the builder: each hop copies a fixture's
 * exact byte-for-byte body and its pinned digest (the byte-exact signing rule). `proof-manifest.census.test.ts`
 * recomputes every hop digest against the fixture pins and re-runs the standalone re-verification
 * predicate over each golden, and separately drives the landing-proof index/walk's real index/walk through
 * `buildProofManifest` and asserts it reproduces these goldens exactly.
 */

import {
  LANDING_PROOF_FIXTURES,
  WALLET_W,
  WALLET_S,
  WALLET_R,
} from "./fixtures.contract.ts";
import {
  LANDING_PROOF_MANIFEST_VERSION,
  ECONOMIC_EVALUATION_BASIS,
  REQUIRED_PER_BODY_PREDICATES,
} from "./proof-manifest.contract.ts";
import {
  type HeadReadProvenance,
  type ManifestHop,
  type MoveProofManifest,
  type SinglePathProofManifest,
  type VerificationSemantics,
} from "./proof-manifest.ts";

const { A, B, C, T_SENDER, T_RECEIVER } = LANDING_PROOF_FIXTURES;

/** Frozen, deterministic head-read provenance literals (product-neutral placeholder identities). */
const OBSERVER_ID = "00000000-0000-4000-8000-0000000000ob" as const;
const ENDPOINT_FINGERPRINT = "b".repeat(64);
const OBSERVED_AT = "2026-07-19T00:00:00.000Z" as const;
const HEAD_OBS_ID_W = "00000000-0000-4000-8000-00000000head" as const;
const HEAD_OBS_ID_S = "00000000-0000-4000-8000-0000000senD" as const;
const HEAD_OBS_ID_R = "00000000-0000-4000-8000-0000000recV" as const;

interface FixtureHopSource {
  readonly wallet_public_key: string;
  readonly wallet_role: "sender" | "receiver";
  readonly step_2_signature: string;
  readonly s_signature: string;
  readonly p_signature: string;
  readonly step_1_signature: string;
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
}

/** Independent field projection of a fixture body into a manifest hop (never the builder). */
const hopFromFixture = (f: FixtureHopSource, depth: number): ManifestHop => ({
  depth,
  wallet_public_key: f.wallet_public_key,
  wallet_role: f.wallet_role,
  step_2_signature: f.step_2_signature,
  s_signature: f.s_signature,
  p_signature: f.p_signature,
  step_1_signature: f.step_1_signature,
  completed_transaction_text: f.completed_transaction_text,
  completed_transaction_sha256: f.completed_transaction_sha256,
});

const headReadOf = (f: FixtureHopSource, sourceObservationId: string): HeadReadProvenance => ({
  source_observation_id: sourceObservationId,
  observer_id: OBSERVER_ID,
  endpoint_fingerprint: ENDPOINT_FINGERPRINT,
  wallet_seq: 1,
  observed_at: OBSERVED_AT,
  head_step_2_signature: f.step_2_signature,
  head_completed_transaction_sha256: f.completed_transaction_sha256,
  head_body_matches_authoritative_read: true,
});

export const GOLDEN_VERIFICATION_SEMANTICS: VerificationSemantics = {
  economic_evaluation_basis: ECONOMIC_EVALUATION_BASIS,
  head_anchored_at_verification_time: true,
  intermediate_bodies_untrusted_until_verified: true,
  declared_per_body_predicates: REQUIRED_PER_BODY_PREDICATES,
};

/**
 * Depth-N (N=2) buried landing: the claimed body A is proven a depth-2 ancestor of the fresh head C
 * through the contiguous exact-body chain C(0) -> B(1) -> A(2), A being genesis-rooted.
 */
export const GOLDEN_COMPLETE_PATH_MANIFEST: SinglePathProofManifest = {
  manifest_version: LANDING_PROOF_MANIFEST_VERSION,
  operation: {
    operation_id: "00000000-0000-4000-8000-00000000recX",
    operation_kind: "RECEIVE_EXTERNAL",
    queried_wallet_public_key: WALLET_W,
    wallet_role: "receiver",
  },
  classification: "LANDED_COMPLETE_PATH",
  claimed_landed: {
    step_2_signature: A.step_2_signature,
    completed_transaction_text: A.completed_transaction_text,
    completed_transaction_sha256: A.completed_transaction_sha256,
    depth: 2,
  },
  head_read: headReadOf(C, HEAD_OBS_ID_W),
  hop_chain: [hopFromFixture(C, 0), hopFromFixture(B, 1), hopFromFixture(A, 2)],
  verification: GOLDEN_VERIFICATION_SEMANTICS,
};

/**
 * Depth-1 bounded prefix: the claimed body B is proven a depth-1 ancestor of C through C(0) -> B(1).
 * The proof stops at B without reaching genesis (B's predecessor pointer is non-empty) — a valid
 * proof that does NOT require walking below the claimed body.
 */
export const GOLDEN_COMPLETE_PATH_PREFIX_MANIFEST: SinglePathProofManifest = {
  manifest_version: LANDING_PROOF_MANIFEST_VERSION,
  operation: {
    operation_id: "00000000-0000-4000-8000-00000000recY",
    operation_kind: "RECEIVE_EXTERNAL",
    queried_wallet_public_key: WALLET_W,
    wallet_role: "receiver",
  },
  classification: "LANDED_COMPLETE_PATH",
  claimed_landed: {
    step_2_signature: B.step_2_signature,
    completed_transaction_text: B.completed_transaction_text,
    completed_transaction_sha256: B.completed_transaction_sha256,
    depth: 1,
  },
  head_read: headReadOf(C, HEAD_OBS_ID_W),
  hop_chain: [hopFromFixture(C, 0), hopFromFixture(B, 1)],
  verification: GOLDEN_VERIFICATION_SEMANTICS,
};

/**
 * Depth-0 exact landing: the claimed body C IS the fresh verified head — a one-hop chain and the
 * `LANDED_EXACT` classification.
 */
export const GOLDEN_EXACT_MANIFEST: SinglePathProofManifest = {
  manifest_version: LANDING_PROOF_MANIFEST_VERSION,
  operation: {
    operation_id: "00000000-0000-4000-8000-00000000recZ",
    operation_kind: "RECEIVE_EXTERNAL",
    queried_wallet_public_key: WALLET_W,
    wallet_role: "receiver",
  },
  classification: "LANDED_EXACT",
  claimed_landed: {
    step_2_signature: C.step_2_signature,
    completed_transaction_text: C.completed_transaction_text,
    completed_transaction_sha256: C.completed_transaction_sha256,
    depth: 0,
  },
  head_read: headReadOf(C, HEAD_OBS_ID_W),
  hop_chain: [hopFromFixture(C, 0)],
  verification: GOLDEN_VERIFICATION_SEMANTICS,
};

/**
 * MOVE_INTERNAL dual path: one move body T is proven landed under BOTH role-views — the source
 * (sender) and destination (receiver) — each an independent single-path proof sharing the move's
 * step-2 signature. Here T is the fresh head in each role-view (depth-0 `LANDED_EXACT` legs).
 */
const GOLDEN_MOVE_SOURCE_PATH: SinglePathProofManifest = {
  manifest_version: LANDING_PROOF_MANIFEST_VERSION,
  operation: {
    operation_id: "00000000-0000-4000-8000-0000000movE",
    operation_kind: "MOVE_INTERNAL",
    queried_wallet_public_key: WALLET_S,
    wallet_role: "sender",
  },
  classification: "LANDED_EXACT",
  claimed_landed: {
    step_2_signature: T_SENDER.step_2_signature,
    completed_transaction_text: T_SENDER.completed_transaction_text,
    completed_transaction_sha256: T_SENDER.completed_transaction_sha256,
    depth: 0,
  },
  head_read: headReadOf(T_SENDER, HEAD_OBS_ID_S),
  hop_chain: [hopFromFixture(T_SENDER, 0)],
  verification: GOLDEN_VERIFICATION_SEMANTICS,
};

const GOLDEN_MOVE_DESTINATION_PATH: SinglePathProofManifest = {
  manifest_version: LANDING_PROOF_MANIFEST_VERSION,
  operation: {
    operation_id: "00000000-0000-4000-8000-0000000movE",
    operation_kind: "MOVE_INTERNAL",
    queried_wallet_public_key: WALLET_R,
    wallet_role: "receiver",
  },
  classification: "LANDED_EXACT",
  claimed_landed: {
    step_2_signature: T_RECEIVER.step_2_signature,
    completed_transaction_text: T_RECEIVER.completed_transaction_text,
    completed_transaction_sha256: T_RECEIVER.completed_transaction_sha256,
    depth: 0,
  },
  head_read: headReadOf(T_RECEIVER, HEAD_OBS_ID_R),
  hop_chain: [hopFromFixture(T_RECEIVER, 0)],
  verification: GOLDEN_VERIFICATION_SEMANTICS,
};

export const GOLDEN_MOVE_MANIFEST: MoveProofManifest = {
  manifest_version: LANDING_PROOF_MANIFEST_VERSION,
  operation: {
    operation_id: "00000000-0000-4000-8000-0000000movE",
    operation_kind: "MOVE_INTERNAL",
    queried_wallet_public_key: WALLET_S,
    wallet_role: "sender",
  },
  classification: "LANDED_EXACT",
  move_step_2_signature: T_SENDER.step_2_signature,
  source_path: GOLDEN_MOVE_SOURCE_PATH,
  destination_path: GOLDEN_MOVE_DESTINATION_PATH,
  verification: GOLDEN_VERIFICATION_SEMANTICS,
};

/** All golden manifests, for the aggregated review-diff snapshot (tier 2). */
export const LANDING_PROOF_GOLDEN_MANIFESTS = {
  GOLDEN_COMPLETE_PATH_MANIFEST,
  GOLDEN_COMPLETE_PATH_PREFIX_MANIFEST,
  GOLDEN_EXACT_MANIFEST,
  GOLDEN_MOVE_MANIFEST,
} as const;
