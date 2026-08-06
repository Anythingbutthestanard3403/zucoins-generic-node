/**
 * SOURCE: the observation-verification spec (buried-landing complete-path walk,
 * verification-material access and retention, threats/limitations), the protocol foundation,
 * and the complete-path landing-proof rule (canonical).
 * the landing-proof manifest builder — the any-depth operation proof-manifest contract.
 *
 * This slice freezes the durable, independently re-verifiable landing-proof MANIFEST: the shape a
 * node emits to prove a specific expected operation body landed at any finite ancestor depth of a
 * fresh verified head, and the re-verification predicate a third party re-runs from that manifest
 * ALONE. It CONSUMES the landing-proof index/walk's frozen index/walk/completeness primitives and re-freezes none of
 * them (.1 wins on any conflict). It does NOT own the fail-closed INDETERMINATE cause taxonomy of
 * an incomplete or bounded walk, nor any bound/cap on depth — that is the landing-proof e2e's territory.
 */

import { type FieldSpec } from "../observation/record-fields.contract.ts";

/** Frozen envelope discriminator for a v1 landing-proof manifest; product-neutral by design. */
export const LANDING_PROOF_MANIFEST_VERSION = "landing-proof-manifest/v1" as const;

/**
 * The two positive landing classifications (the complete-path landing-proof rule). `LANDED_EXACT` — the expected exact completed
 * body IS the fresh verified head (a one-hop chain at depth 0). `LANDED_COMPLETE_PATH` — the
 * expected body is a finite ancestor of the head proven by a contiguous exact-body chain (chain
 * length >= 2). There is no third positive verdict and no generic `PROVEN_NOT_LANDED`.
 */
export const LANDING_CLASSIFICATIONS = ["LANDED_EXACT", "LANDED_COMPLETE_PATH"] as const;
export type LandingClassification = (typeof LANDING_CLASSIFICATIONS)[number];

/**
 * The per-body predicate classes the complete-path landing-proof rule requires every body in the sequence to pass. A manifest
 * DECLARES that its producing node evaluated all of these at verification time. Byte-exact preimage
 * reconstruction and the role-relative backlink are re-executed by the standalone re-verifier over
 * the manifest bytes; the Ed25519 signature and operation-economic predicates are attested (a
 * synthetic contract-freeze cannot re-run real Ed25519 or an operation-artifact economic check —
 * the runtime verification lane owns those), and a manifest that fails to declare the full set is
 * rejected as an incomplete proof.
 */
export const REQUIRED_PER_BODY_PREDICATES = [
  "EXACT_PREIMAGE",
  "BOTH_SIGNATURES",
  "ROLE",
  "BACKLINK",
  "ECONOMIC",
] as const;
export type PerBodyPredicate = (typeof REQUIRED_PER_BODY_PREDICATES)[number];

/**
 * Economics are evaluated against the expected body and its T0 baseline at verification time, never
 * against a later observed balance (a later balance can reflect an unrelated subsequent operation).
 * The frozen basis a valid manifest must declare.
 */
export const ECONOMIC_EVALUATION_BASIS = "EXPECTED_BODY_T0" as const;

/**
 * Depth-unbounded semantics. The head is depth 0; the claimed body may sit at any finite depth with
 * NO cap frozen here. A budget/bound and the fail-closed handling of a bounded or incomplete walk
 * are the landing-proof e2e's; this slice imposes no maximum and asserts no not-landed conclusion.
 */
export const DEPTH_SEMANTICS = {
  headDepth: 0,
  depthCap: null,
  unbounded: true,
  boundedOrIncompleteHandlingOwner: "fail-closed-determination",
} as const;

/**
 * The independently re-verifiable predicate a THIRD PARTY re-runs from the manifest alone, trusting
 * no assertion of the producing node. Intermediate bodies are untrusted supplied evidence until the
 * re-verifier confirms each (the complete-path landing-proof rule). A structurally defective supplied manifest is rejected whole —
 * the re-verifier never accepts a contiguous prefix of a broken chain as a partial landing.
 */
export const REVERIFICATION_PREDICATE = {
  runsFromManifestAlone: true,
  trustsProducingNode: false,
  perHopDigestRecomputedAndByteCompared: true,
  backlinkRoleRelative: "P(W,T[i]) == S(W,T[i-1])",
  headAnchoredAtDepthZero: true,
  claimedBodyIsChainTerminal: true,
  requiresContiguousGapFreeDuplicateFreeCycleFreeChain: true,
  partialPrefixNeverAccepted: true,
} as const;

/**
 * Permanence / retention (the observation retention rules the observation ledger obeys). A proof
 * manifest's canonical settled transaction text and verification verdict are PERMANENT append-only
 * evidence. The default access window (terminal plus 30 days) governs endpoint exposure only; its
 * expiry revokes access, never the underlying permanent evidence. Exact bodies are never
 * parse/re-serialized by retention jobs (the byte-exact signing rule).
 */
export const MANIFEST_RETENTION = {
  permanent: true,
  accessWindowDefault: "TERMINAL_PLUS_30_DAYS",
  expiryRevokesEndpointAccessOnly: true,
  canonicalBodiesNeverReserialized: true,
  verdictIsPermanentEvidence: true,
  source: "the observation retention rules",
} as const;

/** Operation identity — which node operation this manifest proves landed. */
export const OPERATION_IDENTITY_FIELDS = [
  { name: "operation_id", type: "uuid", nullable: false, note: "the node operation this proof is anchored to" },
  { name: "operation_kind", type: "operation_kind", nullable: false, note: "the frozen OperationKind domain (the operations concern OPERATION_KINDS); consumed here, never redeclared" },
  { name: "queried_wallet_public_key", type: "padded_base64url_pubkey", nullable: false, note: "the wallet role-view the single-path chain is walked under" },
  { name: "wallet_role", type: "wallet_observation_role", nullable: false, note: "sender | receiver; genesis is a walk terminal, never an operation role-view" },
] as const satisfies readonly FieldSpec[];

/** The claimed-landed (expected) transaction: its exact body, recomputable digest, and chain depth. */
export const CLAIMED_LANDED_FIELDS = [
  { name: "step_2_signature", type: "padded_base64url_signature", nullable: false, note: "the completing signature; the claimed body's identity in the wallet role-view" },
  { name: "completed_transaction_text", type: "text", nullable: false, note: "the EXACT signed body, byte-for-byte; never normalized or reformatted (the byte-exact signing rule)" },
  { name: "completed_transaction_sha256", type: "sha256_hex", nullable: false, note: "SHA-256 of completed_transaction_text; recomputed and byte-compared on re-verification" },
  { name: "depth", type: "integer_nonneg", nullable: false, note: "the claimed body's depth in the hop chain; 0 iff LANDED_EXACT" },
] as const satisfies readonly FieldSpec[];

/**
 * Head-read provenance — the fresh authoritative head the whole proof is anchored at, carrying the
 * observation record contract's provenance so a re-verifier can bind the depth-0 hop to a specific
 * append-only `gateway_observations` row without trusting the producing node's summary.
 */
export const HEAD_READ_PROVENANCE_FIELDS = [
  { name: "source_observation_id", type: "uuid", nullable: false, note: "the gateway_observations row the fresh head was read from" },
  { name: "observer_id", type: "uuid", nullable: false, note: "the observing domain identity for the head read" },
  { name: "endpoint_fingerprint", type: "sha256_hex", nullable: false, note: "the independently configured endpoint the head was read from" },
  { name: "wallet_seq", type: "bigint_positive", nullable: false, note: "the head row's per-stream sequence" },
  { name: "observed_at", type: "timestamptz", nullable: false, note: "the head read's capture time; never a uniqueness or sequencing key" },
  { name: "head_step_2_signature", type: "padded_base64url_signature", nullable: false, note: "the depth-0 hop identity; must equal hop_chain[0].step_2_signature" },
  { name: "head_completed_transaction_sha256", type: "sha256_hex", nullable: false, note: "the depth-0 hop digest; must equal hop_chain[0].completed_transaction_sha256" },
  { name: "head_body_matches_authoritative_read", type: "boolean", nullable: false, note: "true iff the depth-0 body byte-matched the freshly read authoritative head; false is never a landing proof" },
] as const satisfies readonly FieldSpec[];

/**
 * One hop in the proof chain — a full exact body carried verbatim with its role-relative linkage.
 * Depth 0 is the fresh head; depth increases toward the claimed body. The deepest hop IS the claimed
 * body; its predecessor pointer may be empty (genesis-rooted) or non-empty (a bounded prefix that
 * stops at the claimed body without reaching genesis) — both are valid proofs.
 */
export const MANIFEST_HOP_FIELDS = [
  { name: "depth", type: "integer_nonneg", nullable: false, note: "0 = fresh head; contiguous 0..N toward the claimed body" },
  { name: "wallet_public_key", type: "padded_base64url_pubkey", nullable: false, note: "the role-view wallet stream; constant across a single-path chain" },
  { name: "wallet_role", type: "wallet_observation_role", nullable: false, note: "sender | receiver; constant across a single-path chain" },
  { name: "step_2_signature", type: "padded_base64url_signature", nullable: false, note: "the completing signature; this hop's body identity" },
  { name: "s_signature", type: "padded_base64url_signature", nullable: false, note: "this hop's current state signature; the target its successor's predecessor pointer resolves to" },
  { name: "p_signature", type: "text", nullable: false, note: "role-relative predecessor state signature; must equal the next-deeper hop's s_signature; empty only permitted on the deepest (claimed) hop" },
  { name: "step_1_signature", type: "padded_base64url_signature", nullable: false, note: "the initiating signature" },
  { name: "completed_transaction_text", type: "text", nullable: false, note: "the EXACT signed body, byte-for-byte; never normalized (the byte-exact signing rule)" },
  { name: "completed_transaction_sha256", type: "sha256_hex", nullable: false, note: "SHA-256 of completed_transaction_text; recomputed and byte-compared per hop on re-verification" },
] as const satisfies readonly FieldSpec[];

/** Verification-time semantics the manifest carries and the re-verifier confirms are declared. */
export const VERIFICATION_SEMANTICS_FIELDS = [
  { name: "economic_evaluation_basis", type: "economic_evaluation_basis", nullable: false, note: "must be EXPECTED_BODY_T0; a later-balance basis is rejected" },
  { name: "head_anchored_at_verification_time", type: "boolean", nullable: false, note: "the head read was fresh at verification time; the anchor is contemporaneous" },
  { name: "intermediate_bodies_untrusted_until_verified", type: "boolean", nullable: false, note: "supplied intermediate bodies are untrusted evidence until the re-verifier confirms each" },
  { name: "declared_per_body_predicates", type: "per_body_predicate[]", nullable: false, note: "the frozen predicate classes the producing node evaluated per body; must cover REQUIRED_PER_BODY_PREDICATES" },
] as const satisfies readonly FieldSpec[];

/** The single-path (RECEIVE_EXTERNAL / SEND_EXTERNAL, or one leg of a MOVE) proof-manifest envelope. */
export const SINGLE_PATH_MANIFEST_FIELDS = [
  { name: "manifest_version", type: "text", nullable: false, note: "LANDING_PROOF_MANIFEST_VERSION; an unknown version is rejected" },
  { name: "operation", type: "operation_identity", nullable: false, note: "OPERATION_IDENTITY_FIELDS" },
  { name: "classification", type: "landing_classification", nullable: false, note: "LANDED_EXACT | LANDED_COMPLETE_PATH; must match the chain shape" },
  { name: "claimed_landed", type: "claimed_landed", nullable: false, note: "CLAIMED_LANDED_FIELDS; must equal the deepest hop" },
  { name: "head_read", type: "head_read_provenance", nullable: false, note: "HEAD_READ_PROVENANCE_FIELDS; must equal the depth-0 hop" },
  { name: "hop_chain", type: "manifest_hop[]", nullable: false, note: "MANIFEST_HOP_FIELDS; depth 0 (head) .. depth N (claimed body); length 1 iff LANDED_EXACT" },
  { name: "verification", type: "verification_semantics", nullable: false, note: "VERIFICATION_SEMANTICS_FIELDS" },
] as const satisfies readonly FieldSpec[];

/**
 * The MOVE_INTERNAL dual-path proof-manifest envelope. A MOVE requires two independently complete
 * single-path proofs anchored to the SAME expected move body: the source (sender role-view) and the
 * destination (receiver role-view). Both are re-verified independently and their claimed bodies must
 * share `move_step_2_signature` (the complete-path landing-proof rule).
 */
export const MOVE_PROOF_MANIFEST_FIELDS = [
  { name: "manifest_version", type: "text", nullable: false, note: "LANDING_PROOF_MANIFEST_VERSION" },
  { name: "operation", type: "operation_identity", nullable: false, note: "operation_kind MOVE_INTERNAL" },
  { name: "classification", type: "landing_classification", nullable: false, note: "the weaker of the two paths' classifications is not composed; each path carries its own; the envelope classification is the move's overall verdict basis" },
  { name: "move_step_2_signature", type: "padded_base64url_signature", nullable: false, note: "the shared expected-move completing signature; both paths' claimed bodies carry it" },
  { name: "source_path", type: "single_path_manifest", nullable: false, note: "sender role-view single-path proof; claimed_landed.step_2_signature == move_step_2_signature" },
  { name: "destination_path", type: "single_path_manifest", nullable: false, note: "receiver role-view single-path proof; claimed_landed.step_2_signature == move_step_2_signature" },
  { name: "verification", type: "verification_semantics", nullable: false, note: "VERIFICATION_SEMANTICS_FIELDS; both economic deltas evaluated against expected body T0" },
] as const satisfies readonly FieldSpec[];

/**
 * The closed vocabulary of re-verification failure causes. A manifest re-verifies iff the re-verifier
 * returns NONE of these. These are STRUCTURAL rejections of a supplied manifest — they are not
 * the landing-proof e2e's construction-time INDETERMINATE cause taxonomy, and carry no statement about retry
 * later-attempt, release, or resubmit authority.
 */
export const MANIFEST_REVERIFY_FAILURES = [
  "UNKNOWN_MANIFEST_VERSION",
  "EMPTY_HOP_CHAIN",
  "NON_CONTIGUOUS_DEPTHS",
  "HOP_DIGEST_MISMATCH",
  "BROKEN_BACKLINK",
  "DUPLICATE_OR_CYCLE_HOP",
  "HEAD_ANCHOR_MISMATCH",
  "HEAD_NOT_AUTHORITATIVE",
  "CLAIMED_BODY_NOT_CHAIN_TERMINAL",
  "CLASSIFICATION_MISMATCH",
  "ECONOMIC_BASIS_NOT_EXPECTED_BODY_T0",
  "INCOMPLETE_PER_BODY_PREDICATES",
  "MOVE_PATH_ROLE_MISMATCH",
  "MOVE_ANCHOR_MISMATCH",
] as const;
export type ManifestReverifyFailure = (typeof MANIFEST_REVERIFY_FAILURES)[number];

/**
 * The re-verification verdicts. A clean re-verify maps to the manifest's landing classification, but
 * the `STRUCTURALLY_REVERIFIED_LANDED_*` verdicts assert ONLY that the supplied manifest is
 * STRUCTURALLY sound — every hop body byte-exactly reconstructs and digests, the chain is contiguous /
 * gap-free / duplicate-free / cycle-free, the role-relative backlinks hold, the head anchor and claimed
 * terminal match, and the required per-body predicates are DECLARED. They are deliberately NOT named
 * `REVERIFIED_LANDED_*`: a standalone re-verify CANNOT re-run the real Ed25519 signatures or the
 * operation-artifact / economic predicates (those are attested at construction and re-run by the
 * runtime verification lane), so a clean structural re-verify ALONE is NOT sufficient to conclude a
 * landing. the landing-proof e2e's `classifyLanding` still requires `attestedPredicatesEstablished` on top of a
 * `STRUCTURALLY_REVERIFIED_LANDED_*` verdict before it will return a positive landing; the name makes
 * that boundary impossible to misread (the alternative — a name asserting a completed landing — would
 * be a freeze-time trap the runtime lane could satisfy structurally while the crypto gate is unwired).
 */
export const REVERIFY_VERDICTS = [
  "STRUCTURALLY_REVERIFIED_LANDED_EXACT",
  "STRUCTURALLY_REVERIFIED_LANDED_COMPLETE_PATH",
  "REJECTED",
] as const;
export type ReverifyVerdict = (typeof REVERIFY_VERDICTS)[number];
