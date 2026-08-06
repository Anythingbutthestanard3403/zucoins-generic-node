/**
 * Independent `wallet_evidence[].landing_proof` derivation. The server's
 * `.strict()` `WalletEvidence` schema requires `landing_proof` on every entry, and it must
 * never be echoed from the node's own `ancestor_proofs` claim without independent
 * cross-verification: the consumer supplies the digest and final signature only
 * after independently reading and validating a fresh gateway head and verifying every
 * manifest hop.
 *
 * Two things anchor "independent" here, both reused rather than reimplemented:
 *   - `assessAncestorProofCompleteness` is the exact structural re-verifier the server itself
 *     runs over `path_manifest`/`transaction_bodies` (byte-exact body-hash checks, gap-free
 *     backlinks, fresh-head-anchored terminal) — the SDK and the server can never silently
 *     drift on what "structurally valid" means.
 *   - The manifest's claimed `fresh_head_step_2_signature` is cross-checked against this
 *     pipeline's OWN gateway-verified head signature (`OperationProofVerdict.projection.S` /
 *     `.secondaryProjection.S`, from `verifyOperationIndependently`, never node-relayed). A
 *     valid Ed25519 signature only ever verifies over the exact bytes it was produced for, so
 *     this equality is what makes the rest of the manifest trustworthy — not the node's label.
 *   - The manifest's claimed `fresh_head_transaction_sha256` is cross-checked against this
 *     pipeline's OWN independently-verified digest (`independentHead.completedTransactionSha256`,
 *     from `verdict.completedTransactionSha256`/`secondaryCompletedTransactionSha256`). A genuine
 *     head *signature* proves only that the node once produced signed bytes for the wallet — it
 *     says nothing about which transaction body those bytes belong to. Without this check a node
 *     could pair a real head signature with a forged, self-consistent transaction body and the
 *     signature-only check above would still pass — accepting a server-vouched body on
 *     signature evidence alone is exactly the false-accept this digest check closes. The
 *     digest this function emits is always the independently-verified one, never the node's own
 *     echoed claim.
 *   - `path_manifest_sha256` is re-derived with `computePathManifestSha256`, the same digest
 *     function the server uses, instead of copying the wire-supplied value (the wire value
 *     always matches what a consumer re-derives from the returned path_manifest array).
 *
 * Fails closed: any structural defect, any signature-anchor mismatch, or a missing
 * ancestor-proof/independent-head for a role never fabricates a `landing_proof` — it reports a
 * derivation failure so the caller can refuse to submit rather than blind-retry.
 */

import {
  assessAncestorProofCompleteness,
  computePathManifestSha256,
} from "@zucoins/node-core/observation";
import type { WalletStateProjection } from "@zucoins/node-core";

import type { LandingProofWire, VerificationMaterialAncestorProof } from "./types.js";

export interface IndependentHeadForRole {
  /** This SDK's own gateway-verified projection for the role's wallet (never node-relayed). */
  readonly projection: WalletStateProjection;
  readonly completedTransactionSha256: string;
}

export const LANDING_PROOF_DERIVATION_FAILURES = [
  "no_ancestor_proof_for_role",
  "no_independent_head_for_role",
  "ancestor_proof_indeterminate",
  "ancestor_proof_structurally_invalid",
  "fresh_head_signature_mismatch",
  "fresh_head_transaction_sha256_mismatch",
  "path_manifest_digest_mismatch",
] as const;
export type LandingProofDerivationFailure = (typeof LANDING_PROOF_DERIVATION_FAILURES)[number];

export type LandingProofDerivationResult =
  | { readonly ok: true; readonly landingProof: LandingProofWire }
  | { readonly ok: false; readonly reason: LandingProofDerivationFailure };

/**
 * Derive one wallet's `landing_proof` from the node-supplied ancestor proof plus this
 * pipeline's own independently-verified head for the same wallet. Never trusts the ancestor
 * proof's own `fresh_head_*` claim on its own — only a match against `independentHead` earns
 * it a place in the outgoing request.
 */
export function deriveLandingProof(input: {
  readonly ancestorProof: VerificationMaterialAncestorProof | undefined;
  readonly independentHead: IndependentHeadForRole | undefined;
}): LandingProofDerivationResult {
  const { ancestorProof, independentHead } = input;

  if (ancestorProof === undefined) {
    return { ok: false, reason: "no_ancestor_proof_for_role" };
  }
  if (independentHead === undefined) {
    return { ok: false, reason: "no_independent_head_for_role" };
  }
  if (ancestorProof.classification !== "EXPECTED_AT_HEAD" && ancestorProof.classification !== "EXPECTED_ANCESTOR") {
    // Server-labeled INDETERMINATE confers zero landing authority, and no wire
    // classification exists to report it as.
    return { ok: false, reason: "ancestor_proof_indeterminate" };
  }

  const completeness = assessAncestorProofCompleteness({
    evidence_role: ancestorProof.evidence_role,
    wallet_public_key: ancestorProof.wallet_public_key,
    classification: ancestorProof.classification,
    expected_step_2_signature: ancestorProof.expected_step_2_signature,
    fresh_head_step_2_signature: ancestorProof.fresh_head_step_2_signature,
    fresh_head_transaction_sha256: ancestorProof.fresh_head_transaction_sha256,
    path_manifest: ancestorProof.path_manifest,
    transaction_bodies: ancestorProof.transaction_bodies,
    // Unread by assessAncestorProofCompleteness (it only inspects path_manifest /
    // transaction_bodies / fresh_head_*); classification is already gated above.
    indeterminate_reason: null,
  });
  if (completeness.missingBody || completeness.linkGap || completeness.anomaly || completeness.freshHeadMismatch) {
    return { ok: false, reason: "ancestor_proof_structurally_invalid" };
  }

  if (independentHead.projection.S !== ancestorProof.fresh_head_step_2_signature) {
    return { ok: false, reason: "fresh_head_signature_mismatch" };
  }

  // A genuine head signature only proves the node once signed *some* bytes for this wallet —
  // it says nothing about which transaction body those bytes belong to. A node can pair a real
  // `fresh_head_step_2_signature` with a forged, self-consistent `fresh_head_transaction_sha256`
  // and every check above still passes. This is the only check that catches that: it requires
  // the node's claimed head digest to equal this pipeline's OWN independently-verified digest.
  if (independentHead.completedTransactionSha256 !== ancestorProof.fresh_head_transaction_sha256) {
    return { ok: false, reason: "fresh_head_transaction_sha256_mismatch" };
  }

  const derivedPathManifestSha256 = computePathManifestSha256(ancestorProof.path_manifest);
  if (derivedPathManifestSha256 !== ancestorProof.path_manifest_sha256) {
    return { ok: false, reason: "path_manifest_digest_mismatch" };
  }

  return {
    ok: true,
    landingProof: {
      classification: ancestorProof.classification,
      fresh_head_step_2_signature: independentHead.projection.S,
      // Independently-verified digest, never the node's own echoed claim (see check above).
      fresh_head_transaction_sha256: independentHead.completedTransactionSha256,
      path_manifest_sha256: derivedPathManifestSha256,
    },
  };
}
