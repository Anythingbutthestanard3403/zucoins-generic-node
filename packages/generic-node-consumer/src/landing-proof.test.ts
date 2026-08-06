/**
 * `deriveLandingProof` unit contract (closed `indeterminate_reason` vocabulary).
 *
 * Every branch here mutates exactly one thing away from a valid `EXPECTED_AT_HEAD` fixture and
 * asserts a fail-closed `ok: false` with the specific `LandingProofDerivationFailure` reason —
 * proving the function never fabricates `landing_proof` from partial or contradicted evidence,
 * and that the one field genuinely independent of the node's own claim (the
 * cross-check against `independentHead.projection.S`) is actually load-bearing.
 */

import { describe, expect, it } from "vitest";

import {
  computePathManifestSha256,
  transactionBodySha256,
} from "@zucoins/node-core/observation";

import { deriveLandingProof, type IndependentHeadForRole } from "./landing-proof.js";
import type { VerificationMaterialAncestorProof } from "./types.js";

const SETTLED_TEXT = '{"kind":"receive","step_2_signature":"sig-head","amount":"2.25"}';
const TX_SHA256 = transactionBodySha256(SETTLED_TEXT);

function validAncestorProof(): VerificationMaterialAncestorProof {
  const path_manifest = [
    {
      position: 0,
      step_2_signature: "sig-head",
      queried_wallet_previous_signature: "",
      transaction_sha256: TX_SHA256,
      body_index: 0,
    },
  ];
  return {
    evidence_role: "RECEIVER",
    wallet_public_key: "receiver-pubkey",
    classification: "EXPECTED_AT_HEAD",
    expected_step_2_signature: "sig-head",
    fresh_head_step_2_signature: "sig-head",
    fresh_head_transaction_sha256: TX_SHA256,
    hop_count: 0,
    path_manifest_sha256: computePathManifestSha256(path_manifest),
    path_manifest,
    transaction_bodies: [{ body_index: 0, transaction_sha256: TX_SHA256, settled_transaction_text: SETTLED_TEXT }],
    indeterminate_reason: null,
  };
}

function validIndependentHead(): IndependentHeadForRole {
  return {
    projection: { role: "receiver", S: "sig-head", P: "", B: "2.25", I: null },
    completedTransactionSha256: TX_SHA256,
  };
}

describe("deriveLandingProof — success", () => {
  it("derives a wire-shaped landing_proof matching the server's .strict() field set exactly", () => {
    const result = deriveLandingProof({
      ancestorProof: validAncestorProof(),
      independentHead: validIndependentHead(),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(Object.keys(result.landingProof).sort()).toEqual(
      ["classification", "fresh_head_step_2_signature", "fresh_head_transaction_sha256", "path_manifest_sha256"].sort(),
    );
    expect(result.landingProof).toEqual({
      classification: "EXPECTED_AT_HEAD",
      fresh_head_step_2_signature: "sig-head",
      fresh_head_transaction_sha256: TX_SHA256,
      path_manifest_sha256: computePathManifestSha256(validAncestorProof().path_manifest),
    });
  });

  it("reports the independently-derived signature, not the ancestor proof's own claim", () => {
    // Both agree in the happy path — this only proves which source actually wins by
    // constructing an ancestor proof whose claim differs from a still-consistent structural
    // manifest, then checking the mismatch is caught (see "signature mismatch" below). This
    // test documents the field source explicitly: independentHead.projection.S.
    const independentHead = validIndependentHead();
    const result = deriveLandingProof({ ancestorProof: validAncestorProof(), independentHead });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.landingProof.fresh_head_step_2_signature).toBe(independentHead.projection.S);
  });
});

describe("deriveLandingProof — negative mutations (fail closed, never fabricate)", () => {
  it("no_ancestor_proof_for_role: node never supplied ancestor evidence for this wallet", () => {
    const result = deriveLandingProof({ ancestorProof: undefined, independentHead: validIndependentHead() });
    expect(result).toEqual({ ok: false, reason: "no_ancestor_proof_for_role" });
  });

  it("no_independent_head_for_role: no independently-verified head exists (e.g. non-VERIFIED verdict)", () => {
    const result = deriveLandingProof({ ancestorProof: validAncestorProof(), independentHead: undefined });
    expect(result).toEqual({ ok: false, reason: "no_independent_head_for_role" });
  });

  it("ancestor_proof_indeterminate: server-labeled INDETERMINATE confers zero landing authority", () => {
    const ancestorProof: VerificationMaterialAncestorProof = {
      ...validAncestorProof(),
      classification: "INDETERMINATE",
      indeterminate_reason: "FRESH_HEAD_MISMATCH",
    };
    const result = deriveLandingProof({ ancestorProof, independentHead: validIndependentHead() });
    expect(result).toEqual({ ok: false, reason: "ancestor_proof_indeterminate" });
  });

  it("ancestor_proof_structurally_invalid: missing body referenced by path_manifest", () => {
    const ancestorProof: VerificationMaterialAncestorProof = {
      ...validAncestorProof(),
      transaction_bodies: [],
    };
    const result = deriveLandingProof({ ancestorProof, independentHead: validIndependentHead() });
    expect(result).toEqual({ ok: false, reason: "ancestor_proof_structurally_invalid" });
  });

  it("ancestor_proof_structurally_invalid: link gap (position/predecessor mismatch)", () => {
    const base = validAncestorProof();
    const path_manifest = [
      { ...base.path_manifest[0]!, position: 1 }, // wrong position for a length-1 chain
    ];
    const ancestorProof: VerificationMaterialAncestorProof = { ...base, path_manifest };
    const result = deriveLandingProof({ ancestorProof, independentHead: validIndependentHead() });
    expect(result).toEqual({ ok: false, reason: "ancestor_proof_structurally_invalid" });
  });

  it("ancestor_proof_structurally_invalid: body text digest doesn't match its own claimed sha256", () => {
    const base = validAncestorProof();
    const ancestorProof: VerificationMaterialAncestorProof = {
      ...base,
      transaction_bodies: [
        { body_index: 0, transaction_sha256: TX_SHA256, settled_transaction_text: "tampered-body-text" },
      ],
    };
    const result = deriveLandingProof({ ancestorProof, independentHead: validIndependentHead() });
    expect(result).toEqual({ ok: false, reason: "ancestor_proof_structurally_invalid" });
  });

  it("ancestor_proof_structurally_invalid: manifest tail disagrees with the proof's own claimed fresh head", () => {
    const base = validAncestorProof();
    const ancestorProof: VerificationMaterialAncestorProof = {
      ...base,
      fresh_head_transaction_sha256: "f".repeat(64), // no longer matches manifest[last].transaction_sha256
    };
    const result = deriveLandingProof({ ancestorProof, independentHead: validIndependentHead() });
    expect(result).toEqual({ ok: false, reason: "ancestor_proof_structurally_invalid" });
  });

  it("fresh_head_signature_mismatch: structurally clean but the node's claimed head diverges from the independently-verified one — a lying node must never win", () => {
    const ancestorProof = validAncestorProof(); // internally self-consistent, still claims sig-head
    const independentHead: IndependentHeadForRole = {
      ...validIndependentHead(),
      projection: { role: "receiver", S: "sig-different-head-node-never-saw", P: "", B: "2.25", I: null },
    };
    const result = deriveLandingProof({ ancestorProof, independentHead });
    expect(result).toEqual({ ok: false, reason: "fresh_head_signature_mismatch" });
  });

  it("fresh_head_transaction_sha256_mismatch: valid head SIGNATURE paired with a forged, self-consistent BODY must never be vouched (false-accept guard)", () => {
    // Attack shape: a malicious node knows the genuine head signature (it is public) and pairs
    // it with a forged transaction body X = sha256(craftedText), then rebuilds its own
    // path_manifest/transaction_bodies so the forged body is internally self-consistent with
    // that forged digest. Every structural check and the signature cross-check both pass —
    // this is the only check that must still catch it.
    const forgedText = '{"kind":"receive","step_2_signature":"sig-head","amount":"999999.00"}';
    const forgedSha256 = transactionBodySha256(forgedText);
    const path_manifest = [
      {
        position: 0,
        step_2_signature: "sig-head",
        queried_wallet_previous_signature: "",
        transaction_sha256: forgedSha256,
        body_index: 0,
      },
    ];
    const ancestorProof: VerificationMaterialAncestorProof = {
      ...validAncestorProof(),
      fresh_head_transaction_sha256: forgedSha256,
      path_manifest,
      path_manifest_sha256: computePathManifestSha256(path_manifest),
      transaction_bodies: [{ body_index: 0, transaction_sha256: forgedSha256, settled_transaction_text: forgedText }],
    };
    // independentHead is untouched — it is still this SDK's own independently-verified digest
    // for the REAL settled transaction, and the genuine head signature still matches.
    const result = deriveLandingProof({ ancestorProof, independentHead: validIndependentHead() });
    expect(result).toEqual({ ok: false, reason: "fresh_head_transaction_sha256_mismatch" });
  });

  it("honest matching case still passes and emits the independently-verified digest, not the node's echoed claim", () => {
    const result = deriveLandingProof({ ancestorProof: validAncestorProof(), independentHead: validIndependentHead() });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.landingProof.fresh_head_transaction_sha256).toBe(validIndependentHead().completedTransactionSha256);
  });

  it("path_manifest_digest_mismatch: wire-supplied digest doesn't match a re-derivation from path_manifest", () => {
    const ancestorProof: VerificationMaterialAncestorProof = {
      ...validAncestorProof(),
      path_manifest_sha256: "0".repeat(64),
    };
    const result = deriveLandingProof({ ancestorProof, independentHead: validIndependentHead() });
    expect(result).toEqual({ ok: false, reason: "path_manifest_digest_mismatch" });
  });

  it("classification EXPECTED_ANCESTOR is accepted the same as EXPECTED_AT_HEAD (only INDETERMINATE is rejected)", () => {
    const genesisText = "genesis-text";
    const genesisSha256 = transactionBodySha256(genesisText);
    const genesis = {
      position: 0,
      step_2_signature: "sig-genesis",
      queried_wallet_previous_signature: "",
      transaction_sha256: genesisSha256,
      body_index: 0,
    };
    const head = {
      position: 1,
      step_2_signature: "sig-head",
      queried_wallet_previous_signature: "sig-genesis",
      transaction_sha256: TX_SHA256,
      body_index: 1,
    };
    const path_manifest = [genesis, head];
    const ancestorProof: VerificationMaterialAncestorProof = {
      ...validAncestorProof(),
      classification: "EXPECTED_ANCESTOR",
      hop_count: 1,
      path_manifest,
      path_manifest_sha256: computePathManifestSha256(path_manifest),
      transaction_bodies: [
        { body_index: 0, transaction_sha256: genesisSha256, settled_transaction_text: genesisText },
        { body_index: 1, transaction_sha256: TX_SHA256, settled_transaction_text: SETTLED_TEXT },
      ],
    };
    const result = deriveLandingProof({ ancestorProof, independentHead: validIndependentHead() });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.landingProof.classification).toBe("EXPECTED_ANCESTOR");
  });
});
