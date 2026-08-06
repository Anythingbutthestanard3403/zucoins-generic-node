import { describe, expect, it } from "vitest";

import { LANDING_PROOF_FIXTURES } from "./fixtures.contract.ts";
import {
  ECONOMIC_EVALUATION_BASIS,
  LANDING_PROOF_MANIFEST_VERSION,
  REQUIRED_PER_BODY_PREDICATES,
} from "./proof-manifest.contract.ts";
import {
  GOLDEN_COMPLETE_PATH_MANIFEST,
  GOLDEN_EXACT_MANIFEST,
  GOLDEN_MOVE_MANIFEST,
} from "./proof-manifest.golden.contract.ts";
import {
  reVerifyMoveProofManifest,
  reVerifyProofManifest,
  type ManifestHop,
  type SinglePathProofManifest,
} from "./proof-manifest.ts";

const { B, C } = LANDING_PROOF_FIXTURES;

/** Deep, mutation-safe clone of a manifest so a negative test can tamper with one field. */
const cloneManifest = (m: SinglePathProofManifest): SinglePathProofManifest => ({
  ...m,
  operation: { ...m.operation },
  claimed_landed: { ...m.claimed_landed },
  head_read: { ...m.head_read },
  hop_chain: m.hop_chain.map((h) => ({ ...h })),
  verification: {
    ...m.verification,
    declared_per_body_predicates: [...m.verification.declared_per_body_predicates],
  },
});

describe("the landing-proof manifest builder negative path (one per fact class)", () => {
  it("byte-exactness: a tampered hop body fails re-verification (the byte-exact signing rule)", () => {
    const tampered = cloneManifest(GOLDEN_COMPLETE_PATH_MANIFEST);
    const hops = tampered.hop_chain as ManifestHop[];
    hops[1] = { ...hops[1], completed_transaction_text: `${hops[1].completed_transaction_text} ` };
    const result = reVerifyProofManifest(tampered);
    expect(result.verdict).toBe("REJECTED");
    expect(result.failures).toContain("HOP_DIGEST_MISMATCH");
  });

  it("completeness: a missing interior hop is rejected whole, never partially accepted", () => {
    const gapped = cloneManifest(GOLDEN_COMPLETE_PATH_MANIFEST);
    // Drop the depth-1 hop B, leaving [C(depth 0), A(depth 2)].
    (gapped as { hop_chain: readonly ManifestHop[] }).hop_chain = [
      gapped.hop_chain[0],
      gapped.hop_chain[2],
    ];
    const result = reVerifyProofManifest(gapped);
    expect(result.verdict).toBe("REJECTED");
    expect(result.failures).toContain("BROKEN_BACKLINK");
    expect(result.failures).toContain("NON_CONTIGUOUS_DEPTHS");
    expect(result.verdict).not.toBe("STRUCTURALLY_REVERIFIED_LANDED_COMPLETE_PATH");
  });

  it("claim integrity: a claimed body different from the chain terminal is rejected", () => {
    const wrongClaim: SinglePathProofManifest = {
      ...GOLDEN_COMPLETE_PATH_MANIFEST,
      claimed_landed: {
        ...GOLDEN_COMPLETE_PATH_MANIFEST.claimed_landed,
        step_2_signature: B.step_2_signature,
        completed_transaction_text: B.completed_transaction_text,
        completed_transaction_sha256: B.completed_transaction_sha256,
      },
    };
    const result = reVerifyProofManifest(wrongClaim);
    expect(result.verdict).toBe("REJECTED");
    expect(result.failures).toContain("CLAIMED_BODY_NOT_CHAIN_TERMINAL");
  });

  it("classification: a one-hop chain labelled LANDED_COMPLETE_PATH is rejected", () => {
    const mislabelled: SinglePathProofManifest = {
      ...GOLDEN_EXACT_MANIFEST,
      classification: "LANDED_COMPLETE_PATH",
    };
    const result = reVerifyProofManifest(mislabelled);
    expect(result.verdict).toBe("REJECTED");
    expect(result.failures).toContain("CLASSIFICATION_MISMATCH");
  });

  it("head anchor: a head-read pointing at a body other than depth-0 is rejected", () => {
    const wrongHead: SinglePathProofManifest = {
      ...GOLDEN_COMPLETE_PATH_MANIFEST,
      head_read: {
        ...GOLDEN_COMPLETE_PATH_MANIFEST.head_read,
        head_step_2_signature: B.step_2_signature,
      },
    };
    const result = reVerifyProofManifest(wrongHead);
    expect(result.verdict).toBe("REJECTED");
    expect(result.failures).toContain("HEAD_ANCHOR_MISMATCH");
  });

  it("authoritative read: a manifest whose head did not match the fresh read is rejected", () => {
    const notAuthoritative: SinglePathProofManifest = {
      ...GOLDEN_COMPLETE_PATH_MANIFEST,
      head_read: {
        ...GOLDEN_COMPLETE_PATH_MANIFEST.head_read,
        head_body_matches_authoritative_read: false,
      },
    };
    const result = reVerifyProofManifest(notAuthoritative);
    expect(result.verdict).toBe("REJECTED");
    expect(result.failures).toContain("HEAD_NOT_AUTHORITATIVE");
  });

  it("verification-time semantics: a later-balance economic basis is rejected", () => {
    const laterBalance: SinglePathProofManifest = {
      ...GOLDEN_COMPLETE_PATH_MANIFEST,
      verification: {
        ...GOLDEN_COMPLETE_PATH_MANIFEST.verification,
        economic_evaluation_basis: "LATER_BALANCE",
      },
    };
    expect(laterBalance.verification.economic_evaluation_basis).not.toBe(ECONOMIC_EVALUATION_BASIS);
    const result = reVerifyProofManifest(laterBalance);
    expect(result.verdict).toBe("REJECTED");
    expect(result.failures).toContain("ECONOMIC_BASIS_NOT_EXPECTED_BODY_T0");
  });

  it("declared predicates: dropping a required per-body predicate class is rejected", () => {
    const missingEconomic: SinglePathProofManifest = {
      ...GOLDEN_COMPLETE_PATH_MANIFEST,
      verification: {
        ...GOLDEN_COMPLETE_PATH_MANIFEST.verification,
        declared_per_body_predicates: REQUIRED_PER_BODY_PREDICATES.filter((p) => p !== "ECONOMIC"),
      },
    };
    const result = reVerifyProofManifest(missingEconomic);
    expect(result.verdict).toBe("REJECTED");
    expect(result.failures).toContain("INCOMPLETE_PER_BODY_PREDICATES");
  });

  it("version: an unknown manifest version is rejected", () => {
    const wrongVersion = cloneManifest(GOLDEN_EXACT_MANIFEST);
    (wrongVersion as { manifest_version: string }).manifest_version = "landing-proof-manifest/v0";
    expect(wrongVersion.manifest_version).not.toBe(LANDING_PROOF_MANIFEST_VERSION);
    const result = reVerifyProofManifest(wrongVersion);
    expect(result.verdict).toBe("REJECTED");
    expect(result.failures).toContain("UNKNOWN_MANIFEST_VERSION");
  });

  it("MOVE dual-path: a role mismatch or a mismatched shared anchor is rejected", () => {
    const swappedRoles = {
      ...GOLDEN_MOVE_MANIFEST,
      source_path: GOLDEN_MOVE_MANIFEST.destination_path,
      destination_path: GOLDEN_MOVE_MANIFEST.source_path,
    };
    const roleResult = reVerifyMoveProofManifest(swappedRoles);
    expect(roleResult.verdict).toBe("REJECTED");
    expect(roleResult.failures).toContain("MOVE_PATH_ROLE_MISMATCH");

    const wrongAnchor = { ...GOLDEN_MOVE_MANIFEST, move_step_2_signature: C.step_2_signature };
    const anchorResult = reVerifyMoveProofManifest(wrongAnchor);
    expect(anchorResult.verdict).toBe("REJECTED");
    expect(anchorResult.failures).toContain("MOVE_ANCHOR_MISMATCH");
  });

  it("duplicate / cycle: a repeated hop is rejected", () => {
    const cyclic = cloneManifest(GOLDEN_COMPLETE_PATH_MANIFEST);
    (cyclic as { hop_chain: readonly ManifestHop[] }).hop_chain = [
      cyclic.hop_chain[0],
      cyclic.hop_chain[1],
      { ...cyclic.hop_chain[1], depth: 2 },
    ];
    const result = reVerifyProofManifest(cyclic);
    expect(result.verdict).toBe("REJECTED");
    expect(result.failures).toContain("DUPLICATE_OR_CYCLE_HOP");
  });
});
