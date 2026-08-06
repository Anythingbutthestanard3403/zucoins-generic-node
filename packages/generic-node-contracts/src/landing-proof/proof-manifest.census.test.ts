import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { type GatewayObservationRecord } from "../observation/record-verifier.ts";
import { assertClosedSet } from "../testkit/freeze.ts";
import { buildAncestryIndex, walkAncestry } from "./ancestry-index.ts";
import { LANDING_PROOF_FIXTURES, WALLET_W } from "./fixtures.contract.ts";
import {
  CLAIMED_LANDED_FIELDS,
  DEPTH_SEMANTICS,
  HEAD_READ_PROVENANCE_FIELDS,
  LANDING_CLASSIFICATIONS,
  MANIFEST_HOP_FIELDS,
  MANIFEST_RETENTION,
  MANIFEST_REVERIFY_FAILURES,
  MOVE_PROOF_MANIFEST_FIELDS,
  OPERATION_IDENTITY_FIELDS,
  REQUIRED_PER_BODY_PREDICATES,
  REVERIFICATION_PREDICATE,
  REVERIFY_VERDICTS,
  SINGLE_PATH_MANIFEST_FIELDS,
  VERIFICATION_SEMANTICS_FIELDS,
} from "./proof-manifest.contract.ts";
import {
  GOLDEN_COMPLETE_PATH_MANIFEST,
  GOLDEN_COMPLETE_PATH_PREFIX_MANIFEST,
  GOLDEN_EXACT_MANIFEST,
  GOLDEN_MOVE_MANIFEST,
} from "./proof-manifest.golden.contract.ts";
import {
  buildProofManifest,
  reVerifyMoveProofManifest,
  reVerifyProofManifest,
} from "./proof-manifest.ts";

const sha256hex = (t: string): string => createHash("sha256").update(t, "utf8").digest("hex");
const HEX64 = "a".repeat(64);
const { A, B, C } = LANDING_PROOF_FIXTURES;

interface HeadFixture {
  readonly wallet_public_key: string;
  readonly wallet_role: "sender" | "receiver";
  readonly s_signature: string;
  readonly p_signature: string;
  readonly step_1_signature: string;
  readonly step_2_signature: string;
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
}

let idSeq = 0;
const headRecord = (f: HeadFixture): GatewayObservationRecord => ({
  id: `obs-${++idSeq}`,
  observer_id: "observer-1",
  endpoint_fingerprint: HEX64,
  wallet_id: null,
  wallet_public_key: f.wallet_public_key,
  wallet_seq: 1,
  observed_at: "2026-07-19T00:00:00.000Z",
  http_status: 200,
  raw_response_bytes: new Uint8Array([1, 2, 3]),
  raw_response_sha256: HEX64,
  parse_result: "VERIFIED_HEAD",
  relationship: "SUCCESSOR",
  semantic_fingerprint: HEX64,
  state_changed: true,
  wallet_role: f.wallet_role,
  s_signature: f.s_signature,
  p_signature: f.p_signature,
  b_amount: "10",
  inner_preimage_text: f.completed_transaction_text,
  step_1_signature: f.step_1_signature,
  step_2_signature: f.step_2_signature,
  completed_transaction_text: f.completed_transaction_text,
  completed_transaction_sha256: f.completed_transaction_sha256,
  previous_recorded_observation_id: null,
  created_at: "2026-07-19T00:00:00.000Z",
});

const HEAD_PROVENANCE = {
  source_observation_id: "00000000-0000-4000-8000-00000000head",
  observer_id: "00000000-0000-4000-8000-0000000000ob",
  endpoint_fingerprint: "b".repeat(64),
  wallet_seq: 1,
  observed_at: "2026-07-19T00:00:00.000Z",
  head_body_matches_authoritative_read: true,
} as const;

const namesOf = (fields: readonly { readonly name: string }[]): string[] => fields.map((f) => f.name);

describe("the landing-proof manifest builder frozen vocabulary census", () => {
  it("the two the complete-path landing-proof rule positive landing classifications are a closed set", () => {
    assertClosedSet([...LANDING_CLASSIFICATIONS], ["LANDED_EXACT", "LANDED_COMPLETE_PATH"]);
  });

  it("the required per-body predicate classes match the complete-path landing-proof rule exactly", () => {
    assertClosedSet(
      [...REQUIRED_PER_BODY_PREDICATES],
      ["EXACT_PREIMAGE", "BOTH_SIGNATURES", "ROLE", "BACKLINK", "ECONOMIC"],
    );
  });

  it("the re-verify failure and verdict vocabularies are closed sets", () => {
    expect(new Set(MANIFEST_REVERIFY_FAILURES).size).toBe(MANIFEST_REVERIFY_FAILURES.length);
    assertClosedSet(
      [...REVERIFY_VERDICTS],
      ["STRUCTURALLY_REVERIFIED_LANDED_EXACT", "STRUCTURALLY_REVERIFIED_LANDED_COMPLETE_PATH", "REJECTED"],
    );
  });

  it("depth is unbounded here — no cap, bounded handling deferred to the landing-proof e2e", () => {
    expect(DEPTH_SEMANTICS.headDepth).toBe(0);
    expect(DEPTH_SEMANTICS.depthCap).toBeNull();
    expect(DEPTH_SEMANTICS.unbounded).toBe(true);
    expect(DEPTH_SEMANTICS.boundedOrIncompleteHandlingOwner).toBe("fail-closed-determination");
  });

  it("proof manifests are permanent; the access window governs endpoint exposure only", () => {
    expect(MANIFEST_RETENTION.permanent).toBe(true);
    expect(MANIFEST_RETENTION.expiryRevokesEndpointAccessOnly).toBe(true);
    expect(MANIFEST_RETENTION.canonicalBodiesNeverReserialized).toBe(true);
  });

  it("the re-verification predicate runs from the manifest alone and trusts no producing node", () => {
    expect(REVERIFICATION_PREDICATE.runsFromManifestAlone).toBe(true);
    expect(REVERIFICATION_PREDICATE.trustsProducingNode).toBe(false);
    expect(REVERIFICATION_PREDICATE.partialPrefixNeverAccepted).toBe(true);
  });

  it("the manifest field-spec lists carry their frozen shape", () => {
    expect(namesOf(OPERATION_IDENTITY_FIELDS)).toEqual([
      "operation_id",
      "operation_kind",
      "queried_wallet_public_key",
      "wallet_role",
    ]);
    expect(namesOf(CLAIMED_LANDED_FIELDS)).toContain("completed_transaction_text");
    expect(namesOf(HEAD_READ_PROVENANCE_FIELDS)).toContain("head_body_matches_authoritative_read");
    expect(namesOf(MANIFEST_HOP_FIELDS)).toEqual([
      "depth",
      "wallet_public_key",
      "wallet_role",
      "step_2_signature",
      "s_signature",
      "p_signature",
      "step_1_signature",
      "completed_transaction_text",
      "completed_transaction_sha256",
    ]);
    expect(namesOf(VERIFICATION_SEMANTICS_FIELDS)).toContain("economic_evaluation_basis");
    expect(namesOf(SINGLE_PATH_MANIFEST_FIELDS)).toContain("hop_chain");
    expect(namesOf(MOVE_PROOF_MANIFEST_FIELDS)).toContain("move_step_2_signature");
    for (const list of [
      OPERATION_IDENTITY_FIELDS,
      CLAIMED_LANDED_FIELDS,
      HEAD_READ_PROVENANCE_FIELDS,
      MANIFEST_HOP_FIELDS,
      VERIFICATION_SEMANTICS_FIELDS,
      SINGLE_PATH_MANIFEST_FIELDS,
      MOVE_PROOF_MANIFEST_FIELDS,
    ]) {
      for (const field of list) {
        expect(field.name.length).toBeGreaterThan(0);
        expect(field.note.length).toBeGreaterThan(0);
      }
    }
  });
});

describe("the landing-proof manifest builder golden manifest byte-exact anchor (the byte-exact signing rule)", () => {
  it("every golden hop body digest is the real SHA-256 of its verbatim text", () => {
    const goldens = [
      GOLDEN_COMPLETE_PATH_MANIFEST,
      GOLDEN_COMPLETE_PATH_PREFIX_MANIFEST,
      GOLDEN_EXACT_MANIFEST,
      GOLDEN_MOVE_MANIFEST.source_path,
      GOLDEN_MOVE_MANIFEST.destination_path,
    ];
    for (const g of goldens) {
      for (const hop of g.hop_chain) {
        expect(sha256hex(hop.completed_transaction_text)).toBe(hop.completed_transaction_sha256);
      }
      expect(sha256hex(g.claimed_landed.completed_transaction_text)).toBe(
        g.claimed_landed.completed_transaction_sha256,
      );
    }
  });
});

describe("the landing-proof manifest builder re-verification from the manifest alone (depth 0 / 1 / N)", () => {
  it("a depth-N buried landing re-verifies as LANDED_COMPLETE_PATH", () => {
    const result = reVerifyProofManifest(GOLDEN_COMPLETE_PATH_MANIFEST);
    expect(result.failures).toEqual([]);
    expect(result.verdict).toBe("STRUCTURALLY_REVERIFIED_LANDED_COMPLETE_PATH");
    expect(GOLDEN_COMPLETE_PATH_MANIFEST.hop_chain.map((h) => h.depth)).toEqual([0, 1, 2]);
    expect(GOLDEN_COMPLETE_PATH_MANIFEST.claimed_landed.depth).toBe(2);
  });

  it("a depth-1 bounded prefix re-verifies without reaching genesis", () => {
    const result = reVerifyProofManifest(GOLDEN_COMPLETE_PATH_PREFIX_MANIFEST);
    expect(result.verdict).toBe("STRUCTURALLY_REVERIFIED_LANDED_COMPLETE_PATH");
    const deepest = GOLDEN_COMPLETE_PATH_PREFIX_MANIFEST.hop_chain.at(-1);
    expect(deepest?.p_signature).not.toBe("");
  });

  it("a depth-0 exact landing re-verifies as LANDED_EXACT", () => {
    const result = reVerifyProofManifest(GOLDEN_EXACT_MANIFEST);
    expect(result.verdict).toBe("STRUCTURALLY_REVERIFIED_LANDED_EXACT");
    expect(GOLDEN_EXACT_MANIFEST.hop_chain).toHaveLength(1);
  });

  it("a MOVE dual-path manifest re-verifies both role-views against the shared anchor", () => {
    const result = reVerifyMoveProofManifest(GOLDEN_MOVE_MANIFEST);
    expect(result.failures).toEqual([]);
    expect(result.verdict).toBe("STRUCTURALLY_REVERIFIED_LANDED_EXACT");
    expect(GOLDEN_MOVE_MANIFEST.source_path.operation.wallet_role).toBe("sender");
    expect(GOLDEN_MOVE_MANIFEST.destination_path.operation.wallet_role).toBe("receiver");
  });
});

describe("the landing-proof manifest builder buildProofManifest reproduces the goldens from a real the landing-proof index/walk", () => {
  const { index } = buildAncestryIndex([headRecord(C), headRecord(B), headRecord(A)]);
  const walk = walkAncestry(index, WALLET_W, C.step_2_signature);
  const receiveOp = {
    operation_kind: "RECEIVE_EXTERNAL" as const,
    queried_wallet_public_key: WALLET_W,
    wallet_role: "receiver" as const,
  };

  it("claiming the depth-2 body reproduces the complete-path golden", () => {
    const built = buildProofManifest({
      operation: { ...receiveOp, operation_id: "00000000-0000-4000-8000-00000000recX" },
      walk,
      claimedStepTwoSignature: A.step_2_signature,
      headProvenance: HEAD_PROVENANCE,
    });
    expect(built).toEqual(GOLDEN_COMPLETE_PATH_MANIFEST);
  });

  it("claiming the depth-1 body reproduces the bounded-prefix golden", () => {
    const built = buildProofManifest({
      operation: { ...receiveOp, operation_id: "00000000-0000-4000-8000-00000000recY" },
      walk,
      claimedStepTwoSignature: B.step_2_signature,
      headProvenance: HEAD_PROVENANCE,
    });
    expect(built).toEqual(GOLDEN_COMPLETE_PATH_PREFIX_MANIFEST);
  });

  it("claiming the head reproduces the exact golden", () => {
    const built = buildProofManifest({
      operation: { ...receiveOp, operation_id: "00000000-0000-4000-8000-00000000recZ" },
      walk,
      claimedStepTwoSignature: C.step_2_signature,
      headProvenance: HEAD_PROVENANCE,
    });
    expect(built?.classification).toBe("LANDED_EXACT");
    expect(built).toEqual(GOLDEN_EXACT_MANIFEST);
  });

  it("returns null (no manifest) when the claimed body is absent from the walk", () => {
    const built = buildProofManifest({
      operation: { ...receiveOp, operation_id: "00000000-0000-4000-8000-00000000recX" },
      walk,
      claimedStepTwoSignature: "not-in-any-chain",
      headProvenance: HEAD_PROVENANCE,
    });
    expect(built).toBeNull();
  });
});
