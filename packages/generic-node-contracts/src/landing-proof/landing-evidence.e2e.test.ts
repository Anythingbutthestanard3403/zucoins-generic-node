/**
 * SOURCE: the complete-path landing-proof rule and the observation-verification spec. the landing-proof e2e —
 * end-to-end proof that the fail-closed determination actually FIRES from a real the landing-proof index/walk index/walk
 * through the frozen `buildLandingEvidence` producer, not just from a hand-supplied evidence bundle.
 *
 * This closes the FAIL's B1 (a cycle / over-budget walk must yield INDETERMINATE, never hang), S1 (a
 * surfaced collision on the claimed head must reach the determination as INDEX_COLLISION), and S2 (a
 * clean STRUCTURAL re-verify ALONE is not sufficient to conclude landed — the attested crypto gate is
 * still required). Every evidence field the classifier consumes is DERIVED here from real upstreams by
 * `buildLandingEvidence`; nothing walk-sourced or index-sourced is hand-set.
 */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { type GatewayObservationRecord } from "../observation/record-verifier.ts";
import {
  type AncestryIndex,
  type AncestryIndexEntry,
  type ManifestHop,
  type MoveProofManifest,
  buildAncestryIndex,
  buildLandingEvidence,
  classifyLanding,
  reVerifyMoveProofManifest,
  walkAncestry,
} from "./index.ts";
import { LANDING_PROOF_FIXTURES, WALLET_S, WALLET_W } from "./fixtures.contract.ts";
import { GOLDEN_MOVE_MANIFEST } from "./proof-manifest.golden.contract.ts";

const HEX64 = "a".repeat(64);
const sha256hex = (t: string): string => createHash("sha256").update(t, "utf8").digest("hex");
const { A, B, C, T_SENDER } = LANDING_PROOF_FIXTURES;

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
const headRecord = (
  f: HeadFixture,
  overrides: Partial<GatewayObservationRecord> = {},
): GatewayObservationRecord => ({
  id: `obs-e2e-${++idSeq}`,
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
  ...overrides,
});

/** Assemble an ancestry index directly from entries (for a linear over-budget chain). */
const directIndex = (entries: readonly AncestryIndexEntry[]): AncestryIndex => {
  const byKey = new Map<string, AncestryIndexEntry>();
  const byState = new Map<string, AncestryIndexEntry[]>();
  for (const entry of entries) {
    byKey.set(`${entry.wallet_public_key}\n${entry.step_2_signature}`, entry);
    const stateKey = `${entry.wallet_public_key}\n${entry.s_signature}`;
    const bucket = byState.get(stateKey);
    if (bucket === undefined) byState.set(stateKey, [entry]);
    else bucket.push(entry);
  }
  return { byKey, byState, collisions: [] };
};

const linearChain = (length: number): AncestryIndexEntry[] =>
  Array.from({ length }, (_unused, i) => ({
    wallet_public_key: WALLET_W,
    step_2_signature: `e2e-step2-${i}`,
    wallet_role: "receiver" as const,
    completed_transaction_text: `{"seq":${i}}`,
    completed_transaction_sha256: "0".repeat(64),
    s_signature: `e2e-state-${i}`,
    p_signature: i === length - 1 ? "" : `e2e-state-${i + 1}`,
    step_1_signature: `e2e-step1-${i}`,
    source_observation_id: `obs-e2e-lin-${i}`,
  }));

// A two-node state-signature cycle (X <-> Y), each a valid indexable head.
const CYCLE_X: HeadFixture = {
  wallet_public_key: WALLET_W,
  wallet_role: "receiver",
  s_signature: A.s_signature,
  p_signature: B.s_signature,
  step_1_signature: A.step_1_signature,
  step_2_signature: A.step_2_signature,
  completed_transaction_text: '{"inner":{"seq":"EX","t0":"1700000000"}}',
  completed_transaction_sha256: sha256hex('{"inner":{"seq":"EX","t0":"1700000000"}}'),
};
const CYCLE_Y: HeadFixture = {
  wallet_public_key: WALLET_W,
  wallet_role: "receiver",
  s_signature: B.s_signature,
  p_signature: A.s_signature,
  step_1_signature: B.step_1_signature,
  step_2_signature: B.step_2_signature,
  completed_transaction_text: '{"inner":{"seq":"EY","t0":"1700000100"}}',
  completed_transaction_sha256: sha256hex('{"inner":{"seq":"EY","t0":"1700000100"}}'),
};

describe("the landing-proof e2e end-to-end fail-closed (real index/walk -> buildLandingEvidence -> classifyLanding)", () => {
  it("a cyclic index fails closed to INDETERMINATE / WALK_CYCLE (the phantom-settle hang is closed)", () => {
    const { index } = buildAncestryIndex([headRecord(CYCLE_X), headRecord(CYCLE_Y)]);
    const walk = walkAncestry(index, WALLET_W, CYCLE_X.step_2_signature);
    expect(walk.outcome).toBe("INCOMPLETE_CYCLE");

    const evidence = buildLandingEvidence({
      freshHead: "AUTHORITATIVE",
      invariantAnomaly: false,
      index,
      walk,
      reverify: null,
      attestedPredicatesEstablished: true,
    });
    const result = classifyLanding(evidence);
    expect(result.outcome).toBe("INDETERMINATE");
    expect(result.cause).toBe("WALK_CYCLE");
    expect(result.authority.mayConcludeLanded).toBe(false);
    expect(result.authority.mustHoldLeaseAndAwaitNewObservations).toBe(true);
  });

  it("an over-budget walk fails closed to INDETERMINATE / WORK_BUDGET_EXHAUSTED", () => {
    const index = directIndex(linearChain(6));
    const walk = walkAncestry(index, WALLET_W, "e2e-step2-0", 3);
    expect(walk.outcome).toBe("INCOMPLETE_BUDGET_EXHAUSTED");

    const evidence = buildLandingEvidence({
      freshHead: "AUTHORITATIVE",
      invariantAnomaly: false,
      index,
      walk,
      reverify: null,
      attestedPredicatesEstablished: true,
    });
    const result = classifyLanding(evidence);
    expect(result.outcome).toBe("INDETERMINATE");
    expect(result.cause).toBe("WORK_BUDGET_EXHAUSTED");
  });

  it("a collision on the claimed head fails closed to INDETERMINATE / INDEX_COLLISION, never LANDED (S1)", () => {
    const conflictingHead = headRecord(C, {
      completed_transaction_text: T_SENDER.completed_transaction_text,
      completed_transaction_sha256: T_SENDER.completed_transaction_sha256,
    });
    const { index } = buildAncestryIndex([
      headRecord(C),
      conflictingHead,
      headRecord(B),
      headRecord(A),
    ]);
    const walk = walkAncestry(index, WALLET_W, C.step_2_signature);
    // The walk alone is COMPLETE_CONTIGUOUS — only the derived collision signal fails it closed.
    expect(walk.outcome).toBe("COMPLETE_CONTIGUOUS");

    const evidence = buildLandingEvidence({
      freshHead: "AUTHORITATIVE",
      invariantAnomaly: false,
      index,
      walk,
      reverify: "STRUCTURALLY_REVERIFIED_LANDED_COMPLETE_PATH",
      attestedPredicatesEstablished: true,
    });
    expect(evidence.indexCollisionOnPath).toBe(true);
    const result = classifyLanding(evidence);
    expect(result.outcome).toBe("INDETERMINATE");
    expect(result.cause).toBe("INDEX_COLLISION");
    expect(result.outcome).not.toBe("LANDED_COMPLETE_PATH");
  });

  describe("a clean complete path", () => {
    const cleanEvidence = (attestedPredicatesEstablished: boolean) => {
      const { index } = buildAncestryIndex([headRecord(C), headRecord(B), headRecord(A)]);
      const walk = walkAncestry(index, WALLET_W, C.step_2_signature);
      expect(walk.outcome).toBe("COMPLETE_CONTIGUOUS");
      return buildLandingEvidence({
        freshHead: "AUTHORITATIVE",
        invariantAnomaly: false,
        index,
        walk,
        reverify: "STRUCTURALLY_REVERIFIED_LANDED_COMPLETE_PATH",
        attestedPredicatesEstablished,
      });
    };

    it("with the attested predicates established re-verifies to LANDED_COMPLETE_PATH (positive control)", () => {
      const result = classifyLanding(cleanEvidence(true));
      expect(result.outcome).toBe("LANDED_COMPLETE_PATH");
      expect(result.cause).toBeNull();
    });

    it("with a clean STRUCTURAL re-verify ALONE (crypto NOT attested) is INDETERMINATE / PREDICATE_UNVERIFIABLE, never landed (S2)", () => {
      const result = classifyLanding(cleanEvidence(false));
      expect(result.outcome).toBe("INDETERMINATE");
      expect(result.cause).toBe("PREDICATE_UNVERIFIABLE");
      expect(result.authority.mayConcludeLanded).toBe(false);
    });
  });

  describe("a MOVE proof manifest with exactly one structurally-broken leg (real reVerifyMoveProofManifest -> buildLandingEvidence -> classifyLanding)", () => {
    // The querying wallet's OWN chain (source/sender role-view) is real and genesis-rooted at depth 0
    // — a COMPLETE_CONTIGUOUS walk in every test below. Only the MOVE manifest's re-verify verdict
    // (computed by the real `reVerifyMoveProofManifest`, never hand-set) differs between them.
    const sourceIndexAndWalk = () => {
      const { index } = buildAncestryIndex([headRecord(T_SENDER)]);
      const walk = walkAncestry(index, WALLET_S, T_SENDER.step_2_signature);
      expect(walk.outcome).toBe("COMPLETE_CONTIGUOUS");
      return { index, walk };
    };

    it("rejects the whole move — never landed — when only the destination leg's hop body is tampered (S4)", () => {
      // Tamper ONLY the destination (receiver-side) leg's sole hop body; the source leg is untouched
      // and remains fully valid on its own.
      const brokenDestinationHop: ManifestHop = {
        ...GOLDEN_MOVE_MANIFEST.destination_path.hop_chain[0],
        completed_transaction_text: `${GOLDEN_MOVE_MANIFEST.destination_path.hop_chain[0].completed_transaction_text} `,
      };
      const brokenMove: MoveProofManifest = {
        ...GOLDEN_MOVE_MANIFEST,
        destination_path: {
          ...GOLDEN_MOVE_MANIFEST.destination_path,
          hop_chain: [brokenDestinationHop],
        },
      };

      const moveResult = reVerifyMoveProofManifest(brokenMove);
      expect(moveResult.verdict).toBe("REJECTED");
      expect(moveResult.failures).toContain("HOP_DIGEST_MISMATCH");
      // The break is purely a per-leg structural defect, not the already-covered role/anchor checks.
      expect(moveResult.failures).not.toContain("MOVE_PATH_ROLE_MISMATCH");
      expect(moveResult.failures).not.toContain("MOVE_ANCHOR_MISMATCH");

      const { index, walk } = sourceIndexAndWalk();
      const evidence = buildLandingEvidence({
        freshHead: "AUTHORITATIVE",
        invariantAnomaly: false,
        index,
        walk,
        reverify: moveResult.verdict,
        attestedPredicatesEstablished: true,
      });
      const result = classifyLanding(evidence);
      expect(result.outcome).toBe("INDETERMINATE");
      expect(result.cause).toBe("REVERIFY_REJECTED");
      expect(result.outcome).not.toBe("LANDED_EXACT");
      expect(result.outcome).not.toBe("LANDED_COMPLETE_PATH");
      expect(result.authority.mayConcludeLanded).toBe(false);
    });

    it("positive control: the same MOVE manifest with the leg repaired classifies LANDED_EXACT end-to-end", () => {
      const moveResult = reVerifyMoveProofManifest(GOLDEN_MOVE_MANIFEST);
      expect(moveResult.verdict).toBe("STRUCTURALLY_REVERIFIED_LANDED_EXACT");
      expect(moveResult.failures).toHaveLength(0);

      const { index, walk } = sourceIndexAndWalk();
      const evidence = buildLandingEvidence({
        freshHead: "AUTHORITATIVE",
        invariantAnomaly: false,
        index,
        walk,
        reverify: moveResult.verdict,
        attestedPredicatesEstablished: true,
      });
      const result = classifyLanding(evidence);
      expect(result.outcome).toBe("LANDED_EXACT");
      expect(result.cause).toBeNull();
    });
  });
});
