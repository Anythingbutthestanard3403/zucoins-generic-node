import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { type GatewayObservationRecord } from "../observation/record-verifier.ts";
import {
  LANDING_PROOF_FIXTURES,
  WALLET_W,
  WALK_COMPLETENESS,
  WALK_STEP_BUDGET_DEFAULT,
  type AncestryIndex,
  type AncestryIndexEntry,
  buildAncestryIndex,
  bodyDigestMatches,
  collisionOnPath,
  depthOfBody,
  entryFromRecord,
  isIndexableRecord,
  linksToPredecessor,
  walkAncestry,
} from "./index.ts";

const HEX64 = "a".repeat(64);
const sha256hex = (t: string): string => createHash("sha256").update(t, "utf8").digest("hex");

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

/** A valid, completely-verified VERIFIED_HEAD gateway_observations row built around a fixture. */
const headRecord = (
  f: HeadFixture,
  overrides: Partial<GatewayObservationRecord> = {},
): GatewayObservationRecord => ({
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
  ...overrides,
});

const { A, B, C, T_SENDER, T_RECEIVER, A_NORMALIZED } = LANDING_PROOF_FIXTURES;

describe("the landing-proof index/walk byte-exact anchor (the byte-exact signing rule)", () => {
  it("every frozen body digest is the real SHA-256 of its verbatim text", () => {
    for (const f of [A, B, C, T_SENDER, T_RECEIVER]) {
      expect(sha256hex(f.completed_transaction_text)).toBe(f.completed_transaction_sha256);
    }
    // The normalized body's actual digest differs from stored original A's digest.
    expect(sha256hex(A_NORMALIZED.completed_transaction_text)).toBe(A_NORMALIZED.actual_sha256);
    expect(A_NORMALIZED.actual_sha256).not.toBe(A_NORMALIZED.stored_sha256_of_original_A);
  });
});

describe("the landing-proof index/walk indexability (only verified head full bodies)", () => {
  it("a verified head with a complete body is indexable", () => {
    expect(isIndexableRecord(headRecord(A))).toBe(true);
    expect(entryFromRecord(headRecord(A))?.step_2_signature).toBe(A.step_2_signature);
  });

  it("a non-verified / non-head disposition is never indexable", () => {
    const nonVerified = headRecord(A, {
      parse_result: "TRANSPORT_ERROR",
      relationship: "NOT_APPLICABLE",
      semantic_fingerprint: null,
      state_changed: null,
      wallet_role: null,
      s_signature: null,
      p_signature: null,
      b_amount: null,
      inner_preimage_text: null,
      step_1_signature: null,
      step_2_signature: null,
      completed_transaction_text: null,
      completed_transaction_sha256: null,
    });
    expect(isIndexableRecord(nonVerified)).toBe(false);
    expect(entryFromRecord(nonVerified)).toBeNull();
  });
});

describe("the landing-proof index/walk any-depth ancestry walk (depth 0/1/N)", () => {
  it("the fresh head is depth 0 and a genesis-rooted single body is a complete path", () => {
    const { index } = buildAncestryIndex([headRecord(A)]);
    const walk = walkAncestry(index, WALLET_W, A.step_2_signature);
    expect(walk.outcome).toBe("COMPLETE_CONTIGUOUS");
    expect(walk.chain.map((s) => s.depth)).toEqual([0]);
    expect(depthOfBody(walk, A.step_2_signature)).toBe(0);
  });

  it("walks the buried transaction to depth 1 and to depth 2 (N > 1)", () => {
    const { index } = buildAncestryIndex([headRecord(A), headRecord(B), headRecord(C)]);
    const walk = walkAncestry(index, WALLET_W, C.step_2_signature);
    expect(walk.outcome).toBe("COMPLETE_CONTIGUOUS");
    // C at depth 0 (fresh head), B at depth 1, A at depth 2 (rooted at genesis).
    expect(depthOfBody(walk, C.step_2_signature)).toBe(0);
    expect(depthOfBody(walk, B.step_2_signature)).toBe(1);
    expect(depthOfBody(walk, A.step_2_signature)).toBe(2);
    expect(walk.chain.map((s) => s.entry.step_2_signature)).toEqual([
      C.step_2_signature,
      B.step_2_signature,
      A.step_2_signature,
    ]);
  });

  //  / UP-08: true-cost reproduction + canon minimum. Without a terminal bound
  // index of only [B, C] is MISSING_HOP (B's p is not genesis and A is absent). With the
  // expected body as terminal, the same index is COMPLETE_CONTIGUOUS — matching node-core
  // walkAncestryPath and the canonical minimum expected→head prefix.
  it("bounded expected→head prefix (non-genesis terminal) is COMPLETE_CONTIGUOUS", () => {
    const { index } = buildAncestryIndex([headRecord(C), headRecord(B)]);
    const unbound = walkAncestry(index, WALLET_W, C.step_2_signature);
    expect(unbound.outcome).toBe("INCOMPLETE_MISSING_HOP");

    const bounded = walkAncestry(index, WALLET_W, C.step_2_signature, {
      terminalStepTwoSig: B.step_2_signature,
    });
    expect(bounded.outcome).toBe("COMPLETE_CONTIGUOUS");
    expect(bounded.chain.map((s) => s.entry.step_2_signature)).toEqual([
      C.step_2_signature,
      B.step_2_signature,
    ]);
    expect(depthOfBody(bounded, B.step_2_signature)).toBe(1);
    expect(depthOfBody(bounded, A.step_2_signature)).toBeNull();
  });

  it("exact-head terminal (expected body IS the fresh head) is COMPLETE at depth 0", () => {
    const { index } = buildAncestryIndex([headRecord(C), headRecord(B)]);
    const walk = walkAncestry(index, WALLET_W, C.step_2_signature, {
      terminalStepTwoSig: C.step_2_signature,
    });
    expect(walk.outcome).toBe("COMPLETE_CONTIGUOUS");
    expect(walk.chain).toHaveLength(1);
    expect(depthOfBody(walk, C.step_2_signature)).toBe(0);
  });

  //  D1: bound terminal absent from a full genesis-rooted index is not COMPLETE
  // at genesis — contract is "genesis only when unbound" (linkage.contract.ts).
  it("bound terminal absent on genesis-rooted chain is INCOMPLETE_MISSING_HOP", () => {
    const { index } = buildAncestryIndex([headRecord(A), headRecord(B), headRecord(C)]);
    const foreign = "step2_sig_foreign_not_on_chain";
    const walk = walkAncestry(index, WALLET_W, C.step_2_signature, {
      terminalStepTwoSig: foreign,
    });
    expect(walk.outcome).toBe("INCOMPLETE_MISSING_HOP");
    expect(walk.chain.map((s) => s.entry.step_2_signature)).toEqual([
      C.step_2_signature,
      B.step_2_signature,
      A.step_2_signature,
    ]);
    expect(depthOfBody(walk, foreign)).toBeNull();
    // Unbound still completes at genesis on the same index.
    expect(walkAncestry(index, WALLET_W, C.step_2_signature).outcome).toBe("COMPLETE_CONTIGUOUS");
  });

  it("the role-relative predecessor links a child to its parent (SUCCESSOR backlink)", () => {
    const { index } = buildAncestryIndex([headRecord(A), headRecord(B)]);
    const entB = index.byKey.get(`${WALLET_W}\n${B.step_2_signature}`);
    const entA = index.byKey.get(`${WALLET_W}\n${A.step_2_signature}`);
    expect(entB && entA && linksToPredecessor(entB, entA)).toBe(true);
  });
});

describe("the landing-proof index/walk MOVE dual path (both wallet role-views indexed)", () => {
  it("one transaction is indexed separately under the sender and receiver keys", () => {
    const { index } = buildAncestryIndex([headRecord(T_SENDER), headRecord(T_RECEIVER)]);
    const sender = index.byKey.get(`${T_SENDER.wallet_public_key}\n${T_SENDER.step_2_signature}`);
    const receiver = index.byKey.get(`${T_RECEIVER.wallet_public_key}\n${T_RECEIVER.step_2_signature}`);
    expect(sender?.wallet_role).toBe("sender");
    expect(receiver?.wallet_role).toBe("receiver");
    // Same body + same step-2 signature, different wallet role-views — not a collision.
    expect(sender?.completed_transaction_text).toBe(receiver?.completed_transaction_text);
    expect(index.collisions).toEqual([]);
  });
});

describe("the landing-proof index/walk idempotent re-observation", () => {
  it("re-observing the byte-identical body under the same key is idempotent, not a collision", () => {
    const { index, ingestLog } = buildAncestryIndex([headRecord(B), headRecord(B)]);
    expect(ingestLog.map((l) => l.outcome)).toEqual(["INDEXED", "IDEMPOTENT"]);
    expect(index.collisions).toEqual([]);
  });
});

describe("the landing-proof index/walk negative path (one per fact class)", () => {
  it("collision: a same-key different-bytes body is surfaced, never merged", () => {
    // A second record keyed under B's (wallet, step-2) but carrying T's exact body (self-consistent
    // digest) — a same-signature-different-bytes collision.
    const conflicting = headRecord(B, {
      completed_transaction_text: T_SENDER.completed_transaction_text,
      completed_transaction_sha256: T_SENDER.completed_transaction_sha256,
    });
    const { index, ingestLog } = buildAncestryIndex([headRecord(B), conflicting]);
    expect(ingestLog.map((l) => l.outcome)).toEqual(["INDEXED", "COLLISION"]);
    expect(index.collisions).toHaveLength(1);
    // Never merged: the original B body is retained unchanged.
    expect(index.byKey.get(`${WALLET_W}\n${B.step_2_signature}`)?.completed_transaction_text).toBe(
      B.completed_transaction_text,
    );
  });

  it("normalized body: a reformatted body whose digest no longer matches is rejected", () => {
    const normalized = headRecord(A, {
      completed_transaction_text: A_NORMALIZED.completed_transaction_text,
      completed_transaction_sha256: A_NORMALIZED.stored_sha256_of_original_A,
    });
    expect(
      bodyDigestMatches({
        completed_transaction_text: A_NORMALIZED.completed_transaction_text,
        completed_transaction_sha256: A_NORMALIZED.stored_sha256_of_original_A,
      }),
    ).toBe(false);
    const { index, ingestLog } = buildAncestryIndex([normalized]);
    expect(ingestLog.map((l) => l.outcome)).toEqual(["REJECTED_DIGEST_MISMATCH"]);
    expect(index.byKey.size).toBe(0);
  });

  it("missing hop: a walk over a chain with an unobserved predecessor is incomplete", () => {
    // Index holds C (head) and B, but not A. Walking from C resolves C -> B, then B's predecessor
    // (A) is absent — the walk is incomplete and confers no landed conclusion.
    const { index } = buildAncestryIndex([headRecord(C), headRecord(B)]);
    const walk = walkAncestry(index, WALLET_W, C.step_2_signature);
    expect(walk.outcome).toBe("INCOMPLETE_MISSING_HOP");
    expect(walk.chain.map((s) => s.entry.step_2_signature)).toEqual([
      C.step_2_signature,
      B.step_2_signature,
    ]);
    expect(depthOfBody(walk, A.step_2_signature)).toBeNull();
  });

  it("ambiguous hop: two entries sharing a state signature stop the walk as ambiguous", () => {
    // A forged sibling of A: a different body whose s_signature collides with A's, so C's chain
    // reaches B whose predecessor state resolves to two distinct bodies.
    const forgedSiblingOfA = headRecord(A, {
      step_2_signature: T_SENDER.step_2_signature,
      completed_transaction_text: T_SENDER.completed_transaction_text,
      completed_transaction_sha256: T_SENDER.completed_transaction_sha256,
    });
    const { index } = buildAncestryIndex([
      headRecord(C),
      headRecord(B),
      headRecord(A),
      forgedSiblingOfA,
    ]);
    const walk = walkAncestry(index, WALLET_W, C.step_2_signature);
    expect(walk.outcome).toBe("INCOMPLETE_AMBIGUOUS_HOP");
  });
});

describe("the landing-proof index/walk termination guards — the walk is total (cycle + budget)", () => {
  // A two-node state-signature cycle: X's predecessor resolves to Y and Y's back to X. Distinct
  // step-2 signatures, distinct state signatures, self-consistent digests — both records pass the observation concern
  // format validation and INDEX as INDEXED, exactly the adversarial input the FAIL PoC used to hang
  // the unguarded walk at 100% CPU.
  const CYCLE_X_BODY = '{"inner":{"seq":"CYCX","t0":"1700000000"}}';
  const CYCLE_Y_BODY = '{"inner":{"seq":"CYCY","t0":"1700000100"}}';
  const CYCLE_X: HeadFixture = {
    wallet_public_key: WALLET_W,
    wallet_role: "receiver",
    s_signature: A.s_signature,
    p_signature: B.s_signature, // X -> Y (Y's state signature)
    step_1_signature: A.step_1_signature,
    step_2_signature: A.step_2_signature,
    completed_transaction_text: CYCLE_X_BODY,
    completed_transaction_sha256: sha256hex(CYCLE_X_BODY),
  };
  const CYCLE_Y: HeadFixture = {
    wallet_public_key: WALLET_W,
    wallet_role: "receiver",
    s_signature: B.s_signature,
    p_signature: A.s_signature, // Y -> X (X's state signature): the cycle closes
    step_1_signature: B.step_1_signature,
    step_2_signature: B.step_2_signature,
    completed_transaction_text: CYCLE_Y_BODY,
    completed_transaction_sha256: sha256hex(CYCLE_Y_BODY),
  };
  // A self-loop: one entry whose predecessor pointer resolves to itself.
  const SELF_BODY = '{"inner":{"seq":"SELF","t0":"1700000000"}}';
  const SELF_Z: HeadFixture = {
    wallet_public_key: WALLET_W,
    wallet_role: "receiver",
    s_signature: C.s_signature,
    p_signature: C.s_signature, // Z -> Z
    step_1_signature: C.step_1_signature,
    step_2_signature: C.step_2_signature,
    completed_transaction_text: SELF_BODY,
    completed_transaction_sha256: sha256hex(SELF_BODY),
  };

  /** Assemble an ancestry index directly from entries (no ingest/collision surfacing). */
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

  /** A linear ancestry chain of `length` entries; the deepest is genesis-rooted (p = ""). */
  const linearChain = (length: number): AncestryIndexEntry[] =>
    Array.from({ length }, (_unused, i) => ({
      wallet_public_key: WALLET_W,
      step_2_signature: `budget-step2-${i}`,
      wallet_role: "receiver" as const,
      completed_transaction_text: `{"seq":${i}}`,
      completed_transaction_sha256: "0".repeat(64),
      s_signature: `budget-state-${i}`,
      p_signature: i === length - 1 ? "" : `budget-state-${i + 1}`,
      step_1_signature: `budget-step1-${i}`,
      source_observation_id: `obs-budget-${i}`,
    }));

  it("a two-node state-signature cycle INDEXES then terminates the real walk as INCOMPLETE_CYCLE (no hang)", () => {
    const { index, ingestLog } = buildAncestryIndex([headRecord(CYCLE_X), headRecord(CYCLE_Y)]);
    // The adversarial pair is admitted — this is the exact input that used to hang the walk.
    expect(ingestLog.map((l) => l.outcome)).toEqual(["INDEXED", "INDEXED"]);

    const start = performance.now();
    const walk = walkAncestry(index, WALLET_W, CYCLE_X.step_2_signature);
    const elapsedMs = performance.now() - start;

    expect(walk.outcome).toBe("INCOMPLETE_CYCLE");
    // Wall-clock guard: the guarded walk returns in milliseconds; an unguarded walk never returns.
    expect(elapsedMs).toBeLessThan(1000);
  });

  it("a self-loop terminates the real walk as INCOMPLETE_CYCLE (no hang)", () => {
    const { index, ingestLog } = buildAncestryIndex([headRecord(SELF_Z)]);
    expect(ingestLog.map((l) => l.outcome)).toEqual(["INDEXED"]);

    const start = performance.now();
    const walk = walkAncestry(index, WALLET_W, SELF_Z.step_2_signature);
    const elapsedMs = performance.now() - start;

    expect(walk.outcome).toBe("INCOMPLETE_CYCLE");
    expect(elapsedMs).toBeLessThan(1000);
  });

  it("a chain longer than the step budget terminates as INCOMPLETE_BUDGET_EXHAUSTED", () => {
    const index = directIndex(linearChain(6));
    const walk = walkAncestry(index, WALLET_W, "budget-step2-0", 3);
    expect(walk.outcome).toBe("INCOMPLETE_BUDGET_EXHAUSTED");
    // The returned chain is exactly the bounded prefix (budget hops), never a truncated "complete" path.
    expect(walk.chain).toHaveLength(3);
  });

  it("a genesis-rooted chain exactly at the budget still completes (boundary)", () => {
    const index = directIndex(linearChain(3));
    const walk = walkAncestry(index, WALLET_W, "budget-step2-0", 3);
    expect(walk.outcome).toBe("COMPLETE_CONTIGUOUS");
    expect(walk.chain).toHaveLength(3);
  });

  it("the frozen default step budget is a generous backstop, well beyond any real history depth", () => {
    expect(WALK_STEP_BUDGET_DEFAULT).toBe(1_000_000);
  });

  it("WALK_COMPLETENESS freezes the expected→head terminus, not genesis-required", () => {
    expect(WALK_COMPLETENESS.terminatesAtGenesisRoot).toBe(false);
    expect(WALK_COMPLETENESS.boundedExpectedToHeadPrefixSufficient).toBe(true);
  });
});

describe("the landing-proof index/walk collisionOnPath producer (S1 — a surfaced collision reaches the determination)", () => {
  it("a collision on the CLAIMED HEAD is detected on the resolved COMPLETE_CONTIGUOUS path", () => {
    // A second body under C's (wallet, step-2) key with different bytes: surfaced, never merged. The
    // walk still resolves C -> B -> A as COMPLETE_CONTIGUOUS, but the head key carries a collision.
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
    expect(index.collisions).toHaveLength(1);
    const walk = walkAncestry(index, WALLET_W, C.step_2_signature);
    expect(walk.outcome).toBe("COMPLETE_CONTIGUOUS");
    expect(collisionOnPath(index, walk.chain)).toBe(true);
  });

  it("a clean chain with no collisions is not flagged", () => {
    const { index } = buildAncestryIndex([headRecord(C), headRecord(B), headRecord(A)]);
    const walk = walkAncestry(index, WALLET_W, C.step_2_signature);
    expect(index.collisions).toEqual([]);
    expect(collisionOnPath(index, walk.chain)).toBe(false);
  });

  it("a collision OFF the walked path (a different wallet key) is not flagged", () => {
    const conflictingSender = headRecord(T_SENDER, {
      completed_transaction_text: B.completed_transaction_text,
      completed_transaction_sha256: B.completed_transaction_sha256,
    });
    const { index } = buildAncestryIndex([
      headRecord(C),
      headRecord(B),
      headRecord(A),
      headRecord(T_SENDER),
      conflictingSender,
    ]);
    expect(index.collisions).toHaveLength(1);
    const walk = walkAncestry(index, WALLET_W, C.step_2_signature);
    // The collision is on wallet S's key, which is not on wallet W's resolved chain.
    expect(collisionOnPath(index, walk.chain)).toBe(false);
  });
});
