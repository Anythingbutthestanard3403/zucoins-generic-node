// capture write-path tests. The ticket's test-12 (consecutive
// exact-byte dedup), test-13 (append + relationship classification), and test-14 (observer
// independence) map onto golden sequences (1) AA_BYTE_IDENTICAL,
// (3) ABCA_REGRESSION / (2) AA_PRIME_WRAPPER, and (7) two-observer independence, plus property
// (6) contiguous wallet_seq under concurrent capture. Every case feeds the ACTUAL raw bytes and the
// real classifier through planCapture / createSerializedStreamWriter — no mock of the frozen
// primitives.

import { describe, expect, it } from "vitest";

import { type SequenceCapture, type StreamCursor } from "@zucoins/generic-node-contracts/observation";

import {
  createSerializedStreamWriter,
  planCapture,
  type CaptureWriteResult,
  type ObservationStreamKey,
  type StreamWriterEffects,
} from "./capture-writer.js";

const enc = new TextEncoder();

// A verified head capture. Distinct `bytes` give distinct raw responses; `s`/`p`/`fp` drive the
// relationship classifier (backlink = new p equals prior s).
const head = (opts: {
  bytes: string;
  s: string;
  p: string;
  fp: string;
}): SequenceCapture => ({
  parseResult: "VERIFIED_HEAD",
  rawResponseBytes: enc.encode(opts.bytes),
  isGenesis: false,
  sSignature: opts.s,
  pSignature: opts.p,
  semanticFingerprint: opts.fp,
});

// The A,B,C successor chain and the two tail captures for the golden sequences.
const A = head({ bytes: "response-A", s: "sigA", p: "", fp: "fpA" });
const B = head({ bytes: "response-B", s: "sigB", p: "sigA", fp: "fpB" });
const C = head({ bytes: "response-C", s: "sigC", p: "sigB", fp: "fpC" });
// Same head identity as A but a byte-different envelope -> EQUIVALENT_STATE_DIFFERENT_ENVELOPE.
const APrime = head({ bytes: "response-A-with-different-envelope", s: "sigA", p: "", fp: "fpA" });
// Byte-identical to A; non-adjacent recurrence of an older accepted state -> REGRESSION.
const ARegression = head({ bytes: "response-A", s: "sigA", p: "", fp: "fpA" });

// Fold captures through the pure planner threading each result's nextCursor as the next prior.
const chain = (captures: readonly SequenceCapture[]): CaptureWriteResult[] => {
  let prior: StreamCursor | null = null;
  const results: CaptureWriteResult[] = [];
  for (const capture of captures) {
    const result = planCapture(prior, capture);
    results.push(result);
    prior = result.nextCursor;
  }
  return results;
};

describe("capture write-path: dedup / append / classification", () => {
  it("test-12: byte-identical verified A,A appends once and counts the second as a sighting", () => {
    const [first, second] = chain([A, A]);

    expect(first!.plan.kind).toBe("APPEND");
    if (first!.plan.kind === "APPEND") {
      expect(first!.plan.observation.walletSeq).toBe(1);
      expect(first!.plan.observation.relationship).toBe("FIRST");
    }

    // step 7: no new row; the cursor's consecutive_repeat_count advances instead.
    expect(second!.plan.kind).toBe("SUPPRESS_AS_SIGHTING");
    if (second!.plan.kind === "SUPPRESS_AS_SIGHTING") {
      expect(second!.plan.cursor.consecutiveRepeatCount).toBe(1);
    }
    // Exactly one appended row across the two captures.
    expect(second!.nextCursor.rowCount).toBe(1);
    expect(second!.nextCursor.nextWalletSeq).toBe(2);
  });

  it("test-13a: A,B,C,A appends four with the final A a REGRESSION anomaly (fail closed)", () => {
    const results = chain([A, B, C, ARegression]);

    expect(results.map((r) => r.plan.kind)).toEqual(["APPEND", "APPEND", "APPEND", "APPEND"]);
    const walletSeqs = results.map((r) =>
      r.plan.kind === "APPEND" ? r.plan.observation.walletSeq : null,
    );
    expect(walletSeqs).toEqual([1, 2, 3, 4]);

    const relationships = results.map((r) =>
      r.plan.kind === "APPEND" ? r.plan.observation.relationship : null,
    );
    expect(relationships).toEqual(["FIRST", "SUCCESSOR", "SUCCESSOR", "REGRESSION"]);

    const last = results[3]!.plan;
    if (last.kind === "APPEND") {
      // step 9: the anomalous relationship requires an observation_anomalies row.
      expect(last.anomalyRequired).toBe(true);
      expect(last.observation.stateChanged).toBe(true);
    }
  });

  it("test-13b: same head with a byte-different envelope appends twice, second EQUIVALENT", () => {
    const [first, second] = chain([A, APrime]);

    expect(first!.plan.kind).toBe("APPEND");
    expect(second!.plan.kind).toBe("APPEND");
    if (second!.plan.kind === "APPEND") {
      expect(second!.plan.observation.walletSeq).toBe(2);
      expect(second!.plan.observation.relationship).toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
      expect(second!.plan.observation.stateChanged).toBe(false);
      expect(second!.plan.anomalyRequired).toBe(false);
    }
  });
});

// In-memory persistence fake modelling wallet_observation_cursors: loadPrior returns the last
// committed cursor, apply commits nextCursor. `beforeApply` injects async yield / failure.
interface Store {
  readonly effects: StreamWriterEffects;
  readonly appends: Array<{ readonly key: string; readonly walletSeq: number }>;
}

const keyId = (key: ObservationStreamKey): string =>
  JSON.stringify([key.observerId, key.walletPublicKey]);

const makeStore = (beforeApply?: (n: number) => Promise<void>): Store => {
  const cursors = new Map<string, StreamCursor>();
  const appends: Array<{ key: string; walletSeq: number }> = [];
  let applyCount = 0;
  const effects: StreamWriterEffects = {
    loadPrior: async (key) => cursors.get(keyId(key)) ?? null,
    apply: async (key, result) => {
      applyCount += 1;
      if (beforeApply) await beforeApply(applyCount);
      if (result.plan.kind === "APPEND") {
        appends.push({ key: keyId(key), walletSeq: result.plan.observation.walletSeq });
      }
      cursors.set(keyId(key), result.nextCursor);
    },
  };
  return { effects, appends };
};

describe("capture write-path: serialized writer (step 1, 6/7)", () => {
  it("test-14: the same response on two observers is two independent streams, not one dedup", async () => {
    const store = makeStore();
    const writer = createSerializedStreamWriter(store.effects);
    const wallet = "wallet-pub-key";
    const node: ObservationStreamKey = { observerId: "observer-NODE", walletPublicKey: wallet };
    const platform: ObservationStreamKey = { observerId: "observer-PLATFORM", walletPublicKey: wallet };

    const nodeResult = await writer.capture(node, A);
    const platformResult = await writer.capture(platform, A);

    // No cross-observer dedup: each stream appends its own wallet_seq 1.
    expect(nodeResult.plan.kind).toBe("APPEND");
    expect(platformResult.plan.kind).toBe("APPEND");
    if (nodeResult.plan.kind === "APPEND") expect(nodeResult.plan.observation.walletSeq).toBe(1);
    if (platformResult.plan.kind === "APPEND") {
      expect(platformResult.plan.observation.walletSeq).toBe(1);
    }
    expect(store.appends).toHaveLength(2);
    expect(new Set(store.appends.map((a) => a.key)).size).toBe(2);
  });

  it("serializes concurrent captures on one stream into contiguous gap-free wallet_seq", async () => {
    // apply yields a microtask so captures genuinely overlap; the lock must still serialize them.
    const store = makeStore(async () => {
      await Promise.resolve();
    });
    const writer = createSerializedStreamWriter(store.effects);
    const key: ObservationStreamKey = { observerId: "observer-NODE", walletPublicKey: "wallet" };

    const successorChain = [A, B, C].concat([
      head({ bytes: "response-D", s: "sigD", p: "sigC", fp: "fpD" }),
      head({ bytes: "response-E", s: "sigE", p: "sigD", fp: "fpE" }),
    ]);

    await Promise.all(successorChain.map((capture) => writer.capture(key, capture)));

    expect(store.appends.map((a) => a.walletSeq)).toEqual([1, 2, 3, 4, 5]);
  });

  it("a failed persist rejects that capture but does not poison the stream lock", async () => {
    const store = makeStore(async (n) => {
      if (n === 2) throw new Error("persist failed");
    });
    const writer = createSerializedStreamWriter(store.effects);
    const key: ObservationStreamKey = { observerId: "observer-NODE", walletPublicKey: "wallet" };

    const first = await writer.capture(key, A);
    expect(first.plan.kind).toBe("APPEND");

    // Second persist fails: the failing apply throws before committing, so the cursor stays at 1.
    await expect(writer.capture(key, B)).rejects.toThrow("persist failed");

    // Third capture proceeds on the still-open lock and re-derives wallet_seq 2 (fail-closed).
    const third = await writer.capture(key, B);
    expect(third.plan.kind).toBe("APPEND");
    if (third.plan.kind === "APPEND") {
      expect(third.plan.observation.walletSeq).toBe(2);
      expect(third.plan.observation.relationship).toBe("SUCCESSOR");
    }
    expect(store.appends.map((a) => a.walletSeq)).toEqual([1, 2]);
  });
});
