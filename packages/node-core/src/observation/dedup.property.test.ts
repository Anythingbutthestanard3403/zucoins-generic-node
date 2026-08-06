// property and matrix proofs for the exact-repeat comparator
// (ExactRepeatService / decideAppend). Complements capture.concurrency.test.ts (real-PG
// races and restart) with randomised sequences and the full changed-response
// matrix. No new production behaviour.
//
// Governing:
// md examples,.1
// 3
// observation ledger.md

import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";
import fc from "fast-check";

import {
  ExactRepeatService,
  InMemoryExactRepeatStore,
  type ExactRepeatCandidate,
} from "./dedup.js";

const STREAM = "observer-prop\x00wallet-prop-A";

const BODY_A = Uint8Array.from([123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 116, 125]);
const BODY_A_PRIME = Uint8Array.from([123, 32, 34, 115, 116, 97, 116, 117, 115, 34, 58, 116, 125]);
const BODY_B = Uint8Array.from([123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 102, 125]);
const BODY_C = Uint8Array.from([123, 34, 120, 34, 58, 49, 125]);
const BODY_MALFORMED = Uint8Array.from([110, 111, 116, 45, 106, 115, 111, 110]);
const BODY_GENESIS = Uint8Array.from([123, 34, 103, 101, 110, 101, 115, 105, 115, 34, 125]);
const BODY_CONFLICT = Uint8Array.from([123, 34, 99, 111, 110, 102, 108, 105, 99, 116, 34, 125]);

const FP_1 = "a".repeat(64);
const FP_2 = "b".repeat(64);
const FP_3 = "c".repeat(64);
const FP_GEN = "d".repeat(64);

function candidate(
  bytes: Uint8Array,
  opts: {
    verified?: boolean;
    fingerprint?: string | null;
    anomalyKind?: ExactRepeatCandidate["anomalyKind"];
    anomalyDetails?: string;
  } = {},
): ExactRepeatCandidate {
  const verified = opts.verified ?? true;
  const anomalyKind =
    opts.anomalyKind !== undefined
      ? opts.anomalyKind
      : verified
        ? null
        : "MALFORMED_ENVELOPE";
  return {
    rawResponseBytes: bytes,
    verified,
    semanticFingerprint: opts.fingerprint ?? null,
    anomalyKind,
    anomalyDetails: opts.anomalyDetails ?? (anomalyKind ? `anomaly:${anomalyKind}` : ""),
  };
}

async function classifyAll(
  captures: ExactRepeatCandidate[],
  streamKey = STREAM,
): Promise<InMemoryExactRepeatStore> {
  const store = new InMemoryExactRepeatStore();
  const svc = new ExactRepeatService(store);
  for (const c of captures) {
    await svc.classify(streamKey, c);
  }
  return store;
}

describe("property — changed-response matrix", () => {
  it("A,A → 1 observation row (consecutive verified suppress)", async () => {
    const store = await classifyAll([
      candidate(BODY_A, { fingerprint: FP_1 }),
      candidate(BODY_A, { fingerprint: FP_1 }),
    ]);
    expect(store.getObservations()).toHaveLength(1);
    expect(store.getAnomalies()).toHaveLength(0);
    expect(store.getCursor(STREAM)?.consecutiveRepeatCount).toBe(1);
  });

  it("A,A′ → 2 rows (byte-different wrapper, same fingerprint)", async () => {
    const store = await classifyAll([
      candidate(BODY_A, { fingerprint: FP_1 }),
      candidate(BODY_A_PRIME, { fingerprint: FP_1 }),
    ]);
    expect(store.getObservations()).toHaveLength(2);
    expect(store.getAnomalies()).toHaveLength(0);
    expect(store.getCursor(STREAM)?.consecutiveRepeatCount).toBe(0);
  });

  it("A,B,C,A → 4 rows; final A retained (consecutive-only, not global)", async () => {
    const store = await classifyAll([
      candidate(BODY_A, { fingerprint: FP_1 }),
      candidate(BODY_B, { fingerprint: FP_2 }),
      candidate(BODY_C, { fingerprint: FP_3 }),
      candidate(BODY_A, {
        fingerprint: FP_1,
        anomalyKind: "REGRESSION",
        anomalyDetails: "recurrence",
      }),
    ]);
    expect(store.getObservations()).toHaveLength(4);
    expect(store.getAnomalies()).toHaveLength(1);
    expect(store.getAnomalies()[0]!.kind).toBe("REGRESSION");
    expect(store.getObservations().map((o) => o.walletSeq)).toEqual([1, 2, 3, 4]);
  });

  it("identical malformed X,X → 2 observations + 2 anomalies", async () => {
    const x = candidate(BODY_MALFORMED, {
      verified: false,
      anomalyKind: "MALFORMED_ENVELOPE",
      anomalyDetails: "malformed",
    });
    const store = await classifyAll([x, x]);
    expect(store.getObservations()).toHaveLength(2);
    expect(store.getAnomalies()).toHaveLength(2);
  });

  it("genesis, non-genesis, genesis → 3 rows; final genesis retained with anomaly", async () => {
    const store = await classifyAll([
      candidate(BODY_GENESIS, { fingerprint: FP_GEN }),
      candidate(BODY_A, { fingerprint: FP_1 }),
      candidate(BODY_GENESIS, {
        fingerprint: FP_GEN,
        anomalyKind: "GENESIS_AFTER_HISTORY",
        anomalyDetails: "genesis after history",
      }),
    ]);
    expect(store.getObservations()).toHaveLength(3);
    expect(store.getAnomalies()).toHaveLength(1);
    expect(store.getAnomalies()[0]!.kind).toBe("GENESIS_AFTER_HISTORY");
  });

  it("same fingerprint, conflicting body → 2 rows (no silent suppress)", async () => {
    const store = await classifyAll([
      candidate(BODY_A, { fingerprint: FP_1 }),
      candidate(BODY_CONFLICT, { fingerprint: FP_1 }),
    ]);
    expect(store.getObservations()).toHaveLength(2);
  });

  it("new-head with unrelated prior fingerprint → 2 rows (gap evidence, no suppress)", async () => {
    const store = await classifyAll([
      candidate(BODY_A, { fingerprint: FP_1 }),
      candidate(BODY_B, {
        fingerprint: FP_2,
        anomalyKind: "UNEXPLAINED_JUMP",
        anomalyDetails: "unrelated P0",
      }),
    ]);
    expect(store.getObservations()).toHaveLength(2);
    expect(store.getAnomalies()).toHaveLength(1);
  });

  it("digest collision with differing bytes still appends (exact bytes are authority)", async () => {
    const store = new InMemoryExactRepeatStore();
    const left = Uint8Array.from([1, 2, 3, 4]);
    const right = Uint8Array.from([9, 8, 7, 6]);
    const rightDigest = createHash("sha256").update(right).digest("hex");
    await store.recordSighting(STREAM, {
      nextWalletSeq: 2,
      consecutiveRepeatCount: 0,
      lastRecorded: {
        verified: true,
        rawResponseSha256: rightDigest,
        rawResponseOctets: right.length,
        rawResponseBytes: left,
      },
      lastSemanticFingerprint: FP_1,
      lastObservationId: "seed-obs",
    });
    const svc = new ExactRepeatService(store);
    const result = await svc.classify(STREAM, candidate(right, { fingerprint: FP_2 }));
    expect(result.kind).not.toBe("EXACT_REPEAT");
    expect(store.getObservations()).toHaveLength(1);
    // Explicit byte-level inequality — the comparator path must reach Buffer/byte compare.
    expect(Buffer.from(left).equals(Buffer.from(right))).toBe(false);
  });
});

describe("property — randomised consecutive-dedup invariants", () => {
  it("any non-empty sequence of verified byte-identical captures yields exactly 1 row", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 40 }), async (n) => {
        const store = new InMemoryExactRepeatStore();
        const svc = new ExactRepeatService(store);
        for (let i = 0; i < n; i += 1) {
          await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
        }
        expect(store.getObservations()).toHaveLength(1);
        expect(store.getCursor(STREAM)?.consecutiveRepeatCount).toBe(n - 1);
        expect(store.getAnomalies()).toHaveLength(0);
      }),
      { numRuns: 25 },
    );
  });

  it("alternating two distinct verified bodies never suppresses", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 20 }), async (pairs) => {
        const store = new InMemoryExactRepeatStore();
        const svc = new ExactRepeatService(store);
        for (let i = 0; i < pairs; i += 1) {
          await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
          await svc.classify(STREAM, candidate(BODY_B, { fingerprint: FP_2 }));
        }
        expect(store.getObservations()).toHaveLength(pairs * 2);
        expect(store.getCursor(STREAM)?.consecutiveRepeatCount).toBe(0);
        expect(store.getObservations().map((o) => o.walletSeq)).toEqual(
          Array.from({ length: pairs * 2 }, (_, i) => i + 1),
        );
      }),
      { numRuns: 15 },
    );
  });

  it("every non-verified capture appends even when bytes repeat", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 15 }), async (n) => {
        const store = new InMemoryExactRepeatStore();
        const svc = new ExactRepeatService(store);
        const body = Uint8Array.from([0xde, 0xad, 0xbe, 0xef]);
        for (let i = 0; i < n; i += 1) {
          await svc.classify(
            STREAM,
            candidate(body, {
              verified: false,
              anomalyKind: "TRANSPORT_ERROR",
              anomalyDetails: "timeout",
            }),
          );
        }
        expect(store.getObservations()).toHaveLength(n);
        expect(store.getAnomalies()).toHaveLength(n);
      }),
      { numRuns: 15 },
    );
  });

  it("random byte changes always append; only exact consecutive verified equals suppress", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.uint8Array({ minLength: 1, maxLength: 16 }), { minLength: 1, maxLength: 12 }),
        async (bodies) => {
          const store = new InMemoryExactRepeatStore();
          const svc = new ExactRepeatService(store);
          let expectedRows = 0;
          let last: Uint8Array | null = null;
          for (let i = 0; i < bodies.length; i += 1) {
            const body = bodies[i]!;
            const fp = createHash("sha256").update(body).digest("hex");
            await svc.classify(STREAM, candidate(body, { fingerprint: fp }));
            if (
              last !== null &&
              last.length === body.length &&
              Buffer.from(last).equals(Buffer.from(body))
            ) {
              // suppress
            } else {
              expectedRows += 1;
              last = body;
            }
          }
          expect(store.getObservations()).toHaveLength(expectedRows);
          // wallet_seq is contiguous 1..expectedRows
          expect(store.getObservations().map((o) => o.walletSeq)).toEqual(
            Array.from({ length: expectedRows }, (_, i) => i + 1),
          );
        },
      ),
      { numRuns: 40 },
    );
  });

  it("streams are independent: activity on B never mutates A's cursor", async () => {
    const streamB = "observer-prop\x00wallet-prop-B";
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 10 }), async (n) => {
        const store = new InMemoryExactRepeatStore();
        const svc = new ExactRepeatService(store);
        await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
        // Distinct bodies so B's own consecutive-dedup does not collapse the count.
        for (let i = 0; i < n; i += 1) {
          const body = Uint8Array.from([i + 1, i + 2, i + 3, i + 4]);
          const fp = createHash("sha256").update(body).digest("hex");
          await svc.classify(streamB, candidate(body, { fingerprint: fp }));
        }
        await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
        expect(store.getObservations().filter((o) => o.streamKey === STREAM)).toHaveLength(1);
        expect(store.getCursor(STREAM)?.consecutiveRepeatCount).toBe(1);
        expect(store.getObservations().filter((o) => o.streamKey === streamB)).toHaveLength(n);
      }),
      { numRuns: 10 },
    );
  });

  it("append-only: row count never decreases across a random walk", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            kind: fc.constantFrom("A", "B", "C", "X"),
            repeat: fc.boolean(),
          }),
          { minLength: 1, maxLength: 30 },
        ),
        async (steps) => {
          const store = new InMemoryExactRepeatStore();
          const svc = new ExactRepeatService(store);
          let prevRows = 0;
          for (const step of steps) {
            if (step.kind === "X") {
              await svc.classify(
                STREAM,
                candidate(BODY_MALFORMED, {
                  verified: false,
                  anomalyKind: "MALFORMED_ENVELOPE",
                  anomalyDetails: "x",
                }),
              );
            } else {
              const body = step.kind === "A" ? BODY_A : step.kind === "B" ? BODY_B : BODY_C;
              const fp = step.kind === "A" ? FP_1 : step.kind === "B" ? FP_2 : FP_3;
              await svc.classify(STREAM, candidate(body, { fingerprint: fp }));
              if (step.repeat) {
                await svc.classify(STREAM, candidate(body, { fingerprint: fp }));
              }
            }
            const rows = store.getObservations().length;
            expect(rows).toBeGreaterThanOrEqual(prevRows);
            prevRows = rows;
          }
        },
      ),
      { numRuns: 30 },
    );
  });
});

describe("property — restart continuity (cursor restoration)", () => {
  it("resuming from a stored cursor matches a continuous run", async () => {
    const continuous = await classifyAll([
      candidate(BODY_A, { fingerprint: FP_1 }),
      candidate(BODY_B, { fingerprint: FP_2 }),
      candidate(BODY_C, { fingerprint: FP_3 }),
      candidate(BODY_A, { fingerprint: FP_1 }),
    ]);

    // Part 1
    const part1 = new InMemoryExactRepeatStore();
    const svc1 = new ExactRepeatService(part1);
    await svc1.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
    await svc1.classify(STREAM, candidate(BODY_B, { fingerprint: FP_2 }));
    const cursor = part1.getCursor(STREAM)!;

    // Part 2 — restore cursor into a fresh store (models process restart loading cursor).
    const part2 = new InMemoryExactRepeatStore();
    await part2.recordSighting(STREAM, cursor);
    // Also re-seed the "prior observation" presence: ExactRepeatService only needs cursor.
    const svc2 = new ExactRepeatService(part2);
    await svc2.classify(STREAM, candidate(BODY_C, { fingerprint: FP_3 }));
    await svc2.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));

    // Combined observations: part1's 2 + part2's new appends.
    const part2New = part2.getObservations().length;
    expect(part1.getObservations().length + part2New).toBe(continuous.getObservations().length);
    expect(part2.getCursor(STREAM)?.nextWalletSeq).toBe(continuous.getCursor(STREAM)?.nextWalletSeq);
  });

  it("NEGATIVE: restart from empty cursor renumbers from wallet_seq 1", async () => {
    const part1 = await classifyAll([
      candidate(BODY_A, { fingerprint: FP_1 }),
      candidate(BODY_B, { fingerprint: FP_2 }),
    ]);
    expect(part1.getCursor(STREAM)?.nextWalletSeq).toBe(3);

    const lost = await classifyAll([candidate(BODY_C, { fingerprint: FP_3 })]);
    expect(lost.getObservations()[0]!.walletSeq).toBe(1);
    expect(lost.getObservations()[0]!.walletSeq).not.toBe(3);
  });
});
