import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  ExactRepeatService,
  InMemoryExactRepeatStore,
  type ExactRepeatCandidate,
} from "./dedup.js";

const STREAM = "observer-1\x00wallet-pub-A";
const STREAM_B = "observer-1\x00wallet-pub-B";

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

const BODY_A = Uint8Array.from([123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 116, 125]);
const BODY_A_PRIME = Uint8Array.from([123, 32, 34, 115, 116, 97, 116, 117, 115, 34, 58, 116, 125]);
const BODY_B = Uint8Array.from([123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 102, 125]);
const BODY_C = Uint8Array.from([123, 34, 120, 34, 58, 49, 125]);
const BODY_MALFORMED = Uint8Array.from([110, 111, 116, 45, 106, 115, 111, 110]);

const FP_1 = "a".repeat(64);
const FP_2 = "b".repeat(64);
const FP_3 = "c".repeat(64);

describe("ExactRepeatService — consecutive verified suppress (step 7; changed-response observation ledger)", () => {
  it("byte-identical verified A,A → 1 gateway_observations row; counter increments", async () => {
    const store = new InMemoryExactRepeatStore();
    const svc = new ExactRepeatService(store);

    const first = await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
    expect(first.kind).toBe("NEW_OBSERVATION");
    if (first.kind === "NEW_OBSERVATION") {
      expect(first.walletSeq).toBe(1);
      expect(first.anomalyAppended).toBe(false);
    }

    const second = await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
    expect(second.kind).toBe("EXACT_REPEAT");
    if (second.kind === "EXACT_REPEAT") {
      expect(second.consecutiveRepeatCount).toBe(1);
    }

    expect(store.getObservations()).toHaveLength(1);
    expect(store.getAnomalies()).toHaveLength(0);
    expect(store.getCursor(STREAM)?.consecutiveRepeatCount).toBe(1);
  });

  it("three consecutive identical verified responses increment the counter to 2", async () => {
    const store = new InMemoryExactRepeatStore();
    const svc = new ExactRepeatService(store);

    await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
    await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
    const third = await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));

    expect(third.kind).toBe("EXACT_REPEAT");
    if (third.kind === "EXACT_REPEAT") {
      expect(third.consecutiveRepeatCount).toBe(2);
    }
    expect(store.getObservations()).toHaveLength(1);
    expect(store.getAnomalies()).toHaveLength(0);
  });
});

describe("ExactRepeatService — anomaly always appends (step 9)", () => {
  it("identical malformed X,X → 2 gateway_observations AND 2 observation_anomalies", async () => {
    const store = new InMemoryExactRepeatStore();
    const svc = new ExactRepeatService(store);

    const first = await svc.classify(
      STREAM,
      candidate(BODY_MALFORMED, {
        verified: false,
        fingerprint: null,
        anomalyKind: "MALFORMED_ENVELOPE",
        anomalyDetails: "strict utf-8/json failed",
      }),
    );
    expect(first.kind).toBe("NEW_OBSERVATION");
    if (first.kind === "NEW_OBSERVATION") {
      expect(first.anomalyAppended).toBe(true);
      expect(first.walletSeq).toBe(1);
    }

    const second = await svc.classify(
      STREAM,
      candidate(BODY_MALFORMED, {
        verified: false,
        fingerprint: null,
        anomalyKind: "MALFORMED_ENVELOPE",
        anomalyDetails: "strict utf-8/json failed",
      }),
    );
    expect(second.kind).toBe("NEW_OBSERVATION");
    if (second.kind === "NEW_OBSERVATION") {
      expect(second.anomalyAppended).toBe(true);
      expect(second.walletSeq).toBe(2);
    }

    expect(store.getObservations()).toHaveLength(2);
    expect(store.getAnomalies()).toHaveLength(2);
    expect(store.getAnomalies().map((a) => a.kind)).toEqual([
      "MALFORMED_ENVELOPE",
      "MALFORMED_ENVELOPE",
    ]);
    // Each anomaly is bound to its own observation (UNIQUE observation_id).
    expect(store.getAnomalies()[0]!.observationId).toBe(store.getObservations()[0]!.observationId);
    expect(store.getAnomalies()[1]!.observationId).toBe(store.getObservations()[1]!.observationId);
    expect(store.getAnomalies()[0]!.observationId).not.toBe(store.getAnomalies()[1]!.observationId);
  });

  it("unverified TRANSPORT_ERROR with identical bytes always appends both ledgers", async () => {
    const store = new InMemoryExactRepeatStore();
    const svc = new ExactRepeatService(store);
    const empty = new Uint8Array(0);

    await svc.classify(
      STREAM,
      candidate(empty, {
        verified: false,
        anomalyKind: "TRANSPORT_ERROR",
        anomalyDetails: "no complete body",
      }),
    );
    await svc.classify(
      STREAM,
      candidate(empty, {
        verified: false,
        anomalyKind: "TRANSPORT_ERROR",
        anomalyDetails: "no complete body",
      }),
    );

    expect(store.getObservations()).toHaveLength(2);
    expect(store.getAnomalies()).toHaveLength(2);
    expect(store.getAnomalies().every((a) => a.kind === "TRANSPORT_ERROR")).toBe(true);
  });

  it("verified REGRESSION (A,B,C,A) appends anomaly on the recurring final A", async () => {
    const store = new InMemoryExactRepeatStore();
    const svc = new ExactRepeatService(store);

    await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
    await svc.classify(STREAM, candidate(BODY_B, { fingerprint: FP_2 }));
    await svc.classify(STREAM, candidate(BODY_C, { fingerprint: FP_3 }));
    const finalA = await svc.classify(
      STREAM,
      candidate(BODY_A, {
        fingerprint: FP_1,
        anomalyKind: "REGRESSION",
        anomalyDetails: "recurrence of older accepted S",
      }),
    );

    expect(finalA.kind).toBe("NEW_OBSERVATION");
    if (finalA.kind === "NEW_OBSERVATION") {
      expect(finalA.walletSeq).toBe(4);
      expect(finalA.anomalyAppended).toBe(true);
    }
    expect(store.getObservations()).toHaveLength(4);
    expect(store.getAnomalies()).toHaveLength(1);
    expect(store.getAnomalies()[0]!.kind).toBe("REGRESSION");
    expect(store.getAnomalies()[0]!.priorObservationId).toBe(
      store.getObservations()[2]!.observationId,
    );
    expect(store.getObservations().map((o) => o.relationship)).toEqual([
      "FIRST",
      "SUCCESSOR",
      "SUCCESSOR",
      "REGRESSION",
    ]);
  });
});

describe("ExactRepeatService — semantic envelope change is not suppressed", () => {
  it("A,A′ same fingerprint different bytes → 2 rows, SEMANTIC_REPEAT, no anomaly", async () => {
    const store = new InMemoryExactRepeatStore();
    const svc = new ExactRepeatService(store);

    const first = await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
    expect(first.kind).toBe("NEW_OBSERVATION");

    const second = await svc.classify(STREAM, candidate(BODY_A_PRIME, { fingerprint: FP_1 }));
    expect(second.kind).toBe("SEMANTIC_REPEAT");
    if (second.kind === "SEMANTIC_REPEAT") {
      expect(second.walletSeq).toBe(2);
    }
    expect(store.getObservations()).toHaveLength(2);
    expect(store.getAnomalies()).toHaveLength(0);
    expect(store.getCursor(STREAM)?.consecutiveRepeatCount).toBe(0);
    // Relationship frozen at INSERT under append-only (AA_PRIME_WRAPPER).
    expect(store.getObservations().map((o) => o.relationship)).toEqual([
      "FIRST",
      "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
    ]);
  });
});

describe("ExactRepeatService — non-adjacent and digest collision", () => {
  it("A,B,C,A without anomaly kind still appends final A (not consecutive)", async () => {
    const store = new InMemoryExactRepeatStore();
    const svc = new ExactRepeatService(store);

    await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
    await svc.classify(STREAM, candidate(BODY_B, { fingerprint: FP_2 }));
    await svc.classify(STREAM, candidate(BODY_C, { fingerprint: FP_3 }));
    const finalA = await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));

    // Without handed anomalyKind this is still a NEW_OBSERVATION (or SEMANTIC if fp
    // matched last — last is C's FP_3, so NEW). Non-adjacent bytes never suppress.
    expect(finalA.kind).not.toBe("EXACT_REPEAT");
    expect(store.getObservations()).toHaveLength(4);
  });

  it("digest match with differing bytes still appends (digest is index only, not equality)", async () => {
    // Seed a prior whose reported digest+length equal the next capture's real digest,
    // but whose stored bytes differ — forces decideAppend past the digest/length gates
    // into the exact-byte comparison, which must APPEND ("The raw hash is an
    // index, not equality proof"; hash-collision simulation).
    const store = new InMemoryExactRepeatStore();
    const left = Uint8Array.from([1, 2, 3, 4]);
    const right = Uint8Array.from([9, 8, 7, 6]);
    expect(left.length).toBe(right.length);
    expect(Buffer.from(left).equals(Buffer.from(right))).toBe(false);

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
  });

  it("streams are isolated: repeat on A does not affect B", async () => {
    const store = new InMemoryExactRepeatStore();
    const svc = new ExactRepeatService(store);

    await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
    await svc.classify(STREAM_B, candidate(BODY_A, { fingerprint: FP_1 }));
    await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));

    expect(store.getObservations().filter((o) => o.streamKey === STREAM)).toHaveLength(1);
    expect(store.getObservations().filter((o) => o.streamKey === STREAM_B)).toHaveLength(1);
    expect(store.getCursor(STREAM)?.consecutiveRepeatCount).toBe(1);
    expect(store.getCursor(STREAM_B)?.consecutiveRepeatCount).toBe(0);
  });
});

describe("ExactRepeatService — new verified state resets counter", () => {
  it("A,A then B appends and resets consecutive_repeat_count to 0", async () => {
    const store = new InMemoryExactRepeatStore();
    const svc = new ExactRepeatService(store);

    await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
    await svc.classify(STREAM, candidate(BODY_A, { fingerprint: FP_1 }));
    const result = await svc.classify(STREAM, candidate(BODY_B, { fingerprint: FP_2 }));

    expect(result.kind).toBe("NEW_OBSERVATION");
    expect(store.getCursor(STREAM)?.consecutiveRepeatCount).toBe(0);
    expect(store.getCursor(STREAM)?.nextWalletSeq).toBe(3);
    expect(store.getObservations()).toHaveLength(2);
  });
});
