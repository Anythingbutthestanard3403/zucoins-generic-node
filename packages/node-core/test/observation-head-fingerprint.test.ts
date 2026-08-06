import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  HEAD_FINGERPRINT_DRIFT_VERDICTS,
  OBSERVATION_HEAD_FINGERPRINT_FIELDS,
  OBSERVATION_HEAD_FINGERPRINT_PURPOSE,
  ObservationHeadFingerprintError,
  buildObservationHeadFingerprintPreimage,
  compareObservationHeadFingerprints,
  computeObservationHeadFingerprint,
  type ObservationHeadState,
  type WalletHeadStateEntry,
} from "../src/observation/head-fingerprint.ts";

const KEY_A = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const KEY_B = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const FP_A = "a".repeat(64);
const FP_B = "b".repeat(64);

function entry(overrides: Partial<WalletHeadStateEntry> = {}): WalletHeadStateEntry {
  return {
    walletPublicKey: KEY_A,
    latestSemanticFingerprint: FP_A,
    nextWalletSeq: 4,
    consecutiveRepeatCount: 1,
    anomalyCount: 0,
    ...overrides,
  };
}

function state(entries: readonly WalletHeadStateEntry[]): ObservationHeadState {
  return { entries };
}

describe("observation head fingerprint", () => {
  it("is deterministic for identical state", () => {
    const snapshot = state([entry(), entry({ walletPublicKey: KEY_B, latestSemanticFingerprint: FP_B })]);
    const first = computeObservationHeadFingerprint(snapshot);
    const second = computeObservationHeadFingerprint(snapshot);
    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is independent of caller-supplied entry sequence", () => {
    const a = entry();
    const b = entry({ walletPublicKey: KEY_B, latestSemanticFingerprint: FP_B });
    expect(computeObservationHeadFingerprint(state([a, b]))).toBe(
      computeObservationHeadFingerprint(state([b, a])),
    );
  });

  it("emits the purpose-prefixed canonical preimage in the frozen field sequence", () => {
    const preimage = buildObservationHeadFingerprintPreimage(state([entry()]));
    const [purposeLine, json] = preimage.split("\n");
    expect(purposeLine).toBe(OBSERVATION_HEAD_FINGERPRINT_PURPOSE);
    const parsed = JSON.parse(json) as Record<string, unknown>;
    expect(Object.keys(parsed)).toEqual([...OBSERVATION_HEAD_FINGERPRINT_FIELDS]);
    expect(parsed.purpose).toBe(OBSERVATION_HEAD_FINGERPRINT_PURPOSE);
    expect(parsed.canonical_version).toBe(1);
    expect(parsed.wallet_count).toBe(1);
    expect(parsed.wallets).toEqual([
      {
        wallet_public_key: KEY_A,
        latest_semantic_fingerprint: FP_A,
        next_wallet_seq: 4,
        consecutive_repeat_count: 1,
        anomaly_count: 0,
      },
    ]);
  });

  it("is the SHA-256 of the canonical preimage", () => {
    const snapshot = state([entry()]);
    const expected = createHash("sha256")
      .update(buildObservationHeadFingerprintPreimage(snapshot), "utf8")
      .digest("hex");
    expect(computeObservationHeadFingerprint(snapshot)).toBe(expected);
  });

  it("differs when any covered field changes", () => {
    const baseline = computeObservationHeadFingerprint(state([entry()]));
    const variants = [
      entry({ latestSemanticFingerprint: FP_B }),
      entry({ nextWalletSeq: 5 }),
      entry({ consecutiveRepeatCount: 2 }),
      entry({ anomalyCount: 1 }),
      entry({ walletPublicKey: KEY_B }),
    ];
    for (const variant of variants) {
      expect(computeObservationHeadFingerprint(state([variant]))).not.toBe(baseline);
    }
  });

  it("differs when a wallet is added or removed", () => {
    const one = computeObservationHeadFingerprint(state([entry()]));
    const two = computeObservationHeadFingerprint(
      state([entry(), entry({ walletPublicKey: KEY_B, latestSemanticFingerprint: FP_B })]),
    );
    expect(two).not.toBe(one);
  });

  it("supports a null semantic fingerprint (genesis / no semantic state)", () => {
    const genesis = state([entry({ latestSemanticFingerprint: null, nextWalletSeq: 1 })]);
    const fingerprint = computeObservationHeadFingerprint(genesis);
    expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(fingerprint).not.toBe(computeObservationHeadFingerprint(state([entry()])));
  });

  it("produces a stable digest for the empty head state", () => {
    const empty = computeObservationHeadFingerprint(state([]));
    expect(empty).toBe(computeObservationHeadFingerprint(state([])));
    expect(empty).not.toBe(computeObservationHeadFingerprint(state([entry()])));
  });

  it("reports drift between distinct fingerprints and equality otherwise", () => {
    const prior = computeObservationHeadFingerprint(state([entry()]));
    const same = computeObservationHeadFingerprint(state([entry()]));
    const changed = computeObservationHeadFingerprint(state([entry({ anomalyCount: 3 })]));
    expect(HEAD_FINGERPRINT_DRIFT_VERDICTS).toEqual(["EQUAL", "DRIFTED"]);
    expect(compareObservationHeadFingerprints(prior, same)).toBe("EQUAL");
    expect(compareObservationHeadFingerprints(prior, changed)).toBe("DRIFTED");
  });

  it("rejects a duplicate wallet key", () => {
    expect(() => computeObservationHeadFingerprint(state([entry(), entry()]))).toThrow(
      ObservationHeadFingerprintError,
    );
  });

  it("rejects an empty wallet public key", () => {
    expect(() => computeObservationHeadFingerprint(state([entry({ walletPublicKey: "" })]))).toThrow(
      ObservationHeadFingerprintError,
    );
  });

  it("rejects a malformed semantic fingerprint", () => {
    expect(() =>
      computeObservationHeadFingerprint(state([entry({ latestSemanticFingerprint: "not-hex" })])),
    ).toThrow(ObservationHeadFingerprintError);
  });

  it("rejects non-integer or negative counters", () => {
    const bad = [
      entry({ nextWalletSeq: -1 }),
      entry({ nextWalletSeq: 1.5 }),
      entry({ consecutiveRepeatCount: -2 }),
      entry({ anomalyCount: -1 }),
    ];
    for (const variant of bad) {
      expect(() => computeObservationHeadFingerprint(state([variant]))).toThrow(
        ObservationHeadFingerprintError,
      );
    }
  });
});
