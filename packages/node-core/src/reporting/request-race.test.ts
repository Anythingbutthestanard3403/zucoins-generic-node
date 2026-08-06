// review indicator 3: same-nonce concurrency. Two or more requests
// carrying the same nonce arrive near-simultaneously; exactly one may succeed, and it must be
// one that passes every other check. The in-memory reference store's burn critical section
// contains no `await`, so check-then-insert cannot interleave under JS run-to-completion —
// these tests prove the arrangement empirically through the real pipeline (real signatures,
// real concurrent verify calls, no stubbed flags).

import { describe, expect, it } from "vitest";

import { InMemoryReportingStore } from "./in-memory-store.js";
import type { ReportingVerifyOutcome } from "./request-verifier.js";
import {
  ISSUED_MS,
  keyFromSeed,
  makeVerifier,
  GOLDEN_NONCE,
  pubOf,
  seedGoldenStore,
  signRequest,
  TEST_KEY_SEED,
} from "./test-fixtures.js";

const TEST_PRIV = keyFromSeed(TEST_KEY_SEED);

function seededStore(): InMemoryReportingStore {
  const store = new InMemoryReportingStore();
  seedGoldenStore(store, pubOf(TEST_PRIV));
  return store;
}

const validRequest = () =>
  signRequest({
    privateKey: TEST_PRIV,
    method: "GET",
    target: "/v1/events?after_implementer_seq=5",
    body: "",
    nonce: GOLDEN_NONCE,
    issuedAtMs: ISSUED_MS,
    expiresAtMs: ISSUED_MS + 60_000,
  });

describe("same-nonce concurrent burn atomicity (indicator 3)", () => {
  it("admits exactly one of eight concurrent same-nonce requests", async () => {
    const store = seededStore();
    const verifier = makeVerifier(store);
    const outcomes = await Promise.all(
      Array.from({ length: 8 }, () => verifier.verify(validRequest())),
    );
    const accepted = outcomes.filter((outcome) => outcome.ok);
    expect(accepted.length).toBe(1);
    const codes = outcomes
      .filter((outcome): outcome is Extract<ReportingVerifyOutcome, { ok: false }> => !outcome.ok)
      .map((outcome) => outcome.code);
    expect(codes).toEqual(Array.from({ length: 7 }, () => "nonce_replay"));
    const evidence = store.listNonceEvidence();
    expect(evidence.length).toBe(1);
    expect(evidence[0]!.nonce).toBe(GOLDEN_NONCE);
  });

  it("the single burn belongs to a fully-valid request, never to a same-nonce invalid rival", async () => {
    const store = seededStore();
    const verifier = makeVerifier(store);
    // The invalid rival carries the same nonce but a signature over a different target.
    const invalidRival = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events?after_implementer_seq=6",
      signedTarget: "/v1/events?after_implementer_seq=5",
      body: "",
      nonce: GOLDEN_NONCE,
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    const outcomes = await Promise.all([
      verifier.verify(validRequest()),
      verifier.verify(invalidRival),
      verifier.verify(validRequest()),
      verifier.verify(invalidRival),
    ]);
    const accepted = outcomes.filter((outcome) => outcome.ok);
    expect(accepted.length).toBe(1);
    const rejected = outcomes.filter(
      (outcome): outcome is Extract<ReportingVerifyOutcome, { ok: false }> => !outcome.ok,
    );
    expect(rejected.map((outcome) => outcome.code).sort()).toEqual([
      "invalid_signature",
      "invalid_signature",
      "nonce_replay",
    ]);
    const evidence = store.listNonceEvidence();
    expect(evidence.length).toBe(1);
    // The retained burn is the valid request's exact bytes (the after_implementer_seq=5 target).
    expect(evidence[0]!.rawTarget).toBe("/v1/events?after_implementer_seq=5");
  });
});
