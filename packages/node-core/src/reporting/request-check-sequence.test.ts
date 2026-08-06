// frozen PRE_BURN_CHECKS sequencing: signed_time_window sits at
// position 2, immediately after bounded_shape and BEFORE bounded_rate, the registration
// lookup, holds/key_status, and tenant equality. A window-invalid request therefore rejects
// identically no matter the presented key's registration state — no existence or liveness
// signal leaks — and consumes zero rate-limit budget.

import { describe, expect, it } from "vitest";

import { InMemoryReportingStore } from "./in-memory-store.js";
import {
  createReportingRequestVerifier,
  type CapturedReportRequest,
} from "./request-verifier.js";
import type { ReportingRateLimiter } from "./store.js";
import {
  IMPLEMENTER_ID,
  ISSUED_MS,
  KEY_ID,
  keyFromSeed,
  MID_WINDOW_MS,
  NODE_ID,
  pubOf,
  seedGoldenStore,
  signRequest,
  TEST_KEY_SEED,
} from "./test-fixtures.js";

const TEST_PRIV = keyFromSeed(TEST_KEY_SEED);

// A properly signed request whose receipt instant falls 1ms past its signed expires_at.
const expiredRequest = (nonce: string): CapturedReportRequest => ({
  ...signRequest({
    privateKey: TEST_PRIV,
    method: "GET",
    target: "/v1/events?after_implementer_seq=5",
    body: "",
    nonce,
    issuedAtMs: ISSUED_MS,
    expiresAtMs: ISSUED_MS + 60_000,
  }),
  receivedAtMs: ISSUED_MS + 60_001,
});

const countingLimiter = (): ReportingRateLimiter & { calls: number } => {
  const state = {
    calls: 0,
    consume: (): boolean => {
      state.calls += 1;
      return true;
    },
  };
  return state;
};

const verifierFor = (store: InMemoryReportingStore, rateLimiter: ReportingRateLimiter) =>
  createReportingRequestVerifier({
    nodeId: NODE_ID,
    store,
    rateLimiter,
    nowMs: () => MID_WINDOW_MS,
  });

describe("signed_time_window precedes bounded rate, registration, holds, and key status", () => {
  it("rejects an expired request identically for every key registration state", async () => {
    // Unregistered: nothing seeded — the registration lookup would say unknown key.
    const unregistered = new InMemoryReportingStore();
    // Registered but revoked: the lifecycle admission would say key not active.
    const revoked = new InMemoryReportingStore();
    seedGoldenStore(revoked, pubOf(TEST_PRIV));
    revoked.seedReportingKeyState(NODE_ID, IMPLEMENTER_ID, KEY_ID, {
      state: "REVOKED",
      revokedAtMs: ISSUED_MS,
    });
    // Registered but held: the hold gate would say auth hold.
    const held = new InMemoryReportingStore();
    seedGoldenStore(held, pubOf(TEST_PRIV));
    held.seedRestoreHold(NODE_ID, true);

    const codes: string[] = [];
    const stores = [unregistered, revoked, held];
    for (const [index, store] of stores.entries()) {
      const outcome = await verifierFor(store, countingLimiter()).verify(
        expiredRequest(`11111111-1111-4111-8111-11111111111${index}`),
      );
      expect(outcome.ok).toBe(false);
      if (!outcome.ok) codes.push(outcome.code);
      expect(store.listNonceEvidence().length).toBe(0);
    }
    expect(codes).toEqual([
      "reporting_request_expired",
      "reporting_request_expired",
      "reporting_request_expired",
    ]);
  });

  it("consumes no rate-limit budget on an expired request", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store, pubOf(TEST_PRIV));
    const limiter = countingLimiter();
    const verifier = verifierFor(store, limiter);
    const expired = await verifier.verify(
      expiredRequest("22222222-2222-4222-8222-222222222222"),
    );
    expect(expired.ok).toBe(false);
    if (!expired.ok) expect(expired.code).toBe("reporting_request_expired");
    expect(limiter.calls).toBe(0);
    expect(store.listNonceEvidence().length).toBe(0);

    // The full budget remains: a valid in-window request is admitted afterwards.
    const valid = await verifier.verify(
      signRequest({
        privateKey: TEST_PRIV,
        method: "GET",
        target: "/v1/events?after_implementer_seq=5",
        body: "",
        nonce: "33333333-3333-4333-8333-333333333333",
        issuedAtMs: ISSUED_MS,
        expiresAtMs: ISSUED_MS + 60_000,
      }),
    );
    expect(valid.ok).toBe(true);
    expect(limiter.calls).toBe(1);
    expect(store.listNonceEvidence().length).toBe(1);
  });
});
