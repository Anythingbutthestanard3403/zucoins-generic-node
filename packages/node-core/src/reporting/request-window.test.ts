// admission-stage tests for the signed reporting request verifier:
// the zero-skew signed time window with inclusive boundaries, rewriting-adapter rejection
// (review indicator 2), bounded rate position, mutation-route Idempotency-Key form, and
// pre-burn replay rejection.

import { describe, expect, it } from "vitest";

import { REPORT_REQUEST_GOLDEN_SIGNATURE } from "@zucoins/generic-node-contracts";

import { InMemoryReportingStore } from "./in-memory-store.js";
import { createReportingRequestVerifier, type CapturedReportRequest } from "./request-verifier.js";
import {
  goldenCaptured,
  ISSUED_MS,
  keyFromSeed,
  makeVerifier,
  MID_WINDOW_MS,
  GOLDEN_NONCE,
  NODE_ID,
  pubOf,
  seedGoldenStore,
  signRequest,
  TEST_KEY_SEED,
} from "./test-fixtures.js";

const TEST_PRIV = keyFromSeed(TEST_KEY_SEED);

const seededTestKeyStore = (): InMemoryReportingStore => {
  const store = new InMemoryReportingStore();
  seedGoldenStore(store, pubOf(TEST_PRIV));
  return store;
};

// Window-boundary helper: signs over the guard-free serializer so it can construct the
// adversarial over-window (>60s) and zero-window requests the honest minter refuses to mint,
// letting these tests exercise the verifier's independent invalid_reporting_window rejection on
// the real breaking inputs. In-window uses are byte-identical to the guarded builder path.
const signWindowed = (
  issuedAtMs: number,
  expiresAtMs: number,
  nonce: string,
): CapturedReportRequest =>
  signRequest({
    privateKey: TEST_PRIV,
    method: "GET",
    target: "/v1/events?after_implementer_seq=5",
    body: "",
    nonce,
    issuedAtMs,
    expiresAtMs,
    allowInvalidWindow: true,
  });

describe("signed time window (zero skew, inclusive boundaries)", () => {
  it("accepts a lifetime of exactly 60s; rejects 60001ms and 0ms", async () => {
    const store = seededTestKeyStore();
    const verifier = makeVerifier(store);
    const exact = await verifier.verify(
      signWindowed(ISSUED_MS, ISSUED_MS + 60_000, "11111111-1111-4111-8111-111111111111"),
    );
    expect(exact.ok).toBe(true);
    const tooWide = await verifier.verify(
      signWindowed(ISSUED_MS, ISSUED_MS + 60_001, "22222222-2222-4222-8222-222222222222"),
    );
    expect(tooWide.ok).toBe(false);
    if (!tooWide.ok) expect(tooWide.code).toBe("invalid_reporting_window");
    const zero = await verifier.verify(
      signWindowed(ISSUED_MS, ISSUED_MS, "33333333-3333-4333-8333-333333333333"),
    );
    expect(zero.ok).toBe(false);
    if (!zero.ok) expect(zero.code).toBe("invalid_reporting_window");
    expect(store.listNonceEvidence().length).toBe(1);
  });

  it("accepts receipt exactly at issued_at and at expires_at; rejects 1ms beyond either", async () => {
    const nonce = "44444444-4444-4444-8444-444444444444";
    const atIssued = seededTestKeyStore();
    const first = await makeVerifier(atIssued, () => ISSUED_MS).verify({
      ...signWindowed(ISSUED_MS, ISSUED_MS + 60_000, nonce),
      receivedAtMs: ISSUED_MS,
    });
    expect(first.ok).toBe(true);

    const atExpires = seededTestKeyStore();
    const second = await makeVerifier(atExpires, () => ISSUED_MS + 60_000).verify({
      ...signWindowed(ISSUED_MS, ISSUED_MS + 60_000, nonce),
      receivedAtMs: ISSUED_MS + 60_000,
    });
    expect(second.ok).toBe(true);

    const pastExpiry = seededTestKeyStore();
    const expired = await makeVerifier(pastExpiry, () => ISSUED_MS + 60_001).verify({
      ...signWindowed(ISSUED_MS, ISSUED_MS + 60_000, nonce),
      receivedAtMs: ISSUED_MS + 60_001,
    });
    expect(expired.ok).toBe(false);
    if (!expired.ok) expect(expired.code).toBe("reporting_request_expired");

    const tooEarly = seededTestKeyStore();
    const notYet = await makeVerifier(tooEarly, () => ISSUED_MS - 1).verify({
      ...signWindowed(ISSUED_MS, ISSUED_MS + 60_000, nonce),
      receivedAtMs: ISSUED_MS - 1,
    });
    expect(notYet.ok).toBe(false);
    if (!notYet.ok) expect(notYet.code).toBe("reporting_request_not_yet_valid");
  });

  it("checks the window before spending signature crypto", async () => {
    const store = seededTestKeyStore();
    const request = signWindowed(ISSUED_MS, ISSUED_MS + 60_000, "55555555-5555-4555-8555-555555555555");
    // A garbage-but-well-formed signature on an expired request still meets the window
    // rejection first (REPORTING_VERIFIER_ORDER — status/window before signature).
    const garbageSignature = {
      ...request,
      rawHeaders: request.rawHeaders.map((value, index) =>
        index === 9 ? REPORT_REQUEST_GOLDEN_SIGNATURE : value,
      ),
    };
    const outcome = await makeVerifier(store, () => ISSUED_MS + 60_001).verify({
      ...garbageSignature,
      receivedAtMs: ISSUED_MS + 60_001,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("reporting_request_expired");
  });
});

describe("rewriting-adapter rejection (indicator 2)", () => {
  it("rejects a delivered target that desyncs from the signed bytes, burning nothing", async () => {
    const store = seededTestKeyStore();
    const mutatedValue = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events?after_implementer_seq=1044&limit=100&wait_seconds=30",
      signedTarget: "/v1/events?after_implementer_seq=1043&limit=100&wait_seconds=30",
      body: "",
      nonce: GOLDEN_NONCE,
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    const outcome = await makeVerifier(store).verify(mutatedValue);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("invalid_signature");
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("rejects an absolute-form target at the form gate, never reconstructing it", async () => {
    const store = seededTestKeyStore();
    const absolute = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "http://node.example/v1/events?after_implementer_seq=5",
      body: "",
      nonce: GOLDEN_NONCE,
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    const outcome = await makeVerifier(store).verify(absolute);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("invalid_request_target");
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("rejects trailing-slash and percent-byte variants before any crypto", async () => {
    const store = seededTestKeyStore();
    const verifier = makeVerifier(store);
    const trailing = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events/",
      signedTarget: "/v1/events",
      body: "",
      nonce: "66666666-6666-4666-8666-666666666666",
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    expect((await verifier.verify(trailing)).ok).toBe(false);
    const percent = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events/%7E",
      body: "",
      nonce: "77777777-7777-4777-8777-777777777777",
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    expect((await verifier.verify(percent)).ok).toBe(false);
    expect(store.listNonceEvidence().length).toBe(0);
  });
});

describe("bounded rate, idempotency-key form, and replay", () => {
  it("applies the bounded rate before the registration lookup", async () => {
    const store = seededTestKeyStore();
    // One shared budget across principals: the second call is refused regardless of the
    // presented key, so an unknown key id meets the rate check before the registration
    // lookup that would otherwise reject it.
    let calls = 0;
    const sharedBudgetLimiter = {
      consume: (): boolean => {
        calls += 1;
        return calls === 1;
      },
    };
    const verifier = createReportingRequestVerifier({
      nodeId: NODE_ID,
      store,
      rateLimiter: sharedBudgetLimiter,
      nowMs: () => MID_WINDOW_MS,
    });
    const first = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events?after_implementer_seq=5",
      body: "",
      nonce: "88888888-8888-4888-8888-888888888888",
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    expect((await verifier.verify(first)).ok).toBe(true);
    const unknownKey = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events?after_implementer_seq=5",
      body: "",
      nonce: "99999999-9999-4999-8999-999999999999",
      keyId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    const second = await verifier.verify(unknownKey);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe("rate_limited");
    expect(store.listNonceEvidence().length).toBe(1);
  });

  it("requires a canonical Idempotency-Key on mutation routes", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store);
    const missingKey = {
      ...goldenCaptured(),
      rawHeaders: goldenCaptured().rawHeaders.slice(0, 10),
    };
    const outcome = await makeVerifier(store).verify(missingKey);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("invalid_idempotency_key");
    const shortKey = {
      ...goldenCaptured(),
      rawHeaders: [...goldenCaptured().rawHeaders.slice(0, 10), "Idempotency-Key", "short"],
    };
    const second = await makeVerifier(store).verify(shortKey);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe("invalid_idempotency_key");
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("rejects a replayed nonce and retains exactly one burn", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store);
    const verifier = makeVerifier(store);
    expect((await verifier.verify(goldenCaptured())).ok).toBe(true);
    const replay = await verifier.verify(goldenCaptured());
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.code).toBe("nonce_replay");
    expect(store.listNonceEvidence().length).toBe(1);
  });
});
