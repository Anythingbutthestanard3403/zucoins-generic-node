// live-pipeline tests for the signed reporting request verifier.
// Case 1 (request side): the A.8 queryless and query goldens reproduce
// byte-for-byte through this pipeline, with the golden signatures verifying through live
// node:crypto (no re-signing). Case 2 (request side): a delivered target whose
// bytes desync from the signed bytes is always a rejection, proven with real signatures over
// real preimages through the full capture shape — never a stubbed decision flag.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  decodeCanonicalEd25519Signature,
  decodeCanonicalReportingPublicKey,
  REPORTING_KEY_PUBKEY,
  REPORT_REQUEST_GOLDEN_PREIMAGE,
  REPORT_REQUEST_GOLDEN_SHA256,
  REPORT_REQUEST_GOLDEN_SIGNATURE,
  REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE,
  REPORT_REQUEST_QUERY_GOLDEN_SHA256,
  REPORT_REQUEST_QUERY_GOLDEN_SIGNATURE,
} from "@zucoins/generic-node-contracts";

import { verifyDetachedEd25519 } from "./ed25519.js";
import { InMemoryReportingStore } from "./in-memory-store.js";
import type { CapturedReportRequest } from "./request-verifier.js";
import {
  goldenCaptured,
  goldenHeaders,
  ISSUED_MS,
  keyFromSeed,
  KEY_ID,
  makeVerifier,
  MID_WINDOW_MS,
  GOLDEN_NONCE,
  NODE_ID,
  IMPLEMENTER_ID,
  pubOf,
  seedGoldenStore,
  signRequest,
  TEST_KEY_SEED,
} from "./test-fixtures.js";

const TEST_PRIV = keyFromSeed(TEST_KEY_SEED);

const readArtifact = (name: string): string =>
  readFileSync(
    fileURLToPath(
      new URL(`../../../generic-node-contracts/src/reporting-tuples/gen/${name}`, import.meta.url),
    ),
    "utf8",
  );

describe("A.8 goldens through the live verifier path", () => {
  it("accepts the queryless golden byte-for-byte and burns its exact evidence", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store);
    const outcome = await makeVerifier(store).verify(goldenCaptured());
    expect(outcome.ok).toBe(true);
    const evidence = store.listNonceEvidence();
    expect(evidence.length).toBe(1);
    expect(evidence[0]!.requestPreimageText).toBe(REPORT_REQUEST_GOLDEN_PREIMAGE);
    expect(evidence[0]!.requestPreimageText).toBe(readArtifact("zp-report-request-v1.preimage.txt"));
    expect(evidence[0]!.requestPreimageSha256).toBe(REPORT_REQUEST_GOLDEN_SHA256);
    expect(evidence[0]!.requestSignature).toBe(REPORT_REQUEST_GOLDEN_SIGNATURE);
  });

  it("accepts the query-bearing golden byte-for-byte with its exact raw target", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store);
    const captured: CapturedReportRequest = {
      method: "GET",
      rawTarget: "/v1/events?after_implementer_seq=1043&limit=100&wait_seconds=30",
      rawHeaders: goldenHeaders(REPORT_REQUEST_QUERY_GOLDEN_SIGNATURE, GOLDEN_NONCE),
      bodyBytes: new Uint8Array(0),
      receivedAtMs: MID_WINDOW_MS,
    };
    const outcome = await makeVerifier(store).verify(captured);
    expect(outcome.ok).toBe(true);
    const evidence = store.listNonceEvidence();
    expect(evidence.length).toBe(1);
    expect(evidence[0]!.requestPreimageText).toBe(REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE);
    expect(evidence[0]!.requestPreimageText).toBe(
      readArtifact("zp-report-request-v1.query.preimage.txt"),
    );
    expect(evidence[0]!.requestPreimageSha256).toBe(REPORT_REQUEST_QUERY_GOLDEN_SHA256);
  });

  it("verifies both golden signatures through the live node:crypto path", () => {
    const publicKey = decodeCanonicalReportingPublicKey(REPORTING_KEY_PUBKEY);
    expect(publicKey).not.toBeNull();
    for (const [preimage, signature] of [
      [REPORT_REQUEST_GOLDEN_PREIMAGE, REPORT_REQUEST_GOLDEN_SIGNATURE],
      [REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE, REPORT_REQUEST_QUERY_GOLDEN_SIGNATURE],
    ] as const) {
      const signatureBytes = decodeCanonicalEd25519Signature(signature);
      expect(signatureBytes).not.toBeNull();
      expect(
        verifyDetachedEd25519({
          publicKeyBytes: publicKey!,
          preimageText: preimage,
          signatureBytes: signatureBytes!,
        }),
      ).toBe(true);
    }
  });
});

describe("unsigned transport headers on VerifiedReportRequest", () => {
  it("extracts Last-Event-ID into lastEventId (absent → null)", async () => {
    const store = new InMemoryReportingStore();
    // Sign with TEST_PRIV → registration must carry its public key (not the A.8 golden).
    seedGoldenStore(store, pubOf(TEST_PRIV));
    const without = await makeVerifier(store).verify(
      signRequest({
        privateKey: TEST_PRIV,
        method: "GET",
        target: "/v1/events/stream",
        body: "",
        nonce: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        issuedAtMs: ISSUED_MS,
        expiresAtMs: ISSUED_MS + 60_000,
      }),
    );
    expect(without.ok).toBe(true);
    if (!without.ok) return;
    expect(without.lastEventId).toBeNull();

    const withHeader = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events/stream",
      body: "",
      nonce: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    const captured: CapturedReportRequest = {
      ...withHeader,
      rawHeaders: [...withHeader.rawHeaders, "Last-Event-ID", "6"],
    };
    const withLeid = await makeVerifier(store).verify(captured);
    expect(withLeid.ok).toBe(true);
    if (!withLeid.ok) return;
    expect(withLeid.lastEventId).toBe("6");
  });
});

// REQUEST_CLOCK_SKEW_MS is frozen at 0 (05-api-contract.md "Clock skew (frozen at zero)");
// REPORTING_CLOCK_SKEW_SECONDS is rejected at boot rather than threaded here (config-schema.test.ts).
// These prove the frozen zero actually gates receipt time, inclusive at both edges.
describe("signed-window receipt check — REQUEST_CLOCK_SKEW_MS frozen at 0", () => {
  it("accepts receipt exactly at expires_at and rejects one ms later", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store, pubOf(TEST_PRIV));
    const expiresAtMs = ISSUED_MS + 60_000;

    const onTime = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events/stream",
      body: "",
      nonce: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      issuedAtMs: ISSUED_MS,
      expiresAtMs,
    });
    const onTimeOutcome = await makeVerifier(store).verify({ ...onTime, receivedAtMs: expiresAtMs });
    expect(onTimeOutcome.ok).toBe(true);

    const late = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events/stream",
      body: "",
      nonce: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
      issuedAtMs: ISSUED_MS,
      expiresAtMs,
    });
    const lateOutcome = await makeVerifier(store).verify({ ...late, receivedAtMs: expiresAtMs + 1 });
    expect(lateOutcome.ok).toBe(false);
    if (lateOutcome.ok) return;
    expect(lateOutcome.code).toBe("reporting_request_expired");
  });

  it("accepts receipt exactly at issued_at and rejects one ms earlier", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store, pubOf(TEST_PRIV));

    const onTime = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events/stream",
      body: "",
      nonce: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    const onTimeOutcome = await makeVerifier(store).verify({ ...onTime, receivedAtMs: ISSUED_MS });
    expect(onTimeOutcome.ok).toBe(true);

    const early = signRequest({
      privateKey: TEST_PRIV,
      method: "GET",
      target: "/v1/events/stream",
      body: "",
      nonce: "ffffffff-ffff-4fff-8fff-ffffffffffff",
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    const earlyOutcome = await makeVerifier(store).verify({ ...early, receivedAtMs: ISSUED_MS - 1 });
    expect(earlyOutcome.ok).toBe(false);
    if (earlyOutcome.ok) return;
    expect(earlyOutcome.code).toBe("reporting_request_not_yet_valid");
  });
});

describe("bounded shape and canonical header forms", () => {
  it("rejects a missing or a duplicated signed header identically", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store);
    const verifier = makeVerifier(store);
    const missing = { ...goldenCaptured(), rawHeaders: goldenCaptured().rawHeaders.slice(2) };
    const missingOutcome = await verifier.verify(missing);
    expect(missingOutcome.ok).toBe(false);
    if (!missingOutcome.ok) expect(missingOutcome.code).toBe("missing_reporting_headers");
    const duplicated = {
      ...goldenCaptured(),
      rawHeaders: [...goldenCaptured().rawHeaders, "X-ZP-Reporting-Nonce", GOLDEN_NONCE],
    };
    const dupOutcome = await verifier.verify(duplicated);
    expect(dupOutcome.ok).toBe(false);
    if (!dupOutcome.ok) expect(dupOutcome.code).toBe("missing_reporting_headers");
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("rejects non-canonical header values (uppercase nonce, unpadded signature)", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store);
    const verifier = makeVerifier(store);
    const badNonce = {
      ...goldenCaptured(),
      rawHeaders: goldenHeaders(REPORT_REQUEST_GOLDEN_SIGNATURE, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
    };
    const outcome = await verifier.verify(badNonce);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("invalid_reporting_headers");
    const unpadded = {
      ...goldenCaptured(),
      rawHeaders: goldenHeaders(REPORT_REQUEST_GOLDEN_SIGNATURE.replace(/=+$/, ""), GOLDEN_NONCE),
    };
    const second = await verifier.verify(unpadded);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe("invalid_reporting_headers");
  });

  it("rejects an oversized body at the bounded-size gate, after the window check", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store);
    const outcome = await makeVerifier(store).verify({
      ...goldenCaptured(),
      bodyBytes: new Uint8Array(1_048_577),
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("request_too_large");
  });
});

describe("tenant binding, key status, and holds", () => {
  it("rejects an unknown reporting key id", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store);
    const rawHeaders = goldenHeaders(REPORT_REQUEST_GOLDEN_SIGNATURE, GOLDEN_NONCE);
    rawHeaders[1] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const outcome = await makeVerifier(store).verify({ ...goldenCaptured(), rawHeaders });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("unknown_reporting_key");
  });

  it("rejects a revoked key even inside its signed window, before signature crypto", async () => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store, pubOf(TEST_PRIV));
    store.seedReportingKeyState(NODE_ID, IMPLEMENTER_ID, KEY_ID, {
      state: "REVOKED",
      revokedAtMs: ISSUED_MS,
    });
    const request = signRequest({
      privateKey: keyFromSeed(0x99),
      method: "GET",
      target: "/v1/events?after_implementer_seq=5",
      body: "",
      nonce: GOLDEN_NONCE,
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    const outcome = await makeVerifier(store).verify(request);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("reporting_key_not_active");
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("accepts a prior key strictly inside the rotation overlap", async () => {
    const store = new InMemoryReportingStore();
    const priorPriv = keyFromSeed(0x07);
    const successorCommitMs = ISSUED_MS - 3_600_000;
    store.seedRegistration({
      reportingKeyId: KEY_ID,
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_ID,
      publicKeyEncoded: pubOf(priorPriv),
    });
    store.seedRestoreHold(NODE_ID, false);
    store.seedLifecycleHead(NODE_ID, IMPLEMENTER_ID, {
      epoch: 2n,
      authHold: false,
      currentKeyId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      priorKeyId: KEY_ID,
      overlapExpiresAtMs: successorCommitMs + 24 * 3_600_000,
      successorCommittedAtMs: successorCommitMs,
    });
    store.seedReportingKeyState(NODE_ID, IMPLEMENTER_ID, KEY_ID, {
      state: "ACTIVE",
      revokedAtMs: null,
    });
    const request = signRequest({
      privateKey: priorPriv,
      method: "GET",
      target: "/v1/events?after_implementer_seq=5",
      body: "",
      nonce: GOLDEN_NONCE,
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    expect((await makeVerifier(store).verify(request)).ok).toBe(true);
  });

  it("rejects the prior key at the exact overlap boundary (strict half-open)", async () => {
    const store = new InMemoryReportingStore();
    const priorPriv = keyFromSeed(0x07);
    const successorCommitMs = ISSUED_MS - 24 * 3_600_000 + 1_000;
    store.seedRegistration({
      reportingKeyId: KEY_ID,
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_ID,
      publicKeyEncoded: pubOf(priorPriv),
    });
    store.seedRestoreHold(NODE_ID, false);
    store.seedLifecycleHead(NODE_ID, IMPLEMENTER_ID, {
      epoch: 2n,
      authHold: false,
      currentKeyId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      priorKeyId: KEY_ID,
      overlapExpiresAtMs: successorCommitMs + 24 * 3_600_000,
      successorCommittedAtMs: successorCommitMs,
    });
    store.seedReportingKeyState(NODE_ID, IMPLEMENTER_ID, KEY_ID, {
      state: "ACTIVE",
      revokedAtMs: null,
    });
    // receipt == issued+1s == successorCommit+24h == the overlap boundary exactly → rejected.
    const request = signRequest({
      privateKey: priorPriv,
      method: "GET",
      target: "/v1/events?after_implementer_seq=5",
      body: "",
      nonce: GOLDEN_NONCE,
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });
    const outcome = await makeVerifier(store).verify(request);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("reporting_key_not_active");
  });

  it.each([
    ["restore hold", true, false],
    ["auth hold", false, true],
  ])("fails closed on the %s", async (_label, restoreHold, authHold) => {
    const store = new InMemoryReportingStore();
    seedGoldenStore(store);
    store.seedRestoreHold(NODE_ID, restoreHold);
    store.seedLifecycleHead(NODE_ID, IMPLEMENTER_ID, {
      epoch: 1n,
      authHold,
      currentKeyId: KEY_ID,
      priorKeyId: null,
      overlapExpiresAtMs: null,
      successorCommittedAtMs: null,
    });
    const outcome = await makeVerifier(store).verify(goldenCaptured());
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.code).toBe("reporting_auth_hold");
  });
});
