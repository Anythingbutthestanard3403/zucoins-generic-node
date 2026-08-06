// RUNTIME adversarial attacks on the reporting KEY-LIFECYCLE (rotation
// overlap, revoke-to-zero, restart/epoch). Companion to reporting-attack-suite.test.ts (nonce +
// tenant-binding attacks) and reporting-attack-suite-events.test.ts (event stream). Drives the
// live createReportingRequestVerifier pipeline and the InMemoryReportingStore burn transaction,
// asserting each attack fails CLOSED with the exact typed rejection — never a shape assertion.
//
// Platform holds zero keys (rotation
// overlap, strict half-open [successor_commit, +24h)); (atomic burn + epoch recheck);
// reporting-behavior/CONTRACT.md (reject/hard-stop/alarm outcome per dimension).

import { describe, expect, it } from "vitest";

import { InMemoryReportingStore } from "./in-memory-store.js";
import type { CapturedReportRequest, ReportingVerifyOutcome } from "./request-verifier.js";
import type { ReportingNonceEvidence } from "./store.js";
import {
  GOLDEN_NONCE,
  IMPLEMENTER_ID,
  ISSUED_MS,
  KEY_ID,
  keyFromSeed,
  makeVerifier,
  NODE_ID,
  pubOf,
  seedGoldenStore,
  signRequest,
  TEST_KEY_SEED,
} from "./test-fixtures.js";

const TEST_PRIV = keyFromSeed(TEST_KEY_SEED);
const OVERLAP_HOURS_MS = 24 * 3_600_000;

function seededStore(): InMemoryReportingStore {
  const store = new InMemoryReportingStore();
  seedGoldenStore(store, pubOf(TEST_PRIV));
  return store;
}

const validRequest = (nonce: string = GOLDEN_NONCE): CapturedReportRequest =>
  signRequest({
    privateKey: TEST_PRIV,
    method: "GET",
    target: "/v1/events?after_implementer_seq=5",
    body: "",
    nonce,
    issuedAtMs: ISSUED_MS,
    expiresAtMs: ISSUED_MS + 60_000,
  });

const rejectionOf = (outcome: ReportingVerifyOutcome): string | null =>
  outcome.ok ? null : outcome.code;

// --------------------------------------------------------------------------
// Attack 4 — key rotation / prior-key overlap: no forgery via the overlap window.
// --------------------------------------------------------------------------

describe("ATTACK 4: key rotation and prior-key overlap window", () => {
  const priorPriv = keyFromSeed(0x07);

  function rotatedStore(input: {
    readonly successorCommittedAtMs: number;
    readonly priorKeyState?: "ACTIVE" | "RETIRED" | "REVOKED";
    readonly revokedAtMs?: number | null;
  }): InMemoryReportingStore {
    const store = new InMemoryReportingStore();
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
      overlapExpiresAtMs: input.successorCommittedAtMs + OVERLAP_HOURS_MS,
      successorCommittedAtMs: input.successorCommittedAtMs,
    });
    store.seedReportingKeyState(NODE_ID, IMPLEMENTER_ID, KEY_ID, {
      state: input.priorKeyState ?? "ACTIVE",
      revokedAtMs: input.revokedAtMs ?? null,
    });
    return store;
  }

  const priorKeyRequest = (): CapturedReportRequest =>
    signRequest({
      privateKey: priorPriv,
      method: "GET",
      target: "/v1/events?after_implementer_seq=5",
      body: "",
      nonce: GOLDEN_NONCE,
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
    });

  it("accepts the rotated-out prior key STRICTLY inside the overlap window (per)", async () => {
    const store = rotatedStore({ successorCommittedAtMs: ISSUED_MS - 3_600_000 });
    expect((await makeVerifier(store).verify(priorKeyRequest())).ok).toBe(true);
  });

  it("rejects the prior key AT the half-open overlap boundary (no one-second-over forgery)", async () => {
    // receipt (issued + 1s) == successorCommit + 24h == the exact exclusive boundary → rejected.
    const store = rotatedStore({ successorCommittedAtMs: ISSUED_MS - OVERLAP_HOURS_MS + 1_000 });
    const outcome = await makeVerifier(store).verify(priorKeyRequest());
    expect(rejectionOf(outcome)).toBe("reporting_key_not_active");
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("rejects a prior key that was revoked, even inside the overlap window", async () => {
    const store = rotatedStore({
      successorCommittedAtMs: ISSUED_MS - 3_600_000,
      priorKeyState: "REVOKED",
      revokedAtMs: ISSUED_MS - 1_800_000,
    });
    const outcome = await makeVerifier(store).verify(priorKeyRequest());
    expect(rejectionOf(outcome)).toBe("reporting_key_not_active");
  });
});

// --------------------------------------------------------------------------
// Attack 5 — revoke-to-zero: revoking the active key raises the fail-closed hard-stop
// (reject, never a silent accept). reporting-behavior/CONTRACT.md hard-stop/alarm dimension.
// --------------------------------------------------------------------------

describe("ATTACK 5: revoke-to-zero active keys is a fail-closed hard-stop", () => {
  it("denies an otherwise-valid request once the current key is revoked, writing no burn", async () => {
    const store = seededStore();
    store.seedReportingKeyState(NODE_ID, IMPLEMENTER_ID, KEY_ID, {
      state: "REVOKED",
      revokedAtMs: ISSUED_MS,
    });
    const outcome = await makeVerifier(store).verify(validRequest());
    expect(rejectionOf(outcome)).toBe("reporting_key_not_active");
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("denies every request when the head carries NO active key (currentKeyId === null)", async () => {
    const store = seededStore();
    store.seedLifecycleHead(NODE_ID, IMPLEMENTER_ID, {
      epoch: 1n,
      authHold: false,
      currentKeyId: null,
      priorKeyId: null,
      overlapExpiresAtMs: null,
      successorCommittedAtMs: null,
    });
    const outcome = await makeVerifier(store).verify(validRequest());
    expect(rejectionOf(outcome)).toBe("reporting_key_not_active");
    expect(store.listNonceEvidence().length).toBe(0);
  });
});

// --------------------------------------------------------------------------
// Attack 6 — restart / epoch: a restart re-holds (no silent resume) and a stale epoch cannot
// re-drive a burn (no cross-epoch replay). RESTORE_POLICY + the burn's under-lock epoch recheck.
// --------------------------------------------------------------------------

describe("ATTACK 6: restart and epoch hard-stop", () => {
  it("a restarted node with no restore-state row is hard-held (no silent resume)", async () => {
    const store = new InMemoryReportingStore();
    // Seed the binding/head/key but NOT the restore hold: RESTORE_POLICY makes a node with no
    // seeded restore-state row default to hard-held, so a previously-valid request now fails closed.
    store.seedRegistration({
      reportingKeyId: KEY_ID,
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_ID,
      publicKeyEncoded: pubOf(TEST_PRIV),
    });
    store.seedLifecycleHead(NODE_ID, IMPLEMENTER_ID, {
      epoch: 1n,
      authHold: false,
      currentKeyId: KEY_ID,
      priorKeyId: null,
      overlapExpiresAtMs: null,
      successorCommittedAtMs: null,
    });
    store.seedReportingKeyState(NODE_ID, IMPLEMENTER_ID, KEY_ID, { state: "ACTIVE", revokedAtMs: null });
    const outcome = await makeVerifier(store).verify(validRequest());
    expect(rejectionOf(outcome)).toBe("reporting_auth_hold");
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("a burn carrying a stale epoch is rejected by the under-lock recheck (no cross-epoch replay)", async () => {
    const store = seededStore();
    const verified = await makeVerifier(store).verify(validRequest()); // admitted at epoch 1
    expect(verified.ok).toBe(true);
    if (!verified.ok) return;
    // Re-present at the store with a bumped epoch and a fresh nonce: the head is still epoch 1, so
    // the recheck fails BEFORE the unique insert — the stale-epoch request writes nothing.
    const crossEpoch: ReportingNonceEvidence = {
      ...verified.nonceEvidence,
      nonce: "88888888-8888-4888-8888-888888888888",
    };
    const outcome = await store.burnNonceAtomically({
      expectedEpoch: verified.nonceEvidence.lifecycleEpoch + 1n,
      evidence: crossEpoch,
    });
    expect(outcome.kind).toBe("LIFECYCLE_RECHECK_FAILED");
    expect(store.listNonceEvidence().length).toBe(1);
  });
});
