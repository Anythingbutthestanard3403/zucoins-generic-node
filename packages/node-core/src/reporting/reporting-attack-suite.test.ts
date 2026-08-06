// the RUNTIME adversarial attack suite for the signed reporting REQUEST
// pipeline: nonce-burn durability and the key_status→tenant→signature verifier
// sequence. It feeds the actual breaking inputs through the live seams
// createReportingRequestVerifier (request-verifier.ts), admitReportingKey (admission.ts), and the
// InMemoryReportingStore burn transaction (in-memory-store.ts / the frozen burn contract
// in store.ts) — and asserts each attack fails CLOSED with the exact typed rejection at the
// correct stage, never a happy-path shape assertion. Mirrors the driving suite
// (verifier/attack-vectors.test.ts): the byte-freeze of the tuples lives one-way in the contracts
// package (reporting-tuples/*), this file drives runtime BEHAVIOR.
//
// Companions: reporting-attack-suite-lifecycle.test.ts (rotation/revoke/restart-epoch) and
// reporting-attack-suite-events.test.ts (zp-node-event-v1 stream). The frozen-shape structural
// cells stay in the contracts package (reporting-tuples/reporting-attack-suite.test.ts), which
// never imports node-core.
//
// Covers PRE_BURN_CHECKS and the atomic-burn contract, the verifier sequence, and the signed
// pull event stream. Two rules carry the suite: signing is byte-exact — the preimage is
// rebuilt by the frozen builder ONLY, from the registration binding, never from
// request-supplied tenant fields — and a submit is never blind-retried.

import { describe, expect, it } from "vitest";

import {
  buildReportRequestPreimage,
  REPORT_REQUEST_CANONICAL_VERSION,
  REPORT_REQUEST_PURPOSE,
} from "@zucoins/generic-node-contracts";

import { sha256HexUtf8 } from "./ed25519.js";
import { InMemoryReportingStore } from "./in-memory-store.js";
import type { CapturedReportRequest, ReportingVerifyOutcome } from "./request-verifier.js";
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
  signPadded,
  signRequest,
  TEST_KEY_SEED,
} from "./test-fixtures.js";

const TEST_PRIV = keyFromSeed(TEST_KEY_SEED);
const FOREIGN_NODE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const FOREIGN_IMPLEMENTER_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

function seededStore(): InMemoryReportingStore {
  const store = new InMemoryReportingStore();
  seedGoldenStore(store, pubOf(TEST_PRIV));
  return store;
}

// A GET reporting request over the query route, signed by TEST_PRIV — genuinely valid against a
// seededStore. The nonce defaults to the golden nonce so a second identical delivery is a replay
// of a burned nonce.
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

// The forgery capture: the attacker SIGNS a preimage embedding a foreign tenant (node_id /
// implementer_id) but presents KEY_ID, which is bound to (NODE_ID, IMPLEMENTER_ID). The runtime
// rebuilds the preimage from the binding, so the attacker's signature is over different bytes
// authorization can never derive from request-supplied tenant fields.
function forgedTenantCapture(overrides: {
  readonly nodeId?: string;
  readonly implementerId?: string;
}): CapturedReportRequest {
  const issuedAt = new Date(ISSUED_MS).toISOString();
  const expiresAt = new Date(ISSUED_MS + 60_000).toISOString();
  const preimage = buildReportRequestPreimage({
    purpose: REPORT_REQUEST_PURPOSE,
    canonical_version: REPORT_REQUEST_CANONICAL_VERSION,
    node_id: overrides.nodeId ?? NODE_ID,
    implementer_id: overrides.implementerId ?? IMPLEMENTER_ID,
    method: "GET",
    path: "/v1/events?after_implementer_seq=5",
    body_sha256: sha256HexUtf8(""),
    nonce: GOLDEN_NONCE,
    issued_at: issuedAt,
    expires_at: expiresAt,
  });
  return {
    method: "GET",
    rawTarget: "/v1/events?after_implementer_seq=5",
    rawHeaders: [
      "X-ZP-Reporting-Key-Id", KEY_ID,
      "X-ZP-Reporting-Timestamp", issuedAt,
      "X-ZP-Reporting-Expires-At", expiresAt,
      "X-ZP-Reporting-Nonce", GOLDEN_NONCE,
      "X-ZP-Reporting-Signature", signPadded(preimage, TEST_PRIV),
    ],
    bodyBytes: new TextEncoder().encode(""),
    receivedAtMs: ISSUED_MS + 1_000,
  };
}

const rejectionOf = (outcome: ReportingVerifyOutcome): string | null =>
  outcome.ok ? null : outcome.code;

// --------------------------------------------------------------------------
// Attack 1 — duplicate-event nonce: nonce-burn durability against replay.
// --------------------------------------------------------------------------

describe("ATTACK 1: duplicate-event nonce (nonce-burn durability)", () => {
  it("rejects a byte-identical re-delivery of a burned nonce with nonce_replay, one burn retained", async () => {
    const store = seededStore();
    const verifier = makeVerifier(store);
    const first = await verifier.verify(validRequest());
    expect(first.ok).toBe(true);
    const replay = await verifier.verify(validRequest());
    expect(rejectionOf(replay)).toBe("nonce_replay");
    // Durability: the first burn persisted and is the ONLY evidence row; the replay wrote nothing.
    expect(store.listNonceEvidence().length).toBe(1);
    expect(store.listNonceEvidence()[0]!.nonce).toBe(GOLDEN_NONCE);
  });

  it("the store burn transaction itself is the authoritative replay guard (REPLAY on the unique insert)", async () => {
    const store = seededStore();
    // Derive a real, admitted evidence row from a live burn, then re-present the SAME
    // (node, implementer, nonce) directly at the frozen unique insert.
    const verified = await makeVerifier(store).verify(validRequest());
    expect(verified.ok).toBe(true);
    if (!verified.ok) return;
    const outcome = await store.burnNonceAtomically({
      expectedEpoch: verified.nonceEvidence.lifecycleEpoch,
      evidence: verified.nonceEvidence,
    });
    expect(outcome.kind).toBe("REPLAY");
    expect(store.listNonceEvidence().length).toBe(1);
  });
});

// --------------------------------------------------------------------------
// Attack 3 — tenant-binding sequence: key_status -> tenant/binding -> signature.
// --------------------------------------------------------------------------

describe("ATTACK 3: verification sequence key_status -> tenant/binding -> signature", () => {
  it("a revoked key with an invalid signature fails at key_status, not signature (key_status precedes crypto)", async () => {
    const store = seededStore();
    store.seedReportingKeyState(NODE_ID, IMPLEMENTER_ID, KEY_ID, {
      state: "REVOKED",
      revokedAtMs: ISSUED_MS,
    });
    // Signed by the WRONG key, so the signature would also fail — key_status must short-circuit first.
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
    expect(rejectionOf(outcome)).toBe("reporting_key_not_active");
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("an unknown key with an invalid signature fails at binding resolution, not signature", async () => {
    const store = seededStore();
    const request = signRequest({
      privateKey: keyFromSeed(0x99),
      method: "GET",
      target: "/v1/events?after_implementer_seq=5",
      body: "",
      nonce: GOLDEN_NONCE,
      issuedAtMs: ISSUED_MS,
      expiresAtMs: ISSUED_MS + 60_000,
      keyId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    });
    const outcome = await makeVerifier(store).verify(request);
    expect(rejectionOf(outcome)).toBe("unknown_reporting_key");
    expect(store.listNonceEvidence().length).toBe(0);
  });

  it("a forged foreign node_id or implementer_id cannot authenticate — auth derives from the binding, not the tuple", async () => {
    // Control: the same harness with the TRUE tenant is admitted — proving the rejections below are
    // caused by the tenant forgery, not a broken harness.
    expect((await makeVerifier(seededStore()).verify(forgedTenantCapture({}))).ok).toBe(true);

    const forgedNode = await makeVerifier(seededStore()).verify(
      forgedTenantCapture({ nodeId: FOREIGN_NODE_ID }),
    );
    expect(rejectionOf(forgedNode)).toBe("invalid_signature");
    const forgedImplementer = await makeVerifier(seededStore()).verify(
      forgedTenantCapture({ implementerId: FOREIGN_IMPLEMENTER_ID }),
    );
    expect(rejectionOf(forgedImplementer)).toBe("invalid_signature");
  });
});

// --------------------------------------------------------------------------
// Cross-runtime coverage note (NOT one of the six node-core runtime attacks).
// --------------------------------------------------------------------------

describe("cross-runtime: operator opt-out", () => {
  // Operator opt-out enforcement is NOT a node-core reporting-runtime concern: the
  // platform ingest verifier FAILS CLOSED when nodes.reporting_opt_in is false, and the
  // node-side gate is on the pusher worker (reporting_state.enabled), not this request pipeline.
  // node-core's dependency boundary forbids importing the platform ingest runtime, so the opt-out
  // attack belongs to a platform-side suite. Tracked separately; intentionally left as a marker.
  it.todo("platform ingest rejects a report from an opted-out node (event stream design) — platform-side runtime");
});
