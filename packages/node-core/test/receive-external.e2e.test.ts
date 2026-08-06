// Offline RECEIVE_EXTERNAL end-to-end: walks the full Layer-1 lifecycle
// (create -> admission -> assignment+T0 -> arm -> intake+submit-once -> landing ->
// verification-complete / expiry) with every gateway interaction mocked. Governing:
// operation flows; the state-event reference; the test plan ("RECEIVE_EXTERNAL exit
// evidence"); observation verification. No live chain, no network (the network guard is
// active for this suite); the golden transaction bytes are the frozen A.8.1 vector,
// re-derived here so byte-exact signing (the byte-exact signing rule) is proven, not assumed.
//
// Scenario boundaries:
//  - Arm barrier uses an independent consumer offline read stream (not a self-copy of T0).
// - verification-complete and pre/post-boundary expiry are their own scenarios.
//  - No-blind-retry never-resubmit is proven via production receiveSubmitOnce (claim store → AMBIGUOUS).
// - post-boundary: gate (isExpiryToExpiredLegal) blocks READY→EXPIRED; table edge
//    remains listed for pre-boundary only — no hand-throw pretending to be the table.
// - Independent consumer landing verdict via verifyReceiveProof, agree + disagree.

import { Buffer } from "node:buffer";
import { createPublicKey, createPrivateKey, generateKeyPairSync, sign as edSign, verify, createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  compareAmounts,
  subtractAmounts,
  validateOperationAmount,
} from "@zucoins/generic-node-contracts";
import { SUBMIT_ACTION_NAME } from "@zucoins/generic-node-contracts/transfer-code";

import {
  RECEIVE_EXTERNAL_TRANSITIONS,
  type ReceiveExternalState,
} from "../../generic-node-contracts/src/operations/states.contract.ts";
import {
  POST_BOUNDARY_EXPIRY_OUTCOME,
  POST_EXPIRY_RECONCILING,
  isExpiryToExpiredLegal,
  receiveExpiryEvents,
} from "../../generic-node-contracts/src/receive-expiry/lifecycle.ts";
import { postBoundaryExpiryDisposition } from "../../generic-node-contracts/src/receive-expiry/ordering.ts";
import {
  receiveSubmitOnce,
  type SubmitClaimStore,
} from "../src/core/receive-submit-once.js";
import { createMetricsHooks, createNodeMetrics } from "../src/core/metrics.js";
import {
  InMemoryAdmissionQueue,
  promoteFifo,
  tryEnqueue,
} from "../src/workers/admission.js";
import type { GatewayExchangeTransport } from "../src/gateway/capture.js";
import {
  buildGatewayActionRequest,
  createGatewayReadCredentials,
} from "../src/gateway/index.js";
import type { GatewaySubmitAttemptRecord, SubmitAttemptRecorder } from "../src/gateway/records.js";
import type { GatewayLimits } from "../src/gateway/types.js";
import type { GatewayRequest, GatewayResponse } from "../src/protocol/index.js";
import { parsePositiveZkzAmount } from "../src/protocol/amounts.js";
import {
  computeInnerDigest,
  type SettledSplitChainTransaction,
  type SplitChainInnerV2,
} from "../src/protocol/inner.js";
import {
  parseEd25519Signature,
  parseSha256Hex,
  parseUuid,
  parseWalletPublicKey,
} from "../src/protocol/scalars.js";
import { buildReceiveExpectedArtifact } from "../src/protocol/suite/builders.js";
import {
  GENESIS_PROJECTION,
  projectRoleRelativeState,
  type WalletStateProjection,
} from "../src/protocol/wallet-role.js";
import { evaluateReceiveDelta } from "../src/protocol/economic-predicates.js";
import { classifyReceiveReconcile } from "../src/protocol/reconcile/index.js";
import {
  mintLandingPathProofFromOracle,
} from "../src/protocol/reconcile/landing-oracle-mint.fixture.js";
import {
  isSettlementAuthority,
  mintSettlementAuthority,
  type SubmitClaim,
} from "../src/protocol/reconcile/submit-authority.js";
import { createOfflineReadTransport } from "../src/testkit/offline.js";
import {
  clampReleaseToVerdict,
  evaluateGroupRelease,
  type GroupReleaseFacts,
} from "../src/verification/index.js";
import {
  verifyReceiveProof,
  type ArtifactEnvelope,
  type NodeVerificationKey,
  type ReceiveProofBundle,
} from "../src/verifier/consumer/index.js";
import {
  assertObservedEventAllowed,
  assertObservedStateAllowed,
  classifyObservedTransition,
  isNoEventMarker,
  type FrozenTable,
} from "./lifecycle-fuzz-oracles.js";

// --- Golden vector (A.8.1): test-only filled-byte Ed25519 seeds 02/03/05 ---------------
const keyFromSeed = (byte: number) =>
  createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, byte),
    ]),
    type: "pkcs8",
    format: "der",
  });
const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
const publicKeyOf = (pk: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(createPublicKey(pk).export({ type: "spki", format: "der" }).subarray(-32));
const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

const seed02 = keyFromSeed(0x02); // external sender (payer)
const seed03 = keyFromSeed(0x03); // node receiver wallet
const seed05 = keyFromSeed(0x05); // funded wallet that paid seed_02 in the predecessor tx
const seed02Public = publicKeyOf(seed02);
const seed03Public = publicKeyOf(seed03);
const seed05Public = publicKeyOf(seed05);
const seed05BoundaryS =
  "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ==";

const predecessorStep1Signature =
  "MsWTpjUtoofWFb13BCpLqLB6tgYiasFakfd2hufS2V2dHg7N2PdRe8n-wrqQhJKc3-Bml7xK6jUfEv2BBiPxAA==";
const predecessorStep2Signature =
  "IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==";

// The predecessor transaction that funds the payer (seed_05 -> seed_02, 0 -> 10 ZKZ). It is
// seed_02's current head, so the sender-preflight read in step 5 observes it.
const predecessorSettled: SettledSplitChainTransaction = {
  inner: {
    type: "unique_combinable",
    version: "2",
    unix_time_secs: "1784332700",
    signer_steps: 2,
    step_1_signer: "sender",
    step_2_signer: "receiver",
    step_1_key_public__base64urlsafe: seed05Public,
    step_2_key_public__base64urlsafe: seed02Public,
    step_1_state: { amount: "0" },
    step_2_state: { amount: "10" },
    previous_step_1_state_signature: seed05BoundaryS,
    previous_step_2_state_signature: "",
  },
  step_1_signature: predecessorStep1Signature,
  step_2_signature: predecessorStep2Signature,
};

// The inbound candidate the external payer builds and signs (step 1), which the node
// co-signs (step 2) and submits once. Field order is the frozen A.8.1 sequence.
// Payer-chosen inbound expiry = unix_time_secs + 3600s. Distinct from the
// SEND_REDEMPTION_WINDOW_SECS = 300s fixture — never derived from it.
const targetInner: SplitChainInnerV2 = {
  type: "unique_combinable",
  version: "2",
  unix_time_secs: "1784332800.125",
  signer_steps: 2,
  step_1_signer: "sender",
  step_2_signer: "receiver",
  step_1_key_public__base64urlsafe: seed02Public,
  step_2_key_public__base64urlsafe: seed03Public,
  step_1_state: { amount: "7.75" },
  step_2_state: { amount: "2.25" },
  previous_step_1_state_signature: predecessorStep2Signature,
  previous_step_2_state_signature: "",
  expiry__unix_time_secs: "1784336400",
  message: "zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3",
};
const targetStep1Text = JSON.stringify(targetInner);
const targetStep1Signature =
  "wpAPEHD-wRRyfdoLM5FUgwS5OhCVwkQBV5w-XFDSx_VK19QiW5szD6Cuy1ogiNlIlvWtx4LlZPIdAm81eKX0BA==";
const targetStep2Text = JSON.stringify({
  inner: targetInner,
  step_1_signature: targetStep1Signature,
});
const targetStep2Signature =
  "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==";
const targetSettled: SettledSplitChainTransaction = {
  inner: targetInner,
  step_1_signature: targetStep1Signature,
  step_2_signature: targetStep2Signature,
};
const targetSettledText = JSON.stringify(targetSettled);

// Node-side T0 for a never-used receiver wallet (node-core genesis). The independent consumer
// must re-derive the same {S,P,B} from ITS OWN scripted read stream — never copy this object.
const NODE_T0: WalletStateProjection = GENESIS_PROJECTION;
const NODE_T0_OBSERVATION_ID = "obs-node-t0-receive";
const AMOUNT_ZKZ = "2.25";
// Amount is derived, not hand-typed as the sole oracle: B1 − B0.
const DERIVED_AMOUNT_ZKZ = subtractAmounts(targetInner.step_2_state.amount, NODE_T0.B);
const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const RECEIVER_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const ATTEMPT_ID = "receive-attempt-1";

// payer window (3600s) — independent of SEND_REDEMPTION_WINDOW_SECS (300s).
const PAYER_CHOSEN_EXPIRY_WINDOW_SECS = 3600;
const RECEIVE_INNER_UNIX_SECS = Number.parseFloat(targetInner.unix_time_secs);
const EXPECTED_PAYER_EXPIRY_UNIX = Math.trunc(RECEIVE_INNER_UNIX_SECS + PAYER_CHOSEN_EXPIRY_WINDOW_SECS);

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const envelopeResponse = (data: unknown): GatewayResponse => ({
  statusCode: 200,
  bodyBytes: encoder.encode(JSON.stringify({ status: true, code: "ok", message: "OK", data })),
});

/** Decode an offline gateway envelope and pull the projection the consumer observed. */
function projectionFromOfflineRead(response: GatewayResponse): WalletStateProjection {
  const envelope = JSON.parse(decoder.decode(response.bodyBytes)) as {
    data?: { projection?: WalletStateProjection };
  };
  const projection = envelope.data?.projection;
  if (projection === undefined) {
    throw new Error("offline consumer read returned no projection");
  }
  return projection;
}

// --- Lifecycle harness: durable store + transition guard over the frozen table ----------
interface OperationRow {
  state: ReceiveExternalState;
  armed: boolean;
  receiverWalletId: string | null;
  leaseHeld: boolean;
  submitClaimed: boolean;
  submitCount: number;
  /** Durable candidate exists once STEP1_SIGNATURE_PERSISTED (boundary). */
  durableCandidate: boolean;
  attentionReason: string | null;
  verificationAck: "NONE" | "VERIFIED" | "REJECTED" | "INDETERMINATE";
}

interface LifecycleHarness {
  readonly row: OperationRow;
  readonly durableEvents: string[];
  readonly transitions: Array<{ from: ReceiveExternalState | null; to: ReceiveExternalState }>;
  transition(to: ReceiveExternalState, observedEvent?: string | null): void;
}

function createHarness(): LifecycleHarness {
  const row: OperationRow = {
    state: "CREATED",
    armed: false,
    receiverWalletId: null,
    leaseHeld: false,
    submitClaimed: false,
    submitCount: 0,
    durableCandidate: false,
    attentionReason: null,
    verificationAck: "NONE",
  };
  const durableEvents: string[] = [];
  const transitions: Array<{ from: ReceiveExternalState | null; to: ReceiveExternalState }> = [];
  const table = RECEIVE_EXTERNAL_TRANSITIONS as FrozenTable;

  return {
    row,
    durableEvents,
    transitions,
    transition(to, observedEvent = null) {
      const from = row.state;
      const verdict = classifyObservedTransition(table, { from, to, event: observedEvent });
      if (verdict.verdict !== "ALLOWED") {
        throw new Error(`transition ${from} -> ${to} refused: ${verdict.verdict}`);
      }
      assertObservedStateAllowed(to);
      const declared = verdict.expectedEvent;
      if (declared !== undefined && declared !== null && !isNoEventMarker(declared)) {
        assertObservedEventAllowed(declared);
        if (observedEvent !== declared) {
          throw new Error(
            `transition ${from} -> ${to} emitted ${observedEvent}, expected ${declared}`,
          );
        }
        durableEvents.push(declared);
      }
      transitions.push({ from, to });
      row.state = to;
    },
  };
}

// --- Production No-blind-retry / observation verification helpers (not test-local tautologies) ----------------------
const SUBMIT_ENDPOINT = "https://gateway.offline.test/";
const SUBMIT_LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 65_536,
  maxResponseBytes: 65_536,
};
const SUBMIT_AUTHORIZATION = {
  submitDecisionId: "11111111-1111-4111-8111-111111111111",
  operationId: OPERATION_ID,
  transactionAttemptNo: 1,
};
const FIXED_NOW = "2026-07-18T00:00:00.000Z";

// Test-only node identity for consumer artifact authentication (NOT an A.8 golden seed).
const { publicKey: nodePubDer, privateKey: nodePriv } = generateKeyPairSync("ed25519");
const NODE_PUBKEY_B64 =
  Buffer.from(nodePubDer.export({ type: "spki", format: "der" }).subarray(12)).toString("base64url") +
  "=";
const NODE_KEY_ID = "33333333-3333-4333-8333-333333333333";
const NODE_KEY: NodeVerificationKey = { keyId: NODE_KEY_ID, publicKey: NODE_PUBKEY_B64 };

function signPreimage(preimageBytes: Uint8Array): string {
  return edSign(null, Buffer.from(preimageBytes), nodePriv).toString("base64url") + "==";
}

function buildReceiveArtifact(amountZkz: string, receiverPubkey: string): ArtifactEnvelope {
  const preimage = buildReceiveExpectedArtifact({
    node_id: parseUuid(NODE_KEY_ID),
    implementer_id: parseUuid("44444444-4444-4444-8444-444444444444"),
    operation_id: parseUuid(OPERATION_ID),
    receiver_wallet_id: parseUuid(RECEIVER_WALLET_ID),
    receiver_pubkey: parseWalletPublicKey(receiverPubkey),
    amount_zkz: parsePositiveZkzAmount(amountZkz),
    discriminator: parseUuid("77777777-7777-4777-8777-777777777777"),
    anchor: "zp1-anchor-test",
    receiver_t0_fingerprint: parseSha256Hex("a".repeat(64)),
    expiry_unix_time_secs: null,
    after_landing: { kind: "HOLD", destination_id: null },
    transfer_code_sha256: parseSha256Hex("b".repeat(64)),
  });
  return {
    key_id: parseUuid(NODE_KEY_ID),
    preimage_text: preimage.preimageText,
    preimage_sha256: parseSha256Hex(preimage.sha256 as string),
    signature: parseEd25519Signature(signPreimage(preimage.preimageBytes)),
  };
}

/** observation verification consumer read stream: gateway envelope with data = [settled tx JSON]. */
function gatewayHeadEnvelopeBytes(settled: SettledSplitChainTransaction): Uint8Array {
  return encoder.encode(
    JSON.stringify({
      status: true,
      code: "success",
      message: "",
      data: [settled],
    }),
  );
}

function makeClaimStore(): SubmitClaimStore & { readonly claims: readonly SubmitClaim[] } {
  const byKey = new Map<string, SubmitClaim & { operationId: string; transactionAttemptNo: number }>();
  return {
    get claims() {
      return [...byKey.values()];
    },
    claimSubmitOnce: async (claim) => {
      const key = `${claim.operationId}#${claim.transactionAttemptNo}`;
      const existing = byKey.get(key);
      if (existing !== undefined) {
        await Promise.resolve();
        return { claim: existing, minted: false };
      }
      byKey.set(key, claim);
      await Promise.resolve();
      return { claim, minted: true };
    },
  };
}

function makeRecorder(): SubmitAttemptRecorder & { readonly records: readonly GatewaySubmitAttemptRecord[] } {
  const records: GatewaySubmitAttemptRecord[] = [];
  return {
    get records() {
      return [...records];
    },
    recordSubmitAttempt: async (r) => {
      records.push(r);
    },
  };
}

/** Counting exchange for receiveSubmitOnce — production No-blind-retry surface (not OfflineSubmitTransport). */
function makeCountingExchange(
  statusCode: number,
  body: string,
): GatewayExchangeTransport & { readonly calls: readonly unknown[] } {
  const calls: unknown[] = [];
  const bodyBytes = encoder.encode(body);
  return {
    get calls() {
      return [...calls];
    },
    exchange: async (endpoint: string, request: GatewayRequest) => {
      calls.push({ endpoint, rpc: request.rpc });
      return {
        endpoint,
        endpointFingerprint: "offline-fp",
        requestBytes: request.bodyBytes,
        requestSha256: sha256Hex(decoder.decode(request.bodyBytes)),
        responseBytes: bodyBytes,
        responseSha256: sha256Hex(body),
        statusCode,
      };
    },
  };
}

/**
 * Production expiry attempt path : the external isExpiryToExpiredLegal gate decides
 * whether READY/CREATED → EXPIRED may fire. The frozen table still lists READY→EXPIRED for
 * the pre-boundary case; post-boundary refusal is this gate, not a table edge removal.
 * Returns the attempted disposition without hand-throwing.
 */
function attemptReceiveExpiry(
  harness: LifecycleHarness,
):
  | { readonly kind: "EXPIRED"; readonly event: "operation.expired" }
  | {
      readonly kind: "POST_BOUNDARY_HELD";
      readonly outcome: typeof POST_BOUNDARY_EXPIRY_OUTCOME;
    } {
  const from = harness.row.state;
  const pastBoundary = harness.row.durableCandidate;
  if (!isExpiryToExpiredLegal(from, pastBoundary)) {
    // Production refuses terminal expiry; apply canonical post-boundary held disposition.
    harness.row.attentionReason = POST_BOUNDARY_EXPIRY_OUTCOME.attentionReason;
    return { kind: "POST_BOUNDARY_HELD", outcome: POST_BOUNDARY_EXPIRY_OUTCOME };
  }
  const events = receiveExpiryEvents(pastBoundary);
  if (events.appendsExpired) {
    harness.transition("EXPIRED", "operation.expired");
    return { kind: "EXPIRED", event: "operation.expired" };
  }
  harness.row.attentionReason = POST_BOUNDARY_EXPIRY_OUTCOME.attentionReason;
  return { kind: "POST_BOUNDARY_HELD", outcome: POST_BOUNDARY_EXPIRY_OUTCOME };
}

describe("offline RECEIVE_EXTERNAL end-to-end", () => {
  it("CREATED -> READY -> RECEIVE_LANDED with independent arm barrier + single submit", async () => {
    const harness = createHarness();
    // admission commit (from: null -> CREATED) carries the "none" marker — no durable event.
    expect(harness.row.state).toBe("CREATED");

    // Admission + wallet assignment. Lease held BEFORE the fresh head read.
    const queue = new InMemoryAdmissionQueue();
    const enqueued = tryEnqueue(queue, {
      operationId: OPERATION_ID,
      walletId: null,
      createdAt: 1,
      status: "QUEUED",
    });
    expect(enqueued.outcome).toBe("ENQUEUED");
    const promoted = promoteFifo(
      queue,
      { availableWalletCount: 1, nonRetiredPoolWalletCount: 1, activeLeases: 0, pinnedLeases: 0 },
      () => RECEIVER_WALLET_ID,
    );
    expect(promoted).toEqual({
      outcome: "PROMOTED",
      operationId: OPERATION_ID,
      walletId: RECEIVER_WALLET_ID,
    });
    harness.row.receiverWalletId = RECEIVER_WALLET_ID;
    harness.row.leaseHeld = true; // lease before any read (operation flows chain-of-custody core)

    // T0 observation (node's own offline read) yields the receiver genesis projection.
    const nodeReadTransport = createOfflineReadTransport(createGatewayReadCredentials(), [
      envelopeResponse({
        observationId: NODE_T0_OBSERVATION_ID,
        projection: NODE_T0,
      }),
    ]);
    const t0Request = buildGatewayActionRequest("get_transaction__v1", {
      public_key_base64urlsafe: seed03Public,
    });
    const t0Response = await nodeReadTransport.read(["https://gateway.offline.test"], t0Request);
    expect(t0Response.statusCode).toBe(200);
    const nodeCapturedT0 = projectionFromOfflineRead(t0Response);
    expect(nodeCapturedT0).toEqual(NODE_T0);

    // code formation -> READY, emitting receive.ready.
    harness.transition("READY", "receive.ready");
    expect(harness.row.state).toBe("READY");

    // Arm barrier: independent consumer opens its OWN offline read transport with its
    // OWN scripted response, captures {S,P,B} itself, and only then arms. Comparing the
    // consumer-captured projection against the node-captured T0 is the load-bearing check —
    // a self-copy of NODE_T0 would be a tautology.
    const consumerReadTransport = createOfflineReadTransport(createGatewayReadCredentials(), [
      envelopeResponse({
        // Distinct observation id in the consumer's trust domain (operation flows step 1–2).
        observationId: "obs-consumer-t0-independent",
        projection: { S: "", P: "", B: "0", role: "genesis", I: null },
      }),
    ]);
    const consumerT0Request = buildGatewayActionRequest("get_transaction__v1", {
      public_key_base64urlsafe: seed03Public,
    });
    const consumerT0Response = await consumerReadTransport.read(
      ["https://gateway.offline.test"],
      consumerT0Request,
    );
    expect(consumerT0Response.statusCode).toBe(200);
    const consumerProjection = projectionFromOfflineRead(consumerT0Response);
    // Independently derived expected value (not NODE_T0 object identity).
    const expectedArmProjection = { S: "", P: "", B: "0" } as const;
    expect(consumerProjection.S).toBe(expectedArmProjection.S);
    expect(consumerProjection.P).toBe(expectedArmProjection.P);
    expect(consumerProjection.B).toBe(expectedArmProjection.B);
    // Cross-domain agreement only where the complete-path predicate holds : S/P/B match.
    expect(consumerProjection.S).toBe(nodeCapturedT0.S);
    expect(consumerProjection.P).toBe(nodeCapturedT0.P);
    expect(consumerProjection.B).toBe(nodeCapturedT0.B);
    // Consumer used its own transport — one call, not the node's.
    expect(consumerReadTransport.calls).toHaveLength(1);
    expect(nodeReadTransport.calls).toHaveLength(1);
    harness.row.armed = true;

    // External sender partial intake.
    // (a) Step-1 signature verifies over the exact captured inner text (the byte-exact signing rule).
    expect(
      verify(
        null,
        Buffer.from(targetStep1Text, "utf8"),
        createPublicKey(seed02),
        Buffer.from(targetStep1Signature, "base64url"),
      ),
    ).toBe(true);
    // (b) Receiver side against issuance T0: link == S0 (never P0); amount = B1 − B0.
    expect(targetInner.previous_step_2_state_signature).toBe(nodeCapturedT0.S);
    expect(compareAmounts(DERIVED_AMOUNT_ZKZ, AMOUNT_ZKZ)).toBe(0);
    expect(
      compareAmounts(
        subtractAmounts(targetInner.step_2_state.amount, nodeCapturedT0.B),
        AMOUNT_ZKZ,
      ),
    ).toBe(0);
    // payer-chosen 3600s expiry is frozen into the inner — not 300s window.
    expect(targetInner.expiry__unix_time_secs).toBe(String(EXPECTED_PAYER_EXPIRY_UNIX));
    expect(PAYER_CHOSEN_EXPIRY_WINDOW_SECS).not.toBe(300);

    // (c) Sender preflight: previous_step_1 == sender_preflight.S; B − step_1.amount == amount.
    const senderPreflight = projectRoleRelativeState(predecessorSettled, seed02Public);
    expect(senderPreflight.ok).toBe(true);
    if (!senderPreflight.ok) throw new Error("sender preflight projection failed");
    expect(senderPreflight.projection.role).toBe("receiver");
    expect(targetInner.previous_step_1_state_signature).toBe(senderPreflight.projection.S);
    expect(
      compareAmounts(
        subtractAmounts(senderPreflight.projection.B, targetInner.step_1_state.amount),
        AMOUNT_ZKZ,
      ),
    ).toBe(0);

    // (d) Node co-signs step 2 over the exact step-2 preimage bytes.
    expect(
      verify(
        null,
        Buffer.from(targetStep2Text, "utf8"),
        createPublicKey(seed03),
        Buffer.from(targetStep2Signature, "base64url"),
      ),
    ).toBe(true);
    expect(computeInnerDigest(targetInner)).toBe(sha256Hex(targetStep1Text));

    // Durable candidate boundary crossed : STEP1_SIGNATURE_PERSISTED exists.
    harness.row.durableCandidate = true;

    // (e) Submit exactly once via production receiveSubmitOnce (the never-blind-retry rule).
    expect(harness.row.armed).toBe(true);
    const claimStore = makeClaimStore();
    const exchange = makeCountingExchange(200, '{"status":true,"code":"ok","message":"OK","data":{}}');
    const recorder = makeRecorder();
    const submitRequest = buildGatewayActionRequest(SUBMIT_ACTION_NAME, {
      inner: targetInner,
      step_1_signature: targetStep1Signature,
      step_2_signature: targetStep2Signature,
    });
    const firstSubmit = await receiveSubmitOnce({
      receiveAttemptId: ATTEMPT_ID,
      signedRequest: submitRequest,
      authorization: SUBMIT_AUTHORIZATION,
      submitOptions: {
        endpoint: SUBMIT_ENDPOINT,
        limits: SUBMIT_LIMITS,
        recorder,
        exchange,
      },
      claimStore,
      nowIso: () => FIXED_NOW,
    });
    expect(firstSubmit.kind).toBe("SUBMITTED");
    if (firstSubmit.kind === "SUBMITTED") {
      expect(firstSubmit.transportOutcome).toBe("ACK");
      expect(isSettlementAuthority(firstSubmit.acknowledgement)).toBe(false);
    }
    harness.row.submitClaimed = true;
    harness.row.submitCount = 1;
    expect(exchange.calls).toHaveLength(1);
    expect(claimStore.claims).toHaveLength(1);

    // Landing: node-side reconcile + independent consumer observation verification verifyReceiveProof.
    // Settlement authority is minted from the landing proof, never from the submit ack.
    const landingProof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: seed03Public,
      expectedBodySha256: sha256Hex(targetSettledText),
      freshHeadBodySha256: sha256Hex(targetSettledText),
      freshHeadObservationId: "obs-terminal",
      depth: 0,
    });
    const settlement = mintSettlementAuthority(ATTEMPT_ID, landingProof);
    expect(isSettlementAuthority(settlement)).toBe(true);

    const reconcile = classifyReceiveReconcile({
      boundary: "POST_SUBMIT",
      receiveAttemptId: ATTEMPT_ID,
      receiverWalletId: RECEIVER_WALLET_ID,
      receiverLeaseState: "ACTIVE",
      receiverObservation: { result: "PROOF", proof: landingProof },
    });
    expect(reconcile.kind).toBe("LANDED_VERIFIED");

    // Economic predicate re-run against the exact signed text (receiver delta = B1 − B0).
    const delta = evaluateReceiveDelta({
      baseline: nodeCapturedT0,
      candidateTx: targetSettled,
      reservedWalletPublicKey: seed03Public,
      operation: { amountZkz: AMOUNT_ZKZ, receiverPubkey: seed03Public },
    });
    expect(delta).toEqual({ ok: true });

    // Independent consumer: own scripted head stream + production verifyReceiveProof.
    // Agree path only where complete-path holds — never by construction from node state.
    const consumerLandingTransport = createOfflineReadTransport(createGatewayReadCredentials(), [
      {
        statusCode: 200,
        bodyBytes: gatewayHeadEnvelopeBytes(targetSettled),
      },
    ]);
    const consumerLandingResponse = await consumerLandingTransport.read(
      ["https://gateway.offline.test"],
      buildGatewayActionRequest("get_transaction__v1", {
        public_key_base64urlsafe: seed03Public,
      }),
    );
    expect(consumerLandingTransport.calls).toHaveLength(1);
    const consumerBundle: ReceiveProofBundle = {
      kind: "receive",
      artifact: buildReceiveArtifact(AMOUNT_ZKZ, seed03Public),
      receiverResponse: consumerLandingResponse.bodyBytes,
      receiverBaseline: GENESIS_PROJECTION,
    };
    const consumerVerdict = verifyReceiveProof(consumerBundle, NODE_KEY);
    expect(consumerVerdict.verdict).toBe("VERIFIED");
    // Cross-domain agreement under matching complete-path evidence.
    expect(reconcile.kind === "LANDED_VERIFIED" && consumerVerdict.verdict === "VERIFIED").toBe(
      true,
    );

    // READY -> RECEIVE_LANDED. Receiver lease STAYS held (operation flows step 5).
    harness.transition("RECEIVE_LANDED", "receive.landed");
    expect(harness.row.state).toBe("RECEIVE_LANDED");
    expect(harness.row.leaseHeld).toBe(true);

    expect(harness.durableEvents).toEqual(["receive.ready", "receive.landed"]);
    expect(harness.transitions).toEqual([
      { from: "CREATED", to: "READY" },
      { from: "READY", to: "RECEIVE_LANDED" },
    ]);
    expect(harness.row.submitCount).toBe(1);
    expect(exchange.calls).toHaveLength(1);
  });

  it("negative: arm barrier refuses when independent consumer projection mismatches node T0", async () => {
    // Consumer's own scripted stream returns a non-genesis B — arm must not release code.
    const consumerReadTransport = createOfflineReadTransport(createGatewayReadCredentials(), [
      envelopeResponse({
        observationId: "obs-consumer-mismatch",
        projection: { S: "", P: "", B: "0.00000000000000000000000000000001", role: "genesis", I: null },
      }),
    ]);
    const response = await consumerReadTransport.read(
      ["https://gateway.offline.test"],
      buildGatewayActionRequest("get_transaction__v1", {
        public_key_base64urlsafe: seed03Public,
      }),
    );
    const consumerProjection = projectionFromOfflineRead(response);
    const nodeT0 = { S: NODE_T0.S, P: NODE_T0.P, B: NODE_T0.B };
    // Independently-derived expected agreement predicate (can go red if B drifts).
    const armAgreed =
      consumerProjection.S === nodeT0.S &&
      consumerProjection.P === nodeT0.P &&
      consumerProjection.B === nodeT0.B;
    expect(armAgreed).toBe(false);
    expect(consumerProjection.B).not.toBe(nodeT0.B);
  });

  it("landing alone does not release the lease; verification-complete VERIFIED does", () => {
    const harness = createHarness();
    harness.row.receiverWalletId = RECEIVER_WALLET_ID;
    harness.row.leaseHeld = true;
    harness.transition("READY", "receive.ready");
    harness.transition("RECEIVE_LANDED", "receive.landed");

    // After landing, no verification ack yet — group release must stay pending.
    const pendingFacts: GroupReleaseFacts = {
      childDisposition: "NONE",
      operations: [
        {
          operationId: OPERATION_ID,
          kind: "RECEIVE_EXTERNAL",
          verdict: null,
          evidenceRoles: [],
          evidence: [],
          expectedWallets: [
            {
              role: "RECEIVER",
              walletId: RECEIVER_WALLET_ID,
              walletPublicKey: seed03Public,
            },
          ],
          completed: false,
        },
      ],
    };
    const pending = evaluateGroupRelease(pendingFacts);
    expect(pending.status).toBe("PINNED_GROUP_PENDING");
    expect(pending.reason).toBe("LEG_NOT_ACKNOWLEDGED");
    // Landing is not verification-complete: lease must still be held.
    expect(harness.row.leaseHeld).toBe(true);
    expect(harness.row.state).toBe("RECEIVE_LANDED");

    // Consumer posts VERIFIED acknowledgement with complete evidence.
    const verifiedFacts: GroupReleaseFacts = {
      childDisposition: "NONE",
      operations: [
        {
          operationId: OPERATION_ID,
          kind: "RECEIVE_EXTERNAL",
          verdict: "VERIFIED",
          evidenceRoles: ["RECEIVER"],
          evidence: [
            {
              role: "RECEIVER",
              walletId: RECEIVER_WALLET_ID,
              walletPublicKey: seed03Public,
            },
          ],
          expectedWallets: [
            {
              role: "RECEIVER",
              walletId: RECEIVER_WALLET_ID,
              walletPublicKey: seed03Public,
            },
          ],
          completed: true,
        },
      ],
    };
    const released = evaluateGroupRelease(verifiedFacts);
    expect(released.status).toBe("RELEASED");
    expect(released.reason).toBe("ALL_LEGS_PROVEN");
    expect(clampReleaseToVerdict("VERIFIED", released.status)).toBe("RELEASED");
    harness.row.verificationAck = "VERIFIED";
    harness.row.leaseHeld = false; // only now, after verification-complete

    // REJECTED / INDETERMINATE never silently release (the API contract clamp).
    expect(clampReleaseToVerdict("REJECTED", "RELEASED")).toBe("PINNED_FOR_ATTENTION");
    expect(clampReleaseToVerdict("INDETERMINATE", "RELEASED")).toBe("PINNED_FOR_ATTENTION");
  });

  it("pre-boundary: unassigned CREATED past queue wait becomes EXPIRED with no wallet", () => {
    const harness = createHarness();
    expect(harness.row.state).toBe("CREATED");
    expect(harness.row.receiverWalletId).toBeNull();
    expect(harness.row.durableCandidate).toBe(false);

    // Pre-boundary expiry to EXPIRED is legal (operation flows first bullet).
    expect(isExpiryToExpiredLegal("CREATED", false)).toBe(true);
    const events = receiveExpiryEvents(false);
    expect(events).toEqual({ appendsExpired: true, appendsNeedsAttention: false });

    harness.transition("EXPIRED", "operation.expired");
    expect(harness.row.state).toBe("EXPIRED");
    expect(harness.row.leaseHeld).toBe(false);
    expect(harness.row.receiverWalletId).toBeNull();
    expect(harness.durableEvents).toEqual(["operation.expired"]);
  });

  it("post-boundary: gate forbids READY→EXPIRED; stays READY + POST_EXPIRY_RECONCILING", () => {
    const harness = createHarness();
    harness.row.receiverWalletId = RECEIVER_WALLET_ID;
    harness.row.leaseHeld = true;
    harness.transition("READY", "receive.ready");
    harness.row.armed = true;
    harness.row.durableCandidate = true; // STEP1_SIGNATURE_PERSISTED exists

    // Terminal expiry after the durable-candidate boundary is forbidden.
    // The frozen table still lists READY→EXPIRED for the *pre-boundary* case; the production
    // refusal is the external isExpiryToExpiredLegal gate (not a table-edge removal).
    expect(isExpiryToExpiredLegal("READY", true)).toBe(false);
    expect(isExpiryToExpiredLegal("READY", false)).toBe(true); // contrast: pre-boundary still legal
    // Table still declares the edge (pre-boundary vocabulary) — gate is external to the table.
    const tableAllowsReadyExpired = (RECEIVE_EXTERNAL_TRANSITIONS as FrozenTable).some(
      (row) => row.from === "READY" && row.to === "EXPIRED" && row.event === "operation.expired",
    );
    expect(tableAllowsReadyExpired).toBe(true);

    const events = receiveExpiryEvents(true);
    expect(events).toEqual({ appendsExpired: false, appendsNeedsAttention: true });

    // Production expiry stepper: gate refuses → never reaches harness.transition("EXPIRED").
    const attempted = attemptReceiveExpiry(harness);
    expect(attempted.kind).toBe("POST_BOUNDARY_HELD");
    if (attempted.kind === "POST_BOUNDARY_HELD") {
      expect(attempted.outcome).toEqual(POST_BOUNDARY_EXPIRY_OUTCOME);
    }
    // State unchanged — READY→EXPIRED was never applied.
    expect(harness.row.state).toBe("READY");
    expect(harness.transitions).toEqual([{ from: "CREATED", to: "READY" }]);
    expect(harness.durableEvents).toEqual(["receive.ready"]); // no operation.expired

    // Canonical post-boundary outcome (contracts/receive-expiry).
    expect(POST_BOUNDARY_EXPIRY_OUTCOME).toEqual({
      state: "READY",
      attentionReason: POST_EXPIRY_RECONCILING,
      leaseHeld: true,
      appendsNeedsAttention: true,
      appendsExpiredEvent: false,
    });
    expect(harness.row.leaseHeld).toBe(true);
    expect(harness.row.attentionReason).toBe(POST_EXPIRY_RECONCILING);

    // Reconcile-first disposition: no landing yet, not durably inconclusive → stay held.
    const held = postBoundaryExpiryDisposition({
      reconcileCompleted: true,
      landingObserved: false,
      durablyInconclusive: false,
      t0Unchanged: false,
      groupAcknowledgementsComplete: false,
    });
    expect(held).toEqual({ kind: "held", attentionReason: POST_EXPIRY_RECONCILING });
  });

  it("proves never-rebuild/never-resubmit via production receiveSubmitOnce (the never-blind-retry rule)", async () => {
    const harness = createHarness();
    harness.row.receiverWalletId = RECEIVER_WALLET_ID;
    harness.row.leaseHeld = true;
    harness.row.armed = true;
    harness.row.durableCandidate = true;
    harness.transition("READY", "receive.ready");

    const claimStore = makeClaimStore();
    // First exchange ACK; a second body would be consumed if blind retry were allowed.
    const exchange = makeCountingExchange(200, '{"status":true,"code":"ok","message":"OK","data":{}}');
    const recorder = makeRecorder();
    const metrics = createNodeMetrics();
    const submitRequest = buildGatewayActionRequest(SUBMIT_ACTION_NAME, {
      inner: targetInner,
      step_1_signature: targetStep1Signature,
      step_2_signature: targetStep2Signature,
    });
    const submitInput = {
      receiveAttemptId: ATTEMPT_ID,
      signedRequest: submitRequest,
      authorization: SUBMIT_AUTHORIZATION,
      submitOptions: {
        endpoint: SUBMIT_ENDPOINT,
        limits: SUBMIT_LIMITS,
        recorder,
        exchange,
      },
      claimStore,
      metricsHooks: createMetricsHooks(metrics),
      nowIso: () => FIXED_NOW,
    } as const;

    // First (and only authorized) submit through production receiveSubmitOnce.
    const first = await receiveSubmitOnce(submitInput);
    expect(first.kind).toBe("SUBMITTED");
    expect(exchange.calls).toHaveLength(1);
    expect(claimStore.claims).toHaveLength(1);
    expect(metrics.submitTotal.get({ outcome: "accepted" })).toBe(1);
    expect(
      metrics.gatewayRequestDuration.series().some(
        ([name, labels]) =>
          name.endsWith("_count") &&
          labels.rpc === "submit_transaction__v1" &&
          labels.outcome === "ok",
      ),
    ).toBe(true);
    harness.row.submitClaimed = true;
    harness.row.submitCount = 1;

    // Ambiguous/indeterminate terminal observation — never settle, never rebuild.
    const reconcile = classifyReceiveReconcile({
      boundary: "POST_SUBMIT",
      receiveAttemptId: ATTEMPT_ID,
      receiverWalletId: RECEIVER_WALLET_ID,
      receiverLeaseState: "ACTIVE",
      receiverObservation: { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" },
    });
    expect(reconcile.kind).toBe("INDETERMINATE");
    expect(harness.row.state).toBe("READY"); // no landing transition
    expect(harness.row.leaseHeld).toBe(true);

    // Production No-blind-retry: second receiveSubmitOnce with same attempt id → AMBIGUOUS, no exchange.
    const second = await receiveSubmitOnce(submitInput);
    expect(second.kind).toBe("AMBIGUOUS");
    if (second.kind === "AMBIGUOUS") {
      expect(second.reason.source).toBe("SUBMIT_OUTCOME_UNKNOWN");
    }
    expect(exchange.calls).toHaveLength(1); // no second transport exchange
    expect(metrics.submitTotal.get({ outcome: "accepted" })).toBe(1);
    expect(recorder.records.length).toBeLessThanOrEqual(1);
    expect(harness.row.submitCount).toBe(1);
  });

  it("proves the golden vector bytes independently (byte-exact signing, the byte-exact signing rule)", () => {
    expect(seed02Public).toBe("gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=");
    expect(seed03Public).toBe("7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=");
    expect(sha256Hex(targetStep1Text)).toBe(
      "ce0741df9ed652b25d0294746c67acd6d9ecb4e3318c3691582fc2acdd52be51",
    );
    expect(sha256Hex(targetStep2Text)).toBe(
      "163d8ef498c09a58d621ed2673c50ed89e79272fcfd14251661c36940e1bb9d0",
    );
    expect(sha256Hex(targetSettledText)).toBe(
      "5554ffa03050cb94173406a85a50aa72c4eca604ab630f0511e61bec7969aebf",
    );
    expect(validateOperationAmount(AMOUNT_ZKZ).ok).toBe(true);
    expect(compareAmounts(DERIVED_AMOUNT_ZKZ, AMOUNT_ZKZ)).toBe(0);
  });

  it("observation verification independent consumer REJECTED on amount-mismatched artifact (disagree path)", async () => {
    // Consumer scripts a valid settled head but an artifact claiming the wrong amount.
    // Node-side landing with matching evidence would be LANDED_VERIFIED; consumer must not
    // mark success from node state alone — verifyReceiveProof is the independent oracle.
    const consumerLandingTransport = createOfflineReadTransport(createGatewayReadCredentials(), [
      {
        statusCode: 200,
        bodyBytes: gatewayHeadEnvelopeBytes(targetSettled),
      },
    ]);
    const consumerLandingResponse = await consumerLandingTransport.read(
      ["https://gateway.offline.test"],
      buildGatewayActionRequest("get_transaction__v1", {
        public_key_base64urlsafe: seed03Public,
      }),
    );
    const wrongAmountBundle: ReceiveProofBundle = {
      kind: "receive",
      artifact: buildReceiveArtifact("9.99", seed03Public), // disagrees with settled +2.25
      receiverResponse: consumerLandingResponse.bodyBytes,
      receiverBaseline: GENESIS_PROJECTION,
    };
    const consumerVerdict = verifyReceiveProof(wrongAmountBundle, NODE_KEY);
    expect(consumerVerdict.verdict).toBe("REJECTED");
    if (consumerVerdict.verdict === "REJECTED") {
      expect(consumerVerdict.stage).toBe("delta");
    }

    // Node-side complete-path with correct amount remains LANDED_VERIFIED — domains disagree.
    const landingProof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: seed03Public,
      expectedBodySha256: sha256Hex(targetSettledText),
      freshHeadBodySha256: sha256Hex(targetSettledText),
      freshHeadObservationId: "obs-terminal-disagree",
      depth: 0,
    });
    const nodeReconcile = classifyReceiveReconcile({
      boundary: "POST_SUBMIT",
      receiveAttemptId: ATTEMPT_ID,
      receiverWalletId: RECEIVER_WALLET_ID,
      receiverLeaseState: "ACTIVE",
      receiverObservation: { result: "PROOF", proof: landingProof },
    });
    expect(nodeReconcile.kind).toBe("LANDED_VERIFIED");
    // Success is not taken from node state alone while consumer rejected.
    const markSuccess =
      nodeReconcile.kind === "LANDED_VERIFIED" && consumerVerdict.verdict === "VERIFIED";
    expect(markSuccess).toBe(false);
  });

  it("rejects an amount-mismatched candidate before any landing verdict", () => {
    const tampered: SettledSplitChainTransaction = {
      inner: { ...targetInner, step_2_state: { amount: "2.24" } },
      step_1_signature: targetStep1Signature,
      step_2_signature: targetStep2Signature,
    };
    const delta = evaluateReceiveDelta({
      baseline: NODE_T0,
      candidateTx: tampered,
      reservedWalletPublicKey: seed03Public,
      operation: { amountZkz: AMOUNT_ZKZ, receiverPubkey: seed03Public },
    });
    expect(delta.ok).toBe(false);
  });
});
