// Offline MOVE_INTERNAL + SEND_EXTERNAL end-to-end.
// Extends offline harness: every gateway interaction is mocked via
// packages/node-core/src/testkit/offline.ts — zero production network.
//
// Governing:
// the operation flows
// the custody rules
// the observation rules
// the recovery rules (no generic PROVEN_NOT_LANDED rebuild;
//     production MOVE ambiguity forbid-list; rebuild evaluator not implemented at launch)
// the test plan
//
// Acceptance: ACK-without-landing / crash / redelivery cannot false-land;
// ≤1 MOVE gateway call; exactly one immutable SEND partial; dual-lease ascending UUID
// including adversarial fixture; ≥1 negative-path invariant breach.

import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify } from "node:crypto";
import { describe, expect, it } from "vitest";

import { compareAmounts, subtractAmounts } from "@zucoins/generic-node-contracts";
import { SUBMIT_ACTION_NAME } from "@zucoins/generic-node-contracts/transfer-code";
import {
  MOVE_INTERNAL_TRANSITIONS,
  SEND_EXTERNAL_TRANSITIONS,
  type MoveInternalState,
  type SendExternalState,
} from "../../generic-node-contracts/src/operations/states.contract.ts";
import { OPERATOR_RECOVERY_ACTIONS } from "../../generic-node-contracts/src/operator-halt/halt.contract.ts";

import {
  executeMoveSubmitClaim,
  type MoveSubmitClaim,
  type MoveSubmitClaimStore,
} from "../src/core/move-submit-claim.js";
import {
  deriveExecutionPhase,
  type DurableExecutionFacts,
} from "../src/core/execution-phase.js";
import {
  createInMemoryFormAndSignState,
  createInMemoryPartialPort,
  createInMemorySignIntentPort,
  formAndSignSendExternal,
  recordInMemoryPartialDelivery,
  type FormAndSignClaim,
  type FormAndSignHeldLease,
  type FormAndSignInput,
} from "../src/core/send-form-and-sign.js";
import {
  type SignerAuditEntry,
  type SignerBoundaryDeps,
  type VaultSigner,
} from "../src/core/signer-boundary.js";
import type { GatewayExchangeTransport } from "../src/gateway/capture.js";
import {
  buildGatewayActionRequest,
  createGatewayReadCredentials,
} from "../src/gateway/index.js";
import type { GatewaySubmitAttemptRecord, SubmitAttemptRecorder } from "../src/gateway/records.js";
import type { GatewayLimits } from "../src/gateway/types.js";
import type { GatewayRequest } from "../src/protocol/index.js";
import { sortWalletIdsAscending } from "../src/leases/sort-wallets.js";
import { evaluateInternalMoveDelta, evaluateExternalSendDelta } from "../src/protocol/economic-predicates.js";
import type { SettledSplitChainTransaction, SplitChainInnerV2 } from "../src/protocol/inner.js";
import { captureDualBaselines } from "../src/protocol/move-baseline.js";
import { constructMoveInner } from "../src/protocol/move-inner.js";
import { classifyMoveReconcile } from "../src/protocol/reconcile/index.js";
import {
  mintLandingPathProofFromOracle,
} from "../src/protocol/reconcile/landing-oracle-mint.fixture.js";
import {
  MOVE_AMBIGUITY_FORBIDDEN_ACTIONS,
  classifyMoveAmbiguity,
  isMoveAmbiguityActionPermitted,
} from "../src/protocol/reconcile/move-ambiguity.js";
import {
  captureSubmitAcknowledgement,
  isSettlementAuthority,
  isSubmitAcknowledgement,
  mintSettlementAuthority,
} from "../src/protocol/reconcile/submit-authority.js";
import { classifySendReconcile } from "../src/protocol/reconcile/send.js";
import { captureSendBaselines } from "../src/protocol/send-baseline.js";
import { SEND_REDEMPTION_WINDOW_SECS } from "../src/protocol/send-redemption.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "../src/protocol/wallet-role.js";
import {
  createOfflineReadTransport,
} from "../src/testkit/offline.js";
import type { GatewayResponse } from "../src/protocol/index.js";
import {
  clampReleaseToVerdict,
  evaluateGroupRelease,
  type GroupReleaseFacts,
} from "../src/verification/index.js";
import {
  assertObservedEventAllowed,
  assertObservedStateAllowed,
  classifyObservedTransition,
  isNoEventMarker,
  type FrozenTable,
} from "./lifecycle-fuzz-oracles.js";

// ─── Keys (test-only filled-byte Ed25519 seeds) ───────────────────────────────
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
const sha256Hex = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");
const signUtf8 = (pk: ReturnType<typeof keyFromSeed>, text: string): string =>
  paddedBase64Url(Buffer.from(nodeSign(null, Buffer.from(text, "utf8"), pk)));

// MOVE wallets: source seed 0x11, dest seed 0x22. SEND source reuses 0x11; external dest 0x33.
const seedSource = keyFromSeed(0x11);
const seedDest = keyFromSeed(0x22);
const seedExternalDest = keyFromSeed(0x33);
const sourcePublic = publicKeyOf(seedSource);
const destPublic = publicKeyOf(seedDest);
const externalDestPublic = publicKeyOf(seedExternalDest);

// Adversarial UUID pair: insertion/role order is source-first, but dest UUID sorts BEFORE source
// (operation-flow / node-core ascending binary UUID). A fixture that only uses convenient sort order is weak.
const MOVE_SOURCE_WALLET_ID = "f0000000-0000-4000-8000-000000000002"; // sorts second
const MOVE_DEST_WALLET_ID = "a0000000-0000-4000-8000-000000000001"; // sorts first
const MOVE_OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const SEND_OPERATION_ID = "44444444-4444-4444-8444-444444444444";
const SEND_SOURCE_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const SEND_APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SEND_LEASE_GROUP_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const MOVE_ATTEMPT_ID = "move-attempt-1";
const SEND_ATTEMPT_ID = "send-attempt-1";

// Production executeMoveSubmitClaim authorization (data-model / gateway submit decision id).
const MOVE_SUBMIT_DECISION_ID = "11111111-1111-4111-8111-111111111111";
const MOVE_SUBMIT_AUTHORIZATION = {
  submitDecisionId: MOVE_SUBMIT_DECISION_ID,
  operationId: MOVE_OPERATION_ID,
  transactionAttemptNo: 1,
} as const;
const MOVE_SUBMIT_ENDPOINT = "https://gateway.offline.test/";
const MOVE_SUBMIT_LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 65_536,
  maxResponseBytes: 65_536,
};
const FIXED_NOW = "2026-07-18T00:00:00.000Z";

// Internal move amount (uncapped automated path). External send ≤ 0.01 ZKZ (the live-chain test cap).
const MOVE_AMOUNT_ZKZ = "2.25";
const SEND_AMOUNT_ZKZ = "0.01";
const SOURCE_B0 = "10";
const NODE_CLOCK_MS = 1_784_332_800_000; // 2026-07-18T00:00:00.000Z
const FORMED_AT = "2026-07-18T00:00:00.000Z";

/** Valid padded Ed25519 signature used as source T0.S (HEAD link). */
const SOURCE_T0_S =
  "IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==";

const encoder = new TextEncoder();
const envelopeResponse = (data: unknown): GatewayResponse => ({
  statusCode: 200,
  bodyBytes: encoder.encode(JSON.stringify({ status: true, code: "ok", message: "OK", data })),
});

function senderProjection(b: string, s: string = SOURCE_T0_S): WalletStateProjection {
  return { role: "sender", S: s, P: s, B: b, I: "digest" };
}

// ─── Lifecycle harnesses over frozen the state/event reference tables ───────────────────────
interface MoveRow {
  state: MoveInternalState;
  sourceLeaseHeld: boolean;
  destLeaseHeld: boolean;
  submitClaimed: boolean;
  submitCount: number;
  attemptNo: number;
  attentionReason: string | null;
  verificationAck: "NONE" | "VERIFIED" | "REJECTED" | "INDETERMINATE";
  /** recovery positive non-landing case id when rebuild is authorized; null otherwise. */
  rebuildCase: 1 | 2 | 3 | null;
}

interface SendRow {
  state: SendExternalState;
  sourceLeaseHeld: boolean;
  totpApproved: boolean;
  signIntentPersisted: boolean;
  partialCount: number;
  submitCountByNode: number;
  attentionReason: string | null;
  persistedPartialText: string | null;
  persistedPartialSha256: string | null;
}

interface LifecycleHarness<S extends string, R> {
  readonly row: R;
  readonly durableEvents: string[];
  readonly transitions: Array<{ from: S | null; to: S }>;
  transition(to: S, observedEvent?: string | null): void;
}

function createLifecycleHarness<S extends string, R extends { state: S }>(
  table: FrozenTable,
  initial: R,
): LifecycleHarness<S, R> {
  const row = initial;
  const durableEvents: string[] = [];
  const transitions: Array<{ from: S | null; to: S }> = [];
  return {
    row,
    durableEvents,
    transitions,
    transition(to, observedEvent = null) {
      const from = row.state;
      const verdict = classifyObservedTransition(table, { from, to, event: observedEvent });
      if (verdict.verdict !== "ALLOWED") {
        throw new Error(`transition ${String(from)} -> ${String(to)} refused: ${verdict.verdict}`);
      }
      assertObservedStateAllowed(to);
      const declared = verdict.expectedEvent;
      if (declared !== undefined && declared !== null && !isNoEventMarker(declared)) {
        assertObservedEventAllowed(declared);
        if (observedEvent !== declared) {
          throw new Error(
            `transition ${String(from)} -> ${String(to)} emitted ${observedEvent}, expected ${declared}`,
          );
        }
        durableEvents.push(declared);
      }
      transitions.push({ from, to });
      row.state = to;
    },
  };
}

function createMoveHarness(): LifecycleHarness<MoveInternalState, MoveRow> {
  return createLifecycleHarness(MOVE_INTERNAL_TRANSITIONS as FrozenTable, {
    state: "CREATED",
    sourceLeaseHeld: false,
    destLeaseHeld: false,
    submitClaimed: false,
    submitCount: 0,
    attemptNo: 1,
    attentionReason: null,
    verificationAck: "NONE",
    rebuildCase: null,
  });
}

function createSendHarness(): LifecycleHarness<SendExternalState, SendRow> {
  return createLifecycleHarness(SEND_EXTERNAL_TRANSITIONS as FrozenTable, {
    state: "CREATED",
    sourceLeaseHeld: false,
    totpApproved: false,
    signIntentPersisted: false,
    partialCount: 0,
    submitCountByNode: 0,
    attentionReason: null,
    persistedPartialText: null,
    persistedPartialSha256: null,
  });
}

// ─── Production No-blind-retry / no-rebuild / no-SEND-submit seams (not test-local tautologies) ─

/** In-memory stand-in for submit_decisions UNIQUE (operation_id, transaction_attempt_no). */
function makeMoveClaimStore(seeded?: MoveSubmitClaim): MoveSubmitClaimStore & {
  readonly mints: number;
  readonly claims: readonly MoveSubmitClaim[];
} {
  const claims = new Map<string, MoveSubmitClaim>();
  if (seeded !== undefined) {
    claims.set(`${seeded.operationId}#${seeded.transactionAttemptNo}`, seeded);
  }
  let mints = 0;
  return {
    get mints() {
      return mints;
    },
    get claims() {
      return [...claims.values()];
    },
    claimSubmitOnce: async (claim) => {
      const key = `${claim.operationId}#${claim.transactionAttemptNo}`;
      const existing = claims.get(key);
      if (existing !== undefined) {
        return { claim: existing, minted: false };
      }
      claims.set(key, claim);
      mints += 1;
      return { claim, minted: true };
    },
  };
}

function makeSubmitRecorder(): SubmitAttemptRecorder & {
  readonly records: readonly GatewaySubmitAttemptRecord[];
} {
  const records: GatewaySubmitAttemptRecord[] = [];
  return {
    get records() {
      return [...records];
    },
    recordSubmitAttempt: async (record) => {
      records.push(record);
    },
  };
}

/** Counting exchange for executeMoveSubmitClaim — production No-blind-retry surface. */
function makeCountingExchange(
  statusCode: number,
  body: string,
): GatewayExchangeTransport & { readonly calls: readonly { endpoint: string; rpc: string }[] } {
  const calls: { endpoint: string; rpc: string }[] = [];
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
        requestSha256: sha256Hex(
          typeof request.bodyBytes === "string"
            ? request.bodyBytes
            : new TextDecoder().decode(request.bodyBytes),
        ),
        responseBytes: bodyBytes,
        responseSha256: sha256Hex(body),
        statusCode,
      };
    },
  };
}

/**
 * Production mandatory DB test 11 / state/event gate: SEND_EXTERNAL must never carry submit facts.
 * deriveExecutionPhase throws when submitStarted || submitReturned on SEND_EXTERNAL.
 */
function sendFacts(partial: Partial<DurableExecutionFacts> = {}): DurableExecutionFacts {
  return {
    operationKind: "SEND_EXTERNAL",
    attemptPhase: null,
    signIntentPersisted: false,
    partialPersisted: false,
    partialFirstDelivered: false,
    submitStarted: false,
    submitReturned: false,
    verificationAccepted: false,
    terminalObservationsPresent: false,
    ...partial,
  };
}

// ─── MOVE_INTERNAL  ───────────────────────────────────────────────────────────
describe("offline MOVE_INTERNAL end-to-end", () => {
  it("dual-lease ascending UUID → form/sign/single-submit → dual-path landing", async () => {
    const harness = createMoveHarness();
    expect(harness.row.state).toBe("CREATED");
    expect(harness.durableEvents).toEqual([]); // null→CREATED is internal_move.created at admission; harness starts CREATED

    // Dual lease in ascending UUID order — adversarial: dest UUID < source UUID.
    const insertionOrder = [MOVE_SOURCE_WALLET_ID, MOVE_DEST_WALLET_ID];
    const acquisitionOrder = sortWalletIdsAscending(insertionOrder);
    expect(acquisitionOrder).toEqual([MOVE_DEST_WALLET_ID, MOVE_SOURCE_WALLET_ID]);
    expect(acquisitionOrder[0]).not.toBe(insertionOrder[0]); // proves adversarial fixture
    // Simulate atomic hold after sorted acquisition.
    harness.row.sourceLeaseHeld = true;
    harness.row.destLeaseHeld = true;

    // T0 observations via offline read transport (both wallets while leases held).
    const sourceT0 = senderProjection(SOURCE_B0, SOURCE_T0_S);
    const destT0 = GENESIS_PROJECTION;
    const readTransport = createOfflineReadTransport(createGatewayReadCredentials(), [
      envelopeResponse({ observationId: "obs-move-src-t0", projection: sourceT0 }),
      envelopeResponse({ observationId: "obs-move-dst-t0", projection: destT0 }),
    ]);
    const srcResp = await readTransport.read(
      ["https://gateway.offline.test"],
      buildGatewayActionRequest("get_transaction__v1", { public_key_base64urlsafe: sourcePublic }),
    );
    const dstResp = await readTransport.read(
      ["https://gateway.offline.test"],
      buildGatewayActionRequest("get_transaction__v1", { public_key_base64urlsafe: destPublic }),
    );
    expect(srcResp.statusCode).toBe(200);
    expect(dstResp.statusCode).toBe(200);
    expect(readTransport.calls).toHaveLength(2);

    const captured = captureDualBaselines({
      operationId: MOVE_OPERATION_ID,
      sourceWalletPublicKey: sourcePublic,
      destinationWalletPublicKey: destPublic,
      sourceLease: { role: "MOVE_SOURCE", lifecycle: "ACTIVE" },
      destinationLease: { role: "MOVE_DESTINATION", lifecycle: "ACTIVE" },
      sourceBaseline: sourceT0,
      destinationBaseline: destT0,
      amountZkz: MOVE_AMOUNT_ZKZ,
      capturedAt: NODE_CLOCK_MS,
    });
    expect(captured.ok).toBe(true);
    if (!captured.ok) throw new Error(captured.detail);

    // Formation: construct exact inner, sign step-1 (source) + step-2 (dest), single submit.
    const constructed = constructMoveInner({
      capture: captured.capture,
      nodeClockMs: NODE_CLOCK_MS,
    });
    const inner = JSON.parse(constructed.innerPreimageText) as SplitChainInnerV2;
    expect(inner.step_1_key_public__base64urlsafe).toBe(sourcePublic);
    expect(inner.step_2_key_public__base64urlsafe).toBe(destPublic);
    expect(inner.previous_step_1_state_signature).toBe(sourceT0.S);
    expect(inner.previous_step_2_state_signature).toBe(destT0.S);
    expect(inner.step_1_state.amount).toBe(subtractAmounts(SOURCE_B0, MOVE_AMOUNT_ZKZ));
    expect(inner.step_2_state.amount).toBe(MOVE_AMOUNT_ZKZ);
    // Byte-exact preimage (the byte-exact signing rule).
    expect(JSON.stringify(inner)).toBe(constructed.innerPreimageText);
    expect(sha256Hex(constructed.innerPreimageText)).toBe(constructed.innerSha256);

    const step1Signature = signUtf8(seedSource, constructed.innerPreimageText);
    expect(
      verify(
        null,
        Buffer.from(constructed.innerPreimageText, "utf8"),
        createPublicKey(seedSource),
        Buffer.from(step1Signature, "base64url"),
      ),
    ).toBe(true);

    const step2PreimageText = JSON.stringify({
      inner,
      step_1_signature: step1Signature,
    });
    const step2Signature = signUtf8(seedDest, step2PreimageText);
    expect(
      verify(
        null,
        Buffer.from(step2PreimageText, "utf8"),
        createPublicKey(seedDest),
        Buffer.from(step2Signature, "base64url"),
      ),
    ).toBe(true);

    const settled: SettledSplitChainTransaction = {
      inner,
      step_1_signature: step1Signature,
      step_2_signature: step2Signature,
    };
    const settledText = JSON.stringify(settled);
    const bodySha = sha256Hex(settledText);

    // Single submit via production executeMoveSubmitClaim (operation-flow step 9 / the never-blind-retry rule).
    // ACK is receipt-only — never settlement.
    const claimStore = makeMoveClaimStore();
    const exchange = makeCountingExchange(
      200,
      JSON.stringify({ status: true, code: "ok", message: "OK", data: {} }),
    );
    const recorder = makeSubmitRecorder();
    const signedTransaction = {
      inner,
      step_1_signature: step1Signature,
      step_2_signature: step2Signature,
    };
    const firstSubmit = await executeMoveSubmitClaim({
      authorization: MOVE_SUBMIT_AUTHORIZATION,
      signedTransaction,
      claimStore,
      submit: {
        endpoint: MOVE_SUBMIT_ENDPOINT,
        limits: MOVE_SUBMIT_LIMITS,
        recorder,
        exchange,
        nowIso: () => FIXED_NOW,
      },
    });
    expect(firstSubmit.executed).toBe(true);
    expect(firstSubmit.recordedOutcome?.status).toBe("ACK");
    expect(exchange.calls).toHaveLength(1);
    expect(exchange.calls[0]?.rpc).toBe(SUBMIT_ACTION_NAME);
    expect(claimStore.mints).toBe(1);
    harness.row.submitClaimed = true;
    harness.row.submitCount = 1;

    const ack = captureSubmitAcknowledgement(MOVE_ATTEMPT_ID, true, "ok", FIXED_NOW);
    expect(isSubmitAcknowledgement(ack)).toBe(true);
    expect(isSettlementAuthority(ack)).toBe(false);

    // Dual-path landing: both wallets observe the same settled tx.
    const sourceProof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: sourcePublic,
      expectedBodySha256: bodySha,
      freshHeadBodySha256: bodySha,
      freshHeadObservationId: "obs-move-src-terminal",
      depth: 0,
    });
    const destProof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: destPublic,
      expectedBodySha256: bodySha,
      freshHeadBodySha256: bodySha,
      freshHeadObservationId: "obs-move-dst-terminal",
      depth: 0,
    });
    const settlement = mintSettlementAuthority(MOVE_ATTEMPT_ID, sourceProof);
    expect(isSettlementAuthority(settlement)).toBe(true);

    const reconcile = classifyMoveReconcile({
      boundary: "POST_SUBMIT",
      moveAttemptId: MOVE_ATTEMPT_ID,
      sourceWalletId: MOVE_SOURCE_WALLET_ID,
      destinationWalletId: MOVE_DEST_WALLET_ID,
      expectedMoveBodySha256: bodySha,
      sourceLeaseState: "ACTIVE",
      destinationLeaseState: "ACTIVE",
      sourceObservation: { result: "PROOF", proof: sourceProof },
      destinationObservation: { result: "PROOF", proof: destProof },
    });
    expect(reconcile.kind).toBe("LANDED_VERIFIED");

    const delta = evaluateInternalMoveDelta({
      source: {
        baseline: sourceT0,
        candidateTx: settled,
        walletPublicKey: sourcePublic,
      },
      destination: {
        baseline: destT0,
        candidateTx: settled,
        walletPublicKey: destPublic,
      },
      operation: {
        amountZkz: MOVE_AMOUNT_ZKZ,
        sourcePubkey: sourcePublic,
        destinationPubkey: destPublic,
      },
    });
    expect(delta).toEqual({ ok: true });
    expect(compareAmounts(subtractAmounts(SOURCE_B0, settled.inner.step_1_state.amount), MOVE_AMOUNT_ZKZ)).toBe(
      0,
    );

    harness.transition("INTERNAL_MOVE_LANDED", "internal_move.landed");
    expect(harness.row.state).toBe("INTERNAL_MOVE_LANDED");
    // Leases remain until verification-complete (step 6).
    expect(harness.row.sourceLeaseHeld).toBe(true);
    expect(harness.row.destLeaseHeld).toBe(true);
    expect(harness.row.submitCount).toBe(1);
    expect(exchange.calls).toHaveLength(1);
    expect(harness.durableEvents).toEqual(["internal_move.landed"]);
  });

  it("adversarial UUID fixture: acquisition order is dest-then-source, never insertion order", () => {
    // Dest UUID begins with 'a', source with 'f' — opposite of role/insertion order.
    expect(MOVE_DEST_WALLET_ID < MOVE_SOURCE_WALLET_ID).toBe(true);
    const sorted = sortWalletIdsAscending([MOVE_SOURCE_WALLET_ID, MOVE_DEST_WALLET_ID]);
    expect(sorted).toEqual([MOVE_DEST_WALLET_ID, MOVE_SOURCE_WALLET_ID]);
    // Reverse insertion still sorts the same (deadlock-free).
    expect(sortWalletIdsAscending([MOVE_DEST_WALLET_ID, MOVE_SOURCE_WALLET_ID])).toEqual(sorted);
  });

  it("recovery — production forbids generic rebuild; no PROVEN_NOT_LANDED path", () => {
    // Launch deliberately has no rebuild evaluator export (move-ambiguity):
    // REBUILD_INTERNAL_MOVE and PROVEN_NOT_LANDED are permanently unrepresentable as permitted
    // ambiguity actions. Operator catalog may still name the action for future evidence-complete
    // cases; the production pin is isMoveAmbiguityActionPermitted → always false.
    expect(MOVE_AMBIGUITY_FORBIDDEN_ACTIONS).toContain("PROVEN_NOT_LANDED");
    expect(MOVE_AMBIGUITY_FORBIDDEN_ACTIONS).toContain("REBUILD_INTERNAL_MOVE");
    expect(MOVE_AMBIGUITY_FORBIDDEN_ACTIONS).toContain("SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING");
    expect(MOVE_AMBIGUITY_FORBIDDEN_ACTIONS).toContain("RETRY_SUBMIT");
    expect(MOVE_AMBIGUITY_FORBIDDEN_ACTIONS).toContain("RESUBMIT");
    expect(MOVE_AMBIGUITY_FORBIDDEN_ACTIONS).toContain("CREATE_ATTEMPT_2");
    expect(isMoveAmbiguityActionPermitted("PROVEN_NOT_LANDED")).toBe(false);
    expect(isMoveAmbiguityActionPermitted("REBUILD_INTERNAL_MOVE")).toBe(false);
    expect(isMoveAmbiguityActionPermitted("SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING")).toBe(false);
    expect(isMoveAmbiguityActionPermitted("RETRY_SUBMIT")).toBe(false);
    expect(isMoveAmbiguityActionPermitted("RESUBMIT")).toBe(false);
    expect(isMoveAmbiguityActionPermitted("CREATE_ATTEMPT_2")).toBe(false);
    // Catalog still names the operator action; production ambiguity surface never permits it.
    expect(OPERATOR_RECOVERY_ACTIONS).toContain("REBUILD_INTERNAL_MOVE");

    // POST_SUBMIT indeterminate parks with both leases retained; never permits second submit/attempt.
    const bodySha = sha256Hex("rebuild-forbid-body");
    const ambiguity = classifyMoveAmbiguity({
      phase: "POST_SUBMIT",
      observation: {
        boundary: "POST_SUBMIT",
        moveAttemptId: MOVE_ATTEMPT_ID,
        sourceWalletId: MOVE_SOURCE_WALLET_ID,
        destinationWalletId: MOVE_DEST_WALLET_ID,
        expectedMoveBodySha256: bodySha,
        sourceLeaseState: "ACTIVE",
        destinationLeaseState: "ACTIVE",
        sourceObservation: { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" },
        destinationObservation: { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" },
      },
      transport: { kind: "ACK", gatewayCode: "ok" },
    });
    expect(ambiguity.kind).toBe("INDETERMINATE");
    if (ambiguity.kind === "INDETERMINATE") {
      expect(ambiguity.permitsSubmitCall).toBe(false);
      expect(ambiguity.permitsSecondAttempt).toBe(false);
      expect(ambiguity.retainSourceLease).toBe(true);
      expect(ambiguity.retainDestinationLease).toBe(true);
    }
  });

  it("negative: ACK-without-landing cannot false-land; second submit refused via executeMoveSubmitClaim (≤1 gateway call)", async () => {
    const harness = createMoveHarness();
    harness.row.sourceLeaseHeld = true;
    harness.row.destLeaseHeld = true;

    const claimStore = makeMoveClaimStore();
    // Second body would be consumed only if production allowed a blind retry.
    const exchange = makeCountingExchange(
      200,
      JSON.stringify({ status: true, code: "ok", message: "OK", data: { ack: true } }),
    );
    const recorder = makeSubmitRecorder();
    const submitOptions = {
      authorization: MOVE_SUBMIT_AUTHORIZATION,
      signedTransaction: { note: "move-signed-body" },
      claimStore,
      submit: {
        endpoint: MOVE_SUBMIT_ENDPOINT,
        limits: MOVE_SUBMIT_LIMITS,
        recorder,
        exchange,
        nowIso: () => FIXED_NOW,
      },
    } as const;

    const first = await executeMoveSubmitClaim(submitOptions);
    expect(first.executed).toBe(true);
    expect(first.recordedOutcome?.status).toBe("ACK");
    expect(exchange.calls).toHaveLength(1);
    harness.row.submitClaimed = true;
    harness.row.submitCount = 1;

    const ack = captureSubmitAcknowledgement(MOVE_ATTEMPT_ID, true, "ok", FIXED_NOW);
    expect(isSettlementAuthority(ack)).toBe(false);

    // Observation is indeterminate — ACK alone never lands.
    const bodySha = sha256Hex("expected-move-body");
    const reconcile = classifyMoveReconcile({
      boundary: "POST_SUBMIT",
      moveAttemptId: MOVE_ATTEMPT_ID,
      sourceWalletId: MOVE_SOURCE_WALLET_ID,
      destinationWalletId: MOVE_DEST_WALLET_ID,
      expectedMoveBodySha256: bodySha,
      sourceLeaseState: "ACTIVE",
      destinationLeaseState: "ACTIVE",
      sourceObservation: { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" },
      destinationObservation: { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" },
    });
    expect(reconcile.kind).toBe("INDETERMINATE");
    expect(harness.row.state).toBe("CREATED"); // no landing transition

    // Ambiguity classifier parks; never rebuilds after submit may have started.
    const ambiguity = classifyMoveAmbiguity({
      phase: "POST_SUBMIT",
      observation: {
        boundary: "POST_SUBMIT",
        moveAttemptId: MOVE_ATTEMPT_ID,
        sourceWalletId: MOVE_SOURCE_WALLET_ID,
        destinationWalletId: MOVE_DEST_WALLET_ID,
        expectedMoveBodySha256: bodySha,
        sourceLeaseState: "ACTIVE",
        destinationLeaseState: "ACTIVE",
        sourceObservation: { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" },
        destinationObservation: { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" },
      },
      transport: { kind: "ACK", gatewayCode: "ok" },
    });
    expect(ambiguity.kind).toBe("INDETERMINATE");
    if (ambiguity.kind === "INDETERMINATE") {
      expect(ambiguity.permitsSubmitCall).toBe(false);
      expect(ambiguity.permitsSecondAttempt).toBe(false);
      expect(ambiguity.retainSourceLease).toBe(true);
      expect(ambiguity.retainDestinationLease).toBe(true);
    }
    // Production forbid: rebuild / resubmit remain unauthorized after ACK.
    expect(isMoveAmbiguityActionPermitted("REBUILD_INTERNAL_MOVE")).toBe(false);
    expect(isMoveAmbiguityActionPermitted("RESUBMIT")).toBe(false);

    // Production No-blind-retry: second executeMoveSubmitClaim same attempt → executed:false, no exchange.
    const second = await executeMoveSubmitClaim(submitOptions);
    expect(second.executed).toBe(false);
    expect(second.recordedOutcome).toBeNull();
    expect(exchange.calls).toHaveLength(1); // second scripted response unconsumed
    expect(claimStore.mints).toBe(1);
    expect(harness.row.submitCount).toBe(1);
    expect(recorder.records.length).toBeLessThanOrEqual(1);
  });

  it("negative: dual-path disagreement / unattributed successor → INVARIANT_BREACH quarantine, no rebuild", () => {
    const harness = createMoveHarness();
    harness.row.sourceLeaseHeld = true;
    harness.row.destLeaseHeld = true;
    harness.row.submitClaimed = true;
    harness.row.submitCount = 1;

    const bodySha = sha256Hex("move-body");
    const breach = classifyMoveReconcile({
      boundary: "POST_SUBMIT",
      moveAttemptId: MOVE_ATTEMPT_ID,
      sourceWalletId: MOVE_SOURCE_WALLET_ID,
      destinationWalletId: MOVE_DEST_WALLET_ID,
      expectedMoveBodySha256: bodySha,
      sourceLeaseState: "ACTIVE",
      destinationLeaseState: "ACTIVE",
      sourceObservation: { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" },
      destinationObservation: {
        result: "PROOF",
        proof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: destPublic,
      expectedBodySha256: bodySha,
      freshHeadBodySha256: bodySha,
      freshHeadObservationId: "obs",
      depth: 0,
    }),
      },
    });
    expect(breach.kind).toBe("INVARIANT_BREACH");
    if (breach.kind === "INVARIANT_BREACH") {
      expect(breach.affectedWalletIds).toContain(MOVE_SOURCE_WALLET_ID);
    }

    harness.transition("NEEDS_ATTENTION", "operation.needs_attention");
    expect(harness.row.state).toBe("NEEDS_ATTENTION");
    // Unexpected successor is custody breach — do not rebuild around it.
    expect(isMoveAmbiguityActionPermitted("REBUILD_INTERNAL_MOVE")).toBe(false);
    expect(harness.row.submitCount).toBe(1);
    expect(harness.row.attemptNo).toBe(1);
  });

  it("landing alone does not release leases; verification-complete VERIFIED does", () => {
    const harness = createMoveHarness();
    harness.row.sourceLeaseHeld = true;
    harness.row.destLeaseHeld = true;
    harness.transition("INTERNAL_MOVE_LANDED", "internal_move.landed");

    const pendingFacts: GroupReleaseFacts = {
      childDisposition: "NONE",
      operations: [
        {
          operationId: MOVE_OPERATION_ID,
          kind: "MOVE_INTERNAL",
          verdict: null,
          evidenceRoles: [],
          evidence: [],
          expectedWallets: [
            { role: "SOURCE", walletId: MOVE_SOURCE_WALLET_ID, walletPublicKey: sourcePublic },
            { role: "DESTINATION", walletId: MOVE_DEST_WALLET_ID, walletPublicKey: destPublic },
          ],
          completed: false,
        },
      ],
    };
    const pending = evaluateGroupRelease(pendingFacts);
    expect(pending.status).toBe("PINNED_GROUP_PENDING");
    expect(harness.row.sourceLeaseHeld).toBe(true);
    expect(harness.row.destLeaseHeld).toBe(true);

    const verifiedFacts: GroupReleaseFacts = {
      childDisposition: "NONE",
      operations: [
        {
          operationId: MOVE_OPERATION_ID,
          kind: "MOVE_INTERNAL",
          verdict: "VERIFIED",
          evidenceRoles: ["SOURCE", "DESTINATION"],
          evidence: [
            { role: "SOURCE", walletId: MOVE_SOURCE_WALLET_ID, walletPublicKey: sourcePublic },
            {
              role: "DESTINATION",
              walletId: MOVE_DEST_WALLET_ID,
              walletPublicKey: destPublic,
            },
          ],
          expectedWallets: [
            { role: "SOURCE", walletId: MOVE_SOURCE_WALLET_ID, walletPublicKey: sourcePublic },
            {
              role: "DESTINATION",
              walletId: MOVE_DEST_WALLET_ID,
              walletPublicKey: destPublic,
            },
          ],
          completed: true,
        },
      ],
    };
    const released = evaluateGroupRelease(verifiedFacts);
    expect(released.status).toBe("RELEASED");
    expect(clampReleaseToVerdict("VERIFIED", released.status)).toBe("RELEASED");
    harness.row.verificationAck = "VERIFIED";
    harness.row.sourceLeaseHeld = false;
    harness.row.destLeaseHeld = false;
    expect(clampReleaseToVerdict("INDETERMINATE", "RELEASED")).toBe("PINNED_FOR_ATTENTION");
  });
});

// ─── SEND_EXTERNAL ───────────────────────────────────────────────────────────
describe("offline SEND_EXTERNAL end-to-end", () => {
  function makeDeterministicVaultSigner(): VaultSigner & { calls: string[] } {
    const calls: string[] = [];
    return {
      calls,
      sign: async (walletId: string, preimageBytes: Uint8Array) => {
        calls.push(walletId);
        const sig = nodeSign(null, Buffer.from(preimageBytes), seedSource);
        return Buffer.from(sig).toString("base64url") + "==";
      },
    };
  }

  function makeSignerDeps(vault: VaultSigner, audit: SignerAuditEntry[] = []): SignerBoundaryDeps {
    return {
      leadership: { held: true },
      leaseReader: {
        readActiveLease: async () => ({
          walletId: SEND_SOURCE_WALLET_ID,
          operationId: SEND_OPERATION_ID,
          epoch: 1n,
          role: "SEND_SOURCE",
          lifecycle: "ACTIVE",
        }),
      },
      vaultSigner: vault,
      auditLog: {
        append: async (e) => {
          audit.push(e);
        },
      },
      now: () => FORMED_AT,
      assertMoneyAdmitted: () => {},
      assertCanOperate: () => {},
      assertWalletMaySign: async () => {},
    };
  }

  function sendClaim(): FormAndSignClaim {
    return {
      operationId: SEND_OPERATION_ID,
      status: "APPROVED",
      formationState: "APPROVED_UNSIGNED",
      rowVersion: 2,
      sourceWalletId: SEND_SOURCE_WALLET_ID,
      sourcePubkey: sourcePublic,
      destinationAddress: externalDestPublic,
      amountZkz: SEND_AMOUNT_ZKZ,
    };
  }

  function sendHeld(): FormAndSignHeldLease {
    return {
      walletId: SEND_SOURCE_WALLET_ID,
      membershipId: "mmmmmmmm-0000-4000-8000-000000000001",
      leaseGroupId: SEND_LEASE_GROUP_ID,
      leaseEpoch: 1n,
      operationId: SEND_OPERATION_ID,
    };
  }

  function sendCapture() {
    const captured = captureSendBaselines({
      operationId: SEND_OPERATION_ID,
      sourceWalletPublicKey: sourcePublic,
      destinationAddress: externalDestPublic,
      sourceLease: { role: "SEND_SOURCE", lifecycle: "ACTIVE" },
      sourceBaseline: senderProjection(SOURCE_B0),
      destinationBaseline: GENESIS_PROJECTION,
      amountZkz: SEND_AMOUNT_ZKZ,
      capturedAt: NODE_CLOCK_MS,
    });
    if (!captured.ok) throw new Error(`send capture failed: ${captured.detail}`);
    return captured.capture;
  }

  function baseFormInput(
    state = createInMemoryFormAndSignState(),
    vault = makeDeterministicVaultSigner(),
  ): FormAndSignInput & { state: ReturnType<typeof createInMemoryFormAndSignState>; vault: ReturnType<typeof makeDeterministicVaultSigner> } {
    return {
      claim: sendClaim(),
      held: sendHeld(),
      approvalId: SEND_APPROVAL_ID,
      sourceT0ObservationId: "obs-send-src-t0",
      destinationFormationObservationId: "obs-send-dst-formation",
      capture: sendCapture(),
      nodeClockMs: NODE_CLOCK_MS,
      preparedAt: FORMED_AT,
      persistedAt: "2026-07-18T00:00:01.000Z",
      signIntentPort: createInMemorySignIntentPort(state),
      partialPort: createInMemoryPartialPort(state),
      signerDeps: makeSignerDeps(vault),
      state,
      vault,
    };
  }

  it("TOTP approve → form/sign one partial → zero node submit → source landing", async () => {
    const harness = createSendHarness();
    expect(harness.row.state).toBe("CREATED");

    // Approval BEFORE any key material / lease.
    expect(harness.row.sourceLeaseHeld).toBe(false);
    expect(harness.row.signIntentPersisted).toBe(false);
    // Simulated TOTP consume + APPROVED transition (no signer called yet).
    harness.row.totpApproved = true;
    harness.transition("APPROVED", "none; operator audit only");
    expect(harness.row.state).toBe("APPROVED");

    // Lease then observe via offline read (source + external dest formation).
    harness.row.sourceLeaseHeld = true;
    const sourceT0 = senderProjection(SOURCE_B0);
    const destFormation = GENESIS_PROJECTION;
    const readTransport = createOfflineReadTransport(createGatewayReadCredentials(), [
      envelopeResponse({ observationId: "obs-send-src-t0", projection: sourceT0 }),
      envelopeResponse({ observationId: "obs-send-dst-formation", projection: destFormation }),
    ]);
    await readTransport.read(
      ["https://gateway.offline.test"],
      buildGatewayActionRequest("get_transaction__v1", { public_key_base64urlsafe: sourcePublic }),
    );
    await readTransport.read(
      ["https://gateway.offline.test"],
      buildGatewayActionRequest("get_transaction__v1", {
        public_key_base64urlsafe: externalDestPublic,
      }),
    );
    expect(readTransport.calls).toHaveLength(2);

    // Durable sign intent → sign once → one immutable partial.
    const formInput = baseFormInput();
    // Structural: vault must not have been called before formAndSign.
    expect(formInput.vault.calls).toHaveLength(0);
    const formed = await formAndSignSendExternal(formInput);
    expect(formed.ok).toBe(true);
    if (!formed.ok) throw new Error(formed.detail);
    expect(formInput.vault.calls).toHaveLength(1); // exactly one sign
    expect(formInput.state.signIntents.size).toBe(1);
    expect(formInput.state.partials.size).toBe(1);
    harness.row.signIntentPersisted = true;
    harness.row.partialCount = 1;
    harness.row.persistedPartialText = formed.transferCodeText;
    harness.row.persistedPartialSha256 = formed.transferCodeSha256;

    // T2 expiry frozen once at formation; available_until is NOT authoritative.
    expect(formed.intent.expiryUnixTimeSecs).toBe(
      String(Math.floor(NODE_CLOCK_MS / 1000) + SEND_REDEMPTION_WINDOW_SECS),
    );
    expect(SEND_REDEMPTION_WINDOW_SECS).toBe(300);
    const inner = JSON.parse(formed.intent.innerPreimageText) as SplitChainInnerV2;
    expect(inner.expiry__unix_time_secs).toBe(formed.intent.expiryUnixTimeSecs);
    expect(inner.step_1_state.amount).toBe(subtractAmounts(SOURCE_B0, SEND_AMOUNT_ZKZ));
    expect(compareAmounts(SEND_AMOUNT_ZKZ, "0.01")).toBe(0); // the live-chain test cap external cap

    harness.transition("AWAITING_REDEMPTION", "external_send.awaiting_redemption");
    expect(harness.row.state).toBe("AWAITING_REDEMPTION");
    expect(formInput.state.status).toBe("AWAITING_REDEMPTION");
    expect(formInput.state.events.map((e) => e.eventType)).toContain(
      "external_send.awaiting_redemption",
    );

    // Redelivery returns byte-identical persisted text.
    const firstDeliveryAt = "2026-07-18T00:00:02.000Z";
    expect(recordInMemoryPartialDelivery(formInput.state, SEND_OPERATION_ID, firstDeliveryAt)).toBe(0);
    const redeliveryAt = "2026-07-18T00:00:03.000Z";
    expect(recordInMemoryPartialDelivery(formInput.state, SEND_OPERATION_ID, redeliveryAt)).toBe(1);
    const partialRow = formInput.state.partials.get(SEND_OPERATION_ID);
    expect(partialRow).toBeDefined();
    expect(partialRow!.transferCodeText).toBe(formed.transferCodeText);
    expect(partialRow!.transferCodeSha256).toBe(formed.transferCodeSha256);
    expect(partialRow!.step1Signature).toBe(formed.step1Signature);
    expect(partialRow!.redeliveryCount).toBe(1);
    // Still exactly one partial row — redelivery must not mint another.
    expect(formInput.state.partials.size).toBe(1);
    harness.row.partialCount = formInput.state.partials.size;

    // Structural: production deriveExecutionPhase forbids any submit fact on SEND_EXTERNAL
    // (mandatory DB test 11 / state/event). A node-created submit attempt is unrepresentable.
    expect(() =>
      deriveExecutionPhase(sendFacts({ submitStarted: true, partialPersisted: true })),
    ).toThrow(/submit attempt exists for an external send/);
    expect(() =>
      deriveExecutionPhase(sendFacts({ submitReturned: true, submitStarted: true, partialPersisted: true })),
    ).toThrow(/submit attempt exists for an external send/);
    // Legal SEND path (partial durable, no submit) derives SIGNED_PERSISTED — never SUBMIT_*.
    expect(
      deriveExecutionPhase(
        sendFacts({
          signIntentPersisted: true,
          partialPersisted: true,
          attemptPhase: "STEP1_SIGNATURE_PERSISTED",
        }),
      ),
    ).toBe("SIGNED_PERSISTED");
    harness.row.submitCountByNode = 0;

    // Recipient-side completion is external — node only observes source lineage.
    const step2Preimage = JSON.stringify({
      inner,
      step_1_signature: formed.step1Signature,
    });
    const step2Signature = signUtf8(seedExternalDest, step2Preimage);
    const settled: SettledSplitChainTransaction = {
      inner,
      step_1_signature: formed.step1Signature,
      step_2_signature: step2Signature,
    };
    const bodySha = sha256Hex(JSON.stringify(settled));
    const sourceProof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: sourcePublic,
      expectedBodySha256: bodySha,
      freshHeadBodySha256: bodySha,
      freshHeadObservationId: "obs-send-src-terminal",
      depth: 0,
    });

    const waiting = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: SEND_ATTEMPT_ID,
      sourceWalletId: SEND_SOURCE_WALLET_ID,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: formed.transferCodeSha256,
      sourceObservation: { result: "NO_SUCCESSOR" },
    });
    expect(waiting.kind).toBe("WAITING");
    if (waiting.kind === "WAITING") {
      expect(waiting.redeliverableTransferCodeSha256).toBe(formed.transferCodeSha256);
    }

    const landed = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: SEND_ATTEMPT_ID,
      sourceWalletId: SEND_SOURCE_WALLET_ID,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: formed.transferCodeSha256,
      sourceObservation: { result: "PROOF", proof: sourceProof },
    });
    expect(landed.kind).toBe("LANDED_VERIFIED");

    const delta = evaluateExternalSendDelta({
      baseline: sourceT0,
      candidateTx: settled,
      sourceWalletPublicKey: sourcePublic,
      operation: {
        amountZkz: SEND_AMOUNT_ZKZ,
        sourcePubkey: sourcePublic,
        destinationAddress: externalDestPublic,
      },
    });
    expect(delta).toEqual({ ok: true });

    harness.transition("EXTERNAL_SEND_LANDED", "external_send.landed");
    expect(harness.row.state).toBe("EXTERNAL_SEND_LANDED");
    expect(harness.row.sourceLeaseHeld).toBe(true); // until verification-complete
    expect(harness.row.partialCount).toBe(1);
    // Production SEND path never creates submit facts (asserted above via deriveExecutionPhase).
    expect(harness.durableEvents).toEqual([
      "external_send.awaiting_redemption",
      "external_send.landed",
    ]);
  });

  it("second sign-intent under same approval is refused (exactly one immutable partial)", async () => {
    const state = createInMemoryFormAndSignState();
    const first = await formAndSignSendExternal(baseFormInput(state));
    expect(first.ok).toBe(true);

    const second = await formAndSignSendExternal(baseFormInput(state));
    expect(second.ok).toBe(false);
    if (second.ok) throw new Error("expected second formation to fail");
    expect(second.reason).toBe("sign_intent_persist_failed");
    expect(state.signIntents.size).toBe(1);
    expect(state.partials.size).toBe(1);
  });

  it("negative: delivered partial with anomaly stays INDETERMINATE / NEEDS_ATTENTION — no close, no node submit", async () => {
    const harness = createSendHarness();
    harness.row.totpApproved = true;
    harness.transition("APPROVED", "none; operator audit only");
    harness.row.sourceLeaseHeld = true;

    const formInput = baseFormInput();
    const formed = await formAndSignSendExternal(formInput);
    expect(formed.ok).toBe(true);
    if (!formed.ok) throw new Error(formed.detail);
    harness.row.signIntentPersisted = true;
    harness.row.partialCount = 1;
    harness.row.persistedPartialText = formed.transferCodeText;
    harness.row.persistedPartialSha256 = formed.transferCodeSha256;
    harness.transition("AWAITING_REDEMPTION", "external_send.awaiting_redemption");

    const indeterminate = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: SEND_ATTEMPT_ID,
      sourceWalletId: SEND_SOURCE_WALLET_ID,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: formed.transferCodeSha256,
      sourceObservation: { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" },
    });
    expect(indeterminate.kind).toBe("INDETERMINATE");

    harness.transition("NEEDS_ATTENTION", "operation.needs_attention");
    expect(harness.row.state).toBe("NEEDS_ATTENTION");
    // Partial + lease retained; no second partial; no node submit.
    expect(harness.row.partialCount).toBe(1);
    expect(harness.row.sourceLeaseHeld).toBe(true);
    expect(formInput.state.partials.size).toBe(1);

    // Production gate still refuses SEND submit facts under NEEDS_ATTENTION.
    expect(() =>
      deriveExecutionPhase(
        sendFacts({
          signIntentPersisted: true,
          partialPersisted: true,
          partialFirstDelivered: true,
          submitStarted: true,
        }),
      ),
    ).toThrow(/submit attempt exists for an external send/);
    expect(harness.row.submitCountByNode).toBe(0);
  });

  it("negative: unattributed successor under source lease is INVARIANT_BREACH (quarantine path)", () => {
    const harness = createSendHarness();
    harness.row.totpApproved = true;
    harness.transition("APPROVED", "none; operator audit only");
    harness.row.sourceLeaseHeld = true;
    harness.row.signIntentPersisted = true;
    harness.row.partialCount = 1;
    harness.transition("AWAITING_REDEMPTION", "external_send.awaiting_redemption");

    const breach = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: SEND_ATTEMPT_ID,
      sourceWalletId: SEND_SOURCE_WALLET_ID,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: "deadbeef",
      sourceObservation: { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" },
    });
    expect(breach.kind).toBe("INVARIANT_BREACH");
    if (breach.kind === "INVARIANT_BREACH") {
      expect(breach.sourceWalletId).toBe(SEND_SOURCE_WALLET_ID);
    }
    harness.transition("NEEDS_ATTENTION", "operation.needs_attention");
    expect(harness.row.partialCount).toBe(1);
    expect(harness.row.sourceLeaseHeld).toBe(true);
  });

  it("proves approval must precede any signer call (custody order)", async () => {
    const harness = createSendHarness();
    const vault = makeDeterministicVaultSigner();
    // CREATED — not yet approved: formation must not run against APPROVED-only ports.
    expect(harness.row.totpApproved).toBe(false);
    expect(vault.calls).toHaveLength(0);

    // In-memory port rejects non-APPROVED status.
    const state = createInMemoryFormAndSignState({ status: "APPROVED" });
    // Force a non-approved claim status path via direct port gate: mutate state after create.
    state.status = "AWAITING_REDEMPTION" as "APPROVED"; // already past APPROVED without our sign
    const rejected = await formAndSignSendExternal({
      ...baseFormInput(state, vault),
      claim: { ...sendClaim(), status: "APPROVED" },
    });
    expect(rejected.ok).toBe(false);
    expect(vault.calls).toHaveLength(0);

    // Correct order: approve → then form.
    harness.row.totpApproved = true;
    harness.transition("APPROVED", "none; operator audit only");
    const okState = createInMemoryFormAndSignState();
    const okVault = makeDeterministicVaultSigner();
    const ok = await formAndSignSendExternal(baseFormInput(okState, okVault));
    expect(ok.ok).toBe(true);
    expect(okVault.calls).toHaveLength(1);
  });
});
