// Offline unit proof of the SEND_EXTERNAL execute ceremony.
//
// Real Ed25519 keys are generated per test (node:crypto only) so the step-1 signature and
// the transfer-code bytes are genuine; no network, no database, no wallet file. The live
// runner substitutes real adapters for these same seams.
//
// Governing:, 13.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
} from "node:crypto";

import { describe, expect, it } from "vitest";

import { buildSendTransferCodeText } from "../../src/protocol/send-transfer-code.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "../../src/protocol/wallet-role.js";
import {
  parseGatewayEnvelope,
  type ParsedSettledTransaction,
} from "../../src/verifier/gateway-envelope.js";
import {
  proveSendLanding,
  type FreshHeadRead,
  type ReadFreshHead,
} from "../../src/verifier/landing-path-oracle.js";

import { createRunnerLock } from "./runner-lock.js";
import { SEND_REDEMPTION_WINDOW_SECS } from "./send-abort-criteria.js";
import {
  createSendGatewayReadGate,
  executeAuthorizedSendExternal,
  type ExternalRecipientSeam,
  type SendExecuteDeps,
  type SendExecuteInput,
  type SendLandingPathEvidence,
  type SendObservation,
  type SendRecipientOutcome,
  type SendRowCounts,
} from "./send-execute.js";
import {
  SAMPLE_SEND_DEST_ADDRESS,
  SAMPLE_SEND_OPERATION_ID,
  SAMPLE_SEND_SOURCE_ID,
  SAMPLE_SEND_SOURCE_PUBKEY,
  eligibleExternalRecipient,
  eligibleSendSource,
  fakeSendProbe,
  readySendState,
  sampleApprovalChallenge,
  sampleOperationRow,
  sampleSendAuth,
  type FakeSendState,
} from "./send-fakes.js";

// ─── Ed25519 helpers (real signatures, padded base64url per A.1) ─────────────

function toPaddedBase64Url(bytes: Buffer): string {
  return bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

function ed25519Signer(): { privateKey: KeyObject; sign: (text: string) => string } {
  const { privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKey,
    sign: (text: string) => toPaddedBase64Url(edSign(null, Buffer.from(text, "utf8"), privateKey)),
  };
}

// ─── Deterministic fake node ────────────────────────────────────────────────

const ATTEMPT_ID = "attempt-send-1";
/** 2026-07-27T12:00:00Z — floor(clock)+300 must land on a stable integer-seconds string. */
const NODE_CLOCK_MS = 1_785_153_600_123;

function senderProjection(balance: string, signature: string): WalletStateProjection {
  return { role: "sender", S: signature, P: signature, B: balance, I: "d".repeat(64) };
}

function observation(
  role: SendObservation["role"],
  publicKey: string,
  projection: WalletStateProjection,
  body: string,
): SendObservation {
  return {
    role,
    publicKey,
    observationId: `obs-${role}`,
    projection,
    rawResponseSha256: createHash("sha256").update(body, "utf8").digest("hex"),
    rawResponseByteLength: Buffer.byteLength(body, "utf8"),
  };
}

interface FakeNode {
  readonly deps: SendExecuteDeps;
  readonly input: SendExecuteInput;
  readonly counts: {
    approvalCalls: number;
    leaseCalls: number;
    gatewayReads: number;
    signerCalls: number;
    signIntentWrites: number;
    partialWrites: number;
    deliveries: number;
    readsBeforeLease: number;
  };
  readonly rows: SendRowCounts & { totpConsumptions: number };
  /** Text handed to the signer, in call order. */
  readonly signedTexts: string[];
}

interface FakeNodeOptions {
  readonly amount?: string;
  readonly sourceBalance?: string;
  readonly sourceProjectionRole?: "sender" | "receiver";
  readonly leaseFails?: boolean;
  readonly approvalCount?: number;
  readonly signIntentFails?: boolean;
  readonly recipient?: (transferCodeText: string) => Promise<SendRecipientOutcome>;
  readonly landingFound?: boolean;
  readonly proveRedelivery?: boolean;
  // ── fault injection: one option per rejection site the census found untested ──
  /** refuse to run unless preflight is ready. False reaches the null-plan guard. */
  readonly requirePreflight?: boolean;
  readonly approvalThrows?: boolean;
  /** The formation observe seam throws under the lease. */
  readonly observeThrows?: boolean;
  /** Node clock in ms. An implausible value makes inner construction throw. */
  readonly nodeClockMs?: number;
  readonly signerThrows?: boolean;
  /** The store reports a status other than AWAITING_REDEMPTION. */
  readonly partialStatusAfter?: "AWAITING_REDEMPTION" | "APPROVED";
  readonly partialPersistFails?: boolean;
  readonly deliveryFails?: boolean;
  /**
   * The store hands back different bytes from this delivery number on. `2`
   * makes the set of delivered texts disagree with itself; `1` makes a self-consistent set
   * that is not the persisted code — the two halves of the re-delivery guard.
   */
  readonly mutateDeliveryFrom?: number;
  readonly countRowsThrows?: boolean;
  /** Row-count evidence the store reports back, overriding the honest tally. */
  readonly rowOverrides?: Partial<SendRowCounts>;
  readonly landingObserveThrows?: boolean;
  /**
   * Force ONE of the two landing-match flags false while the other stays true. No real
   * head can half-match — the step-1 signature is over the inner — but the guard admitting a
   * landing must require BOTH, so the harness has to be able to express the impossible case.
   */
  readonly landingFlagFalse?: "inner" | "step1";
  /**  ceremony mutation: formation observe before lease on the wired path. */
  readonly forceFormationObserveBeforeLease?: boolean;
  /** Keys the ceremony runs against, when the test needs a real signed chain. */
  readonly sourcePubkey?: string;
  readonly destinationAddress?: string;
  /**
   * The private key the run's OWN step 1 is signed with. Must be the source
   * wallet's key whenever a test walks a real chain — otherwise the body the run forms can
   * never be a body the source wallet could have signed, and no assertion about attempt
   * identity can fail.
   */
  readonly signerKey?: KeyObject;
  /** The source baseline's S — the chain link the run's inner is formed over. */
  readonly chainLinkSignature?: string;
  /**
   * The head-anchored landing read finds a head that is NOT our attempt — what a
   * second external inbound to the (public) source address produces in reality.
   */
  readonly headMovedPast?: boolean;
  /**
   * Wires `collectSourceLandingPath`. Omitted = the seam is absent entirely.
   * Built from the material the run actually persisted, so a test can supply either our own
   * attempt or a decoy and the difference is the thing under test.
   */
  readonly landingPath?: (persisted: PersistedAttempt) => SendLandingPathEvidence | null;
}

/** The exact material the run formed and persisted — the seam's query input. */
interface PersistedAttempt {
  readonly innerText: string;
  readonly step1Signature: string;
}

/** Preflight-ready chain state for arbitrary source/destination keys. */
function sendStateFor(sourcePubkey: string, destinationAddress: string): FakeSendState {
  const state = readySendState();
  state.sources.set(
    SAMPLE_SEND_SOURCE_ID,
    eligibleSendSource(SAMPLE_SEND_SOURCE_ID, { pubkey: sourcePubkey }),
  );
  state.recipients.clear();
  state.recipients.set(destinationAddress, eligibleExternalRecipient(destinationAddress));
  state.operations.set(
    SAMPLE_SEND_OPERATION_ID,
    sampleOperationRow(SAMPLE_SEND_OPERATION_ID, { sourcePubkey, destinationAddress }),
  );
  state.challenges.set(
    SAMPLE_SEND_OPERATION_ID,
    sampleApprovalChallenge(SAMPLE_SEND_OPERATION_ID, { sourcePubkey, destinationAddress }),
  );
  return state;
}

function makeFakeNode(options: FakeNodeOptions = {}): FakeNode {
  const signer = ed25519Signer();
  // Captured as a const so the seam below keeps its narrowing inside the closure.
  const supplyLandingPath = options.landingPath;
  const chainLinkSig = options.chainLinkSignature ?? ed25519Signer().sign("prior-settled-state");
  const amount = options.amount ?? "0.000001";
  const sourcePubkey = options.sourcePubkey ?? SAMPLE_SEND_SOURCE_PUBKEY;
  const destinationAddress = options.destinationAddress ?? SAMPLE_SEND_DEST_ADDRESS;
  const sourceProjection: WalletStateProjection =
    options.sourceProjectionRole === "receiver"
      ? { role: "receiver", S: chainLinkSig, P: chainLinkSig, B: options.sourceBalance ?? "1", I: "d".repeat(64) }
      : senderProjection(options.sourceBalance ?? "1", chainLinkSig);

  const counts = {
    approvalCalls: 0,
    leaseCalls: 0,
    gatewayReads: 0,
    signerCalls: 0,
    signIntentWrites: 0,
    partialWrites: 0,
    deliveries: 0,
    readsBeforeLease: 0,
  };
  const rows = {
    totpConsumptions: 0,
    signIntents: 0,
    partials: 0,
    submitDecisions: 0,
    gatewaySubmitAttempts: 0,
  };
  const signedTexts: string[] = [];
  let leaseHeld = false;
  let persistedTransferCode: string | null = null;
  let persistedStep1: string | null = null;
  let persistedInnerText: string | null = null;

  const deps: SendExecuteDeps = {
    approval: {
      consumeApprovalOnce: async () => {
        counts.approvalCalls += 1;
        if (options.approvalThrows === true) throw new Error("approval challenge already consumed");
        if (counts.approvalCalls > 1) {
          throw new Error("approval already consumed for this operation");
        }
        rows.totpConsumptions = options.approvalCount ?? 1;
        return {
          approvalId: "approval-1",
          challengeNonce: "99999999-9999-4999-8999-999999999999",
          totpTimestep: 59_505_120,
          statusAfter: "APPROVED",
          totpConsumptionCount: options.approvalCount ?? 1,
        };
      },
    },
    leases: {
      acquireSourceLease: async ({ operationId, sourceWalletId }) => {
        counts.leaseCalls += 1;
        if (options.leaseFails === true) {
          throw new Error("source wallet already has an active lease");
        }
        leaseHeld = true;
        return {
          walletId: sourceWalletId,
          operationId,
          leaseEpoch: 7n,
          role: "SEND_SOURCE",
          lifecycle: "ACTIVE",
        };
      },
    },
    observe: {
      observeVerified: async ({ publicKey, role }) => {
        counts.gatewayReads += 1;
        if (!leaseHeld) counts.readsBeforeLease += 1;
        if (options.observeThrows === true) throw new Error("gateway observation unavailable");
        return observation(
          role,
          publicKey,
          role === "SEND_SOURCE_T0" ? sourceProjection : GENESIS_PROJECTION,
          `{"status":true,"role":"${role}"}`,
        );
      },
      observeSourceLanding: async ({ persistedInnerPreimageText, persistedStep1Signature }) => {
        counts.gatewayReads += 1;
        if (options.landingObserveThrows === true) throw new Error("source head read unavailable");
        if (options.landingFound === false) return null;
        // `headMovedPast` is the real buried case — the read succeeded, but the
        // head it anchored on is a later transaction, so neither flag can hold.
        const headIsOurs = options.headMovedPast !== true;
        return {
          publicKey: sourcePubkey,
          observationId: "obs-landing",
          step2Signature: ed25519Signer().sign("recipient-step-2"),
          balanceAfter: "0.999999",
          innerTextMatchesPersisted:
            options.landingFlagFalse !== "inner" &&
            headIsOurs &&
            persistedInnerPreimageText === persistedInnerText,
          step1SignatureMatchesPersisted:
            options.landingFlagFalse !== "step1" &&
            headIsOurs &&
            persistedStep1Signature === persistedStep1,
          rawResponseSha256: createHash("sha256").update("landing", "utf8").digest("hex"),
          rawResponseByteLength: 7,
        };
      },
      ...(supplyLandingPath === undefined
        ? {}
        : {
            collectSourceLandingPath: async ({
              persistedInnerPreimageText,
              persistedStep1Signature,
            }) => {
              counts.gatewayReads += 1;
              // A real node retains its own attempt; this fake proves the module asked with
              // the same bytes it persisted, then builds the evidence from them.
              expect(persistedInnerPreimageText).toBe(persistedInnerText);
              expect(persistedStep1Signature).toBe(persistedStep1);
              return supplyLandingPath({
                innerText: persistedInnerPreimageText,
                step1Signature: persistedStep1Signature,
              });
            },
          }),
    },
    signer: {
      signStep1: async ({ preimageText }) => {
        counts.signerCalls += 1;
        signedTexts.push(preimageText);
        if (options.signerThrows === true) throw new Error("vault refused the sign capability");
        return options.signerKey === undefined
          ? signer.sign(preimageText)
          : signWith(preimageText, options.signerKey);
      },
    },
    persist: {
      persistSignIntent: async ({ innerPreimageText }) => {
        if (options.signIntentFails === true) throw new Error("sign-intent DB-TX rolled back");
        counts.signIntentWrites += 1;
        if (counts.signIntentWrites > 1) throw new Error("second sign intent rejected");
        rows.signIntents = 1;
        persistedInnerText = innerPreimageText;
        return { innerPreimageId: "sign-intent-1" };
      },
      persistStep1AndTransferCode: async ({ step1Signature, transferCodeText }) => {
        counts.partialWrites += 1;
        if (options.partialPersistFails === true) throw new Error("partial DB-TX rolled back");
        if (counts.partialWrites > 1) throw new Error("second partial rejected");
        rows.partials = 1;
        persistedStep1 = step1Signature;
        persistedTransferCode = transferCodeText;
        // The guard under test defends against a store that violates its own declared
        // literal type, so only an assertion can express the fault.
        return { statusAfter: (options.partialStatusAfter ?? "AWAITING_REDEMPTION") as "AWAITING_REDEMPTION" };
      },
      countRows: async () => {
        if (options.countRowsThrows === true) throw new Error("row-count read timed out");
        return { ...rows, ...options.rowOverrides };
      },
    },
    delivery: {
      deliver: async ({ transferCodeText }) => {
        counts.deliveries += 1;
        if (options.deliveryFails === true) throw new Error("delivery channel unavailable");
        // A real store re-reads the persisted bytes; this fake proves the caller handed
        // back exactly what was persisted.
        expect(transferCodeText).toBe(persistedTransferCode);
        // A store that hands back different bytes on re-delivery is step 5's
        // exact hazard. The mutation is applied to the PERSISTED bytes, never derived from
        // the argument — a fixture echoing its input could never make the guard fire.
        const delivered =
          options.mutateDeliveryFrom !== undefined && counts.deliveries >= options.mutateDeliveryFrom
            ? `${persistedTransferCode ?? ""}X`
            : persistedTransferCode ?? "";
        return {
          deliveryNo: counts.deliveries,
          transferCodeText: delivered,
          transferCodeSha256: createHash("sha256").update(delivered, "utf8").digest("hex"),
        };
      },
    },
    recipient: {
      verifyCoSignAndSubmit: async ({ transferCodeText }) =>
        options.recipient !== undefined
          ? await options.recipient(transferCodeText)
          : {
              kind: "SUBMITTED",
              detail: "recipient co-signed step 2 and submitted once",
              step2Signature: ed25519Signer().sign("recipient-step-2"),
              rawGatewayResponseBase64: Buffer.from('{"status":true}', "utf8").toString("base64"),
              rawGatewayResponseSha256: createHash("sha256")
                .update('{"status":true}', "utf8")
                .digest("hex"),
              gatewayStatusCode: 200,
              recipientSubmitCallCount: 1,
            },
    },
    nodeClockMs: () => options.nodeClockMs ?? NODE_CLOCK_MS,
  };

  const input: SendExecuteInput = {
    attemptId: ATTEMPT_ID,
    operationId: SAMPLE_SEND_OPERATION_ID,
    sourceWalletId: SAMPLE_SEND_SOURCE_ID,
    sourcePubkey,
    destinationAddress,
    amount,
    authorization: sampleSendAuth(ATTEMPT_ID),
    runnerLock: createRunnerLock(),
    runnerHolderId: "fixture-runner",
    preflightProbe: fakeSendProbe(sendStateFor(sourcePubkey, destinationAddress)),
    proveRedelivery: options.proveRedelivery,
    forceFormationObserveBeforeLease: options.forceFormationObserveBeforeLease,
    requirePreflight: options.requirePreflight,
  };

  return { deps, input, counts, rows, signedTexts };
}

describe("executeAuthorizedSendExternal — full ceremony", () => {
  it("runs the full ceremony once and lands verified", async () => {
    const node = makeFakeNode();
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
    expect(result.ok).toBe(true);
    expect(result.evidence.approval?.totpConsumptionCount).toBe(1);
    expect(result.evidence.leaseHeldBeforeFormationReads).toBe(true);
    // Preflight balance probe is a real gateway read and is counted; formation/landing
    // observes run only after the lease (readsBeforeLease stays 0 on the observe seam).
    expect(result.evidence.preflightGatewayReadCount).toBe(1);
    expect(result.evidence.gatewayReadCount).toBe(4); // preflight + T0 + dest + landing
    expect(node.counts.readsBeforeLease).toBe(0);
    expect(node.counts.signerCalls).toBe(1);
    expect(
      result.evidence.trail.some((line) => line.includes("preflight_gateway_reads=1")),
    ).toBe(true);
    expect(
      result.evidence.trail.some((line) =>
        line.includes("before formation gateway reads") &&
        line.includes("preflight_gateway_reads=1"),
      ),
    ).toBe(true);
    expect(result.evidence.rowCounts).toEqual({
      totpConsumptions: 1,
      signIntents: 1,
      partials: 1,
      submitDecisions: 0,
      gatewaySubmitAttempts: 0,
    });
  });

  it("has no node submit seam at all", () => {
    const node = makeFakeNode();
    expect(Object.keys(node.deps)).not.toContain("submit");
    // @ts-expect-error — SendExecuteDeps has no submit member; adding one must not compile.
    expect(node.deps.submit).toBeUndefined();
  });

  it("consumes the TOTP approval exactly once, and a second consumption is rejected", async () => {
    const node = makeFakeNode();
    await executeAuthorizedSendExternal(node.deps, node.input);
    expect(node.counts.approvalCalls).toBe(1);
    await expect(node.deps.approval.consumeApprovalOnce({ operationId: SAMPLE_SEND_OPERATION_ID }))
      .rejects.toThrow(/already consumed/);
    expect(node.rows.totpConsumptions).toBe(1);
  });

  it("treats a reported second consumption as an invariant breach", async () => {
    const node = makeFakeNode({ approvalCount: 2 });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);
    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(node.counts.gatewayReads).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
    // Preflight still ran its balance probe; the gate counts it.
    expect(result.evidence.preflightGatewayReadCount).toBe(1);
    expect(result.evidence.gatewayReadCount).toBe(1);
  });

  it("acquires the source lease before formation gateway reads; preflight probe is counted", async () => {
    const node = makeFakeNode({ leaseFails: true });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SIGN_INTENT");
    expect(result.evidence.leaseHeldBeforeFormationReads).toBe(false);
    // Observe seam never called — lease failed first.
    expect(node.counts.gatewayReads).toBe(0);
    // But the preflight balance probe DID run and is visible on the gate.
    expect(result.evidence.preflightGatewayReadCount).toBe(1);
    expect(result.evidence.gatewayReadCount).toBe(1);
    // Do not mint another operation or consume another approval.
    expect(node.counts.approvalCalls).toBe(1);
  });

  it("ceremony mutation: formation observe before lease → ESCALATE_INVARIANT_BREACH", async () => {
    // Wired-path proof: force a formation seam call before lease acquisition so
    // executeAuthorizedSendExternal's markLeaseAcquired fail-closed branch reddens.
    // Bare createSendGatewayReadGate unit tests alone would stay green if that branch
    // were deleted — this test would not.
    const node = makeFakeNode({ forceFormationObserveBeforeLease: true });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.leaseHeldBeforeFormationReads).toBe(false);
    expect(result.evidence.abortTrigger).toBe("INVARIANT_BREACH");
    // Preflight (1) + forced formation observe (1); landing never reached.
    expect(result.evidence.preflightGatewayReadCount).toBe(1);
    expect(result.evidence.gatewayReadCount).toBe(2);
    expect(node.counts.readsBeforeLease).toBe(1);
    expect(node.counts.leaseCalls).toBe(1);
    // Fail-closed before formation phase / sign intent / signer.
    expect(node.counts.signerCalls).toBe(0);
    expect(node.counts.signIntentWrites).toBe(0);
    expect(node.counts.partialWrites).toBe(0);
    expect(
      result.evidence.trail.some((line) =>
        line.includes("formation/landing") && line.includes("preceded the source lease"),
      ),
    ).toBe(true);
  });

  it("never calls the signer before the durable sign intent commits", async () => {
    const node = makeFakeNode({ signIntentFails: true });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SIGN_INTENT");
    expect(node.counts.signerCalls).toBe(0);
    expect(node.counts.partialWrites).toBe(0);
  });

  it("freezes the redemption expiry at floor(node_clock)+300 inside the signed preimage", async () => {
    const node = makeFakeNode();
    const result = await executeAuthorizedSendExternal(node.deps, node.input);
    const expected = String(Math.floor(NODE_CLOCK_MS / 1000) + SEND_REDEMPTION_WINDOW_SECS);

    expect(result.evidence.formation?.expiryUnixTimeSecs).toBe(expected);
    expect(node.signedTexts).toHaveLength(1);
    expect(node.signedTexts[0]).toContain(`"expiry__unix_time_secs":"${expected}"`);
  });

  it("builds the transfer code from the persisted text and signature verbatim", async () => {
    const node = makeFakeNode();
    const result = await executeAuthorizedSendExternal(node.deps, node.input);
    const formation = result.evidence.formation;
    if (formation === null) throw new Error("formation missing");

    expect(formation.transferCodeText).toBe(
      buildSendTransferCodeText(formation.innerPreimageText, formation.step1Signature),
    );
    // The persisted inner text is spliced in verbatim — decoding the code must yield the
    // exact same bytes, never a reserialization.
    const decoded = decodeURIComponent(
      Buffer.from(formation.transferCodeText, "base64url").toString("utf8"),
    );
    expect(decoded).toContain(formation.innerPreimageText);
  });

  it("re-delivers byte-identical bytes and signs only once", async () => {
    const node = makeFakeNode();
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.deliveries).toHaveLength(2);
    const [first, second] = result.evidence.deliveries;
    expect(second?.transferCodeText).toBe(first?.transferCodeText);
    expect(second?.transferCodeSha256).toBe(first?.transferCodeSha256);
    expect(second?.deliveryNo).toBe(2);
    expect(node.counts.signerCalls).toBe(1);
    expect(node.counts.partialWrites).toBe(1);
  });

  it("holds the lease and never re-signs when the recipient outcome is stale-destination", async () => {
    const node = makeFakeNode({
      recipient: async () => ({
        kind: "REFUSED_STALE_DESTINATION",
        detail: "recipient head moved after SEND_DESTINATION_FORMATION",
        step2Signature: null,
        rawGatewayResponseBase64: null,
        rawGatewayResponseSha256: null,
        gatewayStatusCode: null,
        recipientSubmitCallCount: 0,
      }),
    });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("RECIPIENT_REFUSED_STALE_DESTINATION");
    expect(result.evidence.abortAction).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(node.counts.signerCalls).toBe(1);
    expect(node.counts.signIntentWrites).toBe(1);
    expect(node.counts.partialWrites).toBe(1);
    expect(result.evidence.rowCounts?.submitDecisions).toBe(0);
    expect(result.evidence.rowCounts?.gatewaySubmitAttempts).toBe(0);
  });

  it("holds and reconciles — never re-forms — on an indeterminate recipient submit", async () => {
    const node = makeFakeNode({
      recipient: async () => ({
        kind: "INDETERMINATE",
        detail: "transport ambiguity after the recipient's single submit",
        step2Signature: null,
        rawGatewayResponseBase64: null,
        rawGatewayResponseSha256: null,
        gatewayStatusCode: null,
        recipientSubmitCallCount: 1,
      }),
    });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(node.counts.signerCalls).toBe(1);
    expect(node.counts.partialWrites).toBe(1);
  });

  it("stays AWAITING_REDEMPTION when the independent read shows no completed transaction", async () => {
    const node = makeFakeNode({ landingFound: false });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("AWAITING_REDEMPTION_DELIVERED");
    expect(result.evidence.landing).toBeNull();
    expect(node.counts.partialWrites).toBe(1);
  });

  it("refuses an amount above the hard cap before consuming the approval", async () => {
    const node = makeFakeNode({ amount: "0.02" });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("PREFLIGHT_NOT_READY");
    // The not-ready gate must be what refused. The null-plan guard below reaches the
    // same disposition, so a disposition-only assertion stays green with this gate deleted.
    expect(
      result.evidence.trail.some((line) => line.includes("preflight not ready — refusing execute")),
    ).toBe(true);
    expect(node.counts.approvalCalls).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
  });

  it("forms successfully when the source baseline projects as receiver", async () => {
    // Has no role condition; dropped the sender-only gate.
    // A treasury whose last settled hop was incoming projects receiver and must still SEND.
    const node = makeFakeNode({ sourceProjectionRole: "receiver" });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
    expect(result.ok).toBe(true);
    expect(node.counts.signerCalls).toBe(1);
    expect(node.counts.signIntentWrites).toBe(1);
    expect(result.evidence.sourceT0?.projection.role).toBe("receiver");
  });
});

// ─── — the rejection sites the census found undeclared ───────────────
//
// `send-execute-guards.census.test.ts` enumerates every `finish(false, …)` site from the
// source text rather than from anyone's list. Twelve of the thirty-one already had a killing
// test; these close fourteen more. Each asserts the site's own trail line, not just the
// disposition — several sites share a disposition, so a disposition-only assertion would
// stay green when a mutant reaches it by the wrong branch.
//

describe("executeAuthorizedSendExternal — declared rejection sites", () => {
  const trailHas = (result: Awaited<ReturnType<typeof executeAuthorizedSendExternal>>, text: string) =>
    result.evidence.trail.some((line) => line.includes(text));

  it("refuses a null plan when the preflight gate itself is bypassed", async () => {
    // `requirePreflight: false` is the only path past the not-ready refusal, and preflight
    // yields no plan when it is not ready — so the ceremony must refuse a second time rather
    // than proceed with `plan` null.
    const node = makeFakeNode({ amount: "0.02", requirePreflight: false });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("PREFLIGHT_NOT_READY");
    expect(trailHas(result, "preflight ready but plan null — refuse")).toBe(true);
    expect(trailHas(result, "preflight not ready — refusing execute")).toBe(false);
    expect(node.counts.approvalCalls).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
  });

  it("aborts before the source lease when the approval consumption throws", async () => {
    const node = makeFakeNode({ approvalThrows: true });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SIGN_INTENT");
    expect(trailHas(result, "approval consumption failed")).toBe(true);
    expect(result.evidence.approval).toBeNull();
    expect(node.counts.leaseCalls).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
  });

  it("a formation observation throws under the lease", async () => {
    const node = makeFakeNode({ observeThrows: true });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SIGN_INTENT");
    expect(result.evidence.abortTrigger).toBe("FORMATION_REJECTED");
    expect(trailHas(result, "formation observation failed")).toBe(true);
    // The lease WAS taken first — this is not the pre-lease breach.
    expect(result.evidence.leaseHeldBeforeFormationReads).toBe(true);
    expect(node.counts.signIntentWrites).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
  });

  it("the baseline predicates reject the capture", async () => {
    // The T0 projection reports a source balance below the plan amount. The preflight
    // gateway probe is a separate read and still passes, so this is the step 5
    // predicate refusing on its own evidence — not preflight refusing again.
    const node = makeFakeNode({ sourceBalance: "0" });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SIGN_INTENT");
    expect(result.evidence.abortTrigger).toBe("FORMATION_REJECTED");
    expect(trailHas(result, "baseline rejected source_insufficient_balance")).toBe(true);
    expect(node.counts.signIntentWrites).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
  });

  it("inner construction throws on an implausible node clock", async () => {
    // plausibility floor: a clock in SECONDS handed to a MILLISECONDS parameter.
    // Formation must abort rather than freeze a nonsense expiry into a signing preimage.
    const node = makeFakeNode({ nodeClockMs: 1_000 });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("ABORTED_BEFORE_SIGN_INTENT");
    expect(result.evidence.abortTrigger).toBe("FORMATION_REJECTED");
    expect(trailHas(result, "inner construction failed")).toBe(true);
    expect(node.counts.signIntentWrites).toBe(0);
    expect(node.counts.signerCalls).toBe(0);
  });

  it("holds the lease when the signer throws after the durable sign intent", async () => {
    // The sign intent is durable, so recovery is "sign the identical persisted
    // preimage" — never re-form. Nothing was delivered, so the lease must be held.
    const node = makeFakeNode({ signerThrows: true });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(result.evidence.abortTrigger).toBe("PARTIAL_DELIVERED_UNOBSERVED");
    expect(trailHas(result, "step-1 sign failed after durable sign intent")).toBe(true);
    expect(node.counts.signIntentWrites).toBe(1);
    expect(node.counts.partialWrites).toBe(0);
    expect(node.counts.deliveries).toBe(0);
  });

  it("the partial persist reports a status other than AWAITING_REDEMPTION", async () => {
    const node = makeFakeNode({ partialStatusAfter: "APPROVED" });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortTrigger).toBe("INVARIANT_BREACH");
    expect(trailHas(result, "INVARIANT: status after partial persist = APPROVED")).toBe(true);
    expect(node.counts.deliveries).toBe(0);
  });

  it("holds and reconciles when the partial persist throws", async () => {
    const node = makeFakeNode({ partialPersistFails: true });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(trailHas(result, "partial persist failed")).toBe(true);
    expect(trailHas(result, "nothing delivered")).toBe(true);
    expect(node.counts.signerCalls).toBe(1);
    expect(node.counts.deliveries).toBe(0);
  });

  it("holds and reconciles when delivery throws", async () => {
    const node = makeFakeNode({ deliveryFails: true });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(trailHas(result, "delivery failed")).toBe(true);
    expect(trailHas(result, "persisted code remains exact")).toBe(true);
    // The partial IS persisted — the code is durable and re-deliverable.
    expect(node.counts.partialWrites).toBe(1);
    expect(result.evidence.formation).not.toBeNull();
  });

  it("escalates when a single delivery returns bytes that are not the persisted code", async () => {
    // The second half of the re-delivery guard. One delivery cannot disagree with itself, so
    // `distinctDelivered.size !== 1` is satisfied — only the membership clause can refuse a
    // self-consistent set of the WRONG bytes.
    const node = makeFakeNode({ mutateDeliveryFrom: 1, proveRedelivery: false });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortTrigger).toBe("INVARIANT_BREACH");
    expect(trailHas(result, "INVARIANT: re-delivery returned different bytes")).toBe(true);
    expect(result.evidence.deliveries).toHaveLength(1);
    expect(result.evidence.deliveries[0]?.transferCodeText).not.toBe(
      result.evidence.formation?.transferCodeText,
    );
  });

  it("escalates when re-delivery returns different bytes", async () => {
    // "the same logical send with different chain-link fields" is forbidden.
    // The mutation is applied to the persisted bytes, so the guard has something real to
    // compare — a delivery fake echoing its argument could never make it fire.
    const node = makeFakeNode({ mutateDeliveryFrom: 2 });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortTrigger).toBe("INVARIANT_BREACH");
    expect(trailHas(result, "INVARIANT: re-delivery returned different bytes")).toBe(true);
    expect(result.evidence.deliveries).toHaveLength(2);
    const [first, second] = result.evidence.deliveries;
    expect(second?.transferCodeText).not.toBe(first?.transferCodeText);
    // Never a second signature or a second partial in response.
    expect(node.counts.signerCalls).toBe(1);
    expect(node.counts.partialWrites).toBe(1);
  });

  it("holds and reconciles when the external recipient seam throws", async () => {
    const node = makeFakeNode({
      recipient: async () => {
        throw new Error("recipient transport failed mid-exchange");
      },
    });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(trailHas(result, "recipient path threw")).toBe(true);
    expect(trailHas(result, "outcome unknown")).toBe(true);
    expect(result.evidence.recipient).toBeNull();
    expect(node.counts.signerCalls).toBe(1);
  });

  it("holds and reconciles when persist.countRows throws", async () => {
    const node = makeFakeNode({ countRowsThrows: true });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(trailHas(result, "row-count read failed")).toBe(true);
    expect(result.evidence.rowCounts).toBeNull();
  });

  // R-08 and: exactly one TOTP consumption, one sign intent, one partial, and
  // structurally zero submits. One row per conjunct, so no single clause can carry the guard.
  it.each([
    ["totpConsumptions", { totpConsumptions: 2 }],
    ["signIntents", { signIntents: 2 }],
    ["partials", { partials: 2 }],
    ["submitDecisions", { submitDecisions: 1 }],
    ["gatewaySubmitAttempts", { gatewaySubmitAttempts: 1 }],
  ] as const)(
    "escalates when the row-count evidence %s violates the one-approval / no-node-submit rule",
    async (_field, rowOverrides) => {
      const node = makeFakeNode({ rowOverrides });
      const result = await executeAuthorizedSendExternal(node.deps, node.input);

      expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
      expect(result.evidence.abortTrigger).toBe("INVARIANT_BREACH");
      expect(trailHas(result, "INVARIANT: row counts violate the one-approval / no-node-submit rule")).toBe(true);
    },
  );

  it("holds and reconciles when the independent landing read throws", async () => {
    const node = makeFakeNode({ landingObserveThrows: true });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(trailHas(result, "landing observation threw")).toBe(true);
    expect(result.evidence.landing).toBeNull();
    // A failed read is not evidence of non-landing: never a breach, never a second partial.
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(node.counts.partialWrites).toBe(1);
  });

  // The head-read landing admission requires BOTH persisted-material flags. Either one
  // alone admitting a landing would release the source lease on a head that is not our
  // attempt — the worst outcome this module has, and the reason exists.
  it.each([
    ["inner", "inner=false step1=true"],
    ["step1", "inner=true step1=false"],
  ] as const)(
    "refuses to call a half-matching head a landing (%s flag false)",
    async (landingFlagFalse, expectedFlags) => {
      const node = makeFakeNode({ landingFlagFalse });
      const result = await executeAuthorizedSendExternal(node.deps, node.input);

      expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
      expect(result.ok).toBe(false);
      expect(trailHas(result, `observed head does not carry the persisted material (${expectedFlags})`)).toBe(
        true,
      );
      expect(result.evidence.abortAction).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    },
  );
});


describe("createSendGatewayReadGate — bare-gate unit (complement; ceremony proof above)", () => {
  const inertProbe = {
    loadSource: async () => null,
    loadRecipient: async () => null,
    activeLeases: async () => [],
    freshGatewayBalance: async () => "1" as const,
    loadOperation: async () => null,
    loadApprovalChallenge: async () => null,
    freshVaultBackup: async () => ({ present: false as const, capturedAt: null }),
  };

  const inertObserve = {
    observeVerified: async ({
      publicKey,
      role,
    }: {
      publicKey: string;
      role: "SEND_SOURCE_T0" | "SEND_DESTINATION_FORMATION";
    }) => ({
      role,
      publicKey,
      observationId: "obs-mut",
      projection: GENESIS_PROJECTION,
      rawResponseSha256: "0".repeat(64),
      rawResponseByteLength: 2,
    }),
    observeSourceLanding: async () => null,
  };

  it("counts preflight probe reads without failing the lease mark", async () => {
    const gate = createSendGatewayReadGate();
    const probe = gate.wrapProbe(inertProbe);
    await probe.freshGatewayBalance("w");
    await probe.freshGatewayBalance("w");
    const marked = gate.markLeaseAcquired();
    expect(marked.ok).toBe(true);
    expect(marked.leaseHeldBeforeFormationReads).toBe(true);
    expect(marked.snapshot.preflight).toBe(2);
    expect(marked.snapshot.total).toBe(2);
    expect(marked.snapshot.formationOrLandingReadsBeforeLease).toBe(0);
  });

  it("mutation proof: formation gateway read before lease reddens markLeaseAcquired", async () => {
    const gate = createSendGatewayReadGate();
    const observe = gate.wrapObserve(inertObserve);
    // Move a formation observe BEFORE the lease mark — the original vacuous-counter defect.
    await observe.observeVerified({
      publicKey: SAMPLE_SEND_SOURCE_PUBKEY,
      role: "SEND_SOURCE_T0",
    });
    const marked = gate.markLeaseAcquired();
    expect(marked.ok).toBe(false);
    expect(marked.leaseHeldBeforeFormationReads).toBe(false);
    expect(marked.snapshot.formationOrLandingReadsBeforeLease).toBe(1);
    expect(marked.snapshot.formation).toBe(1);
    expect(marked.snapshot.preflight).toBe(0);
  });

  it("mutation proof: landing read before lease also reddens", async () => {
    const gate = createSendGatewayReadGate();
    const observe = gate.wrapObserve(inertObserve);
    await observe.observeSourceLanding({
      publicKey: SAMPLE_SEND_SOURCE_PUBKEY,
      persistedInnerPreimageText: "{}",
      persistedStep1Signature: "sig",
    });
    const marked = gate.markLeaseAcquired();
    expect(marked.ok).toBe(false);
    expect(marked.snapshot.formationOrLandingReadsBeforeLease).toBe(1);
    expect(marked.snapshot.landing).toBe(1);
  });

  it("mutation proof: gateway read between lease and formation reddens markFormationStart", async () => {
    const gate = createSendGatewayReadGate();
    const probe = gate.wrapProbe(inertProbe);
    const observe = gate.wrapObserve(inertObserve);
    await probe.freshGatewayBalance("w");
    expect(gate.markLeaseAcquired().ok).toBe(true);
    // Interstitial formation read after lease, before formation phase mark.
    await observe.observeVerified({
      publicKey: SAMPLE_SEND_SOURCE_PUBKEY,
      role: "SEND_SOURCE_T0",
    });
    const formed = gate.markFormationStart();
    expect(formed.ok).toBe(false);
    expect(formed.readsBetweenLeaseAndFormation).toBe(1);
  });

  it("happy path through the gate: preflight → lease → formation start → observes", async () => {
    const gate = createSendGatewayReadGate();
    const probe = gate.wrapProbe(inertProbe);
    const observe = gate.wrapObserve(inertObserve);
    await probe.freshGatewayBalance("w");
    const leased = gate.markLeaseAcquired();
    expect(leased.ok).toBe(true);
    expect(leased.snapshot.preflight).toBe(1);
    expect(gate.markFormationStart().ok).toBe(true);
    await observe.observeVerified({
      publicKey: SAMPLE_SEND_SOURCE_PUBKEY,
      role: "SEND_SOURCE_T0",
    });
    await observe.observeVerified({
      publicKey: SAMPLE_SEND_DEST_ADDRESS,
      role: "SEND_DESTINATION_FORMATION",
    });
    const s = gate.snapshot();
    expect(s.total).toBe(3);
    expect(s.preflight).toBe(1);
    expect(s.formation).toBe(2);
    expect(s.formationOrLandingReadsBeforeLease).toBe(0);
  });
});

describe("ExternalRecipientSeam", () => {
  it("is the only member that can submit — the node's own deps expose no submit", () => {
    const node = makeFakeNode();
    const recipient: ExternalRecipientSeam = node.deps.recipient;
    expect(typeof recipient.verifyCoSignAndSubmit).toBe("function");
    expect(Object.keys(node.deps).sort()).toEqual([
      "approval",
      "delivery",
      "leases",
      "nodeClockMs",
      "observe",
      "persist",
      "recipient",
      "signer",
    ]);
  });
});

// ─── — a buried landing is a landing, never an invariant breach ──────
//
// The source pubkey is a public address and the source lease is a node-side lock, so
// nothing stops a second external payment landing on the source wallet between the
// recipient's submit and the terminal read. The head-anchored read then finds a
// transaction that is not ours. OBS keeps REJECTED for a cryptographically determinate
// mismatch and routes every read/anomaly/gap/regression to INDETERMINATE; the complete-path walk makes
// a head reached from our attempt by a verified complete path a POSITIVE landing.
//
// Every body below is a real Ed25519-signed settled transaction over real signed bytes —
// the oracle reverifies each one and would reject a hand-assembled object.

/** Deterministic Ed25519 key from a seed byte (same recipe as the vectors). */
function keyFromSeed(byte: number): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, byte),
    ]),
    format: "der",
    type: "pkcs8",
  });
}

function publicKeyOf(privateKey: KeyObject): string {
  // The trailing 32 bytes of the SPKI DER are the raw Ed25519 public key (A.1 padded
  // base64url) — derived from the key, never transcribed.
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return toPaddedBase64Url(spki.subarray(spki.length - 32));
}

const signWith = (text: string, key: KeyObject): string =>
  toPaddedBase64Url(edSign(null, Buffer.from(text, "utf8"), key));

const SOURCE_KEY = keyFromSeed(0x11);
const DEST_KEY = keyFromSeed(0x22);
const PAYER_KEY = keyFromSeed(0x33);
const BURIED_SOURCE = publicKeyOf(SOURCE_KEY);
const BURIED_DEST = publicKeyOf(DEST_KEY);
const BURIED_PAYER = publicKeyOf(PAYER_KEY);

function headEnvelope(settledText: string): FreshHeadRead {
  return {
    observationId: `obs-${settledText.length}`,
    envelope: parseGatewayEnvelope(
      new TextEncoder().encode(
        `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
      ),
    ),
  };
}

function parsedBody(settledText: string): ParsedSettledTransaction {
  const verdict = headEnvelope(settledText).envelope;
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD envelope verdict");
  return verdict.parsed;
}

/**
 * One settled `unique_combinable` v2 transaction, signed for real in the order:
 * step 1 over `JSON.stringify(inner)` by the sender key, step 2 over
 * `JSON.stringify({inner, step_1_signature})` by the receiver key. Byte-exact — the field
 * order below IS the signed preimage (the byte-exact signing rule).
 */
function settledTx(spec: {
  readonly senderKey: KeyObject;
  readonly senderPubkey: string;
  readonly receiverKey: KeyObject;
  readonly receiverPubkey: string;
  readonly senderRemaining: string;
  readonly receiverAmount: string;
  readonly previousStep1: string;
  readonly previousStep2: string;
  readonly unixTimeSecs: string;
}): { readonly text: string; readonly body: ParsedSettledTransaction } {
  const inner = {
    type: "unique_combinable" as const,
    version: "2" as const,
    unix_time_secs: spec.unixTimeSecs,
    signer_steps: 2 as const,
    step_1_signer: "sender" as const,
    step_2_signer: "receiver" as const,
    step_1_key_public__base64urlsafe: spec.senderPubkey,
    step_2_key_public__base64urlsafe: spec.receiverPubkey,
    step_1_state: { amount: spec.senderRemaining },
    step_2_state: { amount: spec.receiverAmount },
    previous_step_1_state_signature: spec.previousStep1,
    previous_step_2_state_signature: spec.previousStep2,
  };
  const step1Signature = signWith(JSON.stringify(inner), spec.senderKey);
  const step2Signature = signWith(
    JSON.stringify({ inner, step_1_signature: step1Signature }),
    spec.receiverKey,
  );
  const text = JSON.stringify({
    inner,
    step_1_signature: step1Signature,
    step_2_signature: step2Signature,
  });
  return { text, body: parsedBody(text) };
}

// T0 — an external payer credits the node's source wallet 1 ZKZ. Source projects
// `receiver`, so its baseline B is step_2_state.amount and its S is step_2_signature.
const T0 = settledTx({
  senderKey: PAYER_KEY,
  senderPubkey: BURIED_PAYER,
  receiverKey: SOURCE_KEY,
  receiverPubkey: BURIED_SOURCE,
  senderRemaining: "9",
  receiverAmount: "1",
  previousStep1: "",
  previousStep2: "",
  unixTimeSecs: "1785153600",
});

/**
 * OUR attempt, as it lands: the EXACT inner preimage text the run persisted, spliced
 * verbatim into the completed transaction and co-signed as step 2 by the destination key.
 * The retained inner bytes are never re-serialized — this is the same splice
 * transaction-verify.ts:273-275 performs to rebuild a completed body (the byte-exact signing rule).
 *
 * F2: the body under test has to be the body the run FORMED. A fixture signed with
 * an unrelated key can satisfy every disposition assertion while proving nothing about
 * whose landing was found.
 */
function completedBody(
  innerText: string,
  step1Signature: string,
): { readonly text: string; readonly body: ParsedSettledTransaction } {
  const step2Signature = signWith(
    `{"inner":${innerText},"step_1_signature":${JSON.stringify(step1Signature)}}`,
    DEST_KEY,
  );
  const text =
    `{"inner":${innerText}` +
    `,"step_1_signature":${JSON.stringify(step1Signature)}` +
    `,"step_2_signature":${JSON.stringify(step2Signature)}}`;
  return { text, body: parsedBody(text) };
}

/**
 * A DECOY: a second step_1 from the SAME chain-link position as our attempt, signed by the
 * real source key, differing only in the free `unix_time_secs` field. Same source, same
 * destination, same amount, same predecessor — so it satisfies every predicate
 * `proveSendLanding` checks: both signatures, per-hop `P == S`, fresh-head anchoring and
 * `evaluateExternalSendDelta` against T0. Only the retained bytes tell the two apart.
 *
 * The one-in-flight-per-wallet rule's exact hazard: two unsettled step_1s from one chain-link position, one of
 * which is permanently rejected. If the decoy landed, ours did not.
 */
function decoyInnerText(ourInnerText: string): string {
  const innerText = ourInnerText.replace(
    /"unix_time_secs":"(\d+)"/,
    (_match, secs: string) => `"unix_time_secs":"${String(Number(secs) + 1)}"`,
  );
  if (innerText === ourInnerText) throw new Error("decoy is byte-identical to our attempt");
  return innerText;
}

function decoyBody(ourInnerText: string): {
  readonly text: string;
  readonly body: ParsedSettledTransaction;
} {
  const innerText = decoyInnerText(ourInnerText);
  return completedBody(innerText, signWith(innerText, SOURCE_KEY));
}

/**
 * Two later external inbounds that bury `buried` on the source wallet: T+1 then T+2. The
 * source projects `receiver` on an inbound hop, so its P is `previous_step_2_state_signature`
 * and must back-link to the previous hop's S — which is that hop's `step_2_signature` in
 * either role.
 */
function burialsOver(buried: ParsedSettledTransaction) {
  const first = settledTx({
    senderKey: PAYER_KEY,
    senderPubkey: BURIED_PAYER,
    receiverKey: SOURCE_KEY,
    receiverPubkey: BURIED_SOURCE,
    senderRemaining: "8.5",
    receiverAmount: "0.5",
    previousStep1: T0.body.step_1_signature,
    previousStep2: buried.step_2_signature,
    unixTimeSecs: "1785154200",
  });
  const second = settledTx({
    senderKey: PAYER_KEY,
    senderPubkey: BURIED_PAYER,
    receiverKey: SOURCE_KEY,
    receiverPubkey: BURIED_SOURCE,
    senderRemaining: "8",
    receiverAmount: "0.5",
    previousStep1: first.body.step_1_signature,
    previousStep2: first.body.step_2_signature,
    unixTimeSecs: "1785154500",
  });
  return { first, second };
}

/**
 * Everything a test can hand the seam, built from what the run ACTUALLY persisted:
 * T0 → our attempt → BURIAL → BURIAL_2, and the identical shape over the DECOY. Both
 * segments are real signed chains; only the retained bytes tell our attempt from the decoy.
 */
function walkChain(persisted: PersistedAttempt) {
  const attempt = completedBody(persisted.innerText, persisted.step1Signature);
  const decoy = decoyBody(persisted.innerText);
  const ours = burialsOver(attempt.body);
  return {
    persisted,
    attempt,
    decoy,
    burial: ours.first,
    burial2: ours.second,
    decoyBurial: burialsOver(decoy.body).first,
    // OUR step-1 signature spliced over a DIFFERENT inner. The identity guard
    // has two operands; this body satisfies exactly one of them, so each can be shown
    // load-bearing on its own. It cannot verify — the signature is over the inner — which is
    // precisely why the guard must refuse it BEFORE the walk rather than let the oracle see it.
    ourStep1OverDecoyInner: completedBody(decoyInnerText(persisted.innerText), persisted.step1Signature),
  };
}

type WalkChain = ReturnType<typeof walkChain>;

/** Head reader that answers both oracle reads with the same head. */
function staticHead(settledText: string): ReadFreshHead {
  return async () => headEnvelope(settledText);
}

function evidence(
  expectedBody: ParsedSettledTransaction,
  successorBodies: readonly ParsedSettledTransaction[],
  headText: string,
): SendLandingPathEvidence {
  return {
    t0Body: T0.body,
    expectedBody,
    successorBodies,
    readFreshHead: staticHead(headText),
  };
}

/**
 * A node whose source wallet really is `BURIED_SOURCE`: the run's own step 1 is signed with
 * that wallet's key and formed over T0's chain link, so the body it forms is a body that
 * could actually land on this chain.
 */
function buriedNode(
  landingPath?: (persisted: PersistedAttempt) => SendLandingPathEvidence | null,
  overrides: FakeNodeOptions = {},
) {
  return makeFakeNode({
    sourcePubkey: BURIED_SOURCE,
    destinationAddress: BURIED_DEST,
    signerKey: SOURCE_KEY,
    chainLinkSignature: T0.body.step_2_signature,
    headMovedPast: true,
    ...(landingPath === undefined ? {} : { landingPath }),
    ...overrides,
  });
}

/**
 * Runs the ceremony on the buried node and lets `supply` choose what the seam hands back,
 * with the chain built from the bytes the run itself persisted. Returns the chain so a test
 * can assert against the body the run FORMED rather than a fixture that merely resembles it.
 */
async function runBuried(
  supply: (chain: WalkChain) => SendLandingPathEvidence | null,
  overrides: FakeNodeOptions = {},
) {
  const built: WalkChain[] = [];
  const node = buriedNode((persisted) => {
    const chain = walkChain(persisted);
    built.push(chain);
    return supply(chain);
  }, overrides);
  const result = await executeAuthorizedSendExternal(node.deps, node.input);
  const chain = built[0];
  if (chain === undefined) throw new Error("the landing-path seam was never consulted");
  return { result, chain, node };
}

describe("buried landing disposition", () => {
  it("the body under test IS the body this run formed, on a real chain", async () => {
    // Guards every assertion below. The expected body is the run's own persisted inner
    // spliced verbatim and co-signed by the destination — not a fixture signed by an
    // unrelated key, which would satisfy every disposition assertion while proving nothing
    // about whose landing was found.
    const { chain } = await runBuried((c) => evidence(c.attempt.body, [c.burial.body], c.burial.text));

    expect(chain.attempt.text.startsWith(`{"inner":${chain.persisted.innerText},`)).toBe(true);
    expect(chain.attempt.body.step_1_signature).toBe(chain.persisted.step1Signature);
    expect(chain.attempt.body.inner.step_1_key_public__base64urlsafe).toBe(BURIED_SOURCE);
    expect(chain.attempt.body.inner.previous_step_1_state_signature).toBe(T0.body.step_2_signature);
    expect(chain.burial.body.inner.previous_step_2_state_signature).toBe(
      chain.attempt.body.step_2_signature,
    );
    // And the decoy really is a rival second step_1 from that same chain-link position.
    expect(chain.decoy.body.inner.step_1_key_public__base64urlsafe).toBe(BURIED_SOURCE);
    expect(chain.decoy.body.inner.previous_step_1_state_signature).toBe(T0.body.step_2_signature);
    expect(chain.decoy.body.step_1_signature).not.toBe(chain.attempt.body.step_1_signature);
  });

  it("a second external inbound between submit and the terminal read is a LANDING, not a breach", async () => {
    const { result, chain, node } = await runBuried((c) =>
      evidence(c.attempt.body, [c.burial.body], c.burial.text),
    );

    expect(result.evidence.disposition).toBe("LANDED_BURIED_COMPLETE_PATH");
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.ok).toBe(true);
    expect(result.evidence.abortAction).toBe("COMPLETE_LANDED_VERIFIED");
    expect(result.evidence.landingProof).toMatchObject({
      kind: "LANDED_COMPLETE_PATH",
      depth: 1,
      walletPubkeyBase64Urlsafe: BURIED_SOURCE,
    });
    // The proof identifies OUR attempt's body, never the head's (the root cause).
    expect(result.evidence.landingProof).toMatchObject({
      expectedBodySha256: createHash("sha256").update(chain.attempt.text, "utf8").digest("hex"),
    });
    // Still exactly one of everything — a landing proof authorizes no second anything.
    expect(node.counts.signerCalls).toBe(1);
    expect(node.counts.partialWrites).toBe(1);
    expect(result.evidence.rowCounts?.submitDecisions).toBe(0);
  });

  it("PROBE-D0: a decoy at depth 0 is INDETERMINATE — a landing proof is not OUR landing", async () => {
    // The one-in-flight-per-wallet rule's hazard: two unsettled step_1s from one chain-link position, only one
    // of which can settle. If the decoy is what landed, ours did not — so reporting a
    // landing here would settle the send and release the source lease on coins that never
    // moved. Refused before the walk runs: the bytes decide, not the seam.
    const { result } = await runBuried((c) => evidence(c.decoy.body, [], c.decoy.text), {
      landingFound: false,
    });

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(result.evidence.landingProof).toBeNull();
    expect(result.evidence.abortAction).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
  });

  it("PROBE-D1: a decoy buried one deep is INDETERMINATE, never LANDED_BURIED_COMPLETE_PATH", async () => {
    const { result } = await runBuried((c) =>
      evidence(c.decoy.body, [c.decoyBurial.body], c.decoyBurial.text),
    );

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.disposition).not.toBe("LANDED_BURIED_COMPLETE_PATH");
    expect(result.ok).toBe(false);
    expect(result.evidence.landingProof).toBeNull();
  });

  it("the decoy segment is otherwise perfect — only attempt identity refuses it", async () => {
    // Without this the two probes above could pass for the wrong reason (a decoy chain the
    // oracle rejects anyway). Run the oracle directly on the decoy segment: both signatures,
    // per-hop P == S, fresh-head anchoring and `evaluateExternalSendDelta` against T0 all
    // hold, because `unix_time_secs` is free. The byte comparison against the persisted
    // attempt is the ONLY thing that tells the two apart.
    const { chain } = await runBuried((c) =>
      evidence(c.decoy.body, [c.decoyBurial.body], c.decoyBurial.text),
    );

    const proof = await proveSendLanding(
      {
        walletPubkeyBase64Urlsafe: BURIED_SOURCE,
        t0Body: T0.body,
        expectedBody: chain.decoy.body,
        successorBodies: [chain.decoyBurial.body],
        operation: {
          amountZkz: "0.000001",
          sourcePubkey: BURIED_SOURCE,
          destinationAddress: BURIED_DEST,
        },
      },
      staticHead(chain.decoyBurial.text),
    );

    expect(proof).toMatchObject({ kind: "LANDED_COMPLETE_PATH", depth: 1 });
  });

  it("MUTATION: drop the intervening body and the walk can no longer bridge — INDETERMINATE", async () => {
    // Identical run, one change: the successor the forward-walk needs is withheld, so the
    // path stops short of the head. If the walk were a no-op — or if the disposition were
    // read off the head instead of anchored on our attempt — this would still report a
    // landing and the test above would be unfalsifiable.
    const { result, node } = await runBuried((c) => evidence(c.attempt.body, [], c.burial.text));

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(result.evidence.landingProof).toEqual({
      kind: "PROOF_INCOMPLETE",
      fault: "MISSING_BODY",
    });
    // INDETERMINATE holds the lease and reconciles; it never escalates and never rebuilds.
    expect(result.evidence.abortAction).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(node.counts.partialWrites).toBe(1);
  });

  it("MUTATION: a gapped path (hop 2 supplied, hop 1 missing) is INDETERMINATE, never a landing", async () => {
    const { result } = await runBuried((c) =>
      evidence(c.attempt.body, [c.burial2.body], c.burial2.text),
    );

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.landingProof).toEqual({ kind: "PROOF_INCOMPLETE", fault: "GAP" });
    // The PROOF_INCOMPLETE branch must be what refused. The exhaustiveness branch
    // below routes to the same disposition, so a disposition-only assertion stays green with
    // this branch deleted.
    expect(
      result.evidence.trail.some((line) => line.includes("landing walk incomplete (GAP)")),
    ).toBe(true);
  });

  it("MUTATION: a head that moved during the walk is INDETERMINATE, never a stale positive", async () => {
    let reads = 0;
    const { result } = await runBuried((c) => ({
      t0Body: T0.body,
      expectedBody: c.attempt.body,
      successorBodies: [c.burial.body],
      readFreshHead: async () => {
        reads += 1;
        return headEnvelope(reads === 1 ? c.burial.text : c.burial2.text);
      },
    }));

    expect(reads).toBe(2); // the oracle anchors AND confirms; one read would be a guess
    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.landingProof).toEqual({ kind: "PROOF_INCOMPLETE", fault: "CONFLICT" });
  });

  it("no retained path evidence at all is INDETERMINATE — never an invariant breach", async () => {
    // The earlier shape: head does not carry the persisted material and nothing can be
    // walked. That is a read outcome, not a determinate mismatch (has no
    // generic PROVEN_NOT_LANDED oracle).
    const node = makeFakeNode({ headMovedPast: true });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.landingProof).toBeNull();
    expect(result.evidence.abortAction).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
  });

  it("a late landing the head read never saw still proves depth 0", async () => {
    // `observeSourceLanding` found no completed transaction at all; the walk then proves our
    // attempt IS the head. Nothing contradicts, so this is a plain late landing.
    const { result } = await runBuried((c) => evidence(c.attempt.body, [], c.attempt.text), {
      landingFound: false,
    });

    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
    expect(result.evidence.landingProof).toMatchObject({ kind: "LANDED_EXACT", depth: 0 });
  });

  it("LANDED_EXACT against a head read that did NOT carry our attempt is a contradiction", async () => {
    // Same evidence as above, but the head read succeeded and reported a head that is not
    // ours. Heads only advance, so "the head is not ours" and "our attempt is the head"
    // cannot both be true — routes a contradictory wallet path to INDETERMINATE, not to
    // a positive landing.
    const { result } = await runBuried((c) => evidence(c.attempt.body, [], c.attempt.text));

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.ok).toBe(false);
    expect(result.evidence.landingProof).toMatchObject({ kind: "LANDED_EXACT", depth: 0 });
    expect(result.evidence.abortAction).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
  });

  it("determinate breaches are untouched — row counts still escalate", async () => {
    // Guards the narrowing: moved ONE predicate off ESCALATE_INVARIANT_BREACH.
    const node = makeFakeNode({ approvalCount: 2 });
    const result = await executeAuthorizedSendExternal(node.deps, node.input);

    expect(result.evidence.disposition).toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.abortAction).toBe("ESCALATE_INVARIANT_BREACH");
  });

  it("the buried-landing seam call passes the gateway-read gate", async () => {
    const { result, node } = await runBuried((c) =>
      evidence(c.attempt.body, [c.burial.body], c.burial.text),
    );

    // preflight + T0 + dest + landing + landing-path = 5 gated seam calls.
    expect(result.evidence.gatewayReadCount).toBe(5);
    expect(result.evidence.leaseHeldBeforeFormationReads).toBe(true);
    expect(node.counts.readsBeforeLease).toBe(0);
  });

  it("a body carrying our step-1 signature over a different inner never reaches the walk", async () => {
    // The identity guard is `!innerMatchesAttempt ||!step1MatchesAttempt`.
    // This body satisfies the step-1 operand exactly (the bytes ARE ours) and fails the inner
    // one, so it isolates the first operand: with only the second guarding, the walk would
    // run on a body that is not our attempt. A null landingProof is the proof it never did.
    const { result, chain } = await runBuried((c) =>
      evidence(c.ourStep1OverDecoyInner.body, [c.burial.body], c.burial.text),
    );

    expect(chain.ourStep1OverDecoyInner.body.step_1_signature).toBe(chain.persisted.step1Signature);
    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.landingProof).toBeNull();
    expect(
      result.evidence.trail.some((line) =>
        line.includes("landing-path evidence names a body that is not our attempt (inner=false step1=true)"),
      ),
    ).toBe(true);
  });

  it("a landing-path evidence read that throws still settles, never propagates", async () => {
    // The seam is optional gateway I/O on a public address; a node that cannot read
    // it must still reach a disposition. The catch swallows deliberately — the run continues
    // with no path evidence and settles INDETERMINATE, rather than rejecting the caller's
    // promise and leaving the operation with no evidence bundle at all.
    const { result } = await runBuried(() => {
      throw new Error("retained-path store unavailable");
    });

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.landingProof).toBeNull();
    expect(result.evidence.abortAction).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(
      result.evidence.trail.some((line) => line.includes("landing-path evidence read threw")),
    ).toBe(true);
  });

  it("the landing walk itself throwing is INDETERMINATE, never a breach", async () => {
    // The oracle's fresh-head confirm-read is live gateway I/O and can fail. The
    // evidence names OUR attempt, so the identity binding passes and the walk really runs —
    // then rejects. has no PROVEN_NOT_LANDED oracle, so a thrown walk authorizes
    // nothing: no rebuild, no second partial, no lease release.
    const { result } = await runBuried((c) => ({
      t0Body: T0.body,
      expectedBody: c.attempt.body,
      successorBodies: [c.burial.body],
      readFreshHead: async () => {
        throw new Error("fresh head confirm-read failed");
      },
    }));

    expect(result.evidence.disposition).toBe("LANDING_INDETERMINATE");
    expect(result.evidence.disposition).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.landingProof).toBeNull();
    expect(result.evidence.abortAction).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(
      result.evidence.trail.some((line) => line.includes("landing walk threw")),
    ).toBe(true);
  });
});
