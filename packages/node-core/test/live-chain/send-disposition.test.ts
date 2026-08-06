// Offline unit tests for SEND_EXTERNAL reconcile + disposition.
//
// No network, no filesystem, no real private-key custody. Builds LANDED_VERIFIED execute
// evidence from real Ed25519 SplitChain transactions (same construction as the
// policy suite), then drives disposeSendExternalEvidence.
// Headline invariants:
//   - fresh source head (not mid-run) drives debit + partial identity;
//   - OBS path manifest all VERIFIED;
//   - source-head mismatch → NEEDS_ATTENTION (never inferred non-landing);
//   - landing DB-TX pairs EXTERNAL_SEND_LANDED with external_send.landed;
//   - ack carries SOURCE + DESTINATION (external counterparty, walletId null);
//   - source lease releases only after group predicate RELEASED;
//   - disposition never submits / never mints replacement partial (submitCallCount === 0);
//   - stale-destination negative documented and held;
//   - at least one negative-path assertion.

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  buildSendTransferCodeText,
  hashTransferCodeText,
} from "../../src/protocol/send-transfer-code.js";
import type { WalletStateProjection } from "../../src/protocol/wallet-role.js";
import type { GroupReleaseFacts } from "../../src/verification/predicates.js";
import { REQUIRED_EVIDENCE_ROLES } from "../../src/verification/predicates.js";
import { verifySettledTransaction } from "../../src/verifier/transaction-verify.js";
import {
  buildTransaction,
  parseSettled,
  publicKeyFromSeed,
  type BuiltTransaction,
} from "../../src/proof/policies/test-transactions.js";

import {
  sendAbortActionFor,
  sendExternalAbortCriteria,
} from "./send-abort-criteria.js";
import {
  SEND_EXTERNAL_PATH_PREDICATES,
  disposeSendExternalEvidence,
  parseSendSettledTransactionText,
  type SendDispositionDeps,
  type SendFreshHeadReRead,
  type SendLandingCommitRecord,
  type SendEvidencePacket,
  type SendVerificationAckRecord,
} from "./send-disposition.js";
import type {
  SendExecuteEvidenceBundle,
  SendFormationRecord,
  SendObservation,
} from "./send-execute.js";
import type { SendExternalPlan } from "./send-preflight.js";
import type { DualControlAuthorization } from "./types.js";

// ─── Fixture keys / chain (mirrors send.test.ts economics at dust scale) ─────

const SOURCE_SEED = 0x30;
const RECIPIENT_SEED = 0x31;
const SOURCE = publicKeyFromSeed(SOURCE_SEED);
const RECIPIENT = publicKeyFromSeed(RECIPIENT_SEED);
const SOURCE_WALLET_ID = "11111111-1111-4111-8111-111111111111";
const OPERATION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ATTEMPT_ID = "attempt-send-disposition-1";
const AMOUNT = "0.000001";
const SOURCE_BALANCE_BEFORE = "1";
const SOURCE_BALANCE_AFTER = "0.999999";
const DEST_BALANCE_AFTER = "0.000001";

const SOURCE_PREDECESSOR = buildTransaction({
  senderSeed: 0x32,
  receiverSeed: SOURCE_SEED,
  senderBalanceAfter: "0",
  receiverBalanceAfter: SOURCE_BALANCE_BEFORE,
});

// Genesis-style recipient baseline (balance 0) needs a projection, not a predecessor tx
// with amount 0 which may still project as receiver. Build with amount "0" after receive
// of 0 is awkward — use verify on predecessor when non-zero, else genesis-like projection.
function baselineOf(built: BuiltTransaction, walletPublicKey: string): WalletStateProjection {
  const verdict = verifySettledTransaction(parseSettled(built.settledText), walletPublicKey);
  if (verdict.verdict !== "VERIFIED") {
    throw new Error(`fixture did not verify: ${verdict.verdict}`);
  }
  return verdict.projection;
}

const SOURCE_BASELINE = baselineOf(SOURCE_PREDECESSOR, SOURCE);

// Recipient starts at genesis (balance 0) for a clean external dust credit.
const RECIPIENT_BASELINE: WalletStateProjection = {
  role: "genesis",
  S: "",
  P: "",
  B: "0",
  I: null,
};

const SEND = buildTransaction({
  senderSeed: SOURCE_SEED,
  receiverSeed: RECIPIENT_SEED,
  senderBalanceAfter: SOURCE_BALANCE_AFTER,
  receiverBalanceAfter: DEST_BALANCE_AFTER,
  previousStep1Signature: SOURCE_PREDECESSOR.step2Signature,
  previousStep2Signature: "", // genesis destination
  expiry: "1785153900",
  unixTimeSecs: "1785153600.125",
});

const CONFLICT_STEP2 =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

// ─── Execute-evidence builder ────────────────────────────────────────────────

function auth(attemptId: string): DualControlAuthorization {
  return {
    attemptId,
    attestationId: "attestation-send-disposition-1",
    recordedAt: "2026-07-27T12:00:00.000Z",
  };
}

function planFor(): SendExternalPlan {
  return {
    kind: "SEND_EXTERNAL",
    attemptId: ATTEMPT_ID,
    operationId: OPERATION_ID,
    sourceWalletId: SOURCE_WALLET_ID,
    sourcePubkey: SOURCE,
    destinationAddress: RECIPIENT,
    amount: AMOUNT,
    authorization: auth(ATTEMPT_ID),
  };
}

function observation(
  role: SendObservation["role"],
  publicKey: string,
  projection: WalletStateProjection,
): SendObservation {
  const body = `{"status":true,"role":"${role}"}`;
  return {
    role,
    publicKey,
    observationId: `obs-${role}`,
    projection,
    rawResponseSha256: createHash("sha256").update(body, "utf8").digest("hex"),
    rawResponseByteLength: Buffer.byteLength(body, "utf8"),
  };
}

function formationFor(built: BuiltTransaction = SEND): SendFormationRecord {
  // Real SEND transfer-code bytes so delivery projection is non-vacuous.
  const transferCodeText = buildSendTransferCodeText(
    built.innerPreimageText,
    built.step1Signature,
  );
  return {
    attemptNo: 1,
    innerPreimageText: built.innerPreimageText,
    innerSha256: createHash("sha256").update(built.innerPreimageText, "utf8").digest("hex"),
    expiryUnixTimeSecs: "1785153900",
    redemptionExpiryAt: "2026-07-27T12:05:00.000Z",
    formationUnixTimeSecs: "1785153600",
    step1Signature: built.step1Signature,
    transferCodeText,
    transferCodeSha256: hashTransferCodeText(transferCodeText),
  };
}

function landedExecuteEvidence(
  overrides: Partial<SendExecuteEvidenceBundle> = {},
  built: BuiltTransaction = SEND,
): SendExecuteEvidenceBundle {
  const formation = formationFor(built);
  const code = formation.transferCodeText;
  return {
    attemptId: ATTEMPT_ID,
    operationId: OPERATION_ID,
    plan: planFor(),
    disposition: "LANDED_VERIFIED",
    abortAction: "COMPLETE_LANDED_VERIFIED",
    abortTrigger: "LANDED_VERIFIED",
    leaseHeldBeforeAnyRead: true,
    nodeSubmitSeamAbsent: true,
    approval: {
      approvalId: "approval-send-1",
      challengeNonce: "99999999-9999-4999-8999-999999999999",
      totpTimestep: 59_505_120,
      statusAfter: "APPROVED",
      totpConsumptionCount: 1,
    },
    sourceT0: observation("SEND_SOURCE_T0", SOURCE, SOURCE_BASELINE),
    destinationFormation: observation(
      "SEND_DESTINATION_FORMATION",
      RECIPIENT,
      RECIPIENT_BASELINE,
    ),
    formation,
    deliveries: [
      {
        deliveryNo: 1,
        transferCodeText: code,
        transferCodeSha256: formation.transferCodeSha256,
      },
      {
        deliveryNo: 2,
        transferCodeText: code,
        transferCodeSha256: formation.transferCodeSha256,
      },
    ],
    recipient: {
      kind: "SUBMITTED",
      detail: "recipient co-signed step 2 and submitted once",
      step2Signature: built.step2Signature,
      rawGatewayResponseBase64: Buffer.from('{"status":true}', "utf8").toString("base64"),
      rawGatewayResponseSha256: createHash("sha256")
        .update('{"status":true}', "utf8")
        .digest("hex"),
      gatewayStatusCode: 200,
      recipientSubmitCallCount: 1,
    },
    landing: {
      publicKey: SOURCE,
      observationId: "obs-landing-midrun",
      step2Signature: built.step2Signature,
      balanceAfter: SOURCE_BALANCE_AFTER,
      innerTextMatchesPersisted: true,
      step1SignatureMatchesPersisted: true,
      rawResponseSha256: createHash("sha256").update("landing-mid", "utf8").digest("hex"),
      rawResponseByteLength: 11,
    },
    rowCounts: {
      totpConsumptions: 1,
      signIntents: 1,
      partials: 1,
      submitDecisions: 0,
      gatewaySubmitAttempts: 0,
    },
    trail: ["execute LANDED_VERIFIED (fixture)"],
    preflight: null,
    ...overrides,
  };
}

// ─── Disposition fakes ───────────────────────────────────────────────────────

interface DispositionWorld {
  readonly executeEvidence: SendExecuteEvidenceBundle;
  readonly built: BuiltTransaction;
  freshMissing: boolean;
  /** Fresh head carries a different step_2 (source-head mismatch → NEEDS_ATTENTION). */
  freshHeadMismatch: boolean;
  /** Fresh head balance wrong (debit ≠ amount → ESCALATE). */
  freshBalanceWrong: boolean;
  /** Fresh settled body uses foreign inner bytes (partial identity fail). */
  freshForeignBody: boolean;
  dbAgrees: boolean;
  groupChildPending: boolean;
  releaseCalls: number;
  archiveCalls: number;
  landingCommits: SendLandingCommitRecord[];
  acks: SendVerificationAckRecord[];
  archivedPackets: SendEvidencePacket[];
  refuseRelease: boolean;
}

function makeDispositionWorld(
  overrides: Partial<DispositionWorld> & {
    executeEvidence?: SendExecuteEvidenceBundle;
    built?: BuiltTransaction;
  } = {},
): DispositionWorld {
  const built = overrides.built ?? SEND;
  return {
    executeEvidence: overrides.executeEvidence ?? landedExecuteEvidence({}, built),
    built,
    freshMissing: false,
    freshHeadMismatch: false,
    freshBalanceWrong: false,
    freshForeignBody: false,
    dbAgrees: true,
    groupChildPending: false,
    releaseCalls: 0,
    archiveCalls: 0,
    landingCommits: [],
    acks: [],
    archivedPackets: [],
    refuseRelease: false,
    ...overrides,
  };
}

function buildDispositionDeps(dworld: DispositionWorld): SendDispositionDeps {
  const exec = dworld.executeEvidence;
  const plan = exec.plan!;

  return {
    freshHeads: {
      async reReadFreshSourceHead() {
        if (dworld.freshMissing) return null;

        if (dworld.freshForeignBody) {
          // Foreign body bytes with the *expected* head step_2 stamp so D1 head-identity
          // passes and partial-identity (inner/step1) is the load-bearing failure.
          const twin = buildTransaction({
            senderSeed: SOURCE_SEED,
            receiverSeed: RECIPIENT_SEED,
            senderBalanceAfter: SOURCE_BALANCE_AFTER,
            receiverBalanceAfter: DEST_BALANCE_AFTER,
            previousStep1Signature: SOURCE_PREDECESSOR.step2Signature,
            previousStep2Signature: "",
            expiry: "1785153900",
            unixTimeSecs: "1785153601.750",
          });
          return {
            publicKey: SOURCE,
            observationId: "obs-fresh-source-foreign",
            step2Signature: dworld.built.step2Signature,
            balance: SOURCE_BALANCE_AFTER,
            settled: twin.parsed,
            settledTransactionText: twin.settledText,
            rawResponseSha256: createHash("sha256")
              .update(twin.settledText, "utf8")
              .digest("hex"),
            rawResponseByteLength: Buffer.byteLength(twin.settledText, "utf8"),
          } satisfies SendFreshHeadReRead;
        }

        let step2 = dworld.built.step2Signature;
        const text = dworld.built.settledText;
        const settled = dworld.built.parsed;
        let balance = SOURCE_BALANCE_AFTER;
        let obsId = "obs-fresh-source";

        if (dworld.freshHeadMismatch) {
          step2 = CONFLICT_STEP2;
          // Keep same body bytes but report a different head step2 — models
          // "head names something else" without rewriting the landed body.
          obsId = "obs-fresh-source-mismatch";
        }
        if (dworld.freshBalanceWrong) {
          balance = "0.999998";
          obsId = "obs-fresh-source-bad-delta";
        }

        return {
          publicKey: SOURCE,
          observationId: obsId,
          step2Signature: step2,
          balance,
          settled,
          settledTransactionText: text,
          rawResponseSha256: createHash("sha256").update(text, "utf8").digest("hex"),
          rawResponseByteLength: Buffer.byteLength(text, "utf8"),
        } satisfies SendFreshHeadReRead;
      },
    },
    landing: {
      async commitLanding(input) {
        const record: SendLandingCommitRecord = {
          operationId: input.operationId,
          priorState: input.priorState,
          nextState: "EXTERNAL_SEND_LANDED",
          eventType: "external_send.landed",
          sourceTerminalObservationId: input.sourceTerminalObservationId,
          verifiedAt: input.verifiedAt,
          sameDbTx: true,
        };
        dworld.landingCommits.push(record);
        return record;
      },
    },
    ack: {
      async recordAcknowledgement(input) {
        const record: SendVerificationAckRecord = {
          operationId: input.operationId,
          verdict: input.verdict,
          evidenceRoles: ["SOURCE", "DESTINATION"],
          evidence: [...input.evidence],
          evidenceSetComplete: true,
        };
        dworld.acks.push(record);
        return record;
      },
    },
    groupFacts: {
      async loadGroupFacts(input) {
        const facts: GroupReleaseFacts = {
          childDisposition: dworld.groupChildPending ? "PENDING" : "NONE",
          operations: [
            {
              operationId: input.operationId,
              kind: "SEND_EXTERNAL",
              verdict: input.thisLegAck.verdict,
              evidenceRoles: input.thisLegAck.evidenceRoles,
              evidence: input.thisLegAck.evidence,
              expectedWallets: [
                {
                  role: "SOURCE",
                  walletId: plan.sourceWalletId,
                  walletPublicKey: SOURCE,
                },
                {
                  role: "DESTINATION",
                  walletId: null,
                  walletPublicKey: plan.destinationAddress,
                },
              ],
              completed: true,
            },
          ],
        };
        return facts;
      },
    },
    leases: {
      async releaseSourceIfGroupPassed(input) {
        dworld.releaseCalls += 1;
        if (input.status !== "RELEASED") {
          throw new Error("release seam invoked without RELEASED status");
        }
        if (dworld.refuseRelease) {
          return { sourceReleased: false };
        }
        return { sourceReleased: true };
      },
    },
    evidenceArchive: {
      async archive(packet) {
        dworld.archiveCalls += 1;
        dworld.archivedPackets.push(packet);
        return { archiveId: `qa-${packet.attemptId}` };
      },
    },
    dbChain: {
      async dbAgreesWithChain(input) {
        // D3: harness default compares settled body bytes to the independent fresh head
        // (not a free boolean). Tests may still force disagreement via dworld.dbAgrees.
        const freshBytesMatch =
          input.settledTransactionText === input.source.settledTransactionText;
        if (!freshBytesMatch) {
          return {
            agrees: false,
            detail: "settledTransactionText ≠ fresh-head settled body bytes",
          };
        }
        return dworld.dbAgrees
          ? { agrees: true, detail: "persisted formation and fresh head byte-agree" }
          : { agrees: false, detail: "persisted step_1 ≠ fresh settled step_1" };
      },
    },
    nowIso: () => "2026-07-27T12:10:00.000Z",
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("disposeSendExternalEvidence — happy path", () => {
  it("disposes LANDED_VERIFIED execute: path, debit, ack, source release, evidence", async () => {
    const evidence = landedExecuteEvidence();
    const dworld = makeDispositionWorld({ executeEvidence: evidence });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: SEND.settledText,
      destinationBaseline: RECIPIENT_BASELINE,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(true);
    expect(result.evidence.outcome).toBe("DISPOSED_VERIFIED");
    expect(result.evidence.submitCallCount).toBe(0);
    expect(result.evidence.mayResubmit).toBe(false);
    expect(result.evidence.mayMintReplacementPartial).toBe(false);
    expect(result.evidence.mayReconsumeApproval).toBe(false);
    expect(result.evidence.mayRebuildWithoutPositiveOracle).toBe(false);
    expect(result.evidence.mayInferNonLandingFromSilence).toBe(false);
    expect(result.evidence.mayFreeLeaseBecauseRecipientSilent).toBe(false);

    // Fresh head is not the mid-run landing observation.
    expect(result.evidence.freshSource?.observationId).toBe("obs-fresh-source");
    expect(result.evidence.freshSource?.observationId).not.toBe(
      evidence.landing?.observationId,
    );
    expect(result.evidence.freshSource?.rawResponseSha256).toMatch(/^[0-9a-f]{64}$/);

    // Source debit exact.
    expect(result.evidence.sourceDebit?.sourceExact).toBe(true);
    expect(result.evidence.sourceDebit?.sourceDebit).toBe(AMOUNT);

    // Partial identity.
    expect(result.evidence.partialIdentity?.innerMatches).toBe(true);
    expect(result.evidence.partialIdentity?.step1Matches).toBe(true);

    // Path manifest — all predicates VERIFIED.
    expect(result.evidence.pathManifest?.outcome).toBe("VERIFIED");
    expect(result.evidence.pathManifest?.allVerified).toBe(true);
    expect(result.evidence.pathManifest?.entries).toHaveLength(
      SEND_EXTERNAL_PATH_PREDICATES.length,
    );
    for (const e of result.evidence.pathManifest!.entries) {
      expect(e.status).toBe("VERIFIED");
    }

    // Landing DB-TX.
    expect(result.evidence.landing?.nextState).toBe("EXTERNAL_SEND_LANDED");
    expect(result.evidence.landing?.eventType).toBe("external_send.landed");
    expect(result.evidence.landing?.priorState).toBe("AWAITING_REDEMPTION");
    expect(result.evidence.landing?.sameDbTx).toBe(true);

    // Ack SOURCE + DESTINATION (external walletId null).
    expect(result.evidence.acknowledgement?.verdict).toBe("VERIFIED");
    expect(result.evidence.acknowledgement?.evidenceRoles).toEqual([
      "SOURCE",
      "DESTINATION",
    ]);
    const destEv = result.evidence.acknowledgement?.evidence.find(
      (e) => e.role === "DESTINATION",
    );
    expect(destEv?.walletId).toBeNull();
    expect(destEv?.walletPublicKey).toBe(RECIPIENT);

    // Source lease release gated on group predicate.
    expect(result.evidence.leaseRelease?.clampedStatus).toBe("RELEASED");
    expect(result.evidence.leaseRelease?.released).toBe(true);
    expect(result.evidence.leaseRelease?.releaseGatedOnGroupPredicate).toBe(true);
    expect(dworld.releaseCalls).toBe(1);

    // evidence packet.
    expect(dworld.archiveCalls).toBe(1);
    const packet = result.evidence.evidencePacket!;
    expect(packet.kind).toBe("SEND_EXTERNAL_LIVE_CHAIN_EVIDENCE_V1");
    expect(packet.dualControl).toBe(true);
    expect(packet.externalCounterparty).toBe(true);
    expect(packet.staleDestinationNegativeDocumented).toBe(true);
    expect(packet.safeForbiddenHonored).toBe(true);
    expect(packet.noSpeculativeContractImplemented).toBe(true);
    expect(packet.negativePathAssertion.length).toBeGreaterThan(0);
    expect(packet.packetSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(
      packet.governingRules.some((s) => s.includes("observation and verification")),
    ).toBe(true);
    expect(packet.governingRules.some((s) => s.includes("operations and recovery"))).toBe(
      true,
    );
  });

  it("SEND_EXTERNAL required evidence roles are SOURCE + DESTINATION", () => {
    expect(REQUIRED_EVIDENCE_ROLES.SEND_EXTERNAL).toEqual(["SOURCE", "DESTINATION"]);
    expect(SEND_EXTERNAL_PATH_PREDICATES).toEqual([
      "send_artifact_verify",
      "approval_consumed",
      "sign_intent_bind",
      "preimage_exact_match",
      "source_sender_bind",
      "destination_key_approved",
      "destination_predecessor_consistent",
      "source_exact_head",
      "single_partial_delivery",
    ]);
  });
});

describe("disposeSendExternalEvidence — negative paths (no blind retry / no submit)", () => {
  it("refuses when execute is not LANDED_VERIFIED and never releases", async () => {
    const base = landedExecuteEvidence();
    const broken: SendExecuteEvidenceBundle = {
      ...base,
      disposition: "HOLD_SOURCE_LEASE_AND_RECONCILE",
    };
    const dworld = makeDispositionWorld({ executeEvidence: broken });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: broken,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("REFUSED_EXECUTE_NOT_LANDED");
    expect(result.evidence.submitCallCount).toBe(0);
    expect(dworld.releaseCalls).toBe(0);
    expect(dworld.archiveCalls).toBe(0);
  });

  it("stale-destination execute → HOLD, never re-sign, documents negative", async () => {
    const base = landedExecuteEvidence();
    const stale: SendExecuteEvidenceBundle = {
      ...base,
      disposition: "RECIPIENT_REFUSED_STALE_DESTINATION",
      recipient: {
        kind: "REFUSED_STALE_DESTINATION",
        detail: "destination head advanced past formation baseline",
        step2Signature: null,
        rawGatewayResponseBase64: null,
        rawGatewayResponseSha256: null,
        gatewayStatusCode: null,
        recipientSubmitCallCount: 0,
      },
      landing: null,
    };
    const dworld = makeDispositionWorld({ executeEvidence: stale });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: stale,
      artifactVerificationOk: true,
      requireLandedExecute: false,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("HOLD_SOURCE_LEASE_AND_RECONCILE");
    expect(result.evidence.mayMintReplacementPartial).toBe(false);
    expect(result.evidence.mayResubmit).toBe(false);
    expect(dworld.releaseCalls).toBe(0);
    expect(result.evidence.trail.some((l) => l.includes("stale-destination"))).toBe(true);
  });

  it("NEGATIVE: missing fresh head → NEEDS_ATTENTION, no release, no non-landing inference", async () => {
    const evidence = landedExecuteEvidence();
    const dworld = makeDispositionWorld({
      executeEvidence: evidence,
      freshMissing: true,
    });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: SEND.settledText,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("NEEDS_ATTENTION");
    expect(result.evidence.mayInferNonLandingFromSilence).toBe(false);
    expect(result.evidence.submitCallCount).toBe(0);
    expect(dworld.releaseCalls).toBe(0);
    expect(sendAbortActionFor("PARTIAL_DELIVERED_UNOBSERVED").mayMintReplacementPartial).toBe(
      false,
    );
  });

  it("NEGATIVE: source-head mismatch → NEEDS_ATTENTION (never non-landing per)", async () => {
    const evidence = landedExecuteEvidence();
    const dworld = makeDispositionWorld({
      executeEvidence: evidence,
      freshHeadMismatch: true,
    });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: SEND.settledText,
      destinationBaseline: RECIPIENT_BASELINE,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("NEEDS_ATTENTION");
    expect(result.evidence.outcome).not.toBe("DISPOSED_VERIFIED");
    expect(result.evidence.outcome).not.toBe("REJECTED");
    expect(result.evidence.trail.some((l) => l.includes("non-landing NOT proven"))).toBe(true);
    expect(dworld.releaseCalls).toBe(0);
    expect(result.evidence.submitCallCount).toBe(0);
  });

  it("NEGATIVE: head mismatch + debit drift → NEEDS_ATTENTION (head wins; D1)", async () => {
    // Combined case: fresh head names foreign step_2 AND balance ≠ Ts0.B − amount.
    // Debit ESCALATE must not swallow the INDETERMINATE head-mismatch path.
    const evidence = landedExecuteEvidence();
    const dworld = makeDispositionWorld({
      executeEvidence: evidence,
      freshHeadMismatch: true,
      freshBalanceWrong: true,
    });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: SEND.settledText,
      destinationBaseline: RECIPIENT_BASELINE,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("NEEDS_ATTENTION");
    expect(result.evidence.outcome).not.toBe("ESCALATE_INVARIANT_BREACH");
    expect(result.evidence.trail.some((l) => l.includes("non-landing NOT proven"))).toBe(true);
    expect(dworld.releaseCalls).toBe(0);
    expect(dworld.archiveCalls).toBe(0);
  });

  it("NEGATIVE: foreign delivery transfer-code → path REJECTED, no release (D2)", async () => {
    const base = landedExecuteEvidence();
    const foreignCode = buildSendTransferCodeText(
      SEND.innerPreimageText,
      // Distinct step-1 sig bytes → distinct transfer code (not formation's code).
      "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==",
    );
    const foreignSha = hashTransferCodeText(foreignCode);
    const evidence: SendExecuteEvidenceBundle = {
      ...base,
      deliveries: [
        {
          deliveryNo: 1,
          transferCodeText: foreignCode,
          transferCodeSha256: foreignSha,
        },
      ],
    };
    const dworld = makeDispositionWorld({ executeEvidence: evidence });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: SEND.settledText,
      destinationBaseline: RECIPIENT_BASELINE,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("REJECTED");
    const single = result.evidence.pathManifest?.entries.find(
      (e) => e.predicate === "single_partial_delivery",
    );
    expect(single?.status).toBe("REJECTED");
    expect(dworld.releaseCalls).toBe(0);
    expect(dworld.archiveCalls).toBe(0);
  });

  it("NEGATIVE: caller settled body ≠ fresh head → ESCALATE, no landing (D3)", async () => {
    const evidence = landedExecuteEvidence();
    const dworld = makeDispositionWorld({ executeEvidence: evidence });
    const twin = buildTransaction({
      senderSeed: SOURCE_SEED,
      receiverSeed: RECIPIENT_SEED,
      senderBalanceAfter: SOURCE_BALANCE_AFTER,
      receiverBalanceAfter: DEST_BALANCE_AFTER,
      previousStep1Signature: SOURCE_PREDECESSOR.step2Signature,
      previousStep2Signature: "",
      expiry: "1785153900",
      unixTimeSecs: "1785153602.500",
    });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: twin.settledText,
      destinationBaseline: RECIPIENT_BASELINE,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
    expect(
      result.evidence.trail.some((l) =>
        l.includes("completedSettledTransactionText ≠ fresh-head"),
      ),
    ).toBe(true);
    expect(dworld.landingCommits).toHaveLength(0);
    expect(dworld.releaseCalls).toBe(0);
  });

  it("NEGATIVE: leaseHeldBeforeAnyRead false refuses (D4)", async () => {
    const base = landedExecuteEvidence();
    const evidence: SendExecuteEvidenceBundle = {
      ...base,
      leaseHeldBeforeAnyRead: false,
    };
    const dworld = makeDispositionWorld({ executeEvidence: evidence });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: SEND.settledText,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("REFUSED_INCOMPLETE_EXECUTE_EVIDENCE");
    expect(result.evidence.trail.some((l) => l.includes("lease-before-read"))).toBe(true);
    expect(dworld.releaseCalls).toBe(0);
  });

  it("NEGATIVE: deviceSignatureRequired without verified → path REJECTED (D5)", async () => {
    const evidence = landedExecuteEvidence();
    const dworld = makeDispositionWorld({ executeEvidence: evidence });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: SEND.settledText,
      destinationBaseline: RECIPIENT_BASELINE,
      artifactVerificationOk: true,
      deviceSignatureRequired: true,
      // omit deviceSignatureVerified — must fail closed, not default-true
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("REJECTED");
    const approval = result.evidence.pathManifest?.entries.find(
      (e) => e.predicate === "approval_consumed",
    );
    expect(approval?.status).toBe("REJECTED");
    expect(dworld.releaseCalls).toBe(0);
  });

  it("NEGATIVE: foreign landed body → ESCALATE, no release", async () => {
    const evidence = landedExecuteEvidence();
    const dworld = makeDispositionWorld({
      executeEvidence: evidence,
      freshForeignBody: true,
    });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      // Let fresh head supply the foreign body.
      destinationBaseline: RECIPIENT_BASELINE,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.partialIdentity?.innerMatches).toBe(false);
    expect(result.evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
    expect(dworld.releaseCalls).toBe(0);
  });

  it("NEGATIVE: fresh-head debit mismatch → ESCALATE, no release", async () => {
    const evidence = landedExecuteEvidence();
    const dworld = makeDispositionWorld({
      executeEvidence: evidence,
      freshBalanceWrong: true,
    });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: SEND.settledText,
      destinationBaseline: RECIPIENT_BASELINE,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.sourceDebit?.sourceExact).toBe(false);
    expect(result.evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
    expect(dworld.releaseCalls).toBe(0);
  });

  it("NEGATIVE: DB-vs-chain disagreement → ESCALATE, no release", async () => {
    const evidence = landedExecuteEvidence();
    const dworld = makeDispositionWorld({
      executeEvidence: evidence,
      dbAgrees: false,
    });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: SEND.settledText,
      destinationBaseline: RECIPIENT_BASELINE,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
    expect(dworld.releaseCalls).toBe(0);
    expect(dworld.archiveCalls).toBe(0);
  });

  it("group child PENDING pins source lease — never releases early", async () => {
    const evidence = landedExecuteEvidence();
    const dworld = makeDispositionWorld({
      executeEvidence: evidence,
      groupChildPending: true,
    });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: SEND.settledText,
      destinationBaseline: RECIPIENT_BASELINE,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("ACK_PINNED");
    expect(result.evidence.leaseRelease?.clampedStatus).toBe("PINNED_GROUP_PENDING");
    expect(result.evidence.leaseRelease?.released).toBe(false);
    expect(dworld.releaseCalls).toBe(0);
    // Landing + ack still happened — only release is gated.
    expect(result.evidence.landing?.eventType).toBe("external_send.landed");
    expect(result.evidence.acknowledgement?.verdict).toBe("VERIFIED");
  });

  it("artifact verification failure fails path manifest and never releases", async () => {
    const evidence = landedExecuteEvidence();
    const dworld = makeDispositionWorld({ executeEvidence: evidence });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: evidence,
      completedSettledTransactionText: SEND.settledText,
      destinationBaseline: RECIPIENT_BASELINE,
      artifactVerificationOk: false,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.pathManifest?.allVerified).toBe(false);
    expect(
      result.evidence.pathManifest?.entries.find((e) => e.predicate === "send_artifact_verify")
        ?.status,
    ).toBe("REJECTED");
    expect(result.evidence.outcome).toBe("REJECTED");
    expect(dworld.releaseCalls).toBe(0);
  });

  it("abort criteria still forbid submit, replacement partial, and reconsume", () => {
    const criteria = sendExternalAbortCriteria();
    expect(criteria.nodeSubmitForbidden).toBe(true);
    expect(criteria.blindRetryForbidden).toBe(true);
    expect(criteria.rebuildRequiresPositiveNonLandingOracle).toBe(true);
    for (const rule of criteria.rules) {
      expect(rule.maySubmit).toBe(false);
      expect(rule.mayMintReplacementPartial).toBe(false);
      expect(rule.mayReconsumeApproval).toBe(false);
    }
  });

  it("parseSendSettledTransactionText accepts formed settled body via envelope stage", () => {
    const parsed = parseSendSettledTransactionText(SEND.settledText);
    expect(parsed.step_2_signature).toBe(SEND.step2Signature);
    expect(parsed.step_1_signature).toBe(SEND.step1Signature);
  });

  it("incomplete execute row counts refuse without release", async () => {
    const base = landedExecuteEvidence();
    const broken: SendExecuteEvidenceBundle = {
      ...base,
      rowCounts: {
        totpConsumptions: 1,
        signIntents: 1,
        partials: 1,
        submitDecisions: 1, // node must never submit
        gatewaySubmitAttempts: 0,
      },
    };
    const dworld = makeDispositionWorld({ executeEvidence: broken });

    const result = await disposeSendExternalEvidence(buildDispositionDeps(dworld), {
      operationId: OPERATION_ID,
      executeEvidence: broken,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("REFUSED_INCOMPLETE_EXECUTE_EVIDENCE");
    expect(dworld.releaseCalls).toBe(0);
  });
});
