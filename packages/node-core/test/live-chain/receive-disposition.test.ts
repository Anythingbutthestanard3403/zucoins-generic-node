// RECEIVE_EXTERNAL reconcile + evidence disposition.
//
// Every observation in this file comes from a miniature receiver chain of real Ed25519-signed
// SplitChain transactions (test-transactions.ts). The seams serve those pre-built rows by
// LOOKUP KEY ONLY: no fake ever computes a return value out of the argument it was handed, so
// a guard reading those operands can genuinely fail rather than comparing a value to itself.
// Each negative case swaps one pre-built row for another pre-built row.
//
import { createHash } from "node:crypto";

import { transferCodeSha256 } from "@zucoins/generic-node-contracts/transfer-code";
import { describe, expect, it } from "vitest";

import {
  buildTransaction,
  publicKeyFromSeed,
  type BuiltTransaction,
} from "../../src/proof/policies/test-transactions.js";
import { verifySettledTransaction } from "../../src/verifier/transaction-verify.js";
import type {
  DurableEvidenceFact,
  GroupReleaseFacts,
  LeaseReleaseStatus,
} from "../../src/verification/predicates.js";

import { RECEIVE_CODE_TTL_DEFAULT_SECS } from "./receive-abort-criteria.js";
import {
  disposeReceiveExternalEvidence,
  RECEIVE_DISPOSITION_GUARDS,
  RECEIVE_EXTERNAL_PATH_PREDICATES,
  RECEIVE_RELEASE_SEQUENCE,
  type ReceiveDispositionDeps,
  type ReceiveDispositionInput,
  type ReceiveExecuteSummary,
  type ReceiveLandingCommitRecord,
  type ReceiveObservationRecord,
  type ReceiveProofExposure,
  type ReceiveProofRevocationRecord,
  type ReceiveEvidencePacket,
  type ReceiveReleaseProofRecord,
  type ReceiveVerificationAckRecord,
} from "./receive-disposition.js";
import type { ReceiveExternalPlan } from "./receive-preflight.js";

// ─── The miniature chain ─────────────────────────────────────────────────────

const RECEIVER_SEED = 0x21;
const PAYER_SEED = 0x22;
const RIVAL_PAYER_SEED = 0x23;
const ANCESTOR_SEED = 0x24;

const RECEIVER = publicKeyFromSeed(RECEIVER_SEED);
const PAYER_ADDRESS = publicKeyFromSeed(PAYER_SEED);

const DISCRIMINATOR = "44444444-4444-4444-8444-444444444444";
const ANCHOR = "ord_fixture";
const TRANSFER_CODE = "eyJhbW91bnQiOiIwLjAwMDAwMSJ9";
const AMOUNT = "0.000001";
const T0_BALANCE = "10";
const TERMINAL_BALANCE = "10.000001";
const EXPIRY_SECS = 1_784_336_400;
const OBSERVED_AT = 1_784_332_800;

const OPERATION_ID = "99999999-9999-4999-8999-999999999999";
const RECEIVER_WALLET_ID = "11111111-1111-4111-8111-111111111111";
const ACK_ID = "22222222-2222-4222-8222-222222222222";
const NOW = "2026-07-28T10:00:00.000Z";

/** The receiver's prior accepted state: a real earlier transaction crediting it 10 ZKZ. */
const PREDECESSOR = buildTransaction({
  senderSeed: ANCESTOR_SEED,
  receiverSeed: RECEIVER_SEED,
  senderBalanceAfter: "0",
  receiverBalanceAfter: T0_BALANCE,
});

/** The transaction this attempt actually co-signed and submitted. */
const LANDED = buildTransaction({
  senderSeed: PAYER_SEED,
  receiverSeed: RECEIVER_SEED,
  senderBalanceAfter: "1",
  receiverBalanceAfter: TERMINAL_BALANCE,
  previousStep2Signature: PREDECESSOR.step2Signature,
  expiry: String(EXPIRY_SECS),
  message: `zp1:${DISCRIMINATOR}:${ANCHOR}`,
});

/**
 * A different real transaction crediting the same receiver from a different payer. Used where
 * a head must name a transaction that is genuinely not ours.
 */
const RIVAL = buildTransaction({
  senderSeed: RIVAL_PAYER_SEED,
  receiverSeed: RECEIVER_SEED,
  senderBalanceAfter: "5",
  receiverBalanceAfter: TERMINAL_BALANCE,
  previousStep2Signature: PREDECESSOR.step2Signature,
  expiry: String(EXPIRY_SECS),
  message: `zp1:${DISCRIMINATOR}:${ANCHOR}`,
});

/** A real transaction crediting one 32-dp unit more than the artifact claims. */
const OVERCREDIT = buildTransaction({
  senderSeed: PAYER_SEED,
  receiverSeed: RECEIVER_SEED,
  senderBalanceAfter: "1",
  receiverBalanceAfter: `10.000001${"0".repeat(25)}1`,
  previousStep2Signature: PREDECESSOR.step2Signature,
  expiry: String(EXPIRY_SECS),
  message: `zp1:${DISCRIMINATOR}:${ANCHOR}`,
});

/** A real transaction whose message names another operation — message_discriminator rejects. */
const WRONG_ANCHOR = buildTransaction({
  senderSeed: PAYER_SEED,
  receiverSeed: RECEIVER_SEED,
  senderBalanceAfter: "1",
  receiverBalanceAfter: TERMINAL_BALANCE,
  previousStep2Signature: PREDECESSOR.step2Signature,
  expiry: String(EXPIRY_SECS),
  message: `zp1:${DISCRIMINATOR}:ord_SOMEONE_ELSE`,
});

interface ObservationOptions {
  readonly observationId: string;
  readonly domain: ReceiveObservationRecord["observerDomain"];
  readonly source?: ReceiveObservationRecord["source"];
  /** Changes only the envelope wrapper bytes, never the settled body. */
  readonly envelopeNote?: string;
  readonly directRead?: boolean;
  readonly relayedVia?: string | null;
}

function observationFrom(
  built: BuiltTransaction,
  opts: ObservationOptions,
): ReceiveObservationRecord {
  const verdict = verifySettledTransaction(built.parsed, RECEIVER);
  if (verdict.verdict !== "VERIFIED") {
    throw new Error(`fixture did not verify: ${verdict.verdict}`);
  }
  const rawEnvelope = `{"status":true,"code":"success","message":"${opts.envelopeNote ?? ""}","data":[${built.settledText}]}`;
  return {
    observationId: opts.observationId,
    observerDomain: opts.domain,
    source: opts.source ?? "CONFIRMATION_READ",
    publicKey: RECEIVER,
    projection: verdict.projection,
    semanticFingerprint: verdict.semanticFingerprint,
    isGenesis: false,
    historyHasNonGenesis: true,
    acceptedStateSignatureHistory: [PREDECESSOR.step2Signature],
    step2Signature: built.step2Signature,
    settledTransactionText: built.settledText,
    rawResponseSha256: createHash("sha256").update(rawEnvelope, "utf8").digest("hex"),
    rawResponseByteLength: Buffer.byteLength(rawEnvelope, "utf8"),
    directRead: opts.directRead ?? true,
    relayedVia: opts.relayedVia ?? null,
  };
}

const RECEIVER_T0 = observationFrom(PREDECESSOR, {
  observationId: "obs-node-t0",
  domain: "NODE",
});
const NODE_TERMINAL = observationFrom(LANDED, {
  observationId: "obs-node-terminal",
  domain: "NODE",
});
const PLATFORM_TERMINAL = observationFrom(LANDED, {
  observationId: "obs-platform-terminal",
  domain: "PLATFORM",
});

// ─── Plan and execute evidence ───────────────────────────────────────────────

const PLAN: ReceiveExternalPlan = {
  kind: "RECEIVE_EXTERNAL",
  attemptId: "attempt-receive-disposition",
  operationId: OPERATION_ID,
  receiverWalletId: RECEIVER_WALLET_ID,
  receiverPubkey: RECEIVER,
  externalPayerAddress: PAYER_ADDRESS,
  amount: AMOUNT,
  authorization: {
    attemptId: "attempt-receive-disposition",
    attestationId: "attestation-receive-disposition",
    recordedAt: NOW,
  },
  payerKeyholderId: "independent-keyholder-1",
  codeTtlDefaultSecs: RECEIVE_CODE_TTL_DEFAULT_SECS,
  vaultBackupCapturedAt: NOW,
  buildVersion: {
    commitSha: "0".repeat(40),
    imageTag: "local-dev",
    gatewayEndpoint: "https://gateway.example.invalid",
    configFingerprint: "cfg-receive-disposition",
  },
  recoveryVerifiedAt: NOW,
};

function executeSummary(
  overrides: Partial<ReceiveExecuteSummary> = {},
): ReceiveExecuteSummary {
  return {
    attemptId: PLAN.attemptId,
    disposition: "LANDED_VERIFIED",
    plan: PLAN,
    formation: {
      discriminator: DISCRIMINATOR,
      anchor: ANCHOR,
      transferCodeText: TRANSFER_CODE,
      transferCodeSha256: transferCodeSha256(TRANSFER_CODE),
      codeExpiryUnixSecs: EXPIRY_SECS,
    },
    receiverT0: RECEIVER_T0,
    nodeTerminal: NODE_TERMINAL,
    submittedStep2Signature: LANDED.step2Signature,
    operationReceiverWalletId: RECEIVER_WALLET_ID,
    operationReceiverPublicKey: RECEIVER,
    rowCounts: {
      receiveArms: 1,
      candidateIntakes: 1,
      coSignatures: 1,
      gatewaySubmitAttempts: 1,
      landingProofs: 1,
    },
    leaseHeldBeforeAnyRead: true,
    observedAtUnixSecs: OBSERVED_AT,
    ...overrides,
  };
}

// ─── Seam fakes ──────────────────────────────────────────────────────────────

const LANDING_OK: ReceiveLandingCommitRecord = {
  operationId: OPERATION_ID,
  priorState: "READY",
  nextState: "RECEIVE_LANDED",
  eventType: "receive.landed",
  receiverTerminalObservationId: NODE_TERMINAL.observationId,
  verifiedAt: NOW,
  sameDbTx: true,
  eventChainLinked: true,
};

const EXPOSURE_OK: ReceiveProofExposure = {
  operationId: OPERATION_ID,
  proofAccessId: "proof-access-1",
  scopedToOperation: true,
  expiresAt: "2026-07-28T11:00:00.000Z",
};

const ACK_OK: ReceiveVerificationAckRecord = {
  operationId: OPERATION_ID,
  verdict: "VERIFIED",
  evidenceRoles: ["RECEIVER"],
  evidence: [
    { role: "RECEIVER", walletId: RECEIVER_WALLET_ID, walletPublicKey: RECEIVER },
  ] satisfies DurableEvidenceFact[],
  evidenceSetComplete: true,
  acknowledgementId: ACK_ID,
};

const RELEASE_PROOF_OK: ReceiveReleaseProofRecord = {
  operationId: OPERATION_ID,
  releaseKind: "VERIFICATION_COMPLETE",
  verificationAcknowledgementId: ACK_ID,
  receiverWalletId: RECEIVER_WALLET_ID,
};

const REVOCATION_OK: ReceiveProofRevocationRecord = {
  operationId: OPERATION_ID,
  httpStatus: 410,
  ledgerBytesRetained: true,
  observationBytesRetained: true,
};

const GROUP_RELEASABLE: GroupReleaseFacts = {
  childDisposition: "NONE",
  operations: [
    {
      operationId: OPERATION_ID,
      kind: "RECEIVE_EXTERNAL",
      verdict: "VERIFIED",
      evidenceRoles: ["RECEIVER"],
      evidence: [{ role: "RECEIVER", walletId: RECEIVER_WALLET_ID, walletPublicKey: RECEIVER }],
      expectedWallets: [
        { role: "RECEIVER", walletId: RECEIVER_WALLET_ID, walletPublicKey: RECEIVER },
      ],
      completed: true,
    },
  ],
};

interface Recorder {
  readonly archived: ReceiveEvidencePacket[];
  readonly releaseStatuses: LeaseReleaseStatus[];
  readonly revoked: string[];
}

interface DepsOverrides {
  /** Pre-seeded independent-observer rows, keyed by receiver public key. */
  readonly independentRows?: ReadonlyMap<string, ReceiveObservationRecord>;
  readonly independentThrows?: boolean;
  readonly landing?: ReceiveLandingCommitRecord;
  readonly landingThrows?: boolean;
  readonly exposureThrows?: boolean;
  readonly ack?: ReceiveVerificationAckRecord;
  readonly ackThrows?: boolean;
  readonly groupFacts?: GroupReleaseFacts;
  readonly groupFactsThrows?: boolean;
  readonly releaseProof?: ReceiveReleaseProofRecord | null;
  readonly receiverReleased?: boolean;
  readonly releaseThrows?: boolean;
  readonly revocation?: ReceiveProofRevocationRecord;
  readonly revocationThrows?: boolean;
  readonly archiveThrows?: boolean;
}

function makeDeps(
  overrides: DepsOverrides = {},
): { deps: ReceiveDispositionDeps; rec: Recorder } {
  const rec: Recorder = { archived: [], releaseStatuses: [], revoked: [] };
  const independentRows =
    overrides.independentRows ??
    new Map<string, ReceiveObservationRecord>([[RECEIVER, PLATFORM_TERMINAL]]);

  const deps: ReceiveDispositionDeps = {
    independentObserver: {
      // The argument is a lookup key and nothing else — the expected step_2 the caller
      // passes is deliberately never read, so it cannot leak into the answer.
      readReceiverHead: async ({ publicKey }) => {
        if (overrides.independentThrows === true) throw new Error("gateway unreachable");
        return independentRows.get(publicKey) ?? null;
      },
    },
    landing: {
      commitLanding: async () => {
        if (overrides.landingThrows === true) throw new Error("landing tx rolled back");
        return overrides.landing ?? LANDING_OK;
      },
    },
    proofAccess: {
      exposeScopedVerificationMaterial: async () => {
        if (overrides.exposureThrows === true) throw new Error("proof store unavailable");
        return EXPOSURE_OK;
      },
      revokeProofAccess: async ({ proofAccessId }) => {
        if (overrides.revocationThrows === true) throw new Error("proof store unreachable");
        rec.revoked.push(proofAccessId);
        return overrides.revocation ?? REVOCATION_OK;
      },
    },
    ack: {
      recordAcknowledgement: async () => {
        if (overrides.ackThrows === true) throw new Error("ack insert conflict");
        return overrides.ack ?? ACK_OK;
      },
    },
    groupFacts: {
      loadGroupFacts: async () => {
        if (overrides.groupFactsThrows === true) throw new Error("group read failed");
        return overrides.groupFacts ?? GROUP_RELEASABLE;
      },
    },
    leases: {
      releaseReceiverIfGroupPassed: async ({ status }) => {
        if (overrides.releaseThrows === true) throw new Error("lease row locked");
        rec.releaseStatuses.push(status);
        return {
          receiverReleased: overrides.receiverReleased ?? true,
          releaseProof:
            overrides.releaseProof === undefined ? RELEASE_PROOF_OK : overrides.releaseProof,
        };
      },
    },
    evidenceArchive: {
      archive: async (packet) => {
        if (overrides.archiveThrows === true) throw new Error("archive volume full");
        rec.archived.push(packet);
        return { archiveId: "archive-1" };
      },
    },
    nowIso: () => NOW,
  };
  return { deps, rec };
}

function makeInput(overrides: Partial<ReceiveDispositionInput> = {}): ReceiveDispositionInput {
  return {
    operationId: OPERATION_ID,
    executeEvidence: executeSummary(),
    artifactVerificationOk: true,
    ...overrides,
  };
}

function withIndependent(row: ReceiveObservationRecord): DepsOverrides {
  return { independentRows: new Map([[RECEIVER, row]]) };
}

// ─── Fixture self-checks ─────────────────────────────────────────────────────

describe("fixtures", () => {
  it("builds a real chain whose landed transaction is not the rival transaction", () => {
    expect(LANDED.step2Signature).not.toBe(RIVAL.step2Signature);
    expect(LANDED.settledText).not.toBe(RIVAL.settledText);
    expect(NODE_TERMINAL.projection.P).toBe(RECEIVER_T0.projection.S);
  });

  it("serves independent observations by lookup key, never from the caller's argument", async () => {
    const { deps } = makeDeps();
    const answer = await deps.independentObserver.readReceiverHead({
      publicKey: RECEIVER,
      // A step_2 that exists nowhere in the chain. A fake echoing its input would return it.
      expectedStep2Signature: "not-a-signature-from-this-chain",
    });
    expect(answer?.step2Signature).toBe(LANDED.step2Signature);
  });

  it("returns null for a wallet the independent observer has no row for", async () => {
    const { deps } = makeDeps();
    expect(
      await deps.independentObserver.readReceiverHead({
        publicKey: publicKeyFromSeed(0x7f),
        expectedStep2Signature: LANDED.step2Signature,
      }),
    ).toBeNull();
  });
});

// ─── Happy path ──────────────────────────────────────────────────────────────

describe("disposeReceiveExternalEvidence — DISPOSED_VERIFIED", () => {
  it("reconciles both observer ledgers, acknowledges, releases and archives", async () => {
    const { deps, rec } = makeDeps();
    const result = await disposeReceiveExternalEvidence(deps, makeInput());

    expect(result.ok).toBe(true);
    expect(result.evidence.outcome).toBe("DISPOSED_VERIFIED");
    expect(result.evidence.guard).toBeNull();
    expect(result.evidence.abortTrigger).toBe("LANDED_VERIFIED");
    expect(result.evidence.abortAction).toBe("COMPLETE_LANDED_VERIFIED");
    expect(rec.archived).toHaveLength(1);
    expect(rec.revoked).toEqual([EXPOSURE_OK.proofAccessId]);
  });

  it("proves both observer ledgers agree on the landed transaction", () => {
    // The node row and the platform row are distinct rows in distinct domains.
    expect(NODE_TERMINAL.observationId).not.toBe(PLATFORM_TERMINAL.observationId);
    expect(NODE_TERMINAL.observerDomain).toBe("NODE");
    expect(PLATFORM_TERMINAL.observerDomain).toBe("PLATFORM");
  });

  it("records byte-identical agreement between the two ledgers", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    const agreement = evidence.observerAgreement;
    expect(agreement?.agrees).toBe(true);
    expect(agreement?.bytesIdentical).toBe(true);
    expect(agreement?.independentDomain).toBe("PLATFORM");
    expect(agreement?.independentDirectRead).toBe(true);
  });

  it("accepts an independent read whose wrapper bytes differ but whose state is equal", async () => {
    const differentEnvelope = observationFrom(LANDED, {
      observationId: "obs-platform-alt-envelope",
      domain: "PLATFORM",
      envelopeNote: "served from replica",
    });
    const { deps } = makeDeps(withIndependent(differentEnvelope));
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());

    expect(ok).toBe(true);
    expect(evidence.observerAgreement?.bytesIdentical).toBe(false);
    expect(evidence.observerAgreement?.relationship).toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
    expect(evidence.observerAgreement?.agrees).toBe(true);
  });

  it("confirms the economic delta: terminal balance − T0.B0 == amount_zkz", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.receiverCredit).toEqual({
      receiverCredit: AMOUNT,
      amount: AMOUNT,
      creditExact: true,
      t0Balance: T0_BALANCE,
      terminalBalance: TERMINAL_BALANCE,
    });
  });

  it("verifies all ten predicates, in checklist order", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.pathManifest?.outcome).toBe("VERIFIED");
    expect(evidence.pathManifest?.allVerified).toBe(true);
    expect(evidence.pathManifest?.entries.map((e) => e.predicate)).toEqual([
      ...RECEIVE_EXTERNAL_PATH_PREDICATES,
    ]);
    expect(evidence.pathManifest?.entries.every((e) => e.status === "VERIFIED")).toBe(true);
  });

  it("commits READY → RECEIVE_LANDED with receive.landed in one hash-chained DB-TX", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.landing?.priorState).toBe("READY");
    expect(evidence.landing?.nextState).toBe("RECEIVE_LANDED");
    expect(evidence.landing?.eventType).toBe("receive.landed");
    expect(evidence.landing?.sameDbTx).toBe(true);
    expect(evidence.landing?.eventChainLinked).toBe(true);
  });

  it("records a VERIFIED acknowledgement bound to the RECEIVER role", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.acknowledgement?.verdict).toBe("VERIFIED");
    expect(evidence.acknowledgement?.evidenceRoles).toEqual(["RECEIVER"]);
    expect(evidence.acknowledgement?.evidenceSetComplete).toBe(true);
  });

  it("writes a VERIFICATION_COMPLETE release proof naming the acknowledgement", async () => {
    const { deps, rec } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.leaseRelease?.releaseProof?.releaseKind).toBe("VERIFICATION_COMPLETE");
    expect(evidence.leaseRelease?.releaseProof?.verificationAcknowledgementId).toBe(ACK_ID);
    expect(evidence.leaseRelease?.releaseGatedOnGroupPredicate).toBe(true);
    // The lease seam is only ever called with RELEASED.
    expect(rec.releaseStatuses).toEqual(["RELEASED"]);
  });

  it("performs the retention-and-release steps in the normative order", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.releaseSequence).toEqual([...RECEIVE_RELEASE_SEQUENCE]);
  });

  it("revokes proof access with 410 without deleting ledger bytes", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.proofRevocation?.httpStatus).toBe(410);
    expect(evidence.proofRevocation?.ledgerBytesRetained).toBe(true);
    expect(evidence.proofRevocation?.observationBytesRetained).toBe(true);
  });

  it("emits a self-contained packet carrying both ledgers' bytes and a digest", async () => {
    const { deps, rec } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    const packet = rec.archived[0];
    expect(packet).toBeDefined();
    expect(packet?.kind).toBe("RECEIVE_EXTERNAL_LIVE_CHAIN_EVIDENCE_V1");
    expect(packet?.nodeLedgerBytesSha256).toBe(NODE_TERMINAL.rawResponseSha256);
    expect(packet?.independentLedgerBytesSha256).toBe(PLATFORM_TERMINAL.rawResponseSha256);
    expect(packet?.step2Signature).toBe(LANDED.step2Signature);
    expect(packet?.packetSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(packet?.commandsAndResults.length).toBeGreaterThan(0);
    expect(packet?.governingRules.length).toBeGreaterThan(0);
    expect(packet?.noSpeculativeContractImplemented).toBe(true);
    expect(evidence.evidencePacket?.packetSha256).toBe(packet?.packetSha256);
  });

  it("never submits and never claims a right it does not have", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.submitCallCount).toBe(0);
    expect(evidence.mayResubmit).toBe(false);
    expect(evidence.mayReconsumeTransferCode).toBe(false);
    expect(evidence.mayRebuildWithoutPositiveOracle).toBe(false);
    expect(evidence.mayInferNonLandingFromSilence).toBe(false);
    expect(evidence.mayReleaseLeaseOnLandingAlone).toBe(false);
    expect(evidence.maySettleOnSubmitEcho).toBe(false);
    expect(evidence.mayAcceptRelayedIndependentObservation).toBe(false);
  });

  it("contains no private-key material anywhere in the packet (the key-custody rule)", async () => {
    const { deps, rec } = makeDeps();
    await disposeReceiveExternalEvidence(deps, makeInput());
    const serialized = JSON.stringify(rec.archived[0]);
    expect(serialized).not.toMatch(/private/i);
    expect(serialized).not.toMatch(/BEGIN [A-Z ]*PRIVATE KEY/);
    expect(serialized).not.toMatch(/\bseed\b/i);
  });
});

// ─── One killing test per declared guard ─────────────────────────────────────

describe("disposeReceiveExternalEvidence — guards", () => {
  it("guard=execute_not_landed holds when the execute lane did not land", async () => {
    const { deps } = makeDeps();
    const { ok, evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({
        executeEvidence: executeSummary({ disposition: "SUBMIT_AMBIGUOUS_OR_UNOBSERVED" }),
      }),
    );
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("execute_not_landed");
    expect(evidence.outcome).toBe("REFUSED_EXECUTE_NOT_LANDED");
    expect(evidence.abortAction).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
  });

  it("guard=execute_not_landed escalates an execute-side invariant breach", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({
        executeEvidence: executeSummary({ disposition: "ESCALATE_INVARIANT_BREACH" }),
      }),
    );
    expect(evidence.guard).toBe("execute_not_landed");
    expect(evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
  });

  it("guard=incomplete_execute_evidence refuses a second gateway submit attempt", async () => {
    const { deps } = makeDeps();
    const { ok, evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({
        executeEvidence: executeSummary({
          rowCounts: {
            receiveArms: 1,
            candidateIntakes: 1,
            coSignatures: 1,
            gatewaySubmitAttempts: 2,
            landingProofs: 1,
          },
        }),
      }),
    );
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("incomplete_execute_evidence");
    expect(evidence.outcome).toBe("REFUSED_INCOMPLETE_EXECUTE_EVIDENCE");
  });

  it("guard=incomplete_execute_evidence refuses a read taken before the lease was held", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({ executeEvidence: executeSummary({ leaseHeldBeforeAnyRead: false }) }),
    );
    expect(evidence.guard).toBe("incomplete_execute_evidence");
  });

  it("guard=incomplete_execute_evidence refuses an attempt with no submitted step_2", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({ executeEvidence: executeSummary({ submittedStep2Signature: "" }) }),
    );
    expect(evidence.guard).toBe("incomplete_execute_evidence");
  });

  it("guard=settlement_not_from_confirmation_read rejects a submit-response echo", async () => {
    const echo = observationFrom(LANDED, {
      observationId: "obs-node-submit-echo",
      domain: "NODE",
      source: "SUBMIT_RESPONSE",
    });
    const { deps } = makeDeps();
    const { ok, evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({ executeEvidence: executeSummary({ nodeTerminal: echo }) }),
    );
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("settlement_not_from_confirmation_read");
    expect(evidence.outcome).toBe("NEEDS_ATTENTION");
    expect(evidence.landing).toBeNull();
  });

  it("guard=receiver_head_mismatch holds when the agreed head is another transaction", async () => {
    // Both ledgers agree — on the rival transaction, which is not the one we submitted.
    const nodeRival = observationFrom(RIVAL, {
      observationId: "obs-node-rival",
      domain: "NODE",
    });
    const platformRival = observationFrom(RIVAL, {
      observationId: "obs-platform-rival",
      domain: "PLATFORM",
    });
    const { deps } = makeDeps(withIndependent(platformRival));
    const { ok, evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({ executeEvidence: executeSummary({ nodeTerminal: nodeRival }) }),
    );
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("receiver_head_mismatch");
    expect(evidence.outcome).toBe("NEEDS_ATTENTION");
    expect(evidence.observerAgreement?.agrees).toBe(true);
    // Never inferred non-landing.
    expect(evidence.mayInferNonLandingFromSilence).toBe(false);
  });

  it("guard=independent_observation_unavailable holds when the second read throws", async () => {
    const { deps } = makeDeps({ independentThrows: true });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("independent_observation_unavailable");
    expect(evidence.outcome).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
  });

  it("guard=independent_observation_unavailable holds when there is no second row", async () => {
    const { deps } = makeDeps({ independentRows: new Map() });
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.guard).toBe("independent_observation_unavailable");
    expect(evidence.outcome).toBe("NEEDS_ATTENTION");
  });

  it("guard=independent_observation_not_direct rejects a node-relayed platform row", async () => {
    const relayed = observationFrom(LANDED, {
      observationId: "obs-platform-relayed",
      domain: "PLATFORM",
      directRead: false,
      relayedVia: "node",
    });
    const { deps } = makeDeps(withIndependent(relayed));
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("independent_observation_not_direct");
    expect(evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
  });

  it("guard=independent_observation_wrong_domain rejects a second NODE-domain row", async () => {
    const secondNodeRow = observationFrom(LANDED, {
      observationId: "obs-node-second",
      domain: "NODE",
    });
    const { deps } = makeDeps(withIndependent(secondNodeRow));
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("independent_observation_wrong_domain");
    expect(evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
  });

  it("guard=observer_ledgers_disagree holds when the two ledgers see different states", async () => {
    const platformRival = observationFrom(RIVAL, {
      observationId: "obs-platform-rival",
      domain: "PLATFORM",
    });
    const { deps } = makeDeps(withIndependent(platformRival));
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("observer_ledgers_disagree");
    expect(evidence.outcome).toBe("NEEDS_ATTENTION");
    expect(evidence.observerAgreement?.agrees).toBe(false);
    expect(evidence.observerAgreement?.relationship).not.toBe(
      "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
    );
  });

  it("guard=settled_body_parse_failed holds on an unparseable settled body", async () => {
    const corrupt: ReceiveObservationRecord = {
      ...NODE_TERMINAL,
      settledTransactionText: '{"inner":{"type":"unique_combinable"',
    };
    const { deps } = makeDeps();
    const { ok, evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({ executeEvidence: executeSummary({ nodeTerminal: corrupt }) }),
    );
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("settled_body_parse_failed");
  });

  it("guard=credit_not_exact escalates a credit that is not exactly amount_zkz", async () => {
    const overcredited = observationFrom(OVERCREDIT, {
      observationId: "obs-node-overcredit",
      domain: "NODE",
    });
    const platformOvercredited = observationFrom(OVERCREDIT, {
      observationId: "obs-platform-overcredit",
      domain: "PLATFORM",
    });
    const { deps } = makeDeps(withIndependent(platformOvercredited));
    const { ok, evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({
        executeEvidence: executeSummary({
          nodeTerminal: overcredited,
          submittedStep2Signature: OVERCREDIT.step2Signature,
        }),
      }),
    );
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("credit_not_exact");
    expect(evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
    expect(evidence.receiverCredit?.creditExact).toBe(false);
  });

  it("guard=path_manifest_not_verified rejects a landed body naming another order", async () => {
    const wrongAnchor = observationFrom(WRONG_ANCHOR, {
      observationId: "obs-node-wrong-anchor",
      domain: "NODE",
    });
    const platformWrongAnchor = observationFrom(WRONG_ANCHOR, {
      observationId: "obs-platform-wrong-anchor",
      domain: "PLATFORM",
    });
    const { deps } = makeDeps(withIndependent(platformWrongAnchor));
    const { ok, evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({
        executeEvidence: executeSummary({
          nodeTerminal: wrongAnchor,
          submittedStep2Signature: WRONG_ANCHOR.step2Signature,
        }),
      }),
    );
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("path_manifest_not_verified");
    expect(evidence.outcome).toBe("REJECTED");
    expect(
      evidence.pathManifest?.entries.find((e) => e.predicate === "message_discriminator")?.status,
    ).toBe("REJECTED");
  });

  it("guard=path_manifest_not_verified holds, not rejects, when the artifact is undecided", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({ artifactVerificationOk: false }),
    );
    expect(evidence.guard).toBe("path_manifest_not_verified");
    expect(evidence.landing).toBeNull();
  });

  it("guard=landing_commit_failed holds when the landing DB-TX throws", async () => {
    const { deps } = makeDeps({ landingThrows: true });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("landing_commit_failed");
    expect(evidence.releaseSequence).toEqual([]);
  });

  it("guard=landing_commit_shape_invalid escalates a split state/event commit", async () => {
    const { deps } = makeDeps({ landing: { ...LANDING_OK, sameDbTx: false } });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("landing_commit_shape_invalid");
    expect(evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
  });

  it("guard=landing_commit_shape_invalid escalates an unchained receive.landed event", async () => {
    const { deps } = makeDeps({ landing: { ...LANDING_OK, eventChainLinked: false } });
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.guard).toBe("landing_commit_shape_invalid");
  });

  it("guard=proof_exposure_failed holds when scoped material cannot be exposed", async () => {
    const { deps } = makeDeps({ exposureThrows: true });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("proof_exposure_failed");
    expect(evidence.releaseSequence).toEqual(["PERSIST_EVIDENCE"]);
  });

  it("guard=evidence_set_invalid escalates an operation row naming another receiver", async () => {
    // The run credited RECEIVER; the durable operation row names a different wallet key.
    const { deps } = makeDeps();
    const { ok, evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({
        executeEvidence: executeSummary({
          operationReceiverPublicKey: publicKeyFromSeed(0x31),
        }),
      }),
    );
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("evidence_set_invalid");
    expect(evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
  });

  it("guard=evidence_set_invalid escalates an operation row with no receiver assignment", async () => {
    const { deps } = makeDeps();
    const { evidence } = await disposeReceiveExternalEvidence(
      deps,
      makeInput({ executeEvidence: executeSummary({ operationReceiverPublicKey: null }) }),
    );
    expect(evidence.guard).toBe("evidence_set_invalid");
  });

  it("guard=ack_failed holds when the acknowledgement write throws", async () => {
    const { deps } = makeDeps({ ackThrows: true });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("ack_failed");
  });

  it("guard=ack_not_verified pins the lease on a non-VERIFIED verdict", async () => {
    const { deps, rec } = makeDeps({ ack: { ...ACK_OK, verdict: "INDETERMINATE" } });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("ack_not_verified");
    expect(evidence.outcome).toBe("ACK_PINNED");
    expect(rec.releaseStatuses).toEqual([]);
  });

  it("guard=ack_not_verified pins the lease on an incomplete evidence set", async () => {
    const { deps } = makeDeps({ ack: { ...ACK_OK, evidenceSetComplete: false } });
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.guard).toBe("ack_not_verified");
  });

  it("guard=group_facts_failed holds when the lease-group read throws", async () => {
    const { deps } = makeDeps({ groupFactsThrows: true });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("group_facts_failed");
  });

  it("guard=lease_release_failed holds when the release write throws", async () => {
    const { deps } = makeDeps({ releaseThrows: true });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("lease_release_failed");
  });

  it("guard=release_proof_invalid escalates a release proof of the wrong kind", async () => {
    const { deps } = makeDeps({
      releaseProof: { ...RELEASE_PROOF_OK, releaseKind: "T0_EXACT" },
    });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("release_proof_invalid");
    expect(evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
  });

  it("guard=release_proof_invalid escalates a release proof not naming the acknowledgement", async () => {
    const { deps } = makeDeps({
      releaseProof: { ...RELEASE_PROOF_OK, verificationAcknowledgementId: null },
    });
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.guard).toBe("release_proof_invalid");
  });

  it("guard=lease_not_released pins when the group predicate does not pass", async () => {
    const pendingGroup: GroupReleaseFacts = {
      ...GROUP_RELEASABLE,
      operations: [{ ...GROUP_RELEASABLE.operations[0]!, completed: false }],
    };
    const { deps, rec } = makeDeps({ groupFacts: pendingGroup });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("lease_not_released");
    expect(evidence.outcome).toBe("ACK_PINNED");
    // The lease seam was never called: no release is attempted below RELEASED.
    expect(rec.releaseStatuses).toEqual([]);
    expect(evidence.leaseRelease?.released).toBe(false);
  });

  it("guard=lease_not_released pins when a declared child has not joined the group", async () => {
    const { deps } = makeDeps({
      groupFacts: { ...GROUP_RELEASABLE, childDisposition: "PENDING" },
    });
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.guard).toBe("lease_not_released");
  });

  it("guard=proof_access_revocation_failed holds when revocation throws", async () => {
    const { deps } = makeDeps({ revocationThrows: true });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("proof_access_revocation_failed");
    expect(evidence.outcome).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
    // The lease was already released at step 4; revocation failing does not unwind it.
    expect(evidence.leaseRelease?.released).toBe(true);
    expect(evidence.releaseSequence).toEqual([
      "PERSIST_EVIDENCE",
      "EXPOSE_SCOPED_PROOF",
      "AWAIT_VERIFICATION_COMPLETE_ACK",
      "RELEASE_ON_GROUP_PREDICATE",
    ]);
  });

  it("guard=proof_access_revocation_deleted_ledger escalates deleted ledger bytes", async () => {
    const { deps } = makeDeps({
      revocation: { ...REVOCATION_OK, ledgerBytesRetained: false },
    });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("proof_access_revocation_deleted_ledger");
    expect(evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
  });

  it("guard=proof_access_revocation_deleted_ledger escalates a status other than 410", async () => {
    const { deps } = makeDeps({ revocation: { ...REVOCATION_OK, httpStatus: 404 } });
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.guard).toBe("proof_access_revocation_deleted_ledger");
  });

  it("guard=proof_access_revocation_deleted_ledger escalates deleted observation bytes", async () => {
    const { deps } = makeDeps({
      revocation: { ...REVOCATION_OK, observationBytesRetained: false },
    });
    const { evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(evidence.guard).toBe("proof_access_revocation_deleted_ledger");
  });

  it("guard=evidence_archive_failed reports a failed archive without unwinding the release", async () => {
    const { deps } = makeDeps({ archiveThrows: true });
    const { ok, evidence } = await disposeReceiveExternalEvidence(deps, makeInput());
    expect(ok).toBe(false);
    expect(evidence.guard).toBe("evidence_archive_failed");
    expect(evidence.outcome).toBe("EVIDENCE_ARCHIVE_FAILED");
    expect(evidence.evidencePacket).not.toBeNull();
  });

  it("declares every guard exactly once and none that no longer exists", () => {
    expect(new Set(RECEIVE_DISPOSITION_GUARDS).size).toBe(RECEIVE_DISPOSITION_GUARDS.length);
    expect(RECEIVE_DISPOSITION_GUARDS).not.toContain("release_sequence_out_of_order");
  });
});
