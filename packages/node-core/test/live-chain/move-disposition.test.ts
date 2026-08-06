// Offline unit tests for MOVE_INTERNAL reconcile + disposition.
//
// No network, no filesystem, no real private-key custody. Builds on the execute
// harness to produce LANDED_VERIFIED evidence, then drives disposeMoveInternalEvidence.
// Headline invariants:
//   - fresh heads (not mid-run) drive dual deltas + body identity;
//   - OBS path manifest all VERIFIED;
//   - landing DB-TX pairs INTERNAL_MOVE_LANDED with internal_move.landed;
//   - ack carries SOURCE + DESTINATION evidence;
//   - leases release only after group predicate RELEASED;
//   - disposition never submits (submitCallCount === 0);
//   - at least one negative-path assertion.

import { createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

import type { SettledSplitChainTransaction } from "../../src/protocol/inner.js";
import type { WalletStateProjection } from "../../src/protocol/wallet-role.js";
import type { GroupReleaseFacts } from "../../src/verification/predicates.js";
import { REQUIRED_EVIDENCE_ROLES } from "../../src/verification/predicates.js";

import { abortActionFor, moveInternalAbortCriteria } from "./abort-criteria.js";
import {
  SAMPLE_DEST_ID,
  SAMPLE_SOURCE_ID,
  fakeMoveProbe,
  readyMoveState,
  sampleAuth,
} from "./fakes.js";
import {
  DEFAULT_MOVE_AMOUNT,
  executeAuthorizedMoveInternal,
  type HeldMoveLease,
  type MoveExecuteDeps,
  type MoveExecuteEvidenceBundle,
  type MoveExecuteInput,
  type MoveFormationRecord,
  type MoveLeaseSeam,
  type MoveObserveSeam,
  type MovePersistSeam,
  type MoveSignerSeam,
  type MoveSubmitOutcomeKind,
  type MoveSubmitSeam,
  type MoveT0Snapshot,
  type MoveTerminalObservation,
  type MoveWalletDirectory,
} from "./move-execute.js";
import {
  MOVE_INTERNAL_PATH_PREDICATES,
  disposeMoveInternalEvidence,
  parseSettledTransactionText,
  type FreshHeadReRead,
  type LandingCommitRecord,
  type MoveDispositionDeps,
  type MoveEvidencePacket,
  type VerificationAckRecord,
} from "./move-disposition.js";
import { createRunnerLock } from "./runner-lock.js";
import { subtractAmounts } from "./types.js";

// ─── Ed25519 helpers (same shape as move-execute.test.ts) ────────────────────

type NodePrivateKey = ReturnType<typeof createPrivateKey>;

const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");

function generateWallet(): { publicKey: string; privateKey: NodePrivateKey } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const rawPub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return {
    publicKey: paddedBase64Url(Buffer.from(rawPub)),
    privateKey,
  };
}

function signPreimage(preimageText: string, privateKey: NodePrivateKey): string {
  return paddedBase64Url(sign(null, Buffer.from(preimageText, "utf8"), privateKey));
}

// ─── Execute-world fakes (produce LANDED_VERIFIED bundles) ───────────────────

interface FakeWorld {
  source: { publicKey: string; privateKey: NodePrivateKey };
  dest: { publicKey: string; privateKey: NodePrivateKey };
  sourceBalance: string;
  destBalance: string;
  sourceHeadS: string;
  destHeadS: string;
  leaseAcquireLog: string[];
  t0ObserveLog: string[];
  submitCalls: number;
  submitBehavior: MoveSubmitOutcomeKind | "throw";
  terminalMissing: boolean;
  destConflictingStep2: boolean;
  persistLog: string[];
  lastFormation: MoveFormationRecord | null;
}

const PRIOR_SOURCE_S =
  "dwQ0YSQhmtR2zZEqomyL9jGbAhEM2ntp7wL4VLrMySZtGmY-_1LznFUhbD0dj1HH0MulYU4XiNOTlYw1gfCMCQ==";
const PRIOR_DEST_S =
  "mydsK7Eol138MaWFrgXJgLdiVms47ragRTBgfFEP_iatxw9giVXi2jSGoTtUnufO0G7--r7RoZ4mzZ6SgirdBA==";
const CONFLICT_STEP2_S =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

function makeWorld(overrides: Partial<FakeWorld> = {}): FakeWorld {
  return {
    source: generateWallet(),
    dest: generateWallet(),
    sourceBalance: "1",
    destBalance: "0",
    sourceHeadS: PRIOR_SOURCE_S,
    destHeadS: PRIOR_DEST_S,
    leaseAcquireLog: [],
    t0ObserveLog: [],
    submitCalls: 0,
    submitBehavior: "ACK",
    terminalMissing: false,
    destConflictingStep2: false,
    persistLog: [],
    lastFormation: null,
    ...overrides,
  };
}

function t0Projection(balance: string, S: string): WalletStateProjection {
  return {
    role: S === "" ? "genesis" : "receiver",
    S,
    P: "",
    B: balance,
    I: null,
  };
}

function parseSettled(text: string): SettledSplitChainTransaction {
  return JSON.parse(text) as SettledSplitChainTransaction;
}

function buildExecuteDeps(world: FakeWorld): MoveExecuteDeps {
  const leases: MoveLeaseSeam = {
    async acquireBothInUuidOrder(input) {
      for (const id of input.acquireOrder) world.leaseAcquireLog.push(id);
      const byId = new Map<string, HeldMoveLease>([
        [
          input.sourceWalletId,
          {
            walletId: input.sourceWalletId,
            role: "MOVE_SOURCE",
            operationId: input.operationId,
            leaseEpoch: 1n,
          },
        ],
        [
          input.destinationWalletId,
          {
            walletId: input.destinationWalletId,
            role: "MOVE_DESTINATION",
            operationId: input.operationId,
            leaseEpoch: 1n,
          },
        ],
      ]);
      return [
        byId.get(input.acquireOrder[0])!,
        byId.get(input.acquireOrder[1])!,
      ] as [HeldMoveLease, HeldMoveLease];
    },
  };

  const observe: MoveObserveSeam = {
    async observeFreshT0(input) {
      world.t0ObserveLog.push(input.role);
      if (world.leaseAcquireLog.length < 2) {
        throw new Error("T0 observed before both leases acquired");
      }
      const isSource = input.walletId === SAMPLE_SOURCE_ID;
      return {
        walletId: input.walletId,
        publicKey: input.publicKey,
        observationId: `obs-t0-${input.role}`,
        projection: t0Projection(
          isSource ? world.sourceBalance : world.destBalance,
          isSource ? world.sourceHeadS : world.destHeadS,
        ),
      } satisfies MoveT0Snapshot;
    },
    async observeTerminal(input) {
      if (world.terminalMissing) return null;
      const formation = world.lastFormation;
      if (formation === null) return null;
      const settled = parseSettled(formation.settledTransactionText);
      const isSource = input.walletId === SAMPLE_SOURCE_ID;

      if (!isSource && world.destConflictingStep2) {
        const conflict: SettledSplitChainTransaction = {
          ...settled,
          step_2_signature: CONFLICT_STEP2_S,
        };
        return {
          walletId: input.walletId,
          publicKey: input.publicKey,
          observationId: "obs-term-dest-conflict",
          step2Signature: conflict.step_2_signature,
          balanceAfter: addBalance(world.destBalance, DEFAULT_MOVE_AMOUNT),
          settled: conflict,
        } satisfies MoveTerminalObservation;
      }

      const balanceAfter = isSource
        ? subtractAmounts(world.sourceBalance, DEFAULT_MOVE_AMOUNT)
        : addBalance(world.destBalance, DEFAULT_MOVE_AMOUNT);

      return {
        walletId: input.walletId,
        publicKey: input.publicKey,
        observationId: isSource ? "obs-term-src" : "obs-term-dst",
        step2Signature: settled.step_2_signature,
        balanceAfter,
        settled,
      } satisfies MoveTerminalObservation;
    },
  };

  const wallets: MoveWalletDirectory = {
    async publicKeyFor(walletId) {
      if (walletId === SAMPLE_SOURCE_ID) return world.source.publicKey;
      if (walletId === SAMPLE_DEST_ID) return world.dest.publicKey;
      throw new Error(`unknown wallet ${walletId}`);
    },
  };

  const signer: MoveSignerSeam = {
    async signStep1(input) {
      return signPreimage(input.preimageText, world.source.privateKey);
    },
    async signStep2(input) {
      return signPreimage(input.preimageText, world.dest.privateKey);
    },
  };

  const persist: MovePersistSeam = {
    async persistInnerPreimage() {
      world.persistLog.push("inner");
    },
    async persistStep1Signature() {
      world.persistLog.push("step1");
    },
    async persistStep2Preimage() {
      world.persistLog.push("step2-preimage");
    },
    async persistCompletedTransaction(input) {
      world.persistLog.push("completed");
      world.lastFormation = {
        attemptNo: 1,
        innerPreimageText: "",
        innerPreimageSha256: "",
        step1Signature: "",
        step2PreimageText: "",
        step2Signature: input.step2Signature,
        settledTransactionText: input.settledTransactionText,
        settledStep2Signature: input.step2Signature,
      };
    },
    async recordSubmitAttempt() {
      world.persistLog.push("submit-attempt");
    },
  };

  const submit: MoveSubmitSeam = {
    async submitOnce() {
      world.submitCalls += 1;
      if (world.submitBehavior === "throw") {
        throw new Error("simulated transport loss after dispatch");
      }
      return { outcome: world.submitBehavior, detail: `fake-${world.submitBehavior}` };
    },
  };

  return {
    leases,
    observe,
    wallets,
    signer,
    persist,
    submit,
    nowUnixSecs: () => "1785144000.125",
  };
}

function addBalance(a: string, b: string): string {
  const scale = Math.max(fracLen(a), fracLen(b));
  const ai = toScaled(a, scale);
  const bi = toScaled(b, scale);
  const sum = ai + bi;
  if (scale === 0) return sum.toString();
  const raw = sum.toString().padStart(scale + 1, "0");
  const intPart = raw.slice(0, raw.length - scale).replace(/^0+(?=\d)/, "") || "0";
  const frac = raw.slice(raw.length - scale).replace(/0+$/, "");
  return frac === "" ? intPart : `${intPart}.${frac}`;
}

function fracLen(v: string): number {
  const i = v.indexOf(".");
  return i < 0 ? 0 : v.length - i - 1;
}

function toScaled(v: string, scale: number): bigint {
  const [intPart, frac = ""] = v.split(".");
  return BigInt((intPart + frac.padEnd(scale, "0")).replace(/^0+(?=\d)/, "") || "0");
}

function baseExecuteInput(world: FakeWorld, overrides: Partial<MoveExecuteInput> = {}): MoveExecuteInput {
  const attemptId = overrides.attemptId ?? "attempt-move-disposition-1";
  const state = readyMoveState(attemptId);
  state.balances.set(SAMPLE_SOURCE_ID, world.sourceBalance);
  state.balances.set(SAMPLE_DEST_ID, world.destBalance);
  return {
    attemptId,
    operationId: "op-move-disposition-1",
    sourceWalletId: SAMPLE_SOURCE_ID,
    destinationWalletId: SAMPLE_DEST_ID,
    amount: DEFAULT_MOVE_AMOUNT,
    authorization: sampleAuth(attemptId),
    runnerLock: createRunnerLock(),
    runnerHolderId: "runner-disposition-1",
    preflightProbe: fakeMoveProbe(state),
    ...overrides,
  };
}

async function landedExecute(
  world: FakeWorld = makeWorld(),
): Promise<{ world: FakeWorld; evidence: MoveExecuteEvidenceBundle }> {
  const result = await executeAuthorizedMoveInternal(
    buildExecuteDeps(world),
    baseExecuteInput(world),
  );
  expect(result.ok).toBe(true);
  expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
  result.runnerLockHandle?.release();
  return { world, evidence: result.evidence };
}

// ─── Disposition fakes ───────────────────────────────────────────────────────

interface DispositionWorld {
  readonly executeWorld: FakeWorld;
  readonly executeEvidence: MoveExecuteEvidenceBundle;
  freshMissing: boolean;
  freshSourceConflict: boolean;
  freshDestBalanceWrong: boolean;
  dbAgrees: boolean;
  groupChildPending: boolean;
  releaseCalls: number;
  archiveCalls: number;
  landingCommits: LandingCommitRecord[];
  acks: VerificationAckRecord[];
  archivedPackets: MoveEvidencePacket[];
  /** When set, release seam refuses even on RELEASED (should not happen on happy path). */
  refuseRelease: boolean;
}

function makeDispositionWorld(
  overrides: Partial<DispositionWorld> & {
    executeWorld?: FakeWorld;
    executeEvidence?: MoveExecuteEvidenceBundle;
  } = {},
): DispositionWorld {
  return {
    executeWorld: overrides.executeWorld ?? makeWorld(),
    executeEvidence: overrides.executeEvidence!,
    freshMissing: false,
    freshSourceConflict: false,
    freshDestBalanceWrong: false,
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

function buildDispositionDeps(dworld: DispositionWorld): MoveDispositionDeps {
  const exec = dworld.executeEvidence;
  const formation = exec.formation!;
  const plan = exec.plan!;
  const sourceT0 = exec.sourceT0!;
  const destT0 = exec.destinationT0!;

  const freshFromFormation = (
    role: "SOURCE" | "DESTINATION",
    walletId: string,
    publicKey: string,
  ): FreshHeadReRead => {
    const settled = parseSettled(formation.settledTransactionText);
    const isSource = role === "SOURCE";
    let balance = isSource
      ? subtractAmounts(dworld.executeWorld.sourceBalance, plan.amount)
      : addBalance(dworld.executeWorld.destBalance, plan.amount);
    if (!isSource && dworld.freshDestBalanceWrong) {
      balance = addBalance(balance, "0.000001");
    }
    let step2 = formation.settledStep2Signature;
    let text = formation.settledTransactionText;
    if (isSource && dworld.freshSourceConflict) {
      step2 = CONFLICT_STEP2_S;
      const conflict: SettledSplitChainTransaction = {
        ...settled,
        step_2_signature: CONFLICT_STEP2_S,
      };
      text = JSON.stringify(conflict);
      return {
        walletId,
        publicKey,
        observationId: `obs-fresh-${role.toLowerCase()}-conflict`,
        step2Signature: step2,
        balance,
        settled: conflict,
        settledTransactionText: text,
      };
    }
    return {
      walletId,
      publicKey,
      observationId: `obs-fresh-${role.toLowerCase()}`,
      step2Signature: step2,
      balance,
      settled,
      settledTransactionText: text,
    };
  };

  return {
    freshHeads: {
      async reReadFreshHead(input) {
        if (dworld.freshMissing) return null;
        return freshFromFormation(input.role, input.walletId, input.publicKey);
      },
    },
    landing: {
      async commitLanding(input) {
        const record: LandingCommitRecord = {
          operationId: input.operationId,
          priorState: input.priorState,
          nextState: "INTERNAL_MOVE_LANDED",
          eventType: "internal_move.landed",
          sourceTerminalObservationId: input.sourceTerminalObservationId,
          destinationTerminalObservationId: input.destinationTerminalObservationId,
          verifiedAt: input.verifiedAt,
          sameDbTx: true,
        };
        dworld.landingCommits.push(record);
        return record;
      },
    },
    ack: {
      async recordAcknowledgement(input) {
        const record: VerificationAckRecord = {
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
              kind: "MOVE_INTERNAL",
              verdict: input.thisLegAck.verdict,
              evidenceRoles: input.thisLegAck.evidenceRoles,
              evidence: input.thisLegAck.evidence,
              expectedWallets: [
                {
                  role: "SOURCE",
                  walletId: plan.sourceWalletId,
                  walletPublicKey: sourceT0.publicKey,
                },
                {
                  role: "DESTINATION",
                  walletId: plan.destinationWalletId,
                  walletPublicKey: destT0.publicKey,
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
      async releaseBothIfGroupPassed(input) {
        dworld.releaseCalls += 1;
        if (input.status !== "RELEASED") {
          throw new Error("release seam invoked without RELEASED status");
        }
        if (dworld.refuseRelease) {
          return { sourceReleased: false, destinationReleased: false };
        }
        return { sourceReleased: true, destinationReleased: true };
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
      async dbAgreesWithChain() {
        return dworld.dbAgrees
          ? { agrees: true, detail: "persisted body and fresh heads byte-agree" }
          : { agrees: false, detail: "persisted step_2 ≠ fresh head" };
      },
    },
    nowIso: () => "2026-07-27T12:00:00.000Z",
  };
}

function custodyFor(world: FakeWorld) {
  return {
    sourceCustody: {
      walletId: SAMPLE_SOURCE_ID,
      nodeGenerated: true,
      leaseGroupId: "lg-move-disposition-1",
      continuouslyLeased: true,
    },
    destinationCustody: {
      walletId: SAMPLE_DEST_ID,
      nodeGenerated: true,
      blessedUnderB1: true,
      recoveryVerified: true,
    },
    // silence unused when only world keys matter for types
    _pks: [world.source.publicKey, world.dest.publicKey] as const,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("disposeMoveInternalEvidence — happy path", () => {
  it("disposes LANDED_VERIFIED execute: dual deltas, bodies, path, ack, release, evidence", async () => {
    const { world, evidence } = await landedExecute();
    const dworld = makeDispositionWorld({ executeWorld: world, executeEvidence: evidence });
    const custody = custodyFor(world);

    const result = await disposeMoveInternalEvidence(buildDispositionDeps(dworld), {
      operationId: "op-move-disposition-1",
      executeEvidence: evidence,
      sourceCustody: custody.sourceCustody,
      destinationCustody: custody.destinationCustody,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(true);
    expect(result.evidence.outcome).toBe("DISPOSED_VERIFIED");
    expect(result.evidence.submitCallCount).toBe(0);
    expect(result.evidence.mayResubmit).toBe(false);
    expect(result.evidence.mayRebuildWithoutPositiveOracle).toBe(false);

    // Fresh heads (not mid-run obs ids).
    expect(result.evidence.freshSource?.observationId).toBe("obs-fresh-source");
    expect(result.evidence.freshDestination?.observationId).toBe("obs-fresh-destination");
    expect(result.evidence.freshSource?.observationId).not.toBe(
      evidence.landing?.sourceObservation.observationId,
    );

    // Dual exact deltas.
    expect(result.evidence.dualDeltas?.bothExact).toBe(true);
    expect(result.evidence.dualDeltas?.sourceDebit).toBe(DEFAULT_MOVE_AMOUNT);
    expect(result.evidence.dualDeltas?.destinationCredit).toBe(DEFAULT_MOVE_AMOUNT);

    // Body identity.
    expect(result.evidence.bodyIdentity?.sourceEqualsDestination).toBe(true);
    expect(result.evidence.bodyIdentity?.matchesExecuteFormation).toBe(true);
    expect(result.evidence.bodyIdentity?.sameStep2Signature).toBe(true);

    // Path manifest — all predicates VERIFIED.
    expect(result.evidence.pathManifest?.outcome).toBe("VERIFIED");
    expect(result.evidence.pathManifest?.allVerified).toBe(true);
    expect(result.evidence.pathManifest?.entries).toHaveLength(
      MOVE_INTERNAL_PATH_PREDICATES.length,
    );
    for (const e of result.evidence.pathManifest!.entries) {
      expect(e.status).toBe("VERIFIED");
    }

    // Landing DB-TX.
    expect(result.evidence.landing?.nextState).toBe("INTERNAL_MOVE_LANDED");
    expect(result.evidence.landing?.eventType).toBe("internal_move.landed");
    expect(result.evidence.landing?.sameDbTx).toBe(true);
    expect(result.evidence.observationEvidence?.verifiedAt).toBeTruthy();
    expect(result.evidence.observationEvidence?.sourceTerminalObservationId).toBe(
      "obs-fresh-source",
    );
    expect(result.evidence.observationEvidence?.destinationTerminalObservationId).toBe(
      "obs-fresh-destination",
    );

    // Ack SOURCE + DESTINATION.
    expect(result.evidence.acknowledgement?.verdict).toBe("VERIFIED");
    expect(result.evidence.acknowledgement?.evidenceRoles).toEqual(["SOURCE", "DESTINATION"]);
    expect(REQUIRED_EVIDENCE_ROLES.MOVE_INTERNAL).toEqual(["SOURCE", "DESTINATION"]);
    expect(result.evidence.acknowledgement?.evidenceSetComplete).toBe(true);

    // Lease release only after group predicate.
    expect(result.evidence.leaseRelease?.clampedStatus).toBe("RELEASED");
    expect(result.evidence.leaseRelease?.released).toBe(true);
    expect(result.evidence.leaseRelease?.releaseGatedOnGroupPredicate).toBe(true);
    expect(dworld.releaseCalls).toBe(1);

    // evidence packet.
    expect(dworld.archiveCalls).toBe(1);
    const packet = result.evidence.evidencePacket!;
    expect(packet.kind).toBe("MOVE_INTERNAL_LIVE_CHAIN_EVIDENCE_V1");
    expect(packet.dualControl).toBe(true);
    expect(packet.externalCounterparty).toBe(false);
    expect(packet.noSpeculativeContractImplemented).toBe(true);
    expect(packet.negativePathAssertion.length).toBeGreaterThan(0);
    expect(packet.packetSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(packet.governingRules.some((s) => s.includes("observation and verification"))).toBe(
      true,
    );
  });

  it("MOVE_INTERNAL required evidence roles are exactly SOURCE + DESTINATION", () => {
    expect(REQUIRED_EVIDENCE_ROLES.MOVE_INTERNAL).toEqual(["SOURCE", "DESTINATION"]);
    expect(MOVE_INTERNAL_PATH_PREDICATES).toContain("send_artifact_verify");
    expect(MOVE_INTERNAL_PATH_PREDICATES).toContain("source_balance_delta");
    expect(MOVE_INTERNAL_PATH_PREDICATES).toContain("destination_balance_delta");
    expect(MOVE_INTERNAL_PATH_PREDICATES).toContain("spawn_continuity");
  });
});

describe("disposeMoveInternalEvidence — negative paths (no blind retry / no submit)", () => {
  it("refuses when execute is not LANDED_VERIFIED and never releases", async () => {
    const { world, evidence } = await landedExecute();
    const broken: MoveExecuteEvidenceBundle = {
      ...evidence,
      disposition: "HOLD_BOTH_LEASES_AND_RECONCILE",
    };
    const dworld = makeDispositionWorld({ executeWorld: world, executeEvidence: broken });
    const custody = custodyFor(world);

    const result = await disposeMoveInternalEvidence(buildDispositionDeps(dworld), {
      operationId: "op-move-disposition-1",
      executeEvidence: broken,
      sourceCustody: custody.sourceCustody,
      destinationCustody: custody.destinationCustody,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("REFUSED_EXECUTE_NOT_LANDED");
    expect(result.evidence.submitCallCount).toBe(0);
    expect(dworld.releaseCalls).toBe(0);
    expect(dworld.archiveCalls).toBe(0);
  });

  it("NEGATIVE: missing fresh heads → HOLD, no release, no submit", async () => {
    const { world, evidence } = await landedExecute();
    const dworld = makeDispositionWorld({
      executeWorld: world,
      executeEvidence: evidence,
      freshMissing: true,
    });
    const custody = custodyFor(world);

    const result = await disposeMoveInternalEvidence(buildDispositionDeps(dworld), {
      operationId: "op-move-disposition-1",
      executeEvidence: evidence,
      sourceCustody: custody.sourceCustody,
      destinationCustody: custody.destinationCustody,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("HOLD_BOTH_LEASES_AND_RECONCILE");
    expect(result.evidence.abortTrigger).toBe("SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
    expect(result.evidence.submitCallCount).toBe(0);
    expect(result.evidence.mayResubmit).toBe(false);
    expect(dworld.releaseCalls).toBe(0);
    expect(abortActionFor("SUBMIT_AMBIGUOUS_OR_UNOBSERVED").mayResubmit).toBe(false);
  });

  it("NEGATIVE: disagreeing fresh step_2 bodies → HOLD, never partial success", async () => {
    const { world, evidence } = await landedExecute();
    const dworld = makeDispositionWorld({
      executeWorld: world,
      executeEvidence: evidence,
      freshSourceConflict: true,
    });
    const custody = custodyFor(world);

    const result = await disposeMoveInternalEvidence(buildDispositionDeps(dworld), {
      operationId: "op-move-disposition-1",
      executeEvidence: evidence,
      sourceCustody: custody.sourceCustody,
      destinationCustody: custody.destinationCustody,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.bodyIdentity?.sameStep2Signature).toBe(false);
    expect(result.evidence.outcome).toBe("HOLD_BOTH_LEASES_AND_RECONCILE");
    expect(result.evidence.outcome).not.toBe("DISPOSED_VERIFIED");
    expect(dworld.releaseCalls).toBe(0);
    expect(result.evidence.submitCallCount).toBe(0);
  });

  it("NEGATIVE: fresh-head delta mismatch → ESCALATE, no release", async () => {
    const { world, evidence } = await landedExecute();
    const dworld = makeDispositionWorld({
      executeWorld: world,
      executeEvidence: evidence,
      freshDestBalanceWrong: true,
    });
    const custody = custodyFor(world);

    const result = await disposeMoveInternalEvidence(buildDispositionDeps(dworld), {
      operationId: "op-move-disposition-1",
      executeEvidence: evidence,
      sourceCustody: custody.sourceCustody,
      destinationCustody: custody.destinationCustody,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.dualDeltas?.bothExact).toBe(false);
    expect(result.evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
    expect(dworld.releaseCalls).toBe(0);
  });

  it("NEGATIVE: DB-vs-chain disagreement → ESCALATE, no release", async () => {
    const { world, evidence } = await landedExecute();
    const dworld = makeDispositionWorld({
      executeWorld: world,
      executeEvidence: evidence,
      dbAgrees: false,
    });
    const custody = custodyFor(world);

    const result = await disposeMoveInternalEvidence(buildDispositionDeps(dworld), {
      operationId: "op-move-disposition-1",
      executeEvidence: evidence,
      sourceCustody: custody.sourceCustody,
      destinationCustody: custody.destinationCustody,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("ESCALATE_INVARIANT_BREACH");
    expect(dworld.releaseCalls).toBe(0);
    expect(dworld.archiveCalls).toBe(0);
  });

  it("group child PENDING pins leases — never releases early", async () => {
    const { world, evidence } = await landedExecute();
    const dworld = makeDispositionWorld({
      executeWorld: world,
      executeEvidence: evidence,
      groupChildPending: true,
    });
    const custody = custodyFor(world);

    const result = await disposeMoveInternalEvidence(buildDispositionDeps(dworld), {
      operationId: "op-move-disposition-1",
      executeEvidence: evidence,
      sourceCustody: custody.sourceCustody,
      destinationCustody: custody.destinationCustody,
      artifactVerificationOk: true,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.outcome).toBe("ACK_PINNED");
    expect(result.evidence.leaseRelease?.clampedStatus).toBe("PINNED_GROUP_PENDING");
    expect(result.evidence.leaseRelease?.released).toBe(false);
    expect(dworld.releaseCalls).toBe(0);
    // Landing + ack still happened — only release is gated.
    expect(result.evidence.landing?.eventType).toBe("internal_move.landed");
    expect(result.evidence.acknowledgement?.verdict).toBe("VERIFIED");
  });

  it("artifact verification failure fails path manifest and never releases", async () => {
    const { world, evidence } = await landedExecute();
    const dworld = makeDispositionWorld({ executeWorld: world, executeEvidence: evidence });
    const custody = custodyFor(world);

    const result = await disposeMoveInternalEvidence(buildDispositionDeps(dworld), {
      operationId: "op-move-disposition-1",
      executeEvidence: evidence,
      sourceCustody: custody.sourceCustody,
      destinationCustody: custody.destinationCustody,
      artifactVerificationOk: false,
    });

    expect(result.ok).toBe(false);
    expect(result.evidence.pathManifest?.allVerified).toBe(false);
    expect(
      result.evidence.pathManifest?.entries.find((e) => e.predicate === "send_artifact_verify")
        ?.status,
    ).toBe("REJECTED");
    expect(dworld.releaseCalls).toBe(0);
  });

  it("abort criteria still forbid resubmit and rebuild-without-oracle", () => {
    const criteria = moveInternalAbortCriteria();
    expect(criteria.blindRetryForbidden).toBe(true);
    expect(criteria.rebuildRequiresPositiveNonLandingOracle).toBe(true);
    for (const rule of criteria.rules) {
      expect(rule.mayResubmit).toBe(false);
      expect(rule.mayRebuildWithoutPositiveOracle).toBe(false);
    }
  });

  it("parseSettledTransactionText accepts formed settled body via envelope stage", async () => {
    const { evidence } = await landedExecute();
    const text = evidence.formation!.settledTransactionText;
    const parsed = parseSettledTransactionText(text);
    expect(parsed.step_2_signature).toBe(evidence.formation!.settledStep2Signature);
    expect(parsed.inner.version).toBe("2");
  });
});
