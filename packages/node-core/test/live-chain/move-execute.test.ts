// Offline unit tests for the authorized MOVE_INTERNAL execute harness.
//
// No network, no filesystem, no real private-key custody. Signers use node:crypto Ed25519
// over the exact preimage bytes (the byte-exact signing rule). Headline invariants:
//   - both leases acquired before any T0 read;
//   - submit called EXACTLY ONCE across every outcome;
//   - ambiguity never resubmits (the never-blind-retry rule);
//   - landed path proves same step_2_signature + exact dual deltas;
//   - at least one negative-path assertion per acceptance slice.

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

import type { SettledSplitChainTransaction } from "../../src/protocol/inner.js";
import type { WalletStateProjection } from "../../src/protocol/wallet-role.js";

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
  MOVE_AMOUNT_HARD_CAP,
  executeAuthorizedMoveInternal,
  type HeldMoveLease,
  type MoveExecuteDeps,
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
import { DEFAULT_MOVE_AMOUNT as PREFLIGHT_DEFAULT } from "./move-preflight.js";
import { createRunnerLock } from "./runner-lock.js";
import { subtractAmounts } from "./types.js";

// ─── Deterministic Ed25519 helpers (same shape as proof/policies/test-transactions) ─

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

// ─── Fake seams ──────────────────────────────────────────────────────────────

interface FakeWorld {
  source: { publicKey: string; privateKey: NodePrivateKey };
  dest: { publicKey: string; privateKey: NodePrivateKey };
  sourceBalance: string;
  destBalance: string;
  sourceHeadS: string;
  destHeadS: string;
  /** Order of lease acquisition recorded for assertion. */
  leaseAcquireLog: string[];
  /** T0 observe call log (roles). */
  t0ObserveLog: string[];
  submitCalls: number;
  submitBehavior: MoveSubmitOutcomeKind | "throw";
  /** When true, terminal observe returns null (unobserved). */
  terminalMissing: boolean;
  /** When set, terminal returns a conflicting step_2 on dest path. */
  destConflictingStep2: boolean;
  persistLog: string[];
  /** Captured formation for landing injection. */
  lastFormation: MoveFormationRecord | null;
}

/** Valid 88-char padded base64url Ed25519 signatures (scalar grammar). */
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
  const parsed = JSON.parse(text) as SettledSplitChainTransaction;
  return parsed;
}

function buildDeps(world: FakeWorld): MoveExecuteDeps {
  const leases: MoveLeaseSeam = {
    async acquireBothInUuidOrder(input) {
      for (const id of input.acquireOrder) {
        world.leaseAcquireLog.push(id);
      }
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
        // Different signature on dest path → same-tx predicate fails.
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
      return {
        outcome: world.submitBehavior,
        detail: `fake-${world.submitBehavior}`,
      };
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
  // Local tests only use simple canonical amounts; reuse subtract via identity a+b = a - (-b)
  // is not available — decimal add for non-negative test fixtures.
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
  const [i, f = ""] = v.split(".");
  return BigInt((i.replace(/^0+/, "") || "0") + f.padEnd(scale, "0"));
}

function baseInput(world: FakeWorld, overrides: Partial<MoveExecuteInput> = {}): MoveExecuteInput {
  const attemptId = "attempt-move-execute-1";
  const state = readyMoveState(attemptId);
  state.balances.set(SAMPLE_SOURCE_ID, world.sourceBalance);
  state.balances.set(SAMPLE_DEST_ID, world.destBalance);
  return {
    attemptId,
    operationId: "op-move-execute-1",
    sourceWalletId: SAMPLE_SOURCE_ID,
    destinationWalletId: SAMPLE_DEST_ID,
    amount: DEFAULT_MOVE_AMOUNT,
    authorization: sampleAuth(attemptId),
    runnerLock: createRunnerLock(),
    runnerHolderId: "fixture-2-execute",
    preflightProbe: fakeMoveProbe(state),
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("executeAuthorizedMoveInternal — happy path", () => {
  it("lands with one submit, same step_2_signature, and exact dual deltas", async () => {
    const world = makeWorld();
    const result = await executeAuthorizedMoveInternal(buildDeps(world), baseInput(world));

    expect(result.ok).toBe(true);
    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
    expect(result.evidence.submit?.submitCallCount).toBe(1);
    expect(result.evidence.submit?.decision).toBe("INITIAL_SINGLE_SHOT");
    expect(world.submitCalls).toBe(1);

    expect(result.evidence.bothLeasesBeforeAnyRead).toBe(true);
    expect(result.evidence.landing?.sameStep2Signature).toBe(true);
    expect(result.evidence.landing?.deltasMatchAmount).toBe(true);
    expect(result.evidence.landing?.sourceDelta).toBe(DEFAULT_MOVE_AMOUNT);
    expect(result.evidence.landing?.destinationDelta).toBe(DEFAULT_MOVE_AMOUNT);
    expect(result.evidence.landing?.sourceObservation.step2Signature).toBe(
      result.evidence.landing?.destinationObservation.step2Signature,
    );
    expect(result.evidence.formation?.settledStep2Signature).toBe(
      result.evidence.landing?.sourceObservation.step2Signature,
    );

    // Amount default aligns with preflight dust.
    expect(DEFAULT_MOVE_AMOUNT).toBe(PREFLIGHT_DEFAULT);
    expect(compareCap(DEFAULT_MOVE_AMOUNT)).toBe(true);

    result.runnerLockHandle?.release();
  });

  it("acquires leases in UUID ascending order before any T0 read", async () => {
    const world = makeWorld();
    const result = await executeAuthorizedMoveInternal(buildDeps(world), baseInput(world));
    expect(result.ok).toBe(true);

    // SAMPLE_SOURCE_ID < SAMPLE_DEST_ID
    expect(world.leaseAcquireLog).toEqual([SAMPLE_SOURCE_ID, SAMPLE_DEST_ID]);
    // T0 observes happen after both lease ids logged.
    expect(world.t0ObserveLog).toEqual(["MOVE_SOURCE_T0", "MOVE_DESTINATION_T0"]);
    expect(result.evidence.bothLeasesBeforeAnyRead).toBe(true);
    expect(result.evidence.leaseUuidOrder.acquireOrder).toEqual([
      SAMPLE_SOURCE_ID,
      SAMPLE_DEST_ID,
    ]);

    result.runnerLockHandle?.release();
  });

  it("persists formation steps before the single submit", async () => {
    const world = makeWorld();
    const result = await executeAuthorizedMoveInternal(buildDeps(world), baseInput(world));
    expect(result.ok).toBe(true);
    expect(world.persistLog.slice(0, 4)).toEqual([
      "inner",
      "step1",
      "step2-preimage",
      "completed",
    ]);
    expect(world.persistLog).toContain("submit-attempt");
    // submit-attempt is after completed
    expect(world.persistLog.indexOf("completed")).toBeLessThan(
      world.persistLog.indexOf("submit-attempt"),
    );
    result.runnerLockHandle?.release();
  });
});

describe("executeAuthorizedMoveInternal — negative paths (no blind retry)", () => {
  it("refuses when preflight is not ready and never submits", async () => {
    const world = makeWorld();
    const attemptId = "attempt-move-execute-1";
    const state = readyMoveState(attemptId);
    // Break destination recovery so preflight fails.
    const dest = state.wallets.get(SAMPLE_DEST_ID)!;
    state.wallets.set(SAMPLE_DEST_ID, { ...dest, recoveryVerifiedAt: null });

    const result = await executeAuthorizedMoveInternal(
      buildDeps(world),
      baseInput(world, { preflightProbe: fakeMoveProbe(state) }),
    );

    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("PREFLIGHT_NOT_READY");
    expect(world.submitCalls).toBe(0);
    expect(world.leaseAcquireLog).toEqual([]);
    expect(result.evidence.submit).toBeNull();
  });

  it("on gateway REJECT: FAIL_PROVEN_NOT_STARTED, submit once, mayResubmit=false", async () => {
    const world = makeWorld({ submitBehavior: "REJECT" });
    const result = await executeAuthorizedMoveInternal(buildDeps(world), baseInput(world));

    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("FAIL_PROVEN_NOT_STARTED");
    expect(result.evidence.abortTrigger).toBe("SUBMIT_REJECTED");
    expect(result.evidence.abortAction).toBe("FAIL_PROVEN_NOT_STARTED");
    expect(world.submitCalls).toBe(1);
    expect(result.evidence.submit?.submitCallCount).toBe(1);

    const rule = abortActionFor("SUBMIT_REJECTED");
    expect(rule.mayResubmit).toBe(false);
    expect(rule.mayRebuildWithoutPositiveOracle).toBe(false);

    result.runnerLockHandle?.release();
  });

  it("on transport AMBIGUOUS + proven dual landing: still LANDED_VERIFIED, never resubmit", async () => {
    // Gateway receipt is never settlement. An ambiguous ack with independent
    // dual-path proof is a clean land — not a license to resubmit.
    const world = makeWorld({ submitBehavior: "throw" });
    const result = await executeAuthorizedMoveInternal(buildDeps(world), baseInput(world));

    expect(result.ok).toBe(true);
    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
    expect(world.submitCalls).toBe(1);
    expect(result.evidence.submit?.outcome).toBe("AMBIGUOUS");
    expect(result.evidence.submit?.submitCallCount).toBe(1);
    expect(result.evidence.landing?.sameStep2Signature).toBe(true);

    const criteria = moveInternalAbortCriteria();
    expect(criteria.blindRetryForbidden).toBe(true);
    expect(abortActionFor("SUBMIT_AMBIGUOUS_OR_UNOBSERVED").mayResubmit).toBe(false);

    result.runnerLockHandle?.release();
  });

  it("on transport AMBIGUOUS + unobserved heads: HOLD, never resubmit", async () => {
    const world = makeWorld({ submitBehavior: "throw", terminalMissing: true });
    const result = await executeAuthorizedMoveInternal(buildDeps(world), baseInput(world));

    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("HOLD_BOTH_LEASES_AND_RECONCILE");
    expect(result.evidence.abortTrigger).toBe("SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
    expect(world.submitCalls).toBe(1);
    expect(result.evidence.submit?.outcome).toBe("AMBIGUOUS");

    result.runnerLockHandle?.release();
  });

  it("on unobserved terminal heads: HOLD + single submit, no second shot", async () => {
    const world = makeWorld({ terminalMissing: true });
    const result = await executeAuthorizedMoveInternal(buildDeps(world), baseInput(world));

    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("HOLD_BOTH_LEASES_AND_RECONCILE");
    expect(result.evidence.abortTrigger).toBe("SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
    expect(world.submitCalls).toBe(1);
    expect(result.evidence.landing).toBeNull();

    result.runnerLockHandle?.release();
  });

  it("NEGATIVE: disagreeing step_2_signature paths are INDETERMINATE, not partial success", async () => {
    const world = makeWorld({ destConflictingStep2: true });
    const result = await executeAuthorizedMoveInternal(buildDeps(world), baseInput(world));

    expect(result.ok).toBe(false);
    expect(result.evidence.landing?.sameStep2Signature).toBe(false);
    expect(result.evidence.disposition).toBe("HOLD_BOTH_LEASES_AND_RECONCILE");
    expect(world.submitCalls).toBe(1);
    // Must not claim LANDED_VERIFIED on partial/disagreeing evidence.
    expect(result.evidence.disposition).not.toBe("LANDED_VERIFIED");

    result.runnerLockHandle?.release();
  });

  it("rejects amount above hard cap even if probe were green", async () => {
    const world = makeWorld({ sourceBalance: "100" });
    const attemptId = "attempt-move-execute-cap";
    const state = readyMoveState(attemptId);
    state.balances.set(SAMPLE_SOURCE_ID, "100");

    const result = await executeAuthorizedMoveInternal(
      buildDeps(world),
      baseInput(world, {
        attemptId,
        amount: "0.02",
        authorization: sampleAuth(attemptId),
        preflightProbe: fakeMoveProbe(state),
      }),
    );

    expect(result.ok).toBe(false);
    expect(result.evidence.disposition).toBe("PREFLIGHT_NOT_READY");
    expect(world.submitCalls).toBe(0);
    expect(MOVE_AMOUNT_HARD_CAP).toBe("0.01");
  });
});

describe("executeAuthorizedMoveInternal — abort criteria binding", () => {
  it("every abort trigger forbids resubmit and rebuild-without-oracle", () => {
    const criteria = moveInternalAbortCriteria();
    expect(criteria.blindRetryForbidden).toBe(true);
    expect(criteria.rebuildRequiresPositiveNonLandingOracle).toBe(true);
    for (const rule of criteria.rules) {
      expect(rule.mayResubmit).toBe(false);
      expect(rule.mayRebuildWithoutPositiveOracle).toBe(false);
    }
  });
});

function compareCap(amount: string): boolean {
  // amount <= hard cap using string decimal compare via Number is unsafe; use length-free
  // lexical path only for the fixed dust constant.
  return amount === "0.000001";
}

// Ensure createPublicKey is retained for type-compat if tooling flags unused.
void createPublicKey;
