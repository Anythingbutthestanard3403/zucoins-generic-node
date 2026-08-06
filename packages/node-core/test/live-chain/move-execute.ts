// Live MOVE_INTERNAL authorized-execute harness.
//
// Offline-first coordination over injected seams. Follows the internal-move flow
// end-to-end for one dual-control fractional move under both node-controlled wallets
// Real gateway/DB/vault adapters are wired by a live runner; unit tests inject
// in-memory fakes. Hard caps and abort policy come from the preflight surface.
//
// Governing:
//   The one-in-flight-per-wallet and byte-exact signing rules, 4
//
// Invariants this module enforces structurally:
//   - Both leases acquired (UUID order) BEFORE any T0 read.
//   - Exactly one submit call per attempt (the never-blind-retry rule) — never blind-retried.
//   - Ambiguity → HOLD_BOTH_LEASES_AND_RECONCILE; no rebuild, no second submit.
//   - Landing requires independent dual-path same step_2_signature + exact economic deltas.
//   - Private keys never appear on this surface (the key-custody rule) — only signer seams.

import {
  parseObservedZkzBalance,
  parsePositiveZkzAmount,
} from "../../src/protocol/amounts.js";
import { evaluateInternalMoveDelta } from "../../src/protocol/economic-predicates.js";
import type { SettledSplitChainTransaction } from "../../src/protocol/inner.js";
import {
  parseEd25519Signature,
  parsePreviousStateSignature,
  parseUnixTimeSecsV2,
  parseWalletPublicKey,
} from "../../src/protocol/scalars.js";
import {
  buildSettledSplitChainTransactionV2,
  buildSplitChainInnerV2,
  buildSplitChainPartialV2,
  issueCoherentWalletBaselineV2ForVerifiedHead,
  type SplitChainInnerV2Capability,
  type SplitChainPartialV2Capability,
} from "../../src/protocol/transactions.js";
import type { WalletStateProjection } from "../../src/protocol/wallet-role.js";

import {
  abortActionFor,
  type MoveAbortAction,
  type MoveAbortTrigger,
  moveInternalAbortCriteria,
} from "./abort-criteria.js";
import {
  DEFAULT_MOVE_AMOUNT,
  leaseUuidOrder,
  MOVE_AMOUNT_HARD_CAP,
  runMoveInternalPreflight,
  type LeaseUuidOrder,
  type MovePreflightProbe,
  type MovePreflightReport,
} from "./move-preflight.js";
import type { RunnerLock, RunnerLockHandle } from "./runner-lock.js";
import {
  compareAmounts,
  signedDelta,
  type Amount,
  type DualControlAuthorization,
  type MoveInternalPlan,
} from "./types.js";

export { DEFAULT_MOVE_AMOUNT, MOVE_AMOUNT_HARD_CAP };

// ─── Public plan / evidence types ────────────────────────────────────────────

/** Fresh T0 snapshot observed while both leases are held. */
export interface MoveT0Snapshot {
  readonly walletId: string;
  readonly publicKey: string;
  readonly observationId: string;
  readonly projection: WalletStateProjection;
}

/** Persisted formation material for one attempt (key-free; preimage text only). */
export interface MoveFormationRecord {
  readonly attemptNo: 1;
  readonly innerPreimageText: string;
  readonly innerPreimageSha256: string;
  readonly step1Signature: string;
  readonly step2PreimageText: string;
  readonly step2Signature: string;
  /** Exact full dual-signed transaction text submitted once. */
  readonly settledTransactionText: string;
  readonly settledStep2Signature: string;
}

export type MoveSubmitOutcomeKind = "ACK" | "REJECT" | "AMBIGUOUS";

export interface MoveSubmitEvidence {
  readonly outcome: MoveSubmitOutcomeKind;
  readonly submitCallCount: number;
  readonly decision: "INITIAL_SINGLE_SHOT";
  /** Opaque gateway response summary — never raw key material. */
  readonly detail: string;
}

export interface MoveTerminalObservation {
  readonly walletId: string;
  readonly publicKey: string;
  readonly observationId: string;
  readonly step2Signature: string;
  readonly balanceAfter: Amount;
  /** Settled body as observed on this path (for same-tx predicate). */
  readonly settled: SettledSplitChainTransaction;
}

export interface MoveLandingEvidence {
  readonly sameStep2Signature: boolean;
  readonly sourceDelta: Amount;
  readonly destinationDelta: Amount;
  readonly deltasMatchAmount: boolean;
  readonly sourceObservation: MoveTerminalObservation;
  readonly destinationObservation: MoveTerminalObservation;
}

export type MoveExecuteDisposition =
  | "LANDED_VERIFIED"
  | "FAIL_PROVEN_NOT_STARTED"
  | "HOLD_BOTH_LEASES_AND_RECONCILE"
  | "ESCALATE_INVARIANT_BREACH"
  | "PREFLIGHT_NOT_READY"
  | "ABORTED_BEFORE_SUBMIT";

export interface MoveExecuteEvidenceBundle {
  readonly attemptId: string;
  readonly plan: MoveInternalPlan | null;
  readonly disposition: MoveExecuteDisposition;
  readonly abortAction: MoveAbortAction | null;
  readonly abortTrigger: MoveAbortTrigger | null;
  readonly leaseUuidOrder: LeaseUuidOrder;
  /** True only when both leases were acquired before any T0 read. */
  readonly bothLeasesBeforeAnyRead: boolean;
  readonly sourceT0: MoveT0Snapshot | null;
  readonly destinationT0: MoveT0Snapshot | null;
  readonly formation: MoveFormationRecord | null;
  readonly submit: MoveSubmitEvidence | null;
  readonly landing: MoveLandingEvidence | null;
  /** Key-free human-readable trail for the evidence packet. */
  readonly trail: readonly string[];
  readonly preflight: MovePreflightReport | null;
}

export interface MoveExecuteResult {
  readonly ok: boolean;
  readonly evidence: MoveExecuteEvidenceBundle;
  /** Non-null only when the runner lock was acquired and must be released by the caller. */
  readonly runnerLockHandle: RunnerLockHandle | null;
}

// ─── Injected seams (live runner wires real adapters; tests wire fakes) ──────

export interface HeldMoveLease {
  readonly walletId: string;
  readonly role: "MOVE_SOURCE" | "MOVE_DESTINATION";
  readonly operationId: string;
  readonly leaseEpoch: bigint;
}

export interface MoveLeaseSeam {
  /**
   * Acquire source + destination leases atomically in UUID order.
   * Implementations MUST sort by wallet UUID ascending before taking locks and MUST
   * not return until both are held (or throw / reject without a partial hold).
   */
  acquireBothInUuidOrder(input: {
    readonly operationId: string;
    readonly sourceWalletId: string;
    readonly destinationWalletId: string;
    readonly acquireOrder: readonly [string, string];
  }): Promise<readonly [HeldMoveLease, HeldMoveLease]>;
}

export interface MoveObserveSeam {
  /** Fresh verified head for a wallet while its lease is held. */
  observeFreshT0(input: {
    readonly walletId: string;
    readonly publicKey: string;
    readonly role: "MOVE_SOURCE_T0" | "MOVE_DESTINATION_T0";
  }): Promise<MoveT0Snapshot>;

  /**
   * Independent post-submit head read for landing proof. Returns null when the
   * head cannot be established (transport failure / indeterminate) — never a guess.
   */
  observeTerminal(input: {
    readonly walletId: string;
    readonly publicKey: string;
    readonly expectedStep2Signature: string;
  }): Promise<MoveTerminalObservation | null>;
}

export interface MoveWalletDirectory {
  /** Resolve the wallet's current public key (node-controlled identity). */
  publicKeyFor(walletId: string): Promise<string>;
}

/**
 * Signing seam — vault/HSM behind the lease capability. The harness never sees a private
 * key (the key-custody rule). Signers MUST sign the exact preimageText bytes (the byte-exact signing rule).
 */
export interface MoveSignerSeam {
  signStep1(input: {
    readonly walletId: string;
    readonly operationId: string;
    readonly leaseEpoch: bigint;
    readonly preimageText: string;
  }): Promise<string>;
  signStep2(input: {
    readonly walletId: string;
    readonly operationId: string;
    readonly leaseEpoch: bigint;
    readonly preimageText: string;
  }): Promise<string>;
}

/**
 * Durable persist seam for steps 2/4/6/8. Implementations write attempt/preimage/
 * signature rows; the harness only needs confirmations. Fakes may no-op.
 */
export interface MovePersistSeam {
  persistInnerPreimage(input: {
    readonly operationId: string;
    readonly attemptNo: 1;
    readonly innerPreimageText: string;
    readonly innerPreimageSha256: string;
    readonly sourceT0ObservationId: string;
    readonly destinationT0ObservationId: string;
  }): Promise<void>;
  persistStep1Signature(input: {
    readonly operationId: string;
    readonly attemptNo: 1;
    readonly step1Signature: string;
  }): Promise<void>;
  persistStep2Preimage(input: {
    readonly operationId: string;
    readonly attemptNo: 1;
    readonly step2PreimageText: string;
  }): Promise<void>;
  persistCompletedTransaction(input: {
    readonly operationId: string;
    readonly attemptNo: 1;
    readonly step2Signature: string;
    readonly settledTransactionText: string;
    readonly submitDecision: "INITIAL_SINGLE_SHOT";
  }): Promise<void>;
  recordSubmitAttempt(input: {
    readonly operationId: string;
    readonly attemptNo: 1;
    readonly outcome: MoveSubmitOutcomeKind;
    readonly detail: string;
  }): Promise<void>;
}

export interface MoveSubmitSeam {
  /**
   * Invoke the gateway submit EXACTLY ONCE for this attempt. Implementations must not
   * retry internally — ambiguity is the caller's problem (the never-blind-retry rule).
   */
  submitOnce(input: {
    readonly operationId: string;
    readonly attemptNo: 1;
    readonly settledTransactionText: string;
  }): Promise<{ readonly outcome: MoveSubmitOutcomeKind; readonly detail: string }>;
}

export interface MoveExecuteDeps {
  readonly leases: MoveLeaseSeam;
  readonly observe: MoveObserveSeam;
  readonly wallets: MoveWalletDirectory;
  readonly signer: MoveSignerSeam;
  readonly persist: MovePersistSeam;
  readonly submit: MoveSubmitSeam;
  /** Optional clock for unix_time_secs (fractional string). Defaults to Date.now()/1000. */
  readonly nowUnixSecs?: () => string;
}

export interface MoveExecuteInput {
  readonly attemptId: string;
  readonly operationId: string;
  readonly sourceWalletId: string;
  readonly destinationWalletId: string;
  readonly amount: Amount;
  readonly authorization: DualControlAuthorization;
  readonly runnerLock: RunnerLock;
  readonly runnerHolderId: string;
  /** Preflight probe (wallet facts / leases / balance / T0 freshness). */
  readonly preflightProbe: MovePreflightProbe;
  readonly amountCeiling?: Amount;
  /**
   * When true (default), refuse to run if preflight is not ready. Live runners always leave
   * this true; tests may set false only when injecting a pre-validated plan path.
   */
  readonly requirePreflight?: boolean;
}

// ─── Internals ───────────────────────────────────────────────────────────────

function trailPush(trail: string[], line: string): void {
  trail.push(line);
}

function baselineKind(projection: WalletStateProjection): "GENESIS" | "HEAD" {
  return projection.role === "genesis" ? "GENESIS" : "HEAD";
}

function constructMoveInner(input: {
  readonly sourceT0: MoveT0Snapshot;
  readonly destinationT0: MoveT0Snapshot;
  readonly amount: Amount;
  readonly unixTimeSecs: string;
}): {
  readonly capability: SplitChainInnerV2Capability;
  readonly innerPreimageText: string;
  readonly innerPreimageSha256: string;
} {
  // Canonical builder only — JSON.stringify of the 14-field fixed sequence lives
  // inside buildSplitChainInnerV2. Callers never stringify the inner themselves.
  const sender = issueCoherentWalletBaselineV2ForVerifiedHead({
    kind: baselineKind(input.sourceT0.projection),
    publicKey: parseWalletPublicKey(input.sourceT0.publicKey),
    balance: parseObservedZkzBalance(input.sourceT0.projection.B),
    previousSettledStep2Signature: parsePreviousStateSignature(input.sourceT0.projection.S),
  });
  const receiver = issueCoherentWalletBaselineV2ForVerifiedHead({
    kind: baselineKind(input.destinationT0.projection),
    publicKey: parseWalletPublicKey(input.destinationT0.publicKey),
    balance: parseObservedZkzBalance(input.destinationT0.projection.B),
    previousSettledStep2Signature: parsePreviousStateSignature(
      input.destinationT0.projection.S,
    ),
  });

  const capability = buildSplitChainInnerV2({
    unixTimeSecs: parseUnixTimeSecsV2(input.unixTimeSecs),
    sender,
    receiver,
    transferAmount: parsePositiveZkzAmount(input.amount),
  });

  return {
    capability,
    innerPreimageText: capability.innerPreimageText,
    innerPreimageSha256: capability.innerPreimageSha256,
  };
}

function emptyEvidence(
  input: MoveExecuteInput,
  order: LeaseUuidOrder,
): MoveExecuteEvidenceBundle {
  return {
    attemptId: input.attemptId,
    plan: null,
    disposition: "ABORTED_BEFORE_SUBMIT",
    abortAction: null,
    abortTrigger: null,
    leaseUuidOrder: order,
    bothLeasesBeforeAnyRead: false,
    sourceT0: null,
    destinationT0: null,
    formation: null,
    submit: null,
    landing: null,
    trail: [],
    preflight: null,
  };
}

/**
 * Execute one authorized live MOVE_INTERNAL under dual-control with hard caps.
 *
 * Sequence:
 *   1. Preflight  — dual-control, eligibility, amount ceiling, runner lock.
 *   2. Acquire BOTH leases in UUID order BEFORE any read (close).
 *   3. Observe both fresh T0s while leases held; form/sign/persist via canonical builders.
 *   4. Single-shot submit; never retry on ambiguity.
 *   5. Independent dual-path terminal reads; same step_2_signature + exact deltas.
 *
 * Rebuild after positive non-landing oracle is OUT OF SCOPE.
 */
export async function executeAuthorizedMoveInternal(
  deps: MoveExecuteDeps,
  input: MoveExecuteInput,
): Promise<MoveExecuteResult> {
  const order = leaseUuidOrder(input.sourceWalletId, input.destinationWalletId);
  const trail: string[] = [];
  const abortCriteria = moveInternalAbortCriteria();
  trailPush(
    trail,
    `abort policy ${abortCriteria.policyId}: blind-retry=${!abortCriteria.blindRetryForbidden ? "ALLOWED" : "forbidden"}`,
  );

  // ── preflight ────────────────────────────────────────────
  const preflight = await runMoveInternalPreflight(input.preflightProbe, {
    attemptId: input.attemptId,
    sourceWalletId: input.sourceWalletId,
    destinationWalletId: input.destinationWalletId,
    amount: input.amount,
    authorization: input.authorization,
    amountCeiling: input.amountCeiling,
    runnerLock: input.runnerLock,
    runnerHolderId: input.runnerHolderId,
  });

  const requirePreflight = input.requirePreflight !== false;
  if (requirePreflight && !preflight.ready) {
    trailPush(trail, "preflight not ready — refusing execute");
    for (const c of preflight.checks.filter((x) => !x.ok)) {
      trailPush(trail, `  fail ${c.id}: ${c.detail}`);
    }
    return {
      ok: false,
      runnerLockHandle: null,
      evidence: {
        ...emptyEvidence(input, order),
        disposition: "PREFLIGHT_NOT_READY",
        preflight,
        trail,
      },
    };
  }

  const plan = preflight.plan;
  if (plan === null) {
    // Defensive: ready without plan should be unreachable.
    trailPush(trail, "preflight ready but plan null — refuse");
    preflight.runnerLockHandle?.release();
    return {
      ok: false,
      runnerLockHandle: null,
      evidence: {
        ...emptyEvidence(input, order),
        disposition: "PREFLIGHT_NOT_READY",
        preflight,
        trail,
      },
    };
  }

  const runnerLockHandle = preflight.runnerLockHandle;
  trailPush(
    trail,
    `preflight ready; plan amount=${plan.amount}; dual-control=${plan.authorization.attestationId}`,
  );

  // Hard-cap defense even if preflight was bypassed in a test path.
  try {
    if (compareAmounts(plan.amount, MOVE_AMOUNT_HARD_CAP) > 0) {
      trailPush(trail, `amount ${plan.amount} exceeds hard cap ${MOVE_AMOUNT_HARD_CAP}`);
      runnerLockHandle?.release();
      return {
        ok: false,
        runnerLockHandle: null,
        evidence: {
          ...emptyEvidence(input, order),
          plan,
          disposition: "PREFLIGHT_NOT_READY",
          preflight,
          trail,
        },
      };
    }
  } catch (err) {
    trailPush(trail, err instanceof Error ? err.message : "amount parse failed");
    runnerLockHandle?.release();
    return {
      ok: false,
      runnerLockHandle: null,
      evidence: {
        ...emptyEvidence(input, order),
        plan,
        disposition: "PREFLIGHT_NOT_READY",
        preflight,
        trail,
      },
    };
  }

  let bothLeasesBeforeAnyRead = false;
  let sourceT0: MoveT0Snapshot | null = null;
  let destinationT0: MoveT0Snapshot | null = null;
  let formation: MoveFormationRecord | null = null;
  let submitEv: MoveSubmitEvidence | null = null;
  let landing: MoveLandingEvidence | null = null;
  let submitCallCount = 0;

  const finish = (
    ok: boolean,
    disposition: MoveExecuteDisposition,
    trigger: MoveAbortTrigger | null,
  ): MoveExecuteResult => {
    const rule = trigger !== null ? abortActionFor(trigger) : null;
    if (rule !== null && rule.mayResubmit !== false) {
      // Structural: abort criteria always set mayResubmit:false; belt-and-braces.
      throw new Error("abort rule must forbid resubmit");
    }
    return {
      ok,
      runnerLockHandle: runnerLockHandle ?? null,
      evidence: {
        attemptId: input.attemptId,
        plan,
        disposition,
        abortAction: rule?.action ?? null,
        abortTrigger: trigger,
        leaseUuidOrder: order,
        bothLeasesBeforeAnyRead,
        sourceT0,
        destinationT0,
        formation,
        submit: submitEv,
        landing,
        trail: [...trail],
        preflight,
      },
    };
  };

  // ── BOTH leases before any read ────────────────────────────
  trailPush(
    trail,
    `acquiring leases UUID order first=${order.first} second=${order.second}`,
  );
  let held: readonly [HeldMoveLease, HeldMoveLease];
  try {
    held = await deps.leases.acquireBothInUuidOrder({
      operationId: input.operationId,
      sourceWalletId: plan.sourceWalletId,
      destinationWalletId: plan.destinationWalletId,
      acquireOrder: order.acquireOrder,
    });
  } catch (err) {
    trailPush(
      trail,
      `lease acquisition failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  bothLeasesBeforeAnyRead = true;
  trailPush(
    trail,
    `both leases held: ${held.map((h) => `${h.role}@${h.walletId}`).join(", ")}`,
  );

  const sourceLease = held.find((h) => h.role === "MOVE_SOURCE");
  const destLease = held.find((h) => h.role === "MOVE_DESTINATION");
  if (sourceLease === undefined || destLease === undefined) {
    trailPush(trail, "lease pair missing MOVE_SOURCE or MOVE_DESTINATION role");
    return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
  }

  // ── observe both T0s while leases held ──────────────────
  let sourcePk: string;
  let destPk: string;
  try {
    sourcePk = await deps.wallets.publicKeyFor(plan.sourceWalletId);
    destPk = await deps.wallets.publicKeyFor(plan.destinationWalletId);
  } catch (err) {
    trailPush(
      trail,
      `wallet directory failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  try {
    sourceT0 = await deps.observe.observeFreshT0({
      walletId: plan.sourceWalletId,
      publicKey: sourcePk,
      role: "MOVE_SOURCE_T0",
    });
    destinationT0 = await deps.observe.observeFreshT0({
      walletId: plan.destinationWalletId,
      publicKey: destPk,
      role: "MOVE_DESTINATION_T0",
    });
  } catch (err) {
    trailPush(
      trail,
      `T0 observation failed under dual lease: ${err instanceof Error ? err.message : String(err)}`,
    );
    // Ambiguous pre-submit observation → hold leases, reconcile (no submit occurred).
    return finish(false, "HOLD_BOTH_LEASES_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }
  trailPush(
    trail,
    `T0 source B=${sourceT0.projection.B} S=${truncateSig(sourceT0.projection.S)}; ` +
      `dest B=${destinationT0.projection.B} S=${truncateSig(destinationT0.projection.S)}`,
  );

  // Source balance must cover amount (exact decimal).
  try {
    if (compareAmounts(sourceT0.projection.B, plan.amount) < 0) {
      trailPush(
        trail,
        `source T0 balance ${sourceT0.projection.B} < amount ${plan.amount}`,
      );
      return finish(false, "ABORTED_BEFORE_SUBMIT", null);
    }
  } catch (err) {
    trailPush(trail, err instanceof Error ? err.message : "T0 balance compare failed");
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  // ── form, sign, persist (canonical builders only) ───────
  const unixTimeSecs = (deps.nowUnixSecs ?? defaultUnixTimeSecs)();
  let innerCap: SplitChainInnerV2Capability;
  let innerPreimageText: string;
  let innerPreimageSha256: string;
  try {
    const built = constructMoveInner({
      sourceT0,
      destinationT0,
      amount: plan.amount,
      unixTimeSecs,
    });
    innerCap = built.capability;
    innerPreimageText = built.innerPreimageText;
    innerPreimageSha256 = built.innerPreimageSha256;
  } catch (err) {
    trailPush(
      trail,
      `inner construction failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  trailPush(trail, `inner preimage sha256=${innerPreimageSha256.slice(0, 16)}…`);

  try {
    await deps.persist.persistInnerPreimage({
      operationId: input.operationId,
      attemptNo: 1,
      innerPreimageText,
      innerPreimageSha256,
      sourceT0ObservationId: sourceT0.observationId,
      destinationT0ObservationId: destinationT0.observationId,
    });
  } catch (err) {
    trailPush(
      trail,
      `persist inner failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  let step1Signature: string;
  try {
    step1Signature = await deps.signer.signStep1({
      walletId: plan.sourceWalletId,
      operationId: input.operationId,
      leaseEpoch: sourceLease.leaseEpoch,
      preimageText: innerPreimageText,
    });
    parseEd25519Signature(step1Signature);
  } catch (err) {
    trailPush(
      trail,
      `step-1 sign failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  try {
    await deps.persist.persistStep1Signature({
      operationId: input.operationId,
      attemptNo: 1,
      step1Signature,
    });
  } catch (err) {
    trailPush(
      trail,
      `persist step-1 failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  let partial: SplitChainPartialV2Capability;
  try {
    // Build step-2 preimage from persisted inner text + step-1 sig via
    // the canonical partial builder (byte-exact fixed insertion order).
    partial = buildSplitChainPartialV2(innerCap, parseEd25519Signature(step1Signature));
  } catch (err) {
    trailPush(
      trail,
      `partial construction failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  try {
    await deps.persist.persistStep2Preimage({
      operationId: input.operationId,
      attemptNo: 1,
      step2PreimageText: partial.step2PreimageText,
    });
  } catch (err) {
    trailPush(
      trail,
      `persist step-2 preimage failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  let step2Signature: string;
  try {
    step2Signature = await deps.signer.signStep2({
      walletId: plan.destinationWalletId,
      operationId: input.operationId,
      leaseEpoch: destLease.leaseEpoch,
      preimageText: partial.step2PreimageText,
    });
    parseEd25519Signature(step2Signature);
  } catch (err) {
    trailPush(
      trail,
      `step-2 sign failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  let settledText: string;
  let settledStep2: string;
  try {
    const settled = buildSettledSplitChainTransactionV2(
      partial,
      parseEd25519Signature(step2Signature),
    );
    settledText = settled.transactionText;
    settledStep2 = settled.transaction.step_2_signature;
  } catch (err) {
    trailPush(
      trail,
      `settled construction failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  formation = {
    attemptNo: 1,
    innerPreimageText,
    innerPreimageSha256,
    step1Signature,
    step2PreimageText: partial.step2PreimageText,
    step2Signature,
    settledTransactionText: settledText,
    settledStep2Signature: settledStep2,
  };

  try {
    await deps.persist.persistCompletedTransaction({
      operationId: input.operationId,
      attemptNo: 1,
      step2Signature,
      settledTransactionText: settledText,
      submitDecision: "INITIAL_SINGLE_SHOT",
    });
  } catch (err) {
    trailPush(
      trail,
      `persist completed tx failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  trailPush(trail, `formation complete; step_2_sig=${truncateSig(settledStep2)}`);

  // ── single-shot submit (never again) ───────────────────────
  let submitOutcome: MoveSubmitOutcomeKind;
  let submitDetail: string;
  try {
    submitCallCount += 1;
    const resp = await deps.submit.submitOnce({
      operationId: input.operationId,
      attemptNo: 1,
      settledTransactionText: settledText,
    });
    submitOutcome = resp.outcome;
    submitDetail = resp.detail;
  } catch (err) {
    // Transport throw = ambiguous; do NOT resubmit.
    submitOutcome = "AMBIGUOUS";
    submitDetail = err instanceof Error ? err.message : String(err);
  }

  if (submitCallCount !== 1) {
    trailPush(trail, `INVARIANT: submitCallCount=${submitCallCount} (must be 1)`);
    return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
  }

  submitEv = {
    outcome: submitOutcome,
    submitCallCount,
    decision: "INITIAL_SINGLE_SHOT",
    detail: submitDetail,
  };
  try {
    await deps.persist.recordSubmitAttempt({
      operationId: input.operationId,
      attemptNo: 1,
      outcome: submitOutcome,
      detail: submitDetail,
    });
  } catch (err) {
    // Evidence write failure after the exchange is itself ambiguous — hold + reconcile.
    trailPush(
      trail,
      `record submit attempt failed after exchange: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "HOLD_BOTH_LEASES_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }
  trailPush(trail, `submit once → ${submitOutcome}: ${submitDetail}`);

  if (submitOutcome === "REJECT") {
    const rule = abortActionFor("SUBMIT_REJECTED");
    trailPush(trail, `abort ${rule.trigger} → ${rule.action} (mayResubmit=${rule.mayResubmit})`);
    return finish(false, "FAIL_PROVEN_NOT_STARTED", "SUBMIT_REJECTED");
  }

  // ── independent dual-path landing proof ───────────────────────────
  // Even on ACK we prove landing by observation, never by gateway receipt.
  let sourceTerminal: MoveTerminalObservation | null;
  let destTerminal: MoveTerminalObservation | null;
  try {
    sourceTerminal = await deps.observe.observeTerminal({
      walletId: plan.sourceWalletId,
      publicKey: sourcePk,
      expectedStep2Signature: settledStep2,
    });
    destTerminal = await deps.observe.observeTerminal({
      walletId: plan.destinationWalletId,
      publicKey: destPk,
      expectedStep2Signature: settledStep2,
    });
  } catch (err) {
    trailPush(
      trail,
      `terminal observation threw: ${err instanceof Error ? err.message : String(err)}`,
    );
    return finish(false, "HOLD_BOTH_LEASES_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }

  if (sourceTerminal === null || destTerminal === null) {
    trailPush(
      trail,
      `terminal observation incomplete: source=${sourceTerminal !== null} dest=${destTerminal !== null}`,
    );
    return finish(false, "HOLD_BOTH_LEASES_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }

  const sameSig = sourceTerminal.step2Signature === destTerminal.step2Signature;
  const sourceDelta = signedDelta(sourceT0.projection.B, sourceTerminal.balanceAfter);
  // Source should decrease: signedDelta(before, after) is negative; economic check uses absolute.
  const sourceDebit = signedDelta(sourceTerminal.balanceAfter, sourceT0.projection.B);
  const destCredit = signedDelta(destinationT0.projection.B, destTerminal.balanceAfter);

  const deltaEval = evaluateInternalMoveDelta({
    source: {
      baseline: sourceT0.projection,
      candidateTx: sourceTerminal.settled,
      walletPublicKey: sourcePk,
    },
    destination: {
      baseline: destinationT0.projection,
      candidateTx: destTerminal.settled,
      walletPublicKey: destPk,
    },
    operation: {
      amountZkz: plan.amount,
      sourcePubkey: sourcePk,
      destinationPubkey: destPk,
    },
  });

  landing = {
    sameStep2Signature: sameSig,
    sourceDelta: sourceDebit,
    destinationDelta: destCredit,
    deltasMatchAmount:
      deltaEval.ok &&
      compareAmounts(sourceDebit, plan.amount) === 0 &&
      compareAmounts(destCredit, plan.amount) === 0,
    sourceObservation: sourceTerminal,
    destinationObservation: destTerminal,
  };

  trailPush(
    trail,
    `landing same_sig=${sameSig} srcΔ=${sourceDebit} dstΔ=${destCredit} ` +
      `deltaEval=${deltaEval.ok ? "ok" : deltaEval.reason}`,
  );

  if (!sameSig) {
    trailPush(trail, "INDETERMINATE: independent paths disagree on step_2_signature");
    return finish(false, "HOLD_BOTH_LEASES_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }

  if (!deltaEval.ok || !landing.deltasMatchAmount) {
    trailPush(
      trail,
      `delta/invariant failure: ${deltaEval.ok ? "amount mismatch" : deltaEval.detail}`,
    );
    // Contradictory successor under active lease → escalate, never resubmit.
    return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
  }

  // Confirm the observed signature is the one we formed (not some other concurrent move).
  if (sourceTerminal.step2Signature !== settledStep2) {
    trailPush(
      trail,
      `observed step_2 ${truncateSig(sourceTerminal.step2Signature)} ≠ formed ${truncateSig(settledStep2)}`,
    );
    return finish(false, "HOLD_BOTH_LEASES_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }

  trailPush(trail, `LANDED_VERIFIED amount=${plan.amount} step_2=${truncateSig(settledStep2)}`);
  // Silence unused binding (sourceDelta retained for evidence symmetry).
  void sourceDelta;
  return finish(true, "LANDED_VERIFIED", "LANDED_VERIFIED");
}

function defaultUnixTimeSecs(): string {
  // Fractional unix seconds as string  — never floored integer alone.
  const ms = Date.now();
  const whole = Math.floor(ms / 1000);
  const frac = String(ms % 1000).padStart(3, "0");
  return `${whole}.${frac}`;
}

function truncateSig(sig: string): string {
  if (sig === "") return "∅";
  if (sig.length <= 12) return sig;
  return `${sig.slice(0, 8)}…${sig.slice(-4)}`;
}
