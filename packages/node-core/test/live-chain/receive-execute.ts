// Live RECEIVE_EXTERNAL authorized-execute harness.
//
// Offline-first coordination over injected seams. Follows the receive flow
// end-to-end for one authorized fractional external receive. Real gateway/DB/vault/payer
// adapters are wired by the live runner; unit tests inject in-memory fakes. Hard caps and
// abort policy come from the preflight surface (receive-preflight.ts).
//
// Governing:
// 13
//   The one-in-flight-per-wallet and byte-exact signing rules, 4, 5
//
// Invariants this module enforces structurally:
//   - Exactly ONE submit per attempt (the never-blind-retry rule) — never blind-retried.
//   - Receiver lease acquired BEFORE the RECEIVE_T0 formation read (step 2→3).
//   - Arm happens once; code released only after arm commit.
//   - Candidate intake validates against receiver_T0.S0 (never P0).
//   - Step-2 signed only after STEP2_PREIMAGE_PERSISTED.
//   - Landing proof is an independent fresh receiver-head read — never gateway status:true
//     from the submit acknowledgement (C-09).
//   - A terminal head that does not NAME our attempt is never an invariant breach
//     The receiver pubkey is a public address and the receiver lease is a
//     node-side lock, so a second external inbound can bury a real landing between our
//     submit and the terminal read. Identity is anchored by forward-walking `step_2` from
//     our own attempt through the oracle (`proveReceiveLanding`) — never read off
//     the head, never assumed by position. A positive walk is a landing; every fault is
//     INDETERMINATE; neither is a breach and neither proves non-landing. A head that DOES
//     name our attempt keeps every determinate breach it had.
//   - Private keys never appear on this surface (the key-custody rule) — only signer / payer seams.

import { createHash } from "node:crypto";

import { buildReceiveTransferCode } from "../../src/protocol/receive-transfer-code.js";
import { parseEd25519Signature, parseWalletPublicKey } from "../../src/protocol/scalars.js";
import {
  addZkz,
  parsePositiveZkzAmount,
  parseZkzBalance,
  subtractZkz,
} from "../../src/protocol/amounts.js";
import type { LandingProofOutcome } from "../../src/protocol/reconcile/landing-proof.js";
import { type WalletStateProjection } from "../../src/protocol/wallet-role.js";
import { verifyDetachedEd25519 } from "../../src/reporting/ed25519.js";
import type { ParsedSettledTransaction } from "../../src/verifier/gateway-envelope.js";
import {
  proveReceiveLanding,
  type ReadFreshHead,
} from "../../src/verifier/landing-path-oracle.js";
import {
  verifySettledTransaction,
  type TransactionVerifyVerdict,
} from "../../src/verifier/transaction-verify.js";

import {
  receiveAbortActionFor,
  receiveExternalAbortCriteria,
  RECEIVE_CODE_TTL_DEFAULT_SECS,
  type ReceiveAbortAction,
  type ReceiveAbortTrigger,
} from "./receive-abort-criteria.js";
import {
  DEFAULT_RECEIVE_AMOUNT,
  RECEIVE_AMOUNT_HARD_CAP,
  runReceiveExternalPreflight,
  type ReceiveExternalPlan,
  type ReceivePreflightProbe,
  type ReceivePreflightReport,
} from "./receive-preflight.js";
import type { RunnerLock, RunnerLockHandle } from "./runner-lock.js";
import { compareAmounts, type Amount, type DualControlAuthorization } from "./types.js";

export { DEFAULT_RECEIVE_AMOUNT, RECEIVE_AMOUNT_HARD_CAP, RECEIVE_CODE_TTL_DEFAULT_SECS };

// ─── Observation / formation evidence ────────────────────────────────────────

export type ReceiveObservationRole =
  | "RECEIVE_T0"
  | "RECEIVE_SENDER_PREFLIGHT"
  | "RECEIVE_TERMINAL_CHECK";

export interface ReceiveObservation {
  readonly role: ReceiveObservationRole;
  readonly publicKey: string;
  readonly observationId: string;
  readonly projection: WalletStateProjection;
  readonly rawResponseSha256: string;
  readonly rawResponseByteLength: number;
}

/** Persisted formation + arm material (key-free). */
export interface ReceiveFormationRecord {
  readonly attemptNo: 1;
  readonly receiverT0: ReceiveObservation;
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
  readonly expiryUnixTimeSecs: string;
  readonly receiveMessage: string;
  readonly anchor: string;
  readonly discriminator: string;
  readonly armedAt: string;
  readonly codeReleasedAt: string;
}

/** Candidate intake + co-sign material. */
export interface ReceiveCandidateRecord {
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  readonly step1Signature: string;
  readonly step2PreimageText: string;
  readonly step2Signature: string;
  readonly settledTransactionText: string;
  readonly settledTransactionSha256: string;
  readonly senderPreflight: ReceiveObservation;
  /**
   * Which receiver-head field the candidate was actually compared against — derived from
   * the comparison, not asserted. The receiver link requires S0; a "P0" here would be evidence
   * of a breach, not a formatting choice.
   */
  readonly receiverLinkComparedTo: "S0" | "P0";
}

export type ReceiveSubmitOutcomeKind = "ACK" | "REJECT" | "AMBIGUOUS";

export interface ReceiveSubmitEvidence {
  readonly outcome: ReceiveSubmitOutcomeKind;
  readonly submitCallCount: number;
  readonly detail: string;
  readonly rawResponseSha256: string | null;
  readonly rawResponseByteLength: number | null;
  readonly gatewayStatusCode: number | null;
}

/** Independent fresh receiver-head read. Never relayed from the submit ack. */
export interface ReceiveLandingObservation {
  readonly publicKey: string;
  readonly observationId: string;
  readonly step2Signature: string;
  readonly balanceAfter: Amount;
  readonly balanceDeltaMatchesAmount: boolean;
  readonly predecessorMatchesT0S0: boolean;
  readonly settledTextMatchesPersisted: boolean;
  readonly rawResponseSha256: string;
  readonly rawResponseByteLength: number;
  readonly observedAtIso: string;
}

/**
 * Independent landing predicates — shared by live + offline adapters.
 *
 * No OR dilations. Every flag is a strict equality:
 *   settledTextMatchesPersisted ⇔ observed settled bytes === persisted settled bytes
 *                                 AND observed step_2_signature === persisted step_2
 *   predecessorMatchesT0S0      ⇔ observed head P === receiver T0.S0
 *                                 (genesis: both empty string; never skip via S===step2)
 *   balanceDeltaMatchesAmount   ⇔ observed B === B0 + amount
 *
 * Returns null only when no head is present. Callers may still choose null when
 * settled bytes are absent (not yet visible) vs returning false flags (escalate).
 */
export interface ReceiveLandingPredicateInput {
  readonly headPresent: boolean;
  readonly observedSettledTransactionText: string;
  readonly persistedSettledTransactionText: string;
  readonly observedStep2Signature: string;
  readonly persistedStep2Signature: string;
  readonly observedP: string;
  readonly receiverT0S0: string;
  readonly observedB: Amount;
  readonly receiverT0B0: Amount;
  readonly amount: Amount;
}

export interface ReceiveLandingPredicateFlags {
  readonly settledTextMatchesPersisted: boolean;
  readonly predecessorMatchesT0S0: boolean;
  readonly balanceDeltaMatchesAmount: boolean;
  readonly allMatch: boolean;
}

export function evaluateReceiveLandingPredicates(
  input: ReceiveLandingPredicateInput,
): ReceiveLandingPredicateFlags | null {
  if (!input.headPresent) return null;
  const settledTextMatchesPersisted =
    input.observedSettledTransactionText === input.persistedSettledTransactionText &&
    input.observedStep2Signature === input.persistedStep2Signature &&
    input.persistedSettledTransactionText.length > 0 &&
    input.persistedStep2Signature.length > 0;
  // Strict P-link — genesis is both ""; never treat S===step2 or empty T0 as a free pass.
  const predecessorMatchesT0S0 = input.observedP === input.receiverT0S0;
  const expectedB = String(
    addZkz(parseZkzBalance(input.receiverT0B0), parsePositiveZkzAmount(input.amount)),
  );
  const balanceDeltaMatchesAmount = input.observedB === expectedB;
  return {
    settledTextMatchesPersisted,
    predecessorMatchesT0S0,
    balanceDeltaMatchesAmount,
    allMatch:
      settledTextMatchesPersisted &&
      predecessorMatchesT0S0 &&
      balanceDeltaMatchesAmount,
  };
}

export interface ReceiveRowCounts {
  /** MUST be 1: one RECEIVER lease for this operation. */
  readonly receiverLeases: number;
  /** MUST be 1: one arm acknowledgement. */
  readonly armAcknowledgements: number;
  /** MUST be 1: one candidate at STEP1_SIGNATURE_PERSISTED. */
  readonly candidates: number;
  /** MUST be 1: one step-2 preimage. */
  readonly step2Preimages: number;
  /** MUST be 1: one step-2 signature / completed body. */
  readonly step2Signatures: number;
  /** MUST be 1: one submit decision. */
  readonly submitDecisions: number;
  /** MUST be 1: one gateway submit attempt. */
  readonly gatewaySubmitAttempts: number;
}

export type ReceiveExecuteDisposition =
  | "LANDED_VERIFIED"
  /**
   * A POSITIVE landing whose body is no longer the head, proven by the
   * any-depth complete-path walk (`LANDED_COMPLETE_PATH`, depth >= 1). The receiver pubkey
   * is a public address and the receiver lease is a node-side lock, so a second external
   * inbound can advance the head between our submit and the terminal read. That burial is a
   * landing, never an invariant breach.
   */
  | "LANDED_BURIED_COMPLETE_PATH"
  /**
   * The landing read failed, was anomalous, gapped, or contradicted
   * itself. Neither landed nor not-landed: has no generic PROVEN_NOT_LANDED oracle, so
   * this authorizes no rebuild, no resubmit and no lease release. Distinct from
   * ESCALATE_INVARIANT_BREACH, which stays reserved for determinate breaches.
   */
  | "LANDING_INDETERMINATE"
  | "HOLD_RECEIVER_LEASE_AND_RECONCILE"
  | "ESCALATE_INVARIANT_BREACH"
  | "PREFLIGHT_NOT_READY"
  | "ABORTED_BEFORE_SUBMIT"
  | "SUBMIT_REJECTED";

export interface ReceiveExecuteEvidenceBundle {
  readonly attemptId: string;
  readonly operationId: string;
  readonly plan: ReceiveExternalPlan | null;
  readonly disposition: ReceiveExecuteDisposition;
  readonly abortAction: ReceiveAbortAction | null;
  readonly abortTrigger: ReceiveAbortTrigger | null;
  /**
   * True only when the receiver lease was held before the RECEIVE_T0 formation read
   * (before step 3).
   */
  readonly leaseHeldBeforeT0Read: boolean;
  /** Monotone count of gated observe-seam calls (T0 + sender preflight + terminal). */
  readonly gatewayReadCount: number;
  /**
   * Measured, not asserted: the node DOES submit for RECEIVE_EXTERNAL (unlike
   * SEND_EXTERNAL), so this is true only once the submit seam has actually been called.
   * Both flags are derived from submitCallCount so an abort before submit, or a second
   * submit, drives them false — a literal `true` here would be unfalsifiable evidence.
   */
  readonly nodeSubmitSeamExercised: boolean;
  readonly singleSubmitOnly: boolean;
  readonly formation: ReceiveFormationRecord | null;
  readonly candidate: ReceiveCandidateRecord | null;
  readonly submit: ReceiveSubmitEvidence | null;
  readonly landing: ReceiveLandingObservation | null;
  /**
   * The landing-walk outcome, present only when the terminal head did
   * not name our attempt and path evidence was available to walk. A positive proof carries
   * its depth; a `PROOF_INCOMPLETE` carries the fault that made it INDETERMINATE.
   */
  readonly landingProof: LandingProofOutcome | null;
  readonly rowCounts: ReceiveRowCounts | null;
  readonly trail: readonly string[];
  readonly preflight: ReceivePreflightReport | null;
}

export interface ReceiveExecuteResult {
  readonly ok: boolean;
  readonly evidence: ReceiveExecuteEvidenceBundle;
  readonly runnerLockHandle: RunnerLockHandle | null;
}

// ─── Injected seams ──────────────────────────────────────────────────────────

export interface HeldReceiveLease {
  readonly walletId: string;
  readonly operationId: string;
  readonly leaseEpoch: bigint;
  readonly role: "RECEIVER";
  readonly lifecycle: "ACTIVE";
}

export interface ReceiveLeaseSeam {
  /**
   * Acquire RECEIVER lease BEFORE the T0 read. Throws when busy
   * (the one-in-flight-per-wallet rule); caller must NOT mint another operation.
   */
  acquireReceiverLease(input: {
    readonly operationId: string;
    readonly receiverWalletId: string;
  }): Promise<HeldReceiveLease>;
}

/**
 * The evidence the any-depth complete-path landing walk needs
 * when the terminal head no longer names our attempt.
 *
 * Supplying evidence never asserts a landing. Every body here is untrusted until
 * `proveReceiveLanding` reverifies it from exact signed bytes, checks the per-hop
 * `P(T[i]) == S(T[i-1])` backlink, and anchors the last hop on a live confirm-read. The
 * node cannot hand this module a "landed" flag; only the walk decides. `expectedBody` in
 * particular is the seam's CLAIM about which body was ours — the coordinator binds it back
 * to the bytes this run persisted before the walk is allowed to mean anything.
 */
export interface ReceiveLandingPathEvidence {
  /** Receiver T0 body, or null only for a genesis baseline. */
  readonly t0Body: ParsedSettledTransaction | null;
  /** The seam's claim of OUR attempt's retained body — the node-completed step 2. */
  readonly expectedBody: ParsedSettledTransaction;
  /**
   * T_expected+1 … T_head in chain order. Empty asserts our attempt is itself the head,
   * which the walk still has to prove against the fresh read.
   */
  readonly successorBodies: readonly ParsedSettledTransaction[];
  /** Live confirm-read of the authoritative receiver head; the oracle calls it twice. */
  readonly readFreshHead: ReadFreshHead;
}

export interface ReceiveObserveSeam {
  /** Step 1. */
  observeVerified(input: {
    readonly publicKey: string;
    readonly role: ReceiveObservationRole;
  }): Promise<ReceiveObservation>;

  /**
   * INDEPENDENT fresh receiver-head read. Returns null when the
   * completed transaction carrying the persisted settled text is not yet visible.
   * Never a guess, never the submit acknowledgement.
   *
   * This read anchors on the HEAD. A head that does not carry the persisted material is
   * therefore not evidence of non-landing — see `collectReceiverLandingPath`.
   */
  observeReceiverLanding(input: {
    readonly publicKey: string;
    readonly persistedSettledTransactionText: string;
    readonly persistedStep2Signature: string;
    readonly receiverT0S0: string;
    readonly receiverT0B0: Amount;
    readonly amount: Amount;
  }): Promise<ReceiveLandingObservation | null>;

  /**
   * Retained bodies from our own attempt FORWARD to the current
   * head, so a buried landing can be anchored by walking `step_2` rather than by assuming
   * our attempt still sits at the head.
   *
   * Optional: a node that retained nothing to walk omits it or returns null, and the run
   * settles on HOLD_RECEIVER_LEASE_AND_RECONCILE / LANDING_INDETERMINATE — never on an
   * invariant breach. The two inputs are lookup keys naming which attempt to walk; they are
   * not a claim the seam may echo back, because the coordinator rebinds whatever body it
   * returns against these exact persisted bytes.
   */
  collectReceiverLandingPath?(input: {
    readonly publicKey: string;
    readonly persistedSettledTransactionText: string;
    readonly persistedStep2Signature: string;
  }): Promise<ReceiveLandingPathEvidence | null>;
}

/**
 * Arm barrier. The independent consumer verifies T0 in its own trust domain
 * and arms once; only after commit is the withheld code released.
 */
export interface ReceiveArmSeam {
  armOnce(input: {
    readonly operationId: string;
    readonly receiverPubkey: string;
    readonly nodeT0: ReceiveObservation;
    readonly transferCodeText: string;
  }): Promise<{
    readonly armedAt: string;
    readonly codeReleasedAt: string;
    readonly releasedTransferCodeText: string;
  }>;
}

/**
 * Signing seam — vault/HSM behind the receiver lease. Never sees a private key on
 * this surface (the key-custody rule). Signs exact preimageText bytes (the byte-exact signing rule).
 */
export interface ReceiveSignerSeam {
  signStep2(input: {
    readonly walletId: string;
    readonly operationId: string;
    readonly leaseEpoch: bigint;
    readonly step2PreimageId: string;
    readonly preimageText: string;
  }): Promise<string>;
}

export interface ReceivePersistSeam {
  /** Admit CREATED row when preflight was clean-start. */
  admitOperation(input: {
    readonly operationId: string;
    readonly amount: Amount;
    readonly receiverWalletId: string;
    readonly externalPayerAddress: string;
    readonly anchor: string;
    readonly afterLanding: "HOLD";
  }): Promise<void>;

  /** Persist withheld code + expected artifact; CREATED → READY. */
  persistFormation(input: {
    readonly operationId: string;
    readonly receiverWalletId: string;
    readonly leaseEpoch: bigint;
    readonly t0ObservationId: string;
    readonly transferCodeText: string;
    readonly transferCodeSha256: string;
    readonly expiryUnixTimeSecs: string;
    readonly receiveMessage: string;
    readonly anchor: string;
  }): Promise<{ readonly statusAfter: "READY" }>;

  /** Candidate + step-2 preimage (pre-sign). */
  persistCandidateAndStep2Preimage(input: {
    readonly operationId: string;
    readonly innerPreimageText: string;
    readonly innerSha256: string;
    readonly step1Signature: string;
    readonly step2PreimageText: string;
    readonly step2PreimageSha256: string;
    readonly senderObservationId: string;
  }): Promise<{
    readonly step2PreimageId: string;
    /**
     * The payer step-1 bytes READ BACK out of the row just written, never
     * echoed from the input. Revalidating the in-memory candidate would only re-check
     * constants step 3 already accepted, so that branch could never fail; the receiver
     * is about to sign over what storage actually holds, so that is what must be
     * revalidated.
     */
    readonly persistedInnerPreimageText: string;
    readonly persistedStep1Signature: string;
  }>;

  /** Step-2 signature + completed body + initial submit decision. */
  persistSignedAndSubmitDecision(input: {
    readonly operationId: string;
    readonly step2PreimageId: string;
    readonly step2Signature: string;
    readonly settledTransactionText: string;
    readonly settledTransactionSha256: string;
  }): Promise<{ readonly submitDecisionId: string }>;

  /** Record the single submit attempt outcome (never a second). */
  recordSubmitAttempt(input: {
    readonly operationId: string;
    readonly submitDecisionId: string;
    readonly outcome: ReceiveSubmitOutcomeKind;
    readonly detail: string;
  }): Promise<void>;

  countRows(operationId: string): Promise<ReceiveRowCounts>;
}

export interface ReceiveSubmitSeam {
  /**
   * Invoke gateway submit EXACTLY ONCE. Implementations must not
   * retry internally (the never-blind-retry rule).
   */
  submitOnce(input: {
    readonly operationId: string;
    readonly attemptNo: 1;
    readonly settledTransactionText: string;
    readonly submitDecisionId: string;
  }): Promise<{
    readonly outcome: ReceiveSubmitOutcomeKind;
    readonly detail: string;
    readonly rawResponseSha256: string | null;
    readonly rawResponseByteLength: number | null;
    readonly gatewayStatusCode: number | null;
  }>;
}

/**
 * The independently controlled external payer. Holds its own key, builds and
 * signs step 1 from the released transfer code + its current head. NOT the node.
 */
export interface ExternalPayerSeam {
  buildAndSignStep1(input: {
    readonly transferCodeText: string;
    readonly receiverT0: WalletStateProjection;
    readonly amount: Amount;
    readonly receiverPubkey: string;
    readonly expiryUnixTimeSecs: string;
    readonly receiveMessage: string;
  }): Promise<{
    readonly innerPreimageText: string;
    readonly step1Signature: string;
    readonly payerPubkey: string;
  }>;
}

export interface ReceiveExecuteDeps {
  readonly leases: ReceiveLeaseSeam;
  readonly observe: ReceiveObserveSeam;
  readonly arm: ReceiveArmSeam;
  readonly signer: ReceiveSignerSeam;
  readonly persist: ReceivePersistSeam;
  readonly submit: ReceiveSubmitSeam;
  readonly payer: ExternalPayerSeam;
  /** Node clock in ms. Defaults to Date.now(). */
  readonly nodeClockMs?: () => number;
}

export interface ReceiveExecuteInput {
  readonly attemptId: string;
  readonly operationId: string;
  readonly receiverWalletId: string;
  readonly receiverPubkey: string;
  readonly externalPayerAddress: string;
  readonly amount: Amount;
  readonly authorization: DualControlAuthorization;
  readonly runnerLock: RunnerLock;
  readonly runnerHolderId: string;
  readonly preflightProbe: ReceivePreflightProbe;
  readonly amountCeiling?: Amount;
  /** Opaque receive anchor (A.2 alphabet). Default: attempt-bound short id. */
  readonly anchor?: string;
  /**
   * When true (default), refuse to run if preflight is not ready.
   */
  readonly requirePreflight?: boolean;
  /**
   * Test-only: force a RECEIVE_T0 observe before lease acquisition so the gate reddens.
   * Live runner must leave this unset/false.
   */
  readonly forceT0ObserveBeforeLease?: boolean;
}

// ─── Internals ───────────────────────────────────────────────────────────────

function trailPush(trail: string[], line: string): void {
  trail.push(line);
}

function truncateSig(sig: string): string {
  if (sig === "") return "∅";
  if (sig.length <= 12) return sig;
  return `${sig.slice(0, 8)}…${sig.slice(-4)}`;
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// Ed25519 over the EXACT captured inner bytes, under the SplitChain padded
// base64url key/signature encoding. No new crypto: the canonical grammar gate is the
// frozen protocol scalar parser, and the verification is the existing detached primitive.
// Unparseable key or signature bytes fail closed before any crypto call, and a verify
// exception is a failure, never a throw into the ceremony.
function verifyStep1Signature(
  innerPreimageText: string,
  step1KeyPublic: string,
  step1Signature: string,
): boolean {
  let canonicalKey: string;
  let canonicalSignature: string;
  try {
    canonicalKey = parseWalletPublicKey(step1KeyPublic);
    canonicalSignature = parseEd25519Signature(step1Signature);
  } catch {
    return false;
  }
  return verifyDetachedEd25519({
    publicKeyBytes: Buffer.from(canonicalKey, "base64url"),
    preimageText: innerPreimageText,
    signatureBytes: Buffer.from(canonicalSignature, "base64url"),
  });
}

/**
 * Execute one authorized live RECEIVE_EXTERNAL.
 *
 * Sequence:
 *   1. Preflight; admit CREATED if clean-start.
 *   2. Acquire RECEIVER lease BEFORE T0 read; observe RECEIVE_T0; form code +
 *      expected artifact; CREATED → READY (code withheld).
 *   3. Arm once; release exact code only after arm commit.
 *   4. External payer builds/signs step 1; node intakes candidate (S0 link),
 *      persists step-2 preimage, signs step 2, submits EXACTLY once.
 *   5. Independent fresh receiver-head read; prove landing (not ack-only). When
 *      that head does not NAME our attempt, the any-depth complete-path walk
 *      decides: positive → LANDED_VERIFIED / LANDED_BURIED_COMPLETE_PATH, fault →
 *      LANDING_INDETERMINATE. A head that DOES name our attempt keeps every
 *      determinate breach it had.
 *
 * Never re-signs, never re-forms, never blind-retries submit (the never-blind-retry rule).
 */
export async function executeAuthorizedReceiveExternal(
  deps: ReceiveExecuteDeps,
  input: ReceiveExecuteInput,
): Promise<ReceiveExecuteResult> {
  const trail: string[] = [];
  const abortCriteria = receiveExternalAbortCriteria();
  trailPush(
    trail,
    `abort policy ${abortCriteria.policyId}: singleSubmitOnly=${abortCriteria.singleSubmitOnly}; ` +
      `codeTtlDefault=${abortCriteria.codeTtlDefaultSecs}s; blindRetryForbidden=true`,
  );

  let leaseHeldBeforeT0Read = false;
  let gatewayReadCount = 0;
  let formation: ReceiveFormationRecord | null = null;
  let candidate: ReceiveCandidateRecord | null = null;
  let submitEv: ReceiveSubmitEvidence | null = null;
  let landing: ReceiveLandingObservation | null = null;
  let landingProof: LandingProofOutcome | null = null;
  let rowCounts: ReceiveRowCounts | null = null;
  let plan: ReceiveExternalPlan | null = null;
  let preflight: ReceivePreflightReport | null = null;
  let runnerLockHandle: RunnerLockHandle | null = null;
  let submitCallCount = 0;
  let t0ObservedBeforeLease = false;

  const finish = (
    ok: boolean,
    disposition: ReceiveExecuteDisposition,
    trigger: ReceiveAbortTrigger | null,
  ): ReceiveExecuteResult => {
    const rule = trigger !== null ? receiveAbortActionFor(trigger) : null;
    return {
      ok,
      runnerLockHandle,
      evidence: {
        attemptId: input.attemptId,
        operationId: input.operationId,
        plan,
        disposition,
        abortAction: rule?.action ?? null,
        abortTrigger: trigger,
        leaseHeldBeforeT0Read,
        gatewayReadCount,
        nodeSubmitSeamExercised: submitCallCount > 0,
        singleSubmitOnly: submitCallCount === 1,
        formation,
        candidate,
        submit: submitEv,
        landing,
        landingProof,
        rowCounts,
        trail: [...trail],
        preflight,
      },
    };
  };

  // ── preflight ────────────────────────────────────────────
  preflight = await runReceiveExternalPreflight(input.preflightProbe, {
    attemptId: input.attemptId,
    operationId: input.operationId,
    receiverWalletId: input.receiverWalletId,
    externalPayerAddress: input.externalPayerAddress,
    amount: input.amount,
    authorization: input.authorization,
    amountCeiling: input.amountCeiling,
    runnerLock: input.runnerLock,
    runnerHolderId: input.runnerHolderId,
  });
  runnerLockHandle = preflight.runnerLockHandle;

  if (input.requirePreflight !== false && !preflight.ready) {
    trailPush(trail, "preflight not ready — refusing execute");
    for (const c of preflight.checks.filter((x) => !x.ok)) {
      trailPush(trail, `  fail ${c.id}: ${c.detail}`);
    }
    return finish(false, "PREFLIGHT_NOT_READY", null);
  }

  // hard cap, on the REQUESTED amount and before the plan is resolved. Preflight
  // caps too, so on the default path this can never be the first refusal; it is placed
  // here because `requirePreflight: false` is the one path that reaches execution with
  // preflight's cap check skipped, and that is the path this must still stop.
  try {
    if (compareAmounts(input.amount, RECEIVE_AMOUNT_HARD_CAP) > 0) {
      trailPush(trail, `amount ${input.amount} exceeds hard cap ${RECEIVE_AMOUNT_HARD_CAP}`);
      return finish(false, "ABORTED_BEFORE_SUBMIT", null);
    }
  } catch (err) {
    trailPush(trail, describe(err));
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  plan = preflight.plan;
  if (plan === null) {
    trailPush(trail, "preflight ready but plan null — refuse");
    return finish(false, "PREFLIGHT_NOT_READY", null);
  }
  trailPush(
    trail,
    `preflight ready; amount=${plan.amount} receiver=${plan.receiverWalletId} ` +
      `payer=${plan.externalPayerAddress}`,
  );

  const anchor =
    input.anchor ??
    `receive_execute_${input.operationId.replace(/-/g, "").slice(0, 12)}`;
  const operationId = input.operationId;

  // Admit CREATED when clean-start (preflight plan.operationId may be null).
  try {
    await deps.persist.admitOperation({
      operationId,
      amount: plan.amount,
      receiverWalletId: plan.receiverWalletId,
      externalPayerAddress: plan.externalPayerAddress,
      anchor,
      afterLanding: "HOLD",
    });
    trailPush(trail, `operation admitted CREATED id=${operationId}`);
  } catch (err) {
    trailPush(trail, `admit failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  // ── RECEIVER lease BEFORE T0 read ──────────────────────────
  if (input.forceT0ObserveBeforeLease === true) {
    await deps.observe.observeVerified({
      publicKey: plan.receiverPubkey,
      role: "RECEIVE_T0",
    });
    gatewayReadCount += 1;
    t0ObservedBeforeLease = true;
    trailPush(trail, "TEST_ONLY forceT0ObserveBeforeLease: T0 seam call before lease");
  }

  let lease: HeldReceiveLease;
  try {
    lease = await deps.leases.acquireReceiverLease({
      operationId,
      receiverWalletId: plan.receiverWalletId,
    });
  } catch (err) {
    trailPush(trail, `receiver lease unavailable: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  if (t0ObservedBeforeLease) {
    leaseHeldBeforeT0Read = false;
    trailPush(trail, "INVARIANT: T0 observe preceded receiver lease");
    return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
  }
  leaseHeldBeforeT0Read = true;
  trailPush(
    trail,
    `receiver lease held epoch=${lease.leaseEpoch} before T0 read`,
  );

  // ── OBSERVE RECEIVE_T0 under the lease ─────────────────────
  let receiverT0: ReceiveObservation;
  try {
    receiverT0 = await deps.observe.observeVerified({
      publicKey: plan.receiverPubkey,
      role: "RECEIVE_T0",
    });
    gatewayReadCount += 1;
  } catch (err) {
    trailPush(trail, `RECEIVE_T0 observation failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  trailPush(
    trail,
    `T0 receiver B=${receiverT0.projection.B} S=${truncateSig(receiverT0.projection.S)} ` +
      `raw_sha=${receiverT0.rawResponseSha256.slice(0, 16)}…`,
  );

  // ── form code, persist READY (code withheld) ────────────
  const nowMs = (deps.nodeClockMs ?? Date.now)();
  const formationFloorSecs = Math.floor(nowMs / 1000);
  const expiryUnixTimeSecs = String(formationFloorSecs + RECEIVE_CODE_TTL_DEFAULT_SECS);

  let transferCodeText: string;
  let transferCodeSha256: string;
  let receiveMessage: string;
  try {
    const code = buildReceiveTransferCode({
      receiverPubkey: plan.receiverPubkey,
      amountZkz: plan.amount,
      b0: receiverT0.projection.B,
      discriminator: operationId,
      anchor,
      expiryUnixTimeSecs,
    });
    transferCodeText = code.transferCodeText;
    transferCodeSha256 = code.transferCodeSha256;
    receiveMessage = code.receiveMessage;
  } catch (err) {
    trailPush(trail, `transfer code formation failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  try {
    const ready = await deps.persist.persistFormation({
      operationId,
      receiverWalletId: plan.receiverWalletId,
      leaseEpoch: lease.leaseEpoch,
      t0ObservationId: receiverT0.observationId,
      transferCodeText,
      transferCodeSha256,
      expiryUnixTimeSecs,
      receiveMessage,
      anchor,
    });
    if (ready.statusAfter !== "READY") {
      trailPush(trail, `INVARIANT: status after formation = ${ready.statusAfter}`);
      return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
    }
  } catch (err) {
    trailPush(trail, `formation persist failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  trailPush(
    trail,
    `CREATED→READY code withheld sha=${transferCodeSha256.slice(0, 16)}… ` +
      `expiry=${expiryUnixTimeSecs} msg=${receiveMessage}`,
  );

  // ── arm once; release code only after commit ──────────────────────
  let armResult: {
    armedAt: string;
    codeReleasedAt: string;
    releasedTransferCodeText: string;
  };
  try {
    armResult = await deps.arm.armOnce({
      operationId,
      receiverPubkey: plan.receiverPubkey,
      nodeT0: receiverT0,
      transferCodeText,
    });
  } catch (err) {
    trailPush(trail, `arm failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  if (armResult.releasedTransferCodeText !== transferCodeText) {
    trailPush(trail, "INVARIANT: released code bytes differ from persisted withheld code");
    return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
  }
  formation = {
    attemptNo: 1,
    receiverT0,
    transferCodeText,
    transferCodeSha256,
    expiryUnixTimeSecs,
    receiveMessage,
    anchor,
    discriminator: operationId,
    armedAt: armResult.armedAt,
    codeReleasedAt: armResult.codeReleasedAt,
  };
  trailPush(trail, `armed once; code released (${transferCodeText.length}B)`);

  // ── external payer builds + signs step 1 ──────────────────────────
  let payerStep1: {
    innerPreimageText: string;
    step1Signature: string;
    payerPubkey: string;
  };
  try {
    payerStep1 = await deps.payer.buildAndSignStep1({
      transferCodeText,
      receiverT0: receiverT0.projection,
      amount: plan.amount,
      receiverPubkey: plan.receiverPubkey,
      expiryUnixTimeSecs,
      receiveMessage,
    });
  } catch (err) {
    trailPush(trail, `payer step-1 failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  // `payerStep1.payerPubkey` is deliberately NOT checked and NOT used. It is an adjacent
  // seam field that says nothing about what was signed; the authorized-payer fact is pinned
  // at step 3 (`step_1_key_public__base64urlsafe === plan.externalPayerAddress`) from
  // INSIDE the signed bytes, and the sender-preflight observe below reads the plan address
  // for the same reason. A guard over the seam field would only re-assert a value the seam
  // chose, so it is removed rather than tested.
  trailPush(
    trail,
    `payer step-1 captured inner_sha=${sha256Hex(payerStep1.innerPreimageText).slice(0, 16)}… ` +
      `sig=${truncateSig(payerStep1.step1Signature)}`,
  );

  // Parse captured inner for local economic checks BEFORE sender preflight (cheap first).
  let parsedInner: {
    previous_step_2_state_signature: string;
    previous_step_1_state_signature: string;
    step_2_state: { amount: string };
    step_1_state: { amount: string };
    step_2_key_public__base64urlsafe: string;
    step_1_key_public__base64urlsafe: string;
    message?: string;
    expiry__unix_time_secs?: string;
  };
  try {
    // `JSON.parse` succeeds on "null", "42" and '"text"' as readily as on an object, and
    // every field read below would then dereference a non-object OUTSIDE this try — a
    // TypeError that escapes the ceremony instead of refusing it, stranding the runner lock
    // the caller must release. The shape check belongs here, inside the same try, so a
    // parseable-but-wrong-shaped inner takes the ordinary refusal path like every other
    // rejection. (Spelling the idiom out in prose would inflate the census count, which reads
    // the raw source text — so it is named only by the code below.)
    const raw: unknown = JSON.parse(payerStep1.innerPreimageText);
    if (raw === null || typeof raw !== "object") {
      trailPush(trail, `inner is not a JSON object: ${raw === null ? "null" : typeof raw}`);
      return finish(false, "ABORTED_BEFORE_SUBMIT", null);
    }
    parsedInner = raw as typeof parsedInner;
  } catch (err) {
    trailPush(trail, `inner parse failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  // Receiver link vs S0 (never P0). The projection field is named ONCE: the
  // comparison, the trail line and the persisted `receiverLinkComparedTo` all read this one
  // binding, so flipping the binding to "P" flips the printed label with it — which the S0
  // label assertion catches (mutant F3 `receiverLinkSource → P`). What naming it once does
  // NOT buy: replacing the derived label with a literal "S0" while the comparison stays on
  // S is unobservable, because both readings of the binding agree. This removes the drift
  // between comparison and evidence; it does not make the label independently falsifiable.
  const receiverLinkSource: "S" | "P" = "S";
  const receiverLinkComparedTo = `${receiverLinkSource}0` as const;
  if (parsedInner.previous_step_2_state_signature !== receiverT0.projection[receiverLinkSource]) {
    trailPush(
      trail,
      "RECEIVER_LINK_MISMATCH: previous_step_2_state_signature ≠ receiver_T0.S0",
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  // Retained for the landing check below: the receiver balance this operation must
  // produce. Empty until computed, so a landing check that somehow runs first fails closed.
  let expectedReceiverB1 = "";
  try {
    const expectedB1 = addZkz(
      parseZkzBalance(receiverT0.projection.B),
      parsePositiveZkzAmount(plan.amount),
    );
    expectedReceiverB1 = String(expectedB1);
    if (String(parsedInner.step_2_state.amount) !== String(expectedB1)) {
      trailPush(
        trail,
        `receiver delta mismatch: step_2.amount=${parsedInner.step_2_state.amount} ` +
          `expected B0+amount=${expectedB1}`,
      );
      return finish(false, "ABORTED_BEFORE_SUBMIT", null);
    }
  } catch (err) {
    trailPush(trail, `receiver delta check failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  if (parsedInner.step_2_key_public__base64urlsafe !== plan.receiverPubkey) {
    trailPush(trail, "WRONG_KEY_ROLE: step_2 key is not the reserved receiver");
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  // Exact key roles, expiry, message, and the payer's step-1 Ed25519
  // signature over the EXACT captured inner text. The signing key is the one carried
  // INSIDE the signed bytes; `payerStep1.payerPubkey` is an adjacent seam field that
  // says nothing about what was actually signed, so it is never the verification key.
  if (parsedInner.step_1_key_public__base64urlsafe !== plan.externalPayerAddress) {
    trailPush(
      trail,
      `WRONG_KEY_ROLE: step_1 key ${parsedInner.step_1_key_public__base64urlsafe} ` +
        `is not the authorized external payer ${plan.externalPayerAddress}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  if (parsedInner.expiry__unix_time_secs !== expiryUnixTimeSecs) {
    trailPush(
      trail,
      `EXPIRY_MISMATCH: inner expiry=${String(parsedInner.expiry__unix_time_secs)} ` +
        `≠ armed expiry=${expiryUnixTimeSecs}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  if (parsedInner.message !== receiveMessage) {
    trailPush(
      trail,
      `MESSAGE_MISMATCH: inner message=${String(parsedInner.message)} ≠ formed ${receiveMessage}`,
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  if (
    !verifyStep1Signature(
      payerStep1.innerPreimageText,
      parsedInner.step_1_key_public__base64urlsafe,
      payerStep1.step1Signature,
    )
  ) {
    trailPush(
      trail,
      "STEP1_SIGNATURE_INVALID: step-1 signature does not verify over the captured inner " +
        "under the inner's own step_1 key",
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  trailPush(trail, "step-1 key role + expiry + message + Ed25519 signature verified");
  // Byte-exact re-stringify check: JSON.stringify(parsed) must equal captured.
  if (JSON.stringify(parsedInner) !== payerStep1.innerPreimageText) {
    trailPush(trail, "inner re-serialize diverged from captured preimage (the byte-exact signing rule)");
    return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
  }
  trailPush(trail, `receiver link + delta ok (compared_to=${receiverLinkComparedTo}, never P0)`);

  // Sender preflight observe.
  let senderPreflight: ReceiveObservation;
  try {
    senderPreflight = await deps.observe.observeVerified({
      // The wallet whose head is observed is the one the payer SIGNED for (step 3
      // pinned it to plan.externalPayerAddress above), never the adjacent seam field.
      publicKey: plan.externalPayerAddress,
      role: "RECEIVE_SENDER_PREFLIGHT",
    });
    gatewayReadCount += 1;
  } catch (err) {
    trailPush(trail, `sender preflight failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  if (parsedInner.previous_step_1_state_signature !== senderPreflight.projection.S) {
    trailPush(trail, "SENDER_PREFLIGHT_LINK_MISMATCH");
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  try {
    const expectedSenderRemain = subtractZkz(
      parseZkzBalance(senderPreflight.projection.B),
      parsePositiveZkzAmount(plan.amount),
    );
    if (String(parsedInner.step_1_state.amount) !== String(expectedSenderRemain)) {
      trailPush(
        trail,
        `sender delta mismatch: step_1.amount=${parsedInner.step_1_state.amount} ` +
          `expected B-amount=${expectedSenderRemain}`,
      );
      return finish(false, "ABORTED_BEFORE_SUBMIT", null);
    }
  } catch (err) {
    trailPush(trail, `sender delta check failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  trailPush(
    trail,
    `sender preflight B=${senderPreflight.projection.B} S=${truncateSig(senderPreflight.projection.S)}`,
  );

  // Persist candidate + step-2 preimage BEFORE signing.
  // Build step-2 preimage from exact captured inner text + step-1 sig (template splice).
  const step1SigJson = JSON.stringify(payerStep1.step1Signature);
  const step2PreimageText =
    '{"inner":' + payerStep1.innerPreimageText + ',"step_1_signature":' + step1SigJson + "}";
  const step2PreimageSha256 = sha256Hex(step2PreimageText);
  const innerSha256 = sha256Hex(payerStep1.innerPreimageText);

  let step2PreimageId: string;
  let persistedInnerPreimageText: string;
  let persistedStep1Signature: string;
  try {
    const persisted = await deps.persist.persistCandidateAndStep2Preimage({
      operationId,
      innerPreimageText: payerStep1.innerPreimageText,
      innerSha256,
      step1Signature: payerStep1.step1Signature,
      step2PreimageText,
      step2PreimageSha256,
      senderObservationId: senderPreflight.observationId,
    });
    step2PreimageId = persisted.step2PreimageId;
    persistedInnerPreimageText = persisted.persistedInnerPreimageText;
    persistedStep1Signature = persisted.persistedStep1Signature;
  } catch (err) {
    trailPush(trail, `candidate/step2-preimage persist failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  trailPush(trail, `STEP1_SIGNATURE_PERSISTED + STEP2_PREIMAGE_PERSISTED id=${step2PreimageId}`);

  // Revalidate the PERSISTED payer step-1 signature against that exact
  // text, before the receiver's key signs anything spliced from it. Both operands come
  // back out of storage: re-verifying the in-memory candidate would re-check constants
  // step 3 already accepted and could not fail.
  //
  // The two checks run in this order because each is then reachable on its own. Storage
  // that mangles the bytes breaks the signature and stops at the verify; storage that
  // hands back a different — but genuinely payer-signed — candidate verifies fine and is
  // stopped only by the identity check. Identity-first would make the verify dead code.
  if (
    !verifyStep1Signature(
      persistedInnerPreimageText,
      parsedInner.step_1_key_public__base64urlsafe,
      persistedStep1Signature,
    )
  ) {
    trailPush(trail, "STEP1_SIGNATURE_INVALID on post-persist revalidation");
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }
  if (
    persistedInnerPreimageText !== payerStep1.innerPreimageText ||
    persistedStep1Signature !== payerStep1.step1Signature
  ) {
    trailPush(
      trail,
      "STEP1_PERSIST_ROUNDTRIP_MISMATCH: read-back ≠ validated candidate",
    );
    return finish(false, "ABORTED_BEFORE_SUBMIT", null);
  }

  // SIGN step 2 over persisted preimage only.
  let step2Signature: string;
  try {
    step2Signature = await deps.signer.signStep2({
      walletId: plan.receiverWalletId,
      operationId,
      leaseEpoch: lease.leaseEpoch,
      step2PreimageId,
      preimageText: step2PreimageText,
    });
    parseEd25519Signature(step2Signature);
  } catch (err) {
    trailPush(trail, `step-2 sign failed: ${describe(err)}`);
    return finish(false, "HOLD_RECEIVER_LEASE_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }

  // Settled body via template splice from the same exact bytes (the byte-exact signing rule).
  const settledTransactionText =
    '{"inner":' +
    payerStep1.innerPreimageText +
    ',"step_1_signature":' +
    step1SigJson +
    ',"step_2_signature":' +
    JSON.stringify(step2Signature) +
    "}";
  const settledTransactionSha256 = sha256Hex(settledTransactionText);

  let submitDecisionId: string;
  try {
    const signed = await deps.persist.persistSignedAndSubmitDecision({
      operationId,
      step2PreimageId,
      step2Signature,
      settledTransactionText,
      settledTransactionSha256,
    });
    submitDecisionId = signed.submitDecisionId;
  } catch (err) {
    trailPush(trail, `signed+submit-decision persist failed: ${describe(err)}`);
    return finish(false, "HOLD_RECEIVER_LEASE_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }
  trailPush(
    trail,
    `STEP2_SIGNATURE_PERSISTED step_2=${truncateSig(step2Signature)} ` +
      `settled_sha=${settledTransactionSha256.slice(0, 16)}…`,
  );

  candidate = {
    innerPreimageText: payerStep1.innerPreimageText,
    innerSha256,
    step1Signature: payerStep1.step1Signature,
    step2PreimageText,
    step2Signature,
    settledTransactionText,
    settledTransactionSha256,
    senderPreflight,
    receiverLinkComparedTo,
  };

  // ── SINGLE submit (never again) ───────────────────────────
  let submitOutcome: ReceiveSubmitOutcomeKind;
  let submitDetail: string;
  let submitRawSha: string | null = null;
  let submitRawLen: number | null = null;
  let submitStatus: number | null = null;
  try {
    submitCallCount += 1;
    const resp = await deps.submit.submitOnce({
      operationId,
      attemptNo: 1,
      settledTransactionText,
      submitDecisionId,
    });
    submitOutcome = resp.outcome;
    submitDetail = resp.detail;
    submitRawSha = resp.rawResponseSha256;
    submitRawLen = resp.rawResponseByteLength;
    submitStatus = resp.gatewayStatusCode;
  } catch (err) {
    // Transport throw = ambiguous; do NOT resubmit (the never-blind-retry rule).
    submitOutcome = "AMBIGUOUS";
    submitDetail = describe(err);
  }
  // No `submitCallCount !== 1` guard here: the counter is incremented at the top of the try
  // above and nothing between there and this point can write it, so the branch was
  // unreachable — an invariant that can never fire is evidence of nothing.
  // The real single-submit invariants remain: the increment-before-call ordering (a transport
  // throw still forbids a retry), `singleSubmitOnly = submitCallCount === 1`, the row-count
  // ceremony check below, and the DB's UNIQUE (operation_id, attempt_no).
  submitEv = {
    outcome: submitOutcome,
    submitCallCount,
    detail: submitDetail,
    rawResponseSha256: submitRawSha,
    rawResponseByteLength: submitRawLen,
    gatewayStatusCode: submitStatus,
  };
  try {
    await deps.persist.recordSubmitAttempt({
      operationId,
      submitDecisionId,
      outcome: submitOutcome,
      detail: submitDetail,
    });
  } catch (err) {
    trailPush(trail, `record submit attempt failed: ${describe(err)}`);
  }
  trailPush(trail, `submit once → ${submitOutcome}: ${submitDetail.slice(0, 200)}`);

  // Row counts
  try {
    rowCounts = await deps.persist.countRows(operationId);
  } catch (err) {
    trailPush(trail, `row-count read failed: ${describe(err)}`);
    return finish(false, "HOLD_RECEIVER_LEASE_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }
  const countsOk =
    rowCounts.receiverLeases === 1 &&
    rowCounts.armAcknowledgements === 1 &&
    rowCounts.candidates === 1 &&
    rowCounts.step2Preimages === 1 &&
    rowCounts.step2Signatures === 1 &&
    rowCounts.submitDecisions === 1 &&
    rowCounts.gatewaySubmitAttempts === 1;
  trailPush(
    trail,
    `rows leases=${rowCounts.receiverLeases} arms=${rowCounts.armAcknowledgements} ` +
      `candidates=${rowCounts.candidates} step2_pre=${rowCounts.step2Preimages} ` +
      `step2_sig=${rowCounts.step2Signatures} submit_decisions=${rowCounts.submitDecisions} ` +
      `gateway_submit_attempts=${rowCounts.gatewaySubmitAttempts}`,
  );
  if (!countsOk) {
    trailPush(trail, "INVARIANT: row counts violate single-shot ceremony");
    return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
  }

  if (submitOutcome === "REJECT") {
    return finish(false, "SUBMIT_REJECTED", "SUBMIT_REJECTED");
  }
  if (submitOutcome === "AMBIGUOUS") {
    return finish(false, "HOLD_RECEIVER_LEASE_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }

  // ── independent fresh receiver-head read ──────────────────────────
  try {
    landing = await deps.observe.observeReceiverLanding({
      publicKey: plan.receiverPubkey,
      persistedSettledTransactionText: settledTransactionText,
      persistedStep2Signature: step2Signature,
      receiverT0S0: receiverT0.projection.S,
      receiverT0B0: receiverT0.projection.B,
      amount: plan.amount,
    });
    gatewayReadCount += 1;
  } catch (err) {
    trailPush(trail, `landing observation threw: ${describe(err)}`);
    return finish(false, "HOLD_RECEIVER_LEASE_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }
  // Split on IDENTITY first, because only identity decides whether the remaining
  // predicates are determinate at all.
  //
  // `settledTextMatchesPersisted` is the identity predicate: it is true exactly when the
  // head carries OUR settled bytes and OUR step-2 signature. When it holds, the head IS our
  // attempt, so a failing balance or predecessor is a genuine, cryptographically determinate
  // contradiction about a body we know is ours — every one of those escalations is preserved
  // verbatim below. When it does NOT hold, the head simply names a different transaction,
  // which is a read outcome and proves nothing about whether we landed.
  if (landing !== null && landing.settledTextMatchesPersisted) {
    if (!landing.balanceDeltaMatchesAmount || !landing.predecessorMatchesT0S0) {
      trailPush(
        trail,
        `landing predicates failed settled=${landing.settledTextMatchesPersisted} ` +
          `delta=${landing.balanceDeltaMatchesAmount} pred=${landing.predecessorMatchesT0S0}`,
      );
      return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
    }
    // The flags above are computed by the observe seam. Bind the two operands the seam also
    // reports back to what this coordinator persisted, so three true flags asserted over
    // somebody else's head are still caught here rather than trusted.
    if (
      landing.step2Signature !== step2Signature ||
      landing.balanceAfter !== expectedReceiverB1
    ) {
      trailPush(
        trail,
        `LANDING_OPERAND_MISMATCH: observed step_2=${truncateSig(landing.step2Signature)} ` +
          `B=${landing.balanceAfter}; persisted step_2=${truncateSig(step2Signature)} ` +
          `expected B=${expectedReceiverB1}`,
      );
      return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
    }
    trailPush(
      trail,
      `LANDED_VERIFIED step_2=${truncateSig(landing.step2Signature)} ` +
        `receiver B: ${receiverT0.projection.B} → ${landing.balanceAfter}`,
    );
    return finish(true, "LANDED_VERIFIED", "LANDED_VERIFIED");
  }

  // ── the head does not name our attempt ──────────────────
  //
  // The receiver pubkey is a public address and the receiver lease is a node-side
  // lock, so nothing stops a second external inbound from advancing the head between our
  // submit and this read and burying a landing that really happened. OBS keeps REJECTED
  // for a cryptographically determinate mismatch and sends every read failure / anomaly /
  // gap / regression to INDETERMINATE; adds that a head reached from our attempt by a
  // verified complete path is a POSITIVE landing, and that there is no generic
  // PROVEN_NOT_LANDED oracle.
  //
  // So: anchor by forward-walking `step_2` from our own attempt to the head. Never read
  // identity off the fresh head, never assume our attempt is still the head, and never
  // escalate a landing that did happen as an invariant breach.
  let pathEvidence: ReceiveLandingPathEvidence | null = null;
  const collectPath = deps.observe.collectReceiverLandingPath;
  if (collectPath !== undefined) {
    // Gated like every other observe-seam call. Counted BEFORE the await so a read that
    // throws cannot escape the counter; the oracle's two confirm-reads inside
    // `readFreshHead` are inner polls of this one seam call and are counted once here.
    gatewayReadCount += 1;
    try {
      pathEvidence = await collectPath.call(deps.observe, {
        publicKey: plan.receiverPubkey,
        persistedSettledTransactionText: settledTransactionText,
        persistedStep2Signature: step2Signature,
      });
    } catch (err) {
      trailPush(trail, `landing-path evidence read threw: ${describe(err)}`);
    }
  }

  if (pathEvidence === null) {
    if (landing === null) {
      trailPush(trail, "no completed transaction observed yet — hold + reconcile");
      return finish(false, "HOLD_RECEIVER_LEASE_AND_RECONCILE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
    }
    trailPush(
      trail,
      `observed head does not carry the persisted material ` +
        `(settled=${landing.settledTextMatchesPersisted} ` +
        `delta=${landing.balanceDeltaMatchesAmount} pred=${landing.predecessorMatchesT0S0}) ` +
        `and no path evidence was retained — INDETERMINATE; non-landing NOT proven`,
    );
    return finish(false, "LANDING_INDETERMINATE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }

  // "the expected transaction's exact full body is
  // ALREADY RETAINED and both signatures reverify." The seam chooses which chain segment the
  // walk runs on, so its `expectedBody` is untrusted evidence like every other body on the
  // path. `proveReceiveLanding` reverifies signatures, per-hop `P == S`, fresh-head anchoring
  // and the economic delta against T0 — and a DIFFERENT inbound of the same amount to the
  // same receiver satisfies every one of them, because `unix_time_secs` and the payer are
  // free. Believing such a body would settle THIS operation and release the receiver lease on
  // somebody else's transaction — the one-in-flight-per-wallet rule's exact hazard. So bind the returned body to
  // the attempt THIS run formed, before the walk is allowed to mean anything.
  //
  // Unlike SEND, the node co-signs step 2 here, so it retains the COMPLETE settled body —
  // the binding is therefore the whole body, byte-for-byte, not just its two operands. The
  // comparison uses the verifier's own reconstruction (`completedTransactionText`, built from
  // the exact signed preimage bytes) against the exact text this run persisted. Never a fresh
  // hand-rolled re-serialization of the parsed inner (the byte-exact signing rule).
  // The text compare is the whole binding, and it strictly subsumes the verdict check:
  // `completedTransactionText` exists only on the VERIFIED arm, so nothing that fails
  // reverification can satisfy it. Deleting the verdict operand therefore reddens no test —
  // by construction, not by an untested guard. SEND needed two operands because it
  // retains no whole body; here the node co-signs step 2, so one byte-exact compare dominates.
  //
  // `expectedBody` is untrusted seam evidence (see ReceiveLandingPathEvidence). A
  // body with no well-formed `inner` throws inside narrowSplitChainInner (Object.keys on
  // undefined) rather than returning a verdict. Without this catch the TypeError escapes
  // executeAuthorizedReceiveExternal, finish() never runs, and runnerLockHandle strands —
  // the sole unwrapped seam interaction in an otherwise fail-closed envelope. Same shape as
  // the collectPath and proveReceiveLanding catches above/below.
  let expectedVerified: TransactionVerifyVerdict;
  try {
    expectedVerified = verifySettledTransaction(pathEvidence.expectedBody, plan.receiverPubkey);
  } catch (err) {
    trailPush(
      trail,
      `landing-path expectedBody verify threw: ${describe(err)} — INDETERMINATE`,
    );
    return finish(false, "LANDING_INDETERMINATE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }
  const expectedBodyIsOurAttempt =
    expectedVerified.verdict === "VERIFIED" &&
    expectedVerified.completedTransactionText === settledTransactionText;
  if (!expectedBodyIsOurAttempt) {
    trailPush(
      trail,
      `landing-path evidence names a body that is not our attempt ` +
        `(verdict=${expectedVerified.verdict} ` +
        `observed_sha=${
          expectedVerified.verdict === "VERIFIED"
            ? expectedVerified.completedTransactionSha256.slice(0, 16)
            : "n/a"
        }… persisted_sha=${settledTransactionSha256.slice(0, 16)}…) — INDETERMINATE; ` +
        `neither landing nor non-landing proven`,
    );
    return finish(false, "LANDING_INDETERMINATE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }

  try {
    landingProof = await proveReceiveLanding(
      {
        walletPubkeyBase64Urlsafe: plan.receiverPubkey,
        t0Body: pathEvidence.t0Body,
        expectedBody: pathEvidence.expectedBody,
        successorBodies: pathEvidence.successorBodies,
        operation: { amountZkz: plan.amount, receiverPubkey: plan.receiverPubkey },
      },
      pathEvidence.readFreshHead,
    );
  } catch (err) {
    trailPush(trail, `landing walk threw: ${describe(err)} — INDETERMINATE`);
    return finish(false, "LANDING_INDETERMINATE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }

  if (landingProof.kind === "PROOF_INCOMPLETE") {
    trailPush(
      trail,
      `landing walk incomplete (${landingProof.fault}) over ` +
        `${pathEvidence.successorBodies.length} supplied successor(s) — INDETERMINATE; ` +
        `non-landing NOT proven`,
    );
    return finish(false, "LANDING_INDETERMINATE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }
  if (landingProof.kind === "LANDED_EXACT") {
    // `observeReceiverLanding` returns null when the head does not carry the persisted
    // material (its seam contract). A NON-null observation that reached here says the head is
    // NOT our attempt; a fresh read claiming our attempt IS the head contradicts it, and
    // heads only advance. routes "anomaly, contradictory wallet path" to INDETERMINATE —
    // not to a positive landing. Only the no-observation case is a plain late landing.
    if (landing !== null) {
      trailPush(
        trail,
        `landing walk LANDED_EXACT contradicts the head read that did not carry our attempt ` +
          `(settled=${landing.settledTextMatchesPersisted}) — contradictory wallet path, ` +
          `INDETERMINATE`,
      );
      return finish(false, "LANDING_INDETERMINATE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
    }
    trailPush(trail, "landing walk LANDED_EXACT depth=0 — our attempt is the current head");
    return finish(true, "LANDED_VERIFIED", "LANDED_VERIFIED");
  }
  if (landingProof.kind !== "LANDED_COMPLETE_PATH") {
    // frozen outcome type supersedes landing-proof.ts (see its header). A member
    // added there must not become a positive landing by falling through this branch.
    const unhandled: never = landingProof;
    trailPush(trail, `unknown landing proof kind ${JSON.stringify(unhandled)} — INDETERMINATE`);
    return finish(false, "LANDING_INDETERMINATE", "SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
  }
  trailPush(
    trail,
    `landing walk LANDED_COMPLETE_PATH depth=${landingProof.depth} — our attempt landed ` +
      `and was buried by ${landingProof.depth} later transaction(s); ` +
      `expected_body_sha=${landingProof.expectedBodySha256.slice(0, 16)}…`,
  );
  return finish(true, "LANDED_BURIED_COMPLETE_PATH", "LANDED_VERIFIED");
}
