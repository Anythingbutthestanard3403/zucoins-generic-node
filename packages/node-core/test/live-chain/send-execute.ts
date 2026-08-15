// Live SEND_EXTERNAL authorized-execute harness.
//
// Offline-first coordination over injected seams. Follows the external-send flow
// end-to-end for one authorized fractional external send. Real gateway/DB/vault/recipient
// adapters are wired by the live runner; unit tests inject in-memory fakes. Hard caps and
// abort policy come from the preflight surface (send-preflight.ts).
//
// Governing:
// 13
// 10, 13
//   The one-in-flight-per-wallet and byte-exact signing rules, 4, 5
//
// Invariants this module enforces structurally:
//   - `SendExecuteDeps` HAS NO SUBMIT SEAM.: "SEND_EXTERNAL has no node submit
//     function in its type graph." The external recipient submits; the node cannot.
//     There is no flag, adapter slot, or configuration that could re-arm it here.
//   - Source lease acquired BEFORE formation gateway reads. Proven by an
//     authoritative gateway-read gate: every node `freshGatewayBalance` preflight call AND
//     every `SendObserveSeam` invocation (seam-call count, not every inner
//     `get_transaction__v1` poll) increments one monotone counter; the lease mark fails
//     closed if any non-preflight (formation/landing) seam call preceded it. Recipient-owned
//     head/submit I/O is outside this gate. Preflight balance probes are expected before the
//     lease and are counted + trail-recorded — they do not feed signed bytes. The property
//     asserted is: no formation observe seam call before the source lease, and no gated
//     gateway seam call between lease acquisition and formation observes.
//   - Exactly ONE TOTP approval consumption, ONE sign intent, ONE step-1 partial per
//     operation (R-08) — asserted against the persist seam's row counts.
//   - No signing call before the durable sign intent commits.
//   - Re-delivery returns the byte-identical persisted transfer code — never re-signs,
//     never re-forms ("same logical send with different chain-link fields"
//     is forbidden).
//   - Ambiguity after delivery → HOLD_SOURCE_LEASE_AND_RECONCILE; never a second partial.
//   - A terminal head that does not name our attempt is NEVER an invariant breach
//     The source pubkey is a public address and the source lease is a node-side
//     lock, so an external inbound can bury a real landing between the recipient's submit
//     and the terminal read. Landing identity is anchored by forward-walking `step_2` from
//     our own attempt to the head through the oracle (`proveSendLanding`) — never
//     read off rows[0], never assumed by position. A positive walk is a landing; every
//     fault is INDETERMINATE; neither is a breach and neither proves non-landing.
//   - Private keys never appear on this surface (the key-custody rule) — only a signer seam.

import { constructSendInner } from "../../src/protocol/send-inner.js";
import { captureSendBaselines } from "../../src/protocol/send-baseline.js";
import {
  buildSendTransferCodeText,
  hashTransferCodeText,
} from "../../src/protocol/send-transfer-code.js";
import { parseEd25519Signature } from "../../src/protocol/scalars.js";
import type { LandingProofOutcome } from "../../src/protocol/reconcile/landing-proof.js";
import type { WalletStateProjection } from "../../src/protocol/wallet-role.js";
import type { ParsedSettledTransaction } from "../../src/verifier/gateway-envelope.js";
import { proveSendLanding, type ReadFreshHead } from "../../src/verifier/landing-path-oracle.js";
import { verifySettledTransaction } from "../../src/verifier/transaction-verify.js";

import {
  SEND_REDEMPTION_WINDOW_SECS,
  sendAbortActionFor,
  sendExternalAbortCriteria,
  type SendAbortAction,
  type SendAbortTrigger,
} from "./send-abort-criteria.js";
import {
  DEFAULT_SEND_AMOUNT,
  SEND_AMOUNT_HARD_CAP,
  runSendExternalPreflight,
  type SendExternalPlan,
  type SendPreflightProbe,
  type SendPreflightReport,
} from "./send-preflight.js";
import type { RunnerLock, RunnerLockHandle } from "./runner-lock.js";
import { compareAmounts, type Amount, type DualControlAuthorization } from "./types.js";

export { DEFAULT_SEND_AMOUNT, SEND_AMOUNT_HARD_CAP, SEND_REDEMPTION_WINDOW_SECS };

// ─── Observation / formation evidence ────────────────────────────────────────

/** Observation roles. The destination is an external key with no node lease. */
export type SendObservationRole = "SEND_SOURCE_T0" | "SEND_DESTINATION_FORMATION";

/**
 * One verified observation with its raw pre-parse gateway evidence (02:
 * the complete response body is evidence, captured before any decode).
 */
export interface SendObservation {
  readonly role: SendObservationRole;
  readonly publicKey: string;
  readonly observationId: string;
  readonly projection: WalletStateProjection;
  /** SHA-256 of the exact response bytes, captured pre-parse. */
  readonly rawResponseSha256: string;
  readonly rawResponseByteLength: number;
}

/** Persisted formation material for the operation's ONE sign intent (key-free). */
export interface SendFormationRecord {
  readonly attemptNo: 1;
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  /** Integer-SECONDS string byte-frozen inside the preimage (T2). */
  readonly expiryUnixTimeSecs: string;
  readonly redemptionExpiryAt: string;
  readonly formationUnixTimeSecs: string;
  readonly step1Signature: string;
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
}

/** Row counts read back from the durable store — the arithmetic evidence. */
export interface SendRowCounts {
  readonly totpConsumptions: number;
  readonly signIntents: number;
  readonly partials: number;
  /** MUST be 0: the node has no submit route for SEND_EXTERNAL. */
  readonly submitDecisions: number;
  /** MUST be 0, same reason. */
  readonly gatewaySubmitAttempts: number;
}

/** One delivery of the persisted transfer code. Byte-identical across re-deliveries. */
export interface SendDeliveryRecord {
  readonly deliveryNo: number;
  readonly transferCodeText: string;
  readonly transferCodeSha256: string;
}

/** Independent fresh source-head read. Never relayed by the recipient. */
export interface SendLandingObservation {
  readonly publicKey: string;
  readonly observationId: string;
  readonly step2Signature: string;
  readonly balanceAfter: Amount;
  /** Exact persisted inner text found verbatim in the completed transaction. */
  readonly innerTextMatchesPersisted: boolean;
  readonly step1SignatureMatchesPersisted: boolean;
  readonly rawResponseSha256: string;
  readonly rawResponseByteLength: number;
}

// ─── External recipient outcome (the node is NOT the submitter) ──────────────

export type SendRecipientOutcomeKind =
  | "SUBMITTED"
  | "REFUSED_STALE_DESTINATION"
  | "REFUSED_VERIFICATION_FAILED"
  | "INDETERMINATE";

/**
 * What the independently controlled external recipient did with the transfer code.
 * `rawGatewayResponseBase64` is the recipient's own submit response captured pre-parse —
 * evidence of the exchange, never treated as landing proof.
 */
export interface SendRecipientOutcome {
  readonly kind: SendRecipientOutcomeKind;
  readonly detail: string;
  readonly step2Signature: string | null;
  readonly rawGatewayResponseBase64: string | null;
  readonly rawGatewayResponseSha256: string | null;
  readonly gatewayStatusCode: number | null;
  /** Count of submit calls the RECIPIENT made. The node's own count is structurally 0. */
  readonly recipientSubmitCallCount: number;
}

export type SendExecuteDisposition =
  | "LANDED_VERIFIED"
  /**
   * A POSITIVE landing whose body is no longer the head, proven by
   * the any-depth complete-path walk (`LANDED_COMPLETE_PATH`, depth >= 1). The source
   * pubkey is a public address and the source lease is a node-side lock, so an external
   * inbound can advance the head between the recipient's submit and the terminal read.
   * That burial is a landing, never an invariant breach.
   */
  | "LANDED_BURIED_COMPLETE_PATH"
  /**
   * The landing read failed, was anomalous, gapped, or contradicted
   * itself. Neither landed nor not-landed: has no generic PROVEN_NOT_LANDED oracle,
   * so this authorizes no rebuild, no second partial, and no lease release. Distinct from
   * ESCALATE_INVARIANT_BREACH, which stays reserved for determinate breaches.
   */
  | "LANDING_INDETERMINATE"
  | "AWAITING_REDEMPTION_DELIVERED"
  | "RECIPIENT_REFUSED_STALE_DESTINATION"
  | "HOLD_SOURCE_LEASE_AND_RECONCILE"
  | "ESCALATE_INVARIANT_BREACH"
  | "PREFLIGHT_NOT_READY"
  | "ABORTED_BEFORE_SIGN_INTENT";

export interface SendExecuteEvidenceBundle {
  readonly attemptId: string;
  readonly operationId: string;
  readonly plan: SendExternalPlan | null;
  readonly disposition: SendExecuteDisposition;
  readonly abortAction: SendAbortAction | null;
  readonly abortTrigger: SendAbortTrigger | null;
  /**
   * True only when the source lease was held before any *formation* gateway read
   * Preflight `freshGatewayBalance` reads are expected earlier, are
   * counted in `gatewayReadCount` / `preflightGatewayReadCount`, and do not flip this
   * false — they feed no signed byte. False if a formation/landing observe ran before
   * the lease (the gate fails closed). Renamed from the vacuous identifier
   * to match the gate return.
   */
  readonly leaseHeldBeforeFormationReads: boolean;
  /**
   * Monotone count of gated node seam calls on the execute path: each
   * `freshGatewayBalance` + each `SendObserveSeam` invocation (not inner poll loops,
   * not recipient-owned gateway I/O).
   */
  readonly gatewayReadCount: number;
  /** Subset of `gatewayReadCount` made via the preflight probe's `freshGatewayBalance`. */
  readonly preflightGatewayReadCount: number;
  /** Structural: this harness exposes no node submit seam. Always true. */
  readonly nodeSubmitSeamAbsent: true;
  readonly approval: SendApprovalConsumption | null;
  readonly sourceT0: SendObservation | null;
  readonly destinationFormation: SendObservation | null;
  readonly formation: SendFormationRecord | null;
  readonly deliveries: readonly SendDeliveryRecord[];
  readonly recipient: SendRecipientOutcome | null;
  readonly landing: SendLandingObservation | null;
  /**
   * The landing-walk outcome, present only when the terminal head did
   * not name our attempt and path evidence was available to walk. A positive proof carries
   * its depth; a `PROOF_INCOMPLETE` carries the fault that made it INDETERMINATE.
   */
  readonly landingProof: LandingProofOutcome | null;
  readonly rowCounts: SendRowCounts | null;
  /** Key-free human-readable trail for the evidence packet. */
  readonly trail: readonly string[];
  readonly preflight: SendPreflightReport | null;
}

export interface SendExecuteResult {
  readonly ok: boolean;
  readonly evidence: SendExecuteEvidenceBundle;
  /** Non-null only when the runner lock was acquired and must be released by the caller. */
  readonly runnerLockHandle: RunnerLockHandle | null;
}

// ─── Injected seams (live runner wires real adapters; tests wire fakes) ──────

/** Result: one atomic consumption of nonce + timestep. */
export interface SendApprovalConsumption {
  readonly approvalId: string;
  readonly challengeNonce: string;
  readonly totpTimestep: number;
  readonly statusAfter: "APPROVED";
  /** Consumptions recorded for this operation. MUST be 1 (R-08). */
  readonly totpConsumptionCount: number;
}

export interface SendApprovalSeam {
  /**
   * Steps 4–6. Fetch the exact `zp-send-external-approval-v1` challenge and consume
   * the fresh single-use TOTP, transitioning `CREATED → APPROVED` while consuming the
   * challenge nonce and the TOTP timestep ATOMICALLY in one DB-TX. Implementations MUST
   * fail (not silently re-approve) on a second call for the same operation.
   */
  consumeApprovalOnce(input: {
    readonly operationId: string;
  }): Promise<SendApprovalConsumption>;
}

export interface HeldSendSourceLease {
  readonly walletId: string;
  readonly operationId: string;
  readonly leaseEpoch: bigint;
  readonly role: "SEND_SOURCE";
  readonly lifecycle: "ACTIVE";
}

export interface SendLeaseSeam {
  /**
   * Acquire the source wallet's ACTIVE lease with bounded DB backoff.
   * Throws when the wallet is busy; the caller must NOT mint another operation or consume
   * another approval (the one-in-flight-per-wallet rule).
   */
  acquireSourceLease(input: {
    readonly operationId: string;
    readonly sourceWalletId: string;
  }): Promise<HeldSendSourceLease>;
}

/**
 * The evidence the any-depth complete-path landing walk needs
 * when the terminal head no longer names our attempt.
 *
 * Supplying evidence never asserts a landing. Every body here is untrusted until
 * `proveSendLanding` reverifies it from exact signed bytes, checks the per-hop
 * `P(T[i]) == S(T[i-1])` backlink, and anchors the last hop on a live confirm-read. The
 * node cannot hand this module a "landed" flag; only the walk decides.
 *
 * The walk decides whether a landing happened on the segment it is given; it does NOT decide
 * WHOSE landing it is — the seam picks the segment. So `expectedBody` is additionally bound
 * to the persisted attempt by exact bytes at the call site before the walk runs (the
 * point 1). Nothing here is trusted on the seam's word.
 */
export interface SendLandingPathEvidence {
  /** Source T0 body, or null only for a genesis baseline. */
  readonly t0Body: ParsedSettledTransaction | null;
  /**
   * The exact retained body of OUR attempt — the recipient-completed step 2. Its inner
   * preimage text and step-1 signature MUST byte-match the persisted ones; a body that does
   * not is INDETERMINATE, never a landing.
   */
  readonly expectedBody: ParsedSettledTransaction;
  /**
   * T_expected+1 … T_head in chain order. Empty asserts our attempt is itself the head,
   * which the walk still has to prove against the fresh read.
   */
  readonly successorBodies: readonly ParsedSettledTransaction[];
  /** Live confirm-read of the authoritative source head; the oracle calls it twice. */
  readonly readFreshHead: ReadFreshHead;
}

export interface SendObserveSeam {
  /** Fresh verified observation with raw pre-parse capture. */
  observeVerified(input: {
    readonly publicKey: string;
    readonly role: SendObservationRole;
  }): Promise<SendObservation>;

  /**
   * INDEPENDENT fresh source-head read through the node's own
   * observation path. Returns null when no completed transaction carrying the persisted
   * inner text and step-1 signature is visible yet — never a guess, never the recipient's
   * word (a gateway acknowledgement supplied by the recipient is not
   * landing proof).
   *
   * This read anchors on the HEAD. A head that does not carry the persisted material is
   * therefore not evidence of non-landing — see `collectSourceLandingPath`.
   */
  observeSourceLanding(input: {
    readonly publicKey: string;
    readonly persistedInnerPreimageText: string;
    readonly persistedStep1Signature: string;
  }): Promise<SendLandingObservation | null>;

  /**
   * Retained bodies from our own attempt FORWARD to the
   * current head, so a buried landing can be anchored by walking `step_2` rather than by
   * assuming our attempt sits at `rows[0]`.
   *
   * Optional: a node that retained nothing to walk omits it or returns null, and the run
   * settles on AWAITING_REDEMPTION / LANDING_INDETERMINATE — never on an invariant breach.
   */
  collectSourceLandingPath?(input: {
    readonly publicKey: string;
    readonly persistedInnerPreimageText: string;
    readonly persistedStep1Signature: string;
  }): Promise<SendLandingPathEvidence | null>;
}

/**
 * Signing seam — vault/HSM behind the source lease capability. The harness never sees a
 * private key (the key-custody rule). Signers MUST sign the exact preimageText bytes and nothing
 * else (the byte-exact signing rule); Ed25519 over identical bytes is deterministic, so a repeat call
 * on the same preimage returns the same signature.
 */
export interface SendSignerSeam {
  signStep1(input: {
    readonly walletId: string;
    readonly operationId: string;
    readonly leaseEpoch: bigint;
    readonly innerPreimageId: string;
    readonly preimageText: string;
  }): Promise<string>;
}

export interface SendPersistSeam {
  /**
   * The ONE durable sign intent at the `INNER_PREIMAGE_PERSISTED` boundary.
   * Implementations MUST reject a second sign intent for the same operation.
   * Returns the sign-intent id used as the signer's `innerPreimageId`.
   */
  persistSignIntent(input: {
    readonly operationId: string;
    readonly attemptNo: 1;
    readonly innerPreimageText: string;
    readonly innerSha256: string;
    readonly redemptionExpiryAt: string;
    readonly sourceObservationId: string;
    readonly destinationObservationId: string;
    readonly sourceLeaseEpoch: bigint;
  }): Promise<{ readonly innerPreimageId: string }>;

  /**
   * Persist the deterministic step-1 signature plus the transfer-code
   * text/hash against the one sign intent at the `STEP1_SIGNATURE_PERSISTED` boundary,
   * then transition `APPROVED → AWAITING_REDEMPTION` in the SAME DB-TX. Implementations
   * MUST reject a second partial for the same operation.
   */
  persistStep1AndTransferCode(input: {
    readonly operationId: string;
    readonly innerPreimageId: string;
    readonly step1Signature: string;
    readonly transferCodeText: string;
    readonly transferCodeSha256: string;
  }): Promise<{ readonly statusAfter: "AWAITING_REDEMPTION" }>;

  /** Evidence read-back. Live adapters count real rows keyed by `operation_id`. */
  countRows(operationId: string): Promise<SendRowCounts>;
}

export interface SendDeliverySeam {
  /**
   * Return the EXACT persisted transfer-code text. Re-delivery must
   * return byte-identical bytes and increment only delivery audit counters.
   */
  deliver(input: {
    readonly operationId: string;
    readonly transferCodeText: string;
  }): Promise<SendDeliveryRecord>;
}

/**
 * The independently controlled external recipient. NOT part of the node: it holds
 * its own key, verifies the source signature and inner itself, requires its own current
 * head to match the persisted destination formation baseline, signs exact step 2, and
 * submits. This is the ONLY submit path in the whole module.
 */
export interface ExternalRecipientSeam {
  verifyCoSignAndSubmit(input: {
    readonly transferCodeText: string;
    readonly destinationFormationBaseline: WalletStateProjection;
    readonly expectedDestinationAddress: string;
  }): Promise<SendRecipientOutcome>;
}

/**
 * Execute dependencies. There is deliberately NO `submit` member —
 * "`SEND_EXTERNAL` has no node submit function in its type graph." Adding one would be a
 * compile-visible spec violation, not a configuration mistake.
 */
export interface SendExecuteDeps {
  readonly approval: SendApprovalSeam;
  readonly leases: SendLeaseSeam;
  readonly observe: SendObserveSeam;
  readonly signer: SendSignerSeam;
  readonly persist: SendPersistSeam;
  readonly delivery: SendDeliverySeam;
  readonly recipient: ExternalRecipientSeam;
  /** Node clock in ms at sign-intent formation. Defaults to Date.now(). */
  readonly nodeClockMs?: () => number;
}

export interface SendExecuteInput {
  readonly attemptId: string;
  readonly operationId: string;
  readonly sourceWalletId: string;
  readonly sourcePubkey: string;
  readonly destinationAddress: string;
  readonly amount: Amount;
  readonly authorization: DualControlAuthorization;
  readonly runnerLock: RunnerLock;
  readonly runnerHolderId: string;
  readonly preflightProbe: SendPreflightProbe;
  readonly amountCeiling?: Amount;
  /** Extra re-delivery to prove byte-identical redelivery. Default true. */
  readonly proveRedelivery?: boolean;
  /**
   * Test-only : force one formation `observeVerified` seam call after
   * approval and before source-lease acquisition, so the wired
   * `markLeaseAcquired` → `ESCALATE_INVARIANT_BREACH` path can redden offline.
   * Live runner must leave this unset/false — no second live send.
   */
  readonly forceFormationObserveBeforeLease?: boolean;
  /**
   * When true (default), refuse to run if preflight is not ready. Live runners always
   * leave this true; tests may set false only when injecting a pre-validated plan path.
   */
  readonly requirePreflight?: boolean;
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


// ─── Authoritative gateway-read gate ─────────────────
//
// Every node `freshGatewayBalance` and every `SendObserveSeam` invocation on the
// execute path must pass through this gate (seam-call count). Manual `+= 1` next to a
// call site is not evidence — a wrapper the call has to go through is. Inner polls
// inside a single observe adapter and recipient-owned head/submit I/O are out of scope.
// Preflight balance probes are real gateway reads and are counted; they are allowed
// before the lease. Formation/landing observe seam calls are not.

export type SendGatewayReadKind =
  | "preflight_balance"
  | "SEND_SOURCE_T0"
  | "SEND_DESTINATION_FORMATION"
  | "landing";

export interface SendGatewayReadGateSnapshot {
  readonly total: number;
  readonly preflight: number;
  readonly formation: number;
  readonly landing: number;
  /** Non-preflight reads that fired while the source lease was not yet held. */
  readonly formationOrLandingReadsBeforeLease: number;
  readonly leaseHeld: boolean;
  /** `total` at the moment `markLeaseAcquired` ran; null until then. */
  readonly totalAtLeaseAcquisition: number | null;
  /** `total` at the moment the first formation observe began; null until then. */
  readonly totalAtFormationStart: number | null;
}

export interface SendGatewayReadGate {
  readonly wrapProbe: (probe: SendPreflightProbe) => SendPreflightProbe;
  readonly wrapObserve: (observe: SendObserveSeam) => SendObserveSeam;
  /**
   * Record that the source lease is now held. Returns whether the step 2
   * property holds: no formation/landing gateway read preceded the lease.
   */
  readonly markLeaseAcquired: () => {
    ok: boolean;
    leaseHeldBeforeFormationReads: boolean;
    snapshot: SendGatewayReadGateSnapshot;
  };
  /**
   * Record the formation-observe phase start. Returns whether any gateway read
   * occurred between lease acquisition and this moment (must be none).
   */
  readonly markFormationStart: () => {
    ok: boolean;
    readsBetweenLeaseAndFormation: number;
    snapshot: SendGatewayReadGateSnapshot;
  };
  readonly snapshot: () => SendGatewayReadGateSnapshot;
}

/**
 * Build a fresh gate for one `executeAuthorizedSendExternal` invocation.
 * Exported so offline tests can mutate call order and prove the assertion reddens.
 */
export function createSendGatewayReadGate(): SendGatewayReadGate {
  let total = 0;
  let preflight = 0;
  let formation = 0;
  let landing = 0;
  let formationOrLandingReadsBeforeLease = 0;
  let leaseHeld = false;
  let totalAtLeaseAcquisition: number | null = null;
  let totalAtFormationStart: number | null = null;
  let formationStarted = false;

  const snap = (): SendGatewayReadGateSnapshot => ({
    total,
    preflight,
    formation,
    landing,
    formationOrLandingReadsBeforeLease,
    leaseHeld,
    totalAtLeaseAcquisition,
    totalAtFormationStart,
  });

  const note = (kind: SendGatewayReadKind): void => {
    total += 1;
    if (kind === "preflight_balance") {
      preflight += 1;
      return;
    }
    if (kind === "landing") {
      landing += 1;
    } else {
      formation += 1;
    }
    if (!leaseHeld) {
      formationOrLandingReadsBeforeLease += 1;
    }
  };

  return {
    wrapProbe(probe) {
      return {
        loadSource: (walletId) => probe.loadSource(walletId),
        loadRecipient: (destinationAddress) => probe.loadRecipient(destinationAddress),
        activeLeases: (walletId) => probe.activeLeases(walletId),
        freshGatewayBalance: async (walletId) => {
          note("preflight_balance");
          return probe.freshGatewayBalance(walletId);
        },
        loadOperation: (operationId) => probe.loadOperation(operationId),
        loadApprovalChallenge: (operationId) => probe.loadApprovalChallenge(operationId),
        freshVaultBackup: (notBeforeIso) => probe.freshVaultBackup(notBeforeIso),
      };
    },
    wrapObserve(observe) {
      // The buried-landing path evidence is gateway I/O on the same wallet and
      // must pass the same gate. The oracle's two confirm-reads inside `readFreshHead` are
      // inner polls of this one seam call, counted once here (same rule as observe's own
      // inner poll loop). Bound so the wrapper cannot lose the seam's `this`.
      const collectPath = observe.collectSourceLandingPath?.bind(observe);
      return {
        observeVerified: async (input) => {
          note(input.role);
          return observe.observeVerified(input);
        },
        observeSourceLanding: async (input) => {
          note("landing");
          return observe.observeSourceLanding(input);
        },
        ...(collectPath === undefined
          ? {}
          : {
              collectSourceLandingPath: async (
                input: Parameters<NonNullable<SendObserveSeam["collectSourceLandingPath"]>>[0],
              ) => {
                note("landing");
                return collectPath(input);
              },
            }),
      };
    },
    markLeaseAcquired() {
      const ok = formationOrLandingReadsBeforeLease === 0;
      leaseHeld = true;
      totalAtLeaseAcquisition = total;
      return {
        ok,
        leaseHeldBeforeFormationReads: ok,
        snapshot: snap(),
      };
    },
    markFormationStart() {
      if (totalAtLeaseAcquisition === null) {
        return {
          ok: false,
          readsBetweenLeaseAndFormation: total,
          snapshot: snap(),
        };
      }
      const readsBetweenLeaseAndFormation = total - totalAtLeaseAcquisition;
      totalAtFormationStart = total;
      formationStarted = true;
      void formationStarted;
      return {
        ok: readsBetweenLeaseAndFormation === 0,
        readsBetweenLeaseAndFormation,
        snapshot: snap(),
      };
    },
    snapshot: snap,
  };
}

/**
 * Execute one authorized live SEND_EXTERNAL.
 *
 * Sequence:
 *   1. Preflight, then consume the single-use TOTP approval EXACTLY
 *      once; `CREATED → APPROVED` with nonce + timestep consumed atomically.
 *   2. Claim the approved row, acquire the source lease BEFORE any *formation*
 *      gateway read (preflight balance probes may already have run and are gate-counted),
 *      observe `SEND_SOURCE_T0` and `SEND_DESTINATION_FORMATION`, construct the exact
 *      sender inner, persist the ONE durable sign intent (`INNER_PREIMAGE_PERSISTED`).
 *   3. Sign step 1 deterministically, build the transfer code from the PERSISTED
 *      text + signature without parsing or reserializing either, persist at
 *      `STEP1_SIGNATURE_PERSISTED`, `APPROVED → AWAITING_REDEMPTION`, then deliver.
 *   4. The external recipient verifies, co-signs step 2 and submits. The node
 *      never submits: there is no submit seam on `SendExecuteDeps`.
 *   5. One independent fresh source-head read for landing evidence. When
 *      that head does not name our attempt, the any-depth complete-path walk
 *      decides: positive → LANDED_VERIFIED / LANDED_BURIED_COMPLETE_PATH, fault →
 *      LANDING_INDETERMINATE. Full landing commit / disposition is
 *      handled by send-disposition.
 *
 * Never re-signs, never re-forms, never blind-retries anything (the never-blind-retry rule).
 */
export async function executeAuthorizedSendExternal(
  deps: SendExecuteDeps,
  input: SendExecuteInput,
): Promise<SendExecuteResult> {
  const trail: string[] = [];
  const abortCriteria = sendExternalAbortCriteria();
  trailPush(
    trail,
    `abort policy ${abortCriteria.policyId}: node submit route ABSENT; T2=${SEND_REDEMPTION_WINDOW_SECS}s`,
  );

  let leaseHeldBeforeFormationReads = false;
  let gatewayReadCount = 0;
  let preflightGatewayReadCount = 0;
  const readGate = createSendGatewayReadGate();
  const countingProbe = readGate.wrapProbe(input.preflightProbe);
  const countingObserve = readGate.wrapObserve(deps.observe);
  let approval: SendApprovalConsumption | null = null;
  let sourceT0: SendObservation | null = null;
  let destinationFormation: SendObservation | null = null;
  let formation: SendFormationRecord | null = null;
  let recipient: SendRecipientOutcome | null = null;
  let landing: SendLandingObservation | null = null;
  let landingProof: LandingProofOutcome | null = null;
  let rowCounts: SendRowCounts | null = null;
  const deliveries: SendDeliveryRecord[] = [];
  let plan: SendExternalPlan | null = null;
  let preflight: SendPreflightReport | null = null;
  let runnerLockHandle: RunnerLockHandle | null = null;

  const finish = (
    ok: boolean,
    disposition: SendExecuteDisposition,
    trigger: SendAbortTrigger | null,
  ): SendExecuteResult => {
    const rule = trigger !== null ? sendAbortActionFor(trigger) : null;
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
        leaseHeldBeforeFormationReads,
        gatewayReadCount,
        preflightGatewayReadCount,
        nodeSubmitSeamAbsent: true,
        approval,
        sourceT0,
        destinationFormation,
        formation,
        deliveries: [...deliveries],
        recipient,
        landing,
        landingProof,
        rowCounts,
        trail: [...trail],
        preflight,
      },
    };
  };

  // ── preflight ────────────────────────────────────────────
  preflight = await runSendExternalPreflight(countingProbe, {
    attemptId: input.attemptId,
    operationId: input.operationId,
    sourceWalletId: input.sourceWalletId,
    destinationAddress: input.destinationAddress,
    amount: input.amount,
    authorization: input.authorization,
    amountCeiling: input.amountCeiling,
    runnerLock: input.runnerLock,
    runnerHolderId: input.runnerHolderId,
  });
  runnerLockHandle = preflight.runnerLockHandle;

  {
    const s = readGate.snapshot();
    gatewayReadCount = s.total;
    preflightGatewayReadCount = s.preflight;
  }
  if (input.requirePreflight !== false && !preflight.ready) {
    trailPush(trail, "preflight not ready — refusing execute");
    for (const c of preflight.checks.filter((x) => !x.ok)) {
      trailPush(trail, `  fail ${c.id}: ${c.detail}`);
    }
    if (preflightGatewayReadCount > 0) {
      trailPush(trail, `preflight_gateway_reads=${preflightGatewayReadCount}`);
    }
    return finish(false, "PREFLIGHT_NOT_READY", null);
  }
  plan = preflight.plan;
  if (plan === null) {
    trailPush(trail, "preflight ready but plan null — refuse");
    return finish(false, "PREFLIGHT_NOT_READY", null);
  }
  {
    const s = readGate.snapshot();
    preflightGatewayReadCount = s.preflight;
    gatewayReadCount = s.total;
    trailPush(
      trail,
      `preflight ready; amount=${plan.amount} dest=${plan.destinationAddress}; ` +
        `preflight_gateway_reads=${s.preflight}`,
    );
  }

  // hard cap, defended here even if a test path bypassed preflight.
  try {
    if (compareAmounts(plan.amount, SEND_AMOUNT_HARD_CAP) > 0) {
      trailPush(trail, `amount ${plan.amount} exceeds hard cap ${SEND_AMOUNT_HARD_CAP}`);
      return finish(false, "ABORTED_BEFORE_SIGN_INTENT", null);
    }
  } catch (err) {
    trailPush(trail, describe(err));
    return finish(false, "ABORTED_BEFORE_SIGN_INTENT", null);
  }

  // ── consume the ONE single-use TOTP approval ────────────
  try {
    approval = await deps.approval.consumeApprovalOnce({ operationId: input.operationId });
  } catch (err) {
    trailPush(trail, `approval consumption failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SIGN_INTENT", null);
  }
  if (approval.totpConsumptionCount !== 1) {
    trailPush(
      trail,
      `INVARIANT: totpConsumptionCount=${approval.totpConsumptionCount} (the approval rule requires exactly 1)`,
    );
    return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
  }
  trailPush(trail, `approval consumed once → APPROVED (timestep ${approval.totpTimestep})`);

  // ── source lease BEFORE any *formation* gateway read ───────
  // Preflight may already have performed a balance probe (counted above). Spec
  // concern is formation baselines under the lease — the gate enforces that.
  //
  // Test-only mutation : a formation observe before the lease must
  // fail closed at markLeaseAcquired. Live leaves the flag unset.
  if (input.forceFormationObserveBeforeLease === true) {
    await countingObserve.observeVerified({
      publicKey: plan.sourcePubkey,
      role: "SEND_SOURCE_T0",
    });
    const s = readGate.snapshot();
    gatewayReadCount = s.total;
    preflightGatewayReadCount = s.preflight;
    trailPush(
      trail,
      `TEST_ONLY forceFormationObserveBeforeLease: formation seam calls before lease=` +
        `${s.formationOrLandingReadsBeforeLease}`,
    );
  }
  let lease: HeldSendSourceLease;
  try {
    lease = await deps.leases.acquireSourceLease({
      operationId: input.operationId,
      sourceWalletId: plan.sourceWalletId,
    });
  } catch (err) {
    // Busy source: stay APPROVED, do NOT mint another operation or consume another
    // approval. The approval already consumed stays bound to this row.
    const s = readGate.snapshot();
    gatewayReadCount = s.total;
    preflightGatewayReadCount = s.preflight;
    trailPush(trail, `source lease unavailable: ${describe(err)} — remain APPROVED`);
    return finish(false, "ABORTED_BEFORE_SIGN_INTENT", null);
  }
  {
    const marked = readGate.markLeaseAcquired();
    gatewayReadCount = marked.snapshot.total;
    preflightGatewayReadCount = marked.snapshot.preflight;
    leaseHeldBeforeFormationReads = marked.leaseHeldBeforeFormationReads;
    if (!marked.ok) {
      trailPush(
        trail,
        `INVARIANT: ${marked.snapshot.formationOrLandingReadsBeforeLease} formation/landing ` +
          `gateway read(s) preceded the source lease (total reads=${marked.snapshot.total}, ` +
          `preflight=${marked.snapshot.preflight})`,
      );
      return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
    }
    trailPush(
      trail,
      `source lease held epoch=${lease.leaseEpoch} before formation gateway reads ` +
        `(preflight_gateway_reads=${marked.snapshot.preflight} counted; ` +
        `no formation read precedes lease)`,
    );
  }

  // ── both verified observations under the lease ──────────
  {
    const formed = readGate.markFormationStart();
    gatewayReadCount = formed.snapshot.total;
    if (!formed.ok) {
      trailPush(
        trail,
        `INVARIANT: ${formed.readsBetweenLeaseAndFormation} gateway read(s) between ` +
          `lease acquisition and formation observes`,
      );
      return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
    }
  }
  try {
    sourceT0 = await countingObserve.observeVerified({
      publicKey: plan.sourcePubkey,
      role: "SEND_SOURCE_T0",
    });
    destinationFormation = await countingObserve.observeVerified({
      publicKey: plan.destinationAddress,
      role: "SEND_DESTINATION_FORMATION",
    });
    gatewayReadCount = readGate.snapshot().total;
  } catch (err) {
    gatewayReadCount = readGate.snapshot().total;
    trailPush(trail, `formation observation failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SIGN_INTENT", "FORMATION_REJECTED");
  }
  trailPush(
    trail,
    `T0 source B=${sourceT0.projection.B} raw_sha=${sourceT0.rawResponseSha256.slice(0, 16)}…; ` +
      `dest B=${destinationFormation.projection.B} raw_sha=${destinationFormation.rawResponseSha256.slice(0, 16)}…`,
  );

  // Predicates via the canonical module (verified, sufficient, distinct keys).
  const baseline = captureSendBaselines({
    operationId: input.operationId,
    sourceWalletPublicKey: plan.sourcePubkey,
    destinationAddress: plan.destinationAddress,
    sourceLease: { role: lease.role, lifecycle: lease.lifecycle },
    sourceBaseline: sourceT0.projection,
    destinationBaseline: destinationFormation.projection,
    amountZkz: plan.amount,
    capturedAt: (deps.nodeClockMs ?? Date.now)(),
  });
  if (!baseline.ok) {
    trailPush(trail, `baseline rejected ${baseline.reason}: ${baseline.detail}`);
    return finish(false, "ABORTED_BEFORE_SIGN_INTENT", "FORMATION_REJECTED");
  }

  // ── construct the exact inner, persist the ONE sign intent ──
  let inner: ReturnType<typeof constructSendInner>;
  try {
    inner = constructSendInner({
      capture: baseline.capture,
      nodeClockMs: (deps.nodeClockMs ?? Date.now)(),
    });
  } catch (err) {
    trailPush(trail, `inner construction failed: ${describe(err)}`);
    return finish(false, "ABORTED_BEFORE_SIGN_INTENT", "FORMATION_REJECTED");
  }
  trailPush(
    trail,
    `inner formed sha256=${inner.innerSha256.slice(0, 16)}… ` +
      `expiry=${inner.expiryUnixTimeSecs} (= ${inner.formationUnixTimeSecs}+${SEND_REDEMPTION_WINDOW_SECS})`,
  );

  let innerPreimageId: string;
  try {
    const persisted = await deps.persist.persistSignIntent({
      operationId: input.operationId,
      attemptNo: 1,
      innerPreimageText: inner.innerPreimageText,
      innerSha256: inner.innerSha256,
      redemptionExpiryAt: inner.redemptionExpiryAt,
      sourceObservationId: sourceT0.observationId,
      destinationObservationId: destinationFormation.observationId,
      sourceLeaseEpoch: lease.leaseEpoch,
    });
    innerPreimageId = persisted.innerPreimageId;
  } catch (err) {
    // No signing call has occurred — the no-sign-before-intent rule holds trivially.
    trailPush(trail, `sign-intent persist failed: ${describe(err)} — signer never called`);
    return finish(false, "ABORTED_BEFORE_SIGN_INTENT", "FORMATION_REJECTED");
  }
  trailPush(trail, `INNER_PREIMAGE_PERSISTED sign_intent=${innerPreimageId}`);

  // ── deterministic step 1, transfer code, persist ────────
  let step1Signature: string;
  try {
    step1Signature = await deps.signer.signStep1({
      walletId: plan.sourceWalletId,
      operationId: input.operationId,
      leaseEpoch: lease.leaseEpoch,
      innerPreimageId,
      preimageText: inner.innerPreimageText,
    });
    parseEd25519Signature(step1Signature);
  } catch (err) {
    // Sign intent is durable; recovery is "sign the identical persisted preimage"
    // — never re-form. Nothing was delivered.
    trailPush(trail, `step-1 sign failed after durable sign intent: ${describe(err)}`);
    return finish(false, "HOLD_SOURCE_LEASE_AND_RECONCILE", "PARTIAL_DELIVERED_UNOBSERVED");
  }

  // Built from the PERSISTED inner text and PERSISTED signature by
  // template splicing; buildSendTransferCodeText never parses or reserializes either.
  const transferCodeText = buildSendTransferCodeText(inner.innerPreimageText, step1Signature);
  const transferCodeSha256 = hashTransferCodeText(transferCodeText);

  try {
    const persisted = await deps.persist.persistStep1AndTransferCode({
      operationId: input.operationId,
      innerPreimageId,
      step1Signature,
      transferCodeText,
      transferCodeSha256,
    });
    if (persisted.statusAfter !== "AWAITING_REDEMPTION") {
      trailPush(trail, `INVARIANT: status after partial persist = ${persisted.statusAfter}`);
      return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
    }
  } catch (err) {
    trailPush(trail, `partial persist failed: ${describe(err)} — nothing delivered`);
    return finish(false, "HOLD_SOURCE_LEASE_AND_RECONCILE", "PARTIAL_DELIVERED_UNOBSERVED");
  }

  formation = {
    attemptNo: 1,
    innerPreimageText: inner.innerPreimageText,
    innerSha256: inner.innerSha256,
    expiryUnixTimeSecs: inner.expiryUnixTimeSecs,
    redemptionExpiryAt: inner.redemptionExpiryAt,
    formationUnixTimeSecs: inner.formationUnixTimeSecs,
    step1Signature,
    transferCodeText,
    transferCodeSha256,
  };
  trailPush(
    trail,
    `STEP1_SIGNATURE_PERSISTED → AWAITING_REDEMPTION; step_1=${truncateSig(step1Signature)} ` +
      `code_sha=${transferCodeSha256.slice(0, 16)}…`,
  );

  // ── deliver (and prove re-delivery is byte-identical) ───
  try {
    deliveries.push(
      await deps.delivery.deliver({
        operationId: input.operationId,
        transferCodeText,
      }),
    );
    if (input.proveRedelivery !== false) {
      deliveries.push(
        await deps.delivery.deliver({
          operationId: input.operationId,
          transferCodeText,
        }),
      );
    }
  } catch (err) {
    trailPush(trail, `delivery failed: ${describe(err)} — persisted code remains exact`);
    return finish(false, "HOLD_SOURCE_LEASE_AND_RECONCILE", "PARTIAL_DELIVERED_UNOBSERVED");
  }
  const distinctDelivered = new Set(deliveries.map((d) => d.transferCodeText));
  if (distinctDelivered.size !== 1 || !distinctDelivered.has(transferCodeText)) {
    trailPush(trail, "INVARIANT: re-delivery returned different bytes");
    return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
  }
  trailPush(trail, `delivered ${deliveries.length}× byte-identical (${transferCodeText.length}B)`);

  // ── the EXTERNAL recipient verifies, co-signs step 2, submits ─────
  // The node has no submit route: `deps` carries no submit seam at all.
  try {
    recipient = await deps.recipient.verifyCoSignAndSubmit({
      transferCodeText,
      destinationFormationBaseline: destinationFormation.projection,
      expectedDestinationAddress: plan.destinationAddress,
    });
  } catch (err) {
    trailPush(trail, `recipient path threw: ${describe(err)} — outcome unknown`);
    return finish(false, "HOLD_SOURCE_LEASE_AND_RECONCILE", "PARTIAL_DELIVERED_UNOBSERVED");
  }
  trailPush(
    trail,
    `recipient ${recipient.kind} (submits=${recipient.recipientSubmitCallCount}): ${recipient.detail}`,
  );

  // ── Row-count evidence: one approval, one intent, one partial, zero submits ──
  try {
    rowCounts = await deps.persist.countRows(input.operationId);
  } catch (err) {
    trailPush(trail, `row-count read failed: ${describe(err)}`);
    return finish(false, "HOLD_SOURCE_LEASE_AND_RECONCILE", "PARTIAL_DELIVERED_UNOBSERVED");
  }
  const countsOk =
    rowCounts.totpConsumptions === 1 &&
    rowCounts.signIntents === 1 &&
    rowCounts.partials === 1 &&
    rowCounts.submitDecisions === 0 &&
    rowCounts.gatewaySubmitAttempts === 0;
  trailPush(
    trail,
    `rows totp=${rowCounts.totpConsumptions} intents=${rowCounts.signIntents} ` +
      `partials=${rowCounts.partials} submit_decisions=${rowCounts.submitDecisions} ` +
      `gateway_submit_attempts=${rowCounts.gatewaySubmitAttempts}`,
  );
  if (!countsOk) {
    trailPush(trail, "INVARIANT: row counts violate the one-approval / no-node-submit rule");
    return finish(false, "ESCALATE_INVARIANT_BREACH", "INVARIANT_BREACH");
  }

  if (recipient.kind === "REFUSED_STALE_DESTINATION") {
    // The recipient refusing a stale partial does NOT authorize the node to refresh
    // or re-sign. Hold; a new operation is only possible after safe resolution (09).
    trailPush(trail, "recipient refused stale destination — node must NOT re-sign or refresh");
    return finish(false, "RECIPIENT_REFUSED_STALE_DESTINATION", "PARTIAL_DELIVERED_UNOBSERVED");
  }
  if (recipient.kind !== "SUBMITTED") {
    return finish(false, "HOLD_SOURCE_LEASE_AND_RECONCILE", "PARTIAL_DELIVERED_UNOBSERVED");
  }

  // ── independent fresh source-head read ──────────────────
  try {
    landing = await countingObserve.observeSourceLanding({
      publicKey: plan.sourcePubkey,
      persistedInnerPreimageText: inner.innerPreimageText,
      persistedStep1Signature: step1Signature,
    });
    gatewayReadCount = readGate.snapshot().total;
  } catch (err) {
    gatewayReadCount = readGate.snapshot().total;
    trailPush(trail, `landing observation threw: ${describe(err)}`);
    return finish(false, "HOLD_SOURCE_LEASE_AND_RECONCILE", "PARTIAL_DELIVERED_UNOBSERVED");
  }
  if (
    landing !== null &&
    landing.innerTextMatchesPersisted &&
    landing.step1SignatureMatchesPersisted
  ) {
    trailPush(
      trail,
      `LANDED_VERIFIED step_2=${truncateSig(landing.step2Signature)} ` +
        `source B: ${sourceT0.projection.B} → ${landing.balanceAfter}`,
    );
    return finish(true, "LANDED_VERIFIED", "LANDED_VERIFIED");
  }

  // ── the head does not name our attempt ─────────────────
  //
  // That is a read outcome, not a determinate mismatch. The source pubkey is a
  // public address and the source lease is a node-side lock, so nothing stops an external
  // inbound from advancing the head between the recipient's submit and this read and
  // burying a landing that really happened. OBS keeps REJECTED for a cryptographically
  // determinate mismatch and sends every read failure / anomaly / gap / regression to
  // INDETERMINATE; adds that a head reached from our attempt by a verified complete
  // path is a POSITIVE landing, and that there is no generic PROVEN_NOT_LANDED oracle.
  //
  // So: anchor by forward-walking `step_2` from our own attempt to the head. Never read
  // identity off the fresh head, never assume our attempt sits at rows[0], and never
  // escalate a landing that did happen as an invariant breach.
  let pathEvidence: SendLandingPathEvidence | null = null;
  try {
    pathEvidence =
      (await countingObserve.collectSourceLandingPath?.({
        publicKey: plan.sourcePubkey,
        persistedInnerPreimageText: inner.innerPreimageText,
        persistedStep1Signature: step1Signature,
      })) ?? null;
  } catch (err) {
    trailPush(trail, `landing-path evidence read threw: ${describe(err)}`);
  }
  gatewayReadCount = readGate.snapshot().total;

  if (pathEvidence === null) {
    if (landing === null) {
      trailPush(trail, "no completed transaction observed yet — AWAITING_REDEMPTION stands");
      return finish(false, "AWAITING_REDEMPTION_DELIVERED", "PARTIAL_DELIVERED_UNOBSERVED");
    }
    trailPush(
      trail,
      `observed head does not carry the persisted material ` +
        `(inner=${landing.innerTextMatchesPersisted} step1=${landing.step1SignatureMatchesPersisted}) ` +
        `and no path evidence was retained — INDETERMINATE; non-landing NOT proven`,
    );
    return finish(false, "LANDING_INDETERMINATE", "PARTIAL_DELIVERED_UNOBSERVED");
  }

  // "the expected transaction's exact full body is ALREADY
  // RETAINED and both signatures reverify." The seam chooses which chain segment the walk
  // runs on, so its `expectedBody` is untrusted evidence like every other body on the path.
  // `proveSendLanding` reverifies signatures, per-hop `P == S`, fresh-head anchoring and the
  // economic delta against T0 — and a DIFFERENT step_1 from the same chain-link position
  // satisfies every one of them, because `unix_time_secs` is free. Two such step_1s are
  // the one-in-flight-per-wallet rule's exact hazard: if the other one landed, an unbound walk would report OURS
  // landed and release the source lease on coins that never moved. So bind the returned body
  // to the attempt THIS run formed, before the walk is allowed to mean anything.
  //
  // Same idiom as the production lander (send-completion-lander + landing-path-oracle):
  // reverify, then compare the verifier's own byte-exact reconstruction against the retained
  // bytes. Never a fresh hand-rolled re-serialization of the parsed inner (the byte-exact signing rule).
  // The node never sees the completed body — the recipient co-signs step 2 — so the retained
  // material is exactly the inner preimage text and the step-1 signature it persisted.
  const expectedVerified = verifySettledTransaction(pathEvidence.expectedBody, plan.sourcePubkey);
  const innerMatchesAttempt =
    expectedVerified.verdict === "VERIFIED" &&
    expectedVerified.innerPreimageText === inner.innerPreimageText;
  const step1MatchesAttempt = pathEvidence.expectedBody.step_1_signature === step1Signature;
  if (!innerMatchesAttempt || !step1MatchesAttempt) {
    trailPush(
      trail,
      `landing-path evidence names a body that is not our attempt ` +
        `(inner=${innerMatchesAttempt} step1=${step1MatchesAttempt}) — INDETERMINATE; ` +
        `neither landing nor non-landing proven`,
    );
    return finish(false, "LANDING_INDETERMINATE", "PARTIAL_DELIVERED_UNOBSERVED");
  }

  try {
    landingProof = await proveSendLanding(
      {
        walletPubkeyBase64Urlsafe: plan.sourcePubkey,
        t0Body: pathEvidence.t0Body,
        expectedBody: pathEvidence.expectedBody,
        successorBodies: pathEvidence.successorBodies,
        operation: {
          amountZkz: plan.amount,
          sourcePubkey: plan.sourcePubkey,
          destinationAddress: plan.destinationAddress,
        },
      },
      pathEvidence.readFreshHead,
    );
  } catch (err) {
    trailPush(trail, `landing walk threw: ${describe(err)} — INDETERMINATE`);
    return finish(false, "LANDING_INDETERMINATE", "PARTIAL_DELIVERED_UNOBSERVED");
  }

  if (landingProof.kind === "PROOF_INCOMPLETE") {
    trailPush(
      trail,
      `landing walk incomplete (${landingProof.fault}) over ` +
        `${pathEvidence.successorBodies.length} supplied successor(s) — INDETERMINATE; ` +
        `non-landing NOT proven`,
    );
    return finish(false, "LANDING_INDETERMINATE", "PARTIAL_DELIVERED_UNOBSERVED");
  }
  if (landingProof.kind === "LANDED_EXACT") {
    // `observeSourceLanding` returns null when the head does not carry the persisted material
    // (its seam contract). A NON-null observation whose flags are false says the head is not
    // our attempt; a fresh read that says our attempt IS the head contradicts it, and heads
    // only advance. routes "anomaly, contradictory wallet path" to INDETERMINATE — not
    // to a positive landing. Only the no-observation case is a plain late landing.
    if (landing !== null) {
      trailPush(
        trail,
        `landing walk LANDED_EXACT contradicts the head read that did not carry our attempt ` +
          `(inner=${landing.innerTextMatchesPersisted} step1=${landing.step1SignatureMatchesPersisted}) ` +
          `— contradictory wallet path, INDETERMINATE`,
      );
      return finish(false, "LANDING_INDETERMINATE", "PARTIAL_DELIVERED_UNOBSERVED");
    }
    trailPush(trail, "landing walk LANDED_EXACT depth=0 — our attempt is the current head");
    return finish(true, "LANDED_VERIFIED", "LANDED_VERIFIED");
  }
  if (landingProof.kind !== "LANDED_COMPLETE_PATH") {
    // frozen outcome type supersedes landing-proof.ts (see its header). A member
    // added there must not become a positive landing by falling through this branch.
    const unhandled: never = landingProof;
    trailPush(trail, `unknown landing proof kind ${JSON.stringify(unhandled)} — INDETERMINATE`);
    return finish(false, "LANDING_INDETERMINATE", "PARTIAL_DELIVERED_UNOBSERVED");
  }
  // custody half — "an unknown or unattributed deep successor while the wallet remains
  // actively leased is an invariant/custody breach" — is not engaged here: every hop from our
  // attempt to the head was supplied in exact full-body form, reverified and back-linked, so
  // the deep successor is neither unknown nor unattributed. The clause guards the opposite
  // shape (a head the node cannot connect to its own attempt), which the branches above route
  // to INDETERMINATE. `assessSuccessorCustodyAuthority` cannot be wired here verbatim: an
  // external INBOUND is never "attributed to an in-flight operation", so it would reclassify
  // every buried landing as a breach — the exact misclassification removes. An
  // unattributed *outbound* successor draining the leased source is a real residual and is
  // filed against the oracle's callers (this module and send-completion-lander).
  trailPush(
    trail,
    `landing walk LANDED_COMPLETE_PATH depth=${landingProof.depth} — our attempt landed ` +
      `and was buried by ${landingProof.depth} later transaction(s); ` +
      `expected_body_sha=${landingProof.expectedBodySha256.slice(0, 16)}…`,
  );
  return finish(true, "LANDED_BURIED_COMPLETE_PATH", "LANDED_VERIFIED");
}
