// Recipient-owned completion monitor for SEND_EXTERNAL. Governing:
// 5
// ("Recipient completion" / "Landing verification");
// (safe automatic actions while awaiting redemption);
// (observation-service-only
// gateway reads — no operation worker may call the gateway client directly);
// landing-path oracle (no generic PROVEN_NOT_LANDED verdict).
//
// The node never submits SEND_EXTERNAL (.1 / F). Once the signed step-1 partial is
// delivered, the RECIPIENT independently co-signs and submits. This monitor passively
// polls the source wallet's chain lineage (via an observation-service reader, never a
// direct gateway submit surface) for candidate evidence that the recipient completed THIS
// operation. It is strictly observational: no mutation of the send operation, no retry
// of the submit, no lease release, no state-transition authority.
//
// Terminal outcomes (this slice does NOT render a full landing verdict — that is /
// send landing-verify):
// CANDIDATE_MATCH — a path proof bound to this operation's body + source wallet was
// observed, and the candidate completed-tx material byte-matches the persisted
// external_send_partials (inner_sha256 + step_1_signature) with a syntactically valid
// recipient step-2 signature. Feeds for full verification.
// TIMED_OUT — the monitoring window elapsed without a positive candidate match.
// INDETERMINATE — an observation anomaly / proof-incomplete fault / total transport
// exhaustion prevents a match decision.
// INVARIANT_BREACH — custody/lineage breach (unattributed successor under lease,
// REGRESSION / GENESIS_AFTER_HISTORY / SIGNATURE_COLLISION). Preserved as breach
// never downgraded to INDETERMINATE.
//
// None of these outcomes authorize retry, rebuild, resubmit, or lease release (golden
// rule 4 / never-blind-retry submit). TIMED_OUT and INDETERMINATE leave the operation in its current state
// for operator attention; silence is never treated as non-landing.

import { type LandingPathProof } from "../protocol/reconcile/landing-proof.js";
import {
  type PathObservation,
  classifyPathObservation,
} from "../protocol/reconcile/observation-input.js";
import {
  type ReconcileInvariantBreachReason,
  assertUnreachable,
} from "../protocol/reconcile/types.js";

/**
 * Wire-capture digests the observation pipeline may attach to a poll (audit trail only).
 * Deliberately narrower than gateway/capture.GatewayExchangeCapture so this worker stays
 * free of a gateway module dependency (observation-service-only reads).
 */
export interface ObservationWireCapture {
  readonly responseSha256: string;
}

// 86 base64url chars + `==` padding — same surface as proof-body / protocol scalars for
// Ed25519 signatures. Syntactic-only check here; cryptographic verification is.
const PADDED_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}==$/;

export function isSyntacticallyValidStep2Signature(value: string): boolean {
  return typeof value === "string" && PADDED_SIGNATURE_PATTERN.test(value);
}

// The closed terminal outcome for one monitored send.
export type SendCompletionVerdict =
  | {
      readonly kind: "CANDIDATE_MATCH";
      readonly sendAttemptId: string;
      readonly proof: LandingPathProof;
      readonly matchedAt: string;
      readonly candidate: CandidateCompletedTx;
    }
  | {
      readonly kind: "TIMED_OUT";
      readonly sendAttemptId: string;
      readonly pollsExecuted: number;
      readonly windowElapsedMs: number;
    }
  | {
      readonly kind: "INDETERMINATE";
      readonly sendAttemptId: string;
      readonly pollsExecuted: number;
      readonly reason: SendCompletionIndeterminateReason;
    }
  | {
      readonly kind: "INVARIANT_BREACH";
      readonly sendAttemptId: string;
      readonly sourceWalletId: string;
      readonly pollsExecuted: number;
      readonly reason: ReconcileInvariantBreachReason;
    };

export type SendCompletionIndeterminateReason =
  | { readonly source: "OBSERVATION_ANOMALY"; readonly anomaly: string }
  | { readonly source: "LANDING_PROOF_INCOMPLETE"; readonly fault: string }
  | { readonly source: "POLL_TRANSPORT_EXHAUSTED" };

// Persisted operation identity (external_send_partials + source path).
// expectedBodySha256 is the completed-transaction body hash the landing oracle must prove
// for THIS send; transferCodeSha256 is the durable transfer-code identity carried on the
// partial (recorded on every evidence row; also compared when a candidate supplies it).
export interface MonitoredSendDescriptor {
  readonly sendAttemptId: string;
  readonly sourceWalletId: string;
  /** Source wallet pubkey the path proof must name (operation-identity binding). */
  readonly sourceWalletPubkeyBase64Urlsafe: string;
  readonly expectedBodySha256: string;
  readonly transferCodeSha256: string;
  /** external_send_partials.inner_sha256 — byte-compared to the candidate. */
  readonly innerSha256: string;
  /** external_send_partials.step_1_signature — byte-compared to the candidate. */
  readonly step1Signature: string;
}

// Candidate completed-transaction material observed on the source path (pre-filter only).
export interface CandidateCompletedTx {
  readonly innerSha256: string;
  readonly step1Signature: string;
  readonly step2Signature: string;
  /** Optional: when the observed envelope carries a transfer-code digest. */
  readonly transferCodeSha256?: string;
}

// One poll cycle's observation. Callers MUST obtain `observation` via the observation
// service; this module never imports a gateway submit surface.
export interface SendCompletionPollInput {
  readonly descriptor: MonitoredSendDescriptor;
  readonly observation: PathObservation;
  readonly observedAt: string;
  /**
   * Candidate completed-tx fields extracted from the observed successor (when any).
   * Required for CANDIDATE_MATCH — a bare path proof without bound candidate material
   * cannot satisfy F step 2.
   */
  readonly candidate: CandidateCompletedTx | null;
  /**
   * Exact HTTP capture digests from the observation pipeline when the read went to the
   * wire. Null only for pure in-process fixtures.
   */
  readonly capture: ObservationWireCapture | null;
}

// Evidence persisted for audit when the monitor reaches a terminal verdict.
export interface SendCompletionEvidence {
  readonly sendAttemptId: string;
  readonly sourceWalletId: string;
  readonly transferCodeSha256: string;
  readonly expectedBodySha256: string;
  readonly verdict: SendCompletionVerdict;
  readonly evidenceRecordedAt: string;
  readonly pollCount: number;
  /** Last capture digest seen (if any) — raw-bytes audit trail pointer. */
  readonly lastResponseSha256: string | null;
}

export interface CompletionEvidenceRecorder {
  recordCompletionEvidence(evidence: SendCompletionEvidence): Promise<void>;
}

/**
 * Observation-service surface this monitor is allowed to depend on.
 * Implementations must route through the standard observation pipeline
 * (capture exact bytes → hash → parse → …) and must NOT expose submit.
 */
export interface SourcePathObservationService {
  observeSourcePath(input: {
    readonly sourceWalletPubkeyBase64Urlsafe: string;
    readonly expectedBodySha256: string;
  }): Promise<{
    readonly observation: PathObservation;
    readonly observedAt: string;
    readonly candidate: CandidateCompletedTx | null;
    readonly capture: ObservationWireCapture | null;
  }>;
}

/** Build a poll function that always goes through the observation service. */
export function createObservationServicePollFn(
  service: SourcePathObservationService,
): SendCompletionPollFn {
  return async (descriptor) => {
    const result = await service.observeSourcePath({
      sourceWalletPubkeyBase64Urlsafe: descriptor.sourceWalletPubkeyBase64Urlsafe,
      expectedBodySha256: descriptor.expectedBodySha256,
    });
    return {
      descriptor,
      observation: result.observation,
      observedAt: result.observedAt,
      candidate: result.candidate,
      capture: result.capture,
    };
  };
}

/**
 * True only when the path proof is bound to THIS operation's body + source wallet AND
 * the candidate completed-tx material byte-matches the persisted partial with a
 * syntactically valid recipient step-2 signature.
 */
export function isOperationBoundCandidateMatch(
  descriptor: MonitoredSendDescriptor,
  proof: LandingPathProof,
  candidate: CandidateCompletedTx | null,
): candidate is CandidateCompletedTx {
  if (candidate === null) return false;
  if (proof.expectedBodySha256 !== descriptor.expectedBodySha256) return false;
  if (proof.walletPubkeyBase64Urlsafe !== descriptor.sourceWalletPubkeyBase64Urlsafe) {
    return false;
  }
  if (candidate.innerSha256 !== descriptor.innerSha256) return false;
  if (candidate.step1Signature !== descriptor.step1Signature) return false;
  if (!isSyntacticallyValidStep2Signature(candidate.step2Signature)) return false;
  if (
    candidate.transferCodeSha256 !== undefined &&
    candidate.transferCodeSha256 !== descriptor.transferCodeSha256
  ) {
    return false;
  }
  return true;
}

// Classify a single poll. Returns CANDIDATE_MATCH only when operation-identity binding
// succeeds; null means "keep polling" (no-match / not this operation / clean NO_SUCCESSOR).
// INVARIANT_BREACH is preserved (never downgraded to INDETERMINATE).
export function classifySendCompletionPoll(
  input: SendCompletionPollInput,
): SendCompletionVerdict | null {
  const classification = classifyPathObservation(input.observation);

  switch (classification.tier) {
    case "LANDED": {
      // Operation-identity binding: a landed path for SOME other body/wallet, or a
      // proof without matching candidate material, is NOT a completion of THIS send.
      if (
        !isOperationBoundCandidateMatch(
          input.descriptor,
          classification.proof,
          input.candidate,
        )
      ) {
        return null;
      }
      return {
        kind: "CANDIDATE_MATCH",
        sendAttemptId: input.descriptor.sendAttemptId,
        proof: classification.proof,
        matchedAt: input.observedAt,
        candidate: input.candidate,
      };
    }
    case "INVARIANT_BREACH":
      return {
        kind: "INVARIANT_BREACH",
        sendAttemptId: input.descriptor.sendAttemptId,
        sourceWalletId: input.descriptor.sourceWalletId,
        pollsExecuted: 1,
        reason: classification.reason,
      };
    case "INDETERMINATE":
      // NO_SUCCESSOR_OBSERVED is the clean "nothing happened yet" case — keep polling.
      if (classification.reason.source === "NO_SUCCESSOR_OBSERVED") {
        return null;
      }
      if (classification.reason.source === "LANDING_PROOF_INCOMPLETE") {
        return {
          kind: "INDETERMINATE",
          sendAttemptId: input.descriptor.sendAttemptId,
          pollsExecuted: 1,
          reason: {
            source: "LANDING_PROOF_INCOMPLETE",
            fault: classification.reason.fault,
          },
        };
      }
      if (classification.reason.source === "OBSERVATION_ANOMALY") {
        return {
          kind: "INDETERMINATE",
          sendAttemptId: input.descriptor.sendAttemptId,
          pollsExecuted: 1,
          reason: {
            source: "OBSERVATION_ANOMALY",
            anomaly: classification.reason.anomaly,
          },
        };
      }
      return {
        kind: "INDETERMINATE",
        sendAttemptId: input.descriptor.sendAttemptId,
        pollsExecuted: 1,
        reason: {
          source: "OBSERVATION_ANOMALY",
          anomaly: classification.reason.source,
        },
      };
    default:
      return assertUnreachable(classification);
  }
}

// The polling schedule configuration. Spec freezes no numeric cadence for completion
// monitoring ("bounded read retry through the observation service"); these are
// conservative implementer-judgment defaults. Per-poll transport retry is owned by the
// observation service / gateway/read.ts (READ_MAX_ATTEMPTS) — this loop is the outer
// completion-monitoring window, not a second read-retry stack.
export interface SendCompletionMonitorConfig {
  readonly maxPolls: number;
  readonly pollIntervalMs: number;
  readonly windowMs: number;
}

export const DEFAULT_COMPLETION_MONITOR_CONFIG: SendCompletionMonitorConfig = {
  maxPolls: 60,
  pollIntervalMs: 5_000,
  windowMs: 300_000,
};

export type SendCompletionPollFn = (
  descriptor: MonitoredSendDescriptor,
) => Promise<SendCompletionPollInput>;
export type SendCompletionSleepFn = (ms: number) => Promise<void>;
export type SendCompletionNowIsoFn = () => string;
export type SendCompletionNowMsFn = () => number;

const defaultSleep: SendCompletionSleepFn = async (ms) =>
  await new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

const defaultNowIso: SendCompletionNowIsoFn = () => new Date().toISOString();
const defaultNowMs: SendCompletionNowMsFn = () => Date.now();

export interface SendCompletionMonitorOptions {
  readonly config?: Partial<SendCompletionMonitorConfig>;
  /**
   * Prefer `createObservationServicePollFn(service)` so every read is observation
   * service-mediated. A raw poll fn is accepted for unit tests only.
   */
  readonly poll: SendCompletionPollFn;
  readonly recorder: CompletionEvidenceRecorder;
  readonly sleep?: SendCompletionSleepFn;
  readonly nowIso?: SendCompletionNowIsoFn;
  readonly nowMs?: SendCompletionNowMsFn;
}

function toEvidence(
  descriptor: MonitoredSendDescriptor,
  verdict: SendCompletionVerdict,
  evidenceRecordedAt: string,
  pollCount: number,
  lastResponseSha256: string | null,
): SendCompletionEvidence {
  return {
    sendAttemptId: descriptor.sendAttemptId,
    sourceWalletId: descriptor.sourceWalletId,
    transferCodeSha256: descriptor.transferCodeSha256,
    expectedBodySha256: descriptor.expectedBodySha256,
    verdict,
    evidenceRecordedAt,
    pollCount,
    lastResponseSha256,
  };
}

// Run the passive completion monitor for one delivered SEND_EXTERNAL. Polls the source
// path at bounded intervals until a bound candidate match is observed (CANDIDATE_MATCH),
// the monitoring window elapses (TIMED_OUT), every poll threw (INDETERMINATE /
// POLL_TRANSPORT_EXHAUSTED), or an unrecoverable observation fault / custody breach
// terminates the loop. Records evidence for audit on every terminal outcome. Never
// mutates the send operation itself.
export async function monitorSendCompletion(
  descriptor: MonitoredSendDescriptor,
  options: SendCompletionMonitorOptions,
): Promise<SendCompletionVerdict> {
  const config: SendCompletionMonitorConfig = {
    ...DEFAULT_COMPLETION_MONITOR_CONFIG,
    ...options.config,
  };
  const sleep = options.sleep ?? defaultSleep;
  const nowIso = options.nowIso ?? defaultNowIso;
  const nowMs = options.nowMs ?? defaultNowMs;

  const windowStart = nowMs();
  let pollsExecuted = 0;
  let successfulPolls = 0;
  let lastResponseSha256: string | null = null;

  for (let i = 0; i < config.maxPolls; i += 1) {
    const elapsed = nowMs() - windowStart;
    if (elapsed >= config.windowMs) {
      break;
    }

    let pollInput: SendCompletionPollInput;
    try {
      pollInput = await options.poll(descriptor);
    } catch {
      // Single-poll transport failure is not terminal — the next poll may succeed.
      // Only total exhaustion of the window with ZERO successful reads is reported as
      // POLL_TRANSPORT_EXHAUSTED (distinguishable from "recipient never acted").
      pollsExecuted += 1;
      if (i < config.maxPolls - 1) {
        await sleep(config.pollIntervalMs);
      }
      continue;
    }

    pollsExecuted += 1;
    successfulPolls += 1;
    if (pollInput.capture !== null) {
      lastResponseSha256 = pollInput.capture.responseSha256;
    }

    const verdict = classifySendCompletionPoll(pollInput);

    if (verdict !== null) {
      const finalVerdict: SendCompletionVerdict =
        verdict.kind === "INDETERMINATE" ||
        verdict.kind === "TIMED_OUT" ||
        verdict.kind === "INVARIANT_BREACH"
          ? { ...verdict, pollsExecuted }
          : verdict;
      await options.recorder.recordCompletionEvidence(
        toEvidence(descriptor, finalVerdict, nowIso(), pollsExecuted, lastResponseSha256),
      );
      return finalVerdict;
    }

    // NO_SUCCESSOR or unbound/non-matching candidate — continue polling.
    if (i < config.maxPolls - 1) {
      await sleep(config.pollIntervalMs);
    }
  }

  // Window elapsed or maxPolls exhausted. If we never completed a single successful read,
  // that is transport exhaustion — not "recipient silence".
  if (successfulPolls === 0 && pollsExecuted > 0) {
    const exhausted: SendCompletionVerdict = {
      kind: "INDETERMINATE",
      sendAttemptId: descriptor.sendAttemptId,
      pollsExecuted,
      reason: { source: "POLL_TRANSPORT_EXHAUSTED" },
    };
    await options.recorder.recordCompletionEvidence(
      toEvidence(descriptor, exhausted, nowIso(), pollsExecuted, lastResponseSha256),
    );
    return exhausted;
  }

  const timedOut: SendCompletionVerdict = {
    kind: "TIMED_OUT",
    sendAttemptId: descriptor.sendAttemptId,
    pollsExecuted,
    windowElapsedMs: nowMs() - windowStart,
  };
  await options.recorder.recordCompletionEvidence(
    toEvidence(descriptor, timedOut, nowIso(), pollsExecuted, lastResponseSha256),
  );
  return timedOut;
}
