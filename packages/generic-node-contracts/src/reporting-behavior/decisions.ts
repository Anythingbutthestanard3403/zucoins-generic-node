// the reporting bootstrap enrolment — Pure decision functions modelling the replay and key-rotation behaviour the reporting
// contract must exhibit. There is no runtime server in this CONTRACT_FREEZE slice, so each
// behaviour is a deterministic decision over frozen inputs; the freeze test drives them across the
// full scenario matrix and consumes the reporting-auth register tuple's lifecycle rules and the reporting node-event purpose's tuple goldens.
//
// Governing contract: register tuple / event signing; signed reporting; the pull-cursor authority decision (60s window vs SIGNED
// issued_at; durable single-use nonce; per-node gapless pre-signed seq; seq-cursor retirement;
// revoke-to-zero fail-closed; restore monotonic epoch + hash-chain hard-stop).

import type { ReportingKeyState } from "../reporting-auth/index.js";
import { REPORT_REQUEST_CLOCK_SKEW_MS } from "../reporting-tuples/index.js";

export const REQUEST_MAX_WINDOW_MS = 60_000;
export const REQUEST_CLOCK_SKEW_MS = REPORT_REQUEST_CLOCK_SKEW_MS;

// -------- nonce / time / body / tenant (request tuple) --------

export type RequestOutcome =
  | "ACCEPT"
  | "REJECT_WRONG_TENANT"
  | "REJECT_WINDOW"
  | "REJECT_EXPIRED"
  | "REJECT_NOT_YET_VALID"
  | "REJECT_REPLAY"
  | "REJECT_METHOD_MUTATED"
  | "REJECT_TARGET_MUTATED"
  | "REJECT_BODY_MUTATED";

export interface RequestContext {
  readonly boundNodeId: string;
  readonly boundImplementerId: string;
  readonly tupleNodeId: string;
  readonly tupleImplementerId: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  // One wall-clock millisecond instant captured at request ingress by the trusted outer adapter.
  readonly receiptTimeMs: number;
  readonly nonceSeen: boolean;
  readonly signedMethod: string;
  readonly actualMethod: string;
  readonly signedTarget: string;
  readonly actualTarget: string;
  readonly signedBodySha256: string;
  readonly actualBodySha256: string;
}

// Verifier sequence (the pull-cursor authority rule): tenant equality before anything object-scoped; the window is measured
// against the SIGNED issued_at/expires_at, never receipt time; the durable single-use nonce is
// consumed exactly once.
export function evaluateReportRequest(c: RequestContext): RequestOutcome {
  if (c.tupleNodeId !== c.boundNodeId || c.tupleImplementerId !== c.boundImplementerId) {
    return "REJECT_WRONG_TENANT";
  }
  if (![c.issuedAtMs, c.expiresAtMs, c.receiptTimeMs].every(Number.isSafeInteger)) return "REJECT_WINDOW";
  const lifetime = c.expiresAtMs - c.issuedAtMs;
  if (!(lifetime > 0) || lifetime > REQUEST_MAX_WINDOW_MS) return "REJECT_WINDOW";
  if (c.receiptTimeMs > c.expiresAtMs + REQUEST_CLOCK_SKEW_MS) return "REJECT_EXPIRED";
  if (c.receiptTimeMs < c.issuedAtMs - REQUEST_CLOCK_SKEW_MS) return "REJECT_NOT_YET_VALID";
  if (c.actualMethod !== c.signedMethod) return "REJECT_METHOD_MUTATED";
  if (c.actualTarget !== c.signedTarget) return "REJECT_TARGET_MUTATED";
  if (c.actualBodySha256 !== c.signedBodySha256) return "REJECT_BODY_MUTATED";
  if (c.nonceSeen) return "REJECT_REPLAY";
  return "ACCEPT";
}

// -------- key rotation / revocation (reporting key) --------

export type KeyUseOutcome =
  | "ACCEPT_CURRENT"
  | "ACCEPT_PRIOR_OVERLAP"
  | "REJECT_RETIRED"
  | "REJECT_REVOKED"
  | "REJECT_UNKNOWN"
  | "ALARM_NO_ACTIVE_KEY";

export interface KeySlot {
  readonly key_id: string;
  readonly state: ReportingKeyState;
}
export interface KeyRegistry {
  readonly current: KeySlot | null;
  readonly prior: KeySlot | null;
}

function slotOutcome(slot: KeySlot, whenActive: KeyUseOutcome): KeyUseOutcome {
  if (slot.state === "ACTIVE") return whenActive;
  if (slot.state === "REVOKED") return "REJECT_REVOKED";
  return "REJECT_RETIRED";
}

// Verifier sequence (the pull-cursor authority rule point 2): key status is checked first. Revoking every key is an explicit
// ALARMED fail-closed "no active key" state — loud, never a silent cursor stall.
export function evaluateKeyUse(reg: KeyRegistry, keyId: string): KeyUseOutcome {
  const activeCount = [reg.current, reg.prior].filter((k) => k?.state === "ACTIVE").length;
  if (activeCount === 0) return "ALARM_NO_ACTIVE_KEY";
  if (reg.current?.key_id === keyId) return slotOutcome(reg.current, "ACCEPT_CURRENT");
  if (reg.prior?.key_id === keyId) return slotOutcome(reg.prior, "ACCEPT_PRIOR_OVERLAP");
  return "REJECT_UNKNOWN";
}

// Cutover sequencing: the new current is activated BEFORE the prior is retired (overlap), so no
// intermediate registry ever has zero active keys. A sequence that retires before activating opens
// a no-active-key gap and is invalid.
export function cutoverNeverGoesDark(sequence: readonly KeyRegistry[]): boolean {
  return sequence.every((reg) => [reg.current, reg.prior].some((k) => k?.state === "ACTIVE"));
}

// -------- bootstrap enrolment trust-root (reporting key first-key binding) --------

export type BootstrapEnrolmentOutcome =
  | "ACCEPT_PERMANENT"
  | "NOT_BOOTSTRAP"
  | "REJECT_MISSING_ONBOARDING_CREDENTIAL"
  | "REJECT_IMPLEMENTER_ID_FROM_BODY"
  | "REJECT_MISSING_OPERATOR_APPROVAL"
  | "REJECT_MISSING_PROOF_OF_POSSESSION";

export interface BootstrapEnrolmentContext {
  // `null` → bootstrap (first-key binding, gated here); non-null → rotation (existing-key anchor,
  // evaluated by evaluateKeyUse, NOT gated here).
  readonly supersedesKeyId: string | null;
  readonly hasAuthenticatedOnboardingCredential: boolean;
  // The verifier takes implementer_id from the authenticated caller, never the request body.
  readonly implementerIdFromAuthenticatedCaller: boolean;
  readonly hasNodeOriginOperatorApproval: boolean;
  readonly proofOfPossessionValid: boolean;
}

// Bootstrap enrolment trust-root PERMANENT gate (the reporting-key enrolment rule / A.5.1, frozen by the bootstrap enrolment trust-root rule; reporting-auth
// BOOTSTRAP_TRUST_ROOT). A bootstrap (supersedes_key_id === null) binds a FIRST reporting key to an
// implementer_id. Proof of possession proves keypair control, never identity, so "who may bind a
// first key" authors a root of authority. the bootstrap enrolment trust-root rule (operator first-party, Option A) resolved this
// PERMANENT: fail-closed, granting live-ZKZ reporting authority, requiring ALL THREE of an
// authenticated onboarding credential (with implementer_id from the caller, never the body), an
// explicit node-origin operator approval, and a valid PoP signature. Rotation is not gated here.
export function evaluateBootstrapEnrolment(c: BootstrapEnrolmentContext): BootstrapEnrolmentOutcome {
  if (c.supersedesKeyId !== null) return "NOT_BOOTSTRAP";
  if (!c.hasAuthenticatedOnboardingCredential) return "REJECT_MISSING_ONBOARDING_CREDENTIAL";
  if (!c.implementerIdFromAuthenticatedCaller) return "REJECT_IMPLEMENTER_ID_FROM_BODY";
  if (!c.hasNodeOriginOperatorApproval) return "REJECT_MISSING_OPERATOR_APPROVAL";
  if (!c.proofOfPossessionValid) return "REJECT_MISSING_PROOF_OF_POSSESSION";
  return "ACCEPT_PERMANENT";
}

// -------- event stream: tenant seq + node hash-chain + restore --------

export type TenantSeqOutcome = "ACCEPT_ADVANCE" | "REJECT_REORDER_OR_REPLAY";

// A tenant-filtered consumer sees a sparse subset of the node-global seq. Any strictly greater seq
// advances the cursor — a skipped seq is another tenant's event, NOT a gap. A seq at or below the
// cursor is a reorder/replay.
export function evaluateTenantSeq(consumerCursor: bigint, eventSeq: bigint): TenantSeqOutcome {
  return eventSeq > consumerCursor ? "ACCEPT_ADVANCE" : "REJECT_REORDER_OR_REPLAY";
}

export type ChainAppendOutcome = "ACCEPT_CHAIN" | "HARD_STOP_CHAIN_BREAK";

// The node-global hash chain is the true gap detector: an event links only when its
// previous_event_hash equals the prior event's event_hash (null for the first). A mismatch is a
// HARD STOP + reconciliation, never a silent skip.
export function evaluateChainAppend(lastEventHash: string | null, previousEventHash: string | null): ChainAppendOutcome {
  return previousEventHash === lastEventHash ? "ACCEPT_CHAIN" : "HARD_STOP_CHAIN_BREAK";
}

export type RestoreOutcome = "ACCEPT" | "REJECT_EPOCH_REGRESSION" | "HARD_STOP_CHAIN_BREAK";

export interface RestoreState {
  readonly epoch: number;
  readonly lastEventHash: string | null;
}

// Restore-from-backup guard (the pull-cursor authority rule point 3): a monotonic reporting epoch means a post-restore
// stream must carry a strictly greater epoch, so a replayed seq cannot silently collide on the
// consumer dedup. Within an epoch, the hash chain must link or it is a hard stop.
export function evaluateRestoreIngest(
  state: RestoreState,
  event: { readonly epoch: number; readonly previousEventHash: string | null },
): RestoreOutcome {
  if (event.epoch < state.epoch) return "REJECT_EPOCH_REGRESSION";
  if (event.epoch === state.epoch && event.previousEventHash !== state.lastEventHash) {
    return "HARD_STOP_CHAIN_BREAK";
  }
  return "ACCEPT";
}
