import { RECEIVE_QUEUE_MAX_WAIT_MS, RECEIVE_QUEUE_RETRY_AFTER_SECONDS } from "./constants.js";

// Queue dequeue sequence (backpressure rule 4). This sequences RECEIVE operations, not wallets; wallet
// selection remains independently frozen by WALLET_SELECTION_ORDER in selection.ts.
export const RECEIVE_QUEUE_DEQUEUE_ORDER = ["created_at ASC", "operation_id ASC"] as const;

// A queued receive is not a new state. It is the existing unassigned CREATED receive shape with
// no custody/evidence side effects. the DB-domains concern/the named concern must use this same predicate for demand counts
// dequeue, expiry, and the assignment-time recheck.
export const RECEIVE_QUEUE_QUEUED_PREDICATE = {
  kind: "RECEIVE_EXTERNAL",
  status: "CREATED",
  receiverWalletId: null,
  expiryUnixTimeSecs: null,
  t0ObservationId: null,
  hasDurableCode: false,
  hasActiveLease: false,
} as const;

// Strict FIFO and EXPIRED-never-assigned require one serialized promotion branch. The oldest
// operation row is locked without SKIP LOCKED (which could let a later row leapfrog), then the
// authoritative decision time is captured and exactly one expire-or-assign branch may commit.
export const RECEIVE_QUEUE_PROMOTION_TRANSACTION = {
  operationLock: "FOR UPDATE",
  skipLocked: false,
  decisionTime: "after_operation_lock",
  strictFifo: true,
  atomicBranch: "expire_or_assign",
  assignmentRequiresQueuedPredicateRecheck: true,
  expiryBranch: {
    transition: "CREATED_TO_EXPIRED",
    walletAssigned: false,
    leaseCreated: false,
    t0Created: false,
    codeCreated: false,
    artifactCreated: false,
    signingInvoked: false,
  },
} as const;

export interface ReceiveQueueCandidate {
  readonly operationId: string;
  readonly createdAt: string;
  readonly kind: string;
  readonly status: string;
  readonly receiverWalletId: string | null;
  readonly expiryUnixTimeSecs: string | null;
  readonly t0ObservationId: string | null;
  readonly hasDurableCode: boolean;
  readonly hasActiveLease: boolean;
}

export function isQueuedReceiveCandidate(candidate: ReceiveQueueCandidate): boolean {
  return (
    candidate.kind === RECEIVE_QUEUE_QUEUED_PREDICATE.kind &&
    candidate.status === RECEIVE_QUEUE_QUEUED_PREDICATE.status &&
    candidate.receiverWalletId === null &&
    candidate.expiryUnixTimeSecs === null &&
    candidate.t0ObservationId === null &&
    !candidate.hasDurableCode &&
    !candidate.hasActiveLease
  );
}

function byReceiveQueueSequence(a: ReceiveQueueCandidate, b: ReceiveQueueCandidate): number {
  if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt ? -1 : 1;
  if (a.operationId !== b.operationId) return a.operationId < b.operationId ? -1 : 1;
  return 0;
}

// Pure model of queue dequeue: filter the exact queued shape, then choose the oldest receive with
// operation_id as the deterministic tie-break. Array.prototype.filter creates a copy before sort,
// so the caller-owned input sequence is never mutated.
export function selectNextQueuedReceive(
  candidates: readonly ReceiveQueueCandidate[],
): ReceiveQueueCandidate | null {
  return candidates.filter(isQueuedReceiveCandidate).sort(byReceiveQueueSequence)[0] ?? null;
}

// RECEIVE_QUEUE_CAP is derived from pool_cap (backpressure rule 4 — no independent magic number).
export function receiveQueueCap(poolCap: number): number {
  return poolCap;
}

// The reject carries a Retry-After (seconds) named by backpressure rule 4 — the value stamped on
// the `503 receive_queue_full` HTTP response header (`reason` is the stable error envelope `code`).
export type ReceiveAdmission =
  | { readonly kind: "assign" }
  | { readonly kind: "queue"; readonly httpStatus: 202 }
  | {
      readonly kind: "reject";
      readonly httpStatus: 503;
      readonly reason: "receive_queue_full";
      readonly retryAfterSeconds: number;
    };

// Fail-closed backpressure (rule 4, refined by recovery-gated eligibility). If a recovery-verified AVAILABLE
// wallet exists, assign it. Otherwise queue FIFO while depth < RECEIVE_QUEUE_CAP (= pool_cap),
// returning 202 with no address; at/over the cap, reject 503 and create nothing. Minting never
// substitutes for a verified wallet — `availableVerifiedCount` is the recovery-gated count
// (recovery-gated eligibility), so a pool full of minted-but-unverified wallets still queues or rejects.
export function receiveAdmissionDecision(input: {
  readonly availableVerifiedCount: number;
  readonly queueDepth: number;
  readonly poolCap: number;
}): ReceiveAdmission {
  if (input.availableVerifiedCount > 0) return { kind: "assign" };
  if (input.queueDepth < receiveQueueCap(input.poolCap)) return { kind: "queue", httpStatus: 202 };
  return {
    kind: "reject",
    httpStatus: 503,
    reason: "receive_queue_full",
    retryAfterSeconds: RECEIVE_QUEUE_RETRY_AFTER_SECONDS,
  };
}

// A queued receive that has waited longer than RECEIVE_QUEUE_MAX_WAIT becomes EXPIRED with no
// wallet assigned and no lease (backpressure rule 4). Strict `>` — exactly at the bound is not expired.
export function isReceiveExpired(waitedMs: number): boolean {
  return waitedMs > RECEIVE_QUEUE_MAX_WAIT_MS;
}

export type ReceiveQueuePromotionDecision =
  | { readonly kind: "NOT_QUEUED" }
  | { readonly kind: "PROCEED_TO_WALLET_SELECTION" }
  | ({ readonly kind: "EXPIRE_NEVER_ASSIGN" } &
      typeof RECEIVE_QUEUE_PROMOTION_TRANSACTION.expiryBranch);

// Must run after the operation lock is acquired. Exactly at the max-wait bound remains eligible;
// the first time unit beyond it chooses the terminal expiry branch with every custody side effect
// structurally false.
export function receiveQueuePromotionDecision(
  candidate: ReceiveQueueCandidate,
  waitedMs: number,
): ReceiveQueuePromotionDecision {
  if (!isQueuedReceiveCandidate(candidate)) return { kind: "NOT_QUEUED" };
  if (!isReceiveExpired(waitedMs)) return { kind: "PROCEED_TO_WALLET_SELECTION" };
  return {
    kind: "EXPIRE_NEVER_ASSIGN",
    ...RECEIVE_QUEUE_PROMOTION_TRANSACTION.expiryBranch,
  };
}
