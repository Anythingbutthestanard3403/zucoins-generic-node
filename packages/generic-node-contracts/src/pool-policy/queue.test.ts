import { describe, it, expect } from "vitest";
import {
  RECEIVE_QUEUE_DEQUEUE_ORDER,
  RECEIVE_QUEUE_PROMOTION_TRANSACTION,
  isQueuedReceiveCandidate,
  isReceiveExpired,
  receiveAdmissionDecision,
  receiveQueueCap,
  receiveQueuePromotionDecision,
  selectNextQueuedReceive,
  type ReceiveQueueCandidate,
} from "./queue.js";
import { RECEIVE_QUEUE_MAX_WAIT_MS, RECEIVE_QUEUE_RETRY_AFTER_SECONDS } from "./constants.js";

describe("receiveAdmissionDecision — fail-closed backpressure (rule 4 + recovery-gated eligibility)", () => {
  it("assigns when a recovery-verified AVAILABLE wallet exists", () => {
    expect(receiveAdmissionDecision({ availableVerifiedCount: 1, queueDepth: 0, poolCap: 50 })).toEqual({
      kind: "assign",
    });
  });
  it("queues 202 (no address) when none available and the queue is under cap", () => {
    expect(receiveAdmissionDecision({ availableVerifiedCount: 0, queueDepth: 10, poolCap: 50 })).toEqual({
      kind: "queue",
      httpStatus: 202,
    });
  });
  it("rejects 503 at queue cap with a Retry-After and creates nothing (NEGATIVE)", () => {
    expect(receiveAdmissionDecision({ availableVerifiedCount: 0, queueDepth: 50, poolCap: 50 })).toEqual({
      kind: "reject",
      httpStatus: 503,
      reason: "receive_queue_full",
      retryAfterSeconds: RECEIVE_QUEUE_RETRY_AFTER_SECONDS,
    });
  });
  it("freezes Retry-After (seconds) as the derived max-wait window (backpressure rule 4)", () => {
    expect(RECEIVE_QUEUE_RETRY_AFTER_SECONDS).toBe(RECEIVE_QUEUE_MAX_WAIT_MS / 1000);
    expect(RECEIVE_QUEUE_RETRY_AFTER_SECONDS).toBe(30);
  });
  it("never assigns off a pool of minted-but-unverified wallets (minting != availability, recovery-gated eligibility)", () => {
    // availableVerifiedCount is the recovery-gated count; a pool full of unverified wallets
    // presents as 0 available, so admission queues (or rejects at cap), never assigns.
    expect(receiveAdmissionDecision({ availableVerifiedCount: 0, queueDepth: 0, poolCap: 50 }).kind).toBe(
      "queue",
    );
    expect(
      receiveAdmissionDecision({ availableVerifiedCount: 0, queueDepth: 50, poolCap: 50 }).kind,
    ).toBe("reject");
  });
});

describe("receiveQueueCap — derived from pool_cap (no independent number)", () => {
  it("equals pool_cap", () => {
    expect(receiveQueueCap(50)).toBe(50);
    expect(receiveQueueCap(500)).toBe(500);
  });
});

describe("isReceiveExpired — strict max-wait boundary (30s operative)", () => {
  it("expires strictly after RECEIVE_QUEUE_MAX_WAIT", () => {
    expect(RECEIVE_QUEUE_MAX_WAIT_MS).toBe(30000);
    expect(isReceiveExpired(RECEIVE_QUEUE_MAX_WAIT_MS - 1)).toBe(false);
    expect(isReceiveExpired(RECEIVE_QUEUE_MAX_WAIT_MS)).toBe(false);
    expect(isReceiveExpired(RECEIVE_QUEUE_MAX_WAIT_MS + 1)).toBe(true);
  });
});

function queued(overrides: Partial<ReceiveQueueCandidate> = {}): ReceiveQueueCandidate {
  return {
    operationId: "00000000-0000-4000-8000-000000000001",
    createdAt: "2026-07-19T00:00:00.000Z",
    kind: "RECEIVE_EXTERNAL",
    status: "CREATED",
    receiverWalletId: null,
    expiryUnixTimeSecs: null,
    t0ObservationId: null,
    hasDurableCode: false,
    hasActiveLease: false,
    ...overrides,
  };
}

describe("receive queue dequeue — FIFO operation sequence (backpressure rule 4)", () => {
  it("freezes a queue-specific sequence distinct from wallet selection", () => {
    expect(RECEIVE_QUEUE_DEQUEUE_ORDER).toEqual(["created_at ASC", "operation_id ASC"]);
  });

  it("chooses the oldest queued receive regardless of input sequence", () => {
    const oldest = queued({ createdAt: "2026-07-19T00:00:00.000Z" });
    const newer = queued({
      operationId: "00000000-0000-4000-8000-000000000002",
      createdAt: "2026-07-19T00:00:01.000Z",
    });
    expect(selectNextQueuedReceive([newer, oldest])).toBe(oldest);
  });

  it("uses operation_id ascending as the equal-timestamp tie-break without mutating input", () => {
    const lower = queued({ operationId: "00000000-0000-4000-8000-000000000001" });
    const higher = queued({ operationId: "00000000-0000-4000-8000-000000000002" });
    const input = [higher, lower] as const;
    expect(selectNextQueuedReceive(input)).toBe(lower);
    expect(input).toEqual([higher, lower]);
  });

  it.each([
    ["wrong kind", { kind: "MOVE_INTERNAL" }],
    ["wrong status", { status: "EXPIRED" }],
    ["assigned wallet", { receiverWalletId: "10000000-0000-4000-8000-000000000001" }],
    ["persisted expiry", { expiryUnixTimeSecs: "1" }],
    ["T0 evidence", { t0ObservationId: "20000000-0000-4000-8000-000000000001" }],
    ["durable code", { hasDurableCode: true }],
    ["active lease", { hasActiveLease: true }],
  ])("excludes %s from the queue predicate", (_label, overrides) => {
    const candidate = queued(overrides);
    expect(isQueuedReceiveCandidate(candidate)).toBe(false);
    expect(selectNextQueuedReceive([candidate])).toBeNull();
    expect(receiveQueuePromotionDecision(candidate, RECEIVE_QUEUE_MAX_WAIT_MS + 1)).toEqual({
      kind: "NOT_QUEUED",
    });
  });
});

describe("receive queue promotion — atomic EXPIRED-never-assigned branch", () => {
  it("locks the oldest operation without SKIP LOCKED and decides after the lock", () => {
    expect(RECEIVE_QUEUE_PROMOTION_TRANSACTION.operationLock).toBe("FOR UPDATE");
    expect(RECEIVE_QUEUE_PROMOTION_TRANSACTION.skipLocked).toBe(false);
    expect(RECEIVE_QUEUE_PROMOTION_TRANSACTION.decisionTime).toBe("after_operation_lock");
    expect(RECEIVE_QUEUE_PROMOTION_TRANSACTION.atomicBranch).toBe("expire_or_assign");
    expect(RECEIVE_QUEUE_PROMOTION_TRANSACTION.assignmentRequiresQueuedPredicateRecheck).toBe(true);
  });

  it("proceeds before and exactly at the strict max-wait boundary", () => {
    expect(receiveQueuePromotionDecision(queued(), RECEIVE_QUEUE_MAX_WAIT_MS - 1)).toEqual({
      kind: "PROCEED_TO_WALLET_SELECTION",
    });
    expect(receiveQueuePromotionDecision(queued(), RECEIVE_QUEUE_MAX_WAIT_MS)).toEqual({
      kind: "PROCEED_TO_WALLET_SELECTION",
    });
  });

  it("expires one unit beyond the boundary with no custody/signing side effect", () => {
    expect(receiveQueuePromotionDecision(queued(), RECEIVE_QUEUE_MAX_WAIT_MS + 1)).toEqual({
      kind: "EXPIRE_NEVER_ASSIGN",
      transition: "CREATED_TO_EXPIRED",
      walletAssigned: false,
      leaseCreated: false,
      t0Created: false,
      codeCreated: false,
      artifactCreated: false,
      signingInvoked: false,
    });
  });
});
