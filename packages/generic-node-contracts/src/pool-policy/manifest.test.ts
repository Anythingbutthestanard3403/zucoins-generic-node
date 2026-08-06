import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  poolPolicyContract,
  poolPolicyConcernManifest,
  POOL_POLICY_FLAGS,
} from "./manifest.js";
import { WALLET_SELECTION_ORDER } from "./selection.js";

const snapshotPath = fileURLToPath(new URL("../../gen/pool-policy.json", import.meta.url));

describe("pool-policy manifest — snapshot sync (3-tier)", () => {
  it("gen/pool-policy.json equals the as-const poolPolicyContract", () => {
    expect(JSON.parse(readFileSync(snapshotPath, "utf8"))).toEqual(poolPolicyContract);
  });
});

describe("pool-policy manifest — frozen-constant census", () => {
  it("freezes the sizing constants (receive-queue backpressure)", () => {
    expect(poolPolicyContract.sizing).toEqual({
      POOL_FLOOR: 5,
      POOL_CAP_DEFAULT: 50,
      POOL_CAP_CEILING: 500,
      MINT_BATCH_LIMIT: 5,
      HEADROOM_NUMERATOR: 11,
      HEADROOM_DENOMINATOR: 10,
    });
  });
  it("freezes the queue admission, dequeue sequence, queued predicate, and atomic promotion contract", () => {
    expect(poolPolicyContract.queue).toEqual({
      RECEIVE_QUEUE_MAX_WAIT_MS: 30000,
      RECEIVE_QUEUE_CAP: "pool_cap",
      RECEIVE_QUEUE_RETRY_AFTER_SECONDS: 30,
      RECEIVE_QUEUE_DEQUEUE_ORDER: ["created_at ASC", "operation_id ASC"],
      RECEIVE_QUEUE_QUEUED_PREDICATE: {
        kind: "RECEIVE_EXTERNAL",
        status: "CREATED",
        receiverWalletId: null,
        expiryUnixTimeSecs: null,
        t0ObservationId: null,
        hasDurableCode: false,
        hasActiveLease: false,
      },
      RECEIVE_QUEUE_PROMOTION_TRANSACTION: {
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
      },
    });
    expect(poolPolicyContract.queue.RECEIVE_QUEUE_DEQUEUE_ORDER).not.toEqual(WALLET_SELECTION_ORDER);
    expect(poolPolicyContract.queue.RECEIVE_QUEUE_PROMOTION_TRANSACTION.operationLock).not.toContain(
      "SKIP LOCKED",
    );
  });
  it("freezes the recovery-gated receive-eligibility predicate and cap-counts-all fact", () => {
    expect(poolPolicyContract.eligibility.receiveEligiblePredicate).toBe(
      "key_origin='node_generated' AND recovery_verified_at IS NOT NULL AND state='AVAILABLE'",
    );
    expect(poolPolicyContract.eligibility.capCountsAllNonDeleted).toBe(true);
  });
  it("records the concern provenance (receive-queue backpressure refined by recovery-gated eligibility)", () => {
    expect(poolPolicyConcernManifest.concern).toBe("pool-policy");
    expect(poolPolicyConcernManifest.frozenBy).toBe("receive-queue-backpressure");
    expect(poolPolicyConcernManifest.refinedBy).toBe("recovery-gated-eligibility");
  });
});

describe("pool-policy manifest — flagged-for-operator data (operative frozen, alternative recorded)", () => {
  it("records the 30s->~120s max-wait flag as data (operative stays 30s)", () => {
    expect(POOL_POLICY_FLAGS.RECEIVE_QUEUE_MAX_WAIT_MS.operative).toBe(30000);
    expect(POOL_POLICY_FLAGS.RECEIVE_QUEUE_MAX_WAIT_MS.recommended).toBe(120000);
    expect(POOL_POLICY_FLAGS.RECEIVE_QUEUE_MAX_WAIT_MS.status).toBe("flagged_for_operator");
  });
  it("flags the other new constants and marks the queue cap + Retry-After as derived", () => {
    expect(POOL_POLICY_FLAGS.POOL_CAP_CEILING.status).toBe("flagged_for_operator");
    expect(POOL_POLICY_FLAGS.MINT_BATCH_LIMIT.status).toBe("flagged_for_operator");
    expect(POOL_POLICY_FLAGS.RECEIVE_QUEUE_CAP.status).toBe("derived");
    expect(POOL_POLICY_FLAGS.RECEIVE_QUEUE_RETRY_AFTER_SECONDS.status).toBe("derived");
    expect(POOL_POLICY_FLAGS.RECEIVE_QUEUE_RETRY_AFTER_SECONDS.operative).toBe(30);
  });
});
