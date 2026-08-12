// RECEIVE_EXTERNAL single-shot submit. Governing:
// Formation step 9; landing-path oracle; the never-blind-retry rule.
//
// The exit property: one claim per receive attempt, the exchange invoked at most once, and
// any ambiguity reported as AMBIGUOUS (reconcile-only) rather than retried. The store seam is
// a single arbitrated claimSubmitOnce — no separate read-then-write.

import { describe, expect, it } from "vitest";

import type { GatewaySubmitAttemptRecord, SubmitAttemptRecorder } from "../gateway/records.js";
import type { GatewayExchangeTransport } from "../gateway/capture.js";
import type { GatewayRequest } from "../protocol/index.js";
import {
  receiveSubmitOnce,
  type ReceiveSubmitClaim,
  type ReceiveSubmitOnceInput,
  type SubmitClaimStore,
} from "./receive-submit-once.js";

const ATTEMPT_ID = "receive-attempt-1";
const DECISION_ID = "decision-1";
const OPERATION_ID = "op-1";
const REQUEST: GatewayRequest = { rpc: "submit_transaction__v1", bodyBytes: new TextEncoder().encode("v=%7B%7D") };
const AUTHORIZATION = { submitDecisionId: DECISION_ID, operationId: OPERATION_ID, transactionAttemptNo: 1 };
const NOW = "2026-01-01T00:00:00.000Z";

const attemptKey = (claim: ReceiveSubmitClaim): string =>
  `${claim.operationId}#${claim.transactionAttemptNo}`;

function makeRecorder(): SubmitAttemptRecorder & { records: GatewaySubmitAttemptRecord[] } {
  const records: GatewaySubmitAttemptRecord[] = [];
  return { records, recordSubmitAttempt: async (r) => { records.push(r); } };
}

// In-memory stand-in for the UNIQUE (operation_id, transaction_attempt_no) mint. The
// arbitration is one synchronous decision (as the database's is one atomic statement); the
// suspension point sits after it, so a caller cannot observe a half-decided claim.
function makeClaimStore(opts?: {
  preExisting?: boolean;
}): SubmitClaimStore & { claims: Map<string, ReceiveSubmitClaim>; readonly mints: number } {
  const claims = new Map<string, ReceiveSubmitClaim>();
  if (opts?.preExisting) {
    claims.set(`${OPERATION_ID}#1`, {
      attemptId: ATTEMPT_ID,
      claimedAt: "2025-12-31T00:00:00.000Z",
      operationId: OPERATION_ID,
      transactionAttemptNo: 1,
    });
  }
  let mints = 0;
  return {
    claims,
    get mints() {
      return mints;
    },
    claimSubmitOnce: async (claim) => {
      const key = attemptKey(claim);
      const existing = claims.get(key);
      if (existing !== undefined) {
        await Promise.resolve();
        return { claim: existing, minted: false };
      }
      claims.set(key, claim);
      mints += 1;
      await Promise.resolve();
      return { claim, minted: true };
    },
  };
}

function makeFakeExchange(statusCode: number, body: string): GatewayExchangeTransport {
  return {
    exchange: async (_ep: string, _req: GatewayRequest) => ({
      endpoint: "https://gw.invalid/", endpointFingerprint: "fp",
      requestBytes: REQUEST.bodyBytes, requestSha256: "req-sha",
      responseBytes: new TextEncoder().encode(body), responseSha256: "resp-sha", statusCode,
    }),
  };
}

function makeInput(overrides?: Partial<ReceiveSubmitOnceInput>): ReceiveSubmitOnceInput {
  return {
    receiveAttemptId: ATTEMPT_ID, signedRequest: REQUEST, authorization: AUTHORIZATION,
    submitOptions: {
      endpoint: "https://gw.invalid/",
      limits: { readTimeoutMs: 1000, maxRequestBytes: 4096, maxResponseBytes: 4096 },
      recorder: makeRecorder(),
      exchange: makeFakeExchange(200, '{"status":true,"code":"ok","message":"OK","data":{}}'),
    },
    claimStore: makeClaimStore(), nowIso: () => NOW, ...overrides,
  };
}

describe("receiveSubmitOnce", () => {
  it("submits once and returns SUBMITTED with ACK on 2xx", async () => {
    const result = await receiveSubmitOnce(makeInput());
    expect(result.kind).toBe("SUBMITTED");
    if (result.kind === "SUBMITTED") {
      expect(result.transportOutcome).toBe("ACK");
      expect(result.claim.attemptId).toBe(ATTEMPT_ID);
      expect(result.claim.operationId).toBe(OPERATION_ID);
      expect(result.claim.transactionAttemptNo).toBe(1);
      expect(result.acknowledgement.attemptId).toBe(ATTEMPT_ID);
      expect(result.acknowledgement.gatewayStatus).toBe(true);
      expect(result.recordedAttempt.transportOutcome).toBe("ACK");
    }
  });

  it("returns SUBMITTED with REJECT on 4xx", async () => {
    const result = await receiveSubmitOnce(makeInput({
      submitOptions: { endpoint: "https://gw.invalid/", limits: { readTimeoutMs: 1000, maxRequestBytes: 4096, maxResponseBytes: 4096 }, recorder: makeRecorder(), exchange: makeFakeExchange(422, '{"status":false,"code":"invalid"}') },
    }));
    expect(result.kind).toBe("SUBMITTED");
    if (result.kind === "SUBMITTED") {
      expect(result.transportOutcome).toBe("REJECT");
      expect(result.acknowledgement.gatewayStatus).toBe(false);
    }
  });

  it("returns AMBIGUOUS on transport ambiguity (5xx)", async () => {
    const result = await receiveSubmitOnce(makeInput({
      submitOptions: { endpoint: "https://gw.invalid/", limits: { readTimeoutMs: 1000, maxRequestBytes: 4096, maxResponseBytes: 4096 }, recorder: makeRecorder(), exchange: makeFakeExchange(503, '{"status":false}') },
    }));
    expect(result.kind).toBe("AMBIGUOUS");
    if (result.kind === "AMBIGUOUS") {
      expect(result.reason.source).toBe("SUBMIT_OUTCOME_UNKNOWN");
      expect(result.claim.attemptId).toBe(ATTEMPT_ID);
      expect(result.recordedAttempt.transportOutcome).toBe("INDETERMINATE");
    }
  });

  it("returns AMBIGUOUS on empty-body 2xx (never a false ACK receipt)", async () => {
    const result = await receiveSubmitOnce(
      makeInput({
        submitOptions: {
          endpoint: "https://gw.invalid/",
          limits: { readTimeoutMs: 1000, maxRequestBytes: 4096, maxResponseBytes: 4096 },
          recorder: makeRecorder(),
          exchange: makeFakeExchange(200, ""),
        },
      }),
    );
    expect(result.kind).toBe("AMBIGUOUS");
    if (result.kind === "AMBIGUOUS") {
      expect(result.reason.source).toBe("SUBMIT_OUTCOME_UNKNOWN");
      expect(result.recordedAttempt.transportOutcome).toBe("INDETERMINATE");
      expect(result.recordedAttempt.responseBytes?.byteLength ?? 0).toBe(0);
    }
  });

  it("returns AMBIGUOUS when claim already exists (never blind-retry)", async () => {
    const result = await receiveSubmitOnce(makeInput({ claimStore: makeClaimStore({ preExisting: true }) }));
    expect(result.kind).toBe("AMBIGUOUS");
    if (result.kind === "AMBIGUOUS") expect(result.reason.source).toBe("SUBMIT_OUTCOME_UNKNOWN");
  });

  it("mints the claim before the POST (crash-safety sequencing)", async () => {
    const claimStore = makeClaimStore();
    await receiveSubmitOnce(makeInput({ claimStore }));
    expect(claimStore.mints).toBe(1);
    expect(claimStore.claims.get(`${OPERATION_ID}#1`)?.attemptId).toBe(ATTEMPT_ID);
  });

  it("records exactly one submit attempt on success", async () => {
    const recorder = makeRecorder();
    await receiveSubmitOnce(makeInput({ submitOptions: { endpoint: "https://gw.invalid/", limits: { readTimeoutMs: 1000, maxRequestBytes: 4096, maxResponseBytes: 4096 }, recorder, exchange: makeFakeExchange(200, '{"status":true,"code":"ok","message":"OK","data":{}}') } }));
    expect(recorder.records).toHaveLength(1);
    expect(recorder.records[0].decisionId).toBe(DECISION_ID);
  });

  it("does not fire a second POST when claim pre-exists", async () => {
    const recorder = makeRecorder();
    await receiveSubmitOnce(makeInput({ claimStore: makeClaimStore({ preExisting: true }), submitOptions: { endpoint: "https://gw.invalid/", limits: { readTimeoutMs: 1000, maxRequestBytes: 4096, maxResponseBytes: 4096 }, recorder, exchange: makeFakeExchange(200, '{"status":true}') } }));
    expect(recorder.records).toHaveLength(0);
  });

  // The defect this module was rebuilt for: two workers racing one attempt used to
  // produce two gateway POSTs, because claimExists then persistClaim left a TOCTOU window.
  it("two concurrent workers on one attempt produce exactly ONE gateway POST", async () => {
    const claimStore = makeClaimStore();
    const recorder = makeRecorder();
    let postCount = 0;
    const exchange: GatewayExchangeTransport = {
      exchange: async (_ep, _req) => {
        postCount += 1;
        return {
          endpoint: "https://gw.invalid/",
          endpointFingerprint: "fp",
          requestBytes: REQUEST.bodyBytes,
          requestSha256: "req-sha",
          responseBytes: new TextEncoder().encode('{"status":true}'),
          responseSha256: "resp-sha",
          statusCode: 200,
        };
      },
    };
    const input = makeInput({
      claimStore,
      submitOptions: {
        endpoint: "https://gw.invalid/",
        limits: { readTimeoutMs: 1000, maxRequestBytes: 4096, maxResponseBytes: 4096 },
        recorder,
        exchange,
      },
    });

    const [a, b] = await Promise.all([receiveSubmitOnce(input), receiveSubmitOnce(input)]);

    expect([a.kind, b.kind].filter((k) => k === "SUBMITTED")).toHaveLength(1);
    expect([a.kind, b.kind].filter((k) => k === "AMBIGUOUS")).toHaveLength(1);
    expect(postCount).toBe(1);
    expect(recorder.records).toHaveLength(1);
    expect(claimStore.mints).toBe(1);
    expect(a.claim.attemptId).toBe(b.claim.attemptId);
  });

  it("the losing worker never touches the transport at all", async () => {
    const claimStore = makeClaimStore();
    const recorder = makeRecorder();
    let postCount = 0;
    const exchange: GatewayExchangeTransport = {
      exchange: async () => {
        postCount += 1;
        return {
          endpoint: "https://gw.invalid/",
          endpointFingerprint: "fp",
          requestBytes: REQUEST.bodyBytes,
          requestSha256: "req-sha",
          responseBytes: new TextEncoder().encode('{"status":true}'),
          responseSha256: "resp-sha",
          statusCode: 200,
        };
      },
    };
    const input = makeInput({
      claimStore,
      submitOptions: {
        endpoint: "https://gw.invalid/",
        limits: { readTimeoutMs: 1000, maxRequestBytes: 4096, maxResponseBytes: 4096 },
        recorder,
        exchange,
      },
    });

    await receiveSubmitOnce(input);
    const postsAfterWinner = postCount;

    const loser = await receiveSubmitOnce(input);
    expect(loser.kind).toBe("AMBIGUOUS");
    expect(postCount).toBe(postsAfterWinner);
    expect(recorder.records).toHaveLength(1);
  });

  it("propagates non-ambiguity errors (definite local failures)", async () => {
    await expect(receiveSubmitOnce(makeInput({
      submitOptions: { endpoint: "https://gw.invalid/", limits: { readTimeoutMs: 1000, maxRequestBytes: 4096, maxResponseBytes: 4096 }, recorder: makeRecorder(), exchange: { exchange: async () => { throw new Error("definite local failure"); } } },
    }))).rejects.toThrow("definite local failure");
  });

  it("catches SubmitIndeterminateError from recorder failure and returns AMBIGUOUS", async () => {
    const result = await receiveSubmitOnce(makeInput({
      submitOptions: { endpoint: "https://gw.invalid/", limits: { readTimeoutMs: 1000, maxRequestBytes: 4096, maxResponseBytes: 4096 }, recorder: { recordSubmitAttempt: async () => { throw new Error("db write failed"); } }, exchange: makeFakeExchange(200, '{"status":true}') },
    }));
    expect(result.kind).toBe("AMBIGUOUS");
    if (result.kind === "AMBIGUOUS") {
      expect(result.reason.source).toBe("SUBMIT_OUTCOME_UNKNOWN");
      expect(result.recordedAttempt.decisionId).toBe(DECISION_ID);
    }
  });
});
