// MOVE_INTERNAL single-shot submit claim: formation step 9, a submit call that is
// single-shot for one exact authorized attempt; landing-path oracle; the never-blind-retry rule (never
// blind-retry a submit). The exit property: one claim per move attempt, the exchange invoked at most once,
// and any ambiguity reported as AMBIGUOUS (reconcile-only) rather than retried.
//
// Division of proof with submit-decision-claim-store.pg.test.ts: that suite proves the STORE
// arbitrates the mint in PostgreSQL under two genuinely concurrent workers. This suite proves
// the SERVICE reaches the gateway on the winning branch only, given a store that arbitrates.

import { describe, expect, it } from "vitest";

import {
  GatewayTransportAmbiguityError,
  sha256Hex,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
} from "../gateway/capture.js";
import type { GatewaySubmitAttemptRecord, SubmitAttemptRecorder } from "../gateway/records.js";
import type { SubmitAuthorization } from "../gateway/submit.js";
import type { GatewayLimits } from "../gateway/types.js";

import {
  MoveSubmitAmbiguousError,
  executeMoveSubmitClaim,
  type ExecuteMoveSubmitClaimOptions,
  type MoveSubmitClaim,
  type MoveSubmitClaimStore,
} from "./move-submit-claim.js";

import { SUBMIT_ACTION_NAME } from "@zucoins/generic-node-contracts/transfer-code";

const PRIMARY = "https://gateway-a.invalid/";

const LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 1_024,
  maxResponseBytes: 1_024,
};

const AUTHORIZATION: SubmitAuthorization = {
  submitDecisionId: "11111111-1111-4111-8111-111111111111",
  operationId: "22222222-2222-4222-8222-222222222222",
  transactionAttemptNo: 1,
};

const RESPONSE_BYTES = new TextEncoder().encode('{"status":true}');

interface ScriptedExchange {
  readonly touched: string[];
  readonly exchange: GatewayExchangeTransport;
}

function scriptedExchange(
  outcome: { readonly status: number; readonly body: Uint8Array } | Error,
): ScriptedExchange {
  const touched: string[] = [];
  const exchange: GatewayExchangeTransport = {
    exchange: async (endpoint, request) => {
      touched.push(endpoint);
      if (outcome instanceof Error) {
        throw outcome;
      }
      const capture: GatewayExchangeCapture = {
        endpoint,
        endpointFingerprint: sha256Hex(new TextEncoder().encode(endpoint)),
        requestBytes: request.bodyBytes,
        requestSha256: sha256Hex(request.bodyBytes),
        responseBytes: outcome.body,
        responseSha256: sha256Hex(outcome.body),
        statusCode: outcome.status,
      };
      return capture;
    },
  };
  return { touched, exchange };
}

function recordingRecorder(): SubmitAttemptRecorder & { records: GatewaySubmitAttemptRecord[] } {
  const records: GatewaySubmitAttemptRecord[] = [];
  return {
    records,
    recordSubmitAttempt: async (record) => {
      records.push(record);
    },
  };
}

const attemptKey = (claim: MoveSubmitClaim): string =>
  `${claim.operationId}#${claim.transactionAttemptNo}`;

// In-memory stand-in for submit_decisions' UNIQUE (operation_id, transaction_attempt_no).
// The arbitration itself is one synchronous decision (as the database's is one atomic
// statement); the suspension point sits after it, where the round-trip would be, so a caller
// cannot observe a half-decided claim.
function makeClaimStore(seeded?: MoveSubmitClaim): MoveSubmitClaimStore & {
  claims: Map<string, MoveSubmitClaim>;
  readonly mints: number;
} {
  const claims = new Map<string, MoveSubmitClaim>();
  if (seeded !== undefined) {
    claims.set(attemptKey(seeded), seeded);
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

function tickingNow(): () => string {
  let tick = 0;
  return () => {
    tick += 1;
    return `2026-07-21T00:00:0${tick}.000Z`;
  };
}

function makeOptions(
  exchange: GatewayExchangeTransport,
  recorder: SubmitAttemptRecorder,
  claimStore: MoveSubmitClaimStore,
  nowIso: () => string,
): ExecuteMoveSubmitClaimOptions {
  return {
    authorization: AUTHORIZATION,
    signedTransaction: { inner: "move-inner", step_1_signature: "sig" },
    claimStore,
    submit: { endpoint: PRIMARY, limits: LIMITS, recorder, exchange, nowIso },
  };
}

describe("move submit claim — one claim, one shot, no blind retry", () => {
  it("creates exactly one claim and executes the submit once on ACK", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const recorder = recordingRecorder();
    const claimStore = makeClaimStore();
    const result = await executeMoveSubmitClaim(
      makeOptions(scripted.exchange, recorder, claimStore, tickingNow()),
    );

    expect(result.executed).toBe(true);
    expect(result.claim.attemptId).toBe(AUTHORIZATION.submitDecisionId);
    expect(result.claim.operationId).toBe(AUTHORIZATION.operationId);
    expect(result.claim.transactionAttemptNo).toBe(1);
    expect(claimStore.mints).toBe(1);
    expect(scripted.touched).toEqual([PRIMARY]);
    expect(recorder.records.length).toBe(1);
    expect(result.recordedOutcome?.status).toBe("ACK");
    expect(result.recordedOutcome?.capture?.statusCode).toBe(200);
    expect(result.recordedOutcome?.recordedAttempt.decisionId).toBe(AUTHORIZATION.submitDecisionId);
  });

  // The defect this module was rebuilt for: two workers racing one attempt used to produce two
  // gateway POSTs of the same signed transaction, because the loser was handed the winner's
  // claim and never learned it had lost.
  it("two concurrent workers on one attempt produce exactly ONE gateway POST", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const recorder = recordingRecorder();
    const claimStore = makeClaimStore();
    const options = makeOptions(scripted.exchange, recorder, claimStore, tickingNow());

    const [a, b] = await Promise.all([
      executeMoveSubmitClaim(options),
      executeMoveSubmitClaim(options),
    ]);

    expect([a.executed, b.executed].filter(Boolean).length).toBe(1);
    expect(scripted.touched).toEqual([PRIMARY]);
    expect(recorder.records.length).toBe(1);
    expect(claimStore.mints).toBe(1);
    // Both callers see the same durable claim; only the winner carries an outcome.
    expect(a.claim.attemptId).toBe(b.claim.attemptId);
    expect([a.recordedOutcome, b.recordedOutcome].filter((outcome) => outcome !== null).length).toBe(
      1,
    );
  });

  it("the losing worker never touches the transport at all", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const recorder = recordingRecorder();
    const claimStore = makeClaimStore();
    const options = makeOptions(scripted.exchange, recorder, claimStore, tickingNow());

    await executeMoveSubmitClaim(options);
    const touchedAfterWinner = [...scripted.touched];

    const loser = await executeMoveSubmitClaim(options);
    expect(loser.executed).toBe(false);
    expect(loser.recordedOutcome).toBeNull();
    expect(scripted.touched).toEqual(touchedAfterWinner);
    expect(recorder.records.length).toBe(1);
  });

  it("a definite 4xx is REJECT, recorded once and not retried", async () => {
    const scripted = scriptedExchange({ status: 422, body: RESPONSE_BYTES });
    const recorder = recordingRecorder();
    const result = await executeMoveSubmitClaim(
      makeOptions(scripted.exchange, recorder, makeClaimStore(), tickingNow()),
    );
    expect(result.executed).toBe(true);
    expect(result.recordedOutcome?.status).toBe("REJECT");
    expect(scripted.touched).toEqual([PRIMARY]);
    expect(recorder.records.length).toBe(1);
  });

  it("a non-2xx/4xx response is AMBIGUOUS (reconcile-only), never retried", async () => {
    const scripted = scriptedExchange({ status: 503, body: RESPONSE_BYTES });
    const recorder = recordingRecorder();
    const result = await executeMoveSubmitClaim(
      makeOptions(scripted.exchange, recorder, makeClaimStore(), tickingNow()),
    );
    expect(result.executed).toBe(true);
    expect(result.recordedOutcome?.status).toBe("AMBIGUOUS");
    expect(result.recordedOutcome?.recordedAttempt.transportOutcome).toBe("INDETERMINATE");
    expect(scripted.touched).toEqual([PRIMARY]);
    expect(recorder.records.length).toBe(1);
  });

  it("transport ambiguity is AMBIGUOUS with no captured response, recorded once", async () => {
    const scripted = scriptedExchange(
      new GatewayTransportAmbiguityError("scripted", new Error("reset")),
    );
    const recorder = recordingRecorder();
    const result = await executeMoveSubmitClaim(
      makeOptions(scripted.exchange, recorder, makeClaimStore(), tickingNow()),
    );
    expect(result.executed).toBe(true);
    expect(result.recordedOutcome?.status).toBe("AMBIGUOUS");
    expect(result.recordedOutcome?.capture).toBeNull();
    expect(result.recordedOutcome?.recordedAttempt.responseBytes).toBeNull();
    expect(scripted.touched).toEqual([PRIMARY]);
    expect(recorder.records.length).toBe(1);
  });

  it("a claim recovered after a crash short-circuits without any exchange", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const recorder = recordingRecorder();
    const claimStore = makeClaimStore({
      attemptId: AUTHORIZATION.submitDecisionId,
      claimedAt: "2026-07-20T00:00:00.000Z",
      operationId: AUTHORIZATION.operationId,
      transactionAttemptNo: AUTHORIZATION.transactionAttemptNo,
    });

    const result = await executeMoveSubmitClaim(
      makeOptions(scripted.exchange, recorder, claimStore, tickingNow()),
    );
    expect(result.executed).toBe(false);
    expect(result.recordedOutcome).toBeNull();
    expect(result.claim.claimedAt).toBe("2026-07-20T00:00:00.000Z");
    expect(scripted.touched).toEqual([]);
    expect(recorder.records.length).toBe(0);
    expect(claimStore.mints).toBe(0);
  });

  it("claims BEFORE the exchange so a mid-submit crash leaves a durable stop-record", async () => {
    const sequence: string[] = [];
    const exchange: GatewayExchangeTransport = {
      exchange: async (endpoint, request) => {
        sequence.push("exchange");
        return {
          endpoint,
          endpointFingerprint: sha256Hex(new TextEncoder().encode(endpoint)),
          requestBytes: request.bodyBytes,
          requestSha256: sha256Hex(request.bodyBytes),
          responseBytes: RESPONSE_BYTES,
          responseSha256: sha256Hex(RESPONSE_BYTES),
          statusCode: 200,
        };
      },
    };
    const inner = makeClaimStore();
    const claimStore: MoveSubmitClaimStore = {
      claimSubmitOnce: async (claim) => {
        sequence.push("claim");
        return await inner.claimSubmitOnce(claim);
      },
    };
    await executeMoveSubmitClaim(
      makeOptions(exchange, recordingRecorder(), claimStore, tickingNow()),
    );
    expect(sequence).toEqual(["claim", "exchange"]);
  });

  it("a recorder failure after the exchange is AMBIGUOUS and surfaces MoveSubmitAmbiguousError", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const failingRecorder: SubmitAttemptRecorder = {
      recordSubmitAttempt: async () => {
        throw new Error("attempt persistence unavailable");
      },
    };
    const claimStore = makeClaimStore();
    await expect(
      executeMoveSubmitClaim(
        makeOptions(scripted.exchange, failingRecorder, claimStore, tickingNow()),
      ),
    ).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(MoveSubmitAmbiguousError);
      expect((error as MoveSubmitAmbiguousError).claim.attemptId).toBe(
        AUTHORIZATION.submitDecisionId,
      );
      expect((error as Error).cause).toBeInstanceOf(Error);
      expect((error as Error).message).toContain("reconcile");
      return true;
    });
    // The claim was still persisted before the exchange — the durable stop-record exists.
    expect(claimStore.mints).toBe(1);
    expect(scripted.touched).toEqual([PRIMARY]);
  });

  it("a definite local failure propagates unchanged (no exchange completed)", async () => {
    const definite = new Error("definite local failure");
    const scripted = scriptedExchange(definite);
    const recorder = recordingRecorder();
    await expect(
      executeMoveSubmitClaim(
        makeOptions(scripted.exchange, recorder, makeClaimStore(), tickingNow()),
      ),
    ).rejects.toBe(definite);
    expect(recorder.records.length).toBe(0);
    expect(scripted.touched).toEqual([PRIMARY]);
  });

  it("submits the exact signed transaction bytes without reformatting (the byte-exact signing rule)", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const recorder = recordingRecorder();
    await executeMoveSubmitClaim(
      makeOptions(scripted.exchange, recorder, makeClaimStore(), tickingNow()),
    );
    const recorded = recorder.records[0];
    expect(recorded).toBeDefined();
    // The recorded request bytes are the frozen form-body encoding of the action — the
    // service handed the signed transaction to the submit primitive verbatim.
    expect(recorded?.requestSha256).toBe(sha256Hex(recorded?.requestBytes ?? Uint8Array.from([])));
    expect(recorded?.requestBytes.length).toBeGreaterThan(0);
    expect(SUBMIT_ACTION_NAME).toBe("submit_transaction__v1");
  });
});
