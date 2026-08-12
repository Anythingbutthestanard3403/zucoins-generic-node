// the isolated single-shot submit — exactly ONE exchange against
// exactly ONE endpoint per authorization, ACK/REJECT/INDETERMINATE classification, one
// append-only attempt record per shot, and reconcile-only semantics on indeterminacy
// (ACK is receipt-only; never settlement).
import { SUBMIT_ACTION_NAME, buildGatewayRequestBody } from "@zucoins/generic-node-contracts/transfer-code";
import { describe, expect, it } from "vitest";

import * as submitModule from "./submit.js";
import {
  SubmitIndeterminateError,
  classifySubmitCapture,
  classifySubmitHttpStatus,
  createSingleShotSubmitTransport,
  submitGatewayActionOnce,
  type SubmitAuthorization,
  type SubmitGatewayActionOptions,
} from "./submit.js";
import {
  GatewayTransportAmbiguityError,
  sha256Hex,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
} from "./capture.js";
import { fingerprintEndpoint, GatewayConfigurationError, createGatewayClient, createGatewayReadCredentials, createGatewaySubmitCredentials, enableGatewaySubmit } from "./client.js";
import type { GatewaySubmitAttemptRecord, SubmitAttemptRecorder } from "./records.js";
import type { GatewayLimits } from "./types.js";
import type { GatewayRequest } from "../protocol/index.js";

const PRIMARY = "https://gateway-a.invalid/";
const SECONDARY = "https://gateway-b.invalid/";

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

const RESPONSE_BYTES = Uint8Array.from([123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 116, 114, 117, 101, 125]);

interface ScriptedExchange {
  readonly touched: string[];
  readonly requests: GatewayRequest[];
  readonly exchange: GatewayExchangeTransport;
}

function scriptedExchange(
  outcome: { readonly status: number; readonly body: Uint8Array } | Error,
): ScriptedExchange {
  const touched: string[] = [];
  const requests: GatewayRequest[] = [];
  const exchange: GatewayExchangeTransport = {
    exchange: async (endpoint, request) => {
      touched.push(endpoint);
      requests.push(request);
      if (outcome instanceof Error) {
        throw outcome;
      }
      const capture: GatewayExchangeCapture = {
        endpoint,
        endpointFingerprint: fingerprintEndpoint(endpoint),
        requestBytes: request.bodyBytes,
        requestSha256: sha256Hex(request.bodyBytes),
        responseBytes: outcome.body,
        responseSha256: sha256Hex(outcome.body),
        statusCode: outcome.status,
      };
      return capture;
    },
  };
  return { touched, requests, exchange };
}

interface RecordingRecorder {
  readonly records: GatewaySubmitAttemptRecord[];
  readonly recorder: SubmitAttemptRecorder;
}

function recordingRecorder(): RecordingRecorder {
  const records: GatewaySubmitAttemptRecord[] = [];
  return {
    records,
    recorder: {
      recordSubmitAttempt: async (record) => {
        records.push(record);
      },
    },
  };
}

function options(exchange: GatewayExchangeTransport, recorder: SubmitAttemptRecorder): SubmitGatewayActionOptions {
  return {
    endpoint: PRIMARY,
    limits: LIMITS,
    recorder,
    exchange,
    nowIso: (() => {
      let tick = 0;
      return () => {
        tick += 1;
        return `2026-07-21T00:00:0${tick}.000Z`;
      };
    })(),
  };
}

describe("outcome classification — the table", () => {
  it.each([200, 201, 204, 299])("HTTP %i is ACK (receipt only)", (status) => {
    expect(classifySubmitHttpStatus(status)).toBe("ACK");
  });

  it.each([400, 404, 409, 422, 429, 499])("HTTP %i is REJECT (definite gateway answer)", (status) => {
    expect(classifySubmitHttpStatus(status)).toBe("REJECT");
  });

  it.each([100, 301, 302, 500, 502, 503, 599])("HTTP %i is INDETERMINATE (reconcile-only)", (status) => {
    expect(classifySubmitHttpStatus(status)).toBe("INDETERMINATE");
  });

  const wellFormedAck = new TextEncoder().encode('{"status":true,"code":"ok","message":"","data":{}}');
  const wellFormedRejectBody = new TextEncoder().encode(
    '{"status":false,"code":"invalid","message":"no","data":null}',
  );

  it("2xx with a well-formed status boolean is ACK", () => {
    expect(classifySubmitCapture(200, wellFormedAck)).toBe("ACK");
    expect(classifySubmitCapture(204, wellFormedRejectBody)).toBe("ACK");
  });

  it("2xx with an empty body is INDETERMINATE (never a false receipt)", () => {
    expect(classifySubmitCapture(200, new Uint8Array())).toBe("INDETERMINATE");
    expect(classifySubmitCapture(200, null)).toBe("INDETERMINATE");
  });

  it("2xx with non-JSON or status-less JSON is INDETERMINATE", () => {
    expect(classifySubmitCapture(200, new TextEncoder().encode("not-json"))).toBe("INDETERMINATE");
    expect(classifySubmitCapture(200, new TextEncoder().encode('{"code":"ok"}'))).toBe(
      "INDETERMINATE",
    );
    expect(classifySubmitCapture(200, new TextEncoder().encode('{"status":"true"}'))).toBe(
      "INDETERMINATE",
    );
    expect(classifySubmitCapture(200, new TextEncoder().encode("[]"))).toBe("INDETERMINATE");
  });

  it("4xx stays REJECT and 5xx stays INDETERMINATE regardless of body", () => {
    expect(classifySubmitCapture(422, wellFormedRejectBody)).toBe("REJECT");
    expect(classifySubmitCapture(422, new Uint8Array())).toBe("REJECT");
    expect(classifySubmitCapture(503, wellFormedAck)).toBe("INDETERMINATE");
  });
});

describe("the single shot — one exchange, one record, no second call on any branch", () => {
  it("ACK: records the exact request and response bytes with digests and returns the capture", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const recording = recordingRecorder();
    const result = await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      { transaction: "t" },
      AUTHORIZATION,
      options(scripted.exchange, recording.recorder),
    );
    expect(result.transportOutcome).toBe("ACK");
    expect(result.capture?.statusCode).toBe(200);
    expect(scripted.touched).toEqual([PRIMARY]);
    expect(scripted.requests.length).toBe(1);

    const expectedRequestBytes = new TextEncoder().encode(
      buildGatewayRequestBody(SUBMIT_ACTION_NAME, { transaction: "t" }),
    );
    expect(result.recordedAttempt.requestBytes).toEqual(expectedRequestBytes);
    expect(result.recordedAttempt.requestSha256).toBe(sha256Hex(expectedRequestBytes));
    expect(result.recordedAttempt.responseBytes).toEqual(RESPONSE_BYTES);
    expect(result.recordedAttempt.responseSha256).toBe(sha256Hex(RESPONSE_BYTES));
    expect(result.recordedAttempt.decisionId).toBe(AUTHORIZATION.submitDecisionId);
    expect(result.recordedAttempt.operationId).toBe(AUTHORIZATION.operationId);
    expect(result.recordedAttempt.attemptNo).toBe(1);
    expect(result.recordedAttempt.transactionAttemptNo).toBe(1);
    expect(result.recordedAttempt.startedAt).toBe("2026-07-21T00:00:01.000Z");
    expect(result.recordedAttempt.completedAt).toBe("2026-07-21T00:00:02.000Z");
    expect(recording.records).toEqual([result.recordedAttempt]);
  });

  it("INDETERMINATE: a 2xx with an empty body is recorded reconcile-only (never a false ACK)", async () => {
    const scripted = scriptedExchange({ status: 200, body: new Uint8Array() });
    const recording = recordingRecorder();
    const result = await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      { transaction: "t" },
      AUTHORIZATION,
      options(scripted.exchange, recording.recorder),
    );
    expect(result.transportOutcome).toBe("INDETERMINATE");
    expect(result.capture?.statusCode).toBe(200);
    expect(result.capture?.responseBytes.byteLength).toBe(0);
    expect(recording.records[0]?.transportOutcome).toBe("INDETERMINATE");
    expect(scripted.touched).toEqual([PRIMARY]);
  });

  it("REJECT: a definite 4xx is recorded and returned, not retried", async () => {
    const scripted = scriptedExchange({ status: 422, body: RESPONSE_BYTES });
    const recording = recordingRecorder();
    const result = await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      {},
      AUTHORIZATION,
      options(scripted.exchange, recording.recorder),
    );
    expect(result.transportOutcome).toBe("REJECT");
    expect(result.capture?.statusCode).toBe(422);
    expect(scripted.touched).toEqual([PRIMARY]);
    expect(recording.records.length).toBe(1);
    expect(recording.records[0]?.transportOutcome).toBe("REJECT");
  });

  it("INDETERMINATE: a 5xx response is captured, recorded, and classified reconcile-only", async () => {
    const scripted = scriptedExchange({ status: 503, body: RESPONSE_BYTES });
    const recording = recordingRecorder();
    const result = await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      {},
      AUTHORIZATION,
      options(scripted.exchange, recording.recorder),
    );
    expect(result.transportOutcome).toBe("INDETERMINATE");
    expect(result.capture?.statusCode).toBe(503);
    expect(recording.records[0]?.responseBytes).toEqual(RESPONSE_BYTES);
    expect(recording.records[0]?.transportOutcome).toBe("INDETERMINATE");
    expect(scripted.touched).toEqual([PRIMARY]);
  });

  it("INDETERMINATE: transport ambiguity records null response fields and no capture", async () => {
    const ambiguity = new GatewayTransportAmbiguityError("scripted", new Error("timeout"));
    const scripted = scriptedExchange(ambiguity);
    const recording = recordingRecorder();
    const result = await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      {},
      AUTHORIZATION,
      options(scripted.exchange, recording.recorder),
    );
    expect(result.transportOutcome).toBe("INDETERMINATE");
    expect(result.capture).toBeNull();
    expect(recording.records.length).toBe(1);
    const record = recording.records[0];
    expect(record?.responseBytes).toBeNull();
    expect(record?.responseSha256).toBeNull();
    expect(record?.transportOutcome).toBe("INDETERMINATE");
    expect(record?.requestSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(scripted.touched).toEqual([PRIMARY]);
  });

  it("a definite local failure propagates without an attempt record — no exchange occurred", async () => {
    const definite = new Error("definite local failure");
    const scripted = scriptedExchange(definite);
    const recording = recordingRecorder();
    await expect(
      submitGatewayActionOnce(SUBMIT_ACTION_NAME, {}, AUTHORIZATION, options(scripted.exchange, recording.recorder)),
    ).rejects.toBe(definite);
    expect(recording.records.length).toBe(0);
    expect(scripted.touched).toEqual([PRIMARY]);
  });

  it("a recorder failure AFTER a completed exchange is INDETERMINATE, with the recorder error as cause", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const recorderError = new Error("attempt persistence unavailable");
    const failingRecorder: SubmitAttemptRecorder = {
      recordSubmitAttempt: async () => {
        throw recorderError;
      },
    };
    await expect(
      submitGatewayActionOnce(
        SUBMIT_ACTION_NAME,
        {},
        AUTHORIZATION,
        options(scripted.exchange, failingRecorder),
      ),
    ).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(SubmitIndeterminateError);
      expect((error as SubmitIndeterminateError).recordedAttempt.transportOutcome).toBe("ACK");
      expect((error as SubmitIndeterminateError).recordedAttempt.responseBytes).toEqual(
        RESPONSE_BYTES,
      );
      expect((error as Error).cause).toBe(recorderError);
      return true;
    });
    expect(scripted.touched).toEqual([PRIMARY]);
  });
});

describe("adapter — the submit path targets ONLY the primary endpoint", () => {
  it("makes exactly one call against the first endpoint even when handed the full list", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const recording = recordingRecorder();
    const transport = createSingleShotSubmitTransport({
      credentials: createGatewaySubmitCredentials(),
      limits: LIMITS,
      recorder: recording.recorder,
      authorization: AUTHORIZATION,
      exchange: scripted.exchange,
    });
    const request: GatewayRequest = { rpc: SUBMIT_ACTION_NAME, bodyBytes: Uint8Array.from([1]) };
    const response = await transport.submit([PRIMARY, SECONDARY], request);
    expect(response.statusCode).toBe(200);
    expect(response.bodyBytes).toEqual(RESPONSE_BYTES);
    expect(scripted.touched).toEqual([PRIMARY]);
  });

  it("raises SubmitIndeterminateError on an ambiguous shot — never a response a caller could trust", async () => {
    const ambiguity = new GatewayTransportAmbiguityError("scripted", new Error("reset"));
    const scripted = scriptedExchange(ambiguity);
    const recording = recordingRecorder();
    const transport = createSingleShotSubmitTransport({
      credentials: createGatewaySubmitCredentials(),
      limits: LIMITS,
      recorder: recording.recorder,
      authorization: AUTHORIZATION,
      exchange: scripted.exchange,
    });
    const request: GatewayRequest = { rpc: SUBMIT_ACTION_NAME, bodyBytes: Uint8Array.from([1]) };
    await expect(transport.submit([PRIMARY, SECONDARY], request)).rejects.toSatisfy(
      (error: unknown) => {
        expect(error).toBeInstanceOf(SubmitIndeterminateError);
        expect((error as SubmitIndeterminateError).recordedAttempt.transportOutcome).toBe(
          "INDETERMINATE",
        );
        expect((error as Error).message).toContain("reconcile");
        return true;
      },
    );
    expect(scripted.touched).toEqual([PRIMARY]);
    expect(recording.records.length).toBe(1);
  });

  it("rejects an empty endpoint list fail-closed", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const recording = recordingRecorder();
    const transport = createSingleShotSubmitTransport({
      credentials: createGatewaySubmitCredentials(),
      limits: LIMITS,
      recorder: recording.recorder,
      authorization: AUTHORIZATION,
      exchange: scripted.exchange,
    });
    const request: GatewayRequest = { rpc: SUBMIT_ACTION_NAME, bodyBytes: Uint8Array.from([1]) };
    await expect(transport.submit([], request)).rejects.toBeInstanceOf(GatewayConfigurationError);
    expect(scripted.touched.length).toBe(0);
  });

  it("wires through createGatewayClient + enableGatewaySubmit end to end", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const recording = recordingRecorder();
    const client = createGatewayClient({
      gatewayUrls: `${PRIMARY},${SECONDARY}`,
      readTransport: { credentials: createGatewayReadCredentials(), read: async () => ({ statusCode: 200, bodyBytes: Uint8Array.from([]) }) },
      submitCapability: enableGatewaySubmit(
        createSingleShotSubmitTransport({
          credentials: createGatewaySubmitCredentials(),
          limits: LIMITS,
          recorder: recording.recorder,
          authorization: AUTHORIZATION,
          exchange: scripted.exchange,
        }),
      ),
    });
    expect(client.canSubmit).toBe(true);
    const request: GatewayRequest = { rpc: SUBMIT_ACTION_NAME, bodyBytes: Uint8Array.from([2]) };
    const response = await client.submit(request);
    expect(response.statusCode).toBe(200);
    expect(scripted.touched).toEqual([PRIMARY]);
    expect(recording.records.length).toBe(1);
  });
});

describe("ACK is receipt-only — no settlement adjudication lives in this module (landing-path oracle)", () => {
  it("exports no settlement/landing surface", () => {
    const names = Object.keys(submitModule);
    expect(names.some((name) => /settl|landed|landing/i.test(name))).toBe(false);
  });

  it("an ACK result carries only the transport outcome and the captured evidence", async () => {
    const scripted = scriptedExchange({ status: 200, body: RESPONSE_BYTES });
    const recording = recordingRecorder();
    const result = await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      {},
      AUTHORIZATION,
      options(scripted.exchange, recording.recorder),
    );
    expect(Object.keys(result).sort()).toEqual(["capture", "recordedAttempt", "transportOutcome"]);
    expect(Object.keys(result.recordedAttempt).sort()).toEqual([
      "attemptNo",
      "completedAt",
      "decisionId",
      "operationId",
      "requestBytes",
      "requestSha256",
      "responseBytes",
      "responseSha256",
      "startedAt",
      "transactionAttemptNo",
      "transportOutcome",
    ]);
  });
});
