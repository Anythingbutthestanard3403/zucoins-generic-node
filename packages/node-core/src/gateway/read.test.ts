// the bounded, jittered read primitive — endpoint iteration per
// attempt, retry across attempts ONLY for transport ambiguity, one observation record
// per endpoint touched, and fail-closed propagation for everything else.
import { SUBMIT_ACTION_NAME, buildGatewayRequestBody } from "@zucoins/generic-node-contracts/transfer-code";
import { describe, expect, it } from "vitest";

import type { GatewayRequest } from "../protocol/index.js";
import {
  READ_BACKOFF_BASE_MS,
  READ_BACKOFF_JITTER_MS,
  READ_BACKOFF_MAX_MS,
  READ_MAX_ATTEMPTS,
  GatewayReadExhaustedError,
  createGatewayReadTransport,
  readBackoffDelayMs,
  readGatewayAction,
  readGatewayRequest,
  type ReadGatewayRequestOptions,
  type SleepFn,
} from "./read.js";
import { GatewayUnsafeActionError } from "./actions.js";
import {
  GatewayTransportAmbiguityError,
  sha256Hex,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
} from "./capture.js";
import { fingerprintEndpoint, GatewayConfigurationError, createGatewayClient, createGatewayReadCredentials } from "./client.js";
import type { GatewayObservationRecord, ObservationRecorder } from "./records.js";
import type { GatewayLimits } from "./types.js";

const ENDPOINT_A = "https://gateway-a.invalid/";
const ENDPOINT_B = "https://gateway-b.invalid/";

const LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 1_024,
  maxResponseBytes: 1_024,
};

const BODY_OK = Uint8Array.from([1, 2, 3]);
const BODY_ERR = Uint8Array.from([9, 9]);

type ScriptStep =
  | { readonly kind: "capture"; readonly status: number; readonly body: Uint8Array }
  | { readonly kind: "ambiguous" }
  | { readonly kind: "throw"; readonly error: Error };

interface ScriptedExchange {
  readonly touched: string[];
  readonly requests: GatewayRequest[];
  readonly exchange: GatewayExchangeTransport;
}

function scriptedExchange(script: readonly ScriptStep[]): ScriptedExchange {
  const touched: string[] = [];
  const requests: GatewayRequest[] = [];
  let index = 0;
  const exchange: GatewayExchangeTransport = {
    exchange: async (endpoint, request) => {
      touched.push(endpoint);
      requests.push(request);
      const step = script[index];
      index += 1;
      if (step === undefined) {
        throw new Error("exchange script exhausted — more calls than the test planned");
      }
      if (step.kind === "throw") {
        throw step.error;
      }
      if (step.kind === "ambiguous") {
        throw new GatewayTransportAmbiguityError("scripted ambiguity", new Error("transport"));
      }
      const capture: GatewayExchangeCapture = {
        endpoint,
        endpointFingerprint: fingerprintEndpoint(endpoint),
        requestBytes: request.bodyBytes,
        requestSha256: sha256Hex(request.bodyBytes),
        responseBytes: step.body,
        responseSha256: sha256Hex(step.body),
        statusCode: step.status,
      };
      return capture;
    },
  };
  return { touched, requests, exchange };
}

interface RecordingObserver {
  readonly records: GatewayObservationRecord[];
  readonly recorder: ObservationRecorder;
}

function recordingObserver(failing = false): RecordingObserver {
  const records: GatewayObservationRecord[] = [];
  return {
    records,
    recorder: {
      recordObservation: async (record) => {
        if (failing) {
          throw new Error("observation persistence unavailable");
        }
        records.push(record);
      },
    },
  };
}

function options(
  exchange: GatewayExchangeTransport,
  observer: ObservationRecorder,
  endpoints: readonly string[],
  overrides: Partial<ReadGatewayRequestOptions> = {},
): ReadGatewayRequestOptions {
  return {
    endpoints,
    limits: LIMITS,
    recorder: observer,
    exchange,
    sleep: async () => undefined,
    jitter: () => 0,
    nowIso: () => "2026-07-21T00:00:00.000Z",
    ...overrides,
  };
}

const captureStep = (status: number, body: Uint8Array): ScriptStep => ({
  kind: "capture",
  status,
  body,
});
const ambiguousStep: ScriptStep = { kind: "ambiguous" };

describe("bounded read — the first complete response is the authoritative answer", () => {
  it("returns a 2xx capture on the first attempt and records one captured observation", async () => {
    const scripted = scriptedExchange([captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const result = await readGatewayAction(
      "get_transaction__v1",
      { wallet: "w1" },
      options(scripted.exchange, observer.recorder, [ENDPOINT_A]),
    );
    expect(result.capture.statusCode).toBe(200);
    expect(result.capture.responseBytes).toEqual(BODY_OK);
    expect(result.attemptNo).toBe(1);
    expect(scripted.touched).toEqual([ENDPOINT_A]);
    expect(observer.records.length).toBe(1);
    const record = observer.records[0];
    expect(record?.transportAmbiguous).toBe(false);
    expect(record?.httpStatus).toBe(200);
    expect(record?.rawResponseBytes).toEqual(BODY_OK);
    expect(record?.rawResponseSha256).toBe(sha256Hex(BODY_OK));
    expect(record?.endpointFingerprint).toBe(fingerprintEndpoint(ENDPOINT_A));
  });

  it("returns a 5xx capture verbatim — an HTTP response is never a retry trigger", async () => {
    const scripted = scriptedExchange([captureStep(503, BODY_ERR)]);
    const observer = recordingObserver();
    const result = await readGatewayAction(
      "get_transaction__v1",
      {},
      options(scripted.exchange, observer.recorder, [ENDPOINT_A, ENDPOINT_B]),
    );
    expect(result.capture.statusCode).toBe(503);
    expect(scripted.touched).toEqual([ENDPOINT_A]);
    expect(observer.records.length).toBe(1);
  });

  it("builds request bytes identical to the frozen official form-body codec", async () => {
    const scripted = scriptedExchange([captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const actionData = { wallet: "w1", seq: 7 };
    await readGatewayAction(
      "get_transaction__v1",
      actionData,
      options(scripted.exchange, observer.recorder, [ENDPOINT_A]),
    );
    const expected = new TextEncoder().encode(
      buildGatewayRequestBody("get_transaction__v1", actionData),
    );
    expect(scripted.requests[0]?.bodyBytes).toEqual(expected);
  });
});

describe("endpoint iteration and bounded retry — transport ambiguity only", () => {
  it("iterates to the next endpoint on ambiguity within the same attempt", async () => {
    const scripted = scriptedExchange([ambiguousStep, captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const result = await readGatewayAction(
      "get_transaction__v1",
      {},
      options(scripted.exchange, observer.recorder, [ENDPOINT_A, ENDPOINT_B]),
    );
    expect(result.attemptNo).toBe(1);
    expect(scripted.touched).toEqual([ENDPOINT_A, ENDPOINT_B]);
    expect(observer.records.length).toBe(2);
    const ambiguousRecord = observer.records[0];
    expect(ambiguousRecord?.transportAmbiguous).toBe(true);
    expect(ambiguousRecord?.httpStatus).toBeNull();
    expect(ambiguousRecord?.rawResponseBytes).toBeNull();
    expect(ambiguousRecord?.rawResponseSha256).toBeNull();
    expect(ambiguousRecord?.endpointFingerprint).toBe(fingerprintEndpoint(ENDPOINT_A));
    expect(observer.records[1]?.transportAmbiguous).toBe(false);
    expect(observer.records[1]?.endpointFingerprint).toBe(fingerprintEndpoint(ENDPOINT_B));
  });

  it("retries across attempts with the capped exponential backoff sequence", async () => {
    const scripted = scriptedExchange([
      ambiguousStep,
      ambiguousStep,
      ambiguousStep,
      captureStep(200, BODY_OK),
    ]);
    const observer = recordingObserver();
    const sleeps: number[] = [];
    const sleep: SleepFn = async (ms) => {
      sleeps.push(ms);
    };
    const result = await readGatewayAction(
      "get_transaction__v1",
      {},
      options(scripted.exchange, observer.recorder, [ENDPOINT_A], { sleep }),
    );
    expect(result.attemptNo).toBe(4);
    expect(sleeps).toEqual([
      READ_BACKOFF_BASE_MS,
      READ_BACKOFF_BASE_MS * 2,
      READ_BACKOFF_BASE_MS * 4,
    ]);
    expect(observer.records.length).toBe(4);
  });

  it("exhausts after READ_MAX_ATTEMPTS passes over every endpoint and reports each failure", async () => {
    const steps = Array.from({ length: READ_MAX_ATTEMPTS * 2 }, () => ambiguousStep);
    const scripted = scriptedExchange(steps);
    const observer = recordingObserver();
    const sleeps: number[] = [];
    const sleep: SleepFn = async (ms) => {
      sleeps.push(ms);
    };
    await expect(
      readGatewayAction(
        "get_transaction__v1",
        {},
        options(scripted.exchange, observer.recorder, [ENDPOINT_A, ENDPOINT_B], { sleep }),
      ),
    ).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(GatewayReadExhaustedError);
      expect((error as GatewayReadExhaustedError).failures.length).toBe(READ_MAX_ATTEMPTS * 2);
      return true;
    });
    expect(scripted.touched.length).toBe(READ_MAX_ATTEMPTS * 2);
    expect(sleeps.length).toBe(READ_MAX_ATTEMPTS - 1);
    expect(observer.records.length).toBe(READ_MAX_ATTEMPTS * 2);
    expect(observer.records.every((record) => record.transportAmbiguous)).toBe(true);
  });

  it("a custom maxAttempts changes runtime exhaustion count (fewer than READ_MAX_ATTEMPTS)", async () => {
    const customMaxAttempts = 2;
    const steps = Array.from({ length: customMaxAttempts }, () => ambiguousStep);
    const scripted = scriptedExchange(steps);
    const observer = recordingObserver();
    const sleeps: number[] = [];
    const sleep: SleepFn = async (ms) => {
      sleeps.push(ms);
    };
    await expect(
      readGatewayAction(
        "get_transaction__v1",
        {},
        options(scripted.exchange, observer.recorder, [ENDPOINT_A], {
          sleep,
          maxAttempts: customMaxAttempts,
        }),
      ),
    ).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(GatewayReadExhaustedError);
      expect((error as GatewayReadExhaustedError).failures.length).toBe(customMaxAttempts);
      return true;
    });
    expect(scripted.touched.length).toBe(customMaxAttempts);
    expect(sleeps.length).toBe(customMaxAttempts - 1);
  });

  it("a custom backoffMaxMs caps the actual sleep sequence below the default cap", async () => {
    const scripted = scriptedExchange([
      ambiguousStep,
      ambiguousStep,
      ambiguousStep,
      captureStep(200, BODY_OK),
    ]);
    const observer = recordingObserver();
    const sleeps: number[] = [];
    const sleep: SleepFn = async (ms) => {
      sleeps.push(ms);
    };
    const customBackoffMaxMs = 300;
    const result = await readGatewayAction(
      "get_transaction__v1",
      {},
      options(scripted.exchange, observer.recorder, [ENDPOINT_A], {
        sleep,
        backoffMaxMs: customBackoffMaxMs,
      }),
    );
    expect(result.attemptNo).toBe(4);
    // Default-cap behavior (see "retries across attempts with the capped exponential backoff
    // sequence" above) is [250, 500, 1000] — this proves the custom ceiling actually changes
    // the values threaded through the real retry loop, not just readBackoffDelayMs in isolation.
    expect(sleeps).toEqual([READ_BACKOFF_BASE_MS, customBackoffMaxMs, customBackoffMaxMs]);
  });

  it("a non-ambiguity exchange error propagates immediately without consuming attempts", async () => {
    const definite = new Error("definite local failure");
    const scripted = scriptedExchange([{ kind: "throw", error: definite }]);
    const observer = recordingObserver();
    await expect(
      readGatewayAction(
        "get_transaction__v1",
        {},
        options(scripted.exchange, observer.recorder, [ENDPOINT_A, ENDPOINT_B]),
      ),
    ).rejects.toBe(definite);
    expect(scripted.touched).toEqual([ENDPOINT_A]);
    expect(observer.records.length).toBe(0);
  });

  it("a recorder failure fails closed — no retry past the failing record", async () => {
    const scripted = scriptedExchange([captureStep(200, BODY_OK), captureStep(200, BODY_OK)]);
    const observer = recordingObserver(true);
    await expect(
      readGatewayAction(
        "get_transaction__v1",
        {},
        options(scripted.exchange, observer.recorder, [ENDPOINT_A, ENDPOINT_B]),
      ),
    ).rejects.toThrow("observation persistence unavailable");
    expect(scripted.touched).toEqual([ENDPOINT_A]);
  });

  it("rejects an empty endpoint list fail-closed", async () => {
    const scripted = scriptedExchange([]);
    const observer = recordingObserver();
    await expect(
      readGatewayAction("get_transaction__v1", {}, options(scripted.exchange, observer.recorder, [])),
    ).rejects.toBeInstanceOf(GatewayConfigurationError);
  });
});

describe("backoff schedule — finite, capped, jittered", () => {
  it("doubles per attempt from the base and caps at the maximum", () => {
    expect(readBackoffDelayMs(1, () => 0)).toBe(READ_BACKOFF_BASE_MS);
    expect(readBackoffDelayMs(2, () => 0)).toBe(READ_BACKOFF_BASE_MS * 2);
    expect(readBackoffDelayMs(3, () => 0)).toBe(READ_BACKOFF_BASE_MS * 4);
    expect(readBackoffDelayMs(10, () => 0)).toBe(READ_BACKOFF_MAX_MS);
    expect(readBackoffDelayMs(64, () => 0)).toBe(READ_BACKOFF_MAX_MS);
  });

  it("adds bounded jitter on top of the capped base", () => {
    expect(readBackoffDelayMs(1, () => 1)).toBe(READ_BACKOFF_BASE_MS + READ_BACKOFF_JITTER_MS);
    expect(readBackoffDelayMs(1, () => 0.5)).toBe(READ_BACKOFF_BASE_MS + READ_BACKOFF_JITTER_MS / 2);
    expect(readBackoffDelayMs(32, () => 1)).toBe(READ_BACKOFF_MAX_MS + READ_BACKOFF_JITTER_MS);
  });

  it("honors a custom backoffMaxMs ceiling in place of READ_BACKOFF_MAX_MS", () => {
    expect(readBackoffDelayMs(1, () => 0, 1_000)).toBe(READ_BACKOFF_BASE_MS);
    expect(readBackoffDelayMs(10, () => 0, 1_000)).toBe(1_000);
    expect(readBackoffDelayMs(10, () => 1, 1_000)).toBe(1_000 + READ_BACKOFF_JITTER_MS);
  });
});

describe("structural read-safety — the submit action cannot enter this path (the never-blind-retry rule)", () => {
  it("the runtime guard rejects a cast bypass before any endpoint is touched", async () => {
    const scripted = scriptedExchange([captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const bypassed = "submit_transaction__v1" as unknown as "get_transaction__v1";
    await expect(
      readGatewayAction(
        bypassed,
        {},
        options(scripted.exchange, observer.recorder, [ENDPOINT_A]),
      ),
    ).rejects.toBeInstanceOf(GatewayUnsafeActionError);
    expect(scripted.touched.length).toBe(0);
    expect(observer.records.length).toBe(0);
  });

  it("readGatewayRequest rejects an unsafe rpc at the lowest layer — zero endpoints touched", async () => {
    const scripted = scriptedExchange([captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const request: GatewayRequest = { rpc: SUBMIT_ACTION_NAME, bodyBytes: Uint8Array.from([1]) };
    await expect(
      readGatewayRequest(
        request,
        options(scripted.exchange, observer.recorder, [ENDPOINT_A, ENDPOINT_B]),
      ),
    ).rejects.toBeInstanceOf(GatewayUnsafeActionError);
    expect(scripted.touched.length).toBe(0);
    expect(observer.records.length).toBe(0);
  });

  it("the transport adapter rejects the submit rpc before any exchange occurs", async () => {
    const scripted = scriptedExchange([captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const transport = createGatewayReadTransport({
      credentials: createGatewayReadCredentials(),
      limits: LIMITS,
      recorder: observer.recorder,
      exchange: scripted.exchange,
      sleep: async () => undefined,
      jitter: () => 0,
    });
    const request: GatewayRequest = { rpc: SUBMIT_ACTION_NAME, bodyBytes: Uint8Array.from([1]) };
    await expect(transport.read([ENDPOINT_A], request)).rejects.toBeInstanceOf(
      GatewayUnsafeActionError,
    );
    expect(scripted.touched.length).toBe(0);
    expect(observer.records.length).toBe(0);
  });
});

describe("maxAttempts — boundedness is structural, not merely the default (fail-closed)", () => {
  it.each([0, -1, 1.5, Infinity, NaN])(
    "rejects maxAttempts %p before any endpoint is touched",
    async (maxAttempts) => {
      const scripted = scriptedExchange([captureStep(200, BODY_OK)]);
      const observer = recordingObserver();
      const request: GatewayRequest = {
        rpc: "get_transaction__v1",
        bodyBytes: Uint8Array.from([1]),
      };
      await expect(
        readGatewayRequest(
          request,
          options(scripted.exchange, observer.recorder, [ENDPOINT_A], { maxAttempts }),
        ),
      ).rejects.toBeInstanceOf(GatewayConfigurationError);
      expect(scripted.touched.length).toBe(0);
      expect(observer.records.length).toBe(0);
    },
  );
});

describe("backoffMaxMs — boundedness is structural, not merely the default (fail-closed)", () => {
  it.each([0, -1, 1.5, Infinity, NaN])(
    "rejects backoffMaxMs %p before any endpoint is touched",
    async (backoffMaxMs) => {
      const scripted = scriptedExchange([captureStep(200, BODY_OK)]);
      const observer = recordingObserver();
      const request: GatewayRequest = {
        rpc: "get_transaction__v1",
        bodyBytes: Uint8Array.from([1]),
      };
      await expect(
        readGatewayRequest(
          request,
          options(scripted.exchange, observer.recorder, [ENDPOINT_A], { backoffMaxMs }),
        ),
      ).rejects.toBeInstanceOf(GatewayConfigurationError);
      expect(scripted.touched.length).toBe(0);
      expect(observer.records.length).toBe(0);
    },
  );
});

describe("adapter — createGatewayReadTransport under createGatewayClient", () => {
  it("client.read resolves the endpoint list into the bounded primitive and returns the raw response", async () => {
    const scripted = scriptedExchange([ambiguousStep, captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const client = createGatewayClient({
      gatewayUrls: `${ENDPOINT_A},${ENDPOINT_B}`,
      readTransport: createGatewayReadTransport({
        credentials: createGatewayReadCredentials(),
        limits: LIMITS,
        recorder: observer.recorder,
        exchange: scripted.exchange,
        sleep: async () => undefined,
        jitter: () => 0,
      }),
    });
    const request: GatewayRequest = { rpc: "get_transaction__v1", bodyBytes: Uint8Array.from([5]) };
    const response = await client.read(request);
    expect(response.statusCode).toBe(200);
    expect(response.bodyBytes).toEqual(BODY_OK);
    expect(scripted.touched).toEqual(client.endpoints.slice(0, 2));
    expect(observer.records.length).toBe(2);
  });

  it("readGatewayRequest is the request-level core the typed entry point delegates to", async () => {
    const scripted = scriptedExchange([captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const request: GatewayRequest = { rpc: "get_transaction__v1", bodyBytes: Uint8Array.from([7]) };
    const result = await readGatewayRequest(
      request,
      options(scripted.exchange, observer.recorder, [ENDPOINT_A]),
    );
    expect(result.capture.statusCode).toBe(200);
    expect(scripted.requests[0]).toBe(request);
  });
});
