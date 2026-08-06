// engine mechanics of the deterministic fake gateway — wire-form
// byte-identity against the frozen codec (production gateway transport), the scripted outcome vocabulary, the
// submit-attempt counter ("exactly one submit attempt, ever"), degraded-mode
// failure budgets, and fake-endpoint configuration. Test-support only
// production src/ must never import testkit.

import { describe, expect, it } from "vitest";
import {
  GATEWAY_ACTION_FIELDS,
  GATEWAY_FORM_BODY_PARAM,
  GATEWAY_RESPONSE_FIELDS,
  SUBMIT_ACTION_NAME,
  buildGatewayRequestBody,
} from "@zucoins/generic-node-contracts/transfer-code";
import {
  GatewayReadExhaustedError,
  GatewayRequestTooLargeError,
  GatewayTransportAmbiguityError,
  SubmitIndeterminateError,
  buildGatewayActionRequest,
  createGatewayExchangeTransport,
  readBackoffDelayMs,
  sha256Hex,
} from "../gateway/index.js";
import {
  FakeGatewayScriptExhaustedError,
  createFakeGateway,
  createFakeGatewayReadTransport,
  createFakeGatewaySubmitTransport,
} from "./gateway-fake.js";
import {
  FakeGatewayProtocolError,
  parseGatewayFormBody,
  serializeGatewayEnvelope,
  type FakeGatewayEnvelope,
} from "./gateway-fake-wire.js";
import {
  AUTHORIZATION,
  LIMITS,
  PRIMARY,
  READ_ACTION_DATA,
  SECONDARY,
  TX,
  WALLET_KEY,
  observationRecorder,
  submitRecorder,
} from "./gateway-fake-fixtures.js";

const GET_TX = "get_transaction__v1" as const;
const HEAD_OK: FakeGatewayEnvelope = { status: true, code: "ok", message: "OK", data: { head: "head-link-1" } };

function decodeEnvelope(bodyBytes: Uint8Array): FakeGatewayEnvelope {
  return JSON.parse(new TextDecoder().decode(bodyBytes)) as FakeGatewayEnvelope;
}

describe("wire-form fidelity — byte-identity against the frozen codec (production gateway transport)", () => {
  it("parses the exact request form the frozen codec produces", () => {
    const wire = buildGatewayRequestBody(GET_TX, READ_ACTION_DATA);

    const parsed = parseGatewayFormBody(new TextEncoder().encode(wire));

    expect(parsed.actionName).toBe(GET_TX);
    expect(parsed.actionData).toEqual(READ_ACTION_DATA);
  });

  it("round-trips through the real exchange transport byte-identically", async () => {
    const fake = createFakeGateway();
    fake.scriptRead(GET_TX, { kind: "envelope", envelope: HEAD_OK });
    const exchange = createGatewayExchangeTransport({ limits: LIMITS, fetchFn: fake.fetch });
    const request = buildGatewayActionRequest(GET_TX, READ_ACTION_DATA);

    const capture = await exchange.exchange(PRIMARY, request);

    // The bytes the fake saw are exactly the frozen codec's output: no re-serialization
    // anywhere on the path (request.ts builds via buildGatewayRequestBody; the exchange
    // passes request.bodyBytes through untouched).
    expect(new TextDecoder().decode(capture.requestBytes)).toBe(buildGatewayRequestBody(GET_TX, READ_ACTION_DATA));
    const parsed = parseGatewayFormBody(capture.requestBytes);
    expect(parsed.actionName).toBe(GET_TX);
    expect(parsed.actionData).toEqual(READ_ACTION_DATA);
    // And the response body is exactly the frozen envelope serialization.
    expect(new TextDecoder().decode(capture.responseBytes)).toBe(serializeGatewayEnvelope(HEAD_OK));
  });

  it("serializes envelopes with the exact frozen response field sequence", () => {
    const body = serializeGatewayEnvelope({ status: true, code: "ok", message: "OK", data: { head: "h" } });

    const keys = Object.keys(JSON.parse(body) as Record<string, unknown>);
    expect(keys).toEqual([...GATEWAY_RESPONSE_FIELDS]);
    expect(GATEWAY_ACTION_FIELDS).toEqual(["action_name", "action_data"]);
    expect(GATEWAY_FORM_BODY_PARAM).toBe("v");
  });

  it("rejects bodies that are not the frozen form", () => {
    expect(() => parseGatewayFormBody(new TextEncoder().encode("not-a-form-body"))).toThrow(FakeGatewayProtocolError);
    const missingAction = `${GATEWAY_FORM_BODY_PARAM}=${encodeURIComponent(JSON.stringify({ action_data: {} }))}`;
    expect(() => parseGatewayFormBody(new TextEncoder().encode(missingAction))).toThrow(FakeGatewayProtocolError);
  });
});

describe("scripted outcome engine", () => {
  it("serves a head-only success body", async () => {
    const fake = createFakeGateway();
    fake.scriptRead(GET_TX, { kind: "envelope", envelope: HEAD_OK });
    const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });

    const response = await read.read([PRIMARY], buildGatewayActionRequest(GET_TX, READ_ACTION_DATA));

    expect(response.statusCode).toBe(200);
    expect(decodeEnvelope(response.bodyBytes).data).toEqual({ head: "head-link-1" });
    expect(fake.readExchangeCount(GET_TX)).toBe(1);
  });

  it("serves malformed and non-envelope bodies for parsing-failure drills", async () => {
    const fake = createFakeGateway();
    fake.scriptRead(
      GET_TX,
      { kind: "raw-body", httpStatus: 200, body: "{not json" },
      { kind: "empty-body", httpStatus: 200 },
      { kind: "raw-body", httpStatus: 200, body: JSON.stringify({ unexpected: true }) },
    );
    const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });
    const request = buildGatewayActionRequest(GET_TX, READ_ACTION_DATA);

    const first = await read.read([PRIMARY], request);
    expect(() => JSON.parse(new TextDecoder().decode(first.bodyBytes))).toThrow();

    const second = await read.read([PRIMARY], request);
    expect(second.bodyBytes.byteLength).toBe(0);

    const third = await read.read([PRIMARY], request);
    const thirdParsed = JSON.parse(new TextDecoder().decode(third.bodyBytes)) as Record<string, unknown>;
    expect(thirdParsed.status).toBeUndefined();
  });

  it("serves dropped connections as transport ambiguity", async () => {
    const fake = createFakeGateway();
    fake.scriptRead(GET_TX, { kind: "drop" });
    const read = createFakeGatewayReadTransport(fake, {
      limits: LIMITS,
      recorder: observationRecorder(),
      maxAttempts: 1,
    });

    await expect(read.read([PRIMARY], buildGatewayActionRequest(GET_TX, READ_ACTION_DATA))).rejects.toThrow(
      GatewayReadExhaustedError,
    );
    // The single exchange underneath was ambiguous.
    const direct = createGatewayExchangeTransport({ limits: LIMITS, fetchFn: fake.fetch });
    fake.reset();
    fake.scriptRead(GET_TX, { kind: "drop" });
    await expect(direct.exchange(PRIMARY, buildGatewayActionRequest(GET_TX, READ_ACTION_DATA))).rejects.toThrow(
      GatewayTransportAmbiguityError,
    );
  });

  it("serves bare timeouts", async () => {
    const fake = createFakeGateway();
    fake.scriptRead(GET_TX, { kind: "timeout" });
    const read = createFakeGatewayReadTransport(fake, {
      limits: { readTimeoutMs: 20, maxRequestBytes: 4_096, maxResponseBytes: 4_096 },
      recorder: observationRecorder(),
      maxAttempts: 1,
    });

    await expect(read.read([PRIMARY], buildGatewayActionRequest(GET_TX, READ_ACTION_DATA))).rejects.toThrow(
      GatewayReadExhaustedError,
    );
  });

  it("serves equivocating pairs — two differing bodies for the same read", async () => {
    const fake = createFakeGateway();
    fake.scriptRead(
      GET_TX,
      { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { head: "head-A" } } },
      { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { head: "head-B" } } },
    );
    const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });
    const request = buildGatewayActionRequest(GET_TX, READ_ACTION_DATA);

    const first = await read.read([PRIMARY], request);
    const second = await read.read([PRIMARY], request);

    expect((decodeEnvelope(first.bodyBytes).data as { head: string }).head).toBe("head-A");
    expect((decodeEnvelope(second.bodyBytes).data as { head: string }).head).toBe("head-B");
    expect(sha256Hex(first.bodyBytes)).not.toBe(sha256Hex(second.bodyBytes));
  });

  it("fails closed when no outcome is scripted", async () => {
    const fake = createFakeGateway();
    const read = createFakeGatewayReadTransport(fake, {
      limits: LIMITS,
      recorder: observationRecorder(),
      maxAttempts: 1,
    });

    // An unscripted action never succeeds: the exchange wraps the script error as
    // transport ambiguity, and the bounded schedule exhausts with it preserved as cause.
    const error = await read
      .read([PRIMARY], buildGatewayActionRequest(GET_TX, READ_ACTION_DATA))
      .then(
        () => null,
        (thrown: unknown) => thrown,
      );
    expect(error).toBeInstanceOf(GatewayReadExhaustedError);
    const exhausted = error as GatewayReadExhaustedError;
    const ambiguity = exhausted.failures[0]?.error;
    expect(ambiguity).toBeInstanceOf(GatewayTransportAmbiguityError);
    expect((ambiguity as GatewayTransportAmbiguityError).cause).toBeInstanceOf(FakeGatewayScriptExhaustedError);
  });

  it("rejects over-limit requests before any exchange", async () => {
    const fake = createFakeGateway();
    const exchange = createGatewayExchangeTransport({
      limits: { readTimeoutMs: 1_000, maxRequestBytes: 16, maxResponseBytes: 4_096 },
      fetchFn: fake.fetch,
    });

    await expect(exchange.exchange(PRIMARY, buildGatewayActionRequest(GET_TX, READ_ACTION_DATA))).rejects.toThrow(
      GatewayRequestTooLargeError,
    );
    expect(fake.exchangeLog).toHaveLength(0);
  });
});

describe("submit-attempt counter — exactly one attempt, ever", () => {
  const shortTimeout = { readTimeoutMs: 20, maxRequestBytes: 4_096, maxResponseBytes: 4_096 };
  const submitRequest = buildGatewayActionRequest(SUBMIT_ACTION_NAME, TX);

  it.each([
    ["dropped connection", { kind: "drop" } as const],
    ["bare timeout", { kind: "timeout" } as const],
    [
      "injected lag exceeding the timeout",
      { kind: "lag", delayMs: 5_000, then: { kind: "drop" } as const } as const,
    ],
  ])("counts exactly one attempt under %s", async (_label, outcome) => {
    const fake = createFakeGateway();
    fake.scriptSubmit(outcome);
    const recorder = submitRecorder();
    const submit = createFakeGatewaySubmitTransport(fake, {
      limits: shortTimeout,
      recorder,
      authorization: AUTHORIZATION,
    });

    await expect(submit.submit([PRIMARY, SECONDARY], submitRequest)).rejects.toThrow(SubmitIndeterminateError);

    expect(fake.totalSubmitAttempts).toBe(1);
    expect(fake.submitAttemptCountForKey(WALLET_KEY)).toBe(1);
    expect(recorder.records).toHaveLength(1);
    expect(recorder.records[0]?.transportOutcome).toBe("INDETERMINATE");
    // No failover: the single-shot surface never touches the second endpoint.
    expect(fake.exchangeLog.every((entry) => entry.endpoint === PRIMARY)).toBe(true);
  });

  it("counts exactly one attempt when the submit lands", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmit({ kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: {} } });
    const recorder = submitRecorder();
    const submit = createFakeGatewaySubmitTransport(fake, { limits: LIMITS, recorder, authorization: AUTHORIZATION });

    const response = await submit.submit([PRIMARY], submitRequest);

    expect(response.statusCode).toBe(200);
    expect(decodeEnvelope(response.bodyBytes).status).toBe(true);
    expect(fake.totalSubmitAttempts).toBe(1);
    expect(fake.submitAttemptCountForKey(WALLET_KEY)).toBe(1);
    expect(fake.landedCountForKey(WALLET_KEY)).toBe(1);
    expect(recorder.records[0]?.transportOutcome).toBe("ACK");
  });

  it("counts exactly one attempt even when lag completes inside the timeout", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmit({
      kind: "lag",
      delayMs: 10,
      then: { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: {} } },
    });
    const submit = createFakeGatewaySubmitTransport(fake, {
      limits: LIMITS,
      recorder: submitRecorder(),
      authorization: AUTHORIZATION,
    });

    const response = await submit.submit([PRIMARY], submitRequest);

    expect(response.statusCode).toBe(200);
    expect(fake.totalSubmitAttempts).toBe(1);
    expect(fake.submitAttemptCountForKey(WALLET_KEY)).toBe(1);
  });

  it("keys walletless submit payloads by request digest", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmit({ kind: "drop" });
    const submit = createFakeGatewaySubmitTransport(fake, {
      limits: shortTimeout,
      recorder: submitRecorder(),
      authorization: AUTHORIZATION,
    });
    const walletless = buildGatewayActionRequest(SUBMIT_ACTION_NAME, { note: "no wallet keys here" });

    await expect(submit.submit([PRIMARY], walletless)).rejects.toThrow(SubmitIndeterminateError);
    await expect(submit.submit([PRIMARY], walletless)).rejects.toThrow(SubmitIndeterminateError);

    expect(fake.totalSubmitAttempts).toBe(2);
    expect(fake.submitAttemptCountForKey(WALLET_KEY)).toBe(0);
    const firstEntry = fake.exchangeLog[0];
    if (!firstEntry) throw new Error("expected exchange entries");
    const digestKey = `digest:${sha256Hex(firstEntry.requestBytes)}`;
    expect(fake.submitAttemptCountForKey(digestKey)).toBe(2);
  });
});

describe("degraded mode — bounded failure budget", () => {
  it("exhausts a configured failure budget, then recovers", async () => {
    const fake = createFakeGateway();
    const budget = 3;
    fake.scriptRead(
      GET_TX,
      ...Array.from({ length: budget }, () => ({ kind: "drop" as const })),
      { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { head: "recovered" } } },
    );
    const delays: number[] = [];
    const read = createFakeGatewayReadTransport(fake, {
      limits: LIMITS,
      recorder: observationRecorder(),
      sleep: async (ms) => {
        delays.push(ms);
      },
      jitter: () => 0,
    });

    const response = await read.read([PRIMARY], buildGatewayActionRequest(GET_TX, READ_ACTION_DATA));

    expect((decodeEnvelope(response.bodyBytes).data as { head: string }).head).toBe("recovered");
    expect(fake.readExchangeCount(GET_TX)).toBe(budget + 1);
    expect(delays).toHaveLength(budget);
    for (const [index, delay] of delays.entries()) {
      expect(delay).toBe(readBackoffDelayMs(index + 1, () => 0));
    }
  });

  it("honours a zero-failure budget (no degraded tolerance)", async () => {
    const fake = createFakeGateway();
    fake.scriptRead(GET_TX, { kind: "drop" });
    const read = createFakeGatewayReadTransport(fake, {
      limits: LIMITS,
      recorder: observationRecorder(),
      maxAttempts: 1,
      sleep: async () => undefined,
      jitter: () => 0,
    });

    await expect(read.read([PRIMARY], buildGatewayActionRequest(GET_TX, READ_ACTION_DATA))).rejects.toThrow(
      GatewayReadExhaustedError,
    );
    expect(fake.readExchangeCount(GET_TX)).toBe(1);
  });
});

describe("fake-endpoint configuration", () => {
  it("serves clients configured with unreachable hosts entirely in-process", async () => {
    const fake = createFakeGateway();
    fake.scriptRead(GET_TX, { kind: "envelope", envelope: HEAD_OK });
    // The configured endpoint is unreachable on any real network; only the injected
    // adapter serves it (zero network in these suites).
    const unreachable = "https://unreachable-host.invalid/";
    const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });

    const response = await read.read([unreachable], buildGatewayActionRequest(GET_TX, READ_ACTION_DATA));

    expect((decodeEnvelope(response.bodyBytes).data as { head: string }).head).toBe("head-link-1");
    expect(fake.exchangeLog[0]?.endpoint).toBe(unreachable);
  });

  it("keeps the read surface and submit surface independently scriptable", async () => {
    const fake = createFakeGateway();
    fake.scriptRead(GET_TX, { kind: "envelope", envelope: HEAD_OK });
    fake.scriptSubmit({ kind: "drop" });
    const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });
    const submit = createFakeGatewaySubmitTransport(fake, {
      limits: { readTimeoutMs: 20, maxRequestBytes: 4_096, maxResponseBytes: 4_096 },
      recorder: submitRecorder(),
      authorization: AUTHORIZATION,
    });

    const readResponse = await read.read([PRIMARY], buildGatewayActionRequest(GET_TX, READ_ACTION_DATA));
    await expect(
      submit.submit([PRIMARY], buildGatewayActionRequest(SUBMIT_ACTION_NAME, TX)),
    ).rejects.toThrow(SubmitIndeterminateError);

    expect((decodeEnvelope(readResponse.bodyBytes).data as { head: string }).head).toBe("head-link-1");
    expect(fake.readExchangeCount(GET_TX)).toBe(1);
    expect(fake.totalSubmitAttempts).toBe(1);
  });
});
