// Endpoint failover as evidence: the active endpoint switches to a backup on transport
// ambiguity, the switch is recorded as a first-class failover event (not a gap), the
// observation stream stays contiguous across the switch, and the submit action can never
// enter this path (the never-blind-retry rule).
import { SUBMIT_ACTION_NAME } from "@zucoins/generic-node-contracts/transfer-code";
import { describe, expect, it } from "vitest";

import { GatewayUnsafeActionError } from "./actions.js";
import {
  GatewayTransportAmbiguityError,
  sha256Hex,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
} from "./capture.js";
import type { AnomalyRecorder, EndpointDisagreementAnomaly } from "./anomaly.js";
import { fingerprintEndpoint, GatewayConfigurationError } from "./client.js";
import {
  createEndpointFailoverService,
  GatewayEndpointHaltError,
  provesT0Continuity,
  type EndpointFailoverEvent,
  type EndpointFailoverRecorder,
} from "./failover.js";
import type { ReadGatewayRequestOptions } from "./read.js";
import type { GatewayObservationRecord, ObservationRecorder } from "./records.js";
import type { GatewayLimits } from "./types.js";

const ENDPOINT_A = "https://gateway-a.invalid/";
const ENDPOINT_B = "https://gateway-b.invalid/";
const ENDPOINT_C = "https://gateway-c.invalid/";

const LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 1_024,
  maxResponseBytes: 1_024,
};

const BODY_OK = Uint8Array.from([1, 2, 3]);
// A genuinely DIFFERING backup body: a backup that serves this after the active endpoint
// goes ambiguous is a semantic disagreement, not a healable transport gap.
const BODY_DIFF = Uint8Array.from([9, 9, 9]);

type ScriptStep =
  | { readonly kind: "capture"; readonly status: number; readonly body: Uint8Array }
  | { readonly kind: "ambiguous" };

interface ScriptedExchange {
  readonly touched: string[];
  readonly exchange: GatewayExchangeTransport;
}

function scriptedExchange(script: readonly ScriptStep[]): ScriptedExchange {
  const touched: string[] = [];
  let index = 0;
  const exchange: GatewayExchangeTransport = {
    exchange: async (endpoint, request) => {
      touched.push(endpoint);
      const step = script[index];
      index += 1;
      if (step === undefined) {
        throw new Error("exchange script exhausted — more calls than the test planned");
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
  return { touched, exchange };
}

interface RecordingObserver {
  readonly records: GatewayObservationRecord[];
  readonly recorder: ObservationRecorder;
}

function recordingObserver(): RecordingObserver {
  const records: GatewayObservationRecord[] = [];
  return {
    records,
    recorder: {
      recordObservation: async (record) => {
        records.push(record);
      },
    },
  };
}

interface RecordingFailoverRecorder {
  readonly events: EndpointFailoverEvent[];
  readonly recorder: EndpointFailoverRecorder;
}

function recordingFailoverRecorder(failing = false): RecordingFailoverRecorder {
  const events: EndpointFailoverEvent[] = [];
  return {
    events,
    recorder: {
      recordFailover: async (event) => {
        if (failing) {
          throw new Error("failover audit persistence unavailable");
        }
        events.push(event);
      },
    },
  };
}

interface RecordingAnomalyRecorder {
  readonly anomalies: EndpointDisagreementAnomaly[];
  readonly recorder: AnomalyRecorder;
}

// In-memory stand-in for the anomaly sink. The DDL-backed observation_anomalies
// recorder is deferred to; this exercises the disagreement/halt logic against the
// injected port. `failing` models "the anomaly cannot be persisted" (fail-closed).
function recordingAnomalyRecorder(failing = false): RecordingAnomalyRecorder {
  const anomalies: EndpointDisagreementAnomaly[] = [];
  return {
    anomalies,
    recorder: {
      recordDisagreement: async (anomaly) => {
        if (failing) {
          throw new Error("observation_anomalies persistence unavailable");
        }
        anomalies.push(anomaly);
      },
    },
  };
}

function readOptions(
  exchange: GatewayExchangeTransport,
  observer: ObservationRecorder,
): ReadGatewayRequestOptions {
  return {
    endpoints: [],
    limits: LIMITS,
    recorder: observer,
    exchange,
    sleep: async () => undefined,
    jitter: () => 0,
    nowIso: () => "2026-07-21T00:00:00.000Z",
  };
}

const captureStep = (status: number, body: Uint8Array): ScriptStep => ({
  kind: "capture",
  status,
  body,
});
const ambiguousStep: ScriptStep = { kind: "ambiguous" };

describe("endpoint failover — detection and switch to a backup", () => {
  it("a healthy active endpoint serves the read with no failover", async () => {
    const scripted = scriptedExchange([captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const failover = recordingFailoverRecorder();
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      recorder: failover.recorder,
    });

    const result = await service.read(
      "get_transaction__v1",
      { wallet: "w1" },
      readOptions(scripted.exchange, observer.recorder),
    );

    expect(result.failedOver).toBe(false);
    expect(result.failover).toBeNull();
    expect(result.servedEndpoint).toBe(ENDPOINT_A);
    expect(scripted.touched).toEqual([ENDPOINT_A]);
    expect(service.activeEndpoint()).toBe(ENDPOINT_A);
    expect(service.failoverCount()).toBe(0);
    expect(failover.events.length).toBe(0);
  });

  it("switches to the backup when the active endpoint is unreachable and records the failover", async () => {
    const scripted = scriptedExchange([ambiguousStep, captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const failover = recordingFailoverRecorder();
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      recorder: failover.recorder,
      nowIso: () => "2026-07-21T00:00:05.000Z",
    });

    const result = await service.read(
      "get_transaction__v1",
      {},
      readOptions(scripted.exchange, observer.recorder),
    );

    expect(result.failedOver).toBe(true);
    expect(result.servedEndpoint).toBe(ENDPOINT_B);
    expect(scripted.touched).toEqual([ENDPOINT_A, ENDPOINT_B]);
    expect(service.activeEndpoint()).toBe(ENDPOINT_B);
    expect(service.activeEndpointFingerprint()).toBe(fingerprintEndpoint(ENDPOINT_B));
    expect(service.failoverCount()).toBe(1);

    expect(failover.events.length).toBe(1);
    const event = failover.events[0];
    expect(event?.fromEndpointFingerprint).toBe(fingerprintEndpoint(ENDPOINT_A));
    expect(event?.toEndpointFingerprint).toBe(fingerprintEndpoint(ENDPOINT_B));
    expect(event?.fromIndex).toBe(0);
    expect(event?.toIndex).toBe(1);
    expect(event?.ambiguousFailures).toBe(1);
    expect(event?.failedAt).toBe("2026-07-21T00:00:05.000Z");
    expect(result.failover).toEqual(event);
  });

  it("skips multiple unreachable endpoints and counts each ambiguous failure", async () => {
    const scripted = scriptedExchange([
      ambiguousStep,
      ambiguousStep,
      captureStep(200, BODY_OK),
    ]);
    const observer = recordingObserver();
    const failover = recordingFailoverRecorder();
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B, ENDPOINT_C],
      recorder: failover.recorder,
    });

    const result = await service.read(
      "get_transaction__v1",
      {},
      readOptions(scripted.exchange, observer.recorder),
    );

    expect(result.failedOver).toBe(true);
    expect(result.servedEndpoint).toBe(ENDPOINT_C);
    expect(scripted.touched).toEqual([ENDPOINT_A, ENDPOINT_B, ENDPOINT_C]);
    expect(service.activeEndpoint()).toBe(ENDPOINT_C);
    expect(failover.events[0]?.ambiguousFailures).toBe(2);
    expect(failover.events[0]?.fromIndex).toBe(0);
    expect(failover.events[0]?.toIndex).toBe(2);
  });

  it("once failed over, subsequent reads start from the new active endpoint", async () => {
    const scripted = scriptedExchange([
      ambiguousStep,
      captureStep(200, BODY_OK),
      captureStep(200, BODY_OK),
    ]);
    const observer = recordingObserver();
    const failover = recordingFailoverRecorder();
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      recorder: failover.recorder,
    });
    const options = readOptions(scripted.exchange, observer.recorder);

    await service.read("get_transaction__v1", {}, options);
    expect(service.activeEndpoint()).toBe(ENDPOINT_B);

    const second = await service.read("get_transaction__v1", {}, options);
    expect(second.failedOver).toBe(false);
    expect(second.servedEndpoint).toBe(ENDPOINT_B);
    // The second read touched only the now-active backup, not the unreachable primary.
    expect(scripted.touched).toEqual([ENDPOINT_A, ENDPOINT_B, ENDPOINT_B]);
    expect(service.failoverCount()).toBe(1);
    expect(failover.events.length).toBe(1);
  });

  it("wraps around the endpoint list when the active endpoint is last", async () => {
    const scripted = scriptedExchange([
      // First read: A ambiguous, B serves -> active becomes B.
      ambiguousStep,
      captureStep(200, BODY_OK),
      // Second read starts from B: B ambiguous, C serves -> active becomes C.
      ambiguousStep,
      captureStep(200, BODY_OK),
      // Third read starts from C: C ambiguous, wraps to A, A serves -> active becomes A.
      ambiguousStep,
      captureStep(200, BODY_OK),
    ]);
    const observer = recordingObserver();
    const failover = recordingFailoverRecorder();
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B, ENDPOINT_C],
      recorder: failover.recorder,
    });
    const options = readOptions(scripted.exchange, observer.recorder);

    await service.read("get_transaction__v1", {}, options);
    await service.read("get_transaction__v1", {}, options);
    expect(service.activeEndpoint()).toBe(ENDPOINT_C);

    const third = await service.read("get_transaction__v1", {}, options);
    expect(third.failedOver).toBe(true);
    expect(third.servedEndpoint).toBe(ENDPOINT_A);
    expect(service.activeEndpoint()).toBe(ENDPOINT_A);
    expect(service.failoverCount()).toBe(3);
    // The wrap-around failover records from index 2 to index 0 with one ambiguous failure.
    const wrap = failover.events[2];
    expect(wrap?.fromIndex).toBe(2);
    expect(wrap?.toIndex).toBe(0);
    expect(wrap?.ambiguousFailures).toBe(1);
  });
});

describe("failover is evidence, not a gap — observation continuity", () => {
  it("lands an observation row for every endpoint touched across the failover", async () => {
    const scripted = scriptedExchange([ambiguousStep, captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const failover = recordingFailoverRecorder();
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      recorder: failover.recorder,
    });

    await service.read("get_transaction__v1", {}, readOptions(scripted.exchange, observer.recorder));

    // No gap: the unreachable endpoint's transport-ambiguous marker row AND the backup's
    // captured response row are both present, in sequence.
    expect(observer.records.length).toBe(2);
    expect(observer.records[0]?.transportAmbiguous).toBe(true);
    expect(observer.records[0]?.endpointFingerprint).toBe(fingerprintEndpoint(ENDPOINT_A));
    expect(observer.records[0]?.rawResponseBytes).toBeNull();
    expect(observer.records[1]?.transportAmbiguous).toBe(false);
    expect(observer.records[1]?.endpointFingerprint).toBe(fingerprintEndpoint(ENDPOINT_B));
    expect(observer.records[1]?.rawResponseBytes).toEqual(BODY_OK);
    // The failover event is additional audit evidence alongside the observation rows.
    expect(failover.events.length).toBe(1);
  });

  it("a recorder failure fails closed — the active endpoint is not advanced on an unrecorded failover", async () => {
    const scripted = scriptedExchange([ambiguousStep, captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const failover = recordingFailoverRecorder(true);
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      recorder: failover.recorder,
    });

    await expect(
      service.read("get_transaction__v1", {}, readOptions(scripted.exchange, observer.recorder)),
    ).rejects.toThrow("failover audit persistence unavailable");

    // The switch was not persisted, so the active endpoint must not advance.
    expect(service.activeEndpoint()).toBe(ENDPOINT_A);
    expect(service.failoverCount()).toBe(0);
  });
});

describe("structural read-safety — the submit action cannot enter the failover path (the never-blind-retry rule)", () => {
  it("rejects a cast bypass before any endpoint is touched", async () => {
    const scripted = scriptedExchange([captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const service = createEndpointFailoverService({ endpoints: [ENDPOINT_A, ENDPOINT_B] });
    const bypassed = SUBMIT_ACTION_NAME as unknown as "get_transaction__v1";

    await expect(
      service.read(bypassed, {}, readOptions(scripted.exchange, observer.recorder)),
    ).rejects.toBeInstanceOf(GatewayUnsafeActionError);
    expect(scripted.touched.length).toBe(0);
    expect(observer.records.length).toBe(0);
    expect(service.failoverCount()).toBe(0);
  });
});

describe("configuration — fail-closed", () => {
  it("rejects an empty endpoint list", () => {
    expect(() => createEndpointFailoverService({ endpoints: [] })).toThrow(
      GatewayConfigurationError,
    );
  });

  it("exposes the configured endpoints and their fingerprints, index-aligned", () => {
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      observerId: "platform",
    });
    expect(service.endpoints).toEqual([ENDPOINT_A, ENDPOINT_B]);
    expect(service.endpointFingerprints).toEqual([
      fingerprintEndpoint(ENDPOINT_A),
      fingerprintEndpoint(ENDPOINT_B),
    ]);
    expect(service.observerId).toBe("platform");
    expect(service.activeEndpoint()).toBe(ENDPOINT_A);
  });

  it("operates without a recorder — the failover still advances the active endpoint", async () => {
    const scripted = scriptedExchange([ambiguousStep, captureStep(200, BODY_OK)]);
    const observer = recordingObserver();
    const service = createEndpointFailoverService({ endpoints: [ENDPOINT_A, ENDPOINT_B] });

    const result = await service.read(
      "get_transaction__v1",
      {},
      readOptions(scripted.exchange, observer.recorder),
    );
    expect(result.failedOver).toBe(true);
    expect(result.failover).not.toBeNull();
    expect(service.activeEndpoint()).toBe(ENDPOINT_B);
  });
});

describe("endpoint disagreement — a disagreeing backup is not adopted", () => {
  it("(a) a backup that disagrees with the prior accepted state halts INDETERMINATE and records the anomaly", async () => {
    // Read 1: active endpoint A serves BODY_OK and establishes the accepted state.
    // Read 2: A is unreachable, backup B serves a DIFFERING body -> semantic disagreement.
    const scripted = scriptedExchange([
      captureStep(200, BODY_OK),
      ambiguousStep,
      captureStep(200, BODY_DIFF),
    ]);
    const observer = recordingObserver();
    const anomaly = recordingAnomalyRecorder();
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      anomalyRecorder: anomaly.recorder,
      nowIso: () => "2026-07-21T00:00:09.000Z",
    });
    const options = readOptions(scripted.exchange, observer.recorder);

    const first = await service.read("get_transaction__v1", { wallet: "w1" }, options);
    expect(first.verificationStatus).toBe("ACCEPTED");

    const second = await service.read("get_transaction__v1", { wallet: "w1" }, options);

    expect(second.verificationStatus).toBe("INDETERMINATE");
    expect(second.disagreement).not.toBeNull();
    expect(second.failedOver).toBe(false);
    expect(second.servedEndpoint).toBe(ENDPOINT_B);

    // The disagreement is recorded as evidence via the injected anomaly port.
    expect(anomaly.anomalies.length).toBe(1);
    const recorded = anomaly.anomalies[0];
    expect(recorded?.acceptedEndpointFingerprint).toBe(fingerprintEndpoint(ENDPOINT_A));
    expect(recorded?.servingEndpointFingerprint).toBe(fingerprintEndpoint(ENDPOINT_B));
    expect(recorded?.acceptedSemanticState).toBe(sha256Hex(BODY_OK));
    expect(recorded?.servingSemanticState).toBe(sha256Hex(BODY_DIFF));
    expect(recorded?.detectedAt).toBe("2026-07-21T00:00:09.000Z");

    // Money automation is FROZEN: the service is halted, the backup was NOT adopted, and
    // the observation stream still landed both endpoints' rows (evidence, not a gap).
    expect(service.isHalted()).toBe(true);
    expect(service.activeEndpoint()).toBe(ENDPOINT_A);
    expect(service.failoverCount()).toBe(0);
    // Read 1: A(BODY_OK). Read 2: A(ambiguous marker) + B(BODY_DIFF).
    expect(observer.records.length).toBe(3);
    expect(observer.records[2]?.rawResponseBytes).toEqual(BODY_DIFF);
  });

  it("(b) a backup that agrees with the prior accepted state is a normal failover, no special-case bypass", async () => {
    const scripted = scriptedExchange([
      captureStep(200, BODY_OK),
      ambiguousStep,
      captureStep(200, BODY_OK),
    ]);
    const observer = recordingObserver();
    const anomaly = recordingAnomalyRecorder();
    const failover = recordingFailoverRecorder();
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      recorder: failover.recorder,
      anomalyRecorder: anomaly.recorder,
    });
    const options = readOptions(scripted.exchange, observer.recorder);

    await service.read("get_transaction__v1", {}, options);
    const second = await service.read("get_transaction__v1", {}, options);

    expect(second.verificationStatus).toBe("ACCEPTED");
    expect(second.disagreement).toBeNull();
    expect(second.failedOver).toBe(true);
    expect(second.servedEndpoint).toBe(ENDPOINT_B);
    // No anomaly, no halt — an agreeing backup is adopted as an ordinary failover.
    expect(anomaly.anomalies.length).toBe(0);
    expect(service.isHalted()).toBe(false);
    expect(service.activeEndpoint()).toBe(ENDPOINT_B);
    expect(service.failoverCount()).toBe(1);
    expect(failover.events.length).toBe(1);
  });
});

describe("T0-continuity anti-laundering — a post-failover endpoint cannot prove continuity (D3)", () => {
  it("(c) a semantically-equal read on the NEW endpoint does not prove T0-continuity the OLD endpoint established", async () => {
    const scripted = scriptedExchange([
      captureStep(200, BODY_OK), // A establishes T0
      ambiguousStep, // A unreachable
      captureStep(200, BODY_OK), // B serves the SAME state (agrees, so no halt)
    ]);
    const observer = recordingObserver();
    const anomaly = recordingAnomalyRecorder();
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      anomalyRecorder: anomaly.recorder,
    });
    const options = readOptions(scripted.exchange, observer.recorder);

    const t0Read = await service.read("get_transaction__v1", {}, options);
    const baseline = {
      semanticState: sha256Hex(BODY_OK),
      establishedByFingerprint: t0Read.servedEndpointFingerprint,
    };
    expect(baseline.establishedByFingerprint).toBe(fingerprintEndpoint(ENDPOINT_A));

    // A fails over to B; B AGREES (no halt) — an ordinary, valid failover...
    const afterFailover = await service.read("get_transaction__v1", {}, options);
    expect(afterFailover.verificationStatus).toBe("ACCEPTED");
    expect(afterFailover.servedEndpointFingerprint).toBe(fingerprintEndpoint(ENDPOINT_B));

    // ...but the post-failover read (served by B) does NOT prove the T0-continuity that A
    // established, even though the semantic state is identical: continuity is endpoint-bound.
    expect(
      provesT0Continuity(baseline, {
        semanticState: sha256Hex(BODY_OK),
        servedEndpointFingerprint: afterFailover.servedEndpointFingerprint,
      }),
    ).toBe(false);

    // The SAME endpoint that set the baseline still proves it (equal state + same endpoint).
    expect(
      provesT0Continuity(baseline, {
        semanticState: sha256Hex(BODY_OK),
        servedEndpointFingerprint: fingerprintEndpoint(ENDPOINT_A),
      }),
    ).toBe(true);

    // A different semantic state on the SAME endpoint also does not prove continuity.
    expect(
      provesT0Continuity(baseline, {
        semanticState: sha256Hex(BODY_DIFF),
        servedEndpointFingerprint: fingerprintEndpoint(ENDPOINT_A),
      }),
    ).toBe(false);
  });
});

describe("failover-path edge behaviour — lag, stale, conflicting, restart (D4)", () => {
  it("(d-restart) after a halt, further reads are refused until the authority policy resolves it", async () => {
    const scripted = scriptedExchange([
      captureStep(200, BODY_OK), // establish accepted state on A
      ambiguousStep, // A down
      captureStep(200, BODY_DIFF), // B disagrees -> halt
      captureStep(200, BODY_OK), // would-be next read — must be refused before it is reached
    ]);
    const observer = recordingObserver();
    const anomaly = recordingAnomalyRecorder();
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      anomalyRecorder: anomaly.recorder,
    });
    const options = readOptions(scripted.exchange, observer.recorder);

    await service.read("get_transaction__v1", {}, options);
    await service.read("get_transaction__v1", {}, options); // disagreement -> halt
    expect(service.isHalted()).toBe(true);
    expect(service.haltAnomaly()).not.toBeNull();

    // Frozen: no endpoint is touched while halted.
    const touchedBefore = scripted.touched.length;
    await expect(service.read("get_transaction__v1", {}, options)).rejects.toBeInstanceOf(
      GatewayEndpointHaltError,
    );
    expect(scripted.touched.length).toBe(touchedBefore);

    // The configured authority policy resolves the incident; reads resume.
    service.resolveHalt();
    expect(service.isHalted()).toBe(false);
    const resumed = await service.read("get_transaction__v1", {}, options);
    expect(resumed.verificationStatus).toBe("ACCEPTED");
    expect(resumed.servedEndpoint).toBe(ENDPOINT_A);
  });

  it("(d-conflicting-unpersistable) a disagreement with no configured AnomalyRecorder fails closed and still halts", async () => {
    const scripted = scriptedExchange([
      captureStep(200, BODY_OK),
      ambiguousStep,
      captureStep(200, BODY_DIFF),
    ]);
    const observer = recordingObserver();
    const service = createEndpointFailoverService({ endpoints: [ENDPOINT_A, ENDPOINT_B] });
    const options = readOptions(scripted.exchange, observer.recorder);

    await service.read("get_transaction__v1", {}, options);
    await expect(service.read("get_transaction__v1", {}, options)).rejects.toBeInstanceOf(
      GatewayConfigurationError,
    );

    // Unpersistable evidence aborts, but the stream is still frozen and B not adopted.
    expect(service.isHalted()).toBe(true);
    expect(service.activeEndpoint()).toBe(ENDPOINT_A);
    expect(service.failoverCount()).toBe(0);
  });

  it("(d-stale-recorder-failure) a disagreement whose anomaly cannot be persisted fails closed and halts", async () => {
    const scripted = scriptedExchange([
      captureStep(200, BODY_OK),
      ambiguousStep,
      captureStep(200, BODY_DIFF),
    ]);
    const observer = recordingObserver();
    const anomaly = recordingAnomalyRecorder(true); // persistence throws
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      anomalyRecorder: anomaly.recorder,
    });
    const options = readOptions(scripted.exchange, observer.recorder);

    await service.read("get_transaction__v1", {}, options);
    await expect(service.read("get_transaction__v1", {}, options)).rejects.toThrow(
      "observation_anomalies persistence unavailable",
    );
    expect(service.isHalted()).toBe(true);
    expect(service.activeEndpoint()).toBe(ENDPOINT_A);
  });

  it("(d-lag) a same-state backup during a primary outage does not false-halt", async () => {
    const scripted = scriptedExchange([
      captureStep(200, BODY_OK),
      ambiguousStep,
      captureStep(200, BODY_OK),
    ]);
    const observer = recordingObserver();
    const anomaly = recordingAnomalyRecorder();
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      anomalyRecorder: anomaly.recorder,
    });
    const options = readOptions(scripted.exchange, observer.recorder);

    await service.read("get_transaction__v1", {}, options);
    const second = await service.read("get_transaction__v1", {}, options);
    expect(second.verificationStatus).toBe("ACCEPTED");
    expect(service.isHalted()).toBe(false);
    expect(anomaly.anomalies.length).toBe(0);
  });
});

describe("semantic reducer seam — comparison is on semantic state, not raw bytes", () => {
  it("an injected reducer treats different envelopes with the same semantic state as agreement", async () => {
    const scripted = scriptedExchange([
      captureStep(200, BODY_OK),
      ambiguousStep,
      captureStep(200, BODY_DIFF), // different bytes, same semantic token under the reducer
    ]);
    const observer = recordingObserver();
    const anomaly = recordingAnomalyRecorder();
    // Stand-in for the semantic fingerprint: collapses both scripted bodies to
    // one token, so an envelope difference is NOT a semantic disagreement (the
    // EQUIVALENT_STATE_DIFFERENT_ENVELOPE tolerance deferred to).
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      anomalyRecorder: anomaly.recorder,
      semanticState: () => "same-verified-head",
    });
    const options = readOptions(scripted.exchange, observer.recorder);

    await service.read("get_transaction__v1", {}, options);
    const second = await service.read("get_transaction__v1", {}, options);

    expect(second.verificationStatus).toBe("ACCEPTED");
    expect(second.failedOver).toBe(true);
    expect(anomaly.anomalies.length).toBe(0);
    expect(service.isHalted()).toBe(false);
  });
});
