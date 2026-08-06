// Deterministic production of EVERY row of the protocol
// submit-outcome table and EVERY crash-injection point. Each
// test scripts the gateway-side state for one row/point through the fake and asserts the
// invariants this layer (single-shot transport + fake chain truth) can enforce: exactly
// one submit attempt ever, no blind retry, receipt-never-settlement, and evidence
// retention. The landing-path oracle landing oracle sits ABOVE the transport and consumes the fake's
// deterministic bodies; these tests prove the fake produces exactly the gateway-side
// truth each row requires. Test-support only.

import { describe, expect, it } from "vitest";
import {
  SUBMIT_ACK_STATUS_TRUE_MEANS_SETTLED,
  SUBMIT_ACTION_NAME,
  SUBMIT_BLIND_RETRY_ALLOWED,
  SUBMIT_IS_SINGLE_SHOT,
  SUBMIT_LANDED_OUTCOME_CATEGORIES,
  SUBMIT_OUTCOME_CATEGORIES,
} from "@zucoins/generic-node-contracts/transfer-code";
import {
  createFakeGateway,
  createFakeGatewayReadTransport,
  createFakeGatewaySubmitTransport,
  type FakeGateway,
  type SubmitCrashHoldPoint,
} from "./gateway-fake.js";
import {
  GatewayReadExhaustedError,
  READ_SAFE_ACTION_NAMES,
  SubmitIndeterminateError,
  buildGatewayActionRequest,
  classifySubmitHttpStatus,
} from "../gateway/index.js";
import {
  AUTHORIZATION,
  LIMITS,
  PRIMARY,
  RECEIVER_KEY,
  TX,
  WALLET_KEY,
  makeTx,
  observationRecorder,
  submitRecorder,
} from "./gateway-fake-fixtures.js";

const GET_TX = "get_transaction__v1" as const;
const SHORT_TIMEOUT = { readTimeoutMs: 20, maxRequestBytes: 4_096, maxResponseBytes: 4_096 };
const ACK = { status: true, code: "ok", message: "OK", data: {} } as const;

function submitTransportFor(fake: FakeGateway, recorder = submitRecorder()) {
  return {
    submit: createFakeGatewaySubmitTransport(fake, { limits: LIMITS, recorder, authorization: AUTHORIZATION }),
    recorder,
  };
}

const submitRequest = buildGatewayActionRequest(SUBMIT_ACTION_NAME, TX);

describe("submit-outcome table — every row is deterministically producible", () => {
  it("anchors on the frozen closed set of outcome categories", () => {
    expect([...SUBMIT_OUTCOME_CATEGORIES]).toEqual([
      "deterministic_rejection",
      "receipt_acknowledgement",
      "indeterminate_transport",
      "verified_exact_landing",
      "verified_complete_path_landing",
      "incomplete_or_conflicting_or_resource_exhausted",
      "regression_or_gap_or_unrelated_or_unverifiable",
    ]);
    expect([...SUBMIT_LANDED_OUTCOME_CATEGORIES]).toEqual([
      "verified_exact_landing",
      "verified_complete_path_landing",
    ]);
    expect(SUBMIT_IS_SINGLE_SHOT).toBe(true);
    expect(SUBMIT_BLIND_RETRY_ALLOWED).toBe(false);
  });

  it("row 1 — deterministic rejection: 4xx is a terminal REJECT, no blind repeat", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmit({
      kind: "envelope",
      httpStatus: 400,
      envelope: { status: false, code: "rejected", message: "gateway positively rejected this exact request", data: {} },
    });
    const { submit, recorder } = submitTransportFor(fake);

    const response = await submit.submit([PRIMARY], submitRequest);

    expect(response.statusCode).toBe(400);
    expect(classifySubmitHttpStatus(response.statusCode)).toBe("REJECT");
    expect(recorder.records[0]?.transportOutcome).toBe("REJECT");
    // Terminal: exactly one attempt, no landing, and no second POST under the hood.
    expect(fake.totalSubmitAttempts).toBe(1);
    expect(fake.landedCountForKey(WALLET_KEY)).toBe(0);
    expect(fake.exchangeLog.filter((entry) => entry.actionName === SUBMIT_ACTION_NAME)).toHaveLength(1);
  });

  it("row 2 — receipt acknowledgement: 2xx status:true is ACK, receipt-only, never settlement", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmit({ kind: "envelope", envelope: ACK });
    // The landing the oracle will verify: a fresh head read returning the submitted tx.
    fake.scriptRead(GET_TX, { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { transaction: TX } } });
    const { submit, recorder } = submitTransportFor(fake);

    const response = await submit.submit([PRIMARY], submitRequest);

    expect(response.statusCode).toBe(200);
    expect(classifySubmitHttpStatus(response.statusCode)).toBe("ACK");
    expect(recorder.records[0]?.transportOutcome).toBe("ACK");
    // Frozen semantics: a status:true acknowledgement is NEVER settlement (C-09).
    expect(SUBMIT_ACK_STATUS_TRUE_MEANS_SETTLED).toBe(false);
    // Settlement requires a fresh verified read — the oracle reads the sender head:
    const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });
    const head = await read.read([PRIMARY], buildGatewayActionRequest(GET_TX, { public_key_base64urlsafe: WALLET_KEY }));
    expect(head.statusCode).toBe(200);
    expect(fake.totalSubmitAttempts).toBe(1);
  });

  it.each([
    ["a dropped connection", { kind: "drop" } as const, SHORT_TIMEOUT],
    ["a bare timeout", { kind: "timeout" } as const, SHORT_TIMEOUT],
    ["a non-2xx/4xx status (503)", { kind: "envelope", httpStatus: 503, envelope: ACK } as const, LIMITS],
  ])("row 3 — indeterminate transport via %s: reconcile by read only, never resubmit", async (_label, outcome, limits) => {
    const fake = createFakeGateway();
    fake.scriptSubmit(outcome);
    fake.scriptRead(GET_TX, { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { head: "reconciled" } } });
    const recorder = submitRecorder();
    const submit = createFakeGatewaySubmitTransport(fake, { limits, recorder, authorization: AUTHORIZATION });

    await expect(submit.submit([PRIMARY], submitRequest)).rejects.toThrow(SubmitIndeterminateError);

    expect(recorder.records[0]?.transportOutcome).toBe("INDETERMINATE");
    expect(fake.totalSubmitAttempts).toBe(1);
    expect(fake.landedCountForKey(WALLET_KEY)).toBe(0);
    // Reconcile by read ONLY: the read succeeds and the submit count does not move.
    const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });
    const reconciled = await read.read([PRIMARY], buildGatewayActionRequest(GET_TX, { public_key_base64urlsafe: WALLET_KEY }));
    expect(reconciled.statusCode).toBe(200);
    expect(fake.totalSubmitAttempts).toBe(1);
  });

  it("row 4 — verified exact landing: the fresh head is the expected settled transaction", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmit({ kind: "envelope", envelope: ACK });
    const { submit } = submitTransportFor(fake);
    await submit.submit([PRIMARY], submitRequest);

    // Gateway-side truth: the accepted submission landed under its wallet key, and the
    // fresh head the oracle reads back is exactly the submitted body.
    expect(fake.landedCountForKey(WALLET_KEY)).toBe(1);
    expect(fake.headOf(WALLET_KEY)).toEqual(TX);
    fake.scriptRead(GET_TX, { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { transaction: fake.headOf(WALLET_KEY) } } });
    const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });
    const head = await read.read([PRIMARY], buildGatewayActionRequest(GET_TX, { public_key_base64urlsafe: WALLET_KEY }));
    const headData = JSON.parse(new TextDecoder().decode(head.bodyBytes)) as { data: { transaction: unknown } };
    expect(headData.data.transaction).toEqual(TX);
    expect(fake.totalSubmitAttempts).toBe(1);
  });

  it("row 5 — verified complete-path landing: exact bodies connect expected tx to fresh head, never resubmit", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmit({ kind: "envelope", envelope: ACK });
    const { submit } = submitTransportFor(fake);
    await submit.submit([PRIMARY], submitRequest);

    // A complete path of exact bodies: the expected tx, a successor linking to it, and the
    // fresh head linking onward — each served verbatim for the oracle to verify.
    const successor = makeTx(WALLET_KEY, RECEIVER_KEY, TX.step_1_signature, "chain-link-2");
    const head = makeTx(WALLET_KEY, RECEIVER_KEY, successor.step_1_signature, "chain-link-3");
    fake.scriptRead(
      GET_TX,
      { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { transaction: TX } } },
      { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { transaction: successor } } },
      { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { transaction: head } } },
    );
    const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });
    const request = buildGatewayActionRequest(GET_TX, { public_key_base64urlsafe: WALLET_KEY });

    const bodies = [await read.read([PRIMARY], request), await read.read([PRIMARY], request), await read.read([PRIMARY], request)];
    const links = bodies.map((response) => {
      const parsed = JSON.parse(new TextDecoder().decode(response.bodyBytes)) as { data: { transaction: typeof TX } };
      return parsed.data.transaction.inner.previous_step_1_state_signature;
    });
    // Each exact body's predecessor reference chains to the previous body's step-1 link.
    expect(links[0]).toBe(TX.inner.previous_step_1_state_signature);
    expect(links[1]).toBe(TX.step_1_signature);
    expect(links[2]).toBe(successor.step_1_signature);
    // Mark landed; never resubmit — the submit count is still exactly one.
    expect(fake.landedCountForKey(WALLET_KEY)).toBe(1);
    expect(fake.totalSubmitAttempts).toBe(1);
  });

  it("row 6 — incomplete/conflicting/resource-exhausted: history unavailable yields no landing, retry, or release authority", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmit({ kind: "envelope", envelope: ACK });
    const { submit } = submitTransportFor(fake);
    await submit.submit([PRIMARY], submitRequest);

    // Required history is unavailable: every reconciliation read drops.
    fake.scriptRead(GET_TX, { kind: "drop" });
    const read = createFakeGatewayReadTransport(fake, {
      limits: LIMITS,
      recorder: observationRecorder(),
      maxAttempts: 2,
      sleep: async () => undefined,
      jitter: () => 0,
    });

    await expect(read.read([PRIMARY], buildGatewayActionRequest(GET_TX, { public_key_base64urlsafe: WALLET_KEY }))).rejects.toThrow(
      GatewayReadExhaustedError,
    );
    // No verified landing from the node's view, no resubmit, no release authority: the
    // submit count is unchanged and the gateway-side acceptance stays unreconciled.
    expect(fake.totalSubmitAttempts).toBe(1);
  });

  it("row 7 — regression/gap/unrelated/unverifiable: unsafe chain relationship preserves lease and evidence", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmit({ kind: "envelope", envelope: ACK });
    const { submit } = submitTransportFor(fake);
    await submit.submit([PRIMARY], submitRequest);

    // The fresh head is UNRELATED to the expected tx (different wallet, different link).
    const unrelated = makeTx("some-other-wallet-key", RECEIVER_KEY, "unrelated-link", "unrelated-sig");
    const observations = observationRecorder();
    fake.scriptRead(GET_TX, { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { transaction: unrelated } } });
    const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observations });

    const head = await read.read([PRIMARY], buildGatewayActionRequest(GET_TX, { public_key_base64urlsafe: WALLET_KEY }));
    const headData = JSON.parse(new TextDecoder().decode(head.bodyBytes)) as { data: { transaction: typeof TX } };
    expect(headData.data.transaction).not.toEqual(TX);
    expect(headData.data.transaction.inner.step_1_key_public__base64urlsafe).not.toBe(WALLET_KEY);
    // NEEDS_ATTENTION: no landing is marked from this read, and evidence is preserved —
    // the observation rows and the exact exchange bytes remain for adjudication.
    expect(fake.landedCountForKey(WALLET_KEY)).toBe(1); // gateway acceptance stands, unreconciled
    expect(fake.totalSubmitAttempts).toBe(1);
    expect(observations.records.length).toBeGreaterThan(0);
    expect(observations.records[0]?.rawResponseBytes).not.toBeNull();
    expect(fake.exchangeLog.length).toBeGreaterThan(0);
  });
});

describe("crash-injection hold points — gateway-side state per point", () => {
  function submitOnce(fake: FakeGateway): Promise<unknown> {
    const { submit } = submitTransportFor(fake);
    return submit.submit([PRIMARY], submitRequest);
  }

  it.each([
    "before-signed-bytes-persist",
    "after-persist-before-submit",
  ] as const)("at %s the gateway observes nothing (the crash precedes the POST)", async (point: SubmitCrashHoldPoint) => {
    const fake = createFakeGateway();
    fake.scriptSubmitHoldPoint(point);

    // The node died before the POST: no submit attempt reaches the gateway.
    expect(fake.totalSubmitAttempts).toBe(0);
    expect(fake.exchangeLog).toHaveLength(0);
    // And an unscripted (unauthorized) POST would fail closed, never silently accept.
    const { submit } = submitTransportFor(fake);
    await expect(submit.submit([PRIMARY], submitRequest)).rejects.toThrow();
  });

  it("during-submit-no-response: the attempt counts, the outcome is INDETERMINATE, no blind retry", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmitHoldPoint("during-submit-no-response");

    await expect(submitOnce(fake)).rejects.toThrow(SubmitIndeterminateError);

    expect(fake.totalSubmitAttempts).toBe(1);
    expect(fake.landedCountForKey(WALLET_KEY)).toBe(0);
    expect(fake.exchangeLog.filter((entry) => entry.actionName === SUBMIT_ACTION_NAME)).toHaveLength(1);
  });

  it.each([
    "after-acceptance-before-local-ack",
    "after-local-ack-before-event-emission",
    "before-outbox-delivery",
    "after-outbox-delivery",
  ] as const)("at %s the gateway accepted: the landing is retained and reconcilable by read", async (point: SubmitCrashHoldPoint) => {
    const fake = createFakeGateway();
    fake.scriptSubmitHoldPoint(point);

    const response = (await submitOnce(fake)) as { statusCode: number };

    expect(response.statusCode).toBe(200);
    expect(fake.totalSubmitAttempts).toBe(1);
    // The acceptance landed gateway-side and survives the node crash — a fresh read
    // reconciles it (possible landing retains the lease; never resubmit).
    expect(fake.landedCountForKey(WALLET_KEY)).toBe(1);
    expect(fake.headOf(WALLET_KEY)).toEqual(TX);
  });

  it("during-reconciliation: the gateway is unreadable for the whole schedule", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmitHoldPoint("during-reconciliation");

    const read = createFakeGatewayReadTransport(fake, {
      limits: LIMITS,
      recorder: observationRecorder(),
      maxAttempts: 2,
      sleep: async () => undefined,
      jitter: () => 0,
    });
    for (const actionName of READ_SAFE_ACTION_NAMES) {
      await expect(
        read.read([PRIMARY], buildGatewayActionRequest(actionName, { public_key_base64urlsafe: WALLET_KEY })),
      ).rejects.toThrow(GatewayReadExhaustedError);
    }
    // No submit was scripted at this hold point.
    expect(fake.totalSubmitAttempts).toBe(0);
  });
});
