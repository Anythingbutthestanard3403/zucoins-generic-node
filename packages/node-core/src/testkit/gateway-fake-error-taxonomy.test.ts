// Deterministic production of EVERY code of the protocol
// error taxonomy. The codes are internal typed node errors; most are classified by
// validation layers ABOVE this transport slice (signature suite, economic predicates,
// landing oracle, lease manager). The gateway test adapter's contribution to each code is
// twofold: (1) it is scriptable to produce the code's gateway-side trigger deterministically
// (a malformed scalar, a mutated signature, an equivocating body, a dropped read, ...), and
// (2) the transport captures the trigger bytes verbatim as raw evidence before any decode
// so the classifying layer receives the exact bytes. The two gateway_* codes are
// owned by the transport itself and are driven end-to-end here, including their retry
// authority: a read may be retried under policy; a submit may not (the never-blind-retry rule).
// Test-support only.

import { describe, expect, it } from "vitest";
import {
  GATEWAY_RESPONSE_CAPTURED_RAW_BEFORE_DECODE,
  SUBMIT_ACTION_NAME,
} from "@zucoins/generic-node-contracts/transfer-code";
import {
  GatewayReadExhaustedError,
  SubmitIndeterminateError,
  buildGatewayActionRequest,
  sha256Hex,
} from "../gateway/index.js";
import {
  createFakeGateway,
  createFakeGatewayReadTransport,
  createFakeGatewaySubmitTransport,
} from "./gateway-fake.js";
import { serializeGatewayEnvelope, type FakeGatewayEnvelope } from "./gateway-fake-wire.js";
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
const READ_REQUEST = buildGatewayActionRequest(GET_TX, { public_key_base64urlsafe: WALLET_KEY });
const SHORT_TIMEOUT = { readTimeoutMs: 20, maxRequestBytes: 4_096, maxResponseBytes: 4_096 };

// The frozen taxonomy: code -> retry authority. This table is the assertion anchor for
// the per-code retry-authority checks below.
const ERROR_TAXONOMY = {
  invalid_scalar: "none without corrected input",
  unexpected_inner_shape: "none",
  signature_invalid: "none; quarantine evidence",
  wallet_role_invalid: "none",
  chain_link_mismatch: "none; observation adjudication required",
  balance_delta_mismatch: "none",
  gateway_read_indeterminate: "read may be retried under policy; submit may not",
  gateway_submit_indeterminate: "reconcile by read only",
  wallet_lease_conflict: "retry acquisition later; never bypass",
  canonical_bytes_mismatch: "fail closed and alert",
} as const;

function envelopeWith(transaction: unknown): FakeGatewayEnvelope {
  return { status: true, code: "ok", message: "OK", data: { transaction } };
}

// Serves one scripted read body and returns the exact bytes the transport captured, so the
// classifying layer's input is asserted byte-for-byte.
async function capturedReadBytes(trigger: FakeGatewayEnvelope | string): Promise<Uint8Array> {
  const fake = createFakeGateway();
  const outcome =
    typeof trigger === "string"
      ? ({ kind: "raw-body", httpStatus: 200, body: trigger } as const)
      : ({ kind: "envelope", envelope: trigger } as const);
  fake.scriptRead(GET_TX, outcome);
  const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });
  const response = await read.read([PRIMARY], READ_REQUEST);
  return response.bodyBytes;
}

describe("error taxonomy — every code is deterministically producible", () => {
  it("anchors on the frozen ten-code taxonomy and its retry authority", () => {
    expect(Object.keys(ERROR_TAXONOMY)).toHaveLength(10);
    expect(ERROR_TAXONOMY.gateway_read_indeterminate).toBe("read may be retried under policy; submit may not");
    expect(ERROR_TAXONOMY.gateway_submit_indeterminate).toBe("reconcile by read only");
    expect(GATEWAY_RESPONSE_CAPTURED_RAW_BEFORE_DECODE).toBe(true);
  });

  it("invalid_scalar — serves a non-canonical time scalar (number, not a seconds string)", async () => {
    const nonCanonical = {
      ...TX,
      inner: { ...TX.inner, unix_time_secs: 1_753_056_000 }, // number, not the frozen seconds STRING
    };
    const bytes = await capturedReadBytes(envelopeWith(nonCanonical));
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as { data: { transaction: { inner: { unix_time_secs: unknown } } } };
    expect(typeof parsed.data.transaction.inner.unix_time_secs).toBe("number");
    expect(ERROR_TAXONOMY.invalid_scalar).toBe("none without corrected input");
  });

  it("unexpected_inner_shape — serves a wrong-version inner (outside the supported v2 shape)", async () => {
    const wrongVersion = { ...TX, inner: { ...TX.inner, version: "3" } };
    const bytes = await capturedReadBytes(envelopeWith(wrongVersion));
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as { data: { transaction: { inner: { version: string } } } };
    expect(parsed.data.transaction.inner.version).toBe("3");
    expect(ERROR_TAXONOMY.unexpected_inner_shape).toBe("none");
  });

  it("signature_invalid — serves a mutated step-1 signature for quarantine", async () => {
    const mutated = { ...TX, step_1_signature: `${TX.step_1_signature}MUTATED` };
    const bytes = await capturedReadBytes(envelopeWith(mutated));
    expect(new TextDecoder().decode(bytes)).toContain(`${TX.step_1_signature}MUTATED`);
    expect(ERROR_TAXONOMY.signature_invalid).toBe("none; quarantine evidence");
  });

  it("wallet_role_invalid — serves a head that does not involve the queried wallet", async () => {
    const unrelated = makeTx("some-other-sender-key", RECEIVER_KEY, "other-link", "other-sig");
    const bytes = await capturedReadBytes(envelopeWith(unrelated));
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as {
      data: { transaction: { inner: { step_1_key_public__base64urlsafe: string } } };
    };
    expect(parsed.data.transaction.inner.step_1_key_public__base64urlsafe).not.toBe(WALLET_KEY);
    expect(ERROR_TAXONOMY.wallet_role_invalid).toBe("none");
  });

  it("chain_link_mismatch — serves a predecessor that does not match the expected link", async () => {
    const wrongPredecessor = makeTx(WALLET_KEY, RECEIVER_KEY, "not-the-expected-link", "sig-x");
    const bytes = await capturedReadBytes(envelopeWith(wrongPredecessor));
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as {
      data: { transaction: { inner: { previous_step_1_state_signature: string } } };
    };
    expect(parsed.data.transaction.inner.previous_step_1_state_signature).toBe("not-the-expected-link");
    expect(ERROR_TAXONOMY.chain_link_mismatch).toBe("none; observation adjudication required");
  });

  it("balance_delta_mismatch — serves an amount that differs from the expected exact delta", async () => {
    const wrongAmount = {
      ...TX,
      inner: { ...TX.inner, step_1_state: { amount: "2.00000000000000000000000000000000" } },
    };
    const bytes = await capturedReadBytes(envelopeWith(wrongAmount));
    expect(new TextDecoder().decode(bytes)).toContain("2.00000000000000000000000000000000");
    expect(ERROR_TAXONOMY.balance_delta_mismatch).toBe("none");
  });

  it("gateway_read_indeterminate — a bounded read that cannot yield verified state: read retries under policy, submit does not", async () => {
    const fake = createFakeGateway();
    fake.scriptRead(GET_TX, { kind: "drop" });
    const recorder = observationRecorder();
    const read = createFakeGatewayReadTransport(fake, {
      limits: LIMITS,
      recorder,
      maxAttempts: 3,
      sleep: async () => undefined,
      jitter: () => 0,
    });

    await expect(read.read([PRIMARY], READ_REQUEST)).rejects.toThrow(GatewayReadExhaustedError);

    // Read retried under policy (bounded): one exchange per attempt, each recorded.
    expect(fake.readExchangeCount(GET_TX)).toBe(3);
    expect(recorder.records.filter((record) => record.transportAmbiguous)).toHaveLength(3);
    // Submit may NOT: no submit attempt was created by the read failure.
    expect(fake.totalSubmitAttempts).toBe(0);
    expect(ERROR_TAXONOMY.gateway_read_indeterminate).toBe("read may be retried under policy; submit may not");
  });

  it("gateway_submit_indeterminate — unknown submit outcome: reconcile by read only, never resubmit", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmit({ kind: "drop" });
    fake.scriptRead(GET_TX, { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { head: "reconciled" } } });
    const recorder = submitRecorder();
    const submit = createFakeGatewaySubmitTransport(fake, { limits: SHORT_TIMEOUT, recorder, authorization: AUTHORIZATION });

    await expect(submit.submit([PRIMARY], buildGatewayActionRequest(SUBMIT_ACTION_NAME, TX))).rejects.toThrow(
      SubmitIndeterminateError,
    );

    expect(recorder.records[0]?.transportOutcome).toBe("INDETERMINATE");
    expect(fake.totalSubmitAttempts).toBe(1);
    // Reconcile by read ONLY: the read succeeds and the submit count does not move.
    const read = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });
    const reconciled = await read.read([PRIMARY], READ_REQUEST);
    expect(reconciled.statusCode).toBe(200);
    expect(fake.totalSubmitAttempts).toBe(1);
    expect(ERROR_TAXONOMY.gateway_submit_indeterminate).toBe("reconcile by read only");
  });

  it("wallet_lease_conflict — serves a definitive 4xx conflict rejection: retry acquisition later, never bypass", async () => {
    const fake = createFakeGateway();
    fake.scriptSubmit({
      kind: "envelope",
      httpStatus: 409,
      envelope: { status: false, code: "wallet_lease_conflict", message: "wallet already has an active operation", data: {} },
    });
    const recorder = submitRecorder();
    const submit = createFakeGatewaySubmitTransport(fake, { limits: LIMITS, recorder, authorization: AUTHORIZATION });

    const response = await submit.submit([PRIMARY], buildGatewayActionRequest(SUBMIT_ACTION_NAME, TX));

    // A 4xx is the gateway's definitive answer (REJECT): surfaced, not blind-retried.
    expect(response.statusCode).toBe(409);
    expect(recorder.records[0]?.transportOutcome).toBe("REJECT");
    expect(fake.totalSubmitAttempts).toBe(1);
    expect(ERROR_TAXONOMY.wallet_lease_conflict).toBe("retry acquisition later; never bypass");
  });

  it("canonical_bytes_mismatch — serves equivocating bytes whose digest differs: fail closed and alert", async () => {
    // Two byte-distinct representations of the same semantic envelope: the digest of the
    // served bytes disagrees with the canonical digest, which is the stored-bytes trigger.
    const canonical = serializeGatewayEnvelope(envelopeWith(TX));
    const equivocated = serializeGatewayEnvelope({
      status: true,
      code: "ok",
      message: "OK ", // trailing space: same semantics, different bytes
      data: { transaction: TX },
    });
    expect(sha256Hex(new TextEncoder().encode(canonical))).not.toBe(sha256Hex(new TextEncoder().encode(equivocated)));

    const bytes = await capturedReadBytes(equivocated);
    // The transport captured the equivocated bytes verbatim as raw evidence.
    expect(sha256Hex(bytes)).toBe(sha256Hex(new TextEncoder().encode(equivocated)));
    expect(sha256Hex(bytes)).not.toBe(sha256Hex(new TextEncoder().encode(canonical)));
    expect(ERROR_TAXONOMY.canonical_bytes_mismatch).toBe("fail closed and alert");
  });
});
