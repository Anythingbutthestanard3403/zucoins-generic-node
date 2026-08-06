// four Review-indicator tests for the arm pre-open barrier.
//
// 1. Six-field completeness: missing any of operation_id / t0_observation_id / s / p /
// b_zkz / opened_cursor rejects rather than silently defaulting.
// 2. Asymmetry: t0.observation_id is a node durable-row identity claim; t0.projection is
// pure consumer comparison data — never auto-populated from the node's stored projection.
// 3. Reporting credential: arm without a verified zp-report-request-v1 (wrong route / missing
// credential shape) is rejected before T0 comparison.
// 4. Cross-domain: comparison shape never carries consumer raw observation bytes / consumer
// observation id into the node ledger surface.

import { describe, expect, it, vi } from "vitest";

import {
  ARM_REQUEST_BINDING_FIELDS,
  comparisonImportsConsumerObservation,
  parseArmRequestBinding,
  prepareArmT0Comparison,
  type NodeDurableT0,
} from "./arm-binding.js";
import {
  ARM_ROUTE_ID,
  assertArmReportingCredential,
  isVerifiedReportRequest,
  operationIdFromArmTarget,
  runArmPreopen,
  type ArmVerifiedReportingRequest,
} from "./arm-preopen.js";

const OP_ID = "33333333-3333-4333-8333-333333333333";
const NODE_OBS = "55555555-5555-4555-8555-555555555555";
const OTHER_OBS = "66666666-6666-4666-8666-666666666666";
const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPL_ID = "22222222-2222-4222-8222-222222222222";
const KEY_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const NONCE = "99999999-9999-4999-8999-999999999999";

const NODE_T0: NodeDurableT0 = {
  observationId: NODE_OBS,
  projection: { s: "node-S0", p: "node-P0", b_zkz: "0" },
};

const VALID_BODY = {
  expected_row_version: 2,
  t0: {
    observation_id: NODE_OBS,
    projection: { s: "node-S0", p: "node-P0", b_zkz: "0" },
  },
  opened_cursor: "1043",
};

function encodeBody(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function makeVerified(overrides: {
  readonly routeId?: string;
  readonly requestClass?: "READ" | "MUTATION";
  readonly rawTarget?: string;
  readonly body?: unknown;
  readonly bodyBytes?: Uint8Array;
  readonly idempotencyKey?: string | null;
}): ArmVerifiedReportingRequest {
  const bodyBytes =
    overrides.bodyBytes ?? encodeBody(overrides.body ?? VALID_BODY);
  const rawTarget = overrides.rawTarget ?? `/v1/operations/${OP_ID}/armed`;
  return {
    ok: true,
    binding: {
      reportingKeyId: KEY_ID,
      nodeId: NODE_ID,
      implementerId: IMPL_ID,
    },
    route: {
      routeId: overrides.routeId ?? ARM_ROUTE_ID,
      requestClass: overrides.requestClass ?? "MUTATION",
    },
    nonceEvidence: {
      nonce: NONCE,
      requestPreimageText: "preimage",
      requestSignature: "sig",
    },
    idempotencyKey:
      overrides.idempotencyKey === undefined ? "idem-arm-1" : overrides.idempotencyKey,
    fingerprint: {
      method: "POST",
      rawTarget,
      bodySha256: "b".repeat(64),
    },
    bodyBytes,
  };
}

// ---------------------------------------------------------------------------
// 1. Six-field completeness
// ---------------------------------------------------------------------------

describe("arm-request binding — six-field completeness", () => {
  it("exports exactly the six binding field names", () => {
    expect([...ARM_REQUEST_BINDING_FIELDS]).toEqual([
      "operation_id",
      "t0_observation_id",
      "s",
      "p",
      "b_zkz",
      "opened_cursor",
    ]);
  });

  it("accepts a complete body + path operation_id", () => {
    const r = parseArmRequestBinding({ operationId: OP_ID, body: VALID_BODY });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.binding.operationId).toBe(OP_ID);
    expect(r.binding.nodeT0ObservationId).toBe(NODE_OBS);
    expect(r.binding.consumerProjection).toEqual({ s: "node-S0", p: "node-P0", b_zkz: "0" });
    expect(r.binding.openedCursor).toBe(1043n);
    expect(r.binding.expectedRowVersion).toBe(2);
  });

  it("rejects missing operation_id (invalid path id) without defaulting", () => {
    const r = parseArmRequestBinding({ operationId: "", body: VALID_BODY });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.field).toBe("operation_id");
  });

  it("rejects missing t0.observation_id (node t0_observation_id)", () => {
    const body = {
      expected_row_version: 2,
      t0: { projection: { s: "", p: "", b_zkz: "0" } },
      opened_cursor: "1",
    };
    const r = parseArmRequestBinding({ operationId: OP_ID, body });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe("missing_field");
    expect(r.field).toBe("t0_observation_id");
  });

  it("rejects missing t0.projection.s without defaulting to empty string", () => {
    const body = {
      expected_row_version: 2,
      t0: { observation_id: NODE_OBS, projection: { p: "", b_zkz: "0" } },
      opened_cursor: "1",
    };
    const r = parseArmRequestBinding({ operationId: OP_ID, body });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe("missing_field");
    expect(r.field).toBe("s");
  });

  it("rejects missing t0.projection.p", () => {
    const body = {
      expected_row_version: 2,
      t0: { observation_id: NODE_OBS, projection: { s: "", b_zkz: "0" } },
      opened_cursor: "1",
    };
    const r = parseArmRequestBinding({ operationId: OP_ID, body });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.field).toBe("p");
  });

  it("rejects missing t0.projection.b_zkz", () => {
    const body = {
      expected_row_version: 2,
      t0: { observation_id: NODE_OBS, projection: { s: "", p: "" } },
      opened_cursor: "1",
    };
    const r = parseArmRequestBinding({ operationId: OP_ID, body });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.field).toBe("b_zkz");
  });

  it("rejects missing opened_cursor", () => {
    const body = {
      expected_row_version: 2,
      t0: { observation_id: NODE_OBS, projection: { s: "", p: "", b_zkz: "0" } },
    };
    const r = parseArmRequestBinding({ operationId: OP_ID, body });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe("missing_field");
    expect(r.field).toBe("opened_cursor");
  });

  it("rejects missing entire t0 object", () => {
    const body = { expected_row_version: 2, opened_cursor: "1" };
    const r = parseArmRequestBinding({ operationId: OP_ID, body });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.field).toBe("t0_observation_id");
  });
});

// ---------------------------------------------------------------------------
// 2. Asymmetry — node observation id vs consumer projection
// ---------------------------------------------------------------------------

describe("arm-request binding — observation-id / projection asymmetry", () => {
  it("treats t0.observation_id as a node identity claim and projection as consumer data", () => {
    const body = {
      expected_row_version: 2,
      t0: {
        observation_id: NODE_OBS,
        // Deliberately different from node durable projection — consumer's independent read.
        projection: { s: "consumer-S", p: "consumer-P", b_zkz: "7" },
      },
      opened_cursor: "9",
    };
    const parsed = parseArmRequestBinding({ operationId: OP_ID, body });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    const prep = prepareArmT0Comparison(parsed.binding, NODE_T0);
    expect(prep.ok).toBe(true);
    if (!prep.ok) return;

    // Named id is compared against the node row — not used to look up a consumer observation.
    expect(prep.comparison.namedNodeObservationId).toBe(NODE_OBS);
    expect(prep.comparison.nodeObservationId).toBe(NODE_OBS);

    // Consumer projection is exactly what the request carried — never filled from NODE_T0.
    expect(prep.comparison.consumerProjection).toEqual({
      s: "consumer-S",
      p: "consumer-P",
      b_zkz: "7",
    });
    expect(prep.comparison.nodeProjection).toEqual(NODE_T0.projection);
    expect(prep.comparison.consumerProjection).not.toEqual(prep.comparison.nodeProjection);
    expect(prep.mismatchField).toBe("s");
  });

  it("does not auto-populate consumer projection from node durable T0 when fields match on id only", () => {
    const body = {
      expected_row_version: 2,
      t0: {
        observation_id: NODE_OBS,
        projection: { s: "other", p: "other", b_zkz: "1" },
      },
      opened_cursor: "0",
    };
    const parsed = parseArmRequestBinding({ operationId: OP_ID, body });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const prep = prepareArmT0Comparison(parsed.binding, NODE_T0);
    expect(prep.ok).toBe(true);
    if (!prep.ok) return;
    // Still consumer values — prepare never copies node → consumer.
    expect(prep.comparison.consumerProjection.s).toBe("other");
    expect(prep.mismatchField).not.toBeNull();
  });

  it("flags observation_id mismatch when consumer names a non-node id", () => {
    const body = {
      expected_row_version: 2,
      t0: {
        observation_id: OTHER_OBS,
        projection: { ...NODE_T0.projection },
      },
      opened_cursor: "1",
    };
    const parsed = parseArmRequestBinding({ operationId: OP_ID, body });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const prep = prepareArmT0Comparison(parsed.binding, NODE_T0);
    expect(prep.ok).toBe(true);
    if (!prep.ok) return;
    expect(prep.mismatchField).toBe("observation_id");
  });

  it("returns match (mismatchField null) only when all four fields agree", () => {
    const parsed = parseArmRequestBinding({ operationId: OP_ID, body: VALID_BODY });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const prep = prepareArmT0Comparison(parsed.binding, NODE_T0);
    expect(prep.ok).toBe(true);
    if (!prep.ok) return;
    expect(prep.mismatchField).toBeNull();
  });

  it("returns t0_not_found when the operation has no node durable T0", () => {
    const parsed = parseArmRequestBinding({ operationId: OP_ID, body: VALID_BODY });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const prep = prepareArmT0Comparison(parsed.binding, null);
    expect(prep.ok).toBe(false);
    if (prep.ok) return;
    expect(prep.reason).toBe("t0_not_found");
  });
});

// ---------------------------------------------------------------------------
// 3. Reporting credential gate before T0 comparison
// ---------------------------------------------------------------------------

describe("arm pre-open — zp-report-request-v1 credential gate (A.5)", () => {
  it("identifies the frozen operation_armed reporting route id", () => {
    expect(ARM_ROUTE_ID).toBe("operation_armed");
  });

  it("extracts operation_id from the armed path", () => {
    expect(operationIdFromArmTarget(`/v1/operations/${OP_ID}/armed`)).toBe(OP_ID);
    expect(operationIdFromArmTarget(`/v1/operations/${OP_ID}/verification-complete`)).toBeNull();
  });

  it("rejects a verified request on the wrong reporting route before T0 compare", async () => {
    const getT0 = vi.fn(async () => NODE_T0);
    const request = makeVerified({
      routeId: "verification_complete",
      rawTarget: `/v1/operations/${OP_ID}/verification-complete`,
    });
    const gate = assertArmReportingCredential(request);
    expect(gate.ok).toBe(false);
    if (gate.ok) return;
    expect(gate.code).toBe("wrong_reporting_route");

    const result = await runArmPreopen(request, { getNodeDurableT0: getT0 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.rejectedBeforeComparison).toBe(true);
    expect(result.code).toBe("wrong_reporting_route");
    expect(getT0).not.toHaveBeenCalled();
  });

  it("rejects a non-VerifiedReportRequest shape (no credential) via type guard", () => {
    expect(isVerifiedReportRequest(undefined)).toBe(false);
    expect(isVerifiedReportRequest(null)).toBe(false);
    expect(isVerifiedReportRequest({ ok: false, code: "invalid_signature" })).toBe(false);
    expect(isVerifiedReportRequest(makeVerified({}))).toBe(true);
  });

  it("rejects malformed arm body before durable T0 load", async () => {
    const getT0 = vi.fn(async () => NODE_T0);
    const request = makeVerified({
      bodyBytes: encodeBody({ expected_row_version: 2, opened_cursor: "1" }),
    });
    const result = await runArmPreopen(request, { getNodeDurableT0: getT0 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.rejectedBeforeComparison).toBe(true);
    expect(result.code).toBe("invalid_arm_binding");
    expect(getT0).not.toHaveBeenCalled();
  });

  it("accepts a verified operation_armed request and prepares comparison", async () => {
    const getT0 = vi.fn(async () => NODE_T0);
    const result = await runArmPreopen(makeVerified({}), { getNodeDurableT0: getT0 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(getT0).toHaveBeenCalledOnce();
    expect(result.mismatchField).toBeNull();
    expect(result.binding.openedCursor).toBe(1043n);
    expect(result.reporting.implementerId).toBe(IMPL_ID);
    expect(result.reporting.nonce).toBe(NONCE);
  });

  it("surfaces t0 mismatch on the prepared shape without mutating durable T0", async () => {
    const durable: NodeDurableT0 = {
      observationId: NODE_OBS,
      projection: { s: "node-S0", p: "node-P0", b_zkz: "0" },
    };
    const body = {
      expected_row_version: 2,
      t0: {
        observation_id: NODE_OBS,
        projection: { s: "wrong", p: "node-P0", b_zkz: "0" },
      },
      opened_cursor: "1043",
    };
    const result = await runArmPreopen(makeVerified({ body }), {
      getNodeDurableT0: async () => durable,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.mismatchField).toBe("s");
    // Durable port returned the same object reference; pre-open must not have rewritten it.
    expect(durable.projection.s).toBe("node-S0");
  });
});

// ---------------------------------------------------------------------------
// 4. Cross-domain — no consumer raw observation import
// ---------------------------------------------------------------------------

describe("arm pre-open — cross-domain isolation", () => {
  it("comparison shape carries only node id + projections + cursor — no consumer obs id/body", () => {
    const parsed = parseArmRequestBinding({ operationId: OP_ID, body: VALID_BODY });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const prep = prepareArmT0Comparison(parsed.binding, NODE_T0);
    expect(prep.ok).toBe(true);
    if (!prep.ok) return;
    expect(comparisonImportsConsumerObservation(prep.comparison)).toBe(false);
    expect(prep.comparison).not.toHaveProperty("consumerObservationId");
    expect(prep.comparison).not.toHaveProperty("rawBody");
    expect(prep.comparison).not.toHaveProperty("node_observation_raw_body_base64");
    // Only projection strings on the consumer side.
    expect(Object.keys(prep.comparison.consumerProjection).sort()).toEqual(["b_zkz", "p", "s"]);
  });

  it("runArmPreopen never asks the durable port for a consumer observation id", async () => {
    const getT0 = vi.fn(async (input: {
      operationId: string;
      nodeId: string;
      implementerId: string;
    }) => {
      // Port contract: only operation + tenant identity — no consumer obs id parameter.
      expect(Object.keys(input).sort()).toEqual(["implementerId", "nodeId", "operationId"]);
      return NODE_T0;
    });
    const body = {
      expected_row_version: 2,
      t0: {
        observation_id: NODE_OBS,
        projection: { s: "consumer-only", p: "", b_zkz: "0" },
      },
      opened_cursor: "3",
    };
    await runArmPreopen(makeVerified({ body }), { getNodeDurableT0: getT0 });
    expect(getT0).toHaveBeenCalledOnce();
  });
});
