// Operation action routes.
import { describe, expect, it } from "vitest";
import {
  handleArm,
  handleVerificationComplete,
  compareT0Evidence,
  leaseReleaseStatusForVerdict,
  classifyAncestorProof,
  isOperationKind,
  ACTION_EVIDENCE_ROLES,
  OperationVersionConflictError,
  T0MismatchError,
  OperationNotArmableError,
  ProtocolPredicateFailedError,
  type ActionRouteStore,
  type ArmSuccessResponse,
  type VerificationCompleteSuccessResponse,
  type VerificationMaterialResponse,
  type T0EvidenceWire,
  type AncestorProof,
} from "../src/api/routes/index.js";
import { handleGetVerificationMaterial as handleGetVerificationMaterialGated } from "../src/api/verification-material.js";
import {
  ArmBody,
  VerificationCompleteBody,
  ROUTE_SCHEMAS,
  findRouteSchema,
} from "../src/api/route-schemas.js";
import { IdempotencyConflictError } from "../src/api/routes/operation-routes.js";
import type { PipelineContext } from "../src/api/pipeline.js";
import { OPERATION_KINDS, FORBIDDEN_STATE_ALIASES } from "@zucoins/generic-node-contracts/operations";
import { OPERATION_STATUS } from "@zucoins/generic-node-contracts/operations";

const OP_ID = "00000000-0000-4000-8000-000000000001";
const REQ_ID = "00000000-0000-4000-8000-000000000099";
const OBS_ID = "00000000-0000-4000-8000-000000000050";
const WALLET_ID = "00000000-0000-4000-8000-000000000010";
const SHA = "a".repeat(64);

const DURABLE_T0: T0EvidenceWire = {
  observation_id: OBS_ID,
  projection: { s: "sig0", p: "prev0", b_zkz: "0" },
};

const ARM_BODY = {
  expected_row_version: 2,
  t0: DURABLE_T0,
  opened_cursor: "1043",
};

const ARM_SUCCESS: ArmSuccessResponse = {
  operation_id: OP_ID,
  state: "READY",
  row_version: 3,
  code_status: "RELEASED",
  transfer_code: "exact-transfer-code-text",
  transfer_code_sha256: SHA,
  expires_at: "2026-01-01T00:05:00.000Z",
};

const VC_BODY = {
  expected_row_version: 7,
  consumed_cursor: "1051",
  verdict: "VERIFIED" as const,
  wallet_evidence: [
    {
      wallet_id: WALLET_ID,
      role: "RECEIVER" as const,
      t0: DURABLE_T0,
      terminal: {
        observation_id: "00000000-0000-4000-8000-000000000051",
        projection: { s: "sigT", p: "prevT", b_zkz: "5.5" },
      },
      landing_proof: {
        classification: "EXPECTED_ANCESTOR" as const,
        fresh_head_step_2_signature: "sig-head",
        fresh_head_transaction_sha256: SHA,
        path_manifest_sha256: SHA,
      },
    },
  ],
};

const VC_SUCCESS: VerificationCompleteSuccessResponse = {
  operation_id: OP_ID,
  acknowledgement_id: "00000000-0000-4000-8000-000000000070",
  verdict: "VERIFIED",
  lease_release_status: "RELEASED",
  acknowledged_at: "2026-01-01T00:10:00.000Z",
};

const COMPLETE_ANCESTOR: AncestorProof = {
  evidence_role: "RECEIVER",
  wallet_public_key: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
  classification: "EXPECTED_ANCESTOR",
  expected_step_2_signature: "sig-expected",
  fresh_head_step_2_signature: "sig-head",
  fresh_head_transaction_sha256: SHA,
  hop_count: 1,
  path_manifest_sha256: SHA,
  path_manifest: [
    {
      position: 0,
      step_2_signature: "sig-expected",
      queried_wallet_previous_signature: "",
      transaction_sha256: SHA,
      body_index: 0,
    },
    {
      position: 1,
      step_2_signature: "sig-head",
      queried_wallet_previous_signature: "sig-expected",
      transaction_sha256: "b".repeat(64),
      body_index: 1,
    },
  ],
  transaction_bodies: [
    {
      body_index: 0,
      transaction_sha256: SHA,
      settled_transaction_text: "exact-body-0",
    },
    {
      body_index: 1,
      transaction_sha256: "b".repeat(64),
      settled_transaction_text: "exact-body-1",
    },
  ],
  indeterminate_reason: null,
};

const MATERIAL_SUCCESS: VerificationMaterialResponse = {
  operation_id: OP_ID,
  operation_type: "RECEIVE_EXTERNAL",
  state: "RECEIVE_LANDED",
  landed_attempt_no: 1,
  expected_artifact: {
    key_id: "00000000-0000-4000-8000-000000000099",
    preimage_text: "exact canonical text",
    preimage_sha256: SHA,
    signature: "A".repeat(86) + "==",
  },
  observation_evidence: [
    {
      evidence_role: "RECEIVER",
      wallet_id: WALLET_ID,
      wallet_public_key: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
      t0: DURABLE_T0,
      terminal: {
        observation_id: "00000000-0000-4000-8000-000000000051",
        projection: { s: "sigT", p: "prevT", b_zkz: "5.5" },
      },
      node_observation_raw_body_base64: "e30=",
    },
  ],
  attempts: [
    {
      attempt_no: 1,
      classification: "LANDED_VERIFIED",
      transaction: {
        inner_preimage_text: "{}",
        inner_sha256: SHA,
        step_1_signature: "s1",
        step_2_preimage_text: "{}",
        step_2_signature: "s2",
        settled_transaction_text: "exact settled",
      },
    },
  ],
  ancestor_proofs: [COMPLETE_ANCESTOR],
  available_until: "2026-01-31T00:10:00.000Z",
};

function makeCtx(overrides: Partial<PipelineContext> = {}): PipelineContext {
  return {
    requestId: REQ_ID,
    request: {
      method: "POST",
      path: `/v1/operations/${OP_ID}/armed`,
      rawBody: new Uint8Array(0),
      headers: { "idempotency-key": "test-idempotency-key-arm-1" },
      query: {},
    },
    routeSchema: {
      method: "POST",
      path: "/v1/operations/:operation_id/armed",
      requiresIdempotencyKey: true,
    },
    parsedBody: { ...ARM_BODY },
    parsedQuery: undefined,
    ...overrides,
  };
}

function makeStore(overrides: Partial<ActionRouteStore> = {}): ActionRouteStore {
  return {
    arm: async () => ({ status: 200 as const, body: ARM_SUCCESS }),
    verificationComplete: async () => ({ status: 200 as const, body: VC_SUCCESS }),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Route inventory — retired aliases and invent-routes must not exist (AC)
// ---------------------------------------------------------------------------

describe("route inventory (canonical surface only)", () => {
  it("registers the three action routes with the correct methods", () => {
    expect(findRouteSchema("POST", "/v1/operations/:operation_id/armed")).toBeDefined();
    expect(
      findRouteSchema("POST", "/v1/operations/:operation_id/verification-complete"),
    ).toBeDefined();
    expect(
      findRouteSchema("GET", "/v1/operations/:operation_id/verification-material"),
    ).toBeDefined();
  });

  it("does not register invent-routes (arm/sign/approve/cancel aliases, retired paths)", () => {
    const paths = ROUTE_SCHEMAS.map((r) => `${r.method} ${r.path}`);
    const forbidden = [
      "POST /v1/receives/:operation_id/arm",
      "POST /v1/internal-moves/:operation_id/sign",
      "POST /v1/external-sends/:operation_id/approve",
      "POST /v1/external-sends/:operation_id/reject",
      "POST /v1/operations/:operation_id/cancel",
      "POST /v1/operations/:operation_id/sign",
      "POST /v1/operations/:operation_id/state",
      "PATCH /v1/operations/:operation_id",
      "PUT /v1/operations/:operation_id",
      "POST /v1/reservations",
      "POST /v1/payments",
      "POST /v1/refunds",
      "POST /v1/outbound-requests",
    ];
    for (const f of forbidden) {
      expect(paths.includes(f), `must not register ${f}`).toBe(false);
    }
  });

  it("requires idempotency on arm and verification-complete; not on material GET", () => {
    expect(findRouteSchema("POST", "/v1/operations/:operation_id/armed")!.requiresIdempotencyKey).toBe(
      true,
    );
    expect(
      findRouteSchema("POST", "/v1/operations/:operation_id/verification-complete")!
        .requiresIdempotencyKey,
    ).toBe(true);
    expect(
      findRouteSchema("GET", "/v1/operations/:operation_id/verification-material")!
        .requiresIdempotencyKey,
    ).toBe(false);
  });

  it("consumes frozen OPERATION_KINDS / OPERATION_STATUS (no fabricated Layer-1 states)", () => {
    expect([...OPERATION_KINDS]).toEqual([
      "RECEIVE_EXTERNAL",
      "MOVE_INTERNAL",
      "SEND_EXTERNAL",
    ]);
    // Forbidden aliases from states.contract must not be treated as operation kinds.
    for (const alias of FORBIDDEN_STATE_ALIASES) {
      expect(isOperationKind(alias)).toBe(false);
    }
    // Fabricated states from the prior failed PR must not appear in frozen status.
    for (const bad of ["SUBMITTED", "FAILED", "LANDED", "CANCELLED", "ARMED"] as const) {
      expect((OPERATION_STATUS as readonly string[]).includes(bad)).toBe(false);
    }
    expect(isOperationKind("RECEIVE_EXTERNAL")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Pure predicates
// ---------------------------------------------------------------------------

describe("compareT0Evidence ", () => {
  it("returns null when all fields match", () => {
    expect(compareT0Evidence(DURABLE_T0, { ...DURABLE_T0 })).toBeNull();
  });

  it("returns the first mismatched field without claiming a match", () => {
    expect(
      compareT0Evidence(DURABLE_T0, {
        ...DURABLE_T0,
        observation_id: "00000000-0000-4000-8000-000000000099",
      }),
    ).toBe("observation_id");
    expect(
      compareT0Evidence(DURABLE_T0, {
        observation_id: OBS_ID,
        projection: { ...DURABLE_T0.projection, s: "wrong" },
      }),
    ).toBe("s");
    expect(
      compareT0Evidence(DURABLE_T0, {
        observation_id: OBS_ID,
        projection: { ...DURABLE_T0.projection, p: "wrong" },
      }),
    ).toBe("p");
    expect(
      compareT0Evidence(DURABLE_T0, {
        observation_id: OBS_ID,
        projection: { ...DURABLE_T0.projection, b_zkz: "1" },
      }),
    ).toBe("b_zkz");
  });
});

describe("leaseReleaseStatusForVerdict ", () => {
  it("allows RELEASED only for VERIFIED", () => {
    expect(leaseReleaseStatusForVerdict("VERIFIED", "RELEASED")).toBe("RELEASED");
    expect(leaseReleaseStatusForVerdict("VERIFIED", "PINNED_GROUP_PENDING")).toBe(
      "PINNED_GROUP_PENDING",
    );
  });

  it("never silently releases on REJECTED or INDETERMINATE", () => {
    expect(leaseReleaseStatusForVerdict("REJECTED", "RELEASED")).toBe("PINNED_FOR_ATTENTION");
    expect(leaseReleaseStatusForVerdict("INDETERMINATE", "RELEASED")).toBe(
      "PINNED_FOR_ATTENTION",
    );
    expect(leaseReleaseStatusForVerdict("INDETERMINATE", "PINNED_GROUP_PENDING")).toBe(
      "PINNED_GROUP_PENDING",
    );
  });
});

describe("classifyAncestorProof ", () => {
  it("emits landing classification only when complete", () => {
    expect(
      classifyAncestorProof({
        missingBody: false,
        linkGap: false,
        anomaly: false,
        freshHeadMismatch: false,
        budgetExceeded: false,
        intendedClassification: "EXPECTED_AT_HEAD",
      }),
    ).toEqual({ classification: "EXPECTED_AT_HEAD", indeterminate_reason: null });
  });

  it("forces INDETERMINATE with MISSING_BODY — never a landing classification", () => {
    const r = classifyAncestorProof({
      missingBody: true,
      linkGap: false,
      anomaly: false,
      freshHeadMismatch: false,
      budgetExceeded: false,
      intendedClassification: "EXPECTED_ANCESTOR",
    });
    expect(r.classification).toBe("INDETERMINATE");
    expect(r.indeterminate_reason).toBe("MISSING_BODY");
  });

  it("forces INDETERMINATE for LINK_GAP / ANOMALY / FRESH_HEAD_MISMATCH / BUDGET_EXCEEDED", () => {
    expect(
      classifyAncestorProof({
        missingBody: false,
        linkGap: true,
        anomaly: false,
        freshHeadMismatch: false,
        budgetExceeded: false,
        intendedClassification: "EXPECTED_ANCESTOR",
      }).indeterminate_reason,
    ).toBe("LINK_GAP");
    expect(
      classifyAncestorProof({
        missingBody: false,
        linkGap: false,
        anomaly: true,
        freshHeadMismatch: false,
        budgetExceeded: false,
        intendedClassification: "EXPECTED_ANCESTOR",
      }).indeterminate_reason,
    ).toBe("ANOMALY");
    expect(
      classifyAncestorProof({
        missingBody: false,
        linkGap: false,
        anomaly: false,
        freshHeadMismatch: true,
        budgetExceeded: false,
        intendedClassification: "EXPECTED_AT_HEAD",
      }).indeterminate_reason,
    ).toBe("FRESH_HEAD_MISMATCH");
    expect(
      classifyAncestorProof({
        missingBody: false,
        linkGap: false,
        anomaly: false,
        freshHeadMismatch: false,
        budgetExceeded: true,
        intendedClassification: "EXPECTED_AT_HEAD",
      }).indeterminate_reason,
    ).toBe("BUDGET_EXCEEDED");
  });
});

// ---------------------------------------------------------------------------
// handleArm
// ---------------------------------------------------------------------------

describe("handleArm ", () => {
  it("returns 200 with released transfer code on success", async () => {
    const result = await handleArm(makeCtx(), makeStore(), OP_ID);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(200);
    const body = JSON.parse(result.body) as ArmSuccessResponse;
    expect(body.operation_id).toBe(OP_ID);
    expect(body.state).toBe("READY");
    expect(body.code_status).toBe("RELEASED");
    expect(body.transfer_code).toBe("exact-transfer-code-text");
    expect(body.transfer_code_sha256).toBe(SHA);
    expect(body.row_version).toBe(3);
  });

  it("returns 409 operation_version_conflict on stale expected_row_version (CAS)", async () => {
    const store = makeStore({
      arm: async () => {
        throw new OperationVersionConflictError();
      },
    });
    const result = await handleArm(makeCtx(), store, OP_ID);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("operation_version_conflict");
  });

  it("returns 409 t0_mismatch when durable T0 disagrees (no code release)", async () => {
    const store = makeStore({
      arm: async () => {
        throw new T0MismatchError("b_zkz");
      },
    });
    const result = await handleArm(makeCtx(), store, OP_ID);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("t0_mismatch");
  });

  it("returns 409 operation_not_armable when not READY / code unavailable", async () => {
    const store = makeStore({
      arm: async () => {
        throw new OperationNotArmableError("operation is in state CREATED, expected READY");
      },
    });
    const result = await handleArm(makeCtx(), store, OP_ID);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("operation_not_armable");
  });

  it("replays byte-identical body with Idempotency-Replayed on same key/request", async () => {
    const store = makeStore({
      arm: async () => ({
        status: 200 as const,
        body: ARM_SUCCESS,
        idempotentReplay: true,
      }),
    });
    const result = await handleArm(makeCtx(), store, OP_ID);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.headers?.["Idempotency-Replayed"]).toBe("true");
    // Exact stored body bytes — not a freshly-minted release.
    expect(result.body).toBe(JSON.stringify(ARM_SUCCESS));
  });

  it("omits Idempotency-Replayed on a fresh arm", async () => {
    const result = await handleArm(makeCtx(), makeStore(), OP_ID);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.headers?.["Idempotency-Replayed"]).toBeUndefined();
  });

  it("returns 409 idempotency_conflict on fingerprint mismatch", async () => {
    const store = makeStore({
      arm: async () => {
        throw new IdempotencyConflictError();
      },
    });
    const result = await handleArm(makeCtx(), store, OP_ID);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("idempotency_conflict");
  });
});

// ---------------------------------------------------------------------------
// handleVerificationComplete
// ---------------------------------------------------------------------------

describe("handleVerificationComplete ", () => {
  function vcCtx(overrides: Partial<PipelineContext> = {}): PipelineContext {
    return makeCtx({
      request: {
        method: "POST",
        path: `/v1/operations/${OP_ID}/verification-complete`,
        rawBody: new Uint8Array(0),
        headers: { "idempotency-key": "test-idempotency-key-vc-1" },
        query: {},
      },
      routeSchema: {
        method: "POST",
        path: "/v1/operations/:operation_id/verification-complete",
        requiresIdempotencyKey: true,
      },
      parsedBody: { ...VC_BODY },
      ...overrides,
    });
  }

  it("returns 200 with acknowledgement and lease_release_status on VERIFIED", async () => {
    const result = await handleVerificationComplete(vcCtx(), makeStore(), OP_ID);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(200);
    const body = JSON.parse(result.body) as VerificationCompleteSuccessResponse;
    expect(body.verdict).toBe("VERIFIED");
    expect(body.lease_release_status).toBe("RELEASED");
    expect(body.acknowledgement_id).toBe(VC_SUCCESS.acknowledgement_id);
  });

  it("returns 409 operation_version_conflict on stale expected_row_version (CAS)", async () => {
    const store = makeStore({
      verificationComplete: async () => {
        throw new OperationVersionConflictError();
      },
    });
    const result = await handleVerificationComplete(vcCtx(), store, OP_ID);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("operation_version_conflict");
  });

  it("forces PINNED_FOR_ATTENTION when store wrongly releases on REJECTED", async () => {
    const store = makeStore({
      verificationComplete: async () => ({
        status: 200 as const,
        body: {
          ...VC_SUCCESS,
          verdict: "REJECTED",
          lease_release_status: "RELEASED", // illegal — handler must pin
        },
      }),
    });
    const result = await handleVerificationComplete(
      vcCtx({ parsedBody: { ...VC_BODY, verdict: "REJECTED" } }),
      store,
      OP_ID,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const body = JSON.parse(result.body) as VerificationCompleteSuccessResponse;
    expect(body.verdict).toBe("REJECTED");
    expect(body.lease_release_status).toBe("PINNED_FOR_ATTENTION");
  });

  it("forces pin on INDETERMINATE (incomplete landing_proof acknowledgement)", async () => {
    const store = makeStore({
      verificationComplete: async () => ({
        status: 200 as const,
        body: {
          ...VC_SUCCESS,
          verdict: "INDETERMINATE",
          lease_release_status: "RELEASED",
        },
      }),
    });
    const result = await handleVerificationComplete(
      vcCtx({ parsedBody: { ...VC_BODY, verdict: "INDETERMINATE" } }),
      store,
      OP_ID,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const body = JSON.parse(result.body) as VerificationCompleteSuccessResponse;
    expect(body.lease_release_status).toBe("PINNED_FOR_ATTENTION");
  });

  it("returns byte-identical body on idempotent replay", async () => {
    const store = makeStore({
      verificationComplete: async () => ({
        status: 200 as const,
        body: VC_SUCCESS,
        idempotentReplay: true,
      }),
    });
    const result = await handleVerificationComplete(vcCtx(), store, OP_ID);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.headers?.["Idempotency-Replayed"]).toBe("true");
    expect(result.body).toBe(JSON.stringify(VC_SUCCESS));
  });

  it("returns 422 when wallet_evidence set fails the protocol predicate", async () => {
    const store = makeStore({
      verificationComplete: async () => {
        throw new ProtocolPredicateFailedError(
          "wallet_evidence set does not match operation rows",
        );
      },
    });
    const result = await handleVerificationComplete(vcCtx(), store, OP_ID);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(422);
    expect(JSON.parse(result.error.body).error.code).toBe("protocol_predicate_failed");
  });
});

// ---------------------------------------------------------------------------
// verification-material — gated transport only (D5)
// ---------------------------------------------------------------------------

describe("verification-material surface (no action-routes twin)", () => {
  it("routes/index does not export an ungated handleGetVerificationMaterial", async () => {
    const routes = await import("../src/api/routes/index.js");
    expect(
      Object.prototype.hasOwnProperty.call(routes, "handleGetVerificationMaterial"),
    ).toBe(false);
  });

  it("ACTION_EVIDENCE_ROLES includes EXTERNAL_DESTINATION_PARTIAL (not LOOKUP)", () => {
    expect([...ACTION_EVIDENCE_ROLES]).toEqual([
      "RECEIVER",
      "SOURCE",
      "DESTINATION",
      "EXTERNAL_SENDER_PREFLIGHT",
      "EXTERNAL_DESTINATION_PARTIAL",
    ]);
  });

  it("MATERIAL_SUCCESS wire shape allows null landed_attempt_no", () => {
    const withNull: VerificationMaterialResponse = {
      ...MATERIAL_SUCCESS,
      landed_attempt_no: null,
    };
    expect(withNull.landed_attempt_no).toBeNull();
  });

  it("classifyAncestorProof still forces INDETERMINATE for incomplete paths", () => {
    const incomplete = classifyAncestorProof({
      missingBody: true,
      linkGap: false,
      anomaly: false,
      freshHeadMismatch: false,
      budgetExceeded: false,
      intendedClassification: "EXPECTED_ANCESTOR",
    });
    expect(incomplete).toEqual({
      classification: "INDETERMINATE",
      indeterminate_reason: "MISSING_BODY",
    });
  });

  // Gated handler remains the sole GET entry — smoke that the name still resolves.
  it("gated handleGetVerificationMaterial is importable from api/verification-material", () => {
    expect(typeof handleGetVerificationMaterialGated).toBe("function");
  });
});

// ---------------------------------------------------------------------------
// Body schemas — reject generic mutation fields (AC negative)
// ---------------------------------------------------------------------------

describe("request body schemas reject generic state mutation fields", () => {
  it("ArmBody rejects replacement transaction / destination / amount / state fields", () => {
    for (const poison of [
      { ...ARM_BODY, amount_zkz: "1" },
      { ...ARM_BODY, destination_address: "x" },
      { ...ARM_BODY, transaction_bytes: "deadbeef" },
      { ...ARM_BODY, state: "RECEIVE_LANDED" },
      { ...ARM_BODY, new_state: "READY" },
      { ...ARM_BODY, submit: true },
    ]) {
      const r = ArmBody.safeParse(poison);
      expect(r.success, JSON.stringify(poison)).toBe(false);
      if (!r.success) {
        expect(r.error.issues.some((i) => i.code === "unrecognized_keys")).toBe(true);
      }
    }
  });

  it("VerificationCompleteBody rejects replacement transaction / destination / amount", () => {
    for (const poison of [
      { ...VC_BODY, amount_zkz: "9" },
      { ...VC_BODY, destination_address: "x" },
      { ...VC_BODY, transaction_bytes: "aa" },
      { ...VC_BODY, submit: true },
    ]) {
      const r = VerificationCompleteBody.safeParse(poison);
      expect(r.success, JSON.stringify(poison)).toBe(false);
    }
  });

  it("ArmBody accepts the shape", () => {
    expect(ArmBody.safeParse(ARM_BODY).success).toBe(true);
  });

  it("VerificationCompleteBody accepts the shape", () => {
    expect(VerificationCompleteBody.safeParse(VC_BODY).success).toBe(true);
  });
});
