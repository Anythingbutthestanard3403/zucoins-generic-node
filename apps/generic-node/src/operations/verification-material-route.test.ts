// Composition smoke for the verification-material reporting route binder.

import { describe, expect, it } from "vitest";

import {
  REPORTING_RETENTION_CLASSES,
  asVerificationMaterialFields,
  assembleVerificationMaterial,
  verificationMaterialAvailableUntilMs,
  type VerificationMaterialSource,
  type VerifiedReportRequest,
} from "@zucoins/node-core";

import {
  VERIFICATION_MATERIAL_ROUTE_ID,
  createVerificationMaterialRouteHandler,
  operationIdFromVerificationMaterialTarget,
  verificationMaterialHandlerEntry,
} from "./verification-material-route.js";

const OP = "22222222-2222-4222-8222-222222222222";
const IMPLEMENTER = "impl-a";
const TERMINAL_AT = Date.UTC(2026, 0, 1);
const UNTIL = verificationMaterialAvailableUntilMs(TERMINAL_AT);

const material = asVerificationMaterialFields(
  assembleVerificationMaterial({
    operation_type: "RECEIVE_EXTERNAL",
    state: "RECEIVE_LANDED",
    landed_attempt_no: 1,
    expected_artifact: {
      key_id: "33333333-3333-4333-8333-333333333333",
      preimage_text: "{}",
      preimage_sha256: "a".repeat(64),
      signature: `${"A".repeat(86)}==`,
    },
    observation_evidence: [],
    attempts: [],
    ancestor_proofs: [
      {
        evidence_role: "RECEIVER",
        wallet_public_key: `${"P".repeat(43)}=`,
        classification: "INDETERMINATE",
        expected_step_2_signature: `${"A".repeat(86)}==`,
        fresh_head_step_2_signature: `${"A".repeat(86)}==`,
        fresh_head_transaction_sha256: "b".repeat(64),
        path_manifest: [],
        transaction_bodies: [],
        indeterminate_reason: "MISSING_BODY",
      },
    ],
  }),
);

function verified(rawTarget: string): VerifiedReportRequest {
  return {
    ok: true,
    binding: {
      reportingKeyId: "key-1",
      nodeId: "node-1",
      implementerId: IMPLEMENTER,
      publicKeyEncoded: `${"K".repeat(43)}=`,
    },
    route: {
      routeId: VERIFICATION_MATERIAL_ROUTE_ID,
      requestClass: "READ",
      retentionClass: REPORTING_RETENTION_CLASSES.read,
    },
    nonceEvidence: {
      id: "nonce-row",
      nodeId: "node-1",
      implementerId: IMPLEMENTER,
      nonce: "n",
      purpose: "zp-report-request-v1",
      routeId: VERIFICATION_MATERIAL_ROUTE_ID,
      requestClass: "READ",
      reportingKeyId: "key-1",
      lifecycleEpoch: 1n,
      nonceBurnSequence: 1n,
      requestPreimageText: "{}",
      requestPreimageSha256: "c".repeat(64),
      requestSignature: `${"S".repeat(86)}==`,
      method: "GET",
      rawTarget,
      bodySha256: "0".repeat(64),
      logicalFingerprint: "f".repeat(64),
      issuedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-01T00:05:00.000Z",
      receivedAtMs: TERMINAL_AT,
      consumedAtMs: TERMINAL_AT,
      retentionClass: REPORTING_RETENTION_CLASSES.read,
    },
    idempotencyKey: null,
    fingerprint: {
      method: "GET",
      rawTarget,
      bodySha256: "0".repeat(64),
    },
    bodyBytes: new Uint8Array(),
    lastEventId: null,
  };
}

describe("operationIdFromVerificationMaterialTarget", () => {
  it("extracts the operation id from the frozen path", () => {
    expect(
      operationIdFromVerificationMaterialTarget(`/v1/operations/${OP}/verification-material`),
    ).toBe(OP);
  });

  it("rejects non-matching targets", () => {
    expect(operationIdFromVerificationMaterialTarget("/v1/operations/x/armed")).toBeNull();
  });
});

describe("createVerificationMaterialRouteHandler", () => {
  const source: VerificationMaterialSource = {
    load: async (operationId, tenantId) =>
      operationId === OP && tenantId === IMPLEMENTER
        ? {
            kind: "RECEIVE_EXTERNAL",
            status: "RECEIVE_LANDED",
            verificationMaterialAvailableUntilMs: UNTIL,
            material,
          }
        : null,
  };

  it("registers under the frozen verification_material route id", () => {
    const entry = verificationMaterialHandlerEntry({
      source,
      nowMs: () => TERMINAL_AT + 1,
      newRequestId: () => "11111111-1111-4111-8111-111111111111",
    });
    expect(Object.keys(entry)).toEqual([VERIFICATION_MATERIAL_ROUTE_ID]);
  });

  it("returns 200 with assembled material for an accessible operation", async () => {
    const handler = createVerificationMaterialRouteHandler({
      source,
      nowMs: () => TERMINAL_AT + 1,
      newRequestId: () => "11111111-1111-4111-8111-111111111111",
    });
    const result = await handler(verified(`/v1/operations/${OP}/verification-material`));
    expect(result.persistChild).toBeNull();
    expect(result.response.status).toBe(200);
    const body = JSON.parse(new TextDecoder().decode(result.response.bodyBytes));
    expect(body.operation_id).toBe(OP);
    expect(body.ancestor_proofs[0].classification).toBe("INDETERMINATE");
    expect(body.ancestor_proofs[0].indeterminate_reason).toBe("MISSING_BODY");
  });

  it("returns 404 when the operation is unknown for the implementer", async () => {
    const handler = createVerificationMaterialRouteHandler({
      source,
      nowMs: () => TERMINAL_AT + 1,
      newRequestId: () => "11111111-1111-4111-8111-111111111111",
    });
    const result = await handler(
      verified("/v1/operations/99999999-9999-4999-8999-999999999999/verification-material"),
    );
    expect(result.response.status).toBe(404);
  });
});
