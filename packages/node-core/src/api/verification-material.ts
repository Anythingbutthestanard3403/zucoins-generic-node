// The runtime request→response handler for
// `GET /v1/operations/:operation_id/verification-material`.
//
// Before material is ready the route returns `409 verification_material_not_ready`; after
// access expiry it returns `410 verification_material_expired`. The window is the terminal
// plus 30 days, bounded durably by `operations.verification_material_available_until`.
// Expiry revokes access only and never deletes evidence.
//
// The access DECISION is not made here. It is the pure gate in
// `../data/retention.js` (`resolveVerificationMaterialAccess`), which owns the
// NOT_READY/ACCESSIBLE/EXPIRED verdict and its frozen HTTP projection. This module is
// only the transport edge: it resolves the row through a tenant-scoped port, asks the
// gate, and emits the canonical envelope. Keeping the decision in one place is what stops
// a second, drifting copy of the 409/200/410 rule appearing at the HTTP layer.
//
// Expiry never deletes: a 410 here means the access window closed, not that any evidence
// row was removed (item 20). The port is read-only by construction.

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

import { resolveVerificationMaterialAccess } from "../core/index.js";
import { apiErrorResponse, type ApiErrorCode, type ApiErrorResponse } from "./error-envelope.js";

// The persisted operation state this endpoint gates on, plus the already-assembled.1
// evidence payload. The evidence assembly itself (expected_artifact, observation_evidence,
// attempts, ancestor_proofs) belongs to the verification lanes; this handler never builds
// it and never inspects it — it binds the two fields makes this route responsible
// for (`operation_id` and `available_until`) around whatever the source assembled.
export interface VerificationMaterialRow {
  readonly kind: OperationKind;
  // The operation's current Layer-1 status (states.contract.ts). Only the kind's
  // landed-terminal status can serve material; every other status is 409.
  readonly status: string;
  // The persisted `operations.verification_material_available_until` as a millisecond
  // epoch, or null while the operation has not reached a landed terminal. This is the
  // exact column the terminal-transition writer populates with
  // `verificationMaterialAvailableUntilMs(terminal_at)`.
  readonly verificationMaterialAvailableUntilMs: number | null;
  // The response fields between `operation_id` and `available_until`, in the frozen
  // document sequence (operation_type, state, landed_attempt_no, expected_artifact,
  // observation_evidence, attempts, ancestor_proofs).
  readonly material: Readonly<Record<string, unknown>>;
}

// Tenant-scoped read. Returns null for an unknown operation AND for an operation owned by
// another tenant — pipeline stage 5 (`resolve_object_with_tenant_predicate`) collapses
// cross-tenant to `not_found`, so cross-tenant existence never leaks through a 409/410.
export interface VerificationMaterialSource {
  load(operationId: string, tenantId: string): Promise<VerificationMaterialRow | null>;
}

export interface VerificationMaterialRequest {
  readonly requestId: string;
  readonly operationId: string;
  readonly tenantId: string;
  // Injected read-time clock. The module owns no clock: the same inputs always produce
  // the same verdict.
  readonly nowMs: number;
}

export interface VerificationMaterialOk {
  readonly status: 200;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

export type VerificationMaterialResponse = VerificationMaterialOk | ApiErrorResponse;

const JSON_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "content-type": "application/json",
});

// fields between operation_id and available_until, in document ordering.
// buildBody inserts ONLY these keys from row.material — no open Record spread
// so a hostile/buggy assembler cannot forge operation_id, inject private_key, or
// rearrange the wire object, either of which would break byte-exact signing.
export const VERIFICATION_MATERIAL_FIELD_KEYS = [
  "operation_type",
  "state",
  "landed_attempt_no",
  "expected_artifact",
  "observation_evidence",
  "attempts",
  "ancestor_proofs",
] as const;

export type VerificationMaterialFieldKey = (typeof VERIFICATION_MATERIAL_FIELD_KEYS)[number];

// Explicit key insertion sequence, byte-exact
// `operation_id`, the assembled material fields, then `available_until` last.
// operation_id and available_until are bound here and cannot be overridden by material.
function buildBody(operationId: string, row: VerificationMaterialRow, availableUntilMs: number): string {
  const wire: Record<string, unknown> = {
    operation_id: operationId,
  };
  for (const key of VERIFICATION_MATERIAL_FIELD_KEYS) {
    if (Object.prototype.hasOwnProperty.call(row.material, key)) {
      wire[key] = row.material[key];
    }
  }
  wire.available_until = new Date(availableUntilMs).toISOString();
  return JSON.stringify(wire);
}

export async function handleGetVerificationMaterial(
  request: VerificationMaterialRequest,
  source: VerificationMaterialSource,
): Promise<VerificationMaterialResponse> {
  const row = await source.load(request.operationId, request.tenantId);
  if (row === null) {
    return apiErrorResponse("not_found", request.requestId);
  }

  const access = resolveVerificationMaterialAccess({
    kind: row.kind,
    status: row.status,
    verificationMaterialAvailableUntilMs: row.verificationMaterialAvailableUntilMs,
    nowMs: request.nowMs,
  });

  if (access.code !== null) {
    // NOT_READY → 409 verification_material_not_ready; EXPIRED → 410
    // verification_material_expired. The status comes from HTTP_STATUS_BY_CODE via
    // apiErrorResponse, so the gate's projection and the envelope taxonomy cannot drift.
    return apiErrorResponse(access.code as ApiErrorCode, request.requestId);
  }

  // ACCESSIBLE. The gate only returns ACCESSIBLE with a non-null window, so the row's
  // column is non-null here; the assertion is defensive, not a fallback path.
  const availableUntilMs = row.verificationMaterialAvailableUntilMs;
  /* c8 ignore next 3 -- unreachable: decideProofAccess returns NOT_READY when the column is null */
  if (availableUntilMs === null) {
    return apiErrorResponse("verification_material_not_ready", request.requestId);
  }

  return { status: 200, headers: JSON_HEADERS, body: buildBody(request.operationId, row, availableUntilMs) };
}
