// Reporting-credential-gated arm pre-open entry. Auth is the signed reporting
// credential only.
//
// Steps 1–2 are consumer-side (open reporting cursor + independent gateway read of
// receiver_pubkey). This module is the node-side entry that runs only after the reporting
// pipeline has verified a `zp-report-request-v1` credential and classified the route
// as `operation_armed`. It:
//
// 1. refuses anything that is not a verified reporting request on the arm route;
// 2. parses the six-field arm-request binding;
// 3. resolves the node's durable T0 for the named operation;
// 4. prepares the four-field T0 comparison shape for.
//
// It does NOT perform the guarded DB-TX (row lock, recovery recheck, arm insert, code release)
// that is. Credential failures never reach binding parse or T0 compare.
//
// Boundary: `receive` may not import `reporting` (boundaries.test.ts). The verified-request
// shape below is a structural subset of reporting's VerifiedReportRequest so composition roots
// can pass the real type without this module depending on the reporting package graph.

import { parseStrictJson, type StrictJsonRejectionCode } from "../api/strict-json.js";
import type { T0MismatchField } from "../api/routes/action-routes.js";
import {
  parseArmRequestBinding,
  prepareArmT0Comparison,
  type ArmBindingParseResult,
  type ArmRequestBinding,
  type ArmT0ComparisonShape,
  type NodeDurableT0,
} from "./arm-binding.js";

/** Frozen reporting route id for POST .../armed (reporting/route-table.ts operationArmed). */
export const ARM_ROUTE_ID = "operation_armed" as const;

/**
 * Structural subset of `VerifiedReportRequest` required by arm pre-open.
 * Deliberately local so receive stays free of a reporting module edge.
 */
export interface ArmVerifiedReportingRequest {
  readonly ok: true;
  readonly binding: {
    readonly nodeId: string;
    readonly implementerId: string;
    readonly reportingKeyId: string;
  };
  readonly route: {
    readonly routeId: string;
    readonly requestClass: "READ" | "MUTATION" | string;
  };
  readonly nonceEvidence: {
    readonly nonce: string;
    readonly requestPreimageText: string;
    readonly requestSignature: string;
  };
  readonly idempotencyKey: string | null;
  readonly fingerprint: {
    readonly method: string;
    readonly rawTarget: string;
    readonly bodySha256: string;
  };
  readonly bodyBytes: Uint8Array;
}

const OPERATION_ARMED_PATH =
  /^\/v1\/operations\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/armed$/;

/** Extract operation_id from a verified arm target. null when the path is not the arm route. */
export function operationIdFromArmTarget(rawTarget: string): string | null {
  const path = rawTarget.includes("?") ? rawTarget.slice(0, rawTarget.indexOf("?")) : rawTarget;
  const match = OPERATION_ARMED_PATH.exec(path);
  return match?.[1] ?? null;
}

export type ArmCredentialRejectCode =
  | "missing_reporting_credential"
  | "wrong_reporting_route"
  | "arm_path_mismatch";

export type ArmPreopenRejectCode =
  | ArmCredentialRejectCode
  | StrictJsonRejectionCode
  | "invalid_arm_binding"
  | "t0_not_found";

export type ArmPreopenResult =
  | {
      readonly ok: true;
      readonly binding: ArmRequestBinding;
      readonly comparison: ArmT0ComparisonShape;
      /** null when the four T0 fields agree; maps non-null to 409 t0_mismatch. */
      readonly mismatchField: T0MismatchField | null;
      /** Reporting identity already verified by the pipeline — for evidence rows. */
      readonly reporting: {
        readonly nodeId: string;
        readonly implementerId: string;
        readonly reportingKeyId: string;
        readonly nonce: string;
        readonly rawTarget: string;
        readonly bodySha256: string;
        readonly requestPreimageText: string;
        readonly requestSignature: string;
        readonly idempotencyKey: string;
      };
    }
  | {
      readonly ok: false;
      readonly code: ArmPreopenRejectCode;
      readonly message: string;
      readonly field?: string;
      /** True when rejection happened before binding parse / T0 compare (credential gate). */
      readonly rejectedBeforeComparison: boolean;
    };

export interface ArmPreopenDurableT0Port {
  /**
   * Load the node's durable RECEIVER_T0 for this operation (identity + projection).
   * Must return null when the operation has no node-owned T0 — never a consumer observation.
   * Implementations MUST scope by the authenticated implementer (tenant).
   */
  getNodeDurableT0(input: {
    readonly operationId: string;
    readonly nodeId: string;
    readonly implementerId: string;
  }): Promise<NodeDurableT0 | null>;
}

/**
 * Fail-closed credential gate: only a verified reporting request classified as
 * operation_armed may enter arm pre-open.
 */
export function assertArmReportingCredential(
  request: ArmVerifiedReportingRequest,
):
  | { readonly ok: true; readonly operationId: string }
  | { readonly ok: false; readonly code: ArmCredentialRejectCode; readonly message: string } {
  if (request.ok !== true) {
    return {
      ok: false,
      code: "missing_reporting_credential",
      message: "arm pre-open requires a verified zp-report-request-v1 credential",
    };
  }
  if (request.route.routeId !== ARM_ROUTE_ID) {
    return {
      ok: false,
      code: "wrong_reporting_route",
      message: `arm pre-open requires route ${ARM_ROUTE_ID}, got ${request.route.routeId}`,
    };
  }
  if (request.route.requestClass !== "MUTATION") {
    return {
      ok: false,
      code: "wrong_reporting_route",
      message: "arm pre-open requires a MUTATION reporting route class",
    };
  }
  const operationId = operationIdFromArmTarget(request.fingerprint.rawTarget);
  if (operationId === null) {
    return {
      ok: false,
      code: "arm_path_mismatch",
      message: "verified request target is not POST /v1/operations/:operation_id/armed",
    };
  }
  return { ok: true, operationId };
}

/**
 * Node-side pre-open half of the arm barrier after zp-report-request-v1 verification.
 * Prepares the binding + T0 comparison; does not arm, release code, or open a DB-TX.
 */
export async function runArmPreopen(
  request: ArmVerifiedReportingRequest,
  durableT0: ArmPreopenDurableT0Port,
): Promise<ArmPreopenResult> {
  const credential = assertArmReportingCredential(request);
  if (!credential.ok) {
    return {
      ok: false,
      code: credential.code,
      message: credential.message,
      rejectedBeforeComparison: true,
    };
  }

  const json = parseStrictJson(request.bodyBytes);
  if (!json.ok) {
    return {
      ok: false,
      code: json.code,
      message: `arm body rejected: ${json.code}`,
      rejectedBeforeComparison: true,
    };
  }

  const parsed: ArmBindingParseResult = parseArmRequestBinding({
    operationId: credential.operationId,
    body: json.value,
  });
  if (!parsed.ok) {
    return {
      ok: false,
      code: "invalid_arm_binding",
      message: parsed.message,
      field: parsed.field,
      // Binding failures are post-credential but pre-T0-compare.
      rejectedBeforeComparison: true,
    };
  }

  const nodeT0 = await durableT0.getNodeDurableT0({
    operationId: parsed.binding.operationId,
    nodeId: request.binding.nodeId,
    implementerId: request.binding.implementerId,
  });

  const prep = prepareArmT0Comparison(parsed.binding, nodeT0);
  if (!prep.ok) {
    return {
      ok: false,
      code: "t0_not_found",
      message: "operation has no node-owned durable T0",
      field: "t0_observation_id",
      rejectedBeforeComparison: false,
    };
  }

  if (request.idempotencyKey === null) {
    // MUTATION routes require Idempotency-Key at verify time; defensive.
    return {
      ok: false,
      code: "invalid_arm_binding",
      message: "Idempotency-Key is required for arm",
      field: "Idempotency-Key",
      rejectedBeforeComparison: true,
    };
  }

  return {
    ok: true,
    binding: parsed.binding,
    comparison: prep.comparison,
    mismatchField: prep.mismatchField,
    reporting: {
      nodeId: request.binding.nodeId,
      implementerId: request.binding.implementerId,
      reportingKeyId: request.binding.reportingKeyId,
      nonce: request.nonceEvidence.nonce,
      rawTarget: request.fingerprint.rawTarget,
      bodySha256: request.fingerprint.bodySha256,
      requestPreimageText: request.nonceEvidence.requestPreimageText,
      requestSignature: request.nonceEvidence.requestSignature,
      idempotencyKey: request.idempotencyKey,
    },
  };
}

/** Type-level / runtime guard used by tests: pre-open never accepts a bare rejection. */
export function isVerifiedReportRequest(value: unknown): value is ArmVerifiedReportingRequest {
  if (typeof value !== "object" || value === null) return false;
  const v = value as {
    ok?: unknown;
    route?: { routeId?: unknown };
    binding?: unknown;
    fingerprint?: unknown;
    bodyBytes?: unknown;
  };
  return (
    v.ok === true &&
    typeof v.route?.routeId === "string" &&
    v.binding !== undefined &&
    v.fingerprint !== undefined &&
    v.bodyBytes instanceof Uint8Array
  );
}
