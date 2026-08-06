// generic-node composition for
// `POST /v1/operations/:operation_id/armed`.
//
// Auth is the signed reporting credential (`zp-report-request-v1`, A.5) — the
// reporting request pipeline verifies the credential (signature, nonce burn, window) before
// this handler runs. This module binds a tenant-scoped durable-T0 loader to `runArmPreopen`
// and, when `commitArm` is injected, runs the guarded mutation / code release under
// REPORTING_ROUTE_IDS.operationArmed.
//
// Without commitArm a successful pre-open with matching T0 returns 503 service_unavailable
// rather than releasing code — fail-closed, never a silent unbound arm.
//
// Boundary: apps/generic-node may import only `@zucoins/node-core` (no subpaths).

import {
  ARM_ROUTE_ID,
  REPORTING_ROUTE_IDS,
  apiErrorResponse,
  reportingErrorResponse,
  runArmPreopen,
  type ArmPreopenDurableT0Port,
  type ArmPreopenResult,
  type ReportingHandlerResult,
  type ReportingRouteHandler,
  type VerifiedReportRequest,
} from "@zucoins/node-core";

export const OPERATION_ARMED_ROUTE_ID = REPORTING_ROUTE_IDS.operationArmed;

// Re-export the frozen id so composition roots can assert ARM_ROUTE_ID === operation_armed.
export { ARM_ROUTE_ID };

export interface ArmRouteDeps {
  readonly durableT0: ArmPreopenDurableT0Port;
  readonly newRequestId: () => string;
  /**
   * Guarded mutation. When absent, a successful pre-open with matching T0 still
   * refuses code release (503). When present, it receives the prepared comparison and
   * performs the wallet-lock DB-TX / code release.
   */
  readonly commitArm?: (
    preopen: Extract<ArmPreopenResult, { ok: true }>,
  ) => Promise<ReportingHandlerResult>;
}

function mapPreopenFailure(
  result: Extract<ArmPreopenResult, { ok: false }>,
  requestId: string,
): ReportingHandlerResult {
  // Credential-class failures should be unreachable after the reporting pipeline; map them
  // to internal_error so we never invent a second auth taxonomy at this layer.
  if (
    result.code === "missing_reporting_credential" ||
    result.code === "wrong_reporting_route" ||
    result.code === "arm_path_mismatch"
  ) {
    return {
      response: reportingErrorResponse("internal_error", requestId),
      persistChild: null,
    };
  }

  if (
    result.code === "malformed_json" ||
    result.code === "invalid_utf8" ||
    result.code === "duplicate_json_key" ||
    result.code === "nesting_too_deep" ||
    result.code === "request_too_large"
  ) {
    const api = apiErrorResponse(result.code, requestId);
    return {
      response: {
        status: api.status,
        headers: api.headers,
        bodyBytes: new TextEncoder().encode(api.body),
      },
      persistChild: null,
    };
  }

  if (result.code === "invalid_arm_binding") {
    const api = apiErrorResponse("invalid_scalar", requestId);
    return {
      response: {
        status: api.status,
        headers: api.headers,
        bodyBytes: new TextEncoder().encode(api.body),
      },
      persistChild: null,
    };
  }

  if (result.code === "t0_not_found") {
    const api = apiErrorResponse("operation_not_armable", requestId);
    return {
      response: {
        status: api.status,
        headers: api.headers,
        bodyBytes: new TextEncoder().encode(api.body),
      },
      persistChild: null,
    };
  }

  return {
    response: reportingErrorResponse("internal_error", requestId),
    persistChild: null,
  };
}

export function createArmRouteHandler(deps: ArmRouteDeps): ReportingRouteHandler {
  return async (request: VerifiedReportRequest): Promise<ReportingHandlerResult> => {
    const requestId = deps.newRequestId();
    const preopen = await runArmPreopen(request, deps.durableT0);

    if (!preopen.ok) {
      return mapPreopenFailure(preopen, requestId);
    }

    // Matching T0 is required before any mutation path; mismatch never releases code.
    if (preopen.mismatchField !== null) {
      const api = apiErrorResponse("t0_mismatch", requestId);
      return {
        response: {
          status: api.status,
          headers: api.headers,
          bodyBytes: new TextEncoder().encode(api.body),
        },
        persistChild: null,
      };
    }

    if (deps.commitArm !== undefined) {
      return deps.commitArm(preopen);
    }

    // Fail-closed without a wired mutation: credential + binding prepared; no code release.
    const api = apiErrorResponse("service_unavailable", requestId);
    return {
      response: {
        status: api.status,
        headers: api.headers,
        bodyBytes: new TextEncoder().encode(api.body),
      },
      persistChild: null,
    };
  };
}

export function armHandlerEntry(
  deps: ArmRouteDeps,
): Readonly<Record<string, ReportingRouteHandler>> {
  return {
    [OPERATION_ARMED_ROUTE_ID]: createArmRouteHandler(deps),
  };
}
