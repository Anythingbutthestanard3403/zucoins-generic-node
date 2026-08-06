// generic-node composition for
// `GET /v1/operations/:operation_id/verification-material`.
//
// Auth is the signed reporting credential (`zp-report-request-v1`) — the reporting
// request pipeline verifies the credential before this handler runs. Access control
// (409 not-ready / 410 expired) and response framing live in `@zucoins/node-core`
// (`handleGetVerificationMaterial` + `decideProofAccess`). This module only binds a
// tenant-scoped material loader to that handler and registers it under the frozen
// reporting route id `verification_material`.
//
// Boundary: apps/generic-node may import only `@zucoins/node-core` (no subpaths).

import {
  REPORTING_ROUTE_IDS,
  handleGetVerificationMaterial,
  reportingErrorResponse,
  type ReportingHandlerResult,
  type ReportingRouteHandler,
  type VerificationMaterialSource,
  type VerifiedReportRequest,
} from "@zucoins/node-core";

export const VERIFICATION_MATERIAL_ROUTE_ID = REPORTING_ROUTE_IDS.verificationMaterial;

export const VERIFICATION_MATERIAL_PATH =
  "/v1/operations/:operation_id/verification-material" as const;

// Extract the operation UUID from a verified request's raw target. The reporting route
// table already authenticated the path shape; this is the final segment bind.
const OPERATION_ID_FROM_TARGET =
  /^\/v1\/operations\/([^/?#]+)\/verification-material(?:\?.*)?$/;

export function operationIdFromVerificationMaterialTarget(rawTarget: string): string | null {
  const match = OPERATION_ID_FROM_TARGET.exec(rawTarget);
  return match?.[1] ?? null;
}

export interface VerificationMaterialRouteDeps {
  readonly source: VerificationMaterialSource;
  readonly nowMs: () => number;
  // Request id is generated at the reporting orchestration edge (not on VerifiedReportRequest).
  readonly newRequestId: () => string;
}

// Build the reporting-registry handler for the verification-material read route.
export function createVerificationMaterialRouteHandler(
  deps: VerificationMaterialRouteDeps,
): ReportingRouteHandler {
  return async (request: VerifiedReportRequest): Promise<ReportingHandlerResult> => {
    const operationId = operationIdFromVerificationMaterialTarget(request.fingerprint.rawTarget);
    if (operationId === null) {
      // Route table should never dispatch a non-matching target here; treat as absent.
      return {
        response: reportingErrorResponse("not_found", deps.newRequestId()),
        persistChild: null,
      };
    }

    const result = await handleGetVerificationMaterial(
      {
        requestId: deps.newRequestId(),
        operationId,
        // Authorization derives from the reporting-key → implementer binding, never
        // from a client-asserted tenant field. The material source scopes by implementer id.
        tenantId: request.binding.implementerId,
        nowMs: deps.nowMs(),
      },
      deps.source,
    );

    return {
      response: {
        status: result.status,
        headers: result.headers,
        bodyBytes: new TextEncoder().encode(result.body),
      },
      // GET — no mutation, no completed-idempotency child.
      persistChild: null,
    };
  };
}

// Convenience: the single registry entry to merge into a ReportingHandlerRegistry.
export function verificationMaterialHandlerEntry(
  deps: VerificationMaterialRouteDeps,
): Readonly<Record<string, ReportingRouteHandler>> {
  return {
    [VERIFICATION_MATERIAL_ROUTE_ID]: createVerificationMaterialRouteHandler(deps),
  };
}
