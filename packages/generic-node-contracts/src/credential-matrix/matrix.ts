// The credential/error response matrix, derived purely from the auth-errors freeze and the
// route-policy freeze. Each cell is (auth class × failure state × representative route) → the
// synthesized response the centralized pipeline must return, plus the pipeline stage at which
// the request short-circuits (its "timing class").
//
// CONTRACT_FREEZE note: there is no runtime server in this slice, so the matrix is contract-level
// — every cell's response is reconstructed from the frozen contracts, not observed on the wire.
// The stage index is a structural stand-in for a timing class: a state that resolves before
// object resolution cannot leak object existence through timing, without any flaky wall-clock.
//
// Governed by the API contract's wire conventions and authentication classes, under the frozen
// non-oracular error vocabulary. Depends on the auth-errors and route-policy freezes.

import {
  type AuthFailureState,
  type WireResponse,
  AUTH_FAILURE_STATE_TO_CODE,
  CANONICAL_AUTH_ERROR_HEADERS,
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_AUTH_FAILURE_MESSAGE,
  CANONICAL_NOT_FOUND_MESSAGE,
  HTTP_STATUS_BY_AUTH_ERROR_CODE,
  buildAuthErrorBody,
} from "../auth-errors/index.js";
import {
  type AuthClass,
  type PipelineStageName,
  REQUEST_PIPELINE,
} from "../route-policy/index.js";

// The failure states exercised, in a stable sequence. Covers the five required credential states
// (unknown/expired/revoked/wrong-tenant/wrong-scope) plus missing/malformed presentation, split
// across the credential, scope, and tenant dimensions.
export const MATRIX_STATES = [
  "MISSING_CREDENTIAL",
  "MALFORMED_CREDENTIAL",
  "UNKNOWN_KEY",
  "EXPIRED_KEY",
  "REVOKED_KEY",
  "OUT_OF_SCOPE",
  "ABSENT_OBJECT",
  "CROSS_TENANT_OBJECT",
] as const satisfies readonly AuthFailureState[];

// The matrix dimension each state probes. The non-oracular property is asserted per dimension.
export const STATE_DIMENSION = {
  MISSING_CREDENTIAL: "credential",
  MALFORMED_CREDENTIAL: "credential",
  UNKNOWN_KEY: "credential",
  EXPIRED_KEY: "credential",
  REVOKED_KEY: "credential",
  OUT_OF_SCOPE: "scope",
  ABSENT_OBJECT: "tenant",
  CROSS_TENANT_OBJECT: "tenant",
} as const satisfies Record<AuthFailureState, "credential" | "scope" | "tenant">;

// Pipeline stage at which each state short-circuits. Credential states resolve at authentication,
// scope at authorization — both BEFORE object resolution — so their timing cannot depend on
// object existence. Object/tenant states resolve at object resolution.
export const STATE_RESOLVING_STAGE = {
  MISSING_CREDENTIAL: "authenticate_credential",
  MALFORMED_CREDENTIAL: "authenticate_credential",
  UNKNOWN_KEY: "authenticate_credential",
  EXPIRED_KEY: "authenticate_credential",
  REVOKED_KEY: "authenticate_credential",
  OUT_OF_SCOPE: "authorize_scope",
  ABSENT_OBJECT: "resolve_object_with_tenant_predicate",
  CROSS_TENANT_OBJECT: "resolve_object_with_tenant_predicate",
} as const satisfies Record<AuthFailureState, PipelineStageName>;

// The frozen auth classes whose full collapse the matrix exercises (the multi-tenant surface).
export const MATRIX_AUTH_CLASSES = [
  "IMPLEMENTER_BEARER",
  "REPORTING_CREDENTIAL",
  "SUBSCRIPTION_HANDLE",
] as const satisfies readonly AuthClass[];

// Representative routes per frozen class, referenced by method+path so the matrix stays derived
// from the route-policy catalog (the freeze test asserts each exists there). A mutation and a read
// where both exist, so "no protected mutation" is exercised on a real mutation route.
export const REPRESENTATIVE_ROUTES = {
  IMPLEMENTER_BEARER: [
    { method: "POST", path: "/v1/receives" },
    { method: "GET", path: "/v1/receives/:operation_id" },
  ],
  REPORTING_CREDENTIAL: [
    { method: "GET", path: "/v1/events" },
    { method: "POST", path: "/v1/operations/:operation_id/armed" },
  ],
  SUBSCRIPTION_HANDLE: [{ method: "GET", path: "/v1/operations/:operation_id/subscribe" }],
} as const;

function stageOrder(name: PipelineStageName): number {
  const stage = REQUEST_PIPELINE.find((s) => s.name === name);
  if (!stage) throw new Error(`unknown pipeline stage: ${name}`);
  return stage.order; // contract-allow:frozen-manifest-field-name (reads pipeline.ts's frozen PipelineStage.order)
}

const HANDLER_ORDER = stageOrder("handler");

export interface MatrixCell {
  readonly authClass: AuthClass;
  readonly method: string;
  readonly path: string;
  readonly state: AuthFailureState;
  readonly dimension: "credential" | "scope" | "tenant";
  readonly status: number;
  readonly code: string;
  readonly message: string;
  readonly resolvingStage: PipelineStageName;
  readonly resolvingStageOrder: number;
  readonly reachesHandler: boolean;
}

function buildCell(
  authClass: AuthClass,
  method: string,
  path: string,
  state: AuthFailureState,
): MatrixCell {
  const code = AUTH_FAILURE_STATE_TO_CODE[state];
  const message =
    code === CANONICAL_AUTH_FAILURE_CODE ? CANONICAL_AUTH_FAILURE_MESSAGE : CANONICAL_NOT_FOUND_MESSAGE;
  const resolvingStage = STATE_RESOLVING_STAGE[state];
  const resolvingStageOrder = stageOrder(resolvingStage);
  return {
    authClass,
    method,
    path,
    state,
    dimension: STATE_DIMENSION[state],
    status: HTTP_STATUS_BY_AUTH_ERROR_CODE[code],
    code,
    message,
    resolvingStage,
    resolvingStageOrder,
    reachesHandler: resolvingStageOrder >= HANDLER_ORDER,
  };
}

// The full credential/error response matrix: every frozen class × representative route × state.
export function buildCredentialMatrix(): MatrixCell[] {
  const cells: MatrixCell[] = [];
  for (const authClass of MATRIX_AUTH_CLASSES) {
    for (const route of REPRESENTATIVE_ROUTES[authClass]) {
      for (const state of MATRIX_STATES) {
        cells.push(buildCell(authClass, route.method, route.path, state));
      }
    }
  }
  return cells;
}

// Reconstruct a cell's exact wire response with a specific per-request request_id, so the
// non-oracularity verifier sees responses that differ only where a real response would. Every
// cell carries the frozen constant CANONICAL_AUTH_ERROR_HEADERS, so the matrix proves the header
// channel is non-oracular too (no `WWW-Authenticate` scope oracle), not just status + body.
export function renderCellResponse(cell: MatrixCell, requestId: string): WireResponse {
  return {
    status: cell.status,
    body: buildAuthErrorBody(cell.code, cell.message, requestId),
    headers: CANONICAL_AUTH_ERROR_HEADERS,
  };
}
