/**
 * Public subpath `@zucoins/generic-node-contracts/operations`.
 *
 * Exposes the frozen operation-kind enum set and per-kind state machines so that
 * downstream packages (e.g. the node-core schema migration) can import canonical
 * operation vocabulary without reaching into internal source paths.
 */

export { OPERATION_KINDS, CHILD_LINK, WORKFLOW_GRAPH_SUPPORTED } from "./operations.contract.ts";
export type { OperationKind } from "./operations.contract.ts";

export {
  OPERATION_STATES,
  RECEIVE_EXTERNAL_STATES,
  MOVE_INTERNAL_STATES,
  SEND_EXTERNAL_STATES,
  RECEIVE_EXTERNAL_TRANSITIONS,
  MOVE_INTERNAL_TRANSITIONS,
  SEND_EXTERNAL_TRANSITIONS,
  FORBIDDEN_STATE_ALIASES,
} from "./states.contract.ts";
export type {
  ReceiveExternalState,
  MoveInternalState,
  SendExternalState,
  StateTransition,
} from "./states.contract.ts";

export { OPERATION_STATUS } from "../api-schema/pg-enums.ts";

// Route inventory — consumed by the OpenAPI freeze so the generated document diffs
// against the same PUBLIC_ROUTES / ADMIN_ROUTES / RETIRED_ROUTES the census already pins.
export {
  AUTH_MODES,
  PUBLIC_ROUTES,
  ADMIN_ROUTES,
  RETIRED_ROUTES,
  RETIRED_ROUTES_NON_PATH_CATEGORY,
  isRetiredImportEndpoint,
  SOURCE as ROUTES_SOURCE,
} from "./routes.contract.ts";
export type { RouteEntry, AuthMode } from "./routes.contract.ts";

export {
  ATTENTION_REASON_PRODUCTION_SETTERS,
  ATTENTION_REASON_DISPOSITIONS,
  attentionReasonCoverage,
  assertAttentionReasonCensusComplete,
} from "./attention-reason-setters.ts";

export {
  VERIFICATION_MODES,
  DEFAULT_VERIFICATION_MODE,
  RELEASED_NODE_VERIFIED,
  ALLOW_NODE_VERIFIED_SETTING_KEY,
  ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION,
  VERIFICATION_MODE_ERROR_CODES,
  SOURCE as VERIFICATION_MODE_SOURCE,
} from "./verification-mode.contract.ts";
export type {
  VerificationMode,
  VerificationModeErrorCode,
} from "./verification-mode.contract.ts";

