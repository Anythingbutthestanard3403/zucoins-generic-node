/**
 * the crypto-goldens concern.2 — API schema, state, and event manifest concern.
 *
 * Freezes the complete machine-readable API/schema/event vocabulary as a single concern
 * directory. Re-exports existing frozen data from `operations/` (routes, states, events)
 * and adds the missing pieces: error vocabulary, auth scopes, Postgres ENUMs, and
 * discovery-endpoint shape.
 */

export { HTTP_ERROR_STATUSES, ERROR_ENVELOPE_FIELDS, CITED_ERROR_CODES } from "./error-vocabulary.ts";
export type { HttpStatusEntry, CitedErrorCode } from "./error-vocabulary.ts";

export { IMPLEMENTER_SCOPES, AUTH_CLASSES, REPORTING_HEADERS, BEARER_KEY_EXCLUSIONS } from "./auth-scopes.ts";
export type { ImplementerScope, AuthClass } from "./auth-scopes.ts";

export {
  PG_ENUM_NAMES,
  PG_ENUMS,
  OPERATION_KIND,
  OPERATION_STATUS,
  WALLET_KEY_ORIGIN,
  WALLET_STATE,
  DESTINATION_STATE,
  WALLET_LEASE_ROLE,
  APPROVAL_METHOD,
  APPROVAL_CHALLENGE_STATUS,
  EXTERNAL_FORMATION_STATE,
  OBSERVER_DOMAIN,
  OBSERVATION_PARSE_RESULT,
  OBSERVATION_RELATIONSHIP,
  VERIFICATION_VERDICT,
  LINEAGE_PROOF_VERDICT,
  REPORTING_KEY_STATE,
  REPORTING_KEY_LIFECYCLE_EVENT_TYPE,
  REPORTING_REQUEST_CLASS,
  ATTENTION_REASON,
} from "./pg-enums.ts";
export type { PgEnumName } from "./pg-enums.ts";

export { DISCOVERY_PATH, DISCOVERY_RESPONSE_FIELDS, DISCOVERY_EXCLUSIONS } from "./discovery.ts";

export { API_SCHEMA_VERSION } from "./version.ts";

export {
  UuidSchema,
  WalletPublicKeySchema,
  Ed25519SignatureSchema,
  Sha256HexSchema,
  PositiveZkzAmountSchema,
  ZkzBalanceSchema,
  PreviousStateSignatureSchema,
  Rfc3339MsSchema,
  AnchorSchema,
  ClientReferenceSchema,
  DescriptionSchema,
} from "./scalars.ts";

export {
  ReceiveExternalOperationSchema,
  MoveInternalOperationSchema,
  SendExternalOperationSchema,
  ExpectedArtifactSchema,
  T0EvidenceSchema,
} from "./common-operation.ts";

export {
  AfterLandingSchema,
  ReceiveExternalRequestSchema,
  ReceiveExternalReadyResponseSchema,
  ReceiveExternalQueuedResponseSchema,
  ReceiveExternalResponseSchema,
} from "./receive-external.ts";
export type {
  ReceiveExternalRequest,
  ReceiveExternalResponse,
} from "./receive-external.ts";

export {
  MoveInternalRequestSchema,
  MoveInternalResponseSchema,
} from "./move-internal.ts";
export type {
  MoveInternalRequest,
  MoveInternalResponse,
} from "./move-internal.ts";

export {
  SendExternalRequestSchema,
  SendExternalResponseSchema,
} from "./send-external.ts";
export type {
  SendExternalRequest,
  SendExternalResponse,
} from "./send-external.ts";

export {
  PUBLIC_OPERATION_SCHEMA_SURFACE,
  PUBLIC_OPERATION_SCHEMAS,
} from "./operation-schema-surface.ts";

// Re-export existing frozen data from operations/ (single source of truth)
export { PUBLIC_ROUTES, ADMIN_ROUTES, RETIRED_ROUTES, AUTH_MODES } from "../operations/routes.contract.ts";
export type { RouteEntry, AuthMode } from "../operations/routes.contract.ts";
export { OPERATION_STATES, RECEIVE_EXTERNAL_TRANSITIONS, MOVE_INTERNAL_TRANSITIONS, SEND_EXTERNAL_TRANSITIONS } from "../operations/states.contract.ts";
export { DURABLE_EVENTS, ATTENTION_REASONS } from "../operations/events.contract.ts";
export type { DurableEvent } from "../operations/events.contract.ts";
export { OPERATION_KINDS } from "../operations/operations.contract.ts";
