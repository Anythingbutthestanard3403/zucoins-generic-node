// The centralized request-pipeline stage sequence every route inherits. This is the
// "align middleware across every route" contract: authentication, authorization, error envelope,
// status, request id, audit, and idempotency behaviour are defined once here, not per route, so
// no route can re-introduce a bespoke oracle. It is a CONTRACT: the stage sequence and the failure
// code each stage may emit are frozen; the runtime middleware that implements them is not built
// in this CONTRACT_FREEZE slice.
//
// Governed by the API contract's wire/idempotency conventions and authentication classes, under
// the frozen non-oracular error vocabulary. The auth-relevant stages MUST appear in the same
// relative sequence as the auth-errors AUTH_CHECK_ORDER (authenticate_credential →
// authorize_scope → resolve_object_with_tenant_predicate); the freeze test asserts it, so the
// auth-errors freeze wins on any conflict.

import {
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_NOT_FOUND_CODE,
} from "../auth-errors/index.js";

// `failsWith` is the frozen canonical code a stage emits on failure, or null when the stage
// cannot fail the request in a caller-visible way (request-id assignment, audit append, and the
// error-envelope renderer itself never oracle). `deferredTo` names the owner of a stage whose
// specific failure code is out of the route-policy scope (e.g. idempotency conflict).
export interface PipelineStage {
  readonly order: number; // contract-allow:frozen-manifest-field-name (gen/route-policy.json pipeline[].order)
  readonly name: string;
  readonly failsWith: string | null;
  readonly deferredTo: string | null;
}

export const REQUEST_PIPELINE = [
  { order: 1, name: "assign_request_id", failsWith: null, deferredTo: null }, // contract-allow:frozen-manifest-field-name
  { order: 2, name: "authenticate_credential", failsWith: CANONICAL_AUTH_FAILURE_CODE, deferredTo: null }, // contract-allow:frozen-manifest-field-name
  { order: 3, name: "authorize_scope", failsWith: CANONICAL_AUTH_FAILURE_CODE, deferredTo: null }, // contract-allow:frozen-manifest-field-name
  { order: 4, name: "enforce_idempotency", failsWith: null, deferredTo: "idempotency-key-contract" }, // contract-allow:frozen-manifest-field-name
  { order: 5, name: "resolve_object_with_tenant_predicate", failsWith: CANONICAL_NOT_FOUND_CODE, deferredTo: "tenant-object-resolution-contract" }, // contract-allow:frozen-manifest-field-name
  { order: 6, name: "handler", failsWith: null, deferredTo: null }, // contract-allow:frozen-manifest-field-name
  { order: 7, name: "audit_record", failsWith: null, deferredTo: "audit-record-contract" }, // contract-allow:frozen-manifest-field-name
  { order: 8, name: "emit_error_envelope", failsWith: null, deferredTo: null }, // contract-allow:frozen-manifest-field-name
] as const satisfies readonly PipelineStage[];

export type PipelineStageName = (typeof REQUEST_PIPELINE)[number]["name"];

// The subsequence of pipeline stages that must match the auth-errors AUTH_CHECK_ORDER, in sequence.
export const AUTH_STAGE_SEQUENCE = [
  "authenticate_credential",
  "authorize_scope",
  "resolve_object_with_tenant_predicate",
] as const;

// Frozen cross-cutting invariants the centralized pipeline guarantees for EVERY route. Recorded
// as data so the census test and the credential-matrix can assert them structurally.
export const PIPELINE_INVARIANTS = [
  "every response — 2xx and non-2xx — carries the request_id assigned at stage 1",
  "authorization (scope) runs before any object lookup, so an unauthorized caller cannot probe object existence",
  "every non-2xx body is rendered through the canonical error envelope; no route emits a bespoke error shape",
  "no stage emits a 403 for a scope denial; scope denial is the generic 401",
  "audit records are server-side only and never appear in the response status, body, or headers",
  "idempotency replay returns the original status/body with Idempotency-Replayed: true, never a fresh oracle",
] as const;
