/**
 * SOURCE: the data model, enum vocabulary.
 *
 * All 17 Postgres ENUM types transcribed verbatim. Adding an enum value is a
 * contract-version change, not an application-local migration.
 *
 * Completeness is not a hand-count: `api-schema.census.test.ts` carries the full
 * `CREATE TYPE … AS ENUM` universe as an independently-transcribed fixture and asserts
 * set-equality plus per-enum value sequence against `PG_ENUMS`, so a new or edited enum
 * fails there until it is frozen here.
 */

import { OPERATION_KINDS } from "../operations/operations.contract.ts";
import {
  WALLET_KEY_ORIGINS,
  WALLET_STATES,
  DESTINATION_STATES,
} from "../custody/predicates.contract.ts";
import {
  REPORTING_KEY_STATES,
  REPORTING_LIFECYCLE_EVENT_TYPES,
  REPORTING_REQUEST_CLASSES,
} from "../reporting-persistence/decisions.ts";

/** Re-use the canonical frozen operation kinds (avoids redeclaration per the scan/dependency-boundary gate).*/
export const OPERATION_KIND = OPERATION_KINDS;

export const OPERATION_STATUS = [
  "CREATED",
  "READY",
  "RECEIVE_LANDED",
  "INTERNAL_MOVE_LANDED",
  "APPROVED",
  "AWAITING_REDEMPTION",
  "EXTERNAL_SEND_LANDED",
  "EXPIRED",
  "REJECTED",
  "NEEDS_ATTENTION",
] as const;

/** Re-use the canonical frozen wallet key origins (avoids redeclaration per the scan/dependency-boundary gate).*/
export const WALLET_KEY_ORIGIN = WALLET_KEY_ORIGINS;

/** Re-use the canonical frozen wallet states (avoids redeclaration per the scan/dependency-boundary gate).*/
export const WALLET_STATE = WALLET_STATES;

/** Re-use the canonical frozen destination states (avoids redeclaration per the scan/dependency-boundary gate).*/
export const DESTINATION_STATE = DESTINATION_STATES;

export const WALLET_LEASE_ROLE = [
  "RECEIVE_WINDOW",
  "MOVE_SOURCE",
  "MOVE_DESTINATION",
  "SEND_SOURCE",
  "RECONCILIATION",
] as const;

export const APPROVAL_METHOD = ["TOTP_ONLY", "TOTP_AND_DEVICE"] as const;

export const APPROVAL_CHALLENGE_STATUS = ["ISSUED", "CONSUMED", "SUPERSEDED", "EXPIRED"] as const;

export const EXTERNAL_FORMATION_STATE = [
  "NOT_REQUIRED",
  "APPROVAL_PENDING",
  "APPROVED_UNSIGNED",
  "SIGNING_CLAIMED",
  "PARTIAL_PERSISTED",
  "PARTIAL_DELIVERED",
] as const;

export const OBSERVER_DOMAIN = ["NODE", "PLATFORM"] as const;

export const OBSERVATION_PARSE_RESULT = [
  "VERIFIED_GENESIS",
  "VERIFIED_HEAD",
  "TRANSPORT_ERROR",
  "MALFORMED_ENVELOPE",
  "MALFORMED_TRANSACTION",
  "UNVERIFIED_SIGNATURE",
  "WALLET_ROLE_INVALID",
] as const;

export const OBSERVATION_RELATIONSHIP = [
  "FIRST",
  "SUCCESSOR",
  "COMPLETE_PATH_SUCCESSOR",
  "DUPLICATE",
  "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
  "REGRESSION",
  "UNEXPLAINED_JUMP",
  "GENESIS_AFTER_HISTORY",
  "SIGNATURE_COLLISION",
  "NOT_APPLICABLE",
] as const;

export const VERIFICATION_VERDICT = ["PENDING", "VERIFIED", "REJECTED", "INDETERMINATE"] as const;

export const LINEAGE_PROOF_VERDICT = [
  "LANDED_EXACT",
  "LANDED_COMPLETE_PATH",
  "INDETERMINATE",
  "INVARIANT_BREACH",
] as const;

/** Re-use the canonical reporting lifecycle vocabularies (avoids a fourth twin declaration). */
export const REPORTING_KEY_STATE = REPORTING_KEY_STATES;

export const REPORTING_KEY_LIFECYCLE_EVENT_TYPE = REPORTING_LIFECYCLE_EVENT_TYPES;

export const REPORTING_REQUEST_CLASS = REPORTING_REQUEST_CLASSES;

/** All 17 enum names in their canonical sequence. */
export const PG_ENUM_NAMES = [
  "operation_kind",
  "operation_status",
  "wallet_key_origin",
  "wallet_state",
  "destination_state",
  "wallet_lease_role",
  "approval_method",
  "approval_challenge_status",
  "external_formation_state",
  "observer_domain",
  "observation_parse_result",
  "observation_relationship",
  "verification_verdict",
  "lineage_proof_verdict",
  "reporting_key_state",
  "reporting_key_lifecycle_event_type",
  "reporting_request_class",
] as const;

export type PgEnumName = (typeof PG_ENUM_NAMES)[number];

/** Map from enum name to its frozen value array. */
export const PG_ENUMS: Record<PgEnumName, readonly string[]> = {
  operation_kind: OPERATION_KIND,
  operation_status: OPERATION_STATUS,
  wallet_key_origin: WALLET_KEY_ORIGIN,
  wallet_state: WALLET_STATE,
  destination_state: DESTINATION_STATE,
  wallet_lease_role: WALLET_LEASE_ROLE,
  approval_method: APPROVAL_METHOD,
  approval_challenge_status: APPROVAL_CHALLENGE_STATUS,
  external_formation_state: EXTERNAL_FORMATION_STATE,
  observer_domain: OBSERVER_DOMAIN,
  observation_parse_result: OBSERVATION_PARSE_RESULT,
  observation_relationship: OBSERVATION_RELATIONSHIP,
  verification_verdict: VERIFICATION_VERDICT,
  lineage_proof_verdict: LINEAGE_PROOF_VERDICT,
  reporting_key_state: REPORTING_KEY_STATE,
  reporting_key_lifecycle_event_type: REPORTING_KEY_LIFECYCLE_EVENT_TYPE,
  reporting_request_class: REPORTING_REQUEST_CLASS,
};

export const SOURCE = "data-model: enum vocabulary" as const;
