/**
 * Public subpath `@zucoins/generic-node-contracts/enums`.
 *
 * Exposes the complete frozen Postgres ENUM surface (all 18 enum types) as a single
 * import point. Downstream packages (e.g. the node-core schema migration) can import
 * canonical enum vocabulary without reaching into internal source paths.
 */

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
} from "../api-schema/pg-enums.ts";
export type { PgEnumName } from "../api-schema/pg-enums.ts";
