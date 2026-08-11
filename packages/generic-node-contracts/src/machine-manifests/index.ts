/**
 * the fixture-provenance purposes census — machine-manifests concern public entry.
 *
 * The concern froze the suite-tuple field sequences (`suite-tuples.contract.ts`) and the
 * genesis fingerprint vocabulary (`genesis.contract.ts`) but shipped no subpath export, so a
 * downstream lane could not bind against `WALLET_HEAD_FINGERPRINT_TUPLE` without re-declaring
 * it locally — forbidden by the frozen scan-scope rule. This index plus the `./machine-manifests`
 * exports-map entry close that gap (class, row 6) for 's fingerprint
 * builder. Named re-exports only: both source modules export a `SOURCE` constant, so a wildcard
 * `export *` would collide.
 */
export {
  SUITE_TUPLES_CONTRACT_VERSION,
  SUITE_TUPLE_FIELD_TYPES,
  DESTINATION_BLESS_TUPLE,
  DEVICE_ENROL_TUPLE,
  DEVICE_ENROL_LABEL_RULES,
  WALLET_HEAD_FINGERPRINT_TUPLE,
  WALLET_HEAD_FINGERPRINT_EXCLUSIONS,
  ARTIFACT_ENVELOPE_FIELD_SEQUENCE,
  CEREMONY_WINDOW_RULE,
  REPORT_REQUEST_WINDOW_MAX_SECONDS,
  DEFERRED_IMPLEMENTER_TUPLES,
  FROZEN_IMPLEMENTER_TUPLES,
} from "./suite-tuples.contract.ts";
export type { SuiteTupleFieldType, SuiteTupleFieldDescriptor } from "./suite-tuples.contract.ts";
export {
  GENESIS_CONTRACT_VERSION,
  GENESIS_STATE_SIGNATURE,
  GENESIS_BALANCE,
  WALLET_CHAIN_LINK_RULE,
  WALLET_HEAD_STATE_KINDS,
  GENESIS_FINGERPRINT_VALUES,
  FUNDED_SENDER_GENESIS_PREDECESSOR_REJECTION,
} from "./genesis.contract.ts";
