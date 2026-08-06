import {
  OBSERVATION_PARSE_RESULTS,
  OBSERVATION_RELATIONSHIPS,
  WALLET_OBSERVATION_ROLES,
  isVerifiedParseResult,
  type ObservationParseResult,
  type ObservationRelationship,
  type WalletObservationRole,
} from "./enums.contract.ts";
import { type RecordInvariantId } from "./invariants.contract.ts";
import {
  isSha256Hex,
  isPaddedPubkey,
  isPaddedSignature,
  isEmptyOrPaddedSignature,
  isZkzBalanceText,
} from "./scalars.ts";

/**
 * The persisted `gateway_observations` row, typed. Cross-field presence rules the TS type
 * cannot express are enforced at runtime by verifyGatewayObservationRecord — the exact set
 * of the record CHECK constraints, so a wrong-shaped record is rejected the same way the DB rejects
 * it.
 */
export interface GatewayObservationRecord {
  readonly id: string;
  readonly observer_id: string;
  readonly endpoint_fingerprint: string;
  readonly wallet_id: string | null;
  readonly wallet_public_key: string;
  readonly wallet_seq: number;
  readonly observed_at: string;
  readonly http_status: number | null;
  readonly raw_response_bytes: Uint8Array;
  readonly raw_response_sha256: string;
  readonly parse_result: ObservationParseResult;
  readonly relationship: ObservationRelationship;
  readonly semantic_fingerprint: string | null;
  readonly state_changed: boolean | null;
  readonly wallet_role: WalletObservationRole | null;
  readonly s_signature: string | null;
  readonly p_signature: string | null;
  readonly b_amount: string | null;
  readonly inner_preimage_text: string | null;
  readonly step_1_signature: string | null;
  readonly step_2_signature: string | null;
  readonly completed_transaction_text: string | null;
  readonly completed_transaction_sha256: string | null;
  readonly previous_recorded_observation_id: string | null;
  readonly created_at: string;
}

const inClosedSet = <T extends string>(members: readonly T[], value: string): boolean =>
  (members as readonly string[]).includes(value);

const enumDomainsValid = (record: GatewayObservationRecord): boolean => {
  if (!inClosedSet(OBSERVATION_PARSE_RESULTS, record.parse_result)) return false;
  if (!inClosedSet(OBSERVATION_RELATIONSHIPS, record.relationship)) return false;
  if (record.wallet_role !== null && !inClosedSet(WALLET_OBSERVATION_ROLES, record.wallet_role)) {
    return false;
  }
  return true;
};

const genesisShapeValid = (record: GatewayObservationRecord): boolean =>
  record.wallet_role === "genesis" &&
  record.s_signature === "" &&
  record.p_signature === "" &&
  record.b_amount === "0" &&
  record.inner_preimage_text === null &&
  record.step_1_signature === null &&
  record.step_2_signature === null &&
  record.completed_transaction_text === null &&
  record.completed_transaction_sha256 === null;

const headShapeValid = (record: GatewayObservationRecord): boolean =>
  (record.wallet_role === "sender" || record.wallet_role === "receiver") &&
  record.s_signature !== null &&
  isPaddedSignature(record.s_signature) &&
  record.p_signature !== null &&
  isEmptyOrPaddedSignature(record.p_signature) &&
  record.b_amount !== null &&
  record.inner_preimage_text !== null &&
  record.inner_preimage_text.length > 0 &&
  record.step_1_signature !== null &&
  isPaddedSignature(record.step_1_signature) &&
  record.step_2_signature !== null &&
  isPaddedSignature(record.step_2_signature) &&
  record.completed_transaction_text !== null &&
  record.completed_transaction_text.length > 0;

const nonVerifiedShapeValid = (record: GatewayObservationRecord): boolean =>
  record.relationship === "NOT_APPLICABLE" &&
  record.wallet_role === null &&
  record.s_signature === null &&
  record.p_signature === null &&
  record.b_amount === null &&
  record.inner_preimage_text === null &&
  record.step_1_signature === null &&
  record.step_2_signature === null &&
  record.completed_transaction_text === null &&
  record.completed_transaction_sha256 === null;

const scalarFormatsValid = (record: GatewayObservationRecord): boolean =>
  isSha256Hex(record.endpoint_fingerprint) &&
  isSha256Hex(record.raw_response_sha256) &&
  isPaddedPubkey(record.wallet_public_key) &&
  Number.isInteger(record.wallet_seq) &&
  record.wallet_seq > 0 &&
  record.raw_response_bytes instanceof Uint8Array &&
  (record.semantic_fingerprint === null || isSha256Hex(record.semantic_fingerprint)) &&
  (record.completed_transaction_sha256 === null ||
    isSha256Hex(record.completed_transaction_sha256)) &&
  (record.b_amount === null || isZkzBalanceText(record.b_amount));

/**
 * Returns the sequence of frozen invariant ids the record VIOLATES; an empty result is a
 * valid row. Pure and total: it neither reads storage nor mutates anything.
 */
export const verifyGatewayObservationRecord = (
  record: GatewayObservationRecord,
): readonly RecordInvariantId[] => {
  const violations: RecordInvariantId[] = [];
  const verified = isVerifiedParseResult(record.parse_result);
  const isHead = record.parse_result === "VERIFIED_HEAD";
  const isGenesis = record.parse_result === "VERIFIED_GENESIS";

  if (!enumDomainsValid(record)) violations.push("ENUM_DOMAINS");

  if ((record.semantic_fingerprint !== null) !== verified) {
    violations.push("FIELD_A_FINGERPRINT_IFF_VERIFIED");
  }
  if ((record.state_changed !== null) !== verified) {
    violations.push("FIELD_B_STATE_CHANGED_IFF_VERIFIED");
  }

  const headMaterialPresent =
    record.inner_preimage_text !== null &&
    record.step_1_signature !== null &&
    record.step_2_signature !== null &&
    record.completed_transaction_text !== null &&
    record.completed_transaction_sha256 !== null;
  if (headMaterialPresent !== isHead) violations.push("FIELD_C_HEAD_MATERIAL_IFF_HEAD");

  if (isGenesis && !genesisShapeValid(record)) violations.push("FIELD_D_GENESIS_SHAPE");
  if (isHead && !headShapeValid(record)) violations.push("FIELD_E_HEAD_SHAPE");
  if (!verified && !nonVerifiedShapeValid(record)) violations.push("FIELD_F_NONVERIFIED_SHAPE");

  if (!scalarFormatsValid(record)) violations.push("SCALAR_FORMATS");

  return violations;
};

export const isValidGatewayObservationRecord = (record: GatewayObservationRecord): boolean =>
  verifyGatewayObservationRecord(record).length === 0;
