/**
 * Contract for transaction-material-byte-immutability.sql — BEFORE UPDATE/DELETE/
 * TRUNCATE guards on the three exact SplitChain transaction-material tables
 * (doc 04 §9 / 04:760-767). Tables themselves are created by transaction-material.sql;
 * this append-only pack slice discharges the mutability-regime obligations inventoried
 * there (TRANSACTION_MATERIAL_MUTABILITY_REGIMES / SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS).
 */

export const TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_SCHEMA_FILE =
  "transaction-material-byte-immutability.sql" as const;

export interface TransactionMaterialByteImmutabilityInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_INVARIANTS: readonly TransactionMaterialByteImmutabilityInvariant[] =
  [
    {
      id: "SIGN_INTENT_INSERT_ONLY",
      sqlAnchor: "EXTERNAL_SEND_SIGN_INTENTS_INSERT_ONLY",
      rule: "external_send_sign_intents is insert-only (04:760): UPDATE/DELETE/TRUNCATE raise.",
    },
    {
      id: "ATTEMPT_BYTE_IMMUTABLE",
      sqlAnchor: "OPERATION_TRANSACTIONS_BYTE_IMMUTABLE",
      rule: "operation_transactions rejects overwrite of insert-time bytes and of already-filled one-way completion columns; DELETE/TRUNCATE raise (04:763-766).",
    },
    {
      id: "PARTIAL_BYTE_IMMUTABLE",
      sqlAnchor: "EXTERNAL_SEND_PARTIALS_BYTE_IMMUTABLE",
      rule: "external_send_partials rejects mutation of signed bytes; only delivery counters may UPDATE; DELETE/TRUNCATE raise (04:766-767).",
    },
    {
      id: "SIGN_INTENT_TRIGGER",
      sqlAnchor: "external_send_sign_intents_insert_only",
      rule: "BEFORE UPDATE OR DELETE trigger name on external_send_sign_intents.",
    },
    {
      id: "ATTEMPT_TRIGGER",
      sqlAnchor: "operation_transactions_byte_immutability",
      rule: "BEFORE UPDATE OR DELETE trigger name on operation_transactions.",
    },
    {
      id: "PARTIAL_TRIGGER",
      sqlAnchor: "external_send_partials_byte_immutability",
      rule: "BEFORE UPDATE OR DELETE trigger name on external_send_partials.",
    },
  ] as const;

export const SCHEMA_TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_OBLIGATIONS = [
  "execution sequence: apply after transaction-material.sql so the three tables exist before these triggers attach.",
  "negative: UPDATE or DELETE on external_send_sign_intents raises EXTERNAL_SEND_SIGN_INTENTS_INSERT_ONLY.",
  "negative: overwriting operation_transactions.inner_preimage_text / inner_sha256 / a filled step_* or completed_* column, or DELETE, raises OPERATION_TRANSACTIONS_BYTE_IMMUTABLE; NULL→value one-way fills still succeed.",
  "negative: UPDATE of external_send_partials.inner_sha256 / step_1_signature / transfer_code_* / persisted_at raises EXTERNAL_SEND_PARTIALS_BYTE_IMMUTABLE; delivery-counter UPDATEs still succeed.",
] as const;

export const TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_SOURCE =
  "data-model: exact SplitChain transaction material mutability; ZTR-1138" as const;
