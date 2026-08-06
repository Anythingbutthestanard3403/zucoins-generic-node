/**
 * Exact SplitChain transaction material: the reference scalar checks, the sign-intent /
 * transaction / partial relations, and mandatory database tests 9, 10 and 11. Exactly one
 * persisted partial per external send.
 *
 * Frozen inventory of the structural one-sign-intent / one-partial invariants carried by
 * transaction-material.sql (residual). The census test binds every entry
 * here to the literal SQL text, which is itself byte-identical to the frozen relation
 * block and the domain statements, so inventory, schema contract, and
 * canon doc cannot drift apart silently. Execution against a live database belongs to the
 * schema-apply phase, recorded below as obligations rather than silently omitted.
 *
 * The naming conflict this note used to report is closed: the material is
 * transcribed verbatim, so its FKs target wallets(id) (04:700), and custody-eligibility.sql
 * now declares wallets(id) to match. What remains is execution sequence, not naming — the
 * FK target relations must exist before this file's tables.
 *
 * The application-layer facts this schema enforces structurally — the formation-state
 * ladder, one-per-approval cardinality, per-operation uniqueness — are already frozen in
 * the @zucoins/generic-node-contracts approval concern (sign-intent.contract.ts)
 * and are imported and cross-bound by the census test, never re-declared here.
 */

export const TRANSACTION_MATERIAL_SCHEMA_FILE = "transaction-material.sql" as const;

export interface TransactionMaterialInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const TRANSACTION_MATERIAL_INVARIANTS: readonly TransactionMaterialInvariant[] = [
  {
    id: "DOMAIN_SHA256_HEX",
    sqlAnchor: "CREATE DOMAIN sha256_hex AS text\n  CHECK (VALUE ~ '^[0-9a-f]{64}$');",
    rule: "Verbatim: a sha256_hex value is exactly 64 lowercase hex characters; the regex is a first boundary only, never proof of valid material.",
  },
  {
    id: "DOMAIN_PADDED_BASE64URL_SIGNATURE",
    sqlAnchor:
      "CREATE DOMAIN padded_base64url_signature AS text\n  CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');",
    rule: "Verbatim: a padded base64url signature is exactly 88 characters — 86 base64url characters plus the == pad.",
  },
  {
    id: "SIGN_INTENT_OPERATION_PK",
    sqlAnchor:
      "CREATE TABLE external_send_sign_intents (\n  operation_id uuid PRIMARY KEY REFERENCES operations(id),",
    rule: "one sign intent per operation, structurally: operation_id is the primary key and references operations(id) (04:698).",
  },
  {
    id: "SIGN_INTENT_APPROVAL_UNIQUE",
    sqlAnchor:
      "approval_id uuid NOT NULL UNIQUE REFERENCES operation_approvals(id),\n  source_wallet_id",
    rule: "one sign intent per approval (04:699): the consumed approval is bound, unique across the table, before the signer is ever called.",
  },
  {
    id: "SIGN_INTENT_SOURCE_WALLET_FK",
    sqlAnchor: "source_wallet_id uuid NOT NULL REFERENCES wallets(id),",
    rule: "the leased source wallet is bound at intent creation; the FK target is transcribed verbatim as wallets(id) — see the custody wallets(wallet_id) naming conflict note above.",
  },
  {
    id: "SIGN_INTENT_SOURCE_T0_OBSERVATION",
    sqlAnchor: "source_t0_observation_id uuid NOT NULL,",
    rule: "the fresh source T0 observation is bound (04:701); deliberately NO foreign key — the absence is preserved, not corrected.",
  },
  {
    id: "SIGN_INTENT_DESTINATION_T0_OBSERVATION",
    sqlAnchor: "destination_t0_observation_id uuid NOT NULL,",
    rule: "the fresh destination T0 observation is bound (04:702); deliberately NO foreign key — the absence is preserved, not corrected.",
  },
  {
    id: "SIGN_INTENT_LEASE_GROUP",
    sqlAnchor: "lease_group_id uuid NOT NULL,",
    rule: "the lease group is bound at intent creation (04:703); the signer must present the same lease group and epoch (04:762).",
  },
  {
    id: "SIGN_INTENT_LEASE_EPOCH_POSITIVE",
    sqlAnchor: "lease_epoch bigint NOT NULL CHECK (lease_epoch > 0)",
    rule: "lease epochs are positive (04:704); zero or negative epochs are constraint violations, and uniqueness is NOT declared per epoch — a re-acquired lease at a new epoch never authorizes a second intent.",
  },
  {
    id: "SIGN_INTENT_MATERIAL_COLUMNS",
    sqlAnchor:
      "inner_preimage_text text NOT NULL,\n  inner_sha256 sha256_hex NOT NULL,\n  redemption_expiry_at timestamptz NOT NULL,\n  prepared_at timestamptz NOT NULL,",
    rule: "the exact preimage bytes, their digest, the derived non-authoritative redemption-expiry projection (whole-second timestamptz, NOT NULL, no DEFAULT, insert-only — a projection of the signed inner expiry__unix_time_secs, never itself a signed byte), and the preparation timestamp are persisted before the signer runs; nothing rebuilds the preimage later.",
  },
  {
    id: "SIGN_INTENT_PREIMAGE_NONEMPTY",
    sqlAnchor: "CHECK (octet_length(inner_preimage_text) > 0)",
    rule: "the persisted preimage is never the empty byte string (04:708).",
  },
  {
    id: "ATTEMPT_OPERATION_FK",
    sqlAnchor: "operation_id uuid NOT NULL REFERENCES operations(id),",
    rule: "every transaction-attempt row belongs to exactly one operation (04:712).",
  },
  {
    id: "ATTEMPT_NO_SINGLE",
    sqlAnchor: "attempt_no integer NOT NULL CHECK (attempt_no = 1)",
    rule: "structurally one attempt, ever: a second transaction attempt for one operation fails both ways — a constraint violation, not an application-level rejection — the never-blind-retry rule (never blind-retry) made structural; mandatory database test 10.",
  },
  {
    id: "ATTEMPT_PHASE_FIVE_LADDER",
    sqlAnchor:
      "attempt_phase text NOT NULL CHECK (attempt_phase IN\n    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED',\n     'STEP2_PREIMAGE_PERSISTED','STEP2_SIGNATURE_PERSISTED',\n     'SETTLED_BODY_PERSISTED'))",
    rule: "exactly five internal persistence phases (04:714-717); a sixth phase literal is a constraint violation.",
  },
  {
    id: "ATTEMPT_MATERIAL_COLUMNS",
    sqlAnchor:
      "inner_preimage_text text NOT NULL,\n  inner_sha256 sha256_hex NOT NULL,\n  step_1_signature padded_base64url_signature,",
    rule: "the exact inner preimage and digest are always present on an attempt row; the step-1 signature is added later by one-way completion (04:718-720).",
  },
  {
    id: "STEP2_PREIMAGE_COLUMNS",
    sqlAnchor: "step_2_preimage_text text,\n  step_2_preimage_sha256 sha256_hex,",
    rule: "the exact step-2 preimage and its digest are nullable one-way additions (04:721-722).",
  },
  {
    id: "STEP2_AND_COMPLETED_COLUMNS",
    sqlAnchor:
      "step_2_signature padded_base64url_signature,\n  completed_transaction_text text,\n  completed_transaction_sha256 sha256_hex,",
    rule: "the step-2 signature and the completed fully signed transaction (text plus digest) are nullable one-way additions (04:723-725); the completed transaction is durable before submission (04:765).",
  },
  {
    id: "ATTEMPT_TIMESTAMPS",
    sqlAnchor: "formed_at timestamptz NOT NULL,\n  settled_at timestamptz,",
    rule: "formed_at is always present; settled_at waits for independently verified landing (04:726-727, 04:765).",
  },
  {
    id: "ATTEMPT_COMPOSITE_PK",
    sqlAnchor: "PRIMARY KEY (operation_id, attempt_no)",
    rule: "the composite primary key with ATTEMPT_NO_SINGLE makes a second transaction attempt for one operation fails both ways — a primary-key violation — mandatory database test 10.",
  },
  {
    id: "PHASE_CHECK_STEP1_SIGNATURE_IFF",
    sqlAnchor: "CHECK ((attempt_phase = 'INNER_PREIMAGE_PERSISTED') = (step_1_signature IS NULL))",
    rule: "biconditional (04:729): step_1_signature is NULL exactly at INNER_PREIMAGE_PERSISTED and present at every later phase.",
  },
  {
    id: "PHASE_CHECK_STEP2_PREIMAGE_TEXT_IFF",
    sqlAnchor:
      "CHECK ((attempt_phase IN ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED')) =\n    (step_2_preimage_text IS NULL))",
    rule: "biconditional (04:730-731): step_2_preimage_text is NULL exactly in the first two phases and present from STEP2_PREIMAGE_PERSISTED on.",
  },
  {
    id: "PHASE_CHECK_STEP2_PREIMAGE_SHA256_IFF",
    sqlAnchor:
      "CHECK ((attempt_phase IN ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED')) =\n    (step_2_preimage_sha256 IS NULL))",
    rule: "biconditional (04:732-733): step_2_preimage_sha256 tracks step_2_preimage_text exactly.",
  },
  {
    id: "PHASE_CHECK_STEP2_SIGNATURE_IFF",
    sqlAnchor:
      "CHECK ((attempt_phase IN\n    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED','STEP2_PREIMAGE_PERSISTED')) =\n    (step_2_signature IS NULL))",
    rule: "biconditional (04:734-736): step_2_signature is NULL exactly in the first three phases and present from STEP2_SIGNATURE_PERSISTED on.",
  },
  {
    id: "PHASE_CHECK_COMPLETED_TEXT_IFF",
    sqlAnchor:
      "CHECK ((attempt_phase IN\n    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED','STEP2_PREIMAGE_PERSISTED')) =\n    (completed_transaction_text IS NULL))",
    rule: "biconditional (04:737-739): the completed transaction text populates atomically with the step-2 signature, already at STEP2_SIGNATURE_PERSISTED — not at settlement.",
  },
  {
    id: "PHASE_CHECK_COMPLETED_SHA256_IFF",
    sqlAnchor:
      "CHECK ((attempt_phase IN\n    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED','STEP2_PREIMAGE_PERSISTED')) =\n    (completed_transaction_sha256 IS NULL))",
    rule: "biconditional (04:740-742): the completed transaction digest tracks its text exactly.",
  },
  {
    id: "PHASE_CHECK_SETTLED_AT_IFF",
    sqlAnchor: "CHECK ((attempt_phase <> 'SETTLED_BODY_PERSISTED') = (settled_at IS NULL))",
    rule: "biconditional in negated form (04:743): settled_at is NULL in every phase except SETTLED_BODY_PERSISTED, where it must be present — settlement adds only settled_at beyond the step-2-signature phase.",
  },
  {
    id: "PARTIAL_OPERATION_PK",
    sqlAnchor:
      "CREATE TABLE external_send_partials (\n  operation_id uuid PRIMARY KEY REFERENCES operations(id),",
    rule: "one persisted partial per external send, structurally: a persisted partial cannot be replaced — a replacement insert for the same operation violates the primary key even under a fresh approval, so a retry is a NEW operation; mandatory database test 9.",
  },
  {
    id: "PARTIAL_APPROVAL_UNIQUE",
    sqlAnchor:
      "approval_id uuid NOT NULL UNIQUE REFERENCES operation_approvals(id),\n  inner_sha256",
    rule: "one partial per approval (04:748): the same approval can never back two partials, even under two operations.",
  },
  {
    id: "PARTIAL_MATERIAL_COLUMNS",
    sqlAnchor:
      "inner_sha256 sha256_hex NOT NULL,\n  step_1_signature padded_base64url_signature NOT NULL,\n  transfer_code_text text NOT NULL,\n  transfer_code_sha256 sha256_hex NOT NULL,\n  persisted_at timestamptz NOT NULL,",
    rule: "the partial's signed material — inner digest, step-1 signature, exact transfer code text and digest — is always present and byte-immutable after insertion (04:749-753, 04:766-767).",
  },
  {
    id: "PARTIAL_DELIVERY_COUNTERS",
    sqlAnchor:
      "first_delivered_at timestamptz,\n  last_redelivered_at timestamptz,\n  redelivery_count integer NOT NULL DEFAULT 0 CHECK (redelivery_count >= 0)",
    rule: "the only post-insert mutable columns (04:754-756): redelivery touches only delivery timestamps/count, never a signed byte; the count starts at 0 and never goes negative.",
  },
] as const;

/**
 * The three mutability regimes. No trigger DDL is frozen for them, so the
 * regimes live here as inventory plus schema-apply execution obligations — the guard design belongs
 * to the schema-apply phase (exact-content tables are append-only or carry
 * byte-immutability triggers). `updatableColumns` names every column a legal UPDATE may
 * touch; for operation_transactions each addition is one-way — an existing value can never
 * be overwritten (04:766).
 */
export const TRANSACTION_MATERIAL_MUTABILITY_REGIMES = [
  {
    table: "external_send_sign_intents",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "insert-only (04:760), created only after approval and lease acquisition; no column is updatable or deletable.",
  },
  {
    table: "operation_transactions",
    regime: "insert_then_one_way_completion",
    updatableColumns: [
      "step_1_signature",
      "step_2_preimage_text",
      "step_2_preimage_sha256",
      "step_2_signature",
      "completed_transaction_text",
      "completed_transaction_sha256",
      "settled_at",
    ] as readonly string[],
    rule: "insert, then one-way completion only (04:763-766): the listed columns may be filled exactly in phase sequence, atomically with the phase advance; existing values can never be overwritten.",
  },
  {
    table: "external_send_partials",
    regime: "byte_immutable_except_delivery_counters",
    updatableColumns: [
      "first_delivered_at",
      "last_redelivered_at",
      "redelivery_count",
    ] as readonly string[],
    rule: "byte-immutable (04:766-767): recovery may update only the delivery timestamps and count; every signed byte is frozen at insert. Delivery is forbidden until the partial row commits (04:767).",
  },
] as const;

/**
 * Three phase vocabularies exist and are DISTINCT; none equates to or derives from another
 * attempt_phase is internal persistence state; the formation-state
 * ladder is frozen separately in @zucoins/generic-node-contracts
 * (FORMATION_STATES); the public execution_phase is derived at read time
 * from durable facts and is never an independently mutable column. The census asserts the
 * attempt_phase literals share no member with the frozen formation states.
 */
export const TRANSACTION_MATERIAL_PHASE_VOCABULARY = {
  attemptPhaseSource: "data-model: exact transaction material (internal persistence state)",
  attemptPhaseLiterals: [
    "INNER_PREIMAGE_PERSISTED",
    "STEP1_SIGNATURE_PERSISTED",
    "STEP2_PREIMAGE_PERSISTED",
    "STEP2_SIGNATURE_PERSISTED",
    "SETTLED_BODY_PERSISTED",
  ],
  distinctFromFormationStates: true,
  distinctFromPublicExecutionPhase: true,
  derivableFromEither: false,
} as const;

/**
 * Live-database proofs this package cannot run (no database harness lands in this package). The schema-apply phase MUST discharge each of these against a real
 * Postgres before the schema contract is considered enforced.
 */
export const SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS = [
  "execution sequence: create the FK target relations (operations, operation_approvals, wallets) before this file's tables; the wallets(id) referenced here matches custody-eligibility.sql, so only the execution sequence below remains to be honoured.",
  "guards: install BEFORE UPDATE/DELETE enforcement for the three mutability regimes (insert-only sign intents; one-way completion on operation_transactions; partials byte-immutable except delivery counters) — the conventions sanction byte-immutability triggers; no trigger DDL is frozen in this file.",
  "negative: a second external_send_partials insert for the same operation_id violates the primary key — a persisted partial cannot be replaced, even after expiry or crash.",
  "negative: a second operation_transactions row for the same (operation_id, attempt_no) violates the composite primary key, and attempt_no = 2 violates the column CHECK — a second transaction attempt for one operation fails both ways.",
  "negative: no node code path creates a submit attempt for SEND_EXTERNAL; the completed transaction persisted through operation_transactions is durable, and only delivery of the persisted partial ever occurs.",
  "negative: a duplicate approval_id under two different operation_ids violates UNIQUE on external_send_sign_intents and on external_send_partials — one sign intent and one partial per approval.",
  "negative: each of the seven paired attempt_phase CHECKs rejects both polarities — a byte column present before its phase, or absent at or after its phase — across the full five-phase by seven-column matrix.",
  "negative: lease_epoch 0 or negative, an empty inner_preimage_text, a redelivery_count below zero, and malformed sha256_hex or padded_base64url_signature values are rejected by their CHECKs and domains.",
] as const;

export const TRANSACTION_MATERIAL_SOURCE =
  "data-model: exact SplitChain transaction material" as const;
