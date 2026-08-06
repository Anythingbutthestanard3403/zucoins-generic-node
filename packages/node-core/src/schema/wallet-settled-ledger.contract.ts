// The canonical wallet ledger: verbatim and permanent, one immutable row per
// (wallet, landed operation). Bound to operations / operation_wallets,
// operation_transactions and operation_verifications, and covered by mandatory database
// tests 7 (byte round-trip), 8 (no JSONB on authoritative-byte columns) and 15
// (append-only triggers).
// canonical ZKZ amount contract (ZKZ amount CHECK domains), landing-path oracle (LANDED_EXACT / LANDED_COMPLETE_PATH).
//
// PROVISIONAL contract for wallet-settled-ledger.sql — deliberately not
// declared frozen. The retention matrix names this table only as a row and freezes no
// CREATE TABLE for it, so there is no frozen DDL to transcribe and no drift gate
// can pin the SQL to the spec (contrast operations.sql / transaction-material.sql, which have
// one). The shape is implementer-designed from the canonical-container retention rule and
// the transaction relations, and yields to the retention matrix if a shape is later frozen
// there. Freezing it is an open spec defect, recorded in SPEC_RESIDUE below.
//
// reconciliation note: the slice references wallets, operations, operation_wallets and
// operation_transactions and creates none of them, so it is prerequisite-bound greenfield —
// applied alone it fails on wallets. Characterized in migration-integrity.test.ts; the
// real-PostgreSQL behavioral proof is wallet-settled-ledger.pg.test.ts.

export const WALLET_SETTLED_LEDGER_SCHEMA_FILE = "wallet-settled-ledger.sql" as const;

export interface WalletSettledLedgerInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const WALLET_SETTLED_LEDGER_INVARIANTS: readonly WalletSettledLedgerInvariant[] = [
  {
    id: "APPEND_ONLY_SURROGATE_KEY",
    sqlAnchor: "id uuid PRIMARY KEY,",
    rule: "a surrogate primary key with wallet_id a non-unique FK: a wallet accrues one new immutable row per landed operation instead of mutating a single per-wallet row (append-only).",
  },
  {
    id: "VERBATIM_SETTLED_TEXT_IS_TEXT",
    sqlAnchor: "settled_transaction_text text NOT NULL",
    rule: "the exact settled SplitChain transaction is stored as text — never jsonb, which canonicalizes key sequence and whitespace and would destroy the signed byte layout.",
  },
  {
    id: "SETTLED_DIGEST_BOUND",
    sqlAnchor: "settled_transaction_sha256 sha256_hex NOT NULL,",
    rule: "the settled bytes are stored alongside their sha256 so a byte round-trip is checkable without re-deriving the digest (the evidence is retention plus byte-round-trip tests).",
  },
  {
    id: "SETTLED_BODY_FOREIGN_KEY",
    sqlAnchor:
      "FOREIGN KEY (operation_id, attempt_no)\n    REFERENCES operation_transactions(operation_id, attempt_no)",
    rule: "a ledger row can never exist without the attempt row whose completed_transaction_text it copies — no orphan ledger row.",
  },
  {
    id: "PARTICIPANT_FOREIGN_KEY",
    sqlAnchor:
      "FOREIGN KEY (operation_id, wallet_id)\n    REFERENCES operation_wallets(operation_id, wallet_id)",
    rule: "the wallet must be a recorded participant of the operation. Role-value binding is a separate BEFORE INSERT check — this FK alone only proves participation.",
  },
  {
    id: "ROLE_VOCABULARY_MATCHES_OPERATION_WALLETS",
    sqlAnchor: "operation_role text NOT NULL CHECK (operation_role IN\n    ('RECEIVER','SOURCE','DESTINATION'))",
    rule: "the role column reuses operation_wallets.operation_role's name and value set verbatim; lineage_path_bodies.wallet_role's lowercase ('sender','receiver') pair describes untrusted proof-path hops at a different grain and is not adopted, and no fourth spelling is minted.",
  },
  {
    id: "ROLE_BOUND_TO_PARTICIPANT",
    sqlAnchor: "RAISE EXCEPTION 'WALLET_SETTLED_LEDGER_ROLE_MISMATCH' USING ERRCODE = '23514';",
    rule: "BEFORE INSERT rejects a row whose operation_role disagrees with operation_wallets.operation_role for the same (operation_id, wallet_id). The participant FK alone would admit a swapped SOURCE/DESTINATION label on a permanent insert-only ledger.",
  },
  {
    id: "PUBKEY_BOUND_TO_WALLET",
    sqlAnchor: "RAISE EXCEPTION 'WALLET_SETTLED_LEDGER_PUBKEY_MISMATCH' USING ERRCODE = '23514';",
    rule: "BEFORE INSERT rejects a row whose wallet_public_key disagrees (bytea-compared) with wallets.public_key for wallet_id. Uniqueness and any future export key off (wallet_public_key, settled_transaction_sha256), so a wrong pubkey would mis-attribute settled bytes permanently.",
  },
  {
    id: "WALLET_SIGNATURE_UNIQUENESS",
    sqlAnchor:
      "CONSTRAINT wallet_settled_ledger_wallet_signature_uniq\n    UNIQUE (wallet_public_key, settled_transaction_sha256),",
    rule: "the same settled bytes cannot be recorded twice against the same wallet — rejected by PostgreSQL, not by application code. Named so the negative-path test can assert the constraint identity rather than a truncated auto-generated name.",
  },
  {
    id: "ONE_ROW_PER_ROLE_PER_ATTEMPT",
    sqlAnchor:
      "CONSTRAINT wallet_settled_ledger_one_row_per_role_uniq\n    UNIQUE (operation_id, attempt_no, operation_role),",
    rule: "a settled MOVE_INTERNAL records exactly one SOURCE and one DESTINATION leg; a duplicated leg is rejected at the database.",
  },
  {
    id: "POSITIVE_ZKZ_AMOUNT_DOMAIN",
    sqlAnchor: "amount_zkz zkz_amount_positive_text NOT NULL,",
    rule: "The per-leg amount binds the strictly-positive domain (VALUE::numeric > 0). The retired zkz_amount_text domain must not be attached to a new column, and its grammar-only check would accept the numerically-zero forms '0.0' and '0.' + zeros.",
  },
  {
    id: "LANDED_ORACLE_IS_EXACT_OR_COMPLETE_PATH",
    sqlAnchor: "landing_verdict text NOT NULL CHECK (landing_verdict IN\n    ('LANDED_EXACT','LANDED_COMPLETE_PATH'))",
    rule: "only the two landing oracles are storable — the same value set external_send_landing_records.source_path_kind admits.",
  },
  {
    id: "LANDED_AND_VERBATIM_APPEND_GATE",
    sqlAnchor: "CREATE TRIGGER wallet_settled_ledger_landed_verbatim",
    rule: "BEFORE INSERT the row is rejected unless the attempt reached SETTLED_BODY_PERSISTED, its settled bytes are byte-identical to that body (compared as bytea, not under a collation), an operation_verifications row with verdict VERIFIED carries this landing proof, operation_role matches the participant row, and wallet_public_key matches wallets.public_key. A bare settled_at write or a gateway acknowledgement produces no row.",
  },
  {
    id: "INSERT_ONLY_TRIGGER",
    sqlAnchor: "CREATE TRIGGER wallet_settled_ledger_insert_only",
    rule: "WALLET_SETTLED_LEDGER_INSERT_ONLY — UPDATE and DELETE raise outright, so ledger bytes are permanent; proof-access expiry revokes access without deleting them.",
  },
  {
    id: "NO_TRUNCATE",
    sqlAnchor: "CREATE TRIGGER wallet_settled_ledger_no_truncate",
    rule: "TRUNCATE is rejected too — the insert-only row trigger alone would not see it.",
  },
  {
    id: "NO_MATERIALIZED_BALANCE",
    sqlAnchor: "CREATE TABLE wallet_settled_ledger (",
    rule: "no running-balance and no row_version column: balances are derived by re-reading the verbatim bytes. A CAS-updated per-wallet balance row is the projection the canonical-container rule forbids.",
  },
] as const;

// Mutability regime.
export const WALLET_SETTLED_LEDGER_MUTABILITY_REGIMES = [
  {
    table: "wallet_settled_ledger",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "WALLET_SETTLED_LEDGER_INSERT_ONLY — the trigger rejects UPDATE, DELETE and TRUNCATE outright.",
  },
] as const;

/**
 * The retention-matrix authoring gap this slice designs around. Split into what the
 * canonical-container rule and the transaction relations already fix (not open to change
 * without revisiting that rule) and what remains implementer judgement, pending a frozen
 * shape in the retention matrix.
 */
export const WALLET_SETTLED_LEDGER_SPEC_RESIDUE = {
  governingLawFixes: [
    "insert-only, permanent, never rewritten.",
    "the exact settled transaction text plus its sha256 are retained verbatim.",
    "the ledger binds the settled body via (operation_id, attempt_no).",
    "the grain is (wallet, landed operation), so MOVE_INTERNAL records two legs.",
    "rows appear only after independent landing verification accepts the operation.",
  ],
  implementerJudgement: [
    "the table name wallet_settled_ledger (the retention matrix names the object in prose only).",
    "the role column named operation_role, reusing operation_wallets' vocabulary rather than minting a new one — see the SQL header's reconciliation note.",
    "landing_verdict modelled as a text CHECK over the two landing oracles rather than the lineage_proof_verdict enum, matching external_send_landing_records.source_path_kind.",
    "landing_proof_id carried as a bare uuid: this slice predates operation_landing_proofs (frozen in landing-proof-verifications.sql), so the FK is still a deferred schema-apply obligation (the same forward reference verification-proofs.sql already makes).",
    "the slice-local insert-only trigger pair, which the package-wide retention regime supersedes.",
  ],
  authority: "the retention matrix freezes no DDL for this table",
} as const;

// Live-database obligations the schema phase alone cannot discharge. The [pg] items are
// proven in packages/node-core/test/wallet-settled-ledger.pg.test.ts.
export const SCHEMA_WALLET_SETTLED_LEDGER_OBLIGATIONS = [
  "apply sequence: custody-eligibility.sql (wallets), operations.sql (operations, operation_wallets), transaction-material.sql (operation_transactions) all precede this slice; landing-proof-verifications.sql (operation_verifications, operation_landing_proofs) is appended late in MONEY_SCHEMA_PACK_ORDER, so the trigger's operation_verifications lookup only resolves after full pack apply, not mid-apply.",
  "add FOREIGN KEY (landing_proof_id) REFERENCES operation_landing_proofs(id) once the landing-proof table is frozen — today the trigger's operation_verifications lookup is the only binding.",
  "[pg] the settled text and sha256 read back byte-for-byte identical to operation_transactions.completed_transaction_text / completed_transaction_sha256 for the same (operation_id, attempt_no) — the byte round-trip.",
  "[pg] a settled MOVE_INTERNAL produces exactly two rows (SOURCE, DESTINATION) against one settled body; RECEIVE_EXTERNAL and SEND_EXTERNAL produce exactly one.",
  "[pg] a duplicate (wallet_public_key, settled_transaction_sha256) insert is rejected by PostgreSQL with 23505.",
  "[pg] an operation with no VERIFIED operation_verifications row carrying the landing proof produces no ledger row.",
  "[pg] an attempt short of SETTLED_BODY_PERSISTED, and a re-serialized copy of the settled bytes, are both rejected at INSERT.",
  "[pg] a swapped operation_role on a real participant raises WALLET_SETTLED_LEDGER_ROLE_MISMATCH; a wallet_public_key that is not wallets.public_key for wallet_id raises WALLET_SETTLED_LEDGER_PUBKEY_MISMATCH.",
  "[pg] UPDATE, DELETE and TRUNCATE against the ledger raise WALLET_SETTLED_LEDGER_INSERT_ONLY.",
  "the package-wide retention regime replaces or subsumes the slice-local insert-only triggers with its byte-immutability and proof-access-expiry regime; expiry must revoke access without deleting rows.",
] as const;

export const WALLET_SETTLED_LEDGER_SOURCE =
  "data-model: canonical wallet settled ledger" as const;
