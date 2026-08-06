// Operations: the operations and operation_wallets tables, with the reference scalar
// checks and enumerations they use;
// three public money operations (exactly three public money operations); the one-in-flight-per-wallet rule (one in-flight
// transaction per wallet).
//
// Frozen inventory of the structural operation-model invariants carried by
// operations.sql: the operations table (one row per RECEIVE_EXTERNAL /
// MOVE_INTERNAL / SEND_EXTERNAL operation) and the operation_wallets table (role-relative
// wallet participation). The census test binds every entry here to the literal SQL text,
// so inventory and schema contract cannot drift apart silently. Execution against a live
// database belongs to the schema-apply phase, recorded below as obligations rather than
// silently omitted.
//
// The naming conflict this note used to report is closed: the tables are transcribed
// verbatim with wallet FKs targeting wallets(id), and custody-eligibility.sql declares
// wallets(id) to match. What remains is execution sequence and domain prerequisites
// (base-enums-domains + nodes/implementers before this file's tables).

export const OPERATIONS_SCHEMA_FILE = "operations.sql" as const;

export interface OperationsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const OPERATIONS_INVARIANTS: readonly OperationsInvariant[] = [
  {
    id: "DOMAIN_ZKZ_AMOUNT_POSITIVE_TEXT",
    sqlAnchor:
      "CREATE DOMAIN zkz_amount_positive_text AS text\n  CHECK (VALUE ~ '^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$' AND VALUE::numeric > 0);",
    rule: "A persisted operation amount is canonical decimal text bounded < 1e8 AND NUMERICALLY positive (VALUE::numeric > 0), not merely string `<> '0'` -- closing the zero-form bypass where '0.0' / '0.00' / '0.' + 32 zeros match the grammar and differ from the string '0' yet are mathematically zero. Predicate byte-identical to generic-node-contracts ZKZ_AMOUNT_CHECK_DOMAINS.zkz_amount_positive_text; the regex is a first boundary only, never proof of a valid amount.",
  },
  {
    id: "DOMAIN_SHA256_HEX",
    sqlAnchor: "CREATE DOMAIN sha256_hex AS text\n  CHECK (VALUE ~ '^[0-9a-f]{64}$');",
    rule: "Verbatim: a sha256_hex value is exactly 64 lowercase hex characters; the regex is a first boundary only, never proof of valid material.",
  },
  {
    id: "DOMAIN_PADDED_BASE64URL_PUBKEY",
    sqlAnchor:
      "CREATE DOMAIN padded_base64url_pubkey AS text\n  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');",
    rule: "Verbatim: a padded base64url public key is exactly 44 characters (43 base64url characters plus the = pad); insertion is not proof of valid Ed25519 material.",
  },
  {
    id: "OPERATION_PK",
    sqlAnchor: "CREATE TABLE operations (\n  id uuid PRIMARY KEY,",
    rule: "one row per operation, keyed by a uuid primary key; every operation, wallet, destination, observation, artifact, approval, and event identifier is a uuid.",
  },
  {
    id: "OPERATION_NODE_FK",
    sqlAnchor: "node_id uuid NOT NULL REFERENCES nodes(id),",
    rule: "every operation belongs to exactly one node; the FK is immediate.",
  },
  {
    id: "OPERATION_IMPLEMENTER_FK",
    sqlAnchor: "implementer_id uuid NOT NULL REFERENCES implementers(id),",
    rule: "every operation is owned by exactly one implementer; the implementer scopes the idempotency key below.",
  },
  {
    id: "OPERATION_KIND_CLOSED_SET",
    sqlAnchor: "kind operation_kind NOT NULL,",
    rule: "the operation kind is one of the three public money operations -- RECEIVE_EXTERNAL / MOVE_INTERNAL / SEND_EXTERNAL; a fourth kind is not representable.",
  },
  {
    id: "OPERATION_STATUS_CLOSED_SET",
    sqlAnchor: "status operation_status NOT NULL,",
    rule: "the operation status is drawn from the closed operation_status enum; the per-kind admissible subset is enforced separately by OPERATION_KIND_STATUS_LADDER.",
  },
  {
    id: "OPERATION_ROW_VERSION_CAS",
    sqlAnchor: "row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),",
    rule: "every operation carries a positive compare-and-swap version starting at 1: each status transition bumps it under a transaction, so a stale writer loses the CAS rather than clobbering a concurrent transition.",
  },
  {
    id: "OPERATION_AMOUNT_POSITIVE",
    sqlAnchor: "amount_zkz zkz_amount_positive_text NOT NULL,",
    rule: "an operation never moves zero (or negative) ZKZ: amount_zkz binds the strictly-positive zkz_amount_positive_text domain (VALUE::numeric > 0), so numeric positivity is enforced at rest by the domain, not by a table-level string `<> '0'` check (a string check leaks the numerically-zero forms '0.0' / '0.00' / '0.' + 32 zeros).",
  },
  {
    id: "OPERATION_IDEMPOTENCY_KEY_BOUNDED",
    sqlAnchor: "idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[!-~]{16,255}$'),",
    rule: "the caller-supplied idempotency key is always present and is 16..255 visible-ASCII characters, reconciled with the API contract's idempotency-key grammar; it is the replay-dedup input alongside the request digest.",
  },
  {
    id: "OPERATION_REQUEST_DIGEST",
    sqlAnchor: "request_sha256 sha256_hex NOT NULL,",
    rule: "the SHA-256 of the exact request preimage is persisted on every operation: idempotent replays are matched on the exact request bytes, never on a reconstruction.",
  },
  {
    id: "OPERATION_EXPIRY_IS_DIGIT_STRING",
    sqlAnchor: "expiry_unix_time_secs text CHECK (expiry_unix_time_secs ~ '^[0-9]+$'),",
    rule: "a receive expiry is persisted as a bare digit string of unix SECONDS: the column is text so no lossy integer coercion happens at rest, and the grammar guard keeps a signed, fractional, or millisecond-shaped value out of the row.",
  },
  {
    id: "OPERATION_IDEMPOTENCY_UNIQUE_PER_IMPLEMENTER_KIND",
    sqlAnchor: "UNIQUE (implementer_id, kind, idempotency_key),",
    rule: "at most one operation per (implementer, kind, idempotency key): a replayed request under the same implementer and kind resolves to the existing operation rather than creating a second one.",
  },
  {
    id: "OPERATION_COMPOSITE_IDENTITY_UNIQUE",
    sqlAnchor: "UNIQUE (id, node_id, implementer_id),",
    rule: "the (id, node_id, implementer_id) triple is unique: an operation's identity is pinned to its owning node and implementer, so downstream tables that reference the operation can carry the composite without admitting a mismatched owner.",
  },
  {
    id: "OPERATION_ONE_SPAWN_PER_PARENT",
    sqlAnchor:
      "CREATE UNIQUE INDEX operations_one_spawn_per_parent_uidx\n  ON operations (spawned_from_operation_id)\n  WHERE spawned_from_operation_id IS NOT NULL;",
    rule: "at most one child operation may reference a given parent via spawned_from_operation_id: the partial unique index is the sole arbiter for parent→child spawn races; NULL parents are unrestricted so ordinary creates are unaffected.",
  },
  {
    id: "OPERATION_RECEIVE_DISCRIMINATOR_ANCHOR_IFF",
    sqlAnchor:
      "(kind = 'RECEIVE_EXTERNAL' AND discriminator IS NOT NULL AND anchor IS NOT NULL)\n    OR\n    (kind <> 'RECEIVE_EXTERNAL'\n      AND discriminator IS NULL AND anchor IS NULL AND expiry_unix_time_secs IS NULL)",
    rule: "the receive discriminator and anchor exist exactly for RECEIVE_EXTERNAL and are absent (with expiry) for every other kind: a move or send never carries receive identity material.",
  },
  {
    id: "OPERATION_RECEIVE_ASSIGNMENT_TRIPLE",
    sqlAnchor:
      "kind <> 'RECEIVE_EXTERNAL'\n    OR (\n      status IN ('CREATED','EXPIRED') AND receiver_wallet_id IS NULL\n      AND expiry_unix_time_secs IS NULL AND t0_observation_id IS NULL\n    )\n    OR (\n      receiver_wallet_id IS NOT NULL\n      AND expiry_unix_time_secs IS NOT NULL AND t0_observation_id IS NOT NULL\n    )",
    rule: "a receive either names no wallet at all or names the complete (receiver wallet, expiry, T0) triple: payer-code material is unrepresentable on a walletless row, so queue wait never eats the payer's window, and an assigned receive can never be missing half its code inputs. The walletless arm is `status IN ('CREATED','EXPIRED')` -- in this CHECK and in the receive arm of OPERATION_KIND_WALLET_SHAPE -- so a never-assigned receive that the queue expirer expires in place has a legal terminal row; READY and RECEIVE_LANDED still require the full triple. A walletless EXPIRED row does NOT prove no wallet was leased: assignment binds via the lease and the operation_wallets RECEIVER row first, so release follows the receive-expiry flow, never receiver_wallet_id IS NULL.",
  },
  {
    id: "OPERATION_RECEIVE_DISCRIMINATOR_IS_ID",
    sqlAnchor: "CHECK (kind <> 'RECEIVE_EXTERNAL' OR discriminator = id)",
    rule: "for a receive the discriminator is the operation's own id: the receive code discriminates on the operation itself, never on a foreign value.",
  },
  {
    id: "OPERATION_RECEIVE_ANCHOR_SHAPE",
    sqlAnchor: "CHECK (kind <> 'RECEIVE_EXTERNAL' OR anchor ~ '^[A-Za-z0-9_-]{1,96}$')",
    rule: "a receive anchor is 1..96 base64url-alphabet characters; the regex is a first boundary only.",
  },
  {
    id: "OPERATION_KIND_WALLET_SHAPE",
    sqlAnchor:
      "(kind = 'MOVE_INTERNAL' AND source_wallet_id IS NOT NULL\n      AND destination_id IS NOT NULL AND destination_address IS NULL\n      AND receiver_wallet_id IS NULL AND after_landing IS NULL)\n    OR\n    (kind = 'SEND_EXTERNAL' AND source_wallet_id IS NOT NULL\n      AND destination_address IS NOT NULL AND receiver_wallet_id IS NULL\n      AND destination_id IS NULL AND after_landing IS NULL)",
    rule: "each kind binds exactly its wallet shape: a move names a source wallet and a destination (no address, no receiver, no after-landing); a send names a source wallet and a destination address (no receiver, no destination row, no after-landing); a receive names neither source nor address and always carries an after-landing.",
  },
  {
    id: "OPERATION_AFTER_LANDING_DESTINATION_IFF",
    sqlAnchor:
      "(after_landing = 'INTERNAL_MOVE' AND after_landing_destination_id IS NOT NULL)\n    OR (after_landing IS DISTINCT FROM 'INTERNAL_MOVE' AND after_landing_destination_id IS NULL)",
    rule: "the after-landing destination exists exactly when after_landing is INTERNAL_MOVE: a receive that requests an internal move names its destination, and no other operation does.",
  },
  {
    id: "OPERATION_KIND_STATUS_LADDER",
    sqlAnchor:
      "(kind = 'RECEIVE_EXTERNAL' AND status IN\n      ('CREATED','READY','RECEIVE_LANDED','EXPIRED'))\n    OR\n    (kind = 'MOVE_INTERNAL' AND status IN\n      ('CREATED','INTERNAL_MOVE_LANDED','NEEDS_ATTENTION'))\n    OR\n    (kind = 'SEND_EXTERNAL' AND status IN\n      ('CREATED','APPROVED','AWAITING_REDEMPTION','EXTERNAL_SEND_LANDED',\n       'REJECTED','NEEDS_ATTENTION'))",
    rule: "each kind admits exactly its own status subset: a receive never reaches APPROVED, a move never reaches READY, a send never reaches RECEIVE_LANDED -- the per-kind ladders are structurally disjoint where the protocol says so.",
  },
  {
    id: "OPERATION_SEND_IFF_FORMATION_REQUIRED",
    sqlAnchor: "CHECK ((kind = 'SEND_EXTERNAL') = (formation_state <> 'NOT_REQUIRED'))",
    rule: "an external-send formation state exists exactly for SEND_EXTERNAL: only a send forms a SplitChain transaction, so only a send carries a formation state other than NOT_REQUIRED.",
  },
  {
    id: "OPERATION_ATTENTION_IFF_REASON",
    sqlAnchor: "CHECK (attention_required = (attention_reason IS NOT NULL))",
    rule: "attention_required is true exactly when an attention_reason is present: the flag and its reason are set together or absent together, never divergent.",
  },
  {
    id: "OPERATION_TERMINAL_AT_AFTER_CREATED",
    sqlAnchor: "CHECK (terminal_at IS NULL OR terminal_at >= created_at)",
    rule: "a terminal timestamp, when present, never precedes creation; timestamps are not uniqueness or sequence keys, only a sanity bound here.",
  },
  {
    id: "WALLET_PARTICIPATION_OPERATION_FK",
    sqlAnchor:
      "CREATE TABLE operation_wallets (\n  operation_id uuid NOT NULL REFERENCES operations(id),",
    rule: "every wallet-participation row belongs to exactly one operation; the FK is immediate.",
  },
  {
    id: "WALLET_PARTICIPATION_WALLET_FK",
    sqlAnchor: "wallet_id uuid NOT NULL REFERENCES wallets(id),",
    rule: "every wallet-participation row names an existing wallet; the FK target is transcribed verbatim as wallets(id) -- the prior custody wallets(wallet_id) naming conflict is closed.",
  },
  {
    id: "WALLET_PARTICIPATION_ROLE_CLOSED_SET",
    sqlAnchor:
      "operation_role text NOT NULL CHECK (operation_role IN ('RECEIVER','SOURCE','DESTINATION')),",
    rule: "a wallet participates under exactly one of RECEIVER / SOURCE / DESTINATION: this role-relative participation vocabulary is distinct from the wallet_lease_role enum of the universal lease, which is frozen in the lease lane.",
  },
  {
    id: "WALLET_PARTICIPATION_COMPOSITE_PK",
    sqlAnchor: "PRIMARY KEY (operation_id, wallet_id),",
    rule: "at most one participation row per (operation, wallet): a wallet is recorded once per operation even when the prose describes it in two roles.",
  },
  {
    id: "WALLET_PARTICIPATION_ONE_ROLE_PER_OPERATION",
    sqlAnchor: "UNIQUE (operation_id, operation_role)",
    rule: "each role is filled at most once per operation: one receiver, one source, one destination per operation -- a second wallet claiming the same role is a unique_violation.",
  },
  {
    id: "WALLET_PARTICIPATION_OBSERVATION_NO_FK",
    sqlAnchor: "t0_observation_id uuid,\n  terminal_observation_id uuid,",
    rule: "the per-role T0 and terminal observation references carry NO foreign key yet: the FKs to observation rows are added only after the observation tables exist, and the transition service must also verify matching wallet and observer domain.",
  },
] as const;

// The two mutability regimes. No trigger DDL is frozen for them, so the regimes live
// here as inventory plus schema-apply execution obligations (the conventions sanction
// append-only exact-content tables or byte-immutability triggers). `updatableColumns` names every column a
// legal UPDATE may touch; every other column is frozen at insert.
export const OPERATIONS_MUTABILITY_REGIMES = [
  {
    table: "operations",
    regime: "cas_guarded_status_transition",
    updatableColumns: [
      "status",
      "row_version",
      "attention_required",
      "attention_reason",
      "attention_detail",
      "attention_episode",
      "receive_release_status",
      "receiver_wallet_id",
      "expiry_unix_time_secs",
      "t0_observation_id",
      "terminal_observation_id",
      "formation_state",
      "verification_verdict",
      "verification_material_available_until",
      "updated_at",
      "terminal_at",
    ] as readonly string[],
    rule: "request identity (id, node_id, implementer_id, kind, amount_zkz, idempotency_key, request_sha256, discriminator, anchor) is frozen at insert; status transitions advance only the listed columns, each under a transaction guarded by row_version compare-and-swap.",
  },
  {
    table: "operation_wallets",
    regime: "insert_then_one_way_observation_binding",
    updatableColumns: ["t0_observation_id", "terminal_observation_id"] as readonly string[],
    rule: "the (operation, wallet, role) binding is frozen at insert; only the two observation references are filled one-way later, never overwritten.",
  },
] as const;

// Live-database proofs this package cannot run (no database harness lands in this package). The schema-apply phase MUST discharge each of these against a real
// Postgres before the schema contract is considered enforced.
export const SCHEMA_OPERATIONS_OBLIGATIONS = [
  "execution sequence: create the reference scalar domains (zkz_amount_positive_text, sha256_hex, padded_base64url_pubkey), the four enums (operation_kind, operation_status, external_formation_state, verification_verdict), and the FK target relations nodes(id), implementers(id), wallets(id), destinations(id) before this file's tables; the custody wallets(wallet_id) naming conflict this obligation used to carry is closed, so only the execution sequence and domain prerequisites remain to be honoured.",
  "guards: install the row_version compare-and-swap transition guard on operations and the one-way observation-binding guard on operation_wallets (the conventions sanction byte-immutability triggers; no trigger DDL is frozen in this file).",
  "negative: a second operations row for the same (implementer_id, kind, idempotency_key) is rejected with unique_violation (23505) -- a replayed request resolves to the existing operation, never a duplicate.",
  "negative: a second operations row with the same non-null spawned_from_operation_id is rejected with unique_violation (23505) on operations_one_spawn_per_parent_uidx -- concurrent parent→child spawn races yield exactly one child.",
  "negative: amount_zkz numerically-zero forms ('0', '0.0', '0.00', '0.' + 32 zeros), negative or >= 1e8 amounts, row_version = 0, an empty or 256-character idempotency_key, and malformed zkz_amount_positive_text / sha256_hex / padded_base64url_pubkey values are rejected by their CHECKs and domains (numeric positivity, not a string `<> '0'`).",
  "negative: a RECEIVE_EXTERNAL whose discriminator <> id, whose anchor fails ^[A-Za-z0-9_-]{1,96}$, or which carries a source_wallet_id or destination_address is rejected; a MOVE_INTERNAL or SEND_EXTERNAL carrying discriminator / anchor / expiry_unix_time_secs is rejected.",
  "negative: a kind outside its admissible status subset (e.g. RECEIVE_EXTERNAL at APPROVED, MOVE_INTERNAL at READY, SEND_EXTERNAL at RECEIVE_LANDED) is rejected by the per-kind status CHECK.",
  "negative: a SEND_EXTERNAL with formation_state = NOT_REQUIRED (and any non-send with formation_state <> NOT_REQUIRED) is rejected by the send-iff-formation biconditional.",
  "negative: attention_required set with attention_reason NULL (and the converse), and terminal_at earlier than created_at, are rejected by their CHECKs.",
  "negative: an operation_role outside ('RECEIVER','SOURCE','DESTINATION') is rejected by the column CHECK, and a second operation_wallets row for the same (operation_id, operation_role) -- or the same (operation_id, wallet_id) -- is rejected with unique_violation.",
  "application-level: the wallet_active_leases foreign keys to operations(id) and the observation FKs on operations / operation_wallets are added only after the lease and observation tables exist, and the transition service must verify matching wallet and observer domain; the schema-apply phase must prove the lease schema enforces the one-in-flight-per-wallet rule (one in-flight operation per wallet) through these references.",
] as const;

export const OPERATIONS_SOURCE = "data-model: operations and operation wallets; the one-in-flight-per-wallet rule" as const;
