-- Operations: the operations and operation_wallets tables, plus the reference scalar
-- checks and enumerations they use. There are exactly three public money operations, and
-- the one-in-flight-per-wallet rule holds (one in-flight transaction per wallet).
-- Frozen schema contract. This file is contract text: it is executed only by
-- the schema-apply phase against a live database; nothing in this package runs it. Every
-- invariant below is inventoried in operations.contract.ts and censused by
-- test/operations.census.test.ts.
--
-- Three points where this schema is deliberately narrower or wider than a naive reading of
-- the operation model:
--
--   The operation amount domain: amount_zkz binds the strictly-positive
--   zkz_amount_positive_text domain (VALUE::numeric > 0), sourced byte-for-byte from the
--   generic-node-contracts amounts manifest (ZKZ_AMOUNT_CHECK_DOMAINS). A grammar-only
--   zkz_amount_text domain plus a string `amount_zkz <> '0'` check would leak the
--   numerically-zero forms ('0.0', '0.00', '0.' followed by 32 zeros), which match the
--   grammar and differ from the string '0' while being mathematically zero.
--
--   The two walletless-receive CHECK arms below (the assignment triple, and the receive arm
--   of the per-kind wallet shape) read `status IN ('CREATED','EXPIRED')`. A receive past
--   RECEIVE_QUEUE_MAX_WAIT becomes EXPIRED with no wallet assigned and no lease, so
--   `status = 'CREATED'` alone would make that row unrepresentable and the queue expirer
--   unimplementable. Only EXPIRED joins CREATED: READY and RECEIVE_LANDED still require the
--   complete (wallet, expiry, T0) triple, and expiry and T0 remain unrepresentable without a
--   wallet in EITHER walletless status, so a queued receive still carries no payer-code
--   material. A walletless EXPIRED row is NOT proof that no wallet was ever leased:
--   assignment binds through the lease and the operation_wallets RECEIVER row, which are
--   written before receiver_wallet_id, expiry and t0_observation_id exist. Wallet release is
--   governed by the receive-expiry flow, never by operations.receiver_wallet_id IS NULL.
--
--   The SEND_EXTERNAL status/formation lockstep CHECK admits AWAITING_REDEMPTION with
--   formation_state IN ('PARTIAL_PERSISTED','PARTIAL_DELIVERED'). The money-path
--   compare-and-swap (send-form-and-sign CAS_SIGNING_CLAIMED_TO_AWAITING_REDEMPTION) enters
--   AWAITING_REDEMPTION at the PARTIAL_PERSISTED boundary, before any delivery;
--   PARTIAL_DELIVERED is reached once the partial is made retrievable.
--   EXTERNAL_SEND_LANDED remains PARTIAL_DELIVERED-only (a landed send has been delivered).
--
-- Scope: the two tables that model an operation and its role-relative wallet participation
-- (operations, operation_wallets). The lease relations (lease_groups,
-- lease_group_operations, wallet_lease_memberships, operation_observation_bindings, and the
-- wallet_active_leases ALTER) belong to the universal-lease schema and are deliberately not
-- transcribed here. The wallet-naming reconciliation note is carried in
-- operations.contract.ts, not in this file.

-- Reference scalar checks (the three domains these two tables use). sha256_hex and
-- padded_base64url_pubkey are verbatim; the amount domain is zkz_amount_positive_text
-- (numeric positivity, VALUE::numeric > 0), which replaces a grammar-only zkz_amount_text
-- -- see the header note. Its predicate is byte-identical to generic-node-contracts
-- ZKZ_AMOUNT_CHECK_DOMAINS.zkz_amount_positive_text:

CREATE DOMAIN zkz_amount_positive_text AS text
  CHECK (VALUE ~ '^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$' AND VALUE::numeric > 0);

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

-- Enumerations (verbatim; the four enums these two tables use):

CREATE TYPE operation_kind AS ENUM (
  'RECEIVE_EXTERNAL',
  'MOVE_INTERNAL',
  'SEND_EXTERNAL'
);

CREATE TYPE operation_status AS ENUM (
  'CREATED',
  'READY',
  'RECEIVE_LANDED',
  'INTERNAL_MOVE_LANDED',
  'APPROVED',
  'AWAITING_REDEMPTION',
  'EXTERNAL_SEND_LANDED',
  'EXPIRED',
  'REJECTED',
  'NEEDS_ATTENTION'
);

CREATE TYPE external_formation_state AS ENUM (
  'NOT_REQUIRED',
  'APPROVAL_PENDING',
  'APPROVED_UNSIGNED',
  'SIGNING_CLAIMED',
  'PARTIAL_PERSISTED',
  'PARTIAL_DELIVERED'
);

CREATE TYPE verification_verdict AS ENUM (
  'PENDING',
  'VERIFIED',
  'REJECTED',
  'INDETERMINATE'
);

-- Operations (verbatim; the operations and operation_wallets tables only):

CREATE TABLE operations (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  kind operation_kind NOT NULL,
  status operation_status NOT NULL,
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  attention_required boolean NOT NULL DEFAULT false,
  attention_reason text,
  attention_detail text,
  amount_zkz zkz_amount_positive_text NOT NULL,
  source_wallet_id uuid REFERENCES wallets(id),
  receiver_wallet_id uuid REFERENCES wallets(id),
  destination_id uuid REFERENCES destinations(id),
  destination_address padded_base64url_pubkey,
  after_landing text CHECK (after_landing IN ('HOLD', 'INTERNAL_MOVE')),
  after_landing_destination_id uuid REFERENCES destinations(id),
  spawned_from_operation_id uuid REFERENCES operations(id),
  references_operation_id uuid REFERENCES operations(id),
  discriminator uuid,
  anchor text,
  client_reference text,
  description text,
  idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[!-~]{16,255}$'),
  request_sha256 sha256_hex NOT NULL,
  expiry_unix_time_secs text CHECK (expiry_unix_time_secs ~ '^[0-9]+$'),
  t0_observation_id uuid,
  terminal_observation_id uuid,
  formation_state external_formation_state NOT NULL DEFAULT 'NOT_REQUIRED',
  verification_verdict verification_verdict NOT NULL DEFAULT 'PENDING',
  verification_material_available_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  terminal_at timestamptz,
  UNIQUE (implementer_id, kind, idempotency_key),
  UNIQUE (id, node_id, implementer_id),
  CHECK (
    (kind = 'RECEIVE_EXTERNAL' AND discriminator IS NOT NULL AND anchor IS NOT NULL)
    OR
    (kind <> 'RECEIVE_EXTERNAL'
      AND discriminator IS NULL AND anchor IS NULL AND expiry_unix_time_secs IS NULL)
  ),
  CHECK (
    kind <> 'RECEIVE_EXTERNAL'
    OR (
      status IN ('CREATED','EXPIRED') AND receiver_wallet_id IS NULL
      AND expiry_unix_time_secs IS NULL AND t0_observation_id IS NULL
    )
    OR (
      receiver_wallet_id IS NOT NULL
      AND expiry_unix_time_secs IS NOT NULL AND t0_observation_id IS NOT NULL
    )
  ),
  CHECK (kind <> 'RECEIVE_EXTERNAL' OR discriminator = id),
  CHECK (kind <> 'RECEIVE_EXTERNAL' OR anchor ~ '^[A-Za-z0-9_-]{1,96}$'),
  CHECK (
    (kind = 'RECEIVE_EXTERNAL'
      AND source_wallet_id IS NULL AND destination_address IS NULL
      AND after_landing IS NOT NULL
      AND (
        (status IN ('CREATED','EXPIRED') AND receiver_wallet_id IS NULL)
        OR
        (receiver_wallet_id IS NOT NULL AND discriminator IS NOT NULL AND anchor IS NOT NULL)
      ))
    OR
    (kind = 'MOVE_INTERNAL' AND source_wallet_id IS NOT NULL
      AND destination_id IS NOT NULL AND destination_address IS NULL
      AND receiver_wallet_id IS NULL AND after_landing IS NULL)
    OR
    (kind = 'SEND_EXTERNAL' AND source_wallet_id IS NOT NULL
      AND destination_address IS NOT NULL AND receiver_wallet_id IS NULL
      AND destination_id IS NULL AND after_landing IS NULL)
  ),
  CHECK (
    (after_landing = 'INTERNAL_MOVE' AND after_landing_destination_id IS NOT NULL)
    OR (after_landing IS DISTINCT FROM 'INTERNAL_MOVE' AND after_landing_destination_id IS NULL)
  ),
  CHECK (
    (kind = 'RECEIVE_EXTERNAL' AND status IN
      ('CREATED','READY','RECEIVE_LANDED','EXPIRED'))
    OR
    (kind = 'MOVE_INTERNAL' AND status IN
      ('CREATED','INTERNAL_MOVE_LANDED','NEEDS_ATTENTION'))
    OR
    (kind = 'SEND_EXTERNAL' AND status IN
      ('CREATED','APPROVED','AWAITING_REDEMPTION','EXTERNAL_SEND_LANDED',
       'REJECTED','NEEDS_ATTENTION'))
  ),
  CHECK ((kind = 'SEND_EXTERNAL') = (formation_state <> 'NOT_REQUIRED')),
  CHECK (
    kind <> 'SEND_EXTERNAL'
    OR (status = 'CREATED' AND formation_state = 'APPROVAL_PENDING')
    OR (status = 'APPROVED' AND formation_state IN
      ('APPROVED_UNSIGNED','SIGNING_CLAIMED','PARTIAL_PERSISTED'))
    OR (status = 'AWAITING_REDEMPTION' AND formation_state IN
      ('PARTIAL_PERSISTED','PARTIAL_DELIVERED'))
    OR (status = 'EXTERNAL_SEND_LANDED' AND formation_state = 'PARTIAL_DELIVERED')
    OR status IN ('REJECTED','NEEDS_ATTENTION')
  ),
  CHECK (attention_required = (attention_reason IS NOT NULL)),
  CHECK (terminal_at IS NULL OR terminal_at >= created_at)
);

CREATE TABLE operation_wallets (
  operation_id uuid NOT NULL REFERENCES operations(id),
  wallet_id uuid NOT NULL REFERENCES wallets(id),
  operation_role text NOT NULL CHECK (operation_role IN ('RECEIVER','SOURCE','DESTINATION')),
  t0_observation_id uuid,
  terminal_observation_id uuid,
  PRIMARY KEY (operation_id, wallet_id),
  UNIQUE (operation_id, operation_role)
);

-- At most one child operation per parent. Partial: NULL
-- parents are unrestricted. The service spawnChild path uses ON CONFLICT against this
-- index; create() refuses to write spawned_from_operation_id outside that arbiter.
CREATE UNIQUE INDEX operations_one_spawn_per_parent_uidx
  ON operations (spawned_from_operation_id)
  WHERE spawned_from_operation_id IS NOT NULL;
