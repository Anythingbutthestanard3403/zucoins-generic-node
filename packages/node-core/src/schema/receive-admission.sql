-- Receive admission: the request-admission row, custody, one active lease per wallet
-- (the one-in-flight-per-wallet rule), the idempotency record, the receive queue, and after_landing.
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database; nothing in this package opens a socket.
-- Every invariant below is inventoried in receive-admission.contract.ts.
--
-- Prerequisite slice: custody-eligibility.sql, which declares wallets and destinations. A
-- foreign key needs its target relation to exist EARLIER in the apply sequence, so this file
-- is NOT self-contained: applying it greenfield into an empty schema fails on the missing
-- wallets relation. That is the documented expected outcome, asserted by
-- test/migration-integrity.test.ts alongside the other prerequisite-bound slices.
--
-- The wallets PK is `id`; destinations PK is `id`; destinations.wallet_id FKs wallets(id).
-- Column names on this slice follow that frozen surface (same pattern as send-external-create).

-- The canonical ZKZ amount bound is enforced at rest, never by application
-- validation alone. Numeric positivity (amount_zkz::numeric > 0), NOT string positivity.
-- A column CHECK rather than a CREATE DOMAIN deliberately: base-enums-domains.sql (and
-- the operations.sql slice) already declare zkz_amount_positive_text, and two slices
-- cannot both create it (same pattern as send-external-create.sql).

-- The create-time row for RECEIVE_EXTERNAL. It is simultaneously the operation record and
-- the idempotency record: a row whose completed_at IS NULL is the
-- in-progress marker, and its insert -- not any application-level read -- is the
-- concurrency arbiter for both idempotency and the one-in-flight-per-wallet rule.
--
-- This is a RECEIVE-specific projection table (parallel to send_operations). The universal
-- operations table (operations.sql) remains the surface used by the pool allocator
-- assignment path; the schema-apply phase wires both. Admission writes this row first so
-- idempotency and the one-in-flight-per-wallet rule are decided
-- by UNIQUE constraints before any wallet, code, artifact, or lease exists.
CREATE TABLE receive_operations (
  operation_id uuid PRIMARY KEY,
  implementer_id uuid NOT NULL,
  node_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind = 'RECEIVE_EXTERNAL'),
  status text NOT NULL CHECK (status IN ('CREATED', 'READY', 'RECEIVE_LANDED', 'EXPIRED')),
  -- The idempotency scope is the FULL tuple
  -- (implementer_id, HTTP method, canonical route, idempotency_key). Never key-only.
  http_method text NOT NULL CHECK (http_method = 'POST'),
  route text NOT NULL CHECK (route = '/v1/receives'),
  idempotency_key text NOT NULL
    CHECK (char_length(idempotency_key) BETWEEN 16 AND 255 AND idempotency_key ~ '^[[:print:]]+$'),
  -- A SHA-256 hash of the exact validated canonical request object.
  request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  amount_zkz text NOT NULL,
  anchor text NOT NULL CHECK (anchor ~ '^[A-Za-z0-9_-]{1,96}$'),
  ttl_ms bigint NOT NULL CHECK (ttl_ms > 0),
  after_landing_kind text NOT NULL CHECK (after_landing_kind IN ('HOLD', 'INTERNAL_MOVE')),
  -- INTERNAL_MOVE destination (destinations.id). HOLD leaves both null.
  destination_id uuid,
  -- Denormalized destination wallet (wallets.id) so the one-in-flight-per-wallet rule can index it without a join.
  destination_wallet_id uuid REFERENCES wallets (id),
  -- Receiver wallet stamped by the assignment slice. Admission always leaves null
  -- (admission exit invariant: no receiver while CREATED).
  wallet_id uuid REFERENCES wallets (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  -- Status and exact response body from the first completed execution.
  -- completed_at IS NULL is precisely the in-progress marker.
  completed_at timestamptz,
  response_status integer,
  response_body text,
  -- Amount bound (column CHECK; see header). Predicate text matches
  -- ZKZ_AMOUNT_CHECK_DOMAINS.zkz_amount_positive_text under VALUE -> amount_zkz.
  CONSTRAINT receive_operations_amount_positive
    CHECK (amount_zkz ~ '^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$' AND amount_zkz::numeric > 0),
  CONSTRAINT receive_operations_completion_together
    CHECK ((completed_at IS NULL) = (response_status IS NULL)
           AND (completed_at IS NULL) = (response_body IS NULL)),
  CONSTRAINT receive_operations_destination_iff
    CHECK ((after_landing_kind = 'INTERNAL_MOVE') = (destination_id IS NOT NULL)),
  CONSTRAINT receive_operations_destination_wallet_iff
    CHECK ((destination_id IS NULL) = (destination_wallet_id IS NULL)),
  CONSTRAINT receive_operations_no_receiver_while_created
    CHECK (status <> 'CREATED' OR wallet_id IS NULL),
  -- Idempotency scope, structural. Concurrent first use of one key:
  -- exactly one inserter wins, every follower gets 23505.
  CONSTRAINT receive_operations_idempotency_scope
    UNIQUE (implementer_id, http_method, route, idempotency_key)
);

-- FK into destinations added after the table exists so the CREATE TABLE block stays
-- readable and the inventory can anchor the FK text independently.
ALTER TABLE receive_operations
  ADD CONSTRAINT receive_operations_destination_fk
  FOREIGN KEY (destination_id)
  REFERENCES destinations (id);

-- The one-in-flight-per-wallet rule, structural: one unsettled receive per destination wallet (INTERNAL_MOVE).
CREATE UNIQUE INDEX receive_operations_one_unsettled_per_destination
  ON receive_operations (destination_wallet_id)
  WHERE destination_wallet_id IS NOT NULL AND status IN ('CREATED', 'READY');

-- The one-in-flight-per-wallet rule over the receiver wallet the assignment slice stamps onto the row.
CREATE UNIQUE INDEX receive_operations_one_unsettled_per_wallet
  ON receive_operations (wallet_id)
  WHERE wallet_id IS NOT NULL AND status IN ('CREATED', 'READY');
