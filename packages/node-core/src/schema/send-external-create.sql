-- Send external create: the operations row, the exact expected artifact, the create/response
-- wire shapes, idempotency, and one active lease per wallet (the one-in-flight-per-wallet rule).
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database; nothing in this package opens a socket.
-- Every invariant below is inventoried in send-external-create.contract.ts.
--
-- Prerequisite slice: custody-eligibility.sql, which declares wallets. A foreign key needs
-- its target relation to exist EARLIER in the apply sequence, so this file is NOT
-- self-contained: applying it greenfield into an empty schema fails on the missing wallets
-- relation. That is the documented expected outcome, asserted by
-- test/migration-integrity.test.ts alongside the other prerequisite-bound slices.

-- The create-time row for SEND_EXTERNAL. It is simultaneously the operation record and the
-- Idempotency record: a row whose completed_at IS NULL is the in-progress
-- marker, and its insert -- not any application-level read -- is the concurrency arbiter for
-- both idempotency and the one-in-flight-per-wallet rule.
--
-- status vocabulary is the frozen SEND_EXTERNAL_STATES
-- (generic-node-contracts/src/operations/states.contract.ts); parity is asserted by
-- test/send-external-create-parity.test.ts. This slice only ever writes 'CREATED'.
--
-- There is deliberately NO send expiry column here. The only
-- authoritative SEND_EXTERNAL redemption expiry is the signed inner expiry__unix_time_secs
-- byte-frozen inside external_send_sign_intents.inner_preimage_text, materialized once at
-- sign-intent formation with SEND_REDEMPTION_WINDOW_SECS. The RECEIVE payer-code expiry
-- is a different fixture and is never derived from or into this table.
CREATE TABLE send_operations (
  operation_id uuid PRIMARY KEY,
  implementer_id uuid NOT NULL,
  node_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind = 'SEND_EXTERNAL'),
  status text NOT NULL CHECK (status IN ('CREATED', 'APPROVED', 'AWAITING_REDEMPTION', 'EXTERNAL_SEND_LANDED', 'REJECTED', 'NEEDS_ATTENTION')),
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  attention_required boolean NOT NULL DEFAULT false,
  -- SEND_EXTERNAL carries a formation state at all times; 'APPROVAL_PENDING'
  -- is the only value legal while CREATED, which is the only status this slice writes.
  formation_state text NOT NULL CHECK (formation_state IN ('APPROVAL_PENDING', 'APPROVED_UNSIGNED', 'SIGNING_CLAIMED', 'PARTIAL_PERSISTED', 'PARTIAL_DELIVERED')),
  -- The idempotency scope is the FULL tuple
  -- (implementer_id, HTTP method, canonical route, idempotency_key). Never key-only.
  http_method text NOT NULL CHECK (http_method = 'POST'),
  route text NOT NULL CHECK (route = '/v1/external-sends'),
  idempotency_key text NOT NULL
    CHECK (char_length(idempotency_key) BETWEEN 16 AND 255 AND idempotency_key ~ '^[[:print:]]+$'),
  -- A SHA-256 hash of the exact validated canonical request object.
  -- Same key + different hash is 409 idempotency_key_reused, never a silent replay of a
  -- different request's operation.
  request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  -- The four immutable economic fields. Nothing after the create DB-TX may rewrite any of
  -- them; the guard below is structural, which is what makes the approval-tuple
  -- rebuild-and-compare check meaningful.
  source_wallet_id uuid NOT NULL REFERENCES wallets (id),
  destination_address text NOT NULL
    CHECK (length(destination_address) = 44 AND destination_address ~ '^[A-Za-z0-9_-]{43}=$'),
  amount_zkz text NOT NULL,
  references_operation_id uuid,
  -- Advisory, unsigned, never parsed into business semantics.
  client_reference text,
  description text,
  created_at timestamptz NOT NULL DEFAULT now(),
  -- The status and exact response body produced by the first completed
  -- execution. completed_at IS NULL is precisely the in-progress marker.
  completed_at timestamptz,
  response_status integer,
  response_body text,
  -- The canonical ZKZ amount bound is enforced at rest, never by application
  -- validation alone. Numeric positivity (amount_zkz::numeric > 0), NOT string positivity:
  -- the forms '0.0', '0.00' and '0.' followed by 32 zeros all match the regex and are
  -- distinct from '0' as strings while being mathematically zero. The predicate text is
  -- bound to the frozen generic-node-contracts ZKZ_AMOUNT_CHECK_DOMAINS entry by
  -- test/send-external-create-parity.test.ts under the single documented VALUE ->
  -- amount_zkz substitution, so the two cannot drift. A column CHECK rather than a CREATE
  -- DOMAIN deliberately: a domain of that name is declared by a sibling operation slice and
  -- two slices cannot both create it.
  CONSTRAINT send_operations_amount_positive
    CHECK (amount_zkz ~ '^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$' AND amount_zkz::numeric > 0),
  CONSTRAINT send_operations_completion_together
    CHECK ((completed_at IS NULL) = (response_status IS NULL)
           AND (completed_at IS NULL) = (response_body IS NULL)),
  -- CREATED pairs with APPROVAL_PENDING and nothing else.
  CONSTRAINT send_operations_created_is_approval_pending
    CHECK (status <> 'CREATED' OR formation_state = 'APPROVAL_PENDING'),
  -- The create response carries attention_required false; a CREATED
  -- operation has no attention condition to carry.
  CONSTRAINT send_operations_created_needs_no_attention
    CHECK (status <> 'CREATED' OR attention_required = false),
  -- Idempotency scope, structural. This is the concurrency arbiter for
  -- concurrent first use of one key: exactly one inserter wins, every follower gets 23505.
  -- kind, http_method and route are each pinned to one value by the CHECKs above, so this
  -- constraint is exactly the operations UNIQUE (implementer_id, kind, idempotency_key).
  CONSTRAINT send_operations_idempotency_scope
    UNIQUE (implementer_id, http_method, route, idempotency_key)
);

-- The one-in-flight-per-wallet rule, structural: one in-flight transaction per wallet. A second unsettled
-- external send from the same source wallet is rejected by the database with
-- unique_violation, not by an application read that races the insert that follows it.
--
-- The predicate names the TERMINAL states and excludes them, rather than listing the
-- non-terminal states positively. That direction is the whole safety property: a partial
-- index does not index a row its predicate excludes, so under a positive non-terminal
-- allowlist a status added to the frozen vocabulary would be indexed by nothing, hold no
-- wallet, and silently ADMIT the next send. Excluding the terminal pair instead makes an
-- unknown status unsettled by construction, so it blocks (fail-closed). status is NOT NULL,
-- so NOT IN carries no three-valued-logic hole. NEEDS_ATTENTION is non-terminal by
-- The source lease remains held there, so it holds the wallet.
CREATE UNIQUE INDEX send_operations_one_unsettled_per_source_wallet
  ON send_operations (source_wallet_id)
  WHERE status NOT IN ('EXTERNAL_SEND_LANDED', 'REJECTED');

-- Every operation has exactly one artifact of its own kind, and
-- artifact rows are insert-only. operation_id UNIQUE is the "exactly one" half; the trigger
-- below is the insert-only half.
--
-- Storage column signing_key_id maps to wire field key_id exactly. The
-- API MUST NOT expose a second aliased field.
CREATE TABLE send_operation_expected_artifacts (
  artifact_id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES send_operations (operation_id),
  purpose text NOT NULL CHECK (purpose IN ('zp-receive-expected-v1', 'zp-move-internal-expected-v1', 'zp-send-external-expected-v1')),
  canonical_version integer NOT NULL CHECK (canonical_version = 1),
  signing_key_id uuid NOT NULL,
  preimage_text text NOT NULL CHECK (octet_length(preimage_text) > 0),
  preimage_sha256 text NOT NULL CHECK (preimage_sha256 ~ '^[0-9a-f]{64}$'),
  signature text NOT NULL CHECK (length(signature) = 88 AND signature ~ '^[A-Za-z0-9_-]{86}==$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  -- This slice's operations are exactly SEND_EXTERNAL, so the one artifact they may
  -- carry is exactly the send purpose. The wider three-purpose vocabulary is kept verbatim
  -- from the expected-artifacts relation so the frozen column definition does not drift, and narrowed here.
  CONSTRAINT send_operation_expected_artifacts_purpose_is_send
    CHECK (purpose = 'zp-send-external-expected-v1')
);

-- Artifact rows are insert-only. A signed byte surface that can be
-- updated in place is not evidence of anything.
CREATE FUNCTION send_reject_artifact_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'SEND_ARTIFACT_INSERT_ONLY';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER send_operation_expected_artifacts_insert_only
  BEFORE UPDATE OR DELETE ON send_operation_expected_artifacts
  FOR EACH ROW EXECUTE FUNCTION send_reject_artifact_mutation();

-- The parent's stated exit criterion: approval cannot change source, destination, amount, or
-- reference. This slice establishes that immutability structurally, so no later code path --
-- approval, formation, reconciliation, or an operator tool -- can rewrite an economic field
-- the create-time artifact already signed. row_version, status, formation_state,
-- attention_required and the idempotency response columns remain mutable; they are the
-- fields later slices legitimately advance.
CREATE FUNCTION send_reject_economic_field_mutation() RETURNS trigger AS $$
BEGIN
  IF NEW.source_wallet_id IS DISTINCT FROM OLD.source_wallet_id
     OR NEW.destination_address IS DISTINCT FROM OLD.destination_address
     OR NEW.amount_zkz IS DISTINCT FROM OLD.amount_zkz
     OR NEW.references_operation_id IS DISTINCT FROM OLD.references_operation_id
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.implementer_id IS DISTINCT FROM OLD.implementer_id
     OR NEW.node_id IS DISTINCT FROM OLD.node_id
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.request_sha256 IS DISTINCT FROM OLD.request_sha256 THEN
    RAISE EXCEPTION 'SEND_IMMUTABLE_FIELD_REJECTED';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER send_operations_immutable_fields_guard
  BEFORE UPDATE ON send_operations
  FOR EACH ROW EXECUTE FUNCTION send_reject_economic_field_mutation();
