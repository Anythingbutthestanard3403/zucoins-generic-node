-- The durable PROOF_CHANNEL proof-body intake store: the reference scalar domains, the
-- lineage_path_bodies body-column shape and source_kind, idempotency semantics, and the
-- bounded sighting counters (a sighting appends once and increments the counter, mirroring
-- the consecutive_repeat_count model). Candidate evidence grants no authority.
-- The byte-exact signing rule (byte-exact bodies).
-- Frozen schema contract. This file is contract text: it is
-- executed only by the schema-apply phase against a live database; nothing in this
-- package runs it. Every invariant below is inventoried in proof-body-store.contract.ts
-- and censused by test/proof-body-store.census.test.ts.
--
-- Scope: the durable PROOF_CHANNEL proof-body intake store that backs the
-- persistence logic (src/proof-body/persist.ts) over its frozen ProofBodyStore port
-- (src/proof-body/sql-store.ts is the driver-agnostic implementation). This RESOLVES
-- the observation-ledger.sql deferral of lineage_path_bodies FOR THE PROOF_CHANNEL
-- INTAKE PATH only: it materializes the lineage_path_bodies BODY-COLUMN SHAPE
-- (byte-faithful) for caller-supplied candidate bodies plus the request-scoped
-- bookkeeping the observation ledger does not model. The verifier's FK-bound
-- lineage_path_bodies assembly table (REFERENCES lineage_path_proofs, written by the
-- landing oracle) remains in the observation-verification / landing-oracle
-- lane and is deliberately NOT transcribed here: a candidate body exists BEFORE any
-- lineage_path_proof, so binding it to that FK would fabricate proof-path authority the
-- non-authority rule forbids. A verified candidate promotes into the verifier
-- table by verbatim byte copy (the byte-exact signing rule).
--
-- Non-authority: no table here carries a verdict, landing, lease, verified_at, or
-- promotion column. source_kind records provenance only and grants no authority
--. The sighting counters are mutable operational indexes, not evidence
-- Candidate rows are inert evidence the landing oracle later queries.

-- Reference scalar domains (verbatim; the three domains the body columns use).
-- b_amount is a role-relative absolute BALANCE, so it takes the balance domain, in
-- which '0' is legal - never the strictly-positive zkz_amount_positive_text, which would
-- reject a swept payer, a genesis row, or a landed payer partial.
-- The unbounded single zkz_amount_text domain is retired; the predicate below is
-- frozen in packages/generic-node-contracts (ZKZ_AMOUNT_CHECK_DOMAINS). See CONVENTIONS.md
-- "ZKZ amount CHECK domains" for why this file re-declares rather than references.

CREATE DOMAIN zkz_balance_text AS text
  CHECK (VALUE ~ '^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$');

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN padded_base64url_signature AS text
  CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');

-- The durable PROOF_CHANNEL candidate-body store. Columns path_proof_id ..
-- verification_manifest_sha256 are the lineage_path_bodies body-column shape,
-- byte-faithful (same domains, same CHECKs, same PK components), so a verified candidate
-- promotes into the verifier's lineage_path_bodies by verbatim copy (the byte-exact signing rule).
-- source_kind is pinned to the single value intake can produce: PROOF_CHANNEL is the only
-- caller-supplied provenance; EXPECTED_OPERATION / CANONICAL_LEDGER / FRESH_GATEWAY_HEAD
-- (the other three source_kind values) are node-derived and never arrive through
-- intake. Columns raw_bytes_sha256 .. persisted_at are the request-scoped intake
-- bookkeeping the observation ledger does not model; the ProofBodyStore port needs them and the frozen
-- lineage_path_bodies row must not carry them. tenant_id / operation_id / idempotency_key
-- are opaque request-scoped identifiers typed per the frozen port (text, not uuid): the
-- Cross-tenant isolation requires the idempotency ledger to key on the FULL (tenant_id,
-- operation_id, idempotency_key) tuple, never key-only, so a shared key across tenants
-- can never collide (cross-tenant isolation).
--
-- Candidate bodies are append-only evidence: rows are insert-only and never updated
-- (byte-exact capture, the byte-exact signing rule). The BEFORE UPDATE/DELETE guards enforcing that at
-- the engine level are installed below the table (mandatory database test 15).

CREATE TABLE proof_channel_candidate_bodies (
  path_proof_id uuid NOT NULL,
  path_index bigint NOT NULL CHECK (path_index >= 0),
  source_kind text NOT NULL CHECK (source_kind = 'PROOF_CHANNEL'),
  completed_transaction_text text NOT NULL,
  completed_transaction_sha256 sha256_hex NOT NULL,
  completed_transaction_octets bigint NOT NULL CHECK (completed_transaction_octets > 0),
  wallet_role text NOT NULL CHECK (wallet_role IN ('sender','receiver')),
  s_signature padded_base64url_signature NOT NULL,
  p_signature text NOT NULL CHECK
    (p_signature = '' OR p_signature ~ '^[A-Za-z0-9_-]{86}==$'),
  b_amount zkz_balance_text NOT NULL,
  inner_preimage_text text NOT NULL,
  inner_sha256 sha256_hex NOT NULL,
  step_1_signature padded_base64url_signature NOT NULL,
  step_2_signature padded_base64url_signature NOT NULL,
  verification_manifest_text text NOT NULL,
  verification_manifest_sha256 sha256_hex NOT NULL,
  raw_bytes_sha256 sha256_hex NOT NULL,
  tenant_id text NOT NULL,
  operation_id text NOT NULL,
  idempotency_key text NOT NULL,
  persisted_at timestamptz NOT NULL,
  PRIMARY KEY (path_proof_id, path_index),
  CONSTRAINT proof_channel_candidate_bodies_tenant_op_idem_key
    UNIQUE (tenant_id, operation_id, idempotency_key),
  CHECK (octet_length(completed_transaction_text) = completed_transaction_octets),
  CHECK (octet_length(inner_preimage_text) > 0)
);

CREATE INDEX proof_channel_candidate_bodies_operation_path_idx
  ON proof_channel_candidate_bodies(operation_id, path_index);
CREATE INDEX proof_channel_candidate_bodies_tenant_idx
  ON proof_channel_candidate_bodies(tenant_id);
CREATE INDEX proof_channel_candidate_bodies_tenant_role_idx
  ON proof_channel_candidate_bodies(tenant_id, wallet_role);
CREATE INDEX proof_channel_candidate_bodies_body_digest_idx
  ON proof_channel_candidate_bodies(raw_bytes_sha256);

-- Byte-immutability at the trigger level (mandatory database test 15: observation/event/
-- audit append-only triggers reject update and delete; retention: complete-path
-- bodies/manifests/adjudications are permanent and append-only; the byte-exact signing rule). This closes
-- the deferral this file previously carried, which left the guards to a later phase, and the
-- matching obligation in proof-body-store.contract.ts.
--
-- Application-level insert-only discipline is not the guarantee: the anti-forensics property
-- is that no connection -- including one holding the application role, and including the
-- retention path -- can rewrite or remove captured evidence bytes. Only an engine-level
-- BEFORE UPDATE/DELETE trigger states that. Proof-access expiry revokes ONE endpoint's
-- exposure (the endpoint's 410) and never reaches these rows, so the guard cannot break it.
--
-- The function is 04's reporting_reject_immutable_change transcribed VERBATIM, including its
-- '55000' ERRCODE -- the canonical append-only rejector, consumed rather than re-invented
-- under a second name. It is re-declared here for the same reason this file re-declares the
-- reference domains: each schema fragment applies greenfield standalone.
--
-- The two sighting counters below are deliberately NOT guarded: the data model classifies cursor
-- counters as mutable operational indexes, not evidence, and the +1 UPSERT increment is
-- their one sanctioned mutation.

CREATE FUNCTION reporting_reject_immutable_change()
RETURNS trigger LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER proof_channel_candidate_bodies_no_update
  BEFORE UPDATE ON proof_channel_candidate_bodies
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER proof_channel_candidate_bodies_no_delete
  BEFORE DELETE ON proof_channel_candidate_bodies
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

-- TRUNCATE never fires a row-level DELETE trigger, so the two guards above would leave the
-- whole evidence table removable in one statement. The statement-level BEFORE TRUNCATE guard
-- closes that bypass; without it "append-only" is only true row by row.
CREATE TRIGGER proof_channel_candidate_bodies_no_truncate
  BEFORE TRUNCATE ON proof_channel_candidate_bodies
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();

-- Bounded sighting COUNTER (the wallet_observation_cursors.consecutive_repeat_count
-- model: a sighting appends once and increments the counter). One row per slot
-- and one row per tenant: storage is bounded by the live slot/tenant cardinality, never
-- by the number of duplicate/collision/role-conflict sightings -- which is the
-- DoS the append-ledger risked. countSightingsBySlot / countSightingsByTenant read these
-- counters; each sighting is one idempotent-shaped UPSERT increment (first sighting
-- inserts count 1, "appends once"; each later sighting increments). The application
-- enforces the fail-closed caps MAX_SIGHTINGS_PER_BODY = 100 and
-- MAX_SIGHTINGS_PER_TENANT = 50000 by reading the counter BEFORE the increment
-- (persist.ts sightingCapViolation). Counters are mutable operational indexes, not
-- evidence: the UPSERT increment is the ONLY sanctioned update in this file.
-- Information-loss tradeoff: these counters record totals only, never the frozen
-- ProofBodySighting is_duplicate/is_conflict kind (persist.ts still surfaces that
-- reason synchronously at decision time); durable per-kind forensics is a named
-- landing-oracle follow-up, not a silent drop (see proof-body-store.contract.ts).

CREATE TABLE proof_body_slot_sighting_counters (
  path_proof_id uuid NOT NULL,
  path_index bigint NOT NULL CHECK (path_index >= 0),
  sighting_count bigint NOT NULL DEFAULT 0 CHECK (sighting_count >= 0),
  PRIMARY KEY (path_proof_id, path_index)
);

CREATE TABLE proof_body_tenant_sighting_counters (
  tenant_id text NOT NULL,
  sighting_count bigint NOT NULL DEFAULT 0 CHECK (sighting_count >= 0),
  PRIMARY KEY (tenant_id)
);
