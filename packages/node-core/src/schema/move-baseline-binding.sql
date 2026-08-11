-- Move baseline binding: operation_observation_bindings and move_observation_evidence.
-- operation_expected_artifacts is owned solely by expected-artifacts.sql (one-slice-one-contract);
-- this slice must not re-CREATE it. Recovery axiom: persist before crossing an irreversible
-- boundary; the exact preimage precedes signing.
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database and by test/move-baseline-binding.pg.test.ts, which
-- applies it to a hermetic scratch schema. Every invariant below is inventoried in
-- move-baseline-binding.contract.ts.
--
-- Self-containment: this slice applies greenfield standalone for the binding/evidence tables, so it
-- re-declares the reference domains its columns use and carries out-of-slice references as bare
-- uuid columns with no REFERENCES clause -- the custody-eligibility.sql pattern (wallets.node_id).
-- Deferred references: operations(id) and every gateway_observations(id) edge (observation FKs are
-- added after the observation tables exist). The schema-apply assembly adds them by ALTER TABLE;
-- the contract file inventories them as deferred so the omission is declared, not silent.
--
-- Table-level CHECK/UNIQUE constraints carry explicit names so a drill can assert WHICH
-- constraint rejected an insert rather than only that something did.

-- Reference scalar domains (verbatim; the three this slice's columns use):

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

CREATE DOMAIN padded_base64url_signature AS text
  CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');

-- operation_expected_artifacts: owned by expected-artifacts.sql (not re-CREATED here).

-- Binding table. PRIMARY KEY (operation_id, evidence_role) makes each role bindable
-- exactly once per operation; UNIQUE (operation_id, observation_id) stops one observation row
-- from being reused under two roles of the same operation.

CREATE TABLE operation_observation_bindings (
  operation_id uuid NOT NULL,
  observation_id uuid NOT NULL,
  evidence_role text NOT NULL CONSTRAINT operation_observation_bindings_evidence_role_check
    CHECK (evidence_role IN (
      'SOURCE_T0','SOURCE_TERMINAL','RECEIVER_T0','RECEIVER_TERMINAL',
      'DESTINATION_T0','DESTINATION_TERMINAL','COUNTERPARTY_CONFIRMATION'
    )),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  PRIMARY KEY (operation_id, evidence_role),
  CONSTRAINT operation_observation_bindings_operation_observation_key
    UNIQUE (operation_id, observation_id)
);

-- Move evidence. Both T0s are NOT NULL from this slice's write onward (
-- "for a move, source and destination T0 are mandatory before signing"); the terminal pair and
-- verified_at stay NULL until landing verification, which the paired CHECK enforces as an
-- all-or-nothing set. The distinct-T0 CHECK targets the observation ROW ID, so two wallets whose
-- projections are byte-identical (both genesis: S0="", P0="", B0="0") still require two genuinely
-- distinct observation rows.

CREATE TABLE move_observation_evidence (
  operation_id uuid PRIMARY KEY,
  source_t0_observation_id uuid NOT NULL,
  destination_t0_observation_id uuid NOT NULL,
  source_terminal_observation_id uuid,
  destination_terminal_observation_id uuid,
  verified_at timestamptz,
  CONSTRAINT move_observation_evidence_terminal_set_together CHECK (
    (source_terminal_observation_id IS NULL
      AND destination_terminal_observation_id IS NULL
      AND verified_at IS NULL)
    OR
    (source_terminal_observation_id IS NOT NULL
      AND destination_terminal_observation_id IS NOT NULL
      AND verified_at IS NOT NULL)
  ),
  CONSTRAINT move_observation_evidence_distinct_t0
    CHECK (source_t0_observation_id <> destination_t0_observation_id),
  CONSTRAINT move_observation_evidence_distinct_terminal
    CHECK (source_terminal_observation_id IS NULL
      OR source_terminal_observation_id <> destination_terminal_observation_id)
);

