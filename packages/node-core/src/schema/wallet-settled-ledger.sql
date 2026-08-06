-- The canonical wallet ledger: the ledger is
-- verbatim and permanent: the exact settled transaction text is retained forever;
-- proof-access expiry revokes access, it does not delete ledger bytes; evidence is retention
-- and byte-round-trip tests). Exact preimages and transactions are stored as text/bytes,
-- never reconstructed from JSONB. Bound to the reference scalar checks, operations /
-- operation_wallets, operation_transactions and operation_verifications. Retention:
-- "canonical wallet ledger | permanent, verbatim | append-only". Mandatory database tests (#7 exact
-- transaction bytes survive round-trip, #8 JSONB absent from authoritative-byte columns, #15
-- append-only triggers reject update/delete). Canonical transaction containers are
-- retained verbatim forever.
-- (LANDED_EXACT / LANDED_COMPLETE_PATH). the ZKZ ticker rule (ZKZ is the only ticker), the byte-exact signing rule
-- The byte-exact signing rule (byte-exact signing payloads).
--
-- PROVISIONAL schema contract -- deliberately NOT declared frozen. 04
-- The retention matrix names this table only as a row and freezes no CREATE TABLE for it, so
-- there is no frozen DDL to transcribe and no drift gate can pin this file to a
-- frozen shape. The shape below is implementer-designed from the canonical-container
-- retention rule and the transaction relations; if a different shape is later frozen in the
-- retention matrix, this file yields to
-- it. Authoring that freeze is an open spec defect and is not
-- settled here. Like the other contracts in this directory the file is contract text: it is
-- executed only by the schema-apply phase against a live database; nothing in this package runs
-- it. Every invariant below is inventoried in wallet-settled-ledger.contract.ts, censused by
-- test/wallet-settled-ledger.census.test.ts, and exercised against a real PostgreSQL in
-- test/wallet-settled-ledger.pg.test.ts.
--
-- Scope: the canonical per-(wallet, landed operation) settled ledger. Insert-only and
-- permanent -- one immutable row per wallet leg of an independently-verified landed
-- operation, holding the exact settled SplitChain transaction text verbatim so a read returns
-- the settled bytes byte-for-byte. It is NOT operation_transactions (one row per
-- operation attempt, no wallet grain) and NOT lineage_path_bodies (which carries untrusted
-- intermediate hops); this is the trusted, per-wallet, landed-only projection. A MOVE_INTERNAL
-- lands two legs -- SOURCE and DESTINATION -- under one settled transaction, so two rows share
-- one settled body; RECEIVE_EXTERNAL and SEND_EXTERNAL land exactly one. There is deliberately
-- no running-balance column and no row_version: balances are DERIVED by re-reading the
-- verbatim bytes, never materialized here.
--
-- ROLE VOCABULARY RECONCILIATION (a judgement call,
-- not a transcription). Three role columns already exist in this schema:
--   * operation_wallets.operation_role  -- text CHECK IN ('RECEIVER','SOURCE','DESTINATION')
--   * verification_ack_wallet_evidence.evidence_role
--                                       -- text CHECK IN ('SOURCE','RECEIVER','DESTINATION')
--   * lineage_path_bodies.wallet_role   -- text CHECK IN ('sender','receiver')
-- The first two describe this node's OPERATION participants and already agree on one uppercase
-- three-value vocabulary. The third describes the two parties of an untrusted intermediate hop
-- inside a proof path -- a different object at a different grain -- and is deliberately not
-- adopted. This ledger's rows are per (operation, wallet), which is exactly operation_wallets'
-- grain, so it takes that column's vocabulary verbatim AND its column NAME, operation_role.
-- Calling the column wallet_role while holding uppercase values would put two columns of the
-- same name in one database with contradictory CHECK sets -- strictly worse than the two
-- spellings that exist today. No fourth spelling is minted. The absence of 'SENDER' is
-- correct rather than an omission: the debited wallet of a SEND_EXTERNAL is its SOURCE, the
-- same role MOVE_INTERNAL debits. FOREIGN KEY (operation_id, wallet_id) REFERENCES
-- operation_wallets proves the wallet is a recorded participant; the BEFORE INSERT gate
-- additionally binds NEW.operation_role to that participant's operation_role and
-- NEW.wallet_public_key to wallets.public_key for NEW.wallet_id, so a swapped-role or
-- wrong-pubkey row cannot permanently mis-label a leg.
--
-- ZKZ AMOUNT DOMAIN. The unbounded zkz_amount_text domain is RETIRED and MUST NOT be
-- attached to a new column (CONVENTIONS.md, "ZKZ amount CHECK domains"). amount_zkz
-- here carries the same column role as operations.amount_zkz -- a per-operation ZKZ amount --
-- so it binds the strictly-positive zkz_amount_positive_text domain. A settled leg that moved
-- numerically zero ZKZ is a money-path defect, not a ledger entry.

-- Reference scalar checks (the domains this table's columns use). sha256_hex and
-- padded_base64url_pubkey are verbatim; the amount domain is
-- zkz_amount_positive_text, byte-identical to generic-node-contracts
-- ZKZ_AMOUNT_CHECK_DOMAINS.zkz_amount_positive_text:

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

CREATE DOMAIN zkz_amount_positive_text AS text
  CHECK (VALUE ~ '^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$' AND VALUE::numeric > 0);

-- The canonical per-(wallet, landed operation) settled ledger. Surrogate id primary key
-- with wallet_id a non-unique foreign key,
-- so a wallet accrues a new immutable row per landed operation rather than mutating one:

CREATE TABLE wallet_settled_ledger (
  id uuid PRIMARY KEY,
  wallet_id uuid NOT NULL REFERENCES wallets(id),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  operation_id uuid NOT NULL REFERENCES operations(id),
  attempt_no integer NOT NULL CHECK (attempt_no = 1),
  operation_role text NOT NULL CHECK (operation_role IN
    ('RECEIVER','SOURCE','DESTINATION')),
  amount_zkz zkz_amount_positive_text NOT NULL,
  settled_transaction_text text NOT NULL
    CHECK (octet_length(settled_transaction_text) > 0),
  settled_transaction_sha256 sha256_hex NOT NULL,
  landing_proof_id uuid NOT NULL,
  landing_verdict text NOT NULL CHECK (landing_verdict IN
    ('LANDED_EXACT','LANDED_COMPLETE_PATH')),
  settled_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT wallet_settled_ledger_wallet_signature_uniq
    UNIQUE (wallet_public_key, settled_transaction_sha256),
  CONSTRAINT wallet_settled_ledger_one_row_per_role_uniq
    UNIQUE (operation_id, attempt_no, operation_role),
  FOREIGN KEY (operation_id, attempt_no)
    REFERENCES operation_transactions(operation_id, attempt_no),
  FOREIGN KEY (operation_id, wallet_id)
    REFERENCES operation_wallets(operation_id, wallet_id)
);

-- Landed-verdict, identity-binding and verbatim-copy append gate. Five conditions the row's
-- own columns and foreign keys cannot fully express:
--   1. the referenced attempt has actually reached SETTLED_BODY_PERSISTED -- the FK proves the
--      attempt row exists, not that it settled;
--   2. the ledger's settled bytes ARE the attempt body's bytes, compared as bytes and not under a
--      collation, so a re-parsed or re-serialized copy is rejected at INSERT (golden
--      rule 3);
--   3. independent landing verification has already accepted the operation -- a bare
--      operation_transactions.settled_at write or a gateway acknowledgement is not enough
--      (operation_verifications, verdict VERIFIED, carrying this landing proof);
--   4. NEW.operation_role equals operation_wallets.operation_role for (operation_id, wallet_id)
--      -- the participant FK only proves participation, not that the leg label matches;
--   5. NEW.wallet_public_key equals wallets.public_key for wallet_id -- the wallet_id FK does
--      not bind the parallel pubkey column that uniqueness and export key off.
-- Identity checks only fire when the referenced row exists so a missing participant/wallet
-- still surfaces as the FK 23503 the non-participant drill asserts, not a gate message.
CREATE FUNCTION wallet_settled_ledger_assert_landed_verbatim() RETURNS trigger AS $$
DECLARE
  tx operation_transactions%ROWTYPE;
  strict_role text;
  strict_pk text;
BEGIN
  SELECT * INTO tx
    FROM operation_transactions
    WHERE operation_id = NEW.operation_id AND attempt_no = NEW.attempt_no;

  IF NOT FOUND OR tx.attempt_phase <> 'SETTLED_BODY_PERSISTED' THEN
    RAISE EXCEPTION 'WALLET_SETTLED_LEDGER_NOT_SETTLED' USING ERRCODE = '23514';
  END IF;

  IF convert_to(NEW.settled_transaction_text, 'UTF8')
       IS DISTINCT FROM convert_to(tx.completed_transaction_text, 'UTF8')
     OR NEW.settled_transaction_sha256 IS DISTINCT FROM tx.completed_transaction_sha256
     OR NEW.settled_at IS DISTINCT FROM tx.settled_at THEN
    RAISE EXCEPTION 'WALLET_SETTLED_LEDGER_NOT_VERBATIM' USING ERRCODE = '23514';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM operation_verifications v
      WHERE v.operation_id = NEW.operation_id
        AND v.verdict = 'VERIFIED'
        AND v.landing_proof_id = NEW.landing_proof_id
  ) THEN
    RAISE EXCEPTION 'WALLET_SETTLED_LEDGER_NOT_LANDED' USING ERRCODE = '23514';
  END IF;

  SELECT operation_role INTO strict_role
    FROM operation_wallets
    WHERE operation_id = NEW.operation_id AND wallet_id = NEW.wallet_id;
  IF FOUND AND strict_role IS DISTINCT FROM NEW.operation_role THEN
    RAISE EXCEPTION 'WALLET_SETTLED_LEDGER_ROLE_MISMATCH' USING ERRCODE = '23514';
  END IF;

  SELECT public_key INTO strict_pk
    FROM wallets
    WHERE id = NEW.wallet_id;
  IF FOUND
     AND convert_to(strict_pk, 'UTF8')
         IS DISTINCT FROM convert_to(NEW.wallet_public_key, 'UTF8') THEN
    RAISE EXCEPTION 'WALLET_SETTLED_LEDGER_PUBKEY_MISMATCH' USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER wallet_settled_ledger_landed_verbatim
  BEFORE INSERT ON wallet_settled_ledger
  FOR EACH ROW EXECUTE FUNCTION wallet_settled_ledger_assert_landed_verbatim();

-- Insert-only (append-only; proof-access expiry revokes access, it does not
-- delete ledger bytes). Same construction as external_send_landing_records. The package-wide
-- installs the package-wide byte-immutability and retention regime over this
-- table; this pair is the slice-local floor, so the property holds and is provable from the
-- moment the table exists rather than only once that slice lands.
CREATE FUNCTION wallet_settled_ledger_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'WALLET_SETTLED_LEDGER_INSERT_ONLY';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER wallet_settled_ledger_insert_only
  BEFORE UPDATE OR DELETE ON wallet_settled_ledger
  FOR EACH ROW EXECUTE FUNCTION wallet_settled_ledger_reject_mutation();

CREATE TRIGGER wallet_settled_ledger_no_truncate
  BEFORE TRUNCATE ON wallet_settled_ledger
  FOR EACH STATEMENT EXECUTE FUNCTION wallet_settled_ledger_reject_mutation();
