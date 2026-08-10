-- Byte-immutability guards for the three transaction-material tables (doc 04 §9 /
-- 04:760-767). The frozen CREATE TABLE surface is transaction-material.sql (pack
-- index of that slice); this append-only slice installs the BEFORE UPDATE/DELETE/
-- TRUNCATE triggers the contract inventories as schema-apply obligations.
-- Appended so earlier money-pack version numbers stay stable. Never renumber prior slices.

-- external_send_sign_intents: insert-only (04:760). No column is updatable or deletable.
CREATE FUNCTION external_send_sign_intents_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'EXTERNAL_SEND_SIGN_INTENTS_INSERT_ONLY';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER external_send_sign_intents_insert_only
  BEFORE UPDATE OR DELETE ON external_send_sign_intents
  FOR EACH ROW EXECUTE FUNCTION external_send_sign_intents_reject_mutation();

CREATE TRIGGER external_send_sign_intents_no_truncate
  BEFORE TRUNCATE ON external_send_sign_intents
  FOR EACH STATEMENT EXECUTE FUNCTION external_send_sign_intents_reject_mutation();

-- operation_transactions: insert, then one-way completion only (04:763-766).
-- Insert-time signed material is frozen; nullable completion columns may fill NULL→value
-- exactly once and never overwrite; attempt_phase advances with those fills (phase CHECKs
-- keep the ladder consistent). Rows are never deleted.
CREATE FUNCTION operation_transactions_reject_byte_mutation() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'OPERATION_TRANSACTIONS_BYTE_IMMUTABLE';
  END IF;

  IF NEW.operation_id IS DISTINCT FROM OLD.operation_id
     OR NEW.attempt_no IS DISTINCT FROM OLD.attempt_no
     OR NEW.inner_preimage_text IS DISTINCT FROM OLD.inner_preimage_text
     OR NEW.inner_sha256 IS DISTINCT FROM OLD.inner_sha256
     OR NEW.formed_at IS DISTINCT FROM OLD.formed_at THEN
    RAISE EXCEPTION 'OPERATION_TRANSACTIONS_BYTE_IMMUTABLE';
  END IF;

  IF (OLD.step_1_signature IS NOT NULL
        AND NEW.step_1_signature IS DISTINCT FROM OLD.step_1_signature)
     OR (OLD.step_2_preimage_text IS NOT NULL
        AND NEW.step_2_preimage_text IS DISTINCT FROM OLD.step_2_preimage_text)
     OR (OLD.step_2_preimage_sha256 IS NOT NULL
        AND NEW.step_2_preimage_sha256 IS DISTINCT FROM OLD.step_2_preimage_sha256)
     OR (OLD.step_2_signature IS NOT NULL
        AND NEW.step_2_signature IS DISTINCT FROM OLD.step_2_signature)
     OR (OLD.completed_transaction_text IS NOT NULL
        AND NEW.completed_transaction_text IS DISTINCT FROM OLD.completed_transaction_text)
     OR (OLD.completed_transaction_sha256 IS NOT NULL
        AND NEW.completed_transaction_sha256 IS DISTINCT FROM OLD.completed_transaction_sha256)
     OR (OLD.settled_at IS NOT NULL
        AND NEW.settled_at IS DISTINCT FROM OLD.settled_at) THEN
    RAISE EXCEPTION 'OPERATION_TRANSACTIONS_BYTE_IMMUTABLE';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER operation_transactions_byte_immutability
  BEFORE UPDATE OR DELETE ON operation_transactions
  FOR EACH ROW EXECUTE FUNCTION operation_transactions_reject_byte_mutation();

CREATE TRIGGER operation_transactions_no_truncate
  BEFORE TRUNCATE ON operation_transactions
  FOR EACH STATEMENT EXECUTE FUNCTION operation_transactions_reject_byte_mutation();

-- external_send_partials: byte-immutable except delivery counters (04:766-767).
-- Recovery may update only first_delivered_at / last_redelivered_at / redelivery_count.
CREATE FUNCTION external_send_partials_reject_byte_mutation() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'EXTERNAL_SEND_PARTIALS_BYTE_IMMUTABLE';
  END IF;

  IF NEW.operation_id IS DISTINCT FROM OLD.operation_id
     OR NEW.approval_id IS DISTINCT FROM OLD.approval_id
     OR NEW.inner_sha256 IS DISTINCT FROM OLD.inner_sha256
     OR NEW.step_1_signature IS DISTINCT FROM OLD.step_1_signature
     OR NEW.transfer_code_text IS DISTINCT FROM OLD.transfer_code_text
     OR NEW.transfer_code_sha256 IS DISTINCT FROM OLD.transfer_code_sha256
     OR NEW.persisted_at IS DISTINCT FROM OLD.persisted_at THEN
    RAISE EXCEPTION 'EXTERNAL_SEND_PARTIALS_BYTE_IMMUTABLE';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER external_send_partials_byte_immutability
  BEFORE UPDATE OR DELETE ON external_send_partials
  FOR EACH ROW EXECUTE FUNCTION external_send_partials_reject_byte_mutation();

CREATE TRIGGER external_send_partials_no_truncate
  BEFORE TRUNCATE ON external_send_partials
  FOR EACH STATEMENT EXECUTE FUNCTION external_send_partials_reject_byte_mutation();
