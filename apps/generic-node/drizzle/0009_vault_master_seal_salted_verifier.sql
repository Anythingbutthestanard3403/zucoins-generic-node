-- ZTR-1171: replace bare SHA-256(master) oracle with salted PBKDF2 verifier (96 hex = salt||dk).
-- Existing 64-hex rows are wiped (phase reset is not automatic — operator re-runs show-once
-- or boots with VAULT_MASTER_KEY). Prefer empty over a cheap confirmation oracle.

ALTER TABLE operator_vault_master_seal
  DROP CONSTRAINT IF EXISTS operator_vault_master_seal_fp_chk;

-- Drop legacy oracle rows; they cannot be upgraded without the plaintext master.
DELETE FROM operator_vault_master_seal
 WHERE key_fingerprint_hex !~ '^[0-9a-f]{96}$';

ALTER TABLE operator_vault_master_seal
  ADD CONSTRAINT operator_vault_master_seal_fp_chk
    CHECK (key_fingerprint_hex ~ '^[0-9a-f]{96}$');
