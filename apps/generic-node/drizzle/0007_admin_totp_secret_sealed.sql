-- ZTR-1134: add sealed TOTP envelope column alongside legacy plaintext.
-- Plaintext → sealed backfill runs after vault unlock (needs VAULT_MASTER_KEY root).
-- 0008 drops the plaintext column only when no residual plaintext remains.

ALTER TABLE admin_operators
  ADD COLUMN IF NOT EXISTS totp_secret_sealed text;
