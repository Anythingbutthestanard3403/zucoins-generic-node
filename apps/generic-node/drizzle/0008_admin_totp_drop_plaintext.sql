-- ZTR-1134: drop plaintext TOTP column when safe.
--
-- Fresh / already-migrated nodes have no plaintext rows, so DROP runs here.
-- Nodes that still hold base32 after 0007 keep the column until boot backfill
-- (migrateTotpSecretsAtRest) seals every row and issues the same DROP.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM information_schema.columns
     WHERE table_schema = current_schema()
       AND table_name = 'admin_operators'
       AND column_name = 'totp_secret_base32'
  ) AND NOT EXISTS (
    SELECT 1
      FROM admin_operators
     WHERE totp_secret_base32 IS NOT NULL
       AND length(btrim(totp_secret_base32)) > 0
  ) THEN
    ALTER TABLE admin_operators DROP COLUMN totp_secret_base32;
  END IF;
END $$;
