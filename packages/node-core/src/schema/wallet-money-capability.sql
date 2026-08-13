-- Wallet money-capability columns (ZTR-1267).
--
-- Per-wallet allow flags for external receive, external send, and internal move,
-- plus a denormalised money_mode preset kept consistent via CHECK.
-- Pure column extension on wallets (custody-eligibility.sql). That early pack
-- slice's schema_migrations sql_sha256 must not change, so columns ship here as
-- appended ALTER - never by editing the CREATE TABLE.
--
-- Defaults + backfill are FULL (all three allows true) so existing deployments
-- keep today's behaviour until an operator reconfigures via admin.
-- New mints also write FULL explicitly (mint path + column defaults).
--
-- Pack position: appended after custody-eligibility; never renumber prior slices.

ALTER TABLE wallets
  ADD COLUMN IF NOT EXISTS allow_external_receive boolean NOT NULL DEFAULT true;

ALTER TABLE wallets
  ADD COLUMN IF NOT EXISTS allow_external_send boolean NOT NULL DEFAULT true;

ALTER TABLE wallets
  ADD COLUMN IF NOT EXISTS allow_internal_move boolean NOT NULL DEFAULT true;

ALTER TABLE wallets
  ADD COLUMN IF NOT EXISTS money_mode text NOT NULL DEFAULT 'FULL';

ALTER TABLE wallets
  ADD COLUMN IF NOT EXISTS row_version bigint NOT NULL DEFAULT 1;

-- Converge already-applied rows (IF NOT EXISTS leaves prior rows with defaults;
-- explicit UPDATE keeps intent visible for audits / fix-forward evidence).
UPDATE wallets
   SET allow_external_receive = true,
       allow_external_send = true,
       allow_internal_move = true,
       money_mode = 'FULL'
 WHERE allow_external_receive IS DISTINCT FROM true
    OR allow_external_send IS DISTINCT FROM true
    OR allow_internal_move IS DISTINCT FROM true
    OR money_mode IS DISTINCT FROM 'FULL';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'wallets_money_mode_closed'
  ) THEN
    ALTER TABLE wallets
      ADD CONSTRAINT wallets_money_mode_closed
      CHECK (money_mode IN ('RECEIVE_ONLY', 'SEND_ONLY', 'INTERNAL_ONLY', 'FULL'));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'wallets_money_mode_flags_consistent'
  ) THEN
    ALTER TABLE wallets
      ADD CONSTRAINT wallets_money_mode_flags_consistent
      CHECK (
        (money_mode = 'RECEIVE_ONLY'
          AND allow_external_receive IS TRUE
          AND allow_external_send IS FALSE
          AND allow_internal_move IS TRUE)
        OR (money_mode = 'SEND_ONLY'
          AND allow_external_receive IS FALSE
          AND allow_external_send IS TRUE
          AND allow_internal_move IS TRUE)
        OR (money_mode = 'INTERNAL_ONLY'
          AND allow_external_receive IS FALSE
          AND allow_external_send IS FALSE
          AND allow_internal_move IS TRUE)
        OR (money_mode = 'FULL'
          AND allow_external_receive IS TRUE
          AND allow_external_send IS TRUE
          AND allow_internal_move IS TRUE)
      );
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'wallets_row_version_positive'
  ) THEN
    ALTER TABLE wallets
      ADD CONSTRAINT wallets_row_version_positive
      CHECK (row_version > 0);
  END IF;
END $$;
