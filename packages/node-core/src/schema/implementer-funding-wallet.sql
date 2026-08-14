-- Implementer funding-wallet pin (ZTR-1287).
--
-- Per-integration reserve/proof wallet id. NULL means "use the node-wide default"
-- stored in node_settings under integration.default_funding_wallet_id.
-- This is NOT a send/source pin: external sends stay omit-source / worker-pool.
--
-- Pure column extension on implementers (node-implementer-registry / reporting
-- 0000). That CREATE TABLE is immutable pack history - never edit it; columns
-- ship here as appended ALTER only.
--
-- FK target wallets is created by custody-eligibility far earlier in the pack.
-- ON DELETE RESTRICT: fail closed - cannot drop a wallet still referenced as a
-- funding pin (explicit clear/reattach first).
--
-- Pack position: after wallet-money-capability-lease-guard; never renumber prior slices.

DO $implementer_funding_wallet$
BEGIN
  IF to_regclass('implementers') IS NULL THEN
    RAISE EXCEPTION 'implementer-funding-wallet requires implementers';
  END IF;
  IF to_regclass('wallets') IS NULL THEN
    RAISE EXCEPTION 'implementer-funding-wallet requires wallets (custody-eligibility)';
  END IF;
END
$implementer_funding_wallet$;

ALTER TABLE implementers
  ADD COLUMN IF NOT EXISTS funding_wallet_id uuid NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'implementers_funding_wallet_id_fkey'
  ) THEN
    ALTER TABLE implementers
      ADD CONSTRAINT implementers_funding_wallet_id_fkey
      FOREIGN KEY (funding_wallet_id) REFERENCES wallets (id)
      ON DELETE RESTRICT;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS implementers_funding_wallet_id_idx
  ON implementers (funding_wallet_id)
  WHERE funding_wallet_id IS NOT NULL;
