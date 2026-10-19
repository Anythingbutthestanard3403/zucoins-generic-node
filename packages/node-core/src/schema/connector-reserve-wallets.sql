-- Connector reserve wallets (ZTR-1324 / GN-101).
--
-- Human label on custody wallets, a per-connector custom-routing flag, and the
-- junction that binds a connector to one or more reserve wallets. The junction
-- default row stays aligned with implementers.funding_wallet_id.
--
-- implementers and wallets already exist (reporting registry + custody-eligibility).
-- This slice only appends. Never edit those frozen CREATE TABLE files.
--
-- Wallet delete while a junction row remains is refused (ON DELETE RESTRICT).
-- Connector delete removes its junction rows (ON DELETE CASCADE).
--
-- Pack position: appended after send-landed-unacknowledged-close.

DO $connector_reserve_wallets_guard$
BEGIN
  IF to_regclass('wallets') IS NULL THEN
    RAISE EXCEPTION 'connector-reserve-wallets requires wallets';
  END IF;
  IF to_regclass('implementers') IS NULL THEN
    RAISE EXCEPTION 'connector-reserve-wallets requires implementers';
  END IF;
END
$connector_reserve_wallets_guard$;

ALTER TABLE wallets
  ADD COLUMN IF NOT EXISTS display_label text NULL;

DO $connector_reserve_wallets_label_chk$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'wallets_display_label_len_chk'
  ) THEN
    ALTER TABLE wallets
      ADD CONSTRAINT wallets_display_label_len_chk
      CHECK (
        display_label IS NULL
        OR (char_length(btrim(display_label)) BETWEEN 1 AND 128)
      );
  END IF;
END
$connector_reserve_wallets_label_chk$;

ALTER TABLE implementers
  ADD COLUMN IF NOT EXISTS allow_custom_routing boolean NOT NULL DEFAULT false;

DO $connector_reserve_wallets_table$
BEGIN
  IF to_regclass('implementer_reserve_wallets') IS NULL THEN
    CREATE TABLE implementer_reserve_wallets (
      implementer_id uuid NOT NULL REFERENCES implementers (id) ON DELETE CASCADE,
      wallet_id uuid NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,
      is_default boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (implementer_id, wallet_id)
    );
  END IF;
END
$connector_reserve_wallets_table$;

CREATE UNIQUE INDEX IF NOT EXISTS implementer_reserve_wallets_one_default_uidx
  ON implementer_reserve_wallets (implementer_id)
  WHERE is_default IS TRUE;

CREATE INDEX IF NOT EXISTS implementer_reserve_wallets_wallet_id_idx
  ON implementer_reserve_wallets (wallet_id);

INSERT INTO implementer_reserve_wallets (implementer_id, wallet_id, is_default)
SELECT i.id, i.funding_wallet_id, true
  FROM implementers i
 WHERE i.funding_wallet_id IS NOT NULL
   AND NOT EXISTS (
     SELECT 1
       FROM implementer_reserve_wallets r
      WHERE r.implementer_id = i.id
        AND r.is_default IS TRUE
   )
ON CONFLICT (implementer_id, wallet_id) DO NOTHING;
