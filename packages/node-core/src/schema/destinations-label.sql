-- destinations.label: operator-facing display name (doc 04 §4 / GN-025.2).
--
-- Frozen schema contract. Pure column extension on the already-created
-- destinations table (custody-eligibility.sql). custody-eligibility.sql is an
-- early pack slice whose schema_migrations sql_sha256 must not change, so the
-- column ships here as an appended ALTER — never by editing the CREATE TABLE.
--
-- Advisory and unsigned (04:1261). NOT NULL with '' default so pre-existing rows
-- stay valid; POST /v1/destinations still requires a non-empty label on create.
--
-- Pack position: appended so earlier money-pack versions stay stable.

ALTER TABLE destinations
  ADD COLUMN IF NOT EXISTS label text NOT NULL DEFAULT '';
