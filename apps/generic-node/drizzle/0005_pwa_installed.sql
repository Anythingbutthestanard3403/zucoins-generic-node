-- ZTR-1118 / D10.35: durable PWA install evidence (not a client ack checkbox).
-- Evidence enum is enforced in application code: standalone | fullscreen | appinstalled.

ALTER TABLE operator_setup_state
  ADD COLUMN IF NOT EXISTS pwa_installed_at timestamptz,
  ADD COLUMN IF NOT EXISTS pwa_install_evidence text;
