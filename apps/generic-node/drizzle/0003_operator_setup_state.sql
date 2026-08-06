-- ZTR-1097: durable secret-free operator setup wizard flags (W0–W12).
-- No master keys, TOTP secrets, passwords, or ik_/sh_ material.

CREATE TABLE IF NOT EXISTS operator_setup_state (
  node_id uuid PRIMARY KEY,
  w0_secure_context_ok boolean NOT NULL DEFAULT false,
  w3_pwa_ack boolean NOT NULL DEFAULT false,
  w3_pwa_skipped boolean NOT NULL DEFAULT false,
  w4_device_enrolled boolean NOT NULL DEFAULT false,
  w4_break_glass_ack boolean NOT NULL DEFAULT false,
  w5_vault_ready boolean NOT NULL DEFAULT false,
  w5_offline_backup_ack boolean NOT NULL DEFAULT false,
  w6_ceremony_placeholder_ack boolean NOT NULL DEFAULT false,
  w7_recovery_wallet_ok boolean NOT NULL DEFAULT false,
  w8_implementer_key_ack boolean NOT NULL DEFAULT false,
  w8_implementer_skipped boolean NOT NULL DEFAULT false,
  w9_reporting_key_ok boolean NOT NULL DEFAULT false,
  w10_packs_ack boolean NOT NULL DEFAULT false,
  w10_packs_skipped boolean NOT NULL DEFAULT false,
  w11_mini_steps_ack boolean NOT NULL DEFAULT false,
  w11_mini_steps_skipped boolean NOT NULL DEFAULT false,
  completed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);
