-- ZTR-1100: durable vault-master show-once seal marker (fingerprint only — never plaintext).
-- Survives process restart so generate cannot re-issue after shown/sealed.

CREATE TABLE IF NOT EXISTS operator_vault_master_seal (
  node_id uuid PRIMARY KEY,
  -- shown | sealed | configured — never stores master key material
  phase text NOT NULL,
  key_fingerprint_hex text NOT NULL,
  offline_backup_acked boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT operator_vault_master_seal_phase_chk
    CHECK (phase IN ('shown', 'sealed', 'configured')),
  CONSTRAINT operator_vault_master_seal_fp_chk
    CHECK (key_fingerprint_hex ~ '^[0-9a-f]{64}$')
);
