-- ZTR-1121 / D10.36: durable per-operator recovery-pack prove lockout.
-- After 5 failed decrypt/prove attempts → 15 min hard lock. Digests/counters only.

CREATE TABLE IF NOT EXISTS operator_recovery_pack_prove_lockout (
  node_id uuid NOT NULL,
  operator_id text NOT NULL,
  fail_count integer NOT NULL DEFAULT 0,
  window_start_ms bigint NOT NULL,
  locked_until_ms bigint NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (node_id, operator_id),
  CONSTRAINT operator_recovery_pack_prove_lockout_fail_chk
    CHECK (fail_count >= 0)
);
