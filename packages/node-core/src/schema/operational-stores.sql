-- Operational stores: the operational half of the retention and mutability matrix -- the
-- operator halt, mutable cursor counters, and the signer-leadership and pool/queue
-- settings.
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database; nothing in this package runs it. Every
-- invariant below is inventoried in operational-stores.contract.ts and censused by
-- test/operational-stores.census.test.ts.
--
-- Scope: three operational infrastructure tables -
-- node_settings (versioned key-value node configuration), operator_halts
-- (operator halt state, engage/disengage audited by actor),
-- and worker_cursors (worker progress positions, mutable operational state per
-- Queue-watermark, storage-pressure, subscription-handle, and callback
-- registration/delivery surfaces are deferred to their own slices; this file
-- freezes only the three stores the AC names as first-class tables.

-- Versioned node settings (pool/queue constants, including pool_cap).
-- row_version is the house compare-and-swap counter: an operator change
-- bumps it so a stale/rolled-back read cannot silently reactivate an old cap.
CREATE TABLE node_settings (
  setting_key text PRIMARY KEY,
  setting_value text NOT NULL,
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Operator halt store (the persistence half). Engagement is insert-only;
-- only lifted_at / lifted_by advance on disengage. engaged_by / reason are required
-- non-empty so an unaudited or empty-actor engage is not representable; lifted_by is
-- set (non-empty) when the halt is lifted, paired with lifted_at.
CREATE TABLE operator_halts (
  halt_id uuid PRIMARY KEY,
  scope text NOT NULL CHECK (scope IN ('NODE','WALLET','OPERATION')),
  reason text NOT NULL CHECK (octet_length(reason) > 0),
  engaged_by text NOT NULL CHECK (octet_length(engaged_by) > 0),
  halted_at timestamptz NOT NULL DEFAULT now(),
  lifted_at timestamptz,
  lifted_by text CHECK (lifted_by IS NULL OR octet_length(lifted_by) > 0),
  CHECK ((lifted_at IS NULL) OR (lifted_at >= halted_at)),
  CHECK ((lifted_at IS NULL) = (lifted_by IS NULL))
);

-- Worker progress cursors: distinct from wallet_observation_cursors.
CREATE TABLE worker_cursors (
  worker_id text NOT NULL,
  cursor_key text NOT NULL,
  position bigint NOT NULL CHECK (position >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (worker_id, cursor_key)
);
