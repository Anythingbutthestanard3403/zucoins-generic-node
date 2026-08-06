-- Observation-ledger foreign keys, added by ALTER once the observation tables exist.
-- The relation shape and its CHECKs are owned solely by
-- move-baseline-binding.sql. This file is ALTER-only and must never re-declare
-- the relation.
-- Frozen schema contract. Contract text only — the schema-apply phase
-- executes it against a live database; nothing in this package runs it. Inventoried in
-- move-observation-evidence.contract.ts; proven live by move-internal-landing-store.pg.test.ts
-- after the baseline slice has materialised the relation.
--
-- Prerequisite: move-baseline-binding.sql (the relation and its CHECKs) and gateway_observations.

-- Independent raw observation ledger (verbatim ALTER):

ALTER TABLE move_observation_evidence
  ADD FOREIGN KEY (source_t0_observation_id) REFERENCES gateway_observations(id),
  ADD FOREIGN KEY (destination_t0_observation_id) REFERENCES gateway_observations(id),
  ADD FOREIGN KEY (source_terminal_observation_id) REFERENCES gateway_observations(id),
  ADD FOREIGN KEY (destination_terminal_observation_id) REFERENCES gateway_observations(id);
