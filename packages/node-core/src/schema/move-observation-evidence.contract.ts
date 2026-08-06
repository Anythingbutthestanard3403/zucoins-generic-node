// Observation-ledger foreign keys for move evidence, attached by the landing DB-TX.
// internal_move.landed carries both terminal observation ids.
//
// CREATE TABLE move_observation_evidence (its CHECKs, primary key, bare uuid columns) is
// owned by move-baseline-binding.sql / move-baseline-binding.contract.ts. This
// contract freezes only the ALTER TABLE foreign keys that baseline deferred — a second
// CREATE TABLE would dual-own the relation.
//
// move-observation-evidence.census.test.ts binds every entry here to the literal SQL text;
// move-internal-landing-store.pg.test.ts applies baseline CREATE then this ALTER against real
// Postgres and proves the FKs are live.
//
// reconciliation note: the four observation columns target gateway_observations(id)
//; no slice in this package creates that relation for greenfield-alone, and the
// relation this ALTER targets is created by move-baseline-binding.sql — so this contract is
// prerequisite-bound greenfield (fails first on move_observation_evidence when applied alone).

export const MOVE_OBSERVATION_EVIDENCE_SCHEMA_FILE = "move-observation-evidence.sql" as const;

/** CREATE TABLE owner — single source of truth for the relation shape. */
export const MOVE_OBSERVATION_EVIDENCE_CREATE_OWNER =
  "move-baseline-binding.sql" as const;

export interface MoveObservationEvidenceInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const MOVE_OBSERVATION_EVIDENCE_INVARIANTS: readonly MoveObservationEvidenceInvariant[] = [
  {
    id: "OBSERVATION_IDS_FOREIGN_KEYED",
    sqlAnchor:
      "ALTER TABLE move_observation_evidence\n  ADD FOREIGN KEY (source_t0_observation_id) REFERENCES gateway_observations(id),",
    rule: "all four observation references point at rows in the independent raw observation ledger: evidence cannot cite an observation the node never recorded. CREATE TABLE and its CHECKs remain in move-baseline-binding.sql.",
  },
  {
    id: "SOURCE_T0_FK",
    sqlAnchor:
      "ADD FOREIGN KEY (source_t0_observation_id) REFERENCES gateway_observations(id),",
    rule: "source T0 observation id is foreign-keyed to gateway_observations.",
  },
  {
    id: "DESTINATION_T0_FK",
    sqlAnchor:
      "ADD FOREIGN KEY (destination_t0_observation_id) REFERENCES gateway_observations(id),",
    rule: "destination T0 observation id is foreign-keyed to gateway_observations.",
  },
  {
    id: "SOURCE_TERMINAL_FK",
    sqlAnchor:
      "ADD FOREIGN KEY (source_terminal_observation_id) REFERENCES gateway_observations(id),",
    rule: "source terminal observation id is foreign-keyed to gateway_observations.",
  },
  {
    id: "DESTINATION_TERMINAL_FK",
    sqlAnchor:
      "ADD FOREIGN KEY (destination_terminal_observation_id) REFERENCES gateway_observations(id);",
    rule: "destination terminal observation id is foreign-keyed to gateway_observations.",
  },
] as const;

// The mutability regime is inventoried on the CREATE owner (move-baseline-binding). Re-stated
// here so the landing suite's obligations stay co-located with the attach seam.
export const MOVE_OBSERVATION_EVIDENCE_MUTABILITY_REGIMES = [
  {
    table: "move_observation_evidence",
    regime: "write_once_terminal_pair",
    updatableColumns: [
      "source_terminal_observation_id",
      "destination_terminal_observation_id",
      "verified_at",
    ] as readonly string[],
    rule: "operation_id and both T0 columns are immutable after insert; the terminal pair and verified_at are settable exactly once, together, by the landing transaction. Shape DDL: move-baseline-binding.sql.",
  },
] as const;

// Live-database proofs. The pg suite discharges the negatives marked [pg]; the rest are schema-apply
// schema-phase obligations this package cannot run.
export const SCHEMA_MOVE_OBSERVATION_EVIDENCE_OBLIGATIONS = [
  "execution sequence: apply move-baseline-binding.sql (CREATE TABLE move_observation_evidence) and create gateway_observations before this ALTER-only file.",
  "no second CREATE: this file must never re-declare move_observation_evidence — a dual CREATE TABLE is the defect class this rule exists to prevent.",
  "guards: install BEFORE UPDATE enforcement pinning operation_id and both T0 columns, and rejecting a second write of an already-set terminal pair (the conventions sanction immutability triggers; no trigger DDL is frozen here).",
  "[pg] negative: setting one terminal observation without the other, or either without verified_at, is rejected by the all-or-nothing CHECK owned by move-baseline-binding.sql (23514).",
  "[pg] negative: setting both terminal observations to the same id is rejected by the distinctness CHECK owned by move-baseline-binding.sql (23514).",
  "[pg] negative: a second evidence row for the same operation_id is rejected with unique_violation (23505) by the primary key owned by move-baseline-binding.sql.",
  "negative: an observation id absent from gateway_observations is rejected by the observation foreign keys this file adds.",
] as const;

export const MOVE_OBSERVATION_EVIDENCE_SOURCE =
  "data-model: observation-ledger foreign keys for move evidence (the CREATE is owned by move-baseline-binding)" as const;
