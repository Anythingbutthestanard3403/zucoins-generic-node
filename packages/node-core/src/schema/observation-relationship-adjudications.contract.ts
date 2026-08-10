/**
 * Contract for observation-relationship-adjudications.sql —
 * observation_relationship_adjudications (complete-path derived relationship).
 */

export const OBSERVATION_RELATIONSHIP_ADJUDICATIONS_SCHEMA_FILE =
  "observation-relationship-adjudications.sql" as const;

export const OBSERVATION_RELATIONSHIP_ADJUDICATIONS_TABLES = [
  "observation_relationship_adjudications",
] as const;

interface ObservationRelationshipAdjudicationInvariant {
  id: string;
  sqlAnchor: string;
  rule: string;
}

export const OBSERVATION_RELATIONSHIP_ADJUDICATION_INVARIANTS: readonly ObservationRelationshipAdjudicationInvariant[] =
  [
    {
      id: "observed-must-be-unexplained-jump",
      sqlAnchor: "CHECK (observed_relationship = 'UNEXPLAINED_JUMP')",
      rule: "Only an UNEXPLAINED_JUMP observation may be adjudicated; the observed relationship is immutable on gateway_observations.",
    },
    {
      id: "effective-must-be-complete-path-successor",
      sqlAnchor: "CHECK (effective_relationship = 'COMPLETE_PATH_SUCCESSOR')",
      rule: "Adjudication derives COMPLETE_PATH_SUCCESSOR only — the sole path that makes that enum member reachable.",
    },
    {
      id: "one-adjudication-per-path-proof",
      sqlAnchor: "lineage_path_proof_id uuid NOT NULL UNIQUE REFERENCES lineage_path_proofs(id)",
      rule: "Each lineage path proof adjudicates at most one observation relationship.",
    },
    {
      id: "append-only-triggers",
      sqlAnchor: "observation_relationship_adjudications_no_update",
      rule: "Adjudications are permanent evidence (§15); UPDATE/DELETE/TRUNCATE refused.",
    },
  ] as const;

export const OBSERVATION_RELATIONSHIP_ADJUDICATIONS_SCHEMA_SOURCE =
  "data-model: observation relationship adjudications; ZTR-1169" as const;
