/**
 * Contract for lineage-path-proofs.sql -- lineage_path_proofs + lineage_path_bodies.
 */

export const LINEAGE_PATH_PROOFS_SCHEMA_FILE = "lineage-path-proofs.sql";

export const LINEAGE_PATH_PROOFS_TABLES = [
  "lineage_path_proofs",
  "lineage_path_bodies",
] as const;

interface LineagePathProofInvariant {
  id: string;
  sqlAnchor: string;
  rule: string;
}

export const LINEAGE_PATH_PROOF_INVARIANTS: readonly LineagePathProofInvariant[] = [
  {
    id: "path-depth-equals-body-count-minus-one",
    sqlAnchor: "path_depth >= 0 AND path_depth = body_count - 1",
    rule: "lineage_path_proofs.path_depth is always body_count - 1 (the depth oracle).",
  },
  {
    id: "role-unique-per-landing-proof",
    sqlAnchor: "UNIQUE (landing_proof_id, path_role)",
    rule: "At most one path per role under a landing proof (RECEIVE=1 RECEIVER; MOVE=SOURCE+DESTINATION).",
  },
  {
    id: "body-octet-length-matches-text",
    sqlAnchor: "octet_length(completed_transaction_text) = completed_transaction_octets",
    rule: "lineage_path_bodies stores exact full-body form; octets must match stored text bytes.",
  },
  {
    id: "insert-only-triggers",
    sqlAnchor: "lineage_path_proofs_no_update",
    rule: "Path proof rows are append-only evidence; UPDATE/DELETE refused.",
  },
] as const;

export const LINEAGE_PATH_PROOFS_SCHEMA_SOURCE = "data-model: lineage path proofs";
