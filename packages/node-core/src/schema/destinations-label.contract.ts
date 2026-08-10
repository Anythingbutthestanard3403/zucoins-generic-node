/**
 * destinations.label column (migration-pack ownership).
 *
 * Frozen inventory of the structural invariants carried by destinations-label.sql.
 */

export const DESTINATIONS_LABEL_SCHEMA_FILE = "destinations-label.sql" as const;

export interface DestinationsLabelInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const DESTINATIONS_LABEL_INVARIANTS: readonly DestinationsLabelInvariant[] = [
  {
    id: "LABEL_NOT_NULL_DEFAULT_EMPTY",
    sqlAnchor: "ADD COLUMN IF NOT EXISTS label text NOT NULL DEFAULT ''",
    rule:
      "label is NOT NULL with a '' default so rows predating this column remain valid; create path still requires a non-empty operator label.",
  },
] as const;

export const DESTINATIONS_LABEL_EXECUTION_OBLIGATIONS: readonly string[] = [
  "destinations-label.sql applies after custody-eligibility.sql (destinations must already exist) and is a pure column extension: it creates no table, no index, no trigger.",
] as const;

export const DESTINATIONS_LABEL_SOURCE =
  "data-model: destinations.label / GN-025.2; ZTR-1169" as const;
