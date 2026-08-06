// Durable rate-limit bound: the reporting_rate_limit_buckets primary-key collapse.
// (fix-forward: PK collapse of a table that is already live in production).
//
// Frozen inventory of the structural invariants carried by
// reporting-rate-limit-buckets-pk-collapse.sql — the post-deployment collapse of
// reporting_rate_limit_buckets's primary key from (node_id, principal, window_start_ms) to
// (node_id, principal).

export const REPORTING_RATE_LIMIT_BUCKETS_PK_COLLAPSE_SCHEMA_FILE =
  "reporting-rate-limit-buckets-pk-collapse.sql" as const;

export interface ReportingRateLimitBucketsPkCollapseInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const REPORTING_RATE_LIMIT_BUCKETS_PK_COLLAPSE_INVARIANTS: readonly ReportingRateLimitBucketsPkCollapseInvariant[] =
  [
    {
      id: "DEDUPE_BEFORE_KEY_SWAP",
      sqlAnchor: "DELETE FROM reporting_rate_limit_buckets a",
      rule:
        "every (node_id, principal) group is collapsed to its single latest-window row before the primary key is swapped, so the ADD CONSTRAINT below cannot fail on a duplicate-key violation.",
    },
    {
      id: "PK_COLLAPSED_TO_NODE_PRINCIPAL",
      sqlAnchor: "ADD CONSTRAINT reporting_rate_limit_buckets_pkey PRIMARY KEY (node_id, principal)",
      rule:
        "(node_id, principal) is the primary key going forward: at most one row per principal per node, ever — a window reset merges into that row instead of inserting a new one.",
    },
    {
      id: "UPDATED_AT_INDEX_DROPPED",
      sqlAnchor: "DROP INDEX IF EXISTS reporting_rate_limit_buckets_updated_at_idx;",
      rule:
        "the updated_at index is dropped: with one row per principal the table is already bounded, so the index served no consumer (Q2).",
    },
  ] as const;

export const REPORTING_RATE_LIMIT_BUCKETS_PK_COLLAPSE_EXECUTION_OBLIGATIONS: readonly string[] = [
  "reporting-rate-limit-buckets-pk-collapse.sql applies after reporting-security-ports.sql (the table must already exist) and is a pure ALTER/dedupe extension: it creates no table.",
  "The DELETE + ADD CONSTRAINT ordering must never be reversed: reversing it would fail the constraint add on real duplicate data.",
] as const;

export const REPORTING_RATE_LIMIT_BUCKETS_PK_COLLAPSE_SOURCE = "signing-custody: durable rate-limit bound" as const;
