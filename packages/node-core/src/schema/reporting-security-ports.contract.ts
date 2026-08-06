// SOURCE: 05-api-contract.md:66,82 (reporting rate-limit ports); 07-signing-custody-security.md
// The durable rate-limit bound and the bucket table shape.
//
// Frozen inventory of the structural invariants carried by reporting-security-ports.sql:
// the durable, cross-instance fixed-window reporting-limiter bucket table. The census
// binds every entry here to the literal SQL text.

export const REPORTING_SECURITY_PORTS_SCHEMA_FILE = "reporting-security-ports.sql" as const;

export interface ReportingSecurityPortsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const REPORTING_SECURITY_PORTS_INVARIANTS: readonly ReportingSecurityPortsInvariant[] = [
  {
    id: "BUCKET_NODE_SCOPED",
    sqlAnchor: "node_id uuid NOT NULL REFERENCES nodes(id),",
    rule: "every rate-limit bucket is bound to one node: a bucket on one node confers no quota on another.",
  },
  {
    id: "BUCKET_PRINCIPAL_NOT_FK",
    sqlAnchor: "principal text NOT NULL CHECK (octet_length(principal) BETWEEN 1 AND 512),",
    rule: "the principal is the presented public reporting-key id, deliberately not an FK: unknown keys must be bounded before registration lookup without becoming an existence oracle.",
  },
  {
    id: "BUCKET_WINDOW_NON_NEGATIVE",
    sqlAnchor: "window_start_ms bigint NOT NULL CHECK (window_start_ms >= 0),",
    rule: "window_start_ms is never negative: a bucket's fixed window always anchors at or after epoch zero.",
  },
  {
    id: "BUCKET_COUNT_POSITIVE",
    sqlAnchor: "request_count bigint NOT NULL CHECK (request_count > 0),",
    rule: "request_count is strictly positive: a bucket row only exists once at least one request has landed in its window.",
  },
  {
    id: "BUCKET_PRIMARY_KEY",
    sqlAnchor: "PRIMARY KEY (node_id, principal, window_start_ms)",
    rule: "(node_id, principal, window_start_ms) is the primary key: at most one row counts a given principal's requests in a given fixed window on a given node.",
  },
  {
    id: "BUCKET_UPDATED_AT_INDEXED",
    sqlAnchor: "CREATE INDEX reporting_rate_limit_buckets_updated_at_idx\n  ON reporting_rate_limit_buckets(updated_at);",
    rule: "updated_at is indexed: stale-bucket cleanup/expiry can scan by recency without a full table scan.",
  },
] as const;
