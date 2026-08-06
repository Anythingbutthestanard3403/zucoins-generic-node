-- Durable, cross-instance fixed-window reporting limiter.
-- The principal is the presented public reporting-key id; it is intentionally not an FK
-- because unknown keys must be bounded before registration lookup without becoming an oracle.
CREATE TABLE reporting_rate_limit_buckets (
  node_id uuid NOT NULL REFERENCES nodes(id),
  principal text NOT NULL CHECK (octet_length(principal) BETWEEN 1 AND 512),
  window_start_ms bigint NOT NULL CHECK (window_start_ms >= 0),
  request_count bigint NOT NULL CHECK (request_count > 0),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (node_id, principal, window_start_ms)
);

CREATE INDEX reporting_rate_limit_buckets_updated_at_idx
  ON reporting_rate_limit_buckets(updated_at);