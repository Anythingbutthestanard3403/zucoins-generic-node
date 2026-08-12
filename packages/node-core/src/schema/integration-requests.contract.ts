/**
 * Integration requests: durable state for platform-initiated key requests
 * (Route 2 handshake). ZTR-1238.
 *
 * Frozen inventory of the structural invariants carried by
 * integration-requests.sql. Census tests bind every entry here to the literal
 * SQL text so the inventory and the schema contract cannot drift apart.
 *
 * Public routes: ZTR-1239 (integration-request module). No PWA surface (ZTR-1240).
 */

export const INTEGRATION_REQUESTS_SCHEMA_FILE = "integration-requests.sql" as const;

export const INTEGRATION_REQUESTS_TABLE = "integration_requests" as const;

export const INTEGRATION_REQUESTS_COLUMNS = [
  "id",
  "node_id",
  "display_name",
  "requested_scopes",
  "proposed_rule_json",
  "approved_rule_json",
  "status",
  "row_version",
  "claim_token_hash",
  "created_at",
  "expires_at",
  "decided_at",
  "decided_by",
  "implementer_id",
  "issued_credential_id",
  "claimed_at",
] as const;

/** Closed status vocabulary written by CAS transitions. */
export const INTEGRATION_REQUEST_STATUSES = [
  "PENDING",
  "APPROVED",
  "DECLINED",
  "EXPIRED",
  "CLAIMED",
] as const;

export type IntegrationRequestStatus = (typeof INTEGRATION_REQUEST_STATUSES)[number];

/**
 * Legal CAS transitions. Every writer is a single UPDATE matching
 * `status = $from AND row_version = $v`, then `row_version = row_version + 1`.
 * Concurrent losers match zero rows.
 */
export const INTEGRATION_REQUEST_TRANSITIONS = [
  {
    from: "PENDING",
    to: "APPROVED",
    actor: "operator",
    sets: [
      "decided_at",
      "decided_by",
      "approved_rule_json",
      "implementer_id",
    ] as const,
    note: "Implementer row is created at approval so the identity exists; no credential yet.",
  },
  {
    from: "PENDING",
    to: "DECLINED",
    actor: "operator",
    sets: ["decided_at", "decided_by"] as const,
    note: "Operator decline; no implementer / credential.",
  },
  {
    from: "PENDING",
    to: "EXPIRED",
    actor: "ttl",
    sets: [] as const,
    note: "Lazy on read and/or optional expiry job when expires_at has passed.",
  },
  {
    from: "APPROVED",
    to: "EXPIRED",
    actor: "ttl",
    sets: [] as const,
    note: "Approved-but-unclaimed past TTL; issued_credential_id stays NULL.",
  },
  {
    from: "APPROVED",
    to: "CLAIMED",
    actor: "public_claim",
    sets: ["issued_credential_id", "claimed_at"] as const,
    note: "Same TX: issue credential under implementer_id, record issued_credential_id; raw key only in response.",
  },
] as const;

export interface IntegrationRequestsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const INTEGRATION_REQUESTS_INVARIANTS: readonly IntegrationRequestsInvariant[] = [
  {
    id: "TABLE_PRIMARY_KEY",
    sqlAnchor: "CREATE TABLE integration_requests (\n  id uuid PRIMARY KEY,",
    rule: "each integration request has a stable uuid identity.",
  },
  {
    id: "NODE_FK",
    sqlAnchor: "node_id uuid NOT NULL REFERENCES nodes(id),",
    rule: "every request is tenanted to a node registry row.",
  },
  {
    id: "DISPLAY_NAME_BOUNDED",
    sqlAnchor: "display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),",
    rule: "display_name is non-empty and capped at 120 characters.",
  },
  {
    id: "SCOPES_NONEMPTY_SUBSET",
    sqlAnchor: "cardinality(requested_scopes) > 0",
    rule: "requested_scopes is a non-empty subset of the frozen implementer scope vocabulary.",
  },
  {
    id: "STATUS_CLOSED_SET",
    sqlAnchor:
      "status IN ('PENDING', 'APPROVED', 'DECLINED', 'EXPIRED', 'CLAIMED')",
    rule: "status is the closed five-value set written by CAS transitions only.",
  },
  {
    id: "ROW_VERSION_POSITIVE",
    sqlAnchor: "row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),",
    rule: "row_version is the house CAS counter; writers advance it by exactly one on each transition.",
  },
  {
    id: "CLAIM_TOKEN_HASH_SHAPE",
    sqlAnchor: "claim_token_hash ~ '^[0-9a-f]{64}$'",
    rule: "claim_token_hash is unsalted SHA-256 hex - same discipline as credential_hash.",
  },
  {
    id: "CLAIM_TOKEN_HASH_UNIQUE",
    sqlAnchor: "claim_token_hash text NOT NULL UNIQUE CHECK (claim_token_hash ~ '^[0-9a-f]{64}$'),",
    rule: "claim token hashes are globally unique so a claim resolves to at most one row.",
  },
  {
    id: "NO_RAW_CLAIM_TOKEN_COLUMN",
    sqlAnchor: "claim_token_hash text NOT NULL UNIQUE CHECK (claim_token_hash ~ '^[0-9a-f]{64}$'),",
    rule: "there is no claim_token / raw_token / bearer plaintext column - only claim_token_hash.",
  },
  {
    id: "IMPLEMENTER_FK",
    sqlAnchor: "implementer_id uuid REFERENCES implementers(id),",
    rule: "implementer_id, when set at approval, references the implementer registry.",
  },
  {
    id: "CREDENTIAL_FK",
    sqlAnchor: "issued_credential_id uuid REFERENCES implementer_credentials(id),",
    rule: "issued_credential_id, when set at claim, references implementer_credentials; the raw key never rests here.",
  },
  {
    id: "STATUS_CONSISTENCY_CHECK",
    sqlAnchor: "CONSTRAINT integration_requests_status_consistency CHECK (",
    rule: "composite CHECK pins column nullability to status (APPROVED needs decision+implementer+rule; CLAIMED needs credential+claimed_at; DECLINED/EXPIRED forbid credential).",
  },
  {
    id: "EXPIRES_AFTER_CREATED",
    sqlAnchor: "CHECK (expires_at > created_at)",
    rule: "request TTL must be strictly after creation.",
  },
  {
    id: "STATUS_EXPIRES_INDEX",
    sqlAnchor:
      "CREATE INDEX integration_requests_status_expires_at_idx\n  ON integration_requests (status, expires_at);",
    rule: "expiry-job and lazy-expiry reads filter by (status, expires_at) without a table scan.",
  },
  {
    id: "NODE_STATUS_INDEX",
    sqlAnchor:
      "CREATE INDEX integration_requests_node_status_idx\n  ON integration_requests (node_id, status);",
    rule: "operator list and per-node status filters are indexed.",
  },
] as const;

export const INTEGRATION_REQUESTS_MUTABILITY_REGIMES = [
  {
    table: "integration_requests",
    regime: "cas_lifecycle",
    updatableColumns: [
      "status",
      "row_version",
      "approved_rule_json",
      "decided_at",
      "decided_by",
      "implementer_id",
      "issued_credential_id",
      "claimed_at",
    ] as readonly string[],
    rule: "Intake is insert-only (PENDING). All later writers are CAS UPDATEs on status+row_version; immutable columns (id, node_id, display_name, requested_scopes, proposed_rule_json, claim_token_hash, created_at, expires_at) never change after insert.",
  },
] as const;

export const INTEGRATION_REQUESTS_EXECUTION_OBLIGATIONS: readonly string[] = [
  "execution sequence: apply after nodes, implementers, and implementer_credentials exist (pack append after implementer-credentials).",
  "CAS: every legal transition is one UPDATE ... WHERE status = $from AND row_version = $v RETURNING; concurrent double-apply yields exactly one winner and zero-row losers.",
  "illegal transitions (e.g. DECLINED->CLAIMED, CLAIMED->anything, PENDING->CLAIMED) match zero rows under the status guard.",
  "consistency: half-set APPROVED/CLAIMED/DECLINED rows are rejected by integration_requests_status_consistency.",
  "claim atomicity: APPROVED->CLAIMED and the implementer_credentials INSERT share one transaction; a forced failure between them rolls both back.",
  "secret boundary: claim_token_hash only (never raw claim token); issued API key generated at claim time and returned once - never a column on this table.",
  "duplicate claim_token_hash is rejected with unique_violation (23505).",
  "scope CHECK rejects empty arrays and any scope outside the frozen IMPLEMENTER_SCOPES set.",
  "public intake/claim HTTP lives in packages/node-core/src/integration-request (ZTR-1239).",
] as const;

export const INTEGRATION_REQUESTS_SOURCE =
  "ZTR-1238 integration-requests store; credential hash discipline packages/node-core/src/credential/types.ts; scope vocabulary generic-node-contracts api-schema auth-scopes" as const;
