// Buried SEND completion landing: the gateway_observations indexes the any-depth
// complete-path landing oracle and the retained-body forward walk need.
//
// Frozen inventory of the structural invariants carried by
// gateway-observation-successor-indexes.sql — the two gateway_observations indexes the
// production RetainedPathBodySource adapter needs to walk a retained body chain (forward
// from an operation's own step_1/step_2 completion toward the wallet's current head)
// without a full-table scan.

export const GATEWAY_OBSERVATION_SUCCESSOR_INDEXES_SCHEMA_FILE =
  "gateway-observation-successor-indexes.sql" as const;

export interface GatewayObservationSuccessorIndexInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const GATEWAY_OBSERVATION_SUCCESSOR_INDEX_INVARIANTS: readonly GatewayObservationSuccessorIndexInvariant[] =
  [
    {
      id: "SUCCESSOR_BY_BACKLINK_INDEX",
      sqlAnchor:
        "CREATE INDEX gateway_observations_successor_by_backlink_idx\n  ON gateway_observations(wallet_public_key, p_signature)",
      rule:
        "resolving a state's immediate successor by backlink (its p_signature equalling the state's own S) is a keyed lookup, not a scan; observer-agnostic — a wallet's true next hop does not depend on which observer captured it.",
    },
    {
      id: "SUCCESSOR_BY_BACKLINK_INDEX_PARTIAL",
      sqlAnchor: "WHERE p_signature IS NOT NULL",
      rule:
        "partial on rows that carry a p_signature (every VERIFIED_GENESIS/VERIFIED_HEAD row does, including the empty-string first-hop-from-genesis case); only non-verified anomaly rows have p_signature NULL.",
    },
    {
      id: "COMPLETED_TX_DIGEST_INDEX",
      sqlAnchor:
        "CREATE INDEX gateway_observations_completed_tx_digest_idx\n  ON gateway_observations(completed_transaction_sha256)",
      rule:
        "counting DISTINCT completed_transaction_text values sharing a completed_transaction_sha256 (the walk's duplicate/cycle-free proof, global not wallet-scoped) is index-served, not a scan.",
    },
    {
      id: "COMPLETED_TX_DIGEST_INDEX_PARTIAL",
      sqlAnchor: "WHERE completed_transaction_sha256 IS NOT NULL",
      rule:
        "partial on head rows, the only rows that carry a completed transaction digest.",
    },
    {
      id: "STEP_ONE_SIGNATURE_INDEX",
      sqlAnchor:
        "CREATE INDEX gateway_observations_step_one_signature_idx\n  ON gateway_observations(wallet_public_key, step_1_signature)",
      rule:
        "finding OUR OWN send's completed body wherever it currently sits (buried or at head) is a keyed lookup by (wallet_public_key, step_1_signature) — the one identifier that survives regardless of how many later hops have landed on top of it.",
    },
    {
      id: "STEP_ONE_SIGNATURE_INDEX_PARTIAL",
      sqlAnchor: "WHERE step_1_signature IS NOT NULL",
      rule:
        "partial on rows carrying a step_1_signature; the observation-ledger.sql CHECK makes this exactly the VERIFIED_HEAD rows (parse_result = 'VERIFIED_HEAD' iff step_1_signature IS NOT NULL), the same shape as gateway_observations_exact_body_idx.",
    },
  ] as const;

export const GATEWAY_OBSERVATION_SUCCESSOR_INDEXES_EXECUTION_OBLIGATIONS: readonly string[] = [
  "gateway-observation-successor-indexes.sql applies after observation-ledger.sql (gateway_observations must already exist) and is a pure index extension: it creates no table, no column, no trigger.",
  "EXPLAIN confirms gateway_observations_successor_by_backlink_idx serves a (wallet_public_key, p_signature) equality lookup for resolveSuccessorByBacklink.",
  "EXPLAIN confirms gateway_observations_completed_tx_digest_idx serves a completed_transaction_sha256 equality lookup for countDistinctBodiesWithDigest.",
  "EXPLAIN confirms gateway_observations_step_one_signature_idx serves a (wallet_public_key, step_1_signature) equality lookup for fetchRetainedBodyByStepOneSignature.",
] as const;

export const GATEWAY_OBSERVATION_SUCCESSOR_INDEXES_SOURCE =
  "data-model: gateway observations; buried SEND completion landing" as const;
