// Durable neutral event stream: the composite (node_id, seq) primary key that gives one
// chain per node.
// (fix-forward: composite primary key on a table already live via event-ledger.sql).
//
// Frozen inventory of the structural invariants carried by
// node-events-seq-composite-pk.sql — the post-deployment rewrite of node_events's
// primary key from (seq) to (node_id, seq) so per-node counters cannot collide when
// multiple nodes share one database.

export const NODE_EVENTS_SEQ_COMPOSITE_PK_SCHEMA_FILE =
  "node-events-seq-composite-pk.sql" as const;

export interface NodeEventsSeqCompositePkInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const NODE_EVENTS_SEQ_COMPOSITE_PK_INVARIANTS: readonly NodeEventsSeqCompositePkInvariant[] =
  [
    {
      id: "FAIL_CLOSED_WITHOUT_NODE_EVENTS",
      sqlAnchor: 'RAISE EXCEPTION \'relation "node_events" does not exist\'',
      rule:
        "applied alone (or out of pack sequence) the slice fails with relation \"node_events\" does not exist, matching every other ALTER-only pack slice's greenfield characterization.",
    },
    {
      id: "SWAP_ONLY_WHEN_SINGLE_COLUMN_SEQ_PK",
      sqlAnchor: ") = ARRAY['seq']::text[]",
      rule:
        "the ALTER fires only when the live primary key is still the single-column `seq` form, so a cold greenfield apply whose event-ledger.sql already emitted PRIMARY KEY (node_id, seq) is a no-op rather than a 42P16 duplicate-constraint failure.",
    },
    {
      id: "PK_IS_NODE_ID_SEQ",
      sqlAnchor:
        "ADD CONSTRAINT node_events_pkey PRIMARY KEY (node_id, seq);",
      rule:
        "(node_id, seq) is the primary key going forward: each node owns an independent gapless seq space; equal seq values across different node_id rows are correct and required on shared-DB topologies.",
    },
  ] as const;

export const NODE_EVENTS_SEQ_COMPOSITE_PK_EXECUTION_OBLIGATIONS: readonly string[] = [
  "node-events-seq-composite-pk.sql applies after event-ledger.sql (the table must already exist) and is a pure ALTER extension: it creates no table.",
  "Deploy on every shared-DB topology before multi-node landed dual-chain event appends: once two nodes share one database, equal seq values under different node_id rows arrive immediately, so the composite key must already be in place.",
] as const;

export const NODE_EVENTS_SEQ_COMPOSITE_PK_SOURCE =
  "data-model: durable neutral event stream" as const;
