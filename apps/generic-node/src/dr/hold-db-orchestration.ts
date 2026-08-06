// Shared fail-closed DR hold DB orchestration.
// Generic-node local only — no platform sharing.
//
// Call sites: restore-hold force + dual-gate restore path. Hold semantics stay
// injected; this module owns client lifecycle and the common
// "table exists → resolve IDs → apply per node" skeleton.

import type { Client, QueryResult, QueryResultRow } from "pg";

/** Minimal client surface used by hold orchestration. */
export type HoldDbClient = {
  query<T extends QueryResultRow = QueryResultRow>(
    queryTextOrConfig: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
};

/**
 * Connect a one-shot pg Client, run `fn`, always end the client.
 * Fail-closed: query errors propagate; cleanup still runs.
 */
export async function withConnectedPgClient<T>(
  databaseUrl: string,
  fn: (client: Client) => Promise<T>,
): Promise<T> {
  const { Client: PgClient } = await import("pg");
  const client = new PgClient({ connectionString: databaseUrl });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

/** Default discovery for restore-state force: existing restore rows ∪ nodes.id. */
export const DISCOVER_RESTORE_NODE_IDS_SQL = `
  SELECT node_id::text AS node_id FROM reporting_restore_state
  UNION
  SELECT id::text AS node_id FROM nodes
`;

export interface FailClosedPerNodeHoldInput {
  readonly tableExistsSql: string;
  readonly explicitNodeId?: string;
  readonly discoverNodeIdsSql: string;
  readonly applyPerNode: (client: HoldDbClient, nodeId: string) => Promise<void>;
}

export interface FailClosedPerNodeHoldResult {
  readonly applied: boolean;
  readonly nodeIds: readonly string[];
}

/**
 * If the hold table is absent → no-op (`applied: false`).
 * If present → resolve explicit or discovered/deduped node IDs, apply per node.
 * Any error while the table exists propagates (fail-closed).
 */
export async function runFailClosedPerNodeHold(
  client: HoldDbClient,
  input: FailClosedPerNodeHoldInput,
): Promise<FailClosedPerNodeHoldResult> {
  const exists = await client.query(input.tableExistsSql);
  if (exists.rowCount === 0) {
    return { applied: false, nodeIds: [] };
  }

  const nodeIds: string[] = [];

  if (input.explicitNodeId !== undefined && input.explicitNodeId.trim() !== "") {
    nodeIds.push(input.explicitNodeId.trim());
  } else {
    const found = await client.query<{ node_id: string }>(input.discoverNodeIdsSql);
    for (const row of found.rows) {
      if (!nodeIds.includes(row.node_id)) nodeIds.push(row.node_id);
    }
  }

  for (const nodeId of nodeIds) {
    await input.applyPerNode(client, nodeId);
  }

  return { applied: nodeIds.length > 0, nodeIds };
}
