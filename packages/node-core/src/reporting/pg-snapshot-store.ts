// PostgreSQL SnapshotStore over implementer_state_snapshots
// (implementer-event-stream.sql). Latest-row upsert; body is the exact JSON wire text.

import type { ImplementerStateSnapshot, SnapshotStore } from "./snapshot-service.js";
import type { SqlQueryFn } from "./pg-implementer-event-log.js";

export interface PgSnapshotStoreConfig {
  readonly nodeId: string;
  readonly query: SqlQueryFn;
}

const UPSERT = `
INSERT INTO implementer_state_snapshots (
  node_id, implementer_id, implementer_watermark_seq, snapshot_body, captured_at
) VALUES ($1::uuid, $2::uuid, $3::bigint, $4::text, $5::timestamptz)
ON CONFLICT (node_id, implementer_id) DO UPDATE SET
  implementer_watermark_seq = EXCLUDED.implementer_watermark_seq,
  snapshot_body = EXCLUDED.snapshot_body,
  captured_at = EXCLUDED.captured_at
`;

const LATEST = `
SELECT implementer_id, implementer_watermark_seq, snapshot_body, captured_at
  FROM implementer_state_snapshots
 WHERE node_id = $1::uuid AND implementer_id = $2::uuid
`;

function asString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  if (value instanceof Date) return value.toISOString();
  throw new Error(`expected string, got ${typeof value}`);
}

function asBigint(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(value);
  if (typeof value === "string") return BigInt(value);
  throw new Error(`expected bigint-compatible value, got ${typeof value}`);
}

function parseBody(body: string, implementerId: string, watermark: bigint, capturedAt: string): ImplementerStateSnapshot {
  const parsed = JSON.parse(body) as {
    operations?: ImplementerStateSnapshot["operations"];
    destinations?: ImplementerStateSnapshot["destinations"];
    attentionItems?: ImplementerStateSnapshot["attentionItems"];
    attention_items?: ImplementerStateSnapshot["attentionItems"];
  };
  // Stored body uses the internal field names from ImplementerStateSnapshot JSON form.
  return {
    implementerId,
    implementerWatermarkSeq: watermark.toString(),
    operations: parsed.operations ?? [],
    destinations: parsed.destinations ?? [],
    attentionItems: parsed.attentionItems ?? parsed.attention_items ?? [],
    capturedAt,
  };
}

/** Serialize the durable snapshot row body (internal shape, not the public wire body). */
export function serializeSnapshotRowBody(snapshot: ImplementerStateSnapshot): string {
  return JSON.stringify({
    operations: snapshot.operations,
    destinations: snapshot.destinations,
    attentionItems: snapshot.attentionItems,
  });
}

export function createPgSnapshotStore(config: PgSnapshotStoreConfig): SnapshotStore {
  const { nodeId, query } = config;

  return {
    async save(snapshot: ImplementerStateSnapshot): Promise<void> {
      await query(UPSERT, [
        nodeId,
        snapshot.implementerId,
        BigInt(snapshot.implementerWatermarkSeq),
        serializeSnapshotRowBody(snapshot),
        snapshot.capturedAt,
      ]);
    },

    async latest(implementerId: string): Promise<ImplementerStateSnapshot | null> {
      const rows = await query(LATEST, [nodeId, implementerId]);
      const row = rows[0];
      if (row === undefined) return null;
      return parseBody(
        asString(row.snapshot_body),
        asString(row.implementer_id),
        asBigint(row.implementer_watermark_seq),
        asString(row.captured_at),
      );
    },
  };
}
