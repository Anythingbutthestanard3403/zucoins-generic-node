// PostgreSQL adapter for ImplementerEventLog over implementer-event-stream.sql.
// Same SqlQueryFn / SqlTxFn pattern as event-log/pg-event-store.ts.
// No driver is linked — statements go through the injected ports.

import {
  ImplementerEventLogError,
  isImplementerStreamEventType,
  type ImplementerCheckpointAppendInput,
  type ImplementerEventLog,
  type StoredImplementerCheckpoint,
  type StoredImplementerEvent,
} from "./implementer-event-log.js";
import type {
  ImplementerEventPage,
  ServedImplementerCheckpoint,
} from "./events-read-service.js";

export type SqlQueryFn = (
  text: string,
  values: readonly unknown[],
) => Promise<readonly Record<string, unknown>[]>;

export type SqlTxFn = <T>(body: (query: SqlQueryFn) => Promise<T>) => Promise<T>;

export interface PgImplementerEventLogConfig {
  readonly nodeId: string;
  readonly query: SqlQueryFn;
  readonly withTransaction: SqlTxFn;
}

// Note: the ensure/lock/advance/insert quartet for implementer_event_seq_counters +
// implementer_events lives in event-log/dual-chain-appender.ts — that is the sole writer
// of durable implementer-chain rows. This adapter is read + checkpoint only.

const READ_WATERMARK = `
SELECT COALESCE(
  (SELECT next_seq - 1 FROM implementer_event_seq_counters
    WHERE node_id = $1::uuid AND implementer_id = $2::uuid),
  0
) AS watermark
`;

const SCAN_AFTER = `
SELECT implementer_seq, event_id, event_type, proof_representation, created_at
  FROM implementer_events
 WHERE node_id = $1::uuid
   AND implementer_id = $2::uuid
   AND implementer_seq > $3::bigint
 ORDER BY implementer_seq ASC -- contract-allow:order:frozen-sql-text
 LIMIT $4::integer
`;

const INSERT_CHECKPOINT = `
INSERT INTO implementer_checkpoints (
  node_id, implementer_id, checkpoint_epoch, implementer_seq_head,
  proof_representation, created_at
) VALUES (
  $1::uuid, $2::uuid, $3::bigint, $4::bigint,
  $5::text, $6::timestamptz
)
`;

const SCAN_CHECKPOINTS = `
SELECT checkpoint_epoch, implementer_seq_head, proof_representation, created_at
  FROM implementer_checkpoints
 WHERE node_id = $1::uuid
   AND implementer_id = $2::uuid
 ORDER BY checkpoint_epoch ASC -- contract-allow:order:frozen-sql-text
`;

function asBigint(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(value);
  if (typeof value === "string") return BigInt(value);
  throw new ImplementerEventLogError(`expected bigint-compatible value, got ${typeof value}`);
}

function asString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  if (value instanceof Date) return value.toISOString();
  throw new ImplementerEventLogError(`expected string, got ${typeof value}`);
}

function rowToStored(row: Record<string, unknown>): StoredImplementerEvent {
  const eventType = asString(row.event_type);
  if (!isImplementerStreamEventType(eventType)) {
    throw new ImplementerEventLogError(`stored event_type outside closed set: ${eventType}`);
  }
  return Object.freeze({
    implementerSeq: asBigint(row.implementer_seq),
    eventType,
    proofRepresentation: asString(row.proof_representation),
    eventId: asString(row.event_id),
    createdAt: asString(row.created_at),
  });
}

function rowToCheckpoint(row: Record<string, unknown>): ServedImplementerCheckpoint {
  return Object.freeze({
    checkpointEpoch: asBigint(row.checkpoint_epoch),
    implementerSeqHead: asBigint(row.implementer_seq_head),
    proofRepresentation: asString(row.proof_representation),
  });
}

export function createPgImplementerEventLog(
  config: PgImplementerEventLogConfig,
): ImplementerEventLog {
  const { nodeId, query } = config;
  const listeners = new Map<string, Set<(event: StoredImplementerEvent) => void>>();

  return {
    async watermark(implementerId: string): Promise<bigint> {
      const rows = await query(READ_WATERMARK, [nodeId, implementerId]);
      const row = rows[0];
      if (row === undefined) return 0n;
      return asBigint(row.watermark);
    },

    async readEvents(
      implementerId: string,
      afterImplementerSeq: bigint | null,
      limit: number,
    ): Promise<ImplementerEventPage> {
      const after = afterImplementerSeq ?? 0n;
      const capped = Math.max(0, Math.trunc(limit));
      const [eventRows, watermark] = await Promise.all([
        capped === 0
          ? Promise.resolve([] as readonly Record<string, unknown>[])
          : query(SCAN_AFTER, [nodeId, implementerId, after, capped]),
        this.watermark(implementerId),
      ]);
      return {
        events: eventRows.map(rowToStored),
        watermarkSeq: watermark,
      };
    },

    async readCheckpoints(implementerId: string): Promise<readonly ServedImplementerCheckpoint[]> {
      const rows = await query(SCAN_CHECKPOINTS, [nodeId, implementerId]);
      return rows.map(rowToCheckpoint);
    },

    async appendCheckpoint(
      input: ImplementerCheckpointAppendInput,
    ): Promise<StoredImplementerCheckpoint> {
      if (input.checkpointEpoch <= 0n) {
        throw new ImplementerEventLogError("checkpoint_epoch must be positive");
      }
      if (input.implementerSeqHead < 0n) {
        throw new ImplementerEventLogError("implementer_seq_head must be non-negative");
      }
      if (typeof input.proofRepresentation !== "string" || input.proofRepresentation.length === 0) {
        throw new ImplementerEventLogError("proofRepresentation is required");
      }
      try {
        await query(INSERT_CHECKPOINT, [
          nodeId,
          input.implementerId,
          input.checkpointEpoch,
          input.implementerSeqHead,
          input.proofRepresentation,
          input.createdAt,
        ]);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (/unique|duplicate|23505/i.test(message)) {
          throw new ImplementerEventLogError(
            `checkpoint_epoch ${input.checkpointEpoch.toString()} already reserved`,
          );
        }
        throw error;
      }
      return Object.freeze({
        checkpointEpoch: input.checkpointEpoch,
        implementerSeqHead: input.implementerSeqHead,
        proofRepresentation: input.proofRepresentation,
        createdAt: input.createdAt,
      });
    },

    subscribe(
      implementerId: string,
      listener: (event: StoredImplementerEvent) => void,
    ): () => void {
      let set = listeners.get(implementerId);
      if (set === undefined) {
        set = new Set();
        listeners.set(implementerId, set);
      }
      set.add(listener);
      return () => {
        set?.delete(listener);
      };
    },
  };
}
