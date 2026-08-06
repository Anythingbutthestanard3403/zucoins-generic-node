// PostgreSQL adapter for EventListStore over the frozen event-ledger.sql DDL
// (node_event_seq_counters + node_events). No driver is linked — statements go through
// an injected SqlQueryFn (same pattern as submit-decision-claim-store / move-internal-landing).

import type { NodeEventType } from "../protocol/suite/index.js";
import {
  EventLogError,
  type AppendEventsOutcome,
  type EventListStore,
  type EventRecord,
  type EventStreamTail,
} from "./store.js";

export type SqlQueryFn = (
  text: string,
  values: readonly unknown[],
) => Promise<readonly Record<string, unknown>[]>;

export type SqlTxFn = <T>(body: (query: SqlQueryFn) => Promise<T>) => Promise<T>;

const READ_TAIL = `
SELECT c.next_seq AS next_seq,
       e.event_hash AS last_event_hash
  FROM node_event_seq_counters c
  LEFT JOIN node_events e ON e.node_id = c.node_id AND e.seq = c.next_seq - 1
 WHERE c.node_id = $1::uuid
`;

const ENSURE_COUNTER = `
INSERT INTO node_event_seq_counters (node_id, next_seq)
VALUES ($1::uuid, 1)
ON CONFLICT (node_id) DO NOTHING
`;

const LOCK_COUNTER = `
SELECT next_seq FROM node_event_seq_counters
 WHERE node_id = $1::uuid
 FOR UPDATE
`;

const ADVANCE_COUNTER = `
UPDATE node_event_seq_counters
   SET next_seq = $2::bigint
 WHERE node_id = $1::uuid AND next_seq = $3::bigint
 RETURNING next_seq
`;

/**
 * Take the FOR UPDATE lock on this node's event-seq counter row without reading or
 * advancing it.: a caller that must serialize a quota probe (or any other
 * counter-gated read) against a concurrent append takes this lock BEFORE doing that read, so
 * no reader can observe a pre-lock snapshot while another writer is mid-append in the same
 * counter row. appendBatch below re-acquires the same row lock later in the same
 * transaction — a no-op, since Postgres allows a transaction to re-lock a row it already
 * holds.
 */
export async function lockNodeEventCounter(query: SqlQueryFn, nodeId: string): Promise<void> {
  await query(ENSURE_COUNTER, [nodeId]);
  await query(LOCK_COUNTER, [nodeId]);
}

const INSERT_EVENT = `
INSERT INTO node_events (
  seq, event_id, purpose, canonical_version, node_id, operation_id, wallet_id,
  event_type, data_text, data_sha256, preimage_text, preimage_sha256,
  signing_key_id, signature, previous_event_hash, event_hash, created_at
) VALUES (
  $1::bigint, $2::uuid, $3::text, $4::integer, $5::uuid, $6::uuid, $7::uuid,
  $8::text, $9::text, $10::text, $11::text, $12::text,
  $13::uuid, $14::text, $15::text, $16::text, $17::timestamptz
)
`;

const SCAN_AFTER = `
SELECT seq, event_id, purpose, canonical_version, node_id, operation_id, wallet_id,
       event_type, data_text, data_sha256, preimage_text, preimage_sha256,
       signing_key_id, signature, previous_event_hash, event_hash, created_at
  FROM node_events
 WHERE node_id = $1::uuid AND seq > $2::bigint
 ORDER BY seq ASC -- contract-allow:order:frozen-sql-text
 LIMIT $3::integer
`;

const FIND_SEQ = `
SELECT seq, event_id, purpose, canonical_version, node_id, operation_id, wallet_id,
       event_type, data_text, data_sha256, preimage_text, preimage_sha256,
       signing_key_id, signature, previous_event_hash, event_hash, created_at
  FROM node_events
 WHERE node_id = $1::uuid AND seq = $2::bigint
`;

function asBigint(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(value);
  if (typeof value === "string") return BigInt(value);
  throw new EventLogError(`expected bigint-compatible value, got ${typeof value}`);
}

function asString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  if (value instanceof Date) return value.toISOString();
  throw new EventLogError(`expected string, got ${typeof value}`);
}

function asStringOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return asString(value);
}

function rowToRecord(row: Record<string, unknown>): EventRecord {
  return Object.freeze({
    seq: asBigint(row.seq),
    eventId: asString(row.event_id),
    purpose: "zp-node-event-v1" as const,
    canonicalVersion: 1 as const,
    nodeId: asString(row.node_id),
    operationId: asStringOrNull(row.operation_id),
    walletId: asStringOrNull(row.wallet_id),
    eventType: asString(row.event_type) as NodeEventType,
    dataText: asString(row.data_text),
    dataSha256: asString(row.data_sha256),
    preimageText: asString(row.preimage_text),
    preimageSha256: asString(row.preimage_sha256),
    signingKeyId: asString(row.signing_key_id),
    signature: asString(row.signature),
    previousEventHash: asStringOrNull(row.previous_event_hash),
    eventHash: asString(row.event_hash),
    createdAt:
      row.created_at instanceof Date
        ? row.created_at.toISOString()
        : asString(row.created_at),
  });
}

export interface PgEventListStoreConfig {
  readonly query: SqlQueryFn;
  readonly withTransaction: SqlTxFn;
}

export function createPgEventListStore(config: PgEventListStoreConfig): EventListStore {
  const { query, withTransaction } = config;

  const readTail = async (nodeId: string): Promise<EventStreamTail> => {
    await query(ENSURE_COUNTER, [nodeId]);
    const rows = await query(READ_TAIL, [nodeId]);
    const row = rows[0];
    if (row === undefined) {
      return { highWater: 0n, lastEventHash: null };
    }
    const nextSeq = asBigint(row.next_seq);
    return {
      highWater: nextSeq - 1n,
      lastEventHash: asStringOrNull(row.last_event_hash),
    };
  };

  const appendBatch = async (
    nodeId: string,
    batch: readonly EventRecord[],
    expectedHighWater: bigint,
  ): Promise<AppendEventsOutcome> => {
    if (batch.length === 0) {
      return { kind: "APPENDED", records: [] };
    }
    return withTransaction(async (tx) => {
      await tx(ENSURE_COUNTER, [nodeId]);
      const locked = await tx(LOCK_COUNTER, [nodeId]);
      const lockRow = locked[0];
      if (lockRow === undefined) {
        throw new EventLogError("counter row missing after ensure");
      }
      const currentNext = asBigint(lockRow.next_seq);
      const currentHighWater = currentNext - 1n;
      if (currentHighWater !== expectedHighWater) {
        return { kind: "STALE_TAIL" };
      }
      let expectedSeq = expectedHighWater + 1n;
      for (const record of batch) {
        if (record.nodeId !== nodeId || record.seq !== expectedSeq) {
          throw new EventLogError("append batch seq/node mismatch under lock");
        }
        await tx(INSERT_EVENT, [
          record.seq.toString(),
          record.eventId,
          record.purpose,
          record.canonicalVersion,
          record.nodeId,
          record.operationId,
          record.walletId,
          record.eventType,
          record.dataText,
          record.dataSha256,
          record.preimageText,
          record.preimageSha256,
          record.signingKeyId,
          record.signature,
          record.previousEventHash,
          record.eventHash,
          record.createdAt,
        ]);
        expectedSeq += 1n;
      }
      const newNext = expectedHighWater + BigInt(batch.length) + 1n;
      const advanced = await tx(ADVANCE_COUNTER, [
        nodeId,
        newNext.toString(),
        currentNext.toString(),
      ]);
      if (advanced[0] === undefined) {
        return { kind: "STALE_TAIL" };
      }
      return { kind: "APPENDED", records: batch };
    });
  };

  const scanAfter = async (
    nodeId: string,
    afterSeq: bigint | null,
    limit: number,
  ): Promise<readonly EventRecord[]> => {
    const after = afterSeq ?? 0n;
    const rows = await query(SCAN_AFTER, [nodeId, after.toString(), limit]);
    return rows.map(rowToRecord);
  };

  const find = async (nodeId: string, seq: bigint): Promise<EventRecord | null> => {
    const rows = await query(FIND_SEQ, [nodeId, seq.toString()]);
    const row = rows[0];
    return row === undefined ? null : rowToRecord(row);
  };

  return { readTail, appendBatch, scanAfter, find };
}
