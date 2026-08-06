// admin-mutation idempotency.
//
// The signed-reporting `reporting_mutation_idempotency` table is CHECK-locked to
// `('operation_armed','verification_complete')` and FK-bound to `reporting_request_nonces`, so
// it cannot serve admin-session mutations. This is the admin-surface equivalent: a completed
// mutation stores its exact HTTP status + response-body bytes in the same transaction as the
// mutation, keyed by `(node_id, route_id, idempotency_key)` + the raw request fingerprint
// (method, raw_target, body_sha256). Replay returns those bytes unchanged with
// `Idempotency-Replayed: true`; a reused key with a changed fingerprint is a 409 conflict.
//
// No pending row ("deferred commit-time correlation requires the completed row and exact
// child mutation to appear together"). The raw request target is compared byte-for-byte, never
// decoded or normalized.

import { createHash, randomUUID } from "node:crypto";
import type { Pool } from "pg";

export interface AdminIdempotencyFingerprint {
  readonly method: string;
  readonly rawTarget: string;
  readonly bodySha256: string;
}

export interface AdminIdempotencyCompletedRow {
  readonly responseStatus: number;
  readonly responseBytes: Buffer;
  readonly fingerprint: AdminIdempotencyFingerprint;
}

export interface AdminIdempotencyStore {
  ensureSchema(): Promise<void>;
  /** Find a completed row by (node_id, route_id, idempotency_key). Returns null if absent. */
  findCompleted(
    nodeId: string,
    routeId: string,
    idempotencyKey: string,
    tx?: { query(text: string, params?: readonly unknown[]): Promise<unknown> },
  ): Promise<AdminIdempotencyCompletedRow | null>;
  /** Insert the completed row in the same transaction as the mutation. Throws on UNIQUE violation. */
  recordCompleted(input: {
    readonly nodeId: string;
    readonly routeId: string;
    readonly idempotencyKey: string;
    readonly fingerprint: AdminIdempotencyFingerprint;
    readonly responseStatus: number;
    readonly responseBytes: Buffer;
    readonly tx?: { query(text: string, params?: readonly unknown[]): Promise<unknown> };
  }): Promise<void>;
}

export function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export class SqlAdminIdempotencyStore implements AdminIdempotencyStore {
  constructor(private readonly pool: Pool) {}

  async ensureSchema(): Promise<void> {
    // DDL owned by apps/generic-node/src/db/migrate.ts. No runtime DDL here.
  }

  async findCompleted(
    nodeId: string,
    routeId: string,
    idempotencyKey: string,
    tx?: { query(text: string, params?: readonly unknown[]): Promise<unknown> },
  ): Promise<AdminIdempotencyCompletedRow | null> {
    const executor = tx ?? this.pool;
    const result = await executor.query(
      `SELECT response_status, response_bytes, method, raw_target, body_sha256
         FROM admin_mutation_idempotency
        WHERE node_id = $1::uuid AND route_id = $2 AND idempotency_key = $3`,
      [nodeId, routeId, idempotencyKey],
    ) as { rows: Array<{
      response_status: number;
      response_bytes: Buffer;
      method: string;
      raw_target: string;
      body_sha256: string;
    }> };
    const { rows } = result;
    const row = rows[0];
    if (row === undefined) return null;
    return {
      responseStatus: row.response_status,
      responseBytes: row.response_bytes,
      fingerprint: { method: row.method, rawTarget: row.raw_target, bodySha256: row.body_sha256 },
    };
  }

  async recordCompleted(input: {
    readonly nodeId: string;
    readonly routeId: string;
    readonly idempotencyKey: string;
    readonly fingerprint: AdminIdempotencyFingerprint;
    readonly responseStatus: number;
    readonly responseBytes: Buffer;
    readonly tx?: { query(text: string, params?: readonly unknown[]): Promise<unknown> };
  }): Promise<void> {
    const q = `INSERT INTO admin_mutation_idempotency
      (id, node_id, route_id, idempotency_key, method, raw_target, body_sha256, response_status, response_bytes, completed_at)
      VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::int, $9::bytea, now())`;
    const params = [
      randomUUID(), input.nodeId, input.routeId, input.idempotencyKey,
      input.fingerprint.method, input.fingerprint.rawTarget, input.fingerprint.bodySha256,
      input.responseStatus, input.responseBytes,
    ];
    if (input.tx !== undefined) {
      await input.tx.query(q, params);
    } else {
      await this.pool.query(q, params);
    }
  }
}
