// SQL-backed DestinationStore for custody composition.
// Parameterized statements only — never string-concat untrusted ids into SQL text.

import type {
  DestinationFilter,
  DestinationRecord,
  DestinationStore,
  DestinationWalletFacts,
  NewDestination,
} from "./destination.js";
import type { Uuid, WalletPublicKey } from "../protocol/scalars.js";
import type { WalletKeyOrigin, WalletState } from "@zucoins/generic-node-contracts/custody";

export interface DestinationSqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[] }>;
}

const SELECT_DESTINATION = `
SELECT d.id, d.node_id, d.wallet_id, w.public_key AS wallet_public_key, d.state,
       d.label, d.blessed_at, d.blessed_by_device_key_id, d.blessing_artifact_id,
       d.retired_at, d.created_at
  FROM destinations d
  JOIN wallets w ON w.id = d.wallet_id
 WHERE d.id = $1`;

function mapRow(row: Record<string, unknown>): DestinationRecord {
  return {
    destinationId: String(row.id) as Uuid,
    nodeId: String(row.node_id) as Uuid,
    walletId: String(row.wallet_id) as Uuid,
    walletPublicKey: String(row.wallet_public_key) as WalletPublicKey,
    state: row.state as DestinationRecord["state"],
    label: row.label === null || row.label === undefined ? "" : String(row.label),
    blessedAt:
      row.blessed_at === null || row.blessed_at === undefined ? null : String(row.blessed_at),
    blessedByDeviceKeyId:
      row.blessed_by_device_key_id === null || row.blessed_by_device_key_id === undefined
        ? null
        : (String(row.blessed_by_device_key_id) as Uuid),
    blessingArtifactId:
      row.blessing_artifact_id === null || row.blessing_artifact_id === undefined
        ? null
        : (String(row.blessing_artifact_id) as Uuid),
    retiredAt:
      row.retired_at === null || row.retired_at === undefined ? null : String(row.retired_at),
    createdAt: String(row.created_at),
  };
}

/**
 * Live PG DestinationStore. Idempotency of register is service-layer:
 * destinations DDL has no idempotency_key column, so findByIdempotencyKey is
 * a no-op (null). Label is persisted on destinations.label (ZTR-1169).
 */
export function createSqlDestinationStore(sql: DestinationSqlExecutor): DestinationStore {
  return {
    async findById(destinationId) {
      const result = await sql.query(SELECT_DESTINATION, [destinationId]);
      const row = result.rows[0];
      return row === undefined ? null : mapRow(row);
    },

    async findByIdempotencyKey() {
      return null;
    },

    async insert(record: NewDestination) {
      await sql.query(
        `INSERT INTO destinations (id, node_id, wallet_id, label, state, created_at)
         VALUES ($1, $2, $3, $4, 'PENDING', $5::timestamptz)`,
        [
          record.destinationId,
          record.nodeId,
          record.walletId,
          record.label,
          record.createdAt,
        ],
      );
      return {
        ...record,
        state: "PENDING",
        blessedAt: null,
        blessedByDeviceKeyId: null,
        blessingArtifactId: null,
        retiredAt: null,
      };
    },

    async walletKeyOrigin(walletId) {
      const result = await sql.query<{ key_origin: string }>(
        `SELECT key_origin FROM wallets WHERE id = $1`,
        [walletId],
      );
      const row = result.rows[0];
      if (row === undefined) return null;
      return row.key_origin as WalletKeyOrigin;
    },

    async walletFacts(walletId): Promise<DestinationWalletFacts | null> {
      const result = await sql.query<{
        key_origin: string;
        state: string;
        recovery_verified_at: string | null;
      }>(
        `SELECT key_origin, state::text AS state,
                CASE WHEN recovery_verified_at IS NULL THEN NULL
                     ELSE to_char(recovery_verified_at AT TIME ZONE 'UTC',
                                  'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                END AS recovery_verified_at
           FROM wallets WHERE id = $1`,
        [walletId],
      );
      const row = result.rows[0];
      if (row === undefined) return null;
      return {
        keyOrigin: row.key_origin as WalletKeyOrigin,
        walletState: row.state as WalletState,
        recoveryVerifiedAt: row.recovery_verified_at,
      };
    },

    async bless(destinationId, patch) {
      const result = await sql.query(
        `UPDATE destinations
            SET state = 'BLESSED',
                blessed_at = $2::timestamptz,
                blessed_by_device_key_id = $3::uuid,
                blessing_artifact_id = $4::uuid
          WHERE id = $1 AND state = 'PENDING'
          RETURNING id`,
        [
          destinationId,
          patch.blessedAt,
          patch.blessedByDeviceKeyId,
          patch.blessingArtifactId,
        ],
      );
      if (result.rows.length === 0) return null;
      const loaded = await sql.query(SELECT_DESTINATION, [destinationId]);
      const row = loaded.rows[0];
      return row === undefined ? null : mapRow(row);
    },

    async retire(destinationId, retiredAt) {
      await sql.query(
        `UPDATE destinations
            SET state = 'RETIRED', retired_at = $2::timestamptz
          WHERE id = $1`,
        [destinationId, retiredAt],
      );
      const loaded = await sql.query(SELECT_DESTINATION, [destinationId]);
      const row = loaded.rows[0];
      if (row === undefined) {
        throw new Error("destination retire missed row");
      }
      return mapRow(row);
    },

    async list(nodeId, filter: DestinationFilter) {
      const limit = filter.limit ?? 20;
      const params: unknown[] = [nodeId];
      let stateClause = "";
      let afterClause = "";
      if (filter.state !== undefined) {
        params.push(filter.state);
        stateClause = ` AND d.state = $${params.length}`;
      }
      if (filter.after !== undefined) {
        params.push(filter.after);
        afterClause = ` AND d.id > $${params.length}`;
      }
      params.push(limit + 1);
      const limitIdx = params.length;
      const result = await sql.query(
        `SELECT d.id, d.node_id, d.wallet_id, w.public_key AS wallet_public_key, d.state,
                d.label, d.blessed_at, d.blessed_by_device_key_id, d.blessing_artifact_id,
                d.retired_at, d.created_at
           FROM destinations d
           JOIN wallets w ON w.id = d.wallet_id
          WHERE d.node_id = $1${stateClause}${afterClause}
          ORDER BY d.id -- contract-allow:order:frozen structural vocabulary
          LIMIT $${limitIdx}`,
        params,
      );
      const rows = result.rows.map(mapRow);
      const items = rows.slice(0, limit);
      const nextAfter =
        rows.length > limit ? (items[items.length - 1]?.destinationId ?? null) : null;
      return { items, nextAfter };
    },
  };
}
