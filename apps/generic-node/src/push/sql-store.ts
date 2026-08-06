// Node-scoped SQL adapter for push_subscriptions.
//
// Every statement is bound by node_id like the rest of the v2 stores: a node must never
// read or mutate another node's subscriptions even when they share a database.

import type { Pool } from "pg";

import type {
  PushSubscriptionRow,
  PushSubscriptionStatus,
  PushSubscriptionStore,
  PushWalletRef,
} from "@zucoins/node-core";

interface Row {
  readonly wallet_id: string;
  readonly wallet_public_key: string;
  readonly endpoint_id: string;
  readonly receiver_ecdh_public: string;
  readonly receiver_ecdh_private_sealed: string;
  readonly receiver_auth_secret_sealed: string;
  readonly status: string;
}

function toRow(r: Row): PushSubscriptionRow {
  return {
    walletId: r.wallet_id,
    walletPublicKey: r.wallet_public_key,
    endpointId: r.endpoint_id,
    receiverEcdhPublic: r.receiver_ecdh_public,
    receiverEcdhPrivateSealed: r.receiver_ecdh_private_sealed,
    receiverAuthSecretSealed: r.receiver_auth_secret_sealed,
    status: r.status === "ACTIVE" ? "ACTIVE" : "FAILED",
  };
}

const SELECT_COLS = `wallet_id::text AS wallet_id,
       wallet_public_key,
       endpoint_id,
       receiver_ecdh_public,
       receiver_ecdh_private_sealed,
       receiver_auth_secret_sealed,
       status::text AS status`;

export function createSqlPushSubscriptionStore(
  pool: Pool,
  nodeId: string,
): PushSubscriptionStore {
  return {
    async findByWalletId(walletId) {
      const { rows } = await pool.query<Row>(
        `SELECT ${SELECT_COLS} FROM push_subscriptions
          WHERE wallet_id = $1::uuid AND node_id = $2::uuid LIMIT 1`,
        [walletId, nodeId],
      );
      return rows[0] === undefined ? null : toRow(rows[0]);
    },

    async findByEndpointId(endpointId) {
      const { rows } = await pool.query<Row>(
        `SELECT ${SELECT_COLS} FROM push_subscriptions
          WHERE endpoint_id = $1 AND node_id = $2::uuid LIMIT 1`,
        [endpointId, nodeId],
      );
      return rows[0] === undefined ? null : toRow(rows[0]);
    },

    async insert(row) {
      // ON CONFLICT DO NOTHING: two concurrent provisions for the same wallet must not
      // both insert, and the loser simply reuses the winner's row on its next read.
      await pool.query(
        `INSERT INTO push_subscriptions
           (wallet_id, node_id, wallet_public_key, endpoint_id, receiver_ecdh_public,
            receiver_ecdh_private_sealed, receiver_auth_secret_sealed, status)
         VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, 'FAILED')
         ON CONFLICT (wallet_id) DO NOTHING`,
        [
          row.walletId,
          nodeId,
          row.walletPublicKey,
          row.endpointId,
          row.receiverEcdhPublic,
          row.receiverEcdhPrivateSealed,
          row.receiverAuthSecretSealed,
        ],
      );
    },

    async replaceSealedMaterial(input) {
      // Re-mint recovery for a row whose envelopes no longer open. Status goes back to
      // FAILED (and subscribed_at to NULL, per the table's
      // (status = 'ACTIVE') = (subscribed_at IS NOT NULL) check) because the gateway still
      // holds the superseded public half until the next subscribe acknowledges this one.
      await pool.query(
        `UPDATE push_subscriptions
            SET receiver_ecdh_public = $3,
                receiver_ecdh_private_sealed = $4,
                receiver_auth_secret_sealed = $5,
                status = 'FAILED',
                subscribed_at = NULL,
                updated_at = now()
          WHERE wallet_id = $1::uuid AND node_id = $2::uuid`,
        [
          input.walletId,
          nodeId,
          input.receiverEcdhPublic,
          input.receiverEcdhPrivateSealed,
          input.receiverAuthSecretSealed,
        ],
      );
    },

    async markStatus(walletId, status: PushSubscriptionStatus, appServerPublicKey) {
      // subscribed_at is set on ACTIVE and cleared on FAILED to satisfy the table's
      // (status = 'ACTIVE') = (subscribed_at IS NOT NULL) check.
      await pool.query(
        `UPDATE push_subscriptions
            SET status = $3,
                app_server_public_key = COALESCE($4, app_server_public_key),
                subscribed_at = CASE WHEN $3 = 'ACTIVE' THEN now() ELSE NULL END,
                updated_at = now()
          WHERE wallet_id = $1::uuid AND node_id = $2::uuid`,
        [walletId, nodeId, status, appServerPublicKey],
      );
    },

    async listSubscribableWallets(): Promise<readonly PushWalletRef[]> {
      // Every live wallet of this node is subscribable: the invariant is that a wallet
      // always holds a subscription, so the sweep must see wallets that have no // contract-allow:sweep:frozen structural vocabulary
      // push_subscriptions row at all, not just existing rows.
      const { rows } = await pool.query<{ id: string; public_key: string }>(
        `SELECT id::text AS id, public_key
           FROM wallets
          WHERE node_id = $1::uuid AND retired_at IS NULL
          ORDER BY created_at`, // contract-allow:order:frozen structural vocabulary
        [nodeId],
      );
      return rows.map((r) => ({ walletId: r.id, publicKey: r.public_key }));
    },
  };
}
