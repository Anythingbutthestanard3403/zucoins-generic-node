// Single mint composition: every production node_generated wallet insert also
// writes a destinations row in PENDING so the wallet is blessable without a
// second mint. Blessing stays dual-control; this file never stamps BLESSED.
//
// Callers own key generation and vault.seal (key-custody). This helper only
// writes wallets + destinations. Same executor for both inserts so a caller
// that already holds a transaction keeps them atomic.

export interface NodeGeneratedWalletSqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[]; rowCount?: number | null }>;
}

export const INSERT_NODE_GENERATED_WALLET_SQL = `
INSERT INTO wallets (
  id, node_id, public_key, key_origin, state,
  allow_external_receive, allow_external_send, allow_internal_move, money_mode
) VALUES (
  $1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE',
  true, true, true, 'FULL'
)` as const;

export const INSERT_PENDING_DESTINATION_FOR_WALLET_SQL = `
INSERT INTO destinations (id, node_id, wallet_id, label, state)
VALUES (gen_random_uuid(), $2::uuid, $1::uuid, $3, 'PENDING')
ON CONFLICT (wallet_id) DO NOTHING` as const;

export const DELETE_PENDING_DESTINATION_FOR_WALLET_SQL = `
DELETE FROM destinations WHERE wallet_id = $1::uuid` as const;

export const DELETE_NODE_GENERATED_WALLET_SQL = `
DELETE FROM wallets WHERE id = $1::uuid` as const;

export interface InsertNodeGeneratedWalletInput {
  readonly walletId: string;
  readonly nodeId: string;
  readonly publicKey: string;
  /** Operator-facing destinations.label. Empty is valid; register overwrites. */
  readonly label?: string;
}

/**
 * Insert a node_generated wallet and a matching PENDING destinations row.
 * Idempotent on destinations.wallet_id (UNIQUE) so a later register insert
 * cannot create a second row.
 */
export async function insertNodeGeneratedWalletWithPendingDestination(
  sql: NodeGeneratedWalletSqlExecutor,
  input: InsertNodeGeneratedWalletInput,
): Promise<void> {
  await sql.query(INSERT_NODE_GENERATED_WALLET_SQL, [
    input.walletId,
    input.nodeId,
    input.publicKey,
  ]);
  await sql.query(INSERT_PENDING_DESTINATION_FOR_WALLET_SQL, [
    input.walletId,
    input.nodeId,
    input.label ?? "",
  ]);
}

/**
 * Compensate a failed mint (vault.seal miss, etc.). Destinations first:
 * destinations.wallet_id REFERENCES wallets(id) without ON DELETE CASCADE.
 */
export async function deleteNodeGeneratedWalletMint(
  sql: NodeGeneratedWalletSqlExecutor,
  walletId: string,
): Promise<void> {
  await sql.query(DELETE_PENDING_DESTINATION_FOR_WALLET_SQL, [walletId]);
  await sql.query(DELETE_NODE_GENERATED_WALLET_SQL, [walletId]);
}
