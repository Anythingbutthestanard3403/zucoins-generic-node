// Single mint composition: every production node_generated wallet insert also
// writes a destinations row in PENDING so the wallet is blessable without a
// second mint. Blessing stays dual-control; this file never stamps BLESSED.
//
// Callers own key generation and vault.seal (key-custody). This helper only
// writes wallets + destinations. Same executor for both inserts so a caller
// that already holds a transaction keeps them atomic.
//
// When `idempotencyKey` is set, both INSERTs MUST run on one already-open
// transaction client. The dest row is the first committed write that carries
// the key (partial UNIQUE on (node_id, idempotency_key)); a 23505 must
// ROLLBACK the whole pair so this attempt leaves no wallet and no dest.
// Pool / funding mints omit the key (NULL). Do not autocommit a keyed mint
// on a pool.

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
  $4, $5, $6, $7
)` as const;

export const INSERT_PENDING_DESTINATION_FOR_WALLET_SQL = `
INSERT INTO destinations (id, node_id, wallet_id, label, state, idempotency_key)
VALUES (gen_random_uuid(), $2::uuid, $1::uuid, $3, $4, $5)
ON CONFLICT (wallet_id) DO NOTHING` as const;

export const DELETE_PENDING_DESTINATION_FOR_WALLET_SQL = `
DELETE FROM destinations WHERE wallet_id = $1::uuid` as const;

export const DELETE_NODE_GENERATED_WALLET_SQL = `
DELETE FROM wallets WHERE id = $1::uuid` as const;

export type NodeGeneratedMintRole = "FULL" | "SEND_ONLY" | "RECEIVE_ONLY";

export interface InsertNodeGeneratedWalletInput {
  readonly walletId: string;
  readonly nodeId: string;
  readonly publicKey: string;
  /** Operator-facing destinations.label. Empty is valid; register overwrites. */
  readonly label?: string;
  /**
   * Register replay key. NULL when omitted (pool / funding / dest-on-mint).
   * When set, the caller MUST run this helper on one txn client so a unique
   * miss rolls back the wallet too.
   */
  readonly idempotencyKey?: string;
  /**
   * Default FULL (register / funding). Pool scaler passes SEND_ONLY (WORKER
   * dest, no blessing) or RECEIVE_ONLY (PENDING dest, blessable).
   */
  readonly role?: NodeGeneratedMintRole;
}

const ROLE_INSERT = {
  FULL: {
    allowReceive: true,
    allowSend: true,
    allowMove: true,
    moneyMode: "FULL",
    destState: "PENDING",
  },
  SEND_ONLY: {
    allowReceive: false,
    allowSend: true,
    allowMove: true,
    moneyMode: "SEND_ONLY",
    destState: "WORKER",
  },
  RECEIVE_ONLY: {
    allowReceive: true,
    allowSend: false,
    allowMove: true,
    moneyMode: "RECEIVE_ONLY",
    destState: "PENDING",
  },
} as const;

/**
 * Insert a node_generated wallet and a matching destinations row.
 * Default FULL+PENDING (blessable). SEND_ONLY writes WORKER (composition sink,
 * no ceremony). Idempotent on destinations.wallet_id (UNIQUE).
 */
export async function insertNodeGeneratedWalletWithPendingDestination(
  sql: NodeGeneratedWalletSqlExecutor,
  input: InsertNodeGeneratedWalletInput,
): Promise<void> {
  const spec = ROLE_INSERT[input.role ?? "FULL"];
  await sql.query(INSERT_NODE_GENERATED_WALLET_SQL, [
    input.walletId,
    input.nodeId,
    input.publicKey,
    spec.allowReceive,
    spec.allowSend,
    spec.allowMove,
    spec.moneyMode,
  ]);
  await sql.query(INSERT_PENDING_DESTINATION_FOR_WALLET_SQL, [
    input.walletId,
    input.nodeId,
    input.label ?? "",
    spec.destState,
    input.idempotencyKey ?? null,
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
