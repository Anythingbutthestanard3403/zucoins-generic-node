// App wrapper for GN-102. Key sealing stays here; node-core owns the rows.
// The advisory lock is not held across seal.

import type { Pool } from "pg";

import {
  ensureNodeReserveAndWorkerPool,
  mintNamedReserveWallet,
  type EncryptedWalletKeyStore,
  type EnsureNodeReserveDeps,
  type Uuid,
  type WalletPublicKey,
} from "@zucoins/node-core";

export interface ReservePoolControllerInput {
  readonly pool: Pool;
  readonly nodeId: string;
  readonly poolCapTotal: number;
  readonly vault: EncryptedWalletKeyStore;
  readonly onWalletsMinted?: (walletIds: readonly string[]) => void;
}

type ReserveSql = Parameters<EnsureNodeReserveDeps["withTx"]>[0] extends (
  sql: infer S,
) => Promise<unknown>
  ? S
  : never;

async function queryRows<R extends Record<string, unknown>>(
  run: (text: string, params?: readonly unknown[]) => Promise<{ rows: unknown[]; rowCount?: number | null }>,
  text: string,
  params?: readonly unknown[],
): Promise<{ rows: R[]; rowCount: number | null }> {
  const outcome = await run(text, params);
  return {
    rows: outcome.rows as R[],
    rowCount: outcome.rowCount ?? null,
  };
}

async function withClientTx<T>(pool: Pool, body: (sql: ReserveSql) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await body({
      query: (text, params) =>
        queryRows(
          (sql, values) => client.query(sql, values as never[]),
          text,
          params,
        ),
    } as ReserveSql);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* session may already be aborted */
    }
    throw err;
  } finally {
    client.release();
  }
}

export function createReservePoolController(input: ReservePoolControllerInput): {
  readonly ensure: () => Promise<void>;
  readonly mintNamed: (displayLabel: string) => Promise<{
    readonly walletId: string;
    readonly moneyMode: "INTERNAL_ONLY";
    readonly displayLabel: string;
    readonly destinationState: "BLESSED";
  }>;
} {
  const deps: EnsureNodeReserveDeps = {
    nodeId: input.nodeId,
    poolCapTotal: input.poolCapTotal,
    withTx: (fn) => withClientTx(input.pool, fn),
    query: (text, params) =>
      queryRows(
        (sql, values) => input.pool.query(sql, values as never[]),
        text,
        params,
      ),
    seal: async (minted) => {
      await input.vault.seal(
        {
          nodeId: input.nodeId as Uuid,
          walletId: minted.walletId as Uuid,
          keyVersion: 1,
          publicKey: minted.publicKey as WalletPublicKey,
          keyOrigin: "node_generated",
        },
        minted.secret,
      );
    },
    onWalletsMinted: input.onWalletsMinted,
  };
  return {
    ensure: async () => {
      await ensureNodeReserveAndWorkerPool(deps);
    },
    mintNamed: (displayLabel) => mintNamedReserveWallet({ ...deps, displayLabel }),
  };
}
