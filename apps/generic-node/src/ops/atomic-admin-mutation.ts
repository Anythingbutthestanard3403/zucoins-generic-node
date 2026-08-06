import type { Pool, PoolClient } from "pg";

import type {
  AdminIdempotencyCompletedRow,
  AdminIdempotencyFingerprint,
  AdminIdempotencyStore,
} from "./admin-idempotency.js";
import { isAdminIdempotencyUniqueViolation } from "./admin-idempotency-guard.js";

export type AtomicAdminMutationAction<TPorts, TAbort> = (
  ports: TPorts,
) => Promise<
  | {
      readonly outcome: "commit";
      readonly status: number;
      readonly responseBody: unknown;
      readonly afterCommit?: () => void;
    }
  | { readonly outcome: "abort"; readonly response: TAbort }
>;

export type AtomicAdminMutationResult<TAbort> =
  | { readonly outcome: "committed"; readonly status: number; readonly responseBytes: Buffer }
  | { readonly outcome: "replay"; readonly status: number; readonly responseBytes: Buffer }
  | { readonly outcome: "conflict" }
  | { readonly outcome: "aborted"; readonly response: TAbort };

export interface AtomicAdminMutationInput {
  readonly nodeId: string;
  readonly routeId: string;
  readonly idempotencyKey: string;
  readonly fingerprint: AdminIdempotencyFingerprint;
}

function sameFingerprint(
  row: AdminIdempotencyCompletedRow,
  fingerprint: AdminIdempotencyFingerprint,
): boolean {
  return row.fingerprint.method === fingerprint.method &&
    row.fingerprint.rawTarget === fingerprint.rawTarget &&
    row.fingerprint.bodySha256 === fingerprint.bodySha256;
}

/**
 * One transaction owns the per-key advisory lock, the route child effect, and the exact
 * response row. The lock makes a concurrent same-key loser wait and re-check before auth/TOTP;
 * it therefore replays the winner without burning another factor or running another effect.
 */
export function createAtomicAdminMutationExecutor<TPorts>(input: {
  readonly pool: Pool;
  readonly idempotencyStore: AdminIdempotencyStore;
  readonly portsFor: (client: PoolClient) => TPorts;
}): <TAbort>(
  mutation: AtomicAdminMutationInput,
  action: AtomicAdminMutationAction<TPorts, TAbort>,
) => Promise<AtomicAdminMutationResult<TAbort>> {
  return async <TAbort>(mutation: AtomicAdminMutationInput, action: AtomicAdminMutationAction<TPorts, TAbort>) => {
    const client = await input.pool.connect();
    let afterCommit: (() => void) | undefined;
    try {
      await client.query("BEGIN");
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        [`${mutation.nodeId}\u001f${mutation.routeId}\u001f${mutation.idempotencyKey}`],
      );
      const completed = await input.idempotencyStore.findCompleted(
        mutation.nodeId,
        mutation.routeId,
        mutation.idempotencyKey,
        client,
      );
      if (completed !== null) {
        await client.query("COMMIT");
        return sameFingerprint(completed, mutation.fingerprint)
          ? { outcome: "replay", status: completed.responseStatus, responseBytes: completed.responseBytes }
          : { outcome: "conflict" };
      }

      const result = await action(input.portsFor(client));
      if (result.outcome === "abort") {
        await client.query("ROLLBACK");
        return { outcome: "aborted", response: result.response };
      }
      const responseBytes = Buffer.from(JSON.stringify(result.responseBody), "utf8");
      await input.idempotencyStore.recordCompleted({
        nodeId: mutation.nodeId,
        routeId: mutation.routeId,
        idempotencyKey: mutation.idempotencyKey,
        fingerprint: mutation.fingerprint,
        responseStatus: result.status,
        responseBytes,
        tx: client,
      });
      afterCommit = result.afterCommit;
      await client.query("COMMIT");
      afterCommit?.();
      return { outcome: "committed", status: result.status, responseBytes };
    } catch (err) {
      try { await client.query("ROLLBACK"); } catch { /* retain original */ }
      if (!isAdminIdempotencyUniqueViolation(err)) throw err;
      const winner = await input.idempotencyStore.findCompleted(
        mutation.nodeId,
        mutation.routeId,
        mutation.idempotencyKey,
      );
      if (winner === null) throw err;
      return sameFingerprint(winner, mutation.fingerprint)
        ? { outcome: "replay", status: winner.responseStatus, responseBytes: winner.responseBytes }
        : { outcome: "conflict" };
    } finally {
      client.release();
    }
  };
}