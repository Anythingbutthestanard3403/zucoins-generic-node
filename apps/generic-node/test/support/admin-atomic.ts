import type {
  AdminMutationTxPorts,
  AdminRouteDeps,
} from "../../src/admin-router.js";
import type {
  AdminIdempotencyCompletedRow,
  AdminIdempotencyFingerprint,
  AdminIdempotencyStore,
} from "../../src/ops/admin-idempotency.js";

function key(nodeId: string, routeId: string, idempotencyKey: string): string {
  return `${nodeId}\u001f${routeId}\u001f${idempotencyKey}`;
}

function sameFingerprint(
  row: AdminIdempotencyCompletedRow,
  fingerprint: AdminIdempotencyFingerprint,
): boolean {
  return row.fingerprint.method === fingerprint.method &&
    row.fingerprint.rawTarget === fingerprint.rawTarget &&
    row.fingerprint.bodySha256 === fingerprint.bodySha256;
}

export class MemoryAdminIdempotencyStore implements AdminIdempotencyStore {
  readonly rows = new Map<string, AdminIdempotencyCompletedRow>();

  async ensureSchema(): Promise<void> {}

  async findCompleted(
    nodeId: string,
    routeId: string,
    idempotencyKey: string,
  ): Promise<AdminIdempotencyCompletedRow | null> {
    return this.rows.get(key(nodeId, routeId, idempotencyKey)) ?? null;
  }

  async recordCompleted(input: {
    readonly nodeId: string;
    readonly routeId: string;
    readonly idempotencyKey: string;
    readonly fingerprint: AdminIdempotencyFingerprint;
    readonly responseStatus: number;
    readonly responseBytes: Buffer;
  }): Promise<void> {
    const rowKey = key(input.nodeId, input.routeId, input.idempotencyKey);
    if (this.rows.has(rowKey)) {
      throw Object.assign(new Error("duplicate admin idempotency key"), { code: "23505" });
    }
    this.rows.set(rowKey, {
      fingerprint: input.fingerprint,
      responseStatus: input.responseStatus,
      responseBytes: Buffer.from(input.responseBytes),
    });
  }
}

/**
 * Unit-test executor for router behavior. Production uses the real PostgreSQL transaction
 * executor; its BEGIN/lock/rollback/restart/concurrency guarantees have their own PG suite.
 */
export function createTestAdminAtomicDeps(
  ports: Partial<AdminMutationTxPorts> = {},
): Pick<AdminRouteDeps, "adminIdempotencyStore" | "atomicAdminMutation"> & {
  readonly store: MemoryAdminIdempotencyStore;
} {
  const store = new MemoryAdminIdempotencyStore();
  const transactionPorts = ports as AdminMutationTxPorts;
  const atomicAdminMutation: NonNullable<AdminRouteDeps["atomicAdminMutation"]> = async (
    mutation,
    action,
  ) => {
    const completed = await store.findCompleted(
      mutation.nodeId,
      mutation.routeId,
      mutation.idempotencyKey,
    );
    if (completed !== null) {
      return sameFingerprint(completed, mutation.fingerprint)
        ? {
            outcome: "replay" as const,
            status: completed.responseStatus,
            responseBytes: Buffer.from(completed.responseBytes),
          }
        : { outcome: "conflict" as const };
    }

    const result = await action(transactionPorts);
    if (result.outcome === "abort") {
      return { outcome: "aborted" as const, response: result.response };
    }
    const responseBytes = Buffer.from(JSON.stringify(result.responseBody), "utf8");
    await store.recordCompleted({
      nodeId: mutation.nodeId,
      routeId: mutation.routeId,
      idempotencyKey: mutation.idempotencyKey,
      fingerprint: mutation.fingerprint,
      responseStatus: result.status,
      responseBytes,
    });
    result.afterCommit?.();
    return { outcome: "committed" as const, status: result.status, responseBytes };
  };
  return { store, adminIdempotencyStore: store, atomicAdminMutation };
}
