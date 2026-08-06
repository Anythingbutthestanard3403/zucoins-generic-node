// Composition binding: node-core lease repository → ReceiveLeasePort.
// receive/ is a boundary leaf and must not import leases; the shell injects this port.

import {
  acquireLeases,
  createLeaseGroup,
  type ReceiveLeasePort,
  type ReceiveAllocatorSqlExecutor,
} from "@zucoins/node-core";

export function createReceiveLeasePort(): ReceiveLeasePort {
  return {
    createLeaseGroup: async (db: ReceiveAllocatorSqlExecutor, rootOperationId: string) => {
      // INTERNAL_MOVE after_landing → PENDING so release refuses until
      // child MOVE joins the group (MARK_CHILD_JOINED on continuous handoff).
      // Op row is inserted before allocate (pool-allocator insertOperation first).
      const al = await db.query<{ after_landing: string | null }>(
        `SELECT after_landing::text AS after_landing FROM operations WHERE id = $1::uuid`,
        [rootOperationId],
      );
      const afterLanding = al.rows[0]?.after_landing ?? null;
      const childDisposition = afterLanding === "INTERNAL_MOVE" ? "PENDING" : "NONE";
      return createLeaseGroup(db, { rootOperationId, childDisposition });
    },
    acquireReceiveWindowLease: async (db, p) => {
      const [lease] = await acquireLeases(db, {
        wallets: [{ walletId: p.walletId, leaseRole: "RECEIVE_WINDOW" }],
        leaseGroupId: p.leaseGroupId,
        rootOperationId: p.operationId,
        operationId: p.operationId,
        ownerInstanceId: p.ownerInstanceId,
      });
      if (lease === undefined) {
        throw new Error("acquireLeases returned no RECEIVE_WINDOW membership");
      }
      return { membershipId: lease.membershipId, leaseEpoch: lease.leaseEpoch };
    },
  };
}
