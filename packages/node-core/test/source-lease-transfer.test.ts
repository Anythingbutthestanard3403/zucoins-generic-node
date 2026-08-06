// unit: continuous source-lease transfer guards + composition shape.
// Real-PG crash/concurrency proofs live in source-lease-transfer.pg.test.ts.

import { describe, expect, it } from "vitest";

import { STATEMENTS } from "../src/leases/index.js";
import type { ActiveLeaseRow, SqlExecutor, SqlQueryResult } from "../src/leases/index.js";
import {
  HANDOFF_CHILD_ROLE,
  HANDOFF_PARENT_ROLE,
  transferSourceReceiveToMove,
} from "../src/move/source-lease-transfer.js";

const WALLET = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const GROUP = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PARENT = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const CHILD = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const OWNER = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const MEMBERSHIP = "ffffffff-ffff-4fff-8fff-ffffffffffff";

function activeRow(over: Partial<ActiveLeaseRow> = {}): ActiveLeaseRow {
  return {
    wallet_id: WALLET,
    membership_id: MEMBERSHIP,
    lease_group_id: GROUP,
    root_operation_id: PARENT,
    operation_id: PARENT,
    lease_role: HANDOFF_PARENT_ROLE,
    lease_epoch: "1",
    acquired_at: "2026-07-28T00:00:00.000Z",
    heartbeat_at: "2026-07-28T00:00:00.000Z",
    owner_instance_id: OWNER,
    release_not_before: null,
    ...over,
  };
}

class FakeDb implements SqlExecutor {
  active: ActiveLeaseRow | null = activeRow();
  readonly calls: string[] = [];

  async query<R>(text: string, _params?: readonly unknown[]): Promise<SqlQueryResult<R>> {
    this.calls.push(text);
    if (text === STATEMENTS.SELECT_ACTIVE) {
      return {
        rows: this.active === null ? [] : ([this.active] as R[]),
        rowCount: this.active === null ? 0 : 1,
      };
    }
    // Any mutator path is unreachable in the pure-guard tests below.
    throw new Error(`unexpected query in guard test: ${text.slice(0, 60)}`);
  }
}

describe("transferSourceReceiveToMove guards", () => {
  it("rejects identical parent/child operation ids", async () => {
    const db = new FakeDb();
    const result = await transferSourceReceiveToMove(db, {
      walletId: WALLET,
      ownerInstanceId: OWNER,
      leaseGroupId: GROUP,
      parentOperationId: PARENT,
      childOperationId: PARENT,
      landingProofDigest: "a".repeat(64),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("CHILD_OPERATION_IS_PARENT");
  });

  it("rejects missing active lease", async () => {
    const db = new FakeDb();
    db.active = null;
    const result = await transferSourceReceiveToMove(db, {
      walletId: WALLET,
      ownerInstanceId: OWNER,
      leaseGroupId: GROUP,
      parentOperationId: PARENT,
      childOperationId: CHILD,
      landingProofDigest: "a".repeat(64),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("NO_ACTIVE_LEASE");
  });

  it("idempotent when already MOVE_SOURCE for the child", async () => {
    const db = new FakeDb();
    db.active = activeRow({
      operation_id: CHILD,
      lease_role: HANDOFF_CHILD_ROLE,
      lease_epoch: "2",
      membership_id: "11111111-1111-4111-8111-111111111111",
    });
    const result = await transferSourceReceiveToMove(db, {
      walletId: WALLET,
      ownerInstanceId: OWNER,
      leaseGroupId: GROUP,
      parentOperationId: PARENT,
      childOperationId: CHILD,
      landingProofDigest: "a".repeat(64),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe("ALREADY_TRANSFERRED");
    expect(result.transferred.leaseRole).toBe(HANDOFF_CHILD_ROLE);
    expect(result.transferred.operationId).toBe(CHILD);
    expect(result.acquiredAtBefore).toBe(result.acquiredAtAfter);
  });

  it("rejects wrong parent holder", async () => {
    const db = new FakeDb();
    db.active = activeRow({ operation_id: "99999999-9999-4999-8999-999999999999" });
    const result = await transferSourceReceiveToMove(db, {
      walletId: WALLET,
      ownerInstanceId: OWNER,
      leaseGroupId: GROUP,
      parentOperationId: PARENT,
      childOperationId: CHILD,
      landingProofDigest: "a".repeat(64),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("NOT_PARENT_LEASE_HOLDER");
  });

  it("rejects non-RECEIVE_WINDOW parent role", async () => {
    const db = new FakeDb();
    db.active = activeRow({ lease_role: "SEND_SOURCE" });
    const result = await transferSourceReceiveToMove(db, {
      walletId: WALLET,
      ownerInstanceId: OWNER,
      leaseGroupId: GROUP,
      parentOperationId: PARENT,
      childOperationId: CHILD,
      landingProofDigest: "a".repeat(64),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("PARENT_ROLE_NOT_RECEIVE");
  });

  it("rejects lease group mismatch", async () => {
    const db = new FakeDb();
    db.active = activeRow({ lease_group_id: "99999999-9999-4999-8999-999999999999" });
    const result = await transferSourceReceiveToMove(db, {
      walletId: WALLET,
      ownerInstanceId: OWNER,
      leaseGroupId: GROUP,
      parentOperationId: PARENT,
      childOperationId: CHILD,
      landingProofDigest: "a".repeat(64),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("LEASE_GROUP_MISMATCH");
  });

  it("rejects foreign owner instance", async () => {
    const db = new FakeDb();
    db.active = activeRow({ owner_instance_id: "99999999-9999-4999-8999-999999999999" });
    const result = await transferSourceReceiveToMove(db, {
      walletId: WALLET,
      ownerInstanceId: OWNER,
      leaseGroupId: GROUP,
      parentOperationId: PARENT,
      childOperationId: CHILD,
      landingProofDigest: "a".repeat(64),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("LEASE_OWNER_MISMATCH");
  });
});
