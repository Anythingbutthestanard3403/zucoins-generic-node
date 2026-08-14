// Atomic child MOVE_INTERNAL creation.
//
// Store double models the partial UNIQUE on spawned_from_operation_id and lease-group
// bookkeeping. Real-PostgreSQL enforcement lives in child-move-create.pg.test.ts.

import { describe, expect, it } from "vitest";

import {
  createChildMoveAtomically,
  type ChildMoveCreateStore,
  type ChildMoveInsertInput,
  type ChildMoveInsertOutcome,
  type ChildMoveRecord,
  type ChildMoveTx,
  type LandedParentReceive,
} from "../src/move/child-create.js";
import type {
  MoveDestinationRecord,
  MoveSourceWalletRecord,
} from "../src/move/create.js";
import { MOVE_OPERATION_KIND } from "../src/move/create.js";
import { CHILD_MOVE_STATEMENTS } from "../src/move/child-create-sql.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const PARENT_OP_ID = "33333333-3333-4333-8333-333333333333";
const LEASE_GROUP_ID = "44444444-4444-4444-8444-444444444444";
const RECEIVER_WALLET = "55555555-5555-4555-8555-555555555555";
const DEST_WALLET = "66666666-6666-4666-8666-666666666666";
const DESTINATION_ID = "77777777-7777-4777-8777-777777777777";
const CHILD_OP_ID = "88888888-8888-4888-8888-888888888888";
const CHILD_OP_ID_B = "99999999-9999-4999-8999-999999999999";
const SOURCE_PUBKEY = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DEST_PUBKEY = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";

const PINNED_SOURCE: MoveSourceWalletRecord = {
  walletId: RECEIVER_WALLET,
  nodeId: NODE_ID,
  publicKey: SOURCE_PUBKEY,
  keyOrigin: "node_generated",
  state: "PINNED",
  allowInternalMove: true,
};

const ELIGIBLE_DESTINATION: MoveDestinationRecord = {
  destinationId: DESTINATION_ID,
  nodeId: NODE_ID,
  walletId: DEST_WALLET,
  publicKey: DEST_PUBKEY,
  keyOrigin: "node_generated",
  walletState: "AVAILABLE",
  destinationState: "BLESSED",
  recoveryVerifiedAt: "2026-07-01T00:00:00.000Z",
  allowInternalMove: true,
};

const LANDED_PARENT: LandedParentReceive = {
  parentOperationId: PARENT_OP_ID,
  implementerId: IMPLEMENTER_ID,
  nodeId: NODE_ID,
  amountZkz: "1.5",
  receiverWalletId: RECEIVER_WALLET,
  status: "RECEIVE_LANDED",
  afterLanding: "INTERNAL_MOVE",
  afterLandingDestinationId: DESTINATION_ID,
  leaseGroupId: LEASE_GROUP_ID,
  verificationMode: "INDEPENDENT",
};

/** Constraint-accurate store double: UNIQUE spawned_from_operation_id + lease join. */
class ConstraintStore implements ChildMoveCreateStore {
  parent: LandedParentReceive | null = { ...LANDED_PARENT };
  source: MoveSourceWalletRecord | null = { ...PINNED_SOURCE };
  destination: MoveDestinationRecord | null = { ...ELIGIBLE_DESTINATION };
  readonly childrenByParent = new Map<string, ChildMoveRecord>();
  readonly operations = new Map<string, ChildMoveRecord>();
  readonly groupOps = new Map<string, string>(); // operationId → leaseGroupId
  readonly leaseGroups = new Map<string, { root: string; childDisposition: string }>([
    [LEASE_GROUP_ID, { root: PARENT_OP_ID, childDisposition: "PENDING" }],
  ]);
  readonly events: string[] = [];
  insertCalls = 0;
  /** Artificial hold so concurrent insertChild callers can race past findChildByParent. */
  holdInsert: Promise<void> | null = null;
  releaseInsert: (() => void) | null = null;

  armInsertGate(): void {
    this.holdInsert = new Promise<void>((resolve) => {
      this.releaseInsert = resolve;
    });
  }

  async withTransaction<T>(body: (tx: ChildMoveTx) => Promise<T>): Promise<T> {
    // Single-flight serialization approximates SERIALIZABLE for the unit double unless a
    // concurrent gate is armed — then insertChild waits so races reach the UNIQUE arbiter.
    const tx: ChildMoveTx = {
      loadParent: async (id) =>
        this.parent !== null && this.parent.parentOperationId === id ? this.parent : null,
      loadSourceWallet: async (id) =>
        this.source !== null && this.source.walletId === id ? this.source : null,
      loadDestination: async (id) =>
        this.destination !== null && this.destination.destinationId === id
          ? this.destination
          : null,
      insertChild: async (input) => this.insertChild(input),
      findChildByParent: async (parentId) => this.childrenByParent.get(parentId) ?? null,
      joinParentLeaseGroup: async ({ leaseGroupId, childOperationId }) => {
        const group = this.leaseGroups.get(leaseGroupId);
        if (group === undefined) throw new Error("parent lease group missing");
        this.groupOps.set(childOperationId, leaseGroupId);
        if (group.childDisposition === "PENDING") {
          this.leaseGroups.set(leaseGroupId, { ...group, childDisposition: "JOINED" });
        }
        const child = this.operations.get(childOperationId);
        if (child !== undefined) {
          const joined: ChildMoveRecord = { ...child, leaseGroupId };
          this.operations.set(childOperationId, joined);
          this.childrenByParent.set(child.spawnedFromOperationId, joined);
        }
      },
      appendCreatedEvent: async ({ operationId }) => {
        this.events.push(operationId);
      },
    };
    return body(tx);
  }

  private async insertChild(input: ChildMoveInsertInput): Promise<ChildMoveInsertOutcome> {
    this.insertCalls += 1;
    if (this.holdInsert !== null) {
      await this.holdInsert;
    }
    const existing = this.childrenByParent.get(input.spawnedFromOperationId);
    if (existing !== undefined) {
      return { kind: "SPAWN_CONFLICT", existingOperationId: existing.operationId };
    }
    const dest = this.destination;
    if (dest === null) throw new Error("destination required for insert");
    const child: ChildMoveRecord = {
      operationId: input.operationId,
      kind: MOVE_OPERATION_KIND,
      status: "CREATED",
      implementerId: input.implementerId,
      nodeId: input.nodeId,
      amountZkz: input.amountZkz,
      sourceWalletId: input.sourceWalletId,
      destinationId: input.destinationId,
      destinationWalletId: dest.walletId,
      spawnedFromOperationId: input.spawnedFromOperationId,
      referencesOperationId: input.spawnedFromOperationId,
      leaseGroupId: input.leaseGroupId,
      idempotencyKey: input.idempotencyKey,
      requestSha256: input.requestSha256,
      verificationMode: input.verificationMode,
      createdAt: Date.parse(input.createdAtIso),
    };
    this.operations.set(child.operationId, child);
    this.childrenByParent.set(input.spawnedFromOperationId, child);
    return { kind: "INSERTED" };
  }
}

const FIXED_NOW = 1_700_000_000_000;

function create(store: ConstraintStore, parentId = PARENT_OP_ID, childId = CHILD_OP_ID) {
  return createChildMoveAtomically(store, parentId, {
    generateId: () => childId,
    now: () => FIXED_NOW,
  });
}

describe("createChildMoveAtomically", () => {
  it("creates one MOVE_INTERNAL/CREATED joined to the parent lease group", async () => {
    const store = new ConstraintStore();
    const result = await create(store);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.outcome).toBe("CREATED");
    expect(result.child.kind).toBe("MOVE_INTERNAL");
    expect(result.child.status).toBe("CREATED");
    expect(result.child.amountZkz).toBe("1.5");
    expect(result.child.sourceWalletId).toBe(RECEIVER_WALLET);
    expect(result.child.destinationId).toBe(DESTINATION_ID);
    expect(result.child.spawnedFromOperationId).toBe(PARENT_OP_ID);
    expect(result.child.referencesOperationId).toBe(PARENT_OP_ID);
    expect(result.child.leaseGroupId).toBe(LEASE_GROUP_ID);
    expect(result.child.idempotencyKey).toBe(PARENT_OP_ID);
    expect(store.leaseGroups.size).toBe(1);
    expect(store.leaseGroups.get(LEASE_GROUP_ID)?.childDisposition).toBe("JOINED");
    expect(store.groupOps.get(CHILD_OP_ID)).toBe(LEASE_GROUP_ID);
    expect(store.events).toEqual([CHILD_OP_ID]);
    expect(store.childrenByParent.size).toBe(1);
  });

  it("rejects when parent receive has not landed", async () => {
    const store = new ConstraintStore();
    store.parent = { ...LANDED_PARENT, status: "READY" };
    const result = await create(store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("PARENT_NOT_LANDED");
    expect(store.insertCalls).toBe(0);
    expect(store.childrenByParent.size).toBe(0);
  });

  it("rejects when parent after_landing is HOLD", async () => {
    const store = new ConstraintStore();
    store.parent = {
      ...LANDED_PARENT,
      afterLanding: "HOLD",
      afterLandingDestinationId: null,
    };
    const result = await create(store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("PARENT_NOT_INTERNAL_MOVE");
    expect(store.insertCalls).toBe(0);
  });

  it("rejects invalid inherited amount", async () => {
    const store = new ConstraintStore();
    store.parent = { ...LANDED_PARENT, amountZkz: "0" };
    const result = await create(store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("INVALID_AMOUNT");
    expect(store.insertCalls).toBe(0);
  });

  it("rejects when destination is not BLESSED (TOCTOU recheck)", async () => {
    const store = new ConstraintStore();
    store.destination = { ...ELIGIBLE_DESTINATION, destinationState: "PENDING" };
    const result = await create(store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("DESTINATION_INELIGIBLE");
    expect(result.detail).toContain("destination_state=PENDING");
    expect(store.insertCalls).toBe(0);
    expect(store.events).toEqual([]);
  });

  it("rejects when destination lacks recovery verification", async () => {
    const store = new ConstraintStore();
    store.destination = { ...ELIGIBLE_DESTINATION, recoveryVerifiedAt: null };
    const result = await create(store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("DESTINATION_INELIGIBLE");
    expect(store.insertCalls).toBe(0);
  });

  it("rejects when destination is not node-generated", async () => {
    const store = new ConstraintStore();
    store.destination = { ...ELIGIBLE_DESTINATION, keyOrigin: "imported" };
    const result = await create(store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("DESTINATION_INELIGIBLE");
    expect(store.insertCalls).toBe(0);
  });

  it("rejects when destination wallet is not AVAILABLE", async () => {
    const store = new ConstraintStore();
    store.destination = { ...ELIGIBLE_DESTINATION, walletState: "QUARANTINED" };
    const result = await create(store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("DESTINATION_INELIGIBLE");
    expect(store.insertCalls).toBe(0);
  });

  it("rejects same-wallet destination", async () => {
    const store = new ConstraintStore();
    store.destination = { ...ELIGIBLE_DESTINATION, walletId: RECEIVER_WALLET };
    const result = await create(store);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("SAME_WALLET");
    expect(store.insertCalls).toBe(0);
  });

  it("replay after success returns ALREADY_EXISTS with the same child (idempotent)", async () => {
    const store = new ConstraintStore();
    const first = await create(store);
    expect(first.ok && first.outcome === "CREATED").toBe(true);
    const second = await create(store, PARENT_OP_ID, CHILD_OP_ID_B);
    expect(second.ok).toBe(true);
    if (!second.ok || !first.ok) return;
    expect(second.outcome).toBe("ALREADY_EXISTS");
    expect(second.child.operationId).toBe(first.child.operationId);
    expect(store.childrenByParent.size).toBe(1);
    expect(store.events).toHaveLength(1);
  });

  it("concurrent attempts yield exactly one child (unique-constraint arbiter)", async () => {
    const store = new ConstraintStore();
    store.armInsertGate();

    const N = 8;
    const ids = Array.from(
      { length: N },
      (_, i) => `aaaaaaaa-aaaa-4aaa-8aaa-${String(i).padStart(12, "0")}`,
    );

    const pending = ids.map((id) =>
      createChildMoveAtomically(store, PARENT_OP_ID, {
        generateId: () => id,
        now: () => FIXED_NOW + ids.indexOf(id),
      }),
    );

    // Let every racer pass the eligibility/findChild short-circuit and reach insertChild.
    await new Promise((r) => setTimeout(r, 20));
    store.releaseInsert?.();

    const results = await Promise.all(pending);
    const created = results.filter((r) => r.ok && r.outcome === "CREATED");
    const already = results.filter((r) => r.ok && r.outcome === "ALREADY_EXISTS");
    const rejected = results.filter((r) => !r.ok);

    expect(rejected).toHaveLength(0);
    expect(created).toHaveLength(1);
    expect(already).toHaveLength(N - 1);
    expect(store.childrenByParent.size).toBe(1);
    expect(store.operations.size).toBe(1);
    expect(store.events).toHaveLength(1);
    expect(store.leaseGroups.get(LEASE_GROUP_ID)?.childDisposition).toBe("JOINED");

    const winnerId = created[0] && created[0].ok ? created[0].child.operationId : "";
    for (const r of already) {
      if (r.ok) expect(r.child.operationId).toBe(winnerId);
    }
  });

  it("SQL spawn insert uses ON CONFLICT on spawned_from_operation_id (review indicator 1)", () => {
    expect(CHILD_MOVE_STATEMENTS.INSERT_CHILD).toContain(
      "ON CONFLICT (spawned_from_operation_id) WHERE spawned_from_operation_id IS NOT NULL",
    );
    expect(CHILD_MOVE_STATEMENTS.INSERT_CHILD).toContain("DO NOTHING RETURNING id");
    expect(CHILD_MOVE_STATEMENTS.INSERT_CHILD).toContain("'MOVE_INTERNAL'");
    expect(CHILD_MOVE_STATEMENTS.INSERT_CHILD).toContain("'CREATED'");
  });

  it("child lease_group_id is byte-identical to parent (review indicator 4)", async () => {
    const store = new ConstraintStore();
    const result = await create(store);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.child.leaseGroupId).toBe(LANDED_PARENT.leaseGroupId);
    expect(store.groupOps.get(result.child.operationId)).toBe(LEASE_GROUP_ID);
  });

  it("AC3: child inherits NODE_VERIFIED from parent receive (ZTR-1304)", async () => {
    const store = new ConstraintStore();
    store.parent = { ...LANDED_PARENT, verificationMode: "NODE_VERIFIED" };
    const result = await create(store);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.child.verificationMode).toBe("NODE_VERIFIED");
    expect(store.operations.get(CHILD_OP_ID)?.verificationMode).toBe("NODE_VERIFIED");
  });

  it("AC3: child inherits INDEPENDENT from parent receive (ZTR-1304)", async () => {
    const store = new ConstraintStore();
    store.parent = { ...LANDED_PARENT, verificationMode: "INDEPENDENT" };
    const result = await create(store);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.child.verificationMode).toBe("INDEPENDENT");
  });

  it("INSERT_CHILD binds verification_mode column (ZTR-1304 inheritance)", () => {
    expect(CHILD_MOVE_STATEMENTS.INSERT_CHILD).toContain("verification_mode");
    expect(CHILD_MOVE_STATEMENTS.SELECT_PARENT_RECEIVE).toContain("verification_mode");
  });
});
