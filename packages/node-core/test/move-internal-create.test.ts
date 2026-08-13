// MOVE_INTERNAL admission service.
//
//
// SCOPE: decision logic through a store double that models the frozen operations
// idempotency UNIQUE and the admission multi-write. Real-PostgreSQL enforcement of the
// same constraints lives in move-internal-create.pg.test.ts.

import { describe, expect, it } from "vitest";

import {
  buildInternalMoveResponse,
  canonicalMoveRequestSha256,
  createInternalMove,
  isMoveDestinationEligible,
  isMoveSourceEligible,
  MOVE_CANONICAL_ROUTE,
  MOVE_HTTP_METHOD,
  MOVE_OPERATION_KIND,
  moveOutcomeToRouteResult,
  MoveAdmissionError,
  readInternalMove,
  validateMoveCreateRequest,
  type MoveAdmitInsert,
  type MoveCreateRequest,
  type MoveCreateStore,
  type MoveDestinationRecord,
  type MoveInsertOutcome,
  type MoveSourceWalletRecord,
  type StoredMoveOperation,
} from "../src/move/create.js";
import { STATEMENTS as MOVE_SQL_STATEMENTS } from "../src/move/sql-store.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const SOURCE_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const DEST_WALLET_ID = "66666666-6666-4666-8666-666666666666";
const DESTINATION_ID = "77777777-7777-4777-8777-777777777777";
const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const LEASE_GROUP_ID = "44444444-4444-4444-8444-444444444444";
const PARENT_OP_ID = "88888888-8888-4888-8888-888888888888";
const PARENT_GROUP_ID = "99999999-9999-4999-8999-999999999999";
const IDEMPOTENCY_KEY = "idem-key-move-create-0001";
const SOURCE_PUBKEY = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DEST_PUBKEY = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";

const AVAILABLE_SOURCE: MoveSourceWalletRecord = {
  walletId: SOURCE_WALLET_ID,
  nodeId: NODE_ID,
  publicKey: SOURCE_PUBKEY,
  keyOrigin: "node_generated",
  state: "AVAILABLE",
  allowInternalMove: true,
};

const ELIGIBLE_DESTINATION: MoveDestinationRecord = {
  destinationId: DESTINATION_ID,
  nodeId: NODE_ID,
  walletId: DEST_WALLET_ID,
  publicKey: DEST_PUBKEY,
  keyOrigin: "node_generated",
  walletState: "AVAILABLE",
  destinationState: "BLESSED",
  recoveryVerifiedAt: "2026-07-01T00:00:00.000Z",
  allowInternalMove: true,
};

const request = (overrides: Partial<MoveCreateRequest> = {}): MoveCreateRequest => ({
  implementerId: IMPLEMENTER_ID,
  nodeId: NODE_ID,
  sourceWalletId: SOURCE_WALLET_ID,
  destinationId: DESTINATION_ID,
  amountZkz: "5.5",
  idempotencyKey: IDEMPOTENCY_KEY,
  ...overrides,
});

/** Store double: idempotency UNIQUE + lease-group bookkeeping. No hand-seeded reject flags. */
class ConstraintStore implements MoveCreateStore {
  readonly sources = new Map<string, MoveSourceWalletRecord>();
  readonly destinations = new Map<string, MoveDestinationRecord>();
  readonly activeLeases = new Set<string>();
  readonly operations = new Map<string, StoredMoveOperation>();
  readonly events: string[] = [];
  readonly leaseGroups = new Map<string, { root: string; childDisposition: string }>();
  readonly groupOps = new Map<string, string>(); // operationId → leaseGroupId
  hideFromIdempotencyRead = false;
  insertCalls = 0;

  async findSourceWallet(walletId: string): Promise<MoveSourceWalletRecord | null> {
    return this.sources.get(walletId) ?? null;
  }

  async findDestination(destinationId: string): Promise<MoveDestinationRecord | null> {
    return this.destinations.get(destinationId) ?? null;
  }

  async hasActiveLease(walletId: string): Promise<boolean> {
    return this.activeLeases.has(walletId);
  }

  async insertAdmitted(input: MoveAdmitInsert): Promise<MoveInsertOutcome> {
    this.insertCalls += 1;
    const op = input.operation;
    for (const row of this.operations.values()) {
      if (
        row.implementerId === op.implementerId &&
        row.kind === op.kind &&
        row.idempotencyKey === op.idempotencyKey
      ) {
        return { kind: "IDEMPOTENCY_CONFLICT" };
      }
    }

    let leaseGroupId: string;
    if (input.createLeaseGroup) {
      leaseGroupId = op.leaseGroupId;
      this.leaseGroups.set(leaseGroupId, {
        root: op.operationId,
        childDisposition: "NONE",
      });
      this.groupOps.set(op.operationId, leaseGroupId);
    } else {
      leaseGroupId = input.parentLeaseGroupId as string;
      const group = this.leaseGroups.get(leaseGroupId);
      if (group === undefined) {
        throw new Error("parent lease group missing");
      }
      this.groupOps.set(op.operationId, leaseGroupId);
      if (group.childDisposition === "PENDING") {
        this.leaseGroups.set(leaseGroupId, {
          ...group,
          childDisposition: "JOINED",
        });
      }
    }

    this.events.push(op.operationId);
    this.operations.set(op.operationId, {
      operationId: op.operationId,
      implementerId: op.implementerId,
      nodeId: op.nodeId,
      kind: MOVE_OPERATION_KIND,
      status: op.status,
      rowVersion: op.rowVersion,
      attentionRequired: op.attentionRequired,
      sourceWalletId: op.sourceWalletId,
      destinationId: op.destinationId,
      destinationWalletId: op.destinationWalletId,
      amountZkz: op.amountZkz,
      clientReference: op.clientReference,
      spawnedFromOperationId: op.spawnedFromOperationId,
      leaseGroupId,
      idempotencyKey: op.idempotencyKey,
      requestSha256: op.requestSha256,
      createdAt: op.createdAt,
      updatedAt: op.createdAt,
    });
    return { kind: "INSERTED", leaseGroupId };
  }

  async findByIdempotency(
    implementerId: string,
    kind: typeof MOVE_OPERATION_KIND,
    idempotencyKey: string,
  ): Promise<StoredMoveOperation | null> {
    if (this.hideFromIdempotencyRead) return null;
    for (const row of this.operations.values()) {
      if (
        row.implementerId === implementerId &&
        row.kind === kind &&
        row.idempotencyKey === idempotencyKey
      ) {
        return row;
      }
    }
    return null;
  }

  async findByOperationId(operationId: string): Promise<StoredMoveOperation | null> {
    return this.operations.get(operationId) ?? null;
  }
}

function seededStore(): ConstraintStore {
  const store = new ConstraintStore();
  store.sources.set(SOURCE_WALLET_ID, AVAILABLE_SOURCE);
  store.destinations.set(DESTINATION_ID, ELIGIBLE_DESTINATION);
  return store;
}

const FIXED_NOW = 1_700_000_000_000;

function admit(store: ConstraintStore, overrides: Partial<MoveCreateRequest> = {}) {
  let n = 0;
  return createInternalMove(store, request(overrides), {
    generateId: () => {
      n += 1;
      if (n === 1) return OPERATION_ID;
      if (n === 2) return LEASE_GROUP_ID;
      return `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
    },
    now: () => FIXED_NOW,
  });
}

describe("validateMoveCreateRequest", () => {
  it("accepts a well-formed public request", () => {
    expect(validateMoveCreateRequest(request())).toEqual({ ok: true });
  });

  it("rejects a short idempotency key", () => {
    expect(validateMoveCreateRequest(request({ idempotencyKey: "short" })).ok).toBe(false);
  });

  it("rejects a non-positive amount", () => {
    const zero = validateMoveCreateRequest(request({ amountZkz: "0" }));
    expect(zero).toMatchObject({ ok: false, code: "invalid_amount" });
  });

  it("rejects amount at or above 1e8 (upper bound)", () => {
    const big = validateMoveCreateRequest(request({ amountZkz: "100000000" }));
    expect(big).toMatchObject({ ok: false, code: "invalid_amount" });
  });

  it("requires parent lease group when spawned_from is set", () => {
    const r = validateMoveCreateRequest(
      request({ spawnedFromOperationId: PARENT_OP_ID }),
    );
    expect(r).toMatchObject({ ok: false, code: "invalid_spawned_from_operation_id" });
  });
});

describe("eligibility helpers", () => {
  it("source requires node_generated + this node; public AVAILABLE, child allows PINNED", () => {
    expect(isMoveSourceEligible(AVAILABLE_SOURCE, NODE_ID)).toBe(true);
    expect(
      isMoveSourceEligible({ ...AVAILABLE_SOURCE, keyOrigin: "imported" }, NODE_ID),
    ).toBe(false);
    // Public path: PINNED is not source-eligible.
    expect(
      isMoveSourceEligible({ ...AVAILABLE_SOURCE, state: "PINNED" }, NODE_ID),
    ).toBe(false);
    // Receive-child path: parent lease pins the receiver — PINNED allowed.
    expect(
      isMoveSourceEligible(
        { ...AVAILABLE_SOURCE, state: "PINNED" },
        NODE_ID,
        { allowPinned: true },
      ),
    ).toBe(true);
    // Child still refuses non-AVAILABLE/non-PINNED.
    expect(
      isMoveSourceEligible(
        { ...AVAILABLE_SOURCE, state: "QUARANTINED" },
        NODE_ID,
        { allowPinned: true },
      ),
    ).toBe(false);
    expect(
      isMoveSourceEligible(
        { ...AVAILABLE_SOURCE, nodeId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
        NODE_ID,
      ),
    ).toBe(false);
  });

  it("destination requires BLESSED + recovery + AVAILABLE + distinct wallet", () => {
    expect(
      isMoveDestinationEligible(ELIGIBLE_DESTINATION, NODE_ID, SOURCE_WALLET_ID),
    ).toEqual({ ok: true });
    expect(
      isMoveDestinationEligible(
        { ...ELIGIBLE_DESTINATION, destinationState: "PENDING" },
        NODE_ID,
        SOURCE_WALLET_ID,
      ),
    ).toMatchObject({ ok: false, code: "destination_not_eligible" });
    expect(
      isMoveDestinationEligible(
        { ...ELIGIBLE_DESTINATION, recoveryVerifiedAt: null },
        NODE_ID,
        SOURCE_WALLET_ID,
      ),
    ).toMatchObject({ ok: false, code: "destination_not_eligible" });
    expect(
      isMoveDestinationEligible(
        { ...ELIGIBLE_DESTINATION, walletId: SOURCE_WALLET_ID },
        NODE_ID,
        SOURCE_WALLET_ID,
      ),
    ).toMatchObject({ ok: false, code: "same_wallet" });
  });
});

describe("canonicalMoveRequestSha256", () => {
  it("is stable for identical public bodies and changes when amount changes", () => {
    const a = canonicalMoveRequestSha256(request());
    const b = canonicalMoveRequestSha256(request());
    const c = canonicalMoveRequestSha256(request({ amountZkz: "1.0" }));
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("includes spawned_from only on the child path", () => {
    const publicHash = canonicalMoveRequestSha256(request());
    const childHash = canonicalMoveRequestSha256(
      request({
        spawnedFromOperationId: PARENT_OP_ID,
        parentLeaseGroupId: PARENT_GROUP_ID,
      }),
    );
    expect(publicHash).not.toBe(childHash);
  });

  // Review B D1 — pre-upgrade public preimage omitted client_reference; always embedding
  // null broke post-deploy same-key replay (idempotency_key_reused).
  it("omitted/null client_reference matches pre-upgrade public hash; present value changes it", () => {
    const PRE_UPGRADE_PUBLIC =
      "7fde88d642b82d6274c3cf214a2ed6ac25824a061a0c53c4ef4cebc881aa99da";
    expect(canonicalMoveRequestSha256(request())).toBe(PRE_UPGRADE_PUBLIC);
    expect(canonicalMoveRequestSha256(request({ clientReference: null }))).toBe(
      PRE_UPGRADE_PUBLIC,
    );
    expect(canonicalMoveRequestSha256(request({ clientReference: undefined }))).toBe(
      PRE_UPGRADE_PUBLIC,
    );
    const withRef = canonicalMoveRequestSha256(request({ clientReference: "ord_1" }));
    expect(withRef).not.toBe(PRE_UPGRADE_PUBLIC);
    expect(withRef).toBe(
      "ec7d57de52bdc8e6af98672612ae5536643823252a80263f4d75e89f808561d3",
    );
  });

  it("omitted/null client_reference matches pre-upgrade child hash", () => {
    const PRE_UPGRADE_CHILD =
      "2981f8fdfdf51d3834feb7ffa44d4387dbefd64ad188989cddb6a3d388caa76e";
    const child = {
      spawnedFromOperationId: PARENT_OP_ID,
      parentLeaseGroupId: PARENT_GROUP_ID,
    } as const;
    expect(canonicalMoveRequestSha256(request(child))).toBe(PRE_UPGRADE_CHILD);
    expect(
      canonicalMoveRequestSha256(request({ ...child, clientReference: null })),
    ).toBe(PRE_UPGRADE_CHILD);
    expect(
      canonicalMoveRequestSha256(request({ ...child, clientReference: "ord_1" })),
    ).not.toBe(PRE_UPGRADE_CHILD);
  });
});

describe("createInternalMove — admission", () => {
  it("admits a valid request, creates one lease group, and appends the event", async () => {
    const store = seededStore();
    const outcome = await admit(store);
    expect(outcome.outcome).toBe("CREATED");
    if (outcome.outcome !== "CREATED") return;
    expect(outcome.operation.operationId).toBe(OPERATION_ID);
    expect(outcome.operation.status).toBe("CREATED");
    expect(outcome.operation.kind).toBe("MOVE_INTERNAL");
    expect(outcome.operation.leaseGroupId).toBe(LEASE_GROUP_ID);
    expect(outcome.operation.spawnedFromOperationId).toBeNull();
    expect(store.insertCalls).toBe(1);
    expect(store.events).toEqual([OPERATION_ID]);
    expect(store.leaseGroups.get(LEASE_GROUP_ID)?.root).toBe(OPERATION_ID);
    expect(store.groupOps.get(OPERATION_ID)).toBe(LEASE_GROUP_ID);
  });

  it("rejects same-wallet source=destination before any insert (review indicator 1)", async () => {
    const store = seededStore();
    store.destinations.set(DESTINATION_ID, {
      ...ELIGIBLE_DESTINATION,
      walletId: SOURCE_WALLET_ID,
    });
    const outcome = await admit(store);
    expect(outcome).toMatchObject({ outcome: "REJECTED", code: "same_wallet" });
    expect(store.insertCalls).toBe(0);
  });

  it("rejects an unblessed / PENDING destination (review indicator 2)", async () => {
    const store = seededStore();
    store.destinations.set(DESTINATION_ID, {
      ...ELIGIBLE_DESTINATION,
      destinationState: "PENDING",
    });
    const outcome = await admit(store);
    expect(outcome).toMatchObject({
      outcome: "REJECTED",
      code: "destination_not_eligible",
    });
    expect(store.insertCalls).toBe(0);
  });

  it("rejects a destination without recovery_verified_at", async () => {
    const store = seededStore();
    store.destinations.set(DESTINATION_ID, {
      ...ELIGIBLE_DESTINATION,
      recoveryVerifiedAt: null,
    });
    const outcome = await admit(store);
    expect(outcome).toMatchObject({
      outcome: "REJECTED",
      code: "destination_not_eligible",
      detail: "recovery_unverified",
    });
    expect(store.insertCalls).toBe(0);
  });

  it("rejects source not found / not node_generated", async () => {
    const missing = seededStore();
    missing.sources.clear();
    expect(await admit(missing)).toMatchObject({
      outcome: "REJECTED",
      code: "source_wallet_not_found",
    });

    const imported = seededStore();
    imported.sources.set(SOURCE_WALLET_ID, {
      ...AVAILABLE_SOURCE,
      keyOrigin: "imported",
    });
    expect(await admit(imported)).toMatchObject({
      outcome: "REJECTED",
      code: "source_wallet_not_eligible",
    });
  });

  it("rejects source when allow_internal_move is false (ZTR-1268)", async () => {
    const store = seededStore();
    store.sources.set(SOURCE_WALLET_ID, {
      ...AVAILABLE_SOURCE,
      allowInternalMove: false,
    });
    expect(await admit(store)).toMatchObject({
      outcome: "REJECTED",
      code: "source_wallet_not_eligible",
      detail: "allow_internal_move=false",
    });
    expect(store.insertCalls).toBe(0);
  });

  it("rejects destination when allow_internal_move is false (ZTR-1268)", async () => {
    const store = seededStore();
    store.destinations.set(DESTINATION_ID, {
      ...ELIGIBLE_DESTINATION,
      allowInternalMove: false,
    });
    expect(await admit(store)).toMatchObject({
      outcome: "REJECTED",
      code: "destination_not_eligible",
      detail: "allow_internal_move=false",
    });
    expect(store.insertCalls).toBe(0);
  });

  it("returns 409 wallet_busy when source or destination already has an active lease", async () => {
    const sourceBusy = seededStore();
    sourceBusy.activeLeases.add(SOURCE_WALLET_ID);
    expect(await admit(sourceBusy)).toMatchObject({
      outcome: "REJECTED",
      code: "wallet_busy",
    });
    expect(sourceBusy.insertCalls).toBe(0);

    const destBusy = seededStore();
    destBusy.activeLeases.add(DEST_WALLET_ID);
    expect(await admit(destBusy)).toMatchObject({
      outcome: "REJECTED",
      code: "wallet_busy",
    });
    expect(destBusy.insertCalls).toBe(0);
  });

  it("replays identical idempotency key without a second insert (review indicator 3)", async () => {
    const store = seededStore();
    const first = await admit(store);
    expect(first.outcome).toBe("CREATED");
    const second = await admit(store);
    expect(second.outcome).toBe("IDEMPOTENT_REPLAY");
    if (second.outcome !== "IDEMPOTENT_REPLAY") return;
    expect(second.responseStatus).toBe(201);
    const body = JSON.parse(second.responseBody) as ReturnType<typeof buildInternalMoveResponse>;
    expect(body.operation.operation_id).toBe(OPERATION_ID);
    expect(body.lease_status).toBe("WAITING");
    expect(body.expected_artifact).toBeNull();
    expect(store.insertCalls).toBe(1); // pre-insert idempotency lookup short-circuits replay
    expect(store.operations.size).toBe(1);
    expect(store.events).toHaveLength(1);

    const routed = moveOutcomeToRouteResult(second);
    expect(routed.idempotentReplay).toBe(true);
    expect(routed.status).toBe(201);
  });

  it("rejects same key with different body as idempotency_key_reused (review indicator 4)", async () => {
    const store = seededStore();
    expect((await admit(store)).outcome).toBe("CREATED");
    const conflict = await admit(store, { amountZkz: "1.25" });
    expect(conflict).toMatchObject({
      outcome: "REJECTED",
      code: "idempotency_key_reused",
    });
    expect(store.operations.size).toBe(1);
  });

  it("returns idempotency_in_progress when the winner row is not yet visible", async () => {
    const store = seededStore();
    // Seed a conflict by pre-inserting under the key, then hide the read.
    await admit(store);
    store.hideFromIdempotencyRead = true;
    // Force conflict by calling insert path again with a fresh id generator but same key —
    // the store still has the first row so insert returns IDEMPOTENCY_CONFLICT.
    const stuck = await createInternalMove(store, request(), {
      generateId: () => "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      now: () => FIXED_NOW,
    });
    expect(stuck).toMatchObject({
      outcome: "REJECTED",
      code: "idempotency_in_progress",
    });
  });

  it("receive-child joins parent lease group and does not create a new one (review indicator 5)", async () => {
    const store = seededStore();
    store.leaseGroups.set(PARENT_GROUP_ID, {
      root: PARENT_OP_ID,
      childDisposition: "PENDING",
    });
    // Parent continuously holds the source (receiver) lease while the child is
    // admitted. Public wallet_busy must not fire on the child path.
    store.activeLeases.add(SOURCE_WALLET_ID);
    const outcome = await admit(store, {
      spawnedFromOperationId: PARENT_OP_ID,
      parentLeaseGroupId: PARENT_GROUP_ID,
    });
    expect(outcome.outcome).toBe("CREATED");
    if (outcome.outcome !== "CREATED") return;
    expect(outcome.operation.leaseGroupId).toBe(PARENT_GROUP_ID);
    expect(outcome.operation.spawnedFromOperationId).toBe(PARENT_OP_ID);
    // No new lease group row — only the parent group exists.
    expect(store.leaseGroups.size).toBe(1);
    expect(store.leaseGroups.get(PARENT_GROUP_ID)?.childDisposition).toBe("JOINED");
    expect(store.groupOps.get(outcome.operation.operationId)).toBe(PARENT_GROUP_ID);
  });

  it("receive-child admits when source is PINNED under parent lease (D4)", async () => {
    // Production: operation-flow pins the receiver on lease; child create runs while that
    // source lease is continuously held — wallets.state is PINNED, not AVAILABLE.
    const store = seededStore();
    store.sources.set(SOURCE_WALLET_ID, { ...AVAILABLE_SOURCE, state: "PINNED" });
    store.leaseGroups.set(PARENT_GROUP_ID, {
      root: PARENT_OP_ID,
      childDisposition: "PENDING",
    });
    store.activeLeases.add(SOURCE_WALLET_ID);
    const outcome = await admit(store, {
      spawnedFromOperationId: PARENT_OP_ID,
      parentLeaseGroupId: PARENT_GROUP_ID,
      idempotencyKey: "idem-key-move-child-pinned-src",
    });
    expect(outcome.outcome).toBe("CREATED");
    if (outcome.outcome !== "CREATED") return;
    expect(outcome.operation.leaseGroupId).toBe(PARENT_GROUP_ID);
    expect(outcome.operation.spawnedFromOperationId).toBe(PARENT_OP_ID);
    expect(store.leaseGroups.get(PARENT_GROUP_ID)?.childDisposition).toBe("JOINED");
    expect(store.insertCalls).toBe(1);
  });

  it("public path still rejects PINNED source (D4)", async () => {
    const store = seededStore();
    store.sources.set(SOURCE_WALLET_ID, { ...AVAILABLE_SOURCE, state: "PINNED" });
    const outcome = await admit(store);
    expect(outcome).toMatchObject({
      outcome: "REJECTED",
      code: "source_wallet_not_eligible",
    });
    expect(store.insertCalls).toBe(0);
  });

  it("receive-child still admits when destination is busy (queues CREATED/JOINED)", async () => {
    const store = seededStore();
    store.leaseGroups.set(PARENT_GROUP_ID, {
      root: PARENT_OP_ID,
      childDisposition: "PENDING",
    });
    store.activeLeases.add(SOURCE_WALLET_ID);
    store.activeLeases.add(DEST_WALLET_ID);
    const outcome = await admit(store, {
      spawnedFromOperationId: PARENT_OP_ID,
      parentLeaseGroupId: PARENT_GROUP_ID,
      idempotencyKey: "idem-key-move-child-dest-busy",
    });
    expect(outcome.outcome).toBe("CREATED");
    if (outcome.outcome !== "CREATED") return;
    expect(outcome.operation.leaseGroupId).toBe(PARENT_GROUP_ID);
    expect(store.leaseGroups.get(PARENT_GROUP_ID)?.childDisposition).toBe("JOINED");
  });

  it("same-hash replay wins over wallet_busy after source becomes leased (D1)", async () => {
    const store = seededStore();
    const first = await admit(store);
    expect(first.outcome).toBe("CREATED");
    // Or any cross-op holder acquires the source lease after admission.
    store.activeLeases.add(SOURCE_WALLET_ID);
    const second = await admit(store);
    expect(second.outcome).toBe("IDEMPOTENT_REPLAY");
    if (second.outcome !== "IDEMPOTENT_REPLAY") return;
    expect(second.responseStatus).toBe(201);
    expect(JSON.parse(second.responseBody).operation.operation_id).toBe(OPERATION_ID);
    // Lookup short-circuits — no second insert attempt required, but if one runs ON CONFLICT
    // still yields a single durable row.
    expect(store.operations.size).toBe(1);
  });

  it("buildInternalMoveResponse freezes WAITING + null artifact at create time", async () => {
    const store = seededStore();
    const outcome = await admit(store);
    if (outcome.outcome !== "CREATED") throw new Error("expected CREATED");
    const body = buildInternalMoveResponse(outcome.operation);
    expect(body).toEqual({
      operation: {
        operation_id: OPERATION_ID,
        operation_type: "MOVE_INTERNAL",
        state: "CREATED",
        amount_zkz: "5.5",
        row_version: 1,
        attention_required: false,
        attention_reason: null,
        created_at: new Date(FIXED_NOW).toISOString(),
        updated_at: new Date(FIXED_NOW).toISOString(),
        terminal_at: null,
        verification_material_available_until: null,
      },
      source_wallet_id: SOURCE_WALLET_ID,
      destination_id: DESTINATION_ID,
      spawned_from_operation_id: null,
      lease_status: "WAITING",
      execution_phase: "NOT_STARTED",
      expected_artifact: null,
      source_terminal_observation_id: null,
      destination_terminal_observation_id: null,
    });
  });

  it("readInternalMove returns the create-time shape", async () => {
    const store = seededStore();
    await admit(store);
    const found = await readInternalMove(store, OPERATION_ID);
    expect(found.outcome).toBe("FOUND");
    if (found.outcome !== "FOUND") return;
    expect(found.response.operation.operation_id).toBe(OPERATION_ID);
    expect(await readInternalMove(store, "00000000-0000-4000-8000-000000000099")).toEqual({
      outcome: "NOT_FOUND",
    });
  });

  it("moveOutcomeToRouteResult throws MoveAdmissionError on rejection", async () => {
    const store = seededStore();
    store.activeLeases.add(SOURCE_WALLET_ID);
    const outcome = await admit(store);
    expect(() => moveOutcomeToRouteResult(outcome)).toThrow(MoveAdmissionError);
    try {
      moveOutcomeToRouteResult(outcome);
    } catch (err) {
      expect(err).toBeInstanceOf(MoveAdmissionError);
      expect((err as MoveAdmissionError).code).toBe("wallet_busy");
    }
  });

  it("exposes the frozen route constants", () => {
    expect(MOVE_HTTP_METHOD).toBe("POST");
    expect(MOVE_CANONICAL_ROUTE).toBe("/v1/internal-moves");
  });
});

describe("SqlMoveCreateStore statement surface", () => {
  it("INSERT_OPERATION targets the operations idempotency UNIQUE via ON CONFLICT", () => {
    expect(MOVE_SQL_STATEMENTS.INSERT_OPERATION).toContain(
      "ON CONFLICT (implementer_id, kind, idempotency_key) DO NOTHING",
    );
    expect(MOVE_SQL_STATEMENTS.INSERT_OPERATION).toContain("'MOVE_INTERNAL'");
    expect(MOVE_SQL_STATEMENTS.INSERT_OPERATION).toContain("'CREATED'");
  });

  it("destination resolve joins destinations to wallets for recovery + blessing", () => {
    expect(MOVE_SQL_STATEMENTS.SELECT_DESTINATION).toContain("FROM destinations d");
    expect(MOVE_SQL_STATEMENTS.SELECT_DESTINATION).toContain("JOIN wallets w");
    expect(MOVE_SQL_STATEMENTS.SELECT_DESTINATION).toContain("recovery_verified_at");
  });

  it("busy check reads wallet_active_leases", () => {
    expect(MOVE_SQL_STATEMENTS.SELECT_ACTIVE_LEASE).toContain("wallet_active_leases");
  });
});
