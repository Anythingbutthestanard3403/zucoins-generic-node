// Destination registration and blessing service tests.
// automatic_sink_eligible derivation on GET /v1/destinations.

import { describe, expect, it } from "vitest";

import {
  createDestinationService,
  deriveMoveEligibility,
  DestinationIdempotencyKeyClaimedError,
  type BlessingAuthorizer,
  type DestinationRecord,
  type DestinationStore,
  type DestinationWalletFacts,
  type DestinationWalletKeyClaim,
  type DestinationWalletKeyGenerator,
  type NewDestination,
} from "../src/api/destination.js";
import type { Uuid, WalletPublicKey } from "../src/protocol/scalars.js";
import type { WalletKeyOrigin, WalletState } from "@zucoins/generic-node-contracts/custody";

const NODE_ID = "11111111-1111-4111-8111-111111111111" as Uuid;
const OTHER_NODE_ID = "22222222-2222-4222-8222-222222222222" as Uuid;
const DEVICE_KEY_ID = "33333333-3333-4333-8333-333333333333" as Uuid;
const ARTIFACT_ID = "44444444-4444-4444-8444-444444444444" as Uuid;
const NONCE = "99999999-9999-4999-8999-999999999999" as Uuid;
const ISSUED_AT = "2026-07-18T00:00:00.000Z";
const EXPIRES_AT = "2026-07-18T00:05:00.000Z";
const RECOVERY_VERIFIED_AT = "2026-07-17T12:00:00.000Z";

const uuid = (tag: string): Uuid => `00000000-0000-4000-8000-${tag.padStart(12, "0")}` as Uuid;
const pubkey = (tag: string): WalletPublicKey => `${tag}-pubkey` as WalletPublicKey;

interface StoredDestination extends DestinationRecord {
  readonly idempotencyKey: string;
}

interface StoredWalletFacts {
  keyOrigin: WalletKeyOrigin;
  walletState: WalletState;
  recoveryVerifiedAt: string | null;
}

class MemoryDestinationStore implements DestinationStore {
  readonly rows = new Map<string, StoredDestination>();
  readonly walletOrigins = new Map<string, WalletKeyOrigin>();
  readonly walletFactRows = new Map<string, StoredWalletFacts>();
  private seq = 0;

  async findByIdempotencyKey(nodeId: Uuid, idempotencyKey: string): Promise<DestinationRecord | null> {
    for (const row of this.rows.values()) {
      if (row.nodeId === nodeId && row.idempotencyKey === idempotencyKey) {
        return row;
      }
    }
    return null;
  }

  async insert(record: NewDestination, idempotencyKey: string): Promise<DestinationRecord> {
    this.seq += 1;
    const stored: StoredDestination = {
      ...record,
      state: "PENDING",
      blessedAt: null,
      blessedByDeviceKeyId: null,
      blessingArtifactId: null,
      retiredAt: null,
      idempotencyKey,
    };
    this.rows.set(record.destinationId, stored);
    this.walletOrigins.set(record.walletId, "node_generated");
    // Default wallet facts: node-generated AVAILABLE, not recovery-verified.
    // Tests that need sink eligibility must set recoveryVerifiedAt explicitly.
    this.walletFactRows.set(record.walletId, {
      keyOrigin: "node_generated",
      walletState: "AVAILABLE",
      recoveryVerifiedAt: null,
    });
    return stored;
  }

  async walletKeyOrigin(walletId: Uuid): Promise<WalletKeyOrigin | null> {
    return this.walletOrigins.get(walletId) ?? null;
  }

  async walletFacts(walletId: Uuid): Promise<DestinationWalletFacts | null> {
    const row = this.walletFactRows.get(walletId);
    if (row === undefined) return null;
    return {
      keyOrigin: row.keyOrigin,
      walletState: row.walletState,
      recoveryVerifiedAt: row.recoveryVerifiedAt,
    };
  }

  setWalletFacts(
    walletId: Uuid,
    patch: Partial<StoredWalletFacts>,
  ): void {
    const current = this.walletFactRows.get(walletId) ?? {
      keyOrigin: "node_generated" as WalletKeyOrigin,
      walletState: "AVAILABLE" as WalletState,
      recoveryVerifiedAt: null,
    };
    const next = { ...current, ...patch };
    this.walletFactRows.set(walletId, next);
    if (patch.keyOrigin !== undefined) {
      this.walletOrigins.set(walletId, patch.keyOrigin);
    }
  }

  /** Optional hook so race tests can interleave two bless callers after both observe PENDING. */
  findByIdBarrier: (() => Promise<void>) | null = null;
  /** Counts successful CAS bless commits (for race assertions). */
  blessCommitCount = 0;

  async findById(destinationId: Uuid): Promise<DestinationRecord | null> {
    if (this.findByIdBarrier !== null) {
      await this.findByIdBarrier();
    }
    return this.rows.get(destinationId) ?? null;
  }

  async bless(
    destinationId: Uuid,
    patch: {
      readonly blessedAt: string;
      readonly blessedByDeviceKeyId: Uuid;
      readonly blessingArtifactId: Uuid;
    },
  ): Promise<DestinationRecord | null> {
    const row = this.rows.get(destinationId);
    // Atomic PENDING-only CAS — mirrors UPDATE … WHERE state='PENDING' RETURNING *.
    if (row === undefined || row.state !== "PENDING") {
      return null;
    }
    const updated: StoredDestination = {
      ...row,
      state: "BLESSED",
      blessedAt: patch.blessedAt,
      blessedByDeviceKeyId: patch.blessedByDeviceKeyId,
      blessingArtifactId: patch.blessingArtifactId,
    };
    this.rows.set(destinationId, updated);
    this.blessCommitCount += 1;
    return updated;
  }

  async retire(destinationId: Uuid, retiredAt: string): Promise<DestinationRecord> {
    const row = this.rows.get(destinationId);
    if (row === undefined) throw new Error(`destination ${destinationId} not found`);
    const updated: StoredDestination = { ...row, state: "RETIRED", retiredAt };
    this.rows.set(destinationId, updated);
    return updated;
  }

  async list(
    nodeId: Uuid,
    filter: { readonly state?: string; readonly after?: Uuid; readonly limit?: number },
  ): Promise<{ readonly items: readonly DestinationRecord[]; readonly nextAfter: Uuid | null }> {
    const limit = filter.limit ?? 20;
    const all = [...this.rows.values()]
      .filter((row) => row.nodeId === nodeId)
      .filter((row) => filter.state === undefined || row.state === filter.state)
      .sort((a, b) => a.destinationId.localeCompare(b.destinationId));
    const startIndex =
      filter.after === undefined ? 0 : all.findIndex((row) => row.destinationId === filter.after) + 1;
    const items = all.slice(startIndex, startIndex + limit);
    const last = items[items.length - 1];
    const nextAfter = last !== undefined && startIndex + limit < all.length ? last.destinationId : null;
    return { items, nextAfter };
  }
}

class SequenceKeyGenerator implements DestinationWalletKeyGenerator {
  private seq = 0;
  async generate(): Promise<{ readonly walletId: Uuid; readonly publicKey: WalletPublicKey }> {
    this.seq += 1;
    return { walletId: uuid(`wallet${this.seq}`), publicKey: pubkey(`wallet${this.seq}`) };
  }
}

class FixedClock {
  constructor(private readonly timestamp: string) {}
  now(): string {
    return this.timestamp;
  }
}

class SequenceIds {
  private seq = 0;
  destinationId(): Uuid {
    this.seq += 1;
    return uuid(`dest${this.seq}`);
  }
}

function approvingAuthorizer(): BlessingAuthorizer {
  return {
    async authorize() {
      return { deviceKeyId: DEVICE_KEY_ID, artifactId: ARTIFACT_ID };
    },
  };
}

function makeService(overrides: {
  readonly store?: MemoryDestinationStore;
  readonly blessingAuthorizer?: BlessingAuthorizer;
  readonly keyGenerator?: DestinationWalletKeyGenerator;
  readonly now?: string;
} = {}) {
  const store = overrides.store ?? new MemoryDestinationStore();
  const service = createDestinationService({
    store,
    keyGenerator: overrides.keyGenerator ?? new SequenceKeyGenerator(),
    blessingAuthorizer: overrides.blessingAuthorizer ?? approvingAuthorizer(),
    clock: new FixedClock(overrides.now ?? "2026-07-18T00:00:00.000Z"),
    ids: new SequenceIds(),
  });
  return { service, store };
}

/** Full A.4.2 bless request fields (includes expiresAt + deviceKeyId). */
function blessRequest(
  destinationId: Uuid,
  overrides: Partial<{
    nodeId: Uuid;
    nonce: Uuid;
    issuedAt: string;
    expiresAt: string;
    deviceSignature: string;
    deviceKeyId: Uuid;
  }> = {},
) {
  return {
    nodeId: overrides.nodeId ?? NODE_ID,
    destinationId,
    nonce: overrides.nonce ?? NONCE,
    issuedAt: overrides.issuedAt ?? ISSUED_AT,
    expiresAt: overrides.expiresAt ?? EXPIRES_AT,
    deviceSignature: overrides.deviceSignature ?? "device-signature",
    deviceKeyId: overrides.deviceKeyId ?? DEVICE_KEY_ID,
  };
}

async function registerPending(label = "Primary internal sink") {
  const { service, store } = makeService();
  const outcome = await service.register({ nodeId: NODE_ID, label, idempotencyKey: "idem-1" });
  expect(outcome.status).toBe("created");
  if (outcome.status !== "created") throw new Error("expected created");
  return { service, store, destination: outcome.destination };
}

describe("destination registration", () => {
  it("registers a fresh node-generated destination in PENDING", async () => {
    const { service } = makeService();
    const outcome = await service.register({
      nodeId: NODE_ID,
      label: "Primary internal sink",
      idempotencyKey: "idem-1",
    });

    expect(outcome.status).toBe("created");
    if (outcome.status !== "created") return;
    expect(outcome.destination.state).toBe("PENDING");
    expect(outcome.destination.nodeId).toBe(NODE_ID);
    expect(outcome.destination.label).toBe("Primary internal sink");
    expect(outcome.destination.blessedAt).toBeNull();
    expect(outcome.destination.retiredAt).toBeNull();
    expect(outcome.destination.walletPublicKey).toBeTruthy();
  });

  it("is idempotent on the idempotency key", async () => {
    const { service } = makeService();
    const first = await service.register({ nodeId: NODE_ID, label: "sink", idempotencyKey: "idem-1" });
    const second = await service.register({ nodeId: NODE_ID, label: "sink", idempotencyKey: "idem-1" });

    expect(first.status).toBe("created");
    expect(second.status).toBe("already_registered");
    if (first.status === "created" && second.status === "already_registered") {
      expect(second.destination.destinationId).toBe(first.destination.destinationId);
    }
  });

  it("passes the register claim into generate", async () => {
    const seen: Array<{ nodeId: Uuid; claim: DestinationWalletKeyClaim | undefined }> = [];
    const keyGenerator: DestinationWalletKeyGenerator = {
      async generate(nodeId, claim) {
        seen.push({ nodeId, claim });
        return { walletId: uuid("claimw1"), publicKey: pubkey("claimw1") };
      },
    };
    const { service } = makeService({ keyGenerator });
    const outcome = await service.register({
      nodeId: NODE_ID,
      label: "claimed sink",
      idempotencyKey: "idem-claim-key-01",
    });
    expect(outcome.status).toBe("created");
    expect(seen).toEqual([
      {
        nodeId: NODE_ID,
        claim: { idempotencyKey: "idem-claim-key-01", label: "claimed sink" },
      },
    ]);
  });

  it("maps a typed unique-claim miss to already_registered without a second insert", async () => {
    const store = new MemoryDestinationStore();
    const first = await makeService({ store }).service.register({
      nodeId: NODE_ID,
      label: "winner",
      idempotencyKey: "idem-claim-miss",
    });
    expect(first.status).toBe("created");
    if (first.status !== "created") return;

    // Simulate both first-use finds missing: generate is reached, UNIQUE already
    // belongs to the winner, so generate throws the typed claim-miss.
    let findCalls = 0;
    const origFind = store.findByIdempotencyKey.bind(store);
    store.findByIdempotencyKey = async (nodeId, key) => {
      findCalls += 1;
      if (findCalls === 1) return null;
      return origFind(nodeId, key);
    };
    let generateCalls = 0;
    const keyGenerator: DestinationWalletKeyGenerator = {
      async generate() {
        generateCalls += 1;
        throw new DestinationIdempotencyKeyClaimedError(NODE_ID, "idem-claim-miss");
      },
    };
    let insertCalls = 0;
    const origInsert = store.insert.bind(store);
    store.insert = async (record, idempotencyKey) => {
      insertCalls += 1;
      return origInsert(record, idempotencyKey);
    };

    const { service } = makeService({ store, keyGenerator });
    const second = await service.register({
      nodeId: NODE_ID,
      label: "loser",
      idempotencyKey: "idem-claim-miss",
    });
    expect(second.status).toBe("already_registered");
    expect(generateCalls).toBe(1);
    expect(insertCalls).toBe(0);
    if (second.status !== "already_registered") return;
    expect(second.destination.destinationId).toBe(first.destination.destinationId);
    expect(second.destination.walletId).toBe(first.destination.walletId);
  });

  it("scopes idempotency to the node", async () => {
    const { service } = makeService();
    await service.register({ nodeId: NODE_ID, label: "sink", idempotencyKey: "idem-1" });
    const otherNode = await service.register({
      nodeId: OTHER_NODE_ID,
      label: "sink",
      idempotencyKey: "idem-1",
    });
    expect(otherNode.status).toBe("created");
  });

  it("ignores smuggled public key / address / key_origin and always inserts generator output", async () => {
    const generatedWalletId = uuid("genwallet1");
    const generatedPubkey = pubkey("genwallet1");
    const smuggledPubkey = pubkey("smuggled");
    const smuggledWalletId = uuid("smuggledw1");

    let generateCalls = 0;
    const keyGenerator: DestinationWalletKeyGenerator = {
      async generate() {
        generateCalls += 1;
        return { walletId: generatedWalletId, publicKey: generatedPubkey };
      },
    };

    const inserted: NewDestination[] = [];
    const store = new MemoryDestinationStore();
    const origInsert = store.insert.bind(store);
    store.insert = async (record, idempotencyKey) => {
      inserted.push(record);
      return origInsert(record, idempotencyKey);
    };

    const { service } = makeService({ store, keyGenerator });

    // Cast through unknown: a hostile binder may forward extra body fields.
    const hostileBody = {
      nodeId: NODE_ID,
      label: "Primary internal sink",
      idempotencyKey: "idem-smuggle",
      public_key: smuggledPubkey,
      publicKey: smuggledPubkey,
      address: "smuggled-address",
      key_origin: "imported",
      keyOrigin: "imported",
      walletPublicKey: smuggledPubkey,
      walletId: smuggledWalletId,
    } as unknown as Parameters<typeof service.register>[0];

    const outcome = await service.register(hostileBody);
    expect(outcome.status).toBe("created");
    expect(generateCalls).toBe(1);
    expect(inserted).toHaveLength(1);
    const row = inserted[0]!;
    expect(row.walletId).toBe(generatedWalletId);
    expect(row.walletPublicKey).toBe(generatedPubkey);
    expect(row.walletId).not.toBe(smuggledWalletId);
    expect(row.walletPublicKey).not.toBe(smuggledPubkey);
    // Origin is never taken from the request — store defaults node_generated on insert.
    expect(await store.walletKeyOrigin(row.walletId)).toBe("node_generated");
  });
});

describe("destination blessing", () => {
  it("blesses a PENDING destination into BLESSED with the device-key artifact", async () => {
    const { service, destination } = await registerPending();
    const outcome = await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });

    expect(outcome.status).toBe("blessed");
    if (outcome.status !== "blessed") return;
    expect(outcome.destination.state).toBe("BLESSED");
    expect(outcome.destination.blessedByDeviceKeyId).toBe(DEVICE_KEY_ID);
    expect(outcome.destination.blessingArtifactId).toBe(ARTIFACT_ID);
    expect(outcome.destination.blessedAt).toBe("2026-07-18T00:00:00.000Z");
  });

  it("rejects blessing an unknown destination", async () => {
    const { service } = makeService();
    const outcome = await service.bless({
      nodeId: NODE_ID,
      destinationId: uuid("missing"),
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    expect(outcome.status).toBe("not_found");
  });

  it("rejects blessing another node's destination", async () => {
    const { service, destination } = await registerPending();
    const outcome = await service.bless({
      nodeId: OTHER_NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    expect(outcome.status).toBe("not_found");
  });

  it("is idempotent when already BLESSED", async () => {
    const { service, destination } = await registerPending();
    const first = await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    const second = await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    expect(first.status).toBe("blessed");
    expect(second.status).toBe("already_blessed");
  });

  it("refuses to bless a wallet that is not node-generated (predicate 2)", async () => {
    const { service, store, destination } = await registerPending();
    store.walletOrigins.set(destination.walletId, "imported");
    const outcome = await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    expect(outcome.status).toBe("authorization_rejected");
  });

  it("rejects empty deviceSignature without calling authorizer or mutating (TOTP alone cannot bless)", async () => {
    const store = new MemoryDestinationStore();
    let authorizeCalls = 0;
    const authorizer: BlessingAuthorizer = {
      async authorize() {
        authorizeCalls += 1;
        return { deviceKeyId: DEVICE_KEY_ID, artifactId: ARTIFACT_ID };
      },
    };
    const { service } = makeService({ store, blessingAuthorizer: authorizer });
    const registered = await service.register({
      nodeId: NODE_ID,
      label: "sink",
      idempotencyKey: "idem-1",
    });
    if (registered.status !== "created") throw new Error("expected created");

    const emptySig = await service.bless(
      blessRequest(registered.destination.destinationId, { deviceSignature: "" }),
    );
    expect(emptySig.status).toBe("authorization_rejected");
    expect(authorizeCalls).toBe(0);
    expect(store.blessCommitCount).toBe(0);
    expect((await store.findById(registered.destination.destinationId))?.state).toBe("PENDING");
  });

  it("rejects missing expiresAt without calling authorizer (A.4.2 field 9 required)", async () => {
    const store = new MemoryDestinationStore();
    let authorizeCalls = 0;
    const authorizer: BlessingAuthorizer = {
      async authorize() {
        authorizeCalls += 1;
        return { deviceKeyId: DEVICE_KEY_ID, artifactId: ARTIFACT_ID };
      },
    };
    const { service } = makeService({ store, blessingAuthorizer: authorizer });
    const registered = await service.register({
      nodeId: NODE_ID,
      label: "sink",
      idempotencyKey: "idem-1",
    });
    if (registered.status !== "created") throw new Error("expected created");

    const outcome = await service.bless(
      blessRequest(registered.destination.destinationId, { expiresAt: "" }),
    );
    expect(outcome.status).toBe("authorization_rejected");
    expect(authorizeCalls).toBe(0);
    expect((await store.findById(registered.destination.destinationId))?.state).toBe("PENDING");
  });

  it("passes expiresAt through to the authorizer and rejects invalid device signature", async () => {
    const store = new MemoryDestinationStore();
    const received: Array<Parameters<BlessingAuthorizer["authorize"]>[0]> = [];
    // Real path: authorizer verifies device sig; valid TOTP is irrelevant here —
    // missing/invalid device signature must reject without mutate.
    const authorizer: BlessingAuthorizer = {
      async authorize(input) {
        received.push(input);
        // Simulate verifyDestinationBless failure on wrong preimage / bad sig.
        if (input.deviceSignature !== "valid-device-signature") {
          return null;
        }
        if (!input.expiresAt || input.expiresAt.length === 0) {
          return null;
        }
        return { deviceKeyId: DEVICE_KEY_ID, artifactId: ARTIFACT_ID };
      },
    };
    const { service } = makeService({ store, blessingAuthorizer: authorizer });
    const registered = await service.register({
      nodeId: NODE_ID,
      label: "sink",
      idempotencyKey: "idem-1",
    });
    if (registered.status !== "created") throw new Error("expected created");

    const bad = await service.bless(
      blessRequest(registered.destination.destinationId, {
        deviceSignature: "totp-ok-but-bad-device-sig",
        expiresAt: EXPIRES_AT,
      }),
    );
    expect(bad.status).toBe("authorization_rejected");
    expect(received).toHaveLength(1);
    expect(received[0]!.expiresAt).toBe(EXPIRES_AT);
    expect(received[0]!.deviceSignature).toBe("totp-ok-but-bad-device-sig");
    expect(received[0]!.walletId).toBe(registered.destination.walletId);
    expect(received[0]!.walletPublicKey).toBe(registered.destination.walletPublicKey);
    expect((await store.findById(registered.destination.destinationId))?.state).toBe("PENDING");
    expect(store.blessCommitCount).toBe(0);

    const ok = await service.bless(
      blessRequest(registered.destination.destinationId, {
        deviceSignature: "valid-device-signature",
        expiresAt: EXPIRES_AT,
      }),
    );
    expect(ok.status).toBe("blessed");
    expect(received).toHaveLength(2);
    expect(received[1]!.expiresAt).toBe(EXPIRES_AT);
  });

  it("CAS bless: concurrent double-bless yields exactly one winner", async () => {
    const store = new MemoryDestinationStore();
    const artifactA = uuid("artifacta01");
    const artifactB = uuid("artifactb01");
    let authorizeSeq = 0;
    const authorizer: BlessingAuthorizer = {
      async authorize() {
        authorizeSeq += 1;
        return {
          deviceKeyId: DEVICE_KEY_ID,
          artifactId: authorizeSeq === 1 ? artifactA : artifactB,
        };
      },
    };

    const { service } = makeService({ store, blessingAuthorizer: authorizer });
    const registered = await service.register({
      nodeId: NODE_ID,
      label: "sink",
      idempotencyKey: "idem-race",
    });
    if (registered.status !== "created") throw new Error("expected created");
    const destId = registered.destination.destinationId;

    // Barrier so both bless callers observe PENDING before either CAS commits.
    let findWaiters = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    store.findByIdBarrier = async () => {
      findWaiters += 1;
      // Only the two initial PENDING reads wait; CAS-loser re-read must not block.
      if (findWaiters <= 2) {
        await gate;
      }
    };

    const p1 = service.bless(blessRequest(destId, { deviceSignature: "sig-a" }));
    const p2 = service.bless(blessRequest(destId, { deviceSignature: "sig-b" }));

    // Wait until both have entered findById
    for (let i = 0; i < 50 && findWaiters < 2; i += 1) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(findWaiters).toBeGreaterThanOrEqual(2);
    release();

    const results = await Promise.all([p1, p2]);
    store.findByIdBarrier = null;
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual(["already_blessed", "blessed"]);
    expect(store.blessCommitCount).toBe(1);

    const final = await store.findById(destId);
    expect(final?.state).toBe("BLESSED");
    // Exactly one artifact retained — loser must not overwrite.
    expect(final?.blessingArtifactId === artifactA || final?.blessingArtifactId === artifactB).toBe(
      true,
    );
    const winners = results.filter((r) => r.status === "blessed");
    const losers = results.filter((r) => r.status === "already_blessed");
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(1);
    if (winners[0]!.status === "blessed" && losers[0]!.status === "already_blessed") {
      expect(losers[0]!.destination.blessingArtifactId).toBe(
        winners[0]!.destination.blessingArtifactId,
      );
    }
  });

  it("rejects blessing a RETIRED destination", async () => {
    const { service, destination } = await registerPending();
    await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    await service.retire({ nodeId: NODE_ID, destinationId: destination.destinationId });

    const outcome = await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    expect(outcome.status).toBe("invalid_transition");
    if (outcome.status === "invalid_transition") {
      expect(outcome.from).toBe("RETIRED");
    }
  });

  it("refuses to bless a WORKER sink (scaler-owned, no ceremony)", async () => {
    const { service, store } = makeService();
    const destinationId = uuid("worker1");
    const walletId = uuid("workerw1");
    store.rows.set(destinationId, {
      destinationId,
      nodeId: NODE_ID,
      walletId,
      walletPublicKey: pubkey("worker1"),
      state: "WORKER",
      label: "send-worker-deadbeef",
      blessedAt: null,
      blessedByDeviceKeyId: null,
      blessingArtifactId: null,
      retiredAt: null,
      createdAt: ISSUED_AT,
      idempotencyKey: "worker-1",
    });
    store.walletOrigins.set(walletId, "node_generated");

    const outcome = await service.bless(blessRequest(destinationId));
    expect(outcome.status).toBe("invalid_transition");
    if (outcome.status === "invalid_transition") {
      expect(outcome.from).toBe("WORKER");
    }
  });
});

describe("destination retirement (revocation)", () => {
  it("retires a BLESSED destination into terminal RETIRED", async () => {
    const { service, destination } = await registerPending();
    await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });

    const outcome = await service.retire({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
    });
    expect(outcome.status).toBe("retired");
    if (outcome.status !== "retired") return;
    expect(outcome.destination.state).toBe("RETIRED");
    expect(outcome.destination.retiredAt).toBe("2026-07-18T00:00:00.000Z");
    // Blessing history is preserved on retirement (data-model CHECK keeps blessed_at set).
    expect(outcome.destination.blessedAt).not.toBeNull();
  });

  it("rejects retiring a PENDING destination that was never blessed", async () => {
    const { service, destination } = await registerPending();
    const outcome = await service.retire({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
    });
    expect(outcome.status).toBe("invalid_transition");
    if (outcome.status === "invalid_transition") {
      expect(outcome.from).toBe("PENDING");
    }
  });

  it("rejects retiring a WORKER sink", async () => {
    const { service, store } = makeService();
    const destinationId = uuid("worker2");
    const walletId = uuid("workerw2");
    store.rows.set(destinationId, {
      destinationId,
      nodeId: NODE_ID,
      walletId,
      walletPublicKey: pubkey("worker2"),
      state: "WORKER",
      label: "send-worker-cafebabe",
      blessedAt: null,
      blessedByDeviceKeyId: null,
      blessingArtifactId: null,
      retiredAt: null,
      createdAt: ISSUED_AT,
      idempotencyKey: "worker-2",
    });
    store.walletOrigins.set(walletId, "node_generated");

    const outcome = await service.retire({ nodeId: NODE_ID, destinationId });
    expect(outcome.status).toBe("invalid_transition");
    if (outcome.status === "invalid_transition") {
      expect(outcome.from).toBe("WORKER");
    }
  });

  it("rejects retiring an unknown destination", async () => {
    const { service } = makeService();
    const outcome = await service.retire({ nodeId: NODE_ID, destinationId: uuid("missing") });
    expect(outcome.status).toBe("not_found");
  });

  it("is idempotent when already RETIRED", async () => {
    const { service, destination } = await registerPending();
    await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    await service.retire({ nodeId: NODE_ID, destinationId: destination.destinationId });
    const again = await service.retire({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
    });
    expect(again.status).toBe("already_retired");
  });
});

describe("destination listing and lookup", () => {
  it("lists tenant-scoped destinations and filters by state", async () => {
    const { service } = makeService();
    const a = await service.register({ nodeId: NODE_ID, label: "a", idempotencyKey: "k1" });
    const b = await service.register({ nodeId: NODE_ID, label: "b", idempotencyKey: "k2" });
    await service.register({ nodeId: OTHER_NODE_ID, label: "other", idempotencyKey: "k3" });
    if (a.status !== "created" || b.status !== "created") throw new Error("expected created");

    await service.bless({
      nodeId: NODE_ID,
      destinationId: a.destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });

    const all = await service.list(NODE_ID, {});
    expect(all.items).toHaveLength(2);

    const blessed = await service.list(NODE_ID, { state: "BLESSED" });
    expect(blessed.items).toHaveLength(1);
    expect(blessed.items[0]?.destinationId).toBe(a.destination.destinationId);

    const pending = await service.list(NODE_ID, { state: "PENDING" });
    expect(pending.items).toHaveLength(1);
    expect(pending.items[0]?.destinationId).toBe(b.destination.destinationId);
  });

  it("paginates with an after cursor and limit", async () => {
    const { service } = makeService();
    const created: Uuid[] = [];
    for (let i = 1; i <= 3; i += 1) {
      const outcome = await service.register({
        nodeId: NODE_ID,
        label: `d${i}`,
        idempotencyKey: `k${i}`,
      });
      if (outcome.status === "created") created.push(outcome.destination.destinationId);
    }
    created.sort((x, y) => x.localeCompare(y));

    const pageOne = await service.list(NODE_ID, { limit: 2 });
    expect(pageOne.items.map((item) => item.destinationId)).toEqual(created.slice(0, 2));
    expect(pageOne.nextAfter).toBe(created[1]);

    const pageTwo = await service.list(NODE_ID, {
      limit: 2,
      after: pageOne.nextAfter ?? undefined,
    });
    expect(pageTwo.items.map((item) => item.destinationId)).toEqual(created.slice(2));
    expect(pageTwo.nextAfter).toBeNull();
  });

  it("gets a single destination scoped to the node", async () => {
    const { service, destination } = await registerPending();
    const found = await service.get(NODE_ID, destination.destinationId);
    expect(found?.destinationId).toBe(destination.destinationId);
    // PENDING is never move-eligible.
    expect(found?.move_eligible).toBe(false);
    expect(found?.ineligibility_reason).toBe("DESTINATION_NOT_BLESSED");

    const crossTenant = await service.get(OTHER_NODE_ID, destination.destinationId);
    expect(crossTenant).toBeNull();

    const missing = await service.get(NODE_ID, uuid("missing"));
    expect(missing).toBeNull();
  });
});

describe("derived move_eligible / ineligibility_reason", () => {
  it("marks PENDING destinations move_eligible:false with DESTINATION_NOT_BLESSED", async () => {
    const { service, destination } = await registerPending();
    const page = await service.list(NODE_ID, {});
    expect(page.items).toHaveLength(1);
    const item = page.items[0]!;
    expect(item.destinationId).toBe(destination.destinationId);
    expect(item.state).toBe("PENDING");
    expect(item.move_eligible).toBe(false);
    expect(item.ineligibility_reason).toBe("DESTINATION_NOT_BLESSED");
  });

  it("marks BLESSED-but-not-recovery-verified move_eligible:false with INVALID_RECOVERY_VERIFIED_AT", async () => {
    const { service, store, destination } = await registerPending();
    await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    // Wallet remains AVAILABLE + node_generated, recoveryVerifiedAt stays null.
    store.setWalletFacts(destination.walletId, {
      walletState: "AVAILABLE",
      recoveryVerifiedAt: null,
    });

    const page = await service.list(NODE_ID, { state: "BLESSED" });
    expect(page.items).toHaveLength(1);
    const item = page.items[0]!;
    expect(item.state).toBe("BLESSED");
    expect(item.move_eligible).toBe(false);
    expect(item.ineligibility_reason).toBe("INVALID_RECOVERY_VERIFIED_AT");
  });

  it("marks BLESSED + recovery-verified + QUARANTINED wallet move_eligible:false with WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE", async () => {
    const { service, store, destination } = await registerPending();
    await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    store.setWalletFacts(destination.walletId, {
      walletState: "QUARANTINED",
      recoveryVerifiedAt: RECOVERY_VERIFIED_AT,
    });

    const page = await service.list(NODE_ID, {});
    const item = page.items[0]!;
    expect(item.move_eligible).toBe(false);
    expect(item.ineligibility_reason).toBe("WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE");
  });

  it("marks BLESSED + recovery-verified + RETIRED wallet move_eligible:false with WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE", async () => {
    const { service, store, destination } = await registerPending();
    await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    store.setWalletFacts(destination.walletId, {
      walletState: "RETIRED",
      recoveryVerifiedAt: RECOVERY_VERIFIED_AT,
    });

    const page = await service.list(NODE_ID, {});
    const item = page.items[0]!;
    expect(item.move_eligible).toBe(false);
    expect(item.ineligibility_reason).toBe("WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE");
  });

  it("marks fully sink-eligible destinations move_eligible:true with null reason", async () => {
    const { service, store, destination } = await registerPending();
    await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    store.setWalletFacts(destination.walletId, {
      walletState: "AVAILABLE",
      recoveryVerifiedAt: RECOVERY_VERIFIED_AT,
    });

    const page = await service.list(NODE_ID, {});
    const item = page.items[0]!;
    expect(item.move_eligible).toBe(true);
    expect(item.ineligibility_reason).toBeNull();
  });

  it("derives eligibility live — not from cached destination columns", async () => {
    const { service, store, destination } = await registerPending();
    await service.bless({
      nodeId: NODE_ID,
      destinationId: destination.destinationId,
      nonce: NONCE,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      deviceSignature: "device-signature",
      deviceKeyId: DEVICE_KEY_ID,
    });
    store.setWalletFacts(destination.walletId, {
      walletState: "AVAILABLE",
      recoveryVerifiedAt: RECOVERY_VERIFIED_AT,
    });

    const eligible = await service.list(NODE_ID, {});
    expect(eligible.items[0]?.move_eligible).toBe(true);

    // Mutate only wallet facts (no destination column write) — list must flip.
    store.setWalletFacts(destination.walletId, { walletState: "QUARANTINED" });
    const after = await service.list(NODE_ID, {});
    expect(after.items[0]?.move_eligible).toBe(false);
    expect(after.items[0]?.ineligibility_reason).toBe("WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE");

    // DestinationRecord itself still has no move_eligible column.
    const raw = await store.findById(destination.destinationId);
    expect(raw).not.toHaveProperty("move_eligible");
    expect(raw).not.toHaveProperty("ineligibility_reason");
  });

  it("deriveMoveEligibility fails closed when wallet facts are missing", () => {
    const dest: DestinationRecord = {
      destinationId: uuid("d1"),
      nodeId: NODE_ID,
      walletId: uuid("w1"),
      walletPublicKey: pubkey("w1"),
      state: "BLESSED",
      label: "x",
      blessedAt: ISSUED_AT,
      blessedByDeviceKeyId: DEVICE_KEY_ID,
      blessingArtifactId: ARTIFACT_ID,
      retiredAt: null,
      createdAt: ISSUED_AT,
    };
    expect(deriveMoveEligibility(dest, null)).toEqual({
      move_eligible: false,
      ineligibility_reason: "INVALID_KEY_ORIGIN",
    });
  });
});
