// offline e2e: create destination -> device bless -> BLESSED;
// MOVE dest eligibility while BLESSED; retire blocks further moves.
// Never logs device private keys (AC4).

import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, randomUUID, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  createDestinationService,
  type DestinationRecord,
  type DestinationStore,
  type DestinationWalletFacts,
  type NewDestination,
} from "../src/api/destination.js";
import { createDeviceBlessingAuthorizer } from "../src/device/blessing-authorizer.js";
import type { EnrolledDeviceKey } from "../src/device/types.js";
import { isMoveDestinationEligible } from "../src/move/create.js";
import { buildDestinationBless } from "../src/protocol/suite/builders.js";
import type { Uuid, WalletPublicKey } from "../src/protocol/scalars.js";
import type { WalletKeyOrigin, WalletState } from "@zucoins/generic-node-contracts/custody";

const NODE_ID = "11111111-1111-4111-8111-111111111111" as Uuid;
const DEVICE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" as Uuid;

function privFromSeed(byte: number) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

function pubB64(byte: number): string {
  const pub = createPublicKey(privFromSeed(byte));
  const spki = pub.export({ format: "der", type: "spki" }) as Buffer;
  return Buffer.from(spki.subarray(-32))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function signB64(preimage: string, seedByte: number): string {
  const sig = sign(null, Buffer.from(preimage, "utf8"), privFromSeed(seedByte));
  return Buffer.from(sig).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

const DEVICE_PUB = pubB64(0x01);

class MemoryStore implements DestinationStore {
  readonly rows = new Map<string, DestinationRecord & { idempotencyKey: string }>();
  readonly factRows = new Map<string, DestinationWalletFacts>();

  async findById(id: Uuid) {
    return this.rows.get(id) ?? null;
  }
  async findByIdempotencyKey(nodeId: Uuid, key: string) {
    for (const r of this.rows.values()) {
      if (r.nodeId === nodeId && r.idempotencyKey === key) return r;
    }
    return null;
  }
  async insert(record: NewDestination, idempotencyKey: string) {
    const row = {
      ...record,
      state: "PENDING" as const,
      blessedAt: null,
      blessedByDeviceKeyId: null,
      blessingArtifactId: null,
      retiredAt: null,
      idempotencyKey,
    };
    this.rows.set(record.destinationId, row);
    this.factRows.set(record.walletId, {
      keyOrigin: "node_generated" as WalletKeyOrigin,
      walletState: "AVAILABLE" as WalletState,
      recoveryVerifiedAt: "2026-07-01T00:00:00.000Z",
    });
    return row;
  }
  async walletKeyOrigin(walletId: Uuid) {
    return this.factRows.get(walletId)?.keyOrigin ?? null;
  }
  async walletFacts(walletId: Uuid) {
    return this.factRows.get(walletId) ?? null;
  }
  async bless(
    destinationId: Uuid,
    patch: {
      readonly blessedAt: string;
      readonly blessedByDeviceKeyId: Uuid;
      readonly blessingArtifactId: Uuid;
    },
  ) {
    const cur = this.rows.get(destinationId);
    if (cur === undefined || cur.state !== "PENDING") return null;
    const next = {
      ...cur,
      state: "BLESSED" as const,
      blessedAt: patch.blessedAt,
      blessedByDeviceKeyId: patch.blessedByDeviceKeyId,
      blessingArtifactId: patch.blessingArtifactId,
    };
    this.rows.set(destinationId, next);
    return next;
  }
  async retire(destinationId: Uuid, retiredAt: string) {
    const cur = this.rows.get(destinationId);
    if (cur === undefined) throw new Error("missing");
    const next = { ...cur, state: "RETIRED" as const, retiredAt };
    this.rows.set(destinationId, next);
    return next;
  }
  async list(nodeId: Uuid) {
    const items = [...this.rows.values()].filter((r) => r.nodeId === nodeId);
    return { items, nextAfter: null };
  }
}

function toMoveRecord(d: DestinationRecord, facts: DestinationWalletFacts) {
  return {
    destinationId: d.destinationId,
    nodeId: d.nodeId,
    walletId: d.walletId,
    publicKey: d.walletPublicKey,
    keyOrigin: facts.keyOrigin,
    walletState: facts.walletState,
    destinationState: d.state,
    recoveryVerifiedAt: facts.recoveryVerifiedAt,
  };
}

describe("destination bless offline e2e", () => {
  const seedByte = 0x01;
  const privateSeedHex = Buffer.alloc(32, seedByte).toString("hex");
  const logs: string[] = [];
  const log = (msg: string) => {
    logs.push(msg);
    if (msg.includes(privateSeedHex) || /BEGIN PRIVATE KEY/i.test(msg)) {
      throw new Error("private key material logged");
    }
  };

  it("create -> bless -> BLESSED; MOVE admits; retire blocks", async () => {
    const store = new MemoryStore();
    const device: EnrolledDeviceKey = {
      id: DEVICE_ID,
      nodeId: NODE_ID,
      publicKey: DEVICE_PUB,
      label: "e2e-device",
      enrolledAt: "2026-01-01T00:00:00.000Z",
      revokedAt: null,
    };
    const artifacts: unknown[] = [];
    const now = Date.parse("2026-07-18T00:02:00.000Z");
    const authorizer = createDeviceBlessingAuthorizer({
      nowMs: () => now,
      lookupDevice: async (nodeId, id) =>
        nodeId === device.nodeId && id === device.id && device.revokedAt === null
          ? device
          : null,
      persistArtifact: async (row) => {
        artifacts.push(row);
        log(
          `artifact persisted sha=${row.preimageSha256} device=${row.deviceSignature.slice(0, 8)}...`,
        );
        return "inserted";
      },
      appendAudit: async (e) => {
        log(`audit ${e.action} code=${e.code} device=${e.deviceKeyId}`);
      },
    });

    const sourceWalletId = randomUUID() as Uuid;
    const walletId = randomUUID() as Uuid;
    const destId = randomUUID() as Uuid;
    const walletPub = pubB64(0x03) as WalletPublicKey;

    const service = createDestinationService({
      store,
      keyGenerator: {
        async generate() {
          return { walletId, publicKey: walletPub };
        },
      },
      blessingAuthorizer: authorizer,
      clock: { now: () => "2026-07-18T00:02:00.000Z" },
      ids: { destinationId: () => destId },
    });

    const registered = await service.register({
      nodeId: NODE_ID,
      label: "e2e-sink",
      idempotencyKey: "e2e-1",
    });
    expect(registered.status).toBe("created");
    if (registered.status !== "created") return;

    const facts0 = await store.walletFacts(walletId);
    expect(facts0).not.toBeNull();
    const preMove = isMoveDestinationEligible(
      toMoveRecord(registered.destination, facts0!),
      NODE_ID,
      sourceWalletId,
    );
    expect(preMove.ok).toBe(false);
    if (!preMove.ok) {
      expect(preMove.detail).toContain("PENDING");
    }

    const issuedAt = "2026-07-18T00:00:00.000Z";
    const expiresAt = "2026-07-18T00:05:00.000Z";
    const nonce = randomUUID() as Uuid;
    const preimage = buildDestinationBless({
      node_id: NODE_ID,
      destination_id: destId,
      wallet_id: walletId,
      wallet_pubkey: walletPub,
      nonce,
      issued_at: issuedAt,
      expires_at: expiresAt,
    });
    const deviceSignature = signB64(preimage.preimageText, seedByte);

    const blessed = await service.bless({
      nodeId: NODE_ID,
      destinationId: destId,
      nonce,
      issuedAt,
      expiresAt,
      deviceSignature,
      deviceKeyId: DEVICE_ID,
    });
    expect(blessed.status).toBe("blessed");
    if (blessed.status !== "blessed") return;
    expect(blessed.destination.state).toBe("BLESSED");
    expect(blessed.destination.blessedByDeviceKeyId).toBe(DEVICE_ID);
    expect(blessed.destination.blessingArtifactId).not.toBeNull();
    expect(artifacts).toHaveLength(1);

    const facts1 = await store.walletFacts(walletId);
    const moveOk = isMoveDestinationEligible(
      toMoveRecord(blessed.destination, facts1!),
      NODE_ID,
      sourceWalletId,
    );
    expect(moveOk).toEqual({ ok: true });

    const retired = await service.retire({ nodeId: NODE_ID, destinationId: destId });
    expect(retired.status).toBe("retired");
    if (retired.status !== "retired") return;
    expect(retired.destination.state).toBe("RETIRED");

    const facts2 = await store.walletFacts(walletId);
    const afterRetire = isMoveDestinationEligible(
      toMoveRecord(retired.destination, facts2!),
      NODE_ID,
      sourceWalletId,
    );
    expect(afterRetire.ok).toBe(false);
    if (!afterRetire.ok) {
      expect(afterRetire.detail).toContain("RETIRED");
    }

    expect(logs.join("\n")).not.toContain(privateSeedHex);
  });
});
