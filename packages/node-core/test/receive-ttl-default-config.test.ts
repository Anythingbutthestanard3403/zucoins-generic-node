/**
 * ZTR-1170 — configured RECEIVE_TTL_DEFAULT_SECS is the create default.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { createSqlOperationRouteStore } from "../src/operation-route-store.js";
import {
  DEFAULT_EXPIRES_IN_SECONDS,
  type ReceiveAdmissionStore,
  type ReceiveOperation,
} from "../src/receive/admission.js";

const here = dirname(fileURLToPath(import.meta.url));

function mockReceiveStore(onAdmit: (ttlMs: number) => void): ReceiveAdmissionStore {
  return {
    async findDestination() {
      return null;
    },
    async insertInProgress() {
      throw new Error("unused");
    },
    async insertQueuedIfCapAllows(operation: ReceiveOperation) {
      onAdmit(operation.ttlMs);
      return { kind: "INSERTED", operation };
    },
    async findByIdempotency() {
      return null;
    },
    async completeOperation() {
      return true;
    },
    async findByOperationId() {
      return null;
    },
    async countQueuedReceives() {
      return 0;
    },
  };
}

const stubMove = {
  async createInternalMove() {
    throw new Error("unused");
  },
  async findById() {
    return null;
  },
} as never;

const stubSend = {
  async createExternalSend() {
    throw new Error("unused");
  },
  async findById() {
    return null;
  },
} as never;

const stubSigner = {
  keyId: "k",
  async signExpectedArtifact() {
    throw new Error("unused");
  },
} as never;

const baseInput = {
  amount_zkz: "1",
  anchor: "anchor_value_here1",
  after_landing: { kind: "HOLD" as const, destination_id: null },
  idempotencyKey: "idempotency-key-16chars",
  implementerId: "33333333-3333-4333-8333-333333333333",
};

describe("receive TTL default from config (ZTR-1170)", () => {
  it("uses receiveTtlDefaultSecs when expires_in_seconds omitted", async () => {
    let seenTtlMs = -1;
    const store = createSqlOperationRouteStore({
      nodeId: "11111111-1111-4111-8111-111111111111",
      queueCap: 10,
      receive: mockReceiveStore((ttl) => {
        seenTtlMs = ttl;
      }),
      move: stubMove,
      send: stubSend,
      sendSigner: stubSigner,
      receiveTtlDefaultSecs: 900,
      generateId: () => "22222222-2222-4222-8222-222222222222",
      now: () => 1_700_000_000_000,
    });
    const result = await store.createReceive(baseInput);
    expect(result.status).toBe(202);
    expect(seenTtlMs).toBe(900_000);
  });

  it("falls back to DEFAULT_EXPIRES_IN_SECONDS when config omitted", async () => {
    let seenTtlMs = -1;
    const store = createSqlOperationRouteStore({
      nodeId: "11111111-1111-4111-8111-111111111111",
      queueCap: 10,
      receive: mockReceiveStore((ttl) => {
        seenTtlMs = ttl;
      }),
      move: stubMove,
      send: stubSend,
      sendSigner: stubSigner,
      generateId: () => "22222222-2222-4222-8222-222222222222",
      now: () => 1_700_000_000_000,
    });
    await store.createReceive({ ...baseInput, anchor: "anchor_value_here2" });
    expect(seenTtlMs).toBe(DEFAULT_EXPIRES_IN_SECONDS * 1000);
  });

  it("main.ts threads RECEIVE_TTL_DEFAULT_SECS into createSqlOperationRouteStore", () => {
    const mainSrc = readFileSync(
      join(here, "..", "..", "..", "apps", "generic-node", "src", "main.ts"),
      "utf8",
    );
    expect(mainSrc).toMatch(/receiveTtlDefaultSecs:\s*config\.RECEIVE_TTL_DEFAULT_SECS/);
  });
});
