// ZTR-1312: public dest HTTP JSON is snake_case. Domain types stay camelCase.
import { describe, expect, it } from "vitest";

import {
  destinationToWire,
  handleCreateDestination,
  listDestinationsBody,
} from "../src/api/destination-http.js";
import type {
  DestinationListItem,
  DestinationPage,
  DestinationRecord,
  DestinationService,
} from "../src/api/destination.js";
import type { Uuid, WalletPublicKey } from "../src/protocol/scalars.js";

const NODE = "11111111-1111-4111-8111-111111111111" as Uuid;
const DEST = "22222222-2222-4222-8222-222222222222" as Uuid;
const WALLET = "33333333-3333-4333-8333-333333333333" as Uuid;
const DEVICE = "44444444-4444-4444-8444-444444444444" as Uuid;
const ARTIFACT = "55555555-5555-4555-8555-555555555555" as Uuid;
const PUB = "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=" as WalletPublicKey;

const CAMEL_DEST_KEYS = [
  "destinationId",
  "nodeId",
  "walletId",
  "walletPublicKey",
  "blessedAt",
  "blessedByDeviceKeyId",
  "blessingArtifactId",
  "retiredAt",
  "createdAt",
] as const;

const SNAKE_CREATE_KEYS = [
  "destination_id",
  "node_id",
  "wallet_id",
  "wallet_public_key",
  "state",
  "label",
  "blessed_at",
  "blessed_by_device_key_id",
  "blessing_artifact_id",
  "retired_at",
  "created_at",
] as const;

const SNAKE_LIST_ITEM_KEYS = [...SNAKE_CREATE_KEYS, "move_eligible", "ineligibility_reason"] as const;

function collectKeys(value: unknown, into: Set<string>): void {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, into);
    return;
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    into.add(key);
    collectKeys(child, into);
  }
}

const record: DestinationRecord = {
  destinationId: DEST,
  nodeId: NODE,
  walletId: WALLET,
  walletPublicKey: PUB,
  state: "BLESSED",
  label: "sink",
  blessedAt: "2026-07-30T00:00:00.000Z",
  blessedByDeviceKeyId: DEVICE,
  blessingArtifactId: ARTIFACT,
  retiredAt: null,
  createdAt: "2026-07-29T00:00:00.000Z",
};

const listItem: DestinationListItem = {
  ...record,
  move_eligible: true,
  ineligibility_reason: null,
};

describe("destinations HTTP wire snake_case (ZTR-1312)", () => {
  it("maps domain camelCase onto OpenAPI snake_case field names", () => {
    expect(Object.keys(destinationToWire(record))).toEqual([...SNAKE_CREATE_KEYS]);
    expect(destinationToWire(record)).toEqual({
      destination_id: DEST,
      node_id: NODE,
      wallet_id: WALLET,
      wallet_public_key: PUB,
      state: "BLESSED",
      label: "sink",
      blessed_at: "2026-07-30T00:00:00.000Z",
      blessed_by_device_key_id: DEVICE,
      blessing_artifact_id: ARTIFACT,
      retired_at: null,
      created_at: "2026-07-29T00:00:00.000Z",
    });
    expect(Object.keys(destinationToWire(listItem))).toEqual([...SNAKE_LIST_ITEM_KEYS]);
  });

  it("fails if a camelCase dest field leaks onto create or list JSON", async () => {
    const page: DestinationPage = { items: [listItem], nextAfter: DEST };
    const listBody = JSON.parse(listDestinationsBody(page)) as Record<string, unknown>;
    const listKeys = new Set<string>();
    collectKeys(listBody, listKeys);
    expect(listBody).toEqual({
      items: [destinationToWire(listItem)],
      next_after: DEST,
    });
    expect(Object.keys(listBody.items as object[])).not.toContain("destinationId");

    const service = {
      register: async () => ({ status: "created" as const, destination: record }),
      bless: async () => {
        throw new Error("unused");
      },
      retire: async () => {
        throw new Error("unused");
      },
      list: async () => page,
      get: async () => listItem,
    } as unknown as DestinationService;

    const created = await handleCreateDestination(
      {
        requestId: "req-create",
        principal: { implementerId: "55555555-5555-4555-8555-555555555555" },
        request: { headers: { "idempotency-key": "idem-create-1" }, query: {} },
        parsedBody: { label: "sink" },
        idempotencyTenantId: "55555555-5555-4555-8555-555555555555",
      } as never,
      { service, nodeId: NODE },
    );
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    const createBody = JSON.parse(created.body) as Record<string, unknown>;
    const createKeys = new Set<string>();
    collectKeys(createBody, createKeys);

    for (const camel of CAMEL_DEST_KEYS) {
      expect(listKeys.has(camel), `list leaked ${camel}`).toBe(false);
      expect(createKeys.has(camel), `create leaked ${camel}`).toBe(false);
    }
    expect([...createKeys].sort()).toEqual([...SNAKE_CREATE_KEYS].sort());
    expect([...listKeys].sort()).toEqual(
      ["items", "next_after", ...SNAKE_LIST_ITEM_KEYS].sort(),
    );
  });
});
