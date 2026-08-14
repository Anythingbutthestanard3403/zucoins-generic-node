// Unit tests: implementer funding wallet pin + node default setting (ZTR-1287).
import { describe, expect, it } from "vitest";

import {
  DEFAULT_FUNDING_WALLET_SETTING_KEY,
  InMemoryDefaultFundingWallet,
  InMemoryImplementerRegistry,
} from "./index.js";

const NODE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ACTOR = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const WALLET_A = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const WALLET_B = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const PUB_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const PUB_B = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

describe("InMemoryImplementerRegistry setFundingWallet", () => {
  it("DEFAULT clears explicit pin", async () => {
    const reg = new InMemoryImplementerRegistry();
    reg.seedWallet({ id: WALLET_A, public_key: PUB_A });
    const created = await reg.create({ name: "zukaz", actorId: ACTOR, nodeId: NODE });
    const attached = await reg.setFundingWallet({
      implementerId: created.id,
      mode: "WALLET_ID",
      walletId: WALLET_A,
      actorId: ACTOR,
      nodeId: NODE,
    });
    expect(attached.ok).toBe(true);
    if (!attached.ok) return;
    expect(attached.implementer.funding_wallet_id).toBe(WALLET_A);
    expect(attached.implementer.funding_wallet_public_key).toBe(PUB_A);

    const cleared = await reg.setFundingWallet({
      implementerId: created.id,
      mode: "DEFAULT",
      actorId: ACTOR,
      nodeId: NODE,
    });
    expect(cleared.ok).toBe(true);
    if (!cleared.ok) return;
    expect(cleared.implementer.funding_wallet_id).toBeNull();
    expect(cleared.implementer.funding_wallet_public_key).toBeNull();
    expect(reg.audit.some((a) => a.action === "implementer.funding_wallet_changed")).toBe(true);
  });

  it("WALLET_ID refuses missing and retired wallets", async () => {
    const reg = new InMemoryImplementerRegistry();
    reg.seedWallet({ id: WALLET_B, public_key: PUB_B, retired: true });
    const created = await reg.create({ name: "x", actorId: ACTOR, nodeId: NODE });

    const missing = await reg.setFundingWallet({
      implementerId: created.id,
      mode: "WALLET_ID",
      walletId: WALLET_A,
      actorId: ACTOR,
      nodeId: NODE,
    });
    expect(missing).toEqual({ ok: false, reason: "wallet_not_found" });

    const retired = await reg.setFundingWallet({
      implementerId: created.id,
      mode: "WALLET_ID",
      walletId: WALLET_B,
      actorId: ACTOR,
      nodeId: NODE,
    });
    expect(retired).toEqual({ ok: false, reason: "wallet_retired" });

    const noId = await reg.setFundingWallet({
      implementerId: created.id,
      mode: "WALLET_ID",
      actorId: ACTOR,
      nodeId: NODE,
    });
    expect(noId).toEqual({ ok: false, reason: "wallet_id_required" });
  });

  it("CREATE requires a pre-minted walletId (registry has no vault)", async () => {
    const reg = new InMemoryImplementerRegistry();
    const created = await reg.create({ name: "y", actorId: ACTOR, nodeId: NODE });
    const bare = await reg.setFundingWallet({
      implementerId: created.id,
      mode: "CREATE",
      actorId: ACTOR,
      nodeId: NODE,
    });
    expect(bare).toEqual({ ok: false, reason: "create_not_supported" });

    reg.seedWallet({ id: WALLET_A, public_key: PUB_A });
    const ok = await reg.setFundingWallet({
      implementerId: created.id,
      mode: "CREATE",
      walletId: WALLET_A,
      actorId: ACTOR,
      nodeId: NODE,
    });
    expect(ok.ok).toBe(true);
    if (!ok.ok) return;
    expect(ok.implementer.funding_wallet_id).toBe(WALLET_A);
  });

  it("list/get include funding fields", async () => {
    const reg = new InMemoryImplementerRegistry();
    reg.seed({
      id: "11111111-1111-4111-8111-111111111111",
      name: "seeded",
      created_at: "2026-01-01T00:00:00.000Z",
      retired_at: null,
      funding_wallet_id: WALLET_A,
      funding_wallet_public_key: PUB_A,
    });
    const list = await reg.list();
    expect(list[0]?.funding_wallet_id).toBe(WALLET_A);
    expect(list[0]?.funding_wallet_public_key).toBe(PUB_A);
    const got = await reg.get("11111111-1111-4111-8111-111111111111");
    expect(got?.funding_wallet_public_key).toBe(PUB_A);
  });
});

describe("InMemoryDefaultFundingWallet", () => {
  it("get/set with row_version CAS and clear", async () => {
    const port = new InMemoryDefaultFundingWallet();
    port.seedWallet(WALLET_A, PUB_A);
    expect(DEFAULT_FUNDING_WALLET_SETTING_KEY).toBe("integration.default_funding_wallet_id");

    const empty = await port.get();
    expect(empty).toEqual({ wallet_id: null, public_key: null, row_version: 0 });

    const set = await port.set({
      walletId: WALLET_A,
      expectedRowVersion: 0,
      actorId: ACTOR,
      nodeId: NODE,
    });
    expect(set.ok).toBe(true);
    if (!set.ok) return;
    expect(set.result.wallet_id).toBe(WALLET_A);
    expect(set.result.public_key).toBe(PUB_A);
    expect(set.result.row_version).toBe(1);

    const stale = await port.set({
      walletId: null,
      expectedRowVersion: 0,
      actorId: ACTOR,
      nodeId: NODE,
    });
    expect(stale).toEqual({ ok: false, reason: "conflict" });

    const clear = await port.set({
      walletId: null,
      expectedRowVersion: 1,
      actorId: ACTOR,
      nodeId: NODE,
    });
    expect(clear.ok).toBe(true);
    if (!clear.ok) return;
    expect(clear.result.wallet_id).toBeNull();
    expect(clear.result.row_version).toBe(0);
  });

  it("refuses retired wallet", async () => {
    const port = new InMemoryDefaultFundingWallet();
    port.seedWallet(WALLET_B, PUB_B, true);
    const out = await port.set({
      walletId: WALLET_B,
      expectedRowVersion: 0,
      actorId: ACTOR,
      nodeId: NODE,
    });
    expect(out).toEqual({ ok: false, reason: "wallet_retired" });
  });
});
