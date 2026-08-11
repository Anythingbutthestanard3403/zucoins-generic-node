// delivered-payload resolution, at-rest sealing, and the external-operation
// gate. These are the three places where a mistake is SILENT: a wrong payload path yields
// a 204 with nothing enqueued, a wrong AAD yields a wallet decrypting another's keys, and
// a wrong gate lets an external receive proceed with no way to be notified of payment.

import { createHash, createDecipheriv, hkdfSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildWalletDekInfo, HKDF_DEK_LABEL } from "@zucoins/generic-node-contracts/vault";
import { describe, expect, it } from "vitest";

import {
  buildIdProofQuery,
  buildPushReceiverDekInfo,
  buildPushSecretAad,
  createPushNoTransferCodeStreakTracker,
  createPushReceiveMetricsPort,
  createPushReceiver,
  createPushSecretSealer,
  createPushSubscriptionService,
  DEFAULT_PUSH_NO_TRANSFER_CODE_STREAK_THRESHOLD,
  generateAuthSecret,
  generateEcdhKeypair,
  generateEndpointId,
  isValidEndpointId,
  parsePushCleartext,
  PUSH_RECEIVER_DEK_HKDF_LABEL,
  PushSubscriptionRequiredError,
  resolveTransferCodeFromEnvelope,
  type PushAuditSink,
  type PushGatewayActions,
  type PushReceiveMetricOutcome,
  type PushReceiveMetricShape,
  type PushSubscriptionRow,
  type PushSubscriptionStore,
  type PushWalletRef,
} from "../src/push/index.ts";

const ROOT = new Uint8Array(32).fill(7);
const NODE_ID = "11111111-1111-4111-8111-111111111111";
const WALLET_ID = "22222222-2222-4222-8222-222222222222";
const CODE = "JTdCJTIydmVyc2lvbiUyMiUzQSUyMjElMjI";

describe("delivered payload resolution", () => {
  it("prefers the APNs shape", () => {
    const r = resolveTransferCodeFromEnvelope({
      aps: { data: { type_data: { transfer_code_encoded: CODE } } },
      data: { type_data: { transfer_code_encoded: "wrong" } },
    });
    expect(r).toEqual({ transferCodeEncoded: CODE, shape: "aps" });
  });

  it("falls back to the standard FCM/Mozilla shape", () => {
    const r = resolveTransferCodeFromEnvelope({
      data: { type_data: { transfer_code_encoded: CODE } },
    });
    expect(r).toEqual({ transferCodeEncoded: CODE, shape: "data" });
  });

  // The original silent-204: reading the send-side field FIRST resolved undefined against a
  // reshaped envelope, so nothing was ever enqueued. It stays reachable, but only last.
  it("accepts an un-reshaped send-side envelope only as the trailing fallback", () => {
    const r = resolveTransferCodeFromEnvelope({
      notification_type_data: { transfer_code_encoded: CODE },
    });
    expect(r).toEqual({ transferCodeEncoded: CODE, shape: "send_side_fallback" });
  });

  it("returns null for payloads carrying no code rather than throwing", () => {
    for (const envelope of [
      null,
      undefined,
      "string",
      {},
      { data: {} },
      { data: { type_data: [] } },
      { data: { type_data: { transfer_code_encoded: "" } } },
      { aps: { data: { type_data: { other: "x" } } } },
    ]) {
      expect(resolveTransferCodeFromEnvelope(envelope)).toBeNull();
    }
  });

  it("folds malformed cleartext to null instead of throwing", () => {
    expect(parsePushCleartext(Buffer.from("not json", "utf8"))).toBeNull();
    expect(resolveTransferCodeFromEnvelope(parsePushCleartext(Buffer.from("{", "utf8")))).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// ZTR-1154 — digest-pinned delivered envelope golden (FCM/Mozilla data shape).
// Bytes live under packages/generic-node-contracts/goldens/push/. No committed
// test writes or regenerates them; the sha256 constant is the pin.
// ---------------------------------------------------------------------------

const PUSH_GOLDEN_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../generic-node-contracts/goldens/push",
);
const PUSH_ENVELOPE_GOLDEN_NAME = "delivered-envelope.data.v1.json.txt";
/** SHA-256 of the exact golden bytes. Update only with a reviewed golden change. */
const PUSH_ENVELOPE_DATA_V1_SHA256 =
  "936d81f42de6beebd93493565bceca995aa67514aea6e23205bfb74657a220b5";

describe("delivered envelope golden (ZTR-1154)", () => {
  const raw = readFileSync(join(PUSH_GOLDEN_DIR, PUSH_ENVELOPE_GOLDEN_NAME));

  it("has no trailing newline in the raw golden bytes", () => {
    expect(raw.length).toBeGreaterThan(0);
    expect(raw[raw.length - 1]).not.toBe(0x0a);
  });

  it("digest-pins the golden (sha256 hard-coded; test never writes the file)", () => {
    const digest = createHash("sha256").update(raw).digest("hex");
    expect(digest).toBe(PUSH_ENVELOPE_DATA_V1_SHA256);
  });

  it("resolveTransferCodeFromEnvelope extracts the code from the golden bytes", () => {
    const envelope = parsePushCleartext(raw);
    const resolved = resolveTransferCodeFromEnvelope(envelope);
    expect(resolved).not.toBeNull();
    expect(resolved!.shape).toBe("data");
    expect(resolved!.transferCodeEncoded.length).toBeGreaterThan(0);
    // Embedded code is the pinned RECEIVE transfer-code golden.
    const receiveCode = readFileSync(
      join(PUSH_GOLDEN_DIR, "../transfer-code/receive-code.v1.b64url.txt"),
      "utf8",
    );
    expect(resolved!.transferCodeEncoded).toBe(receiveCode);
  });
});

describe("push receive outcome metrics + no_transfer_code streak (ZTR-1154)", () => {
  it("defaults the consecutive threshold to 20 with documented rationale constant", () => {
    expect(DEFAULT_PUSH_NO_TRANSFER_CODE_STREAK_THRESHOLD).toBe(20);
  });

  it("increments streak on no_transfer_code, resets on enqueued, ignores decrypt_failed", () => {
    const alerts: number[] = [];
    const tracker = createPushNoTransferCodeStreakTracker({
      threshold: 3,
      onAlert: (a) => alerts.push(a.streak),
    });
    tracker.observe("no_transfer_code");
    tracker.observe("no_transfer_code");
    expect(tracker.streak()).toBe(2);
    expect(alerts).toEqual([]);
    tracker.observe("decrypt_failed");
    expect(tracker.streak()).toBe(2);
    tracker.observe("no_transfer_code");
    expect(tracker.streak()).toBe(3);
    expect(alerts).toEqual([3]);
    // Second observation at/above threshold does not re-fire until reset.
    tracker.observe("no_transfer_code");
    expect(alerts).toEqual([3]);
    tracker.observe("enqueued");
    expect(tracker.streak()).toBe(0);
    tracker.observe("no_transfer_code");
    tracker.observe("no_transfer_code");
    tracker.observe("no_transfer_code");
    expect(alerts).toEqual([3, 3]);
  });

  it("createPushReceiver emits outcome metrics with shape on enqueued", async () => {
    const seen: Array<{ outcome: PushReceiveMetricOutcome; shape: PushReceiveMetricShape }> = [];
    const store: PushSubscriptionStore = {
      async insert() {},
      async findByWalletId() {
        return null;
      },
      async findByEndpointId(endpointId) {
        if (endpointId !== "wp_abcdefghijklmnopqrst") return null;
        return {
          walletId: WALLET_ID,
          walletPublicKey: "pk",
          endpointId,
          receiverEcdhPublic: "pub",
          receiverEcdhPrivateSealed: "sealed:aa",
          receiverAuthSecretSealed: "sealed:bb",
          status: "ACTIVE",
          appServerPublicKey: "app",
        };
      },
      async listSubscribableWallets() {
        return [];
      },
      async markStatus() {},
      async replaceSealedMaterial() {},
    };
    const sealer = {
      async open(sealed: string) {
        if (sealed.startsWith("sealed:")) return Buffer.from(sealed.slice(7), "utf8");
        throw new Error("unopenable");
      },
    };
    const golden = readFileSync(join(PUSH_GOLDEN_DIR, PUSH_ENVELOPE_GOLDEN_NAME));
    const receiver = createPushReceiver({
      store,
      sealer,
      decryptor: {
        async decrypt() {
          return golden;
        },
      },
      sink: () => true,
      metrics: createPushReceiveMetricsPort({
        sink: {
          onOutcome(outcome, shape) {
            seen.push({ outcome, shape });
          },
        },
      }),
    });
    const outcome = await receiver.receive("wp_abcdefghijklmnopqrst", Buffer.from("body"));
    expect(outcome).toBe("enqueued");
    expect(seen).toEqual([{ outcome: "enqueued", shape: "data" }]);
  });

  it("createPushReceiver emits no_transfer_code when envelope has no code", async () => {
    const seen: string[] = [];
    const store: PushSubscriptionStore = {
      async insert() {},
      async findByWalletId() {
        return null;
      },
      async findByEndpointId() {
        return {
          walletId: WALLET_ID,
          walletPublicKey: "pk",
          endpointId: "wp_abcdefghijklmnopqrst",
          receiverEcdhPublic: "pub",
          receiverEcdhPrivateSealed: "sealed:aa",
          receiverAuthSecretSealed: "sealed:bb",
          status: "ACTIVE",
          appServerPublicKey: "app",
        };
      },
      async listSubscribableWallets() {
        return [];
      },
      async markStatus() {},
      async replaceSealedMaterial() {},
    };
    const receiver = createPushReceiver({
      store,
      sealer: {
        async open(sealed: string) {
          if (sealed.startsWith("sealed:")) return Buffer.from(sealed.slice(7), "utf8");
          throw new Error("unopenable");
        },
      },
      decryptor: {
        async decrypt() {
          return Buffer.from(JSON.stringify({ data: { type_data: { other: "x" } } }), "utf8");
        },
      },
      sink: () => true,
      metrics: {
        onOutcome(outcome) {
          seen.push(outcome);
        },
      },
    });
    expect(await receiver.receive("wp_abcdefghijklmnopqrst", Buffer.from("b"))).toBe(
      "no_transfer_code",
    );
    expect(seen).toEqual(["no_transfer_code"]);
  });
});

describe("push endpoint ids", () => {
  it("mints ids that satisfy the validator and are unguessable-length", () => {
    const id = generateEndpointId();
    expect(isValidEndpointId(id)).toBe(true);
    expect(id.startsWith("wp_")).toBe(true);
    expect(id.length).toBeGreaterThanOrEqual(23);
  });

  it("rejects traversal and injection attempts", () => {
    for (const bad of ["", "wp_", "../../etc", "wp_short", "zz_aaaaaaaaaaaaaaaaaaaaaaaa", "wp_a/b"]) {
      expect(isValidEndpointId(bad)).toBe(false);
    }
  });
});

describe("at-rest sealing", () => {
  const sealerFor = (walletId: string) =>
    createPushSecretSealer({ rootKey: ROOT, nodeId: NODE_ID, walletId });

  it("round-trips an ECDH private half and an auth secret", async () => {
    const keypair = generateEcdhKeypair();
    const sealer = sealerFor(WALLET_ID);
    const sealedEcdh = await sealer.seal(keypair.privateKeyBytes, "ECDH_PRIVATE");
    expect(Buffer.compare(await sealer.open(sealedEcdh, "ECDH_PRIVATE"), keypair.privateKeyBytes)).toBe(0);

    const auth = generateAuthSecret();
    expect(auth.length).toBe(16);
    const sealedAuth = await sealer.seal(auth, "AUTH_SECRET");
    expect(Buffer.compare(await sealer.open(sealedAuth, "AUTH_SECRET"), auth)).toBe(0);
  });

  it("never emits the plaintext inside the envelope text", async () => {
    const secret = Buffer.from("SUPERSECRETMATERIAL0123456789abc", "utf8");
    const sealed = await sealerFor(WALLET_ID).seal(secret, "ECDH_PRIVATE");
    expect(sealed).not.toContain("SUPERSECRET");
    expect(sealed.startsWith("zp-push-seal-v1.")).toBe(true);
  });

  // The AAD is the reason a stolen blob is useless in another row.
  it("refuses a blob moved to a different wallet, node, or purpose", async () => {
    const sealed = await sealerFor(WALLET_ID).seal(Buffer.from("abcd"), "ECDH_PRIVATE");
    const otherWallet = createPushSecretSealer({
      rootKey: ROOT,
      nodeId: NODE_ID,
      walletId: "33333333-3333-4333-8333-333333333333",
    });
    await expect(otherWallet.open(sealed, "ECDH_PRIVATE")).rejects.toThrow();

    // Same wallet, wrong purpose — the AAD differs, so the auth secret's opener cannot
    // read the ECDH envelope.
    await expect(sealerFor(WALLET_ID).open(sealed, "AUTH_SECRET")).rejects.toThrow();

    const otherNode = createPushSecretSealer({
      rootKey: ROOT,
      nodeId: "44444444-4444-4444-8444-444444444444",
      walletId: WALLET_ID,
    });
    await expect(otherNode.open(sealed, "ECDH_PRIVATE")).rejects.toThrow();
  });

  it("refuses a wrong root key and a tampered envelope", async () => {
    const sealed = await sealerFor(WALLET_ID).seal(Buffer.from("abcd"), "ECDH_PRIVATE");
    const wrongRoot = createPushSecretSealer({
      rootKey: new Uint8Array(32).fill(9),
      nodeId: NODE_ID,
      walletId: WALLET_ID,
    });
    await expect(wrongRoot.open(sealed, "ECDH_PRIVATE")).rejects.toThrow();
    await expect(sealerFor(WALLET_ID).open("bogus.AAAA", "ECDH_PRIVATE")).rejects.toThrow(
      /envelope prefix/u,
    );
    await expect(
      sealerFor(WALLET_ID).open("zp-push-seal-v1.AAAA", "ECDH_PRIVATE"),
    ).rejects.toThrow(/truncated/u);

    // Real tampering flips a byte INSIDE the envelope. Appending characters after the
    // base64 padding would not, because Node's decoder discards them — the decoded bytes,
    // and therefore the GCM tag check, would be unchanged.
    const dot = sealed.indexOf(".");
    const blob = Buffer.from(sealed.slice(dot + 1), "base64");
    for (const offset of [0, blob.length - 1]) {
      const mutated = Buffer.from(blob);
      mutated[offset] ^= 0xff;
      await expect(
        sealerFor(WALLET_ID).open(`zp-push-seal-v1.${mutated.toString("base64")}`, "ECDH_PRIVATE"),
      ).rejects.toThrow();
    }
  });

  it("binds the AAD to node, wallet and purpose", () => {
    expect(buildPushSecretAad({ nodeId: NODE_ID, walletId: WALLET_ID, purpose: "AUTH_SECRET" })).toBe(
      `zp-push-seal-v1|${NODE_ID}|${WALLET_ID}|AUTH_SECRET`,
    );
  });

  // i byte contract (the byte-exact signing rule — never reorder, never reformat). Under a shared
  // root the label is the ONLY thing stopping this store deriving the wallet vault's key.
  it("derives under its own globally-unique HKDF label, LF-joined and version-free", () => {
    const info = buildPushReceiverDekInfo({ nodeId: NODE_ID, walletId: WALLET_ID });
    expect(PUSH_RECEIVER_DEK_HKDF_LABEL).toBe("zp-push-receiver-dek-v1");
    expect(PUSH_RECEIVER_DEK_HKDF_LABEL).not.toBe(HKDF_DEK_LABEL);
    expect(info).toBe(`zp-push-receiver-dek-v1\n${NODE_ID}\n${WALLET_ID}`);
    // Three fields, no key_version: rewrap trial-decrypts across the key ring, so the info
    // must not move when a row's version does or old rows stop being found.
    expect(info.split("\n")).toHaveLength(3);
    // Cross-store: the same (node, wallet) must not produce the wallet vault's info.
    expect(info).not.toBe(
      buildWalletDekInfo({ nodeId: NODE_ID, walletId: WALLET_ID, keyVersion: "1" }),
    );
  });

});

// The AAD tests above pass just as well when the AES key IS the shared vault root —
// which is the collision i forbids. These drive the key itself: the AAD is held
// constant and only the derivation inputs move.
describe("labelled DEK derivation", () => {
  const dekFor = (nodeId: string, walletId: string): Buffer =>
    Buffer.from(
      hkdfSync(
        "sha256",
        Buffer.from(ROOT),
        Buffer.alloc(0),
        Buffer.from(buildPushReceiverDekInfo({ nodeId, walletId }), "utf8"),
        32,
      ),
    );

  /** Opens an envelope with a caller-supplied key, bypassing the sealer's own derivation. */
  const openWith = (sealed: string, key: Buffer, aad: string): Buffer => {
    const blob = Buffer.from(sealed.slice(sealed.indexOf(".") + 1), "base64");
    const decipher = createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(blob.subarray(12, 28));
    return Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]);
  };

  const aad = buildPushSecretAad({
    nodeId: NODE_ID,
    walletId: WALLET_ID,
    purpose: "ECDH_PRIVATE",
  });
  const seal = (): Promise<string> =>
    createPushSecretSealer({ rootKey: ROOT, nodeId: NODE_ID, walletId: WALLET_ID }).seal(
      Buffer.from("abcd"),
      "ECDH_PRIVATE",
    );

  it("keys AES-256-GCM with HKDF(root, label\\nnode\\nwallet), never with the root itself", async () => {
    const sealed = await seal();
    expect(openWith(sealed, dekFor(NODE_ID, WALLET_ID), aad).toString("utf8")).toBe("abcd");
    // The earlier defect: root as the AES key, shared with every other store under it.
    expect(() => openWith(sealed, Buffer.from(ROOT), aad)).toThrow();
  });

  it("gives every (node, wallet) pair its own key, not just its own AAD", async () => {
    const sealed = await seal();
    const otherWallet = "33333333-3333-4333-8333-333333333333";
    const otherNode = "44444444-4444-4444-8444-444444444444";
    for (const wrong of [dekFor(NODE_ID, otherWallet), dekFor(otherNode, WALLET_ID)]) {
      expect(() => openWith(sealed, wrong, aad)).toThrow();
    }
    const keys = [
      dekFor(NODE_ID, WALLET_ID),
      dekFor(NODE_ID, otherWallet),
      dekFor(otherNode, WALLET_ID),
    ].map((k) => k.toString("hex"));
    expect(new Set(keys).size).toBe(3);
  });
});

describe("id proof", () => {
  it("signs the timestamp decimal string and orders the five fields exactly", async () => {
    const signed: { walletId: string; preimage: string }[] = [];
    const query = await buildIdProofQuery({
      walletId: WALLET_ID,
      walletPublicKeyB64url: "A".repeat(43) + "=",
      nowSecs: 1785470676,
      sign: async (walletId, bytes) => {
        signed.push({ walletId, preimage: Buffer.from(bytes).toString("utf8") });
        return "sig";
      },
    });
    // The signed preimage is the timestamp itself — not JSON, not the whole query.
    expect(signed).toEqual([{ walletId: WALLET_ID, preimage: "1785470676" }]);
    expect(query).toBe(
      "utm_source=zupayments_node_v1" +
        "&zucoin__data_pass_through__version=1" +
        `&zucoin__data_pass_through__key_public__base64urlsafe=${encodeURIComponent("A".repeat(43) + "=")}` +
        "&zucoin__data_pass_through__data_timestamp_secs=1785470676" +
        "&zucoin__data_pass_through__data_timestamp_secs_signature__base64urlsafe=sig",
    );
  });
});

// ── subscription service ────────────────────────────────────────────────────────────

function memoryStore(seed: PushSubscriptionRow[] = []): PushSubscriptionStore & {
  rows: PushSubscriptionRow[];
} {
  const rows = [...seed];
  return {
    rows,
    async findByWalletId(walletId) {
      return rows.find((r) => r.walletId === walletId) ?? null;
    },
    async findByEndpointId(endpointId) {
      return rows.find((r) => r.endpointId === endpointId) ?? null;
    },
    async insert(row) {
      // Mirrors the SQL adapter's ON CONFLICT (wallet_id) DO NOTHING.
      if (rows.some((r) => r.walletId === row.walletId)) return;
      rows.push(row);
    },
    async replaceSealedMaterial(input) {
      const i = rows.findIndex((r) => r.walletId === input.walletId);
      if (i >= 0) {
        rows[i] = {
          ...rows[i]!,
          receiverEcdhPublic: input.receiverEcdhPublic,
          receiverEcdhPrivateSealed: input.receiverEcdhPrivateSealed,
          receiverAuthSecretSealed: input.receiverAuthSecretSealed,
          status: "FAILED",
        };
      }
    },
    async markStatus(walletId, status, appServerPublicKey) {
      const i = rows.findIndex((r) => r.walletId === walletId);
      if (i >= 0) {
        rows[i] = {
          ...rows[i]!,
          status,
          appServerPublicKey:
            appServerPublicKey !== null && appServerPublicKey !== undefined
              ? appServerPublicKey
              : rows[i]!.appServerPublicKey,
        };
      }
    },
    async listSubscribableWallets() {
      return rows.map((r) => ({ walletId: r.walletId, publicKey: r.walletPublicKey }));
    },
  };
}

function gateway(overrides: Partial<PushGatewayActions> = {}): PushGatewayActions {
  return {
    async subscribe() {},
    async hasSubscriptionForPublicKey() {
      return true;
    },
    async getAppServerPublicKey() {
      return "appkey";
    },
    ...overrides,
  };
}

const WALLET: PushWalletRef = { walletId: WALLET_ID, publicKey: "B".repeat(43) + "=" };

function service(
  store: PushSubscriptionStore,
  gw: PushGatewayActions,
  audit?: PushAuditSink,
) {
  return createPushSubscriptionService({
    store,
    sealer: createPushSecretSealer({ rootKey: ROOT, nodeId: NODE_ID, walletId: WALLET_ID }),
    gateway: gw,
    sign: async () => "sig",
    nodePublicUrl: "https://node.example",
    audit,
  });
}

describe("subscription lifecycle", () => {
  it("provisions a wallet and marks it ACTIVE only after the gateway acknowledges", async () => {
    const store = memoryStore();
    const result = await service(store, gateway()).provision(WALLET);
    expect(result.outcome).toBe("subscribed");
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0]!.status).toBe("ACTIVE");
    expect(store.rows[0]!.endpointId).toMatch(/^wp_/u);
  });

  // Pessimistic insert: a crash between INSERT and ack must not claim a remote subscription.
  it("leaves the row FAILED when the gateway rejects, and never throws", async () => {
    const store = memoryStore();
    const result = await service(
      store,
      gateway({
        subscribe: async () => {
          throw new Error("gateway down");
        },
      }),
    ).provision(WALLET);
    expect(result.outcome).toBe("failed");
    expect(store.rows[0]!.status).toBe("FAILED");
  });

  // Re-subscribing must not mint a new endpoint: the old URL would be orphaned at the
  // push service while we advertise a new one.
  it("reuses the existing endpoint id and ECDH keypair on re-subscribe", async () => {
    const store = memoryStore();
    const svc = service(store, gateway());
    const first = await svc.provision(WALLET);
    const second = await svc.provision(WALLET);
    expect(second.endpointId).toBe(first.endpointId);
    expect(store.rows).toHaveLength(1);
  });

  it("re-subscribes wallets the push service reports absent", async () => {
    const store = memoryStore();
    const svc = service(store, gateway());
    await svc.provision(WALLET);
    await store.markStatus(WALLET_ID, "FAILED", null);

    const summary = await service(
      store,
      gateway({ hasSubscriptionForPublicKey: async () => false }),
    ).reconcileAll();
    expect(summary.checked).toBe(1);
    expect(summary.resubscribed).toBe(1);
    expect(store.rows[0]!.status).toBe("ACTIVE");
  });

  // Self-heal. A row whose sealed columns no longer open (a wrong root, a rewrap that
  // never landed, a corrupted column) used to fail OPEN: the open threw out of ensureRow,
  // provision audited and returned, and the row stayed ACTIVE for the external-operation
  // gate to wave through. The material is regenerable, so the fix is to re-mint it.
  it("re-mints over the same endpoint id when the sealed material no longer opens", async () => {
    const store = memoryStore();
    const svc = service(store, gateway());
    const first = await svc.provision(WALLET);
    const publicBefore = store.rows[0]!.receiverEcdhPublic;
    store.rows[0] = {
      ...store.rows[0]!,
      receiverEcdhPrivateSealed: "zp-push-seal-v1.AAAA",
      receiverAuthSecretSealed: "zp-push-seal-v1.AAAA",
    };

    const second = await svc.provision(WALLET);
    expect(second.outcome).toBe("subscribed");
    // The published URL must survive the heal, or the push service keeps an orphan.
    expect(second.endpointId).toBe(first.endpointId);
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0]!.receiverEcdhPublic).not.toBe(publicBefore);
    expect(store.rows[0]!.status).toBe("ACTIVE");
    const sealer = createPushSecretSealer({ rootKey: ROOT, nodeId: NODE_ID, walletId: WALLET_ID });
    await expect(
      sealer.open(store.rows[0]!.receiverEcdhPrivateSealed, "ECDH_PRIVATE"),
    ).resolves.toHaveLength(32);
  });

  it("fails CLOSED when the material is unreadable and the re-subscribe also fails", async () => {
    const store = memoryStore();
    await service(store, gateway()).provision(WALLET);
    store.rows[0] = { ...store.rows[0]!, receiverAuthSecretSealed: "zp-push-seal-v1.AAAA" };
    const svc = service(
      store,
      gateway({
        subscribe: async () => {
          throw new Error("gateway down");
        },
      }),
    );
    expect((await svc.provision(WALLET)).outcome).toBe("failed");
    expect(store.rows[0]!.status).toBe("FAILED");
    await expect(svc.requireActiveSubscription(WALLET_ID)).rejects.toBeInstanceOf(
      PushSubscriptionRequiredError,
    );
  });

  // The FAILED mark happens BEFORE the re-mint, so a heal that itself throws still leaves
  // the gate refusing rather than an ACTIVE row nobody can decrypt for.
  it("marks the row FAILED even when the re-mint cannot be persisted", async () => {
    const store = memoryStore();
    const svc = service(store, gateway());
    await svc.provision(WALLET);
    store.rows[0] = { ...store.rows[0]!, receiverAuthSecretSealed: "zp-push-seal-v1.AAAA" };
    store.replaceSealedMaterial = async () => {
      throw new Error("db down");
    };
    expect((await svc.provision(WALLET)).outcome).toBe("failed");
    expect(store.rows[0]!.status).toBe("FAILED");
    await expect(svc.requireActiveSubscription(WALLET_ID)).rejects.toBeInstanceOf(
      PushSubscriptionRequiredError,
    );
  });

  it("keeps sweeping after one wallet fails", async () => {
    const store = memoryStore();
    await service(store, gateway()).provision(WALLET);
    const summary = await service(
      store,
      gateway({
        hasSubscriptionForPublicKey: async () => {
          throw new Error("push api down");
        },
      }),
    ).reconcileAll();
    expect(summary.checked).toBe(1);
    expect(summary.failed).toBe(1);
  });
});

// The Defect-1 fail-open: a row whose envelopes no longer open used to be handed back as-is
// and re-marked ACTIVE, so `requireActiveSubscription` admitted external money for a wallet
// whose push keys were unusable. These drive the recovery, not just the refusal.
describe("self-heal for unopenable sealed material", () => {
  /** A row sealed under a root this node can no longer reproduce (unrewrapped rotation). */
  const staleRow = async (): Promise<PushSubscriptionRow> => {
    const stranger = createPushSecretSealer({
      rootKey: new Uint8Array(32).fill(9),
      nodeId: NODE_ID,
      walletId: WALLET_ID,
    });
    return {
      walletId: WALLET_ID,
      walletPublicKey: WALLET.publicKey,
      endpointId: generateEndpointId(),
      receiverEcdhPublic: "stale-public-half",
      receiverEcdhPrivateSealed: await stranger.seal(
        generateEcdhKeypair().privateKeyBytes,
        "ECDH_PRIVATE",
      ),
      receiverAuthSecretSealed: await stranger.seal(generateAuthSecret(), "AUTH_SECRET"),
      status: "ACTIVE",
      appServerPublicKey: "app-key",
    };
  };

  const openable = (sealed: string) =>
    createPushSecretSealer({ rootKey: ROOT, nodeId: NODE_ID, walletId: WALLET_ID }).open(
      sealed,
      "ECDH_PRIVATE",
    );

  it("mints material this node can actually open when a wallet has no row", async () => {
    const store = memoryStore();
    await service(store, gateway()).provision(WALLET);
    await expect(openable(store.rows[0]!.receiverEcdhPrivateSealed)).resolves.toHaveLength(32);
  });

  it("re-mints in place under the SAME endpoint id and audits the unopenable row", async () => {
    const stale = await staleRow();
    const store = memoryStore([{ ...stale }]);
    const events: { type: string; walletId: string }[] = [];
    const result = await service(store, gateway(), {
      async record(event) {
        events.push({ type: event.type, walletId: event.walletId });
      },
    }).provision(WALLET);

    expect(result.outcome).toBe("subscribed");
    // A new endpoint id would orphan the URL already registered at the push service.
    expect(result.endpointId).toBe(stale.endpointId);
    expect(store.rows[0]!.endpointId).toBe(stale.endpointId);
    expect(store.rows[0]!.receiverEcdhPrivateSealed).not.toBe(stale.receiverEcdhPrivateSealed);
    expect(store.rows[0]!.receiverEcdhPublic).not.toBe(stale.receiverEcdhPublic);
    expect(events).toContainEqual({
      type: "push.sealed_material_unopenable",
      walletId: WALLET_ID,
    });
    await expect(openable(store.rows[0]!.receiverEcdhPrivateSealed)).resolves.toHaveLength(32);
    expect(store.rows[0]!.status).toBe("ACTIVE");
  });

  // The row started ACTIVE with keys it could not use. Whatever else fails, it must not
  // stay that way: FAILED is what the external-operation gate refuses on.
  it("leaves the row FAILED when the re-subscribe cannot complete", async () => {
    const store = memoryStore([await staleRow()]);
    const result = await service(
      store,
      gateway({
        subscribe: async () => {
          throw new Error("gateway down");
        },
      }),
    ).provision(WALLET);
    expect(result.outcome).toBe("failed");
    expect(store.rows[0]!.status).toBe("FAILED");
  });

  it("reconcileAll re-mints and re-registers a wallet the push service reports absent", async () => {
    const stale = await staleRow();
    const store = memoryStore([{ ...stale }]);
    const summary = await service(
      store,
      gateway({ hasSubscriptionForPublicKey: async () => false }),
    ).reconcileAll();
    expect(summary).toMatchObject({ checked: 1, resubscribed: 1, failed: 0 });
    expect(store.rows[0]!.status).toBe("ACTIVE");
    expect(store.rows[0]!.receiverEcdhPrivateSealed).not.toBe(stale.receiverEcdhPrivateSealed);
    await expect(openable(store.rows[0]!.receiverEcdhPrivateSealed)).resolves.toHaveLength(32);
  });
});

describe("external operations require an active subscription", () => {
  it("passes for an ACTIVE wallet", async () => {
    const store = memoryStore();
    const svc = service(store, gateway());
    await svc.provision(WALLET);
    await expect(svc.requireActiveSubscription(WALLET_ID)).resolves.toBeUndefined();
  });

  it("throws for a FAILED subscription — external receives stop when push is down", async () => {
    const store = memoryStore();
    const svc = service(
      store,
      gateway({
        subscribe: async () => {
          throw new Error("down");
        },
      }),
    );
    await svc.provision(WALLET);
    await expect(svc.requireActiveSubscription(WALLET_ID)).rejects.toBeInstanceOf(
      PushSubscriptionRequiredError,
    );
  });

  it("throws for a wallet with no subscription row at all", async () => {
    await expect(
      service(memoryStore(), gateway()).requireActiveSubscription(WALLET_ID),
    ).rejects.toBeInstanceOf(PushSubscriptionRequiredError);
  });
});
