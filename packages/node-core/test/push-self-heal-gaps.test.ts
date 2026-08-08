// Push self-heal gap fixes.
//
// Two latent gaps in the push self-heal path:
// 1. receiver.ts marks FAILED only when sealer.open fails (unopenable sealed material).
//    Decrypt/sink failures stay pure discard  — never a money-path kill switch.
// 2. subscription-service.ts reconcileAll alreadySubscribed skip now verifies the sealed
//    material is openable before skipping, so an ACTIVE row with unopenable material
//    (corrupt envelope, master-key rotation without rewrap) gets re-provisioned.
// 3. the audit record follows the sink's verdict, so a deposit the bounded intake inbox
//    refused is recorded as refused rather than as enqueued (ZTR-1188).

import { describe, expect, it, vi } from "vitest";

import {
  createPushReceiver,
  createPushSubscriptionService,
  type PushAuditSink,
  type PushGatewayActions,
  type PushSecretSealer,
  type PushSubscriptionRow,
  type PushSubscriptionStore,
  type PushWalletRef,
  type WebPushPayloadDecryptor,
} from "../src/push/index.js";

function makeWalletRef(walletId: string): PushWalletRef {
  return {
    walletId,
    publicKey: "test-public-key-" + walletId,
  };
}

function makeInMemoryStore(): PushSubscriptionStore & { rows: Map<string, PushSubscriptionRow> } {
  const rows = new Map<string, PushSubscriptionRow>();
  return {
    rows,
    async insert(row) {
      rows.set(row.walletId, row);
    },
    async findByWalletId(walletId) {
      return rows.get(walletId) ?? null;
    },
    async findByEndpointId(endpointId) {
      for (const row of rows.values()) {
        if (row.endpointId === endpointId) return row;
      }
      return null;
    },
    async listSubscribableWallets() {
      return Array.from(rows.values()).map((r) => makeWalletRef(r.walletId));
    },
    async markStatus(walletId, status, appServerPublicKey) {
      const row = rows.get(walletId);
      if (row) {
        rows.set(walletId, { ...row, status, appServerPublicKey });
      }
    },
    async replaceSealedMaterial(update) {
      const row = rows.get(update.walletId);
      if (row) {
        rows.set(update.walletId, {
          ...row,
          receiverEcdhPublic: update.receiverEcdhPublic,
          receiverEcdhPrivateSealed: update.receiverEcdhPrivateSealed,
          receiverAuthSecretSealed: update.receiverAuthSecretSealed,
        });
      }
    },
  };
}

function makeMockSealer(): PushSecretSealer {
  return {
    async seal(bytes, _purpose) {
      return `sealed:${Buffer.from(bytes).toString("base64")}`;
    },
    async open(sealed, _purpose) {
      if (typeof sealed === "string" && sealed.startsWith("sealed:")) {
        return Buffer.from(sealed.slice(7), "base64");
      }
      throw new Error("unopenable material");
    },
  };
}

function makeMockGateway(hasSubscription = true): PushGatewayActions {
  return {
    async getAppServerPublicKey() {
      return "test-app-server-key";
    },
    async subscribe() {},
    async hasSubscriptionForPublicKey() {
      return hasSubscription;
    },
  };
}

function makeMockDecryptor(shouldFail = false): WebPushPayloadDecryptor {
  return {
    async decrypt() {
      if (shouldFail) {
        throw new Error("decrypt failed");
      }
      // Valid FCM/Mozilla envelope so sink is reached on the happy path.
      return Buffer.from(
        JSON.stringify({ data: { type_data: { transfer_code_encoded: "test-transfer-code" } } }),
      );
    },
  };
}

function makeMockAudit(): PushAuditSink & { records: Array<{ type: string; walletId: string }> } {
  const records: Array<{ type: string; walletId: string }> = [];
  return {
    records,
    async record({ type, walletId }) {
      records.push({ type, walletId });
    },
  };
}

describe("push self-heal gaps", () => {
  describe("receiver markStatus(FAILED) only on sealer.open failure", () => {
    it("marks FAILED when sealed material will not open", async () => {
      const store = makeInMemoryStore();
      const wallet = makeWalletRef("wallet-1");
      await store.insert({
        walletId: wallet.walletId,
        walletPublicKey: wallet.publicKey,
        endpointId: "wp_abcdefghijklmnopqrst",
        receiverEcdhPublic: "ecdh-public",
        receiverEcdhPrivateSealed: "unopenable-material",
        receiverAuthSecretSealed: "unopenable-auth",
        status: "ACTIVE",
        appServerPublicKey: "app-key",
      });

      const audit = makeMockAudit();
      const receiver = createPushReceiver({
        store,
        sealer: makeMockSealer(),
        decryptor: makeMockDecryptor(false),
        sink: () => true,
        audit,
      });

      const outcome = await receiver.receive("wp_abcdefghijklmnopqrst", Buffer.from("encrypted-body"));
      expect(outcome).toBe("decrypt_failed");

      const row = await store.findByWalletId(wallet.walletId);
      expect(row?.status).toBe("FAILED");
      expect(audit.records.some((r) => r.type === "push.receive_decrypt_failed")).toBe(true);
    });

    it("keeps ACTIVE on decrypt-only failure when sealed material is openable", async () => {
      const store = makeInMemoryStore();
      const wallet = makeWalletRef("wallet-1b");
      await store.insert({
        walletId: wallet.walletId,
        walletPublicKey: wallet.publicKey,
        endpointId: "wp_abcdefghijklmnopqrst",
        receiverEcdhPublic: "ecdh-public",
        receiverEcdhPrivateSealed: "sealed:private",
        receiverAuthSecretSealed: "sealed:auth",
        status: "ACTIVE",
        appServerPublicKey: "app-key",
      });

      const audit = makeMockAudit();
      const receiver = createPushReceiver({
        store,
        sealer: makeMockSealer(),
        decryptor: makeMockDecryptor(true),
        sink: () => true,
        audit,
      });

      const outcome = await receiver.receive("wp_abcdefghijklmnopqrst", Buffer.from("encrypted-body"));
      expect(outcome).toBe("decrypt_failed");

      const row = await store.findByWalletId(wallet.walletId);
      expect(row?.status).toBe("ACTIVE");
      expect(audit.records.some((r) => r.type === "push.receive_decrypt_failed")).toBe(true);
    });

    it("keeps ACTIVE when sink throws after successful decrypt", async () => {
      const store = makeInMemoryStore();
      const wallet = makeWalletRef("wallet-1c");
      await store.insert({
        walletId: wallet.walletId,
        walletPublicKey: wallet.publicKey,
        endpointId: "wp_abcdefghijklmnopqrsc",
        receiverEcdhPublic: "ecdh-public",
        receiverEcdhPrivateSealed: "sealed:private",
        receiverAuthSecretSealed: "sealed:auth",
        status: "ACTIVE",
        appServerPublicKey: "app-key",
      });

      const audit = makeMockAudit();
      const receiver = createPushReceiver({
        store,
        sealer: makeMockSealer(),
        decryptor: makeMockDecryptor(false),
        sink: (): boolean => {
          throw new Error("sink failed");
        },
        audit,
      });

      const outcome = await receiver.receive("wp_abcdefghijklmnopqrsc", Buffer.from("encrypted-body"));
      expect(outcome).toBe("decrypt_failed");

      const row = await store.findByWalletId(wallet.walletId);
      expect(row?.status).toBe("ACTIVE");
    });

    it("does not throw when markStatus fails during unopenable-material handling", async () => {
      const store = makeInMemoryStore();
      const wallet = makeWalletRef("wallet-2");
      await store.insert({
        walletId: wallet.walletId,
        walletPublicKey: wallet.publicKey,
        endpointId: "wp_abcdefghijklmnopqrs2",
        receiverEcdhPublic: "ecdh-public",
        receiverEcdhPrivateSealed: "unopenable-material",
        receiverAuthSecretSealed: "unopenable-auth",
        status: "ACTIVE",
        appServerPublicKey: "app-key",
      });

      const failingStore = {
        ...store,
        async markStatus() {
          throw new Error("markStatus failed");
        },
      };

      const receiver = createPushReceiver({
        store: failingStore,
        sealer: makeMockSealer(),
        decryptor: makeMockDecryptor(false),
        sink: () => true,
      });

      const outcome = await receiver.receive("wp_abcdefghijklmnopqrs2", Buffer.from("encrypted-body"));
      expect(outcome).toBe("decrypt_failed");
    });
  });

  describe("receiver audits the sink's verdict, not an assumed enqueue", () => {
    // ZTR-1188: the intake inbox can refuse (push lane at cap). The route still answers 204
    // either way, but the audit trail is the only wallet-scoped record of the deposit — a
    // refusal recorded as `push.receive_enqueued` is a lost credit notification with a record
    // asserting the opposite.
    const insertActiveRow = async (
      store: ReturnType<typeof makeInMemoryStore>,
      walletId: string,
      endpointId: string,
    ): Promise<void> => {
      await store.insert({
        walletId,
        walletPublicKey: makeWalletRef(walletId).publicKey,
        endpointId,
        receiverEcdhPublic: "ecdh-public",
        receiverEcdhPrivateSealed: "sealed:private",
        receiverAuthSecretSealed: "sealed:auth",
        status: "ACTIVE",
        appServerPublicKey: "app-key",
      });
    };

    it("audits push.receive_refused and never push.receive_enqueued when the inbox refuses", async () => {
      const store = makeInMemoryStore();
      await insertActiveRow(store, "wallet-5", "wp_abcdefghijklmnopqrs5");

      const audit = makeMockAudit();
      const receiver = createPushReceiver({
        store,
        sealer: makeMockSealer(),
        decryptor: makeMockDecryptor(false),
        sink: () => false,
        audit,
      });

      const outcome = await receiver.receive("wp_abcdefghijklmnopqrs5", Buffer.from("body"));
      expect(outcome).toBe("refused");
      expect(audit.records).toEqual([{ type: "push.receive_refused", walletId: "wallet-5" }]);

      // The row is not flipped: a shed deposit says nothing about the subscription's health.
      expect((await store.findByWalletId("wallet-5"))?.status).toBe("ACTIVE");
    });

    it("still audits push.receive_enqueued when the inbox accepts", async () => {
      const store = makeInMemoryStore();
      await insertActiveRow(store, "wallet-6", "wp_abcdefghijklmnopqrs6");

      const audit = makeMockAudit();
      const receiver = createPushReceiver({
        store,
        sealer: makeMockSealer(),
        decryptor: makeMockDecryptor(false),
        sink: () => true,
        audit,
      });

      const outcome = await receiver.receive("wp_abcdefghijklmnopqrs6", Buffer.from("body"));
      expect(outcome).toBe("enqueued");
      expect(audit.records).toEqual([{ type: "push.receive_enqueued", walletId: "wallet-6" }]);
    });
  });

  describe("reconcileAll verifies sealed material is openable", () => {
    it("re-provisions when ACTIVE row has unopenable sealed material", async () => {
      const store = makeInMemoryStore();
      const wallet = makeWalletRef("wallet-3");
      await store.insert({
        walletId: wallet.walletId,
        walletPublicKey: wallet.publicKey,
        endpointId: "wp_abcdefghijklmnopqrs3",
        receiverEcdhPublic: "ecdh-public",
        receiverEcdhPrivateSealed: "unopenable-material",
        receiverAuthSecretSealed: "sealed:auth",
        status: "ACTIVE",
        appServerPublicKey: "app-key",
      });

      const gateway = makeMockGateway(true);
      const subscribeSpy = vi.spyOn(gateway, "subscribe");

      const service = createPushSubscriptionService({
        store,
        sealer: makeMockSealer(),
        gateway,
        sign: async () => "test-signature",
        nodePublicUrl: "https://node.example.com",
      });

      const summary = await service.reconcileAll();
      expect(summary.checked).toBe(1);
      expect(summary.resubscribed).toBe(1);
      expect(subscribeSpy).toHaveBeenCalled();

      const row = await store.findByWalletId(wallet.walletId);
      expect(row?.status).toBe("ACTIVE");
      expect(row?.receiverEcdhPrivateSealed).not.toBe("unopenable-material");
    });

    it("skips re-provision when ACTIVE row has openable material", async () => {
      const store = makeInMemoryStore();
      const wallet = makeWalletRef("wallet-4");
      await store.insert({
        walletId: wallet.walletId,
        walletPublicKey: wallet.publicKey,
        endpointId: "wp_abcdefghijklmnopqrs4",
        receiverEcdhPublic: "ecdh-public",
        receiverEcdhPrivateSealed: "sealed:private",
        receiverAuthSecretSealed: "sealed:auth",
        status: "ACTIVE",
        appServerPublicKey: "app-key",
      });

      const gateway = makeMockGateway(true);
      const subscribeSpy = vi.spyOn(gateway, "subscribe");

      const service = createPushSubscriptionService({
        store,
        sealer: makeMockSealer(),
        gateway,
        sign: async () => "test-signature",
        nodePublicUrl: "https://node.example.com",
      });

      const summary = await service.reconcileAll();
      expect(summary.checked).toBe(1);
      expect(summary.alreadySubscribed).toBe(1);
      expect(summary.resubscribed).toBe(0);
      expect(subscribeSpy).not.toHaveBeenCalled();
    });
  });
});
