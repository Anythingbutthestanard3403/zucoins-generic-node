import { randomBytes } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  createPushSecretSealer,
  rewrapPushSecretStore,
  type PushSecretRewrapRow,
} from "../src/push/index.js";
import { SEALED_STORES } from "../src/schema/sealed-store-registry.contract.js";
import {
  InMemoryMasterKeyRotationJournal,
  InMemoryRotationUnitOfWork,
  ProcessLocalMasterKeyRotationInterlock,
  buildKeyRing,
  rotateMasterKey,
} from "../src/vault/index.js";

const OLD_ROOT = Buffer.alloc(32, 0x31);
const NEW_ROOT = Buffer.alloc(32, 0x72);
const FROM_EPOCH = 4;
const TO_EPOCH = 5;
const NODE_ID = "11111111-1111-4111-8111-111111111111";

function purposeFor(materialKind: PushSecretRewrapRow["identity"]["materialKind"]) {
  return materialKind === "ECDH_PRIVATE_KEY" ? "ECDH_PRIVATE" : "AUTH_SECRET";
}

async function row(
  walletId: string,
  materialKind: PushSecretRewrapRow["identity"]["materialKind"],
  root: Uint8Array = OLD_ROOT,
  keyVersion = 1,
): Promise<PushSecretRewrapRow> {
  const identity = { nodeId: NODE_ID, walletId, materialKind, keyVersion } as const;
  const secret = randomBytes(materialKind === "ECDH_PRIVATE_KEY" ? 32 : 16);
  const envelope = await createPushSecretSealer({ rootKey: root, nodeId: NODE_ID, walletId }).seal(
    secret,
    purposeFor(materialKind),
  );
  return { identity, envelope };
}

function keyRing() {
  return buildKeyRing({
    writerEpoch: TO_EPOCH,
    writerRoot: NEW_ROOT,
    retained: [{ epoch: FROM_EPOCH, root: OLD_ROOT }],
  });
}

function emptyOtherStores() {
  return {
    walletVault: { rows: [] },
    countWalletVaultRows: async () => 0,
    nodeSigningKeys: { rows: [] },
    countNodeSigningKeyRows: async () => 0,
    totpSecrets: { rows: [] },
    countTotpSecretRows: async () => 0,
  } as const;
}

describe("PUSH_RECEIVER_SECRETS canonical master-key rewrap", () => {
  it("opens with the old root and seals byte-exact material under the new root", async () => {
    const rows = [await row("wallet_a", "ECDH_PRIVATE_KEY"), await row("wallet_a", "AUTH_SECRET")];
    const before = await Promise.all(
      rows.map((r) =>
        createPushSecretSealer({ rootKey: OLD_ROOT, nodeId: r.identity.nodeId, walletId: r.identity.walletId }).open(
          r.envelope,
          purposeFor(r.identity.materialKind),
        ),
      ),
    );

    const report = await rewrapPushSecretStore({
      keyRing: keyRing(),
      newRootKey: NEW_ROOT,
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      rows,
    });

    expect(report.result).toEqual({ rowsBefore: 2, rowsAfter: 2, rewrapped: 2 });
    for (let index = 0; index < rows.length; index += 1) {
      const after = report.rewrappedRows[index]!;
      const purpose = purposeFor(after.identity.materialKind);
      await expect(
        createPushSecretSealer({ rootKey: OLD_ROOT, nodeId: after.identity.nodeId, walletId: after.identity.walletId }).open(
          after.envelope,
          purpose,
        ),
      ).rejects.toThrow();
      const opened = await createPushSecretSealer({
        rootKey: NEW_ROOT,
        nodeId: after.identity.nodeId,
        walletId: after.identity.walletId,
      }).open(after.envelope, purpose);
      expect(opened.equals(before[index]!)).toBe(true);
    }
  });

  it("maps material purpose, binds purpose, and leaves keyVersion out of AAD", async () => {
    const source = await row("wallet_mapping", "ECDH_PRIVATE_KEY", OLD_ROOT, 7);
    const report = await rewrapPushSecretStore({
      keyRing: keyRing(),
      newRootKey: NEW_ROOT,
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      rows: [source],
    });
    const after = report.rewrappedRows[0]!;
    const sealer = createPushSecretSealer({ rootKey: NEW_ROOT, nodeId: NODE_ID, walletId: "wallet_mapping" });
    await expect(sealer.open(after.envelope, "AUTH_SECRET")).rejects.toThrow();
    await expect(sealer.open(after.envelope, "ECDH_PRIVATE")).resolves.toHaveLength(32);
    expect(after.identity.keyVersion).toBe(7);
  });

  it("rotates push rows in the same transaction and refuses a stale census", async () => {
    const rows = [await row("wallet_tx", "ECDH_PRIVATE_KEY"), await row("wallet_tx", "AUTH_SECRET")];
    const committed: PushSecretRewrapRow[][] = [];
    const uow = new InMemoryRotationUnitOfWork();

    const result = await rotateMasterKey({
      sealedStores: SEALED_STORES,
      ...emptyOtherStores(),
      pushReceiverSecrets: { rows },
      countPushSecretRows: async () => rows.length,
      keyRing: keyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal: new InMemoryMasterKeyRotationJournal(FROM_EPOCH),
      interlock: new ProcessLocalMasterKeyRotationInterlock(),
      commitWalletVault: async () => {},
      commitPushSecrets: async (rewrapped) => committed.push([...rewrapped]),
      rewrapPushSecretStore,
      unitOfWork: uow,
    });

    expect(result.committed).toBe(true);
    expect(committed).toHaveLength(1);
    expect(uow.commits).toBe(1);

    const commitPushSecrets = vi.fn();
    await expect(
      rotateMasterKey({
        sealedStores: SEALED_STORES,
        ...emptyOtherStores(),
        pushReceiverSecrets: { rows },
        countPushSecretRows: async () => rows.length + 1,
        keyRing: keyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal: new InMemoryMasterKeyRotationJournal(FROM_EPOCH),
        interlock: new ProcessLocalMasterKeyRotationInterlock(),
        commitWalletVault: async () => {},
        commitPushSecrets,
        rewrapPushSecretStore,
        unitOfWork: new InMemoryRotationUnitOfWork(),
      }),
    ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });
    expect(commitPushSecrets).not.toHaveBeenCalled();
  });
});
