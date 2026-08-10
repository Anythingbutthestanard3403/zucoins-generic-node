// Crash recovery must prove every IMPLEMENTED sealed store under the new root.
import { afterEach, describe, expect, it } from "vitest";

import {
  InMemoryMasterKeyRotationJournal,
  InMemoryRotationUnitOfWork,
  ProcessLocalMasterKeyRotationInterlock,
  SEALED_STORES,
  buildKeyRing,
  createPushSecretSealer,
  deriveRootKey,
  rewrapPushSecretStore,
  rotateMasterKey,
  type MasterKeyRotationInput,
  type PushSecretRewrapRow,
} from "../src/index.js";

const OLD_ROOT = deriveRootKey(Buffer.from("old-push-finalize-master-key-32b!"), Buffer.from("push-finalize-salt"));
const NEW_ROOT = deriveRootKey(Buffer.from("new-push-finalize-master-key-32b!"), Buffer.from("push-finalize-salt"));
const FROM_EPOCH = 4;
const TO_EPOCH = 5;

async function pushRow(root: Uint8Array): Promise<PushSecretRewrapRow> {
  const identity = {
    nodeId: "11111111-1111-4111-8111-111111111111",
    walletId: "22222222-2222-4222-8222-222222222222",
    materialKind: "ECDH_PRIVATE_KEY" as const,
    keyVersion: 1,
  };
  return {
    identity,
    envelope: await createPushSecretSealer({
      rootKey: root,
      nodeId: identity.nodeId,
      walletId: identity.walletId,
    }).seal(Buffer.alloc(32, 0x6a), "ECDH_PRIVATE"),
  };
}

function corruptEnvelope(envelope: string): string {
  const index = envelope.indexOf(".") + 5;
  const replacement = envelope[index] === "A" ? "B" : "A";
  return `${envelope.slice(0, index)}${replacement}${envelope.slice(index + 1)}`;
}

async function completeJournal(): Promise<InMemoryMasterKeyRotationJournal> {
  const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
  await journal.begin({ fromEpoch: FROM_EPOCH, toEpoch: TO_EPOCH });
  await journal.complete();
  return journal;
}

function input(
  journal: InMemoryMasterKeyRotationJournal,
  rows: readonly PushSecretRewrapRow[],
  overrides: Partial<MasterKeyRotationInput> = {},
): MasterKeyRotationInput {
  return {
    sealedStores: SEALED_STORES,
    walletVault: { rows: [] },
    countWalletVaultRows: async () => 0,
    nodeSigningKeys: { rows: [] },
    countNodeSigningKeyRows: async () => 0,
    pushReceiverSecrets: { rows },
    countPushSecretRows: async () => rows.length,
    totpSecrets: { rows: [] },
    countTotpSecretRows: async () => 0,
    rewrapPushSecretStore,
    keyRing: buildKeyRing({
      writerEpoch: TO_EPOCH,
      writerRoot: NEW_ROOT,
      retained: [{ epoch: FROM_EPOCH, root: OLD_ROOT }],
    }),
    fromEpoch: FROM_EPOCH,
    toEpoch: TO_EPOCH,
    oldRootKey: OLD_ROOT,
    newRootKey: NEW_ROOT,
    journal,
    interlock: new ProcessLocalMasterKeyRotationInterlock(),
    commitWalletVault: async () => {},
    unitOfWork: new InMemoryRotationUnitOfWork(),
    ...overrides,
  };
}

afterEach(() => InMemoryRotationUnitOfWork.resetGlobalHolder());

describe("ROTATION_COMPLETE push-secret recovery", () => {
  it("settles only after a non-empty new-root push population verifies and reports every store", async () => {
    const journal = await completeJournal();
    const result = await rotateMasterKey(input(journal, [await pushRow(NEW_ROOT)]));

    expect(result.committed).toBe(true);
    expect((await journal.read()).phase).toBe("STABLE");
    expect(result.stores.map((store) => store.storeId)).toEqual(SEALED_STORES.map((store) => store.id));
    expect(result.stores.find((store) => store.storeId === "PUSH_RECEIVER_SECRETS")?.result).toEqual({
      rowsBefore: 1,
      rowsAfter: 1,
      rewrapped: 1,
    });
  });

  it("fails closed and leaves COMPLETE when a push row remains under the old root", async () => {
    const journal = await completeJournal();
    await expect(rotateMasterKey(input(journal, [await pushRow(OLD_ROOT)]))).rejects.toMatchObject({
      code: "ROTATION_STATE",
    });
    expect((await journal.read()).phase).toBe("ROTATION_COMPLETE");
  });

  it("fails closed and leaves COMPLETE when a new-root push row is corrupt", async () => {
    const journal = await completeJournal();
    const row = await pushRow(NEW_ROOT);
    const corrupt = {
      ...row,
      envelope: corruptEnvelope(row.envelope),
    };
    await expect(rotateMasterKey(input(journal, [corrupt]))).rejects.toMatchObject({
      code: "ROTATION_STATE",
    });
    expect((await journal.read()).phase).toBe("ROTATION_COMPLETE");
  });

  it("fails closed on missing IMPLEMENTED-store ports and on push count parity drift", async () => {
    for (const overrides of [
      { nodeSigningKeys: undefined },
      { countNodeSigningKeyRows: undefined },
      { pushReceiverSecrets: undefined },
      { countPushSecretRows: undefined },
      { rewrapPushSecretStore: undefined },
      { countPushSecretRows: async () => 2 },
    ] satisfies Array<Partial<MasterKeyRotationInput>>) {
      const journal = await completeJournal();
      await expect(
        rotateMasterKey(input(journal, [await pushRow(NEW_ROOT)], overrides)),
      ).rejects.toMatchObject({ code: "ROTATION_STATE" });
      expect((await journal.read()).phase).toBe("ROTATION_COMPLETE");
    }
  });
});
