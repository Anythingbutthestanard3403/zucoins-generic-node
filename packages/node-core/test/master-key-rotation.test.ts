// Atomic master-key rotation driver.
//
// Acceptance:
//   - dry-run: multi-wallet census rewraps with count parity; journal + store unchanged
//   - commit: every wallet opens under new root; pubkey match via openWalletSecret
//   - fail-closed: wrong old key / tampered row aborts with zero mutation
//   - D1: exclusive TX — unitOfWork required; session+xact lock on begin; interlock refuses
//         MOVE_INTERNAL/signUnderLease; concurrent second rotation refused
//   - D2: journal.complete only AFTER unitOfWork.commit; commit-throw leaves writerEpoch
//   - D3: crash-resume mixed population via key-ring reaches COMPLETE under new root
//   - D-B1: false journal marks (mark without durable NEW ciphertext) resume via key-ring
//   - D-B2: SQL UoW commit-throw leaves handle for rollback (xact lock releasable)
//   - D-B4: session lock held through journal.complete; concurrent begin refused during complete
//   - D-B5: ROTATION_COMPLETE + settle-throw resume settles to STABLE; abort log honest
//   - D-B7: SQL begin session-ok/xact-fail unlocks + returns connection (no leak)
//   - registry: DEFERRED stores skipped; WALLET_VAULT required IMPLEMENTED
//   - logs: only store/phase/counts/timing fields (no key/ciphertext bytes)
//

import { createPrivateKey, createPublicKey } from "node:crypto";

import { afterEach, describe, expect, it, vi } from "vitest";

import { SEALED_STORES } from "../src/schema/sealed-store-registry.contract.js";
import {
  ACQUIRE_ROTATION_SESSION_LOCK_SQL,
  ACQUIRE_ROTATION_XACT_LOCK_SQL,
  RELEASE_ROTATION_SESSION_LOCK_SQL,
  InMemoryMasterKeyRotationJournal,
  InMemoryRotationUnitOfWork,
  MASTER_KEY_ROTATION_ADVISORY_LOCK_ID,
  MasterKeyRotationError,
  ProcessLocalMasterKeyRotationInterlock,
  buildKeyRing,
  createSqlRotationUnitOfWork,
  deriveRootKey,
  keyMaterialHygiene,
  openWalletSecret,
  openWithKeyRing,
  rotateMasterKey,
  sealWalletSecret,
  toBase64UrlPadded,
  type RotationUnitOfWork,
  type WalletIdentity,
  type WalletVaultRewrapRow,
} from "../src/vault/index.js";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const MASTER_OLD = Buffer.from("old-master-key-for-rotation-tests!");
const MASTER_NEW = Buffer.from("new-master-key-for-rotation-tests!");
const SALT = Buffer.from("rotation-test-salt");

const OLD_ROOT = deriveRootKey(MASTER_OLD, SALT);
const NEW_ROOT = deriveRootKey(MASTER_NEW, SALT);

const FROM_EPOCH = 1;
const TO_EPOCH = 2;

afterEach(() => {
  InMemoryRotationUnitOfWork.resetGlobalHolder();
});

function makeSecret(seedByte: number): { secretKey: Buffer; publicKey: string } {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const rawPub = Buffer.from(spki).subarray(-32);
  return {
    publicKey: toBase64UrlPadded(rawPub),
    secretKey: Buffer.concat([seed, rawPub]),
  };
}

function makeRow(
  seedByte: number,
  walletOrdinal: number,
  root: Uint8Array = OLD_ROOT,
): {
  row: WalletVaultRewrapRow;
  secretKey: Buffer;
} {
  const { secretKey, publicKey } = makeSecret(seedByte);
  const identity: WalletIdentity = {
    nodeId: "11111111-1111-4111-8111-111111111111",
    // Lexicographic order deliberately non-insertion order (c before a before b digits).
    walletId: `aaaaaaaa-0000-4000-8000-00000000000${walletOrdinal}`,
    keyVersion: 1,
    publicKey,
    keyOrigin: "node_generated",
  };
  const envelope = sealWalletSecret(root, identity, secretKey);
  return { row: { identity, envelope }, secretKey };
}

function registry(): typeof SEALED_STORES {
  return SEALED_STORES;
}

/**
 * Census + the store-count port that proves it, spread into a rotation input together.
 * In this in-memory suite the fixture census IS the store, so the count mirrors it; the
 * D-A2 tests below pass a deliberately divergent count to prove parity can actually fail.
 * NODE_SIGNING_KEYS ports default to empty greenfield (IMPLEMENTED store requires both).
 */
function census(rows: readonly WalletVaultRewrapRow[]): {
  walletVault: { rows: readonly WalletVaultRewrapRow[] };
  countWalletVaultRows: () => Promise<number>;
  nodeSigningKeys: { rows: readonly [] };
  countNodeSigningKeyRows: () => Promise<number>;
  pushReceiverSecrets: { rows: readonly [] };
  countPushSecretRows: () => Promise<number>;
  totpSecrets: { rows: readonly [] };
  countTotpSecretRows: () => Promise<number>;
} {
  return {
    walletVault: { rows },
    countWalletVaultRows: async () => rows.length,
    nodeSigningKeys: { rows: [] },
    countNodeSigningKeyRows: async () => 0,
    pushReceiverSecrets: { rows: [] },
    countPushSecretRows: async () => 0,
    totpSecrets: { rows: [] },
    countTotpSecretRows: async () => 0,
  };
}

function makeInterlock(): ProcessLocalMasterKeyRotationInterlock {
  return new ProcessLocalMasterKeyRotationInterlock();
}

function makeKeyRing() {
  return buildKeyRing({
    writerEpoch: TO_EPOCH,
    writerRoot: NEW_ROOT,
    retained: [{ epoch: FROM_EPOCH, root: OLD_ROOT }],
  });
}

function makeUow(): InMemoryRotationUnitOfWork {
  return new InMemoryRotationUnitOfWork();
}

describe("rotateMasterKey", () => {
  it("dry-run rewraps N>1 wallets with count parity and commits nothing", async () => {
    const fixtures = [1, 2, 3].map((n) => makeRow(0xa0 + n, n));
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const interlock = makeInterlock();
    const uow = makeUow();
    const commit = vi.fn(async () => {
      throw new Error("commit must not run on dry-run");
    });
    const logLines: Array<Record<string, unknown>> = [];

    const result = await rotateMasterKey({
      sealedStores: registry(),
      ...census(fixtures.map((f) => f.row)),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal,
      interlock,
      commitWalletVault: commit,
      unitOfWork: uow,
      dryRun: true,
      logger: {
        info: (obj) => {
          logLines.push(obj);
        },
        error: (obj) => {
          logLines.push(obj);
        },
      },
    });

    expect(result.committed).toBe(false);
    expect(result.dryRun).toBe(true);
    expect(result.walletCount).toBe(3);
    const vaultReport = result.stores.find((s) => s.storeId === "WALLET_VAULT");
    expect(vaultReport?.result).toEqual({ rowsBefore: 3, rowsAfter: 3, rewrapped: 3 });
    expect(result.stores.filter((s) => s.status === "DEFERRED_NO_SEAL_RUNTIME")).toHaveLength(1);
    expect(result.stores.find((s) => s.storeId === "TOTP_SECRET")?.status).toBe("REWRAPPED");
    expect(result.stores.find((s) => s.storeId === "TOTP_SECRET")?.result).toEqual({
      rowsBefore: 0,
      rowsAfter: 0,
      rewrapped: 0,
    });
    expect(result.stores.find((s) => s.storeId === "NODE_SIGNING_KEYS")?.status).toBe("REWRAPPED");
    expect(result.stores.find((s) => s.storeId === "NODE_SIGNING_KEYS")?.result).toEqual({
      rowsBefore: 0,
      rowsAfter: 0,
      rewrapped: 0,
    });

    // Journal restored to STABLE at the original writer epoch.
    const j = await journal.read();
    expect(j.phase).toBe("STABLE");
    expect(j.writerEpoch).toBe(FROM_EPOCH);
    expect(j.rewrappedWalletIds).toEqual([]);

    expect(commit).not.toHaveBeenCalled();
    expect(uow.begins).toBe(1);
    expect(uow.commits).toBe(0);
    expect(uow.rollbacks).toBe(1);
    expect(uow.lockAcquired).toBe(false); // released on rollback
    expect(interlock.acquireCount).toBe(1);
    expect(interlock.releaseCount).toBe(1);
    expect(interlock.held).toBe(false);

    // Original envelopes still open under OLD only.
    for (const f of fixtures) {
      const opened = openWalletSecret(OLD_ROOT, f.row.envelope, f.row.identity);
      try {
        expect(Buffer.from(opened.bytes)).toEqual(f.secretKey);
      } finally {
        opened.wipe();
      }
    }

    // Log hygiene: no key/ciphertext-sized fields.
    const blob = JSON.stringify(logLines);
    expect(blob).not.toMatch(/old-master-key|new-master-key/);
    expect(blob).not.toContain(Buffer.from(OLD_ROOT).toString("base64"));
    expect(blob).not.toContain(Buffer.from(NEW_ROOT).toString("base64"));
  });

  it("committed rotation persists rewrapped rows and advances writer epoch", async () => {
    const fixtures = [1, 2].map((n) => makeRow(0xb0 + n, n));
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const interlock = makeInterlock();
    const uow = makeUow();
    let committed: readonly WalletVaultRewrapRow[] = [];

    const result = await rotateMasterKey({
      sealedStores: registry(),
      ...census(fixtures.map((f) => f.row)),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal,
      interlock,
      commitWalletVault: async (rows) => {
        committed = rows;
      },
      unitOfWork: uow,
      dryRun: false,
    });

    expect(result.committed).toBe(true);
    expect(result.dryRun).toBe(false);
    expect(result.walletCount).toBe(2);
    expect(committed).toHaveLength(2);
    expect(uow.commits).toBe(1);
    expect(uow.ends).toBe(1);
    expect(uow.rollbacks).toBe(0);
    expect(uow.sessionHeld).toBe(false);
    expect(uow.lockAcquired).toBe(false);

    const j = await journal.read();
    expect(j.phase).toBe("STABLE");
    expect(j.writerEpoch).toBe(TO_EPOCH);

    // Canonical order: wallet ids sorted ascending.
    const ids = committed.map((r) => r.identity.walletId);
    expect(ids).toEqual([...ids].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));

    for (let i = 0; i < fixtures.length; i++) {
      const before = fixtures.find((f) => f.row.identity.walletId === committed[i]!.identity.walletId)!;
      const after = committed[i]!;
      expect(after.identity.keyVersion).toBe(before.row.identity.keyVersion);
      const opened = openWalletSecret(NEW_ROOT, after.envelope, after.identity);
      try {
        expect(Buffer.from(opened.bytes)).toEqual(before.secretKey);
      } finally {
        opened.wipe();
      }
      expect(() => openWalletSecret(OLD_ROOT, after.envelope, after.identity)).toThrow();
    }
  });

  it("aborts on wrong old key with zero commit and journal unrestored advance", async () => {
    const fixtures = [1, 2].map((n) => makeRow(0xc0 + n, n));
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const interlock = makeInterlock();
    const uow = makeUow();
    const commit = vi.fn();
    const wrongOld = deriveRootKey(Buffer.from("wrong-old-master-key-material!!"), SALT);

    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        keyRing: buildKeyRing({
          writerEpoch: TO_EPOCH,
          writerRoot: NEW_ROOT,
          retained: [{ epoch: FROM_EPOCH, root: wrongOld }],
        }),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: wrongOld,
        newRootKey: NEW_ROOT,
        journal,
        interlock,
        commitWalletVault: commit,
        unitOfWork: uow,
      }),
    ).rejects.toBeInstanceOf(MasterKeyRotationError);

    expect(commit).not.toHaveBeenCalled();
    expect(uow.commits).toBe(0);
    expect(uow.rollbacks).toBe(1);
    expect(interlock.releaseCount).toBe(1);

    const j = await journal.read();
    expect(j.phase).toBe("STABLE");
    expect(j.writerEpoch).toBe(FROM_EPOCH);
  });

  it("aborts on a tampered row without committing any store", async () => {
    const good = makeRow(0xd1, 1);
    const bad = makeRow(0xd2, 2);
    const tampered: WalletVaultRewrapRow = {
      ...bad.row,
      envelope: {
        ...bad.row.envelope,
        authTag: Buffer.alloc(bad.row.envelope.authTag.length, 0x7f),
      },
    };
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const commit = vi.fn();

    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census([good.row, tampered]),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock: makeInterlock(),
        commitWalletVault: commit,
        unitOfWork: makeUow(),
      }),
    ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });

    expect(commit).not.toHaveBeenCalled();
    expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
  });

  it("refuses equal old/new roots and mismatched key-ring", async () => {
    const { row } = makeRow(0xe1, 1);
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);

    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census([row]),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: OLD_ROOT,
        journal,
        interlock: makeInterlock(),
        commitWalletVault: async () => {},
        unitOfWork: makeUow(),
      }),
    ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });

    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census([row]),
        keyRing: buildKeyRing({
          writerEpoch: FROM_EPOCH, // wrong — must be toEpoch
          writerRoot: OLD_ROOT,
        }),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock: makeInterlock(),
        commitWalletVault: async () => {},
        unitOfWork: makeUow(),
      }),
    ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
  });

  it("releases the interlock even when commitWalletVault throws", async () => {
    const fixtures = [makeRow(0xf1, 1)];
    const interlock = makeInterlock();
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const uow = makeUow();

    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock,
        commitWalletVault: async () => {
          throw new Error("persist failed");
        },
        unitOfWork: uow,
      }),
    ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });

    expect(interlock.acquireCount).toBe(1);
    expect(interlock.releaseCount).toBe(1);
    expect(uow.rollbacks).toBe(1);
    expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
  });
});

describe("D1 — exclusive TX / interlock enforced", () => {
  it("refuses rotateMasterKey when unitOfWork is missing", async () => {
    const fixtures = [makeRow(0x11, 1)];
    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal: new InMemoryMasterKeyRotationJournal(FROM_EPOCH),
        interlock: makeInterlock(),
        commitWalletVault: async () => {},
        // @ts-expect-error — deliberate missing unitOfWork for fail-closed proof
        unitOfWork: undefined,
      }),
    ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
  });

  it("InMemoryRotationUnitOfWork claims MASTER_KEY_ROTATION_ADVISORY_LOCK_ID on begin", async () => {
    const uow = makeUow();
    expect(uow.lockId).toBe(MASTER_KEY_ROTATION_ADVISORY_LOCK_ID);
    expect(uow.lockAcquired).toBe(false);
    await uow.begin();
    expect(uow.lockAcquired).toBe(true);
    await uow.commit();
  });

  it("createSqlRotationUnitOfWork takes session lock then xact lock; end unlocks session", async () => {
    const queries: Array<{ sql: string; params: readonly unknown[] | undefined }> = [];
    const uow = createSqlRotationUnitOfWork({
      async begin() {
        return {
          client: {
            async query(sql, params) {
              queries.push({ sql, params });
              return { rows: [{ locked: true }] };
            },
          },
          async commit() {},
          async rollback() {},
        };
      },
    });
    await uow.begin();
    expect(queries).toEqual([
      {
        sql: ACQUIRE_ROTATION_SESSION_LOCK_SQL,
        params: [MASTER_KEY_ROTATION_ADVISORY_LOCK_ID],
      },
      {
        sql: ACQUIRE_ROTATION_XACT_LOCK_SQL,
        params: [MASTER_KEY_ROTATION_ADVISORY_LOCK_ID],
      },
    ]);
    expect(ACQUIRE_ROTATION_SESSION_LOCK_SQL).toContain("pg_advisory_lock");
    expect(ACQUIRE_ROTATION_SESSION_LOCK_SQL).not.toContain("xact");
    expect(ACQUIRE_ROTATION_XACT_LOCK_SQL).toContain("pg_advisory_xact_lock");
    await uow.commit();
    // Session still held after vault commit (D-B4).
    expect(queries.filter((q) => q.sql === RELEASE_ROTATION_SESSION_LOCK_SQL)).toHaveLength(0);
    await uow.end();
    expect(queries).toContainEqual({
      sql: RELEASE_ROTATION_SESSION_LOCK_SQL,
      params: [MASTER_KEY_ROTATION_ADVISORY_LOCK_ID],
    });
    expect(RELEASE_ROTATION_SESSION_LOCK_SQL).toContain("pg_advisory_unlock");
  });

  it("D-B7: begin session-ok/xact-fail releases session lock + connection; retry succeeds", async () => {
    const queries: Array<{ sql: string; params: readonly unknown[] | undefined }> = [];
    let rollbackCalls = 0;
    let beginCalls = 0;
    let xactShouldFail = true;

    const factory = {
      async begin() {
        beginCalls += 1;
        return {
          client: {
            async query(sql: string, params?: readonly unknown[]) {
              queries.push({ sql, params });
              if (sql === ACQUIRE_ROTATION_XACT_LOCK_SQL && xactShouldFail) {
                throw new Error("xact lock query failed");
              }
              return { rows: [{ locked: true }] };
            },
          },
          async commit() {},
          async rollback() {
            rollbackCalls += 1;
          },
        };
      },
    };

    const uow = createSqlRotationUnitOfWork(factory);

    await expect(uow.begin()).rejects.toThrow("xact lock query failed");
    // Session lock was taken then released; connection returned via factory.rollback.
    expect(
      queries.filter((q) => q.sql === ACQUIRE_ROTATION_SESSION_LOCK_SQL),
    ).toHaveLength(1);
    expect(
      queries.filter((q) => q.sql === RELEASE_ROTATION_SESSION_LOCK_SQL),
    ).toHaveLength(1);
    expect(rollbackCalls).toBe(1);
    // UoW left clean — no manual operator rollback required.
    expect(beginCalls).toBe(1);

    xactShouldFail = false;
    await uow.begin();
    expect(beginCalls).toBe(2);
    expect(
      queries.filter((q) => q.sql === ACQUIRE_ROTATION_SESSION_LOCK_SQL),
    ).toHaveLength(2);
    expect(
      queries.filter((q) => q.sql === ACQUIRE_ROTATION_XACT_LOCK_SQL),
    ).toHaveLength(2);
    await uow.commit();
    await uow.end();
    expect(
      queries.filter((q) => q.sql === RELEASE_ROTATION_SESSION_LOCK_SQL),
    ).toHaveLength(2);
    expect(rollbackCalls).toBe(2); // begin-fail cleanup + end() connection return
  });

  it("concurrent second rotation cannot both proceed (advisory lock + interlock)", async () => {
    const fixtures = [makeRow(0x21, 1), makeRow(0x22, 2)];
    const interlock = makeInterlock();
    const journalA = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const journalB = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const uowA = makeUow();
    const uowB = makeUow();

    let releaseCommitA!: () => void;
    const commitAGate = new Promise<void>((resolve) => {
      releaseCommitA = resolve;
    });
    let aInCommit = false;

    const runA = rotateMasterKey({
      sealedStores: registry(),
      ...census(fixtures.map((f) => f.row)),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal: journalA,
      interlock,
      commitWalletVault: async () => {
        aInCommit = true;
        await commitAGate;
      },
      unitOfWork: uowA,
    });

    // Wait until A holds interlock + lock and is inside commit.
    for (let i = 0; i < 50 && !aInCommit; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(aInCommit).toBe(true);
    expect(interlock.held).toBe(true);
    expect(uowA.lockAcquired).toBe(true);

    // B must refuse — either interlock or advisory lock.
    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal: journalB,
        interlock,
        commitWalletVault: async () => {
          throw new Error("B must never commit");
        },
        unitOfWork: uowB,
      }),
    ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });

    // MOVE_INTERNAL / signUnderLease admission refused while A holds interlock.
    expect(() => interlock.assertSigningAdmitted("MOVE_INTERNAL")).toThrow(
      expect.objectContaining({ code: "SIGNING_QUIESCED" }),
    );
    expect(() => interlock.assertSigningAdmitted("signUnderLease")).toThrow(
      expect.objectContaining({ code: "SIGNING_QUIESCED" }),
    );

    releaseCommitA();
    const resultA = await runA;
    expect(resultA.committed).toBe(true);
    expect(interlock.held).toBe(false);
    // After release, signing is admitted again.
    expect(() => interlock.assertSigningAdmitted("MOVE_INTERNAL")).not.toThrow();
  });

  it("interlock held for entire commit path; signing quiesced during hold", async () => {
    const fixtures = [makeRow(0x31, 1), makeRow(0x32, 2)];
    const holdLog: boolean[] = [];
    const signingLog: string[] = [];
    const interlock = makeInterlock();
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);

    await rotateMasterKey({
      sealedStores: registry(),
      ...census(fixtures.map((f) => f.row)),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal,
      interlock,
      commitWalletVault: async () => {
        holdLog.push(interlock.held);
        try {
          interlock.assertSigningAdmitted("MOVE_INTERNAL");
          signingLog.push("admitted");
        } catch (err) {
          if (err instanceof MasterKeyRotationError && err.code === "SIGNING_QUIESCED") {
            signingLog.push("quiesced");
          } else {
            throw err;
          }
        }
      },
      unitOfWork: makeUow(),
    });

    expect(holdLog).toEqual([true]);
    expect(signingLog).toEqual(["quiesced"]);
    expect(interlock.held).toBe(false);
  });
});

describe("D2 — journal.complete only after unitOfWork.commit", () => {
  it("unitOfWork.commit throw leaves writerEpoch unadvanced", async () => {
    const fixtures = [makeRow(0x41, 1)];
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const interlock = makeInterlock();
    let vaultRowsPersisted = false;

    const flakyUow: RotationUnitOfWork = {
      async begin() {},
      async commit() {
        throw new Error("disk full on TX commit");
      },
      async end() {},
      async rollback() {},
    };

    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock,
        commitWalletVault: async () => {
          vaultRowsPersisted = true;
        },
        unitOfWork: flakyUow,
      }),
    ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });

    // commitWalletVault may have been called (same TX intent) but writerEpoch must not advance
    // without a successful unit commit.
    expect(vaultRowsPersisted).toBe(true);
    const j = await journal.read();
    expect(j.writerEpoch).toBe(FROM_EPOCH);
    expect(j.phase).toBe("STABLE");
    expect(interlock.held).toBe(false);
  });

  it("ordering: unit commit precedes journal.complete (event log)", async () => {
    const fixtures = [makeRow(0x42, 1)];
    const events: string[] = [];
    const base = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const journal = {
      read: () => base.read(),
      begin: (input: { fromEpoch: number; toEpoch: number }) => base.begin(input),
      async markRewrapped(id: string) {
        events.push("journal.markRewrapped");
        return base.markRewrapped(id);
      },
      async complete() {
        events.push("journal.complete");
        return base.complete();
      },
      settleStable: () => base.settleStable(),
    };
    const uow: RotationUnitOfWork = {
      async begin() {
        events.push("uow.begin");
      },
      async commit() {
        events.push("uow.commit");
      },
      async end() {
        events.push("uow.end");
      },
      async rollback() {
        events.push("uow.rollback");
      },
    };

    await rotateMasterKey({
      sealedStores: registry(),
      ...census(fixtures.map((f) => f.row)),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal,
      interlock: makeInterlock(),
      commitWalletVault: async () => {
        events.push("vault.commit");
      },
      unitOfWork: uow,
    });

    expect(events).toEqual([
      "uow.begin",
      "vault.commit",
      "uow.commit",
      "journal.markRewrapped",
      "journal.complete",
      "uow.end",
    ]);
  });
});

describe("D3 — crash-safe resume / mixed population", () => {
  it("resume with mixed sealed population reaches COMPLETE under new root", async () => {
    // Simulate mid-rotation crash: wallet 1 already under NEW, wallets 2–3 still under OLD.
    // Journal is ROTATING with wallet 1 marked rewrapped.
    const f1 = makeRow(0x51, 1, NEW_ROOT); // already rewrapped
    const f2 = makeRow(0x52, 2, OLD_ROOT);
    const f3 = makeRow(0x53, 3, OLD_ROOT);
    const secrets = new Map([
      [f1.row.identity.walletId, f1.secretKey],
      [f2.row.identity.walletId, f2.secretKey],
      [f3.row.identity.walletId, f3.secretKey],
    ]);

    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await journal.begin({ fromEpoch: FROM_EPOCH, toEpoch: TO_EPOCH });
    await journal.markRewrapped(f1.row.identity.walletId);
    expect((await journal.read()).phase).toBe("ROTATING");
    expect((await journal.read()).rewrappedWalletIds).toEqual([f1.row.identity.walletId]);

    // Full census including already-new + still-old rows.
    let committed: readonly WalletVaultRewrapRow[] = [];
    const result = await rotateMasterKey({
      sealedStores: registry(),
      ...census([f1.row, f2.row, f3.row]),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal,
      interlock: makeInterlock(),
      commitWalletVault: async (rows) => {
        committed = rows;
      },
      unitOfWork: makeUow(),
    });

    expect(result.committed).toBe(true);
    expect(result.walletCount).toBe(3);
    expect(committed).toHaveLength(3);

    const j = await journal.read();
    expect(j.phase).toBe("STABLE");
    expect(j.writerEpoch).toBe(TO_EPOCH);

    // Every row opens under NEW only, secrets match, key-ring agrees.
    const ring = makeKeyRing();
    for (const row of committed) {
      const expected = secrets.get(row.identity.walletId)!;
      const opened = openWalletSecret(NEW_ROOT, row.envelope, row.identity);
      try {
        expect(Buffer.from(opened.bytes)).toEqual(expected);
      } finally {
        opened.wipe();
      }
      expect(() => openWalletSecret(OLD_ROOT, row.envelope, row.identity)).toThrow();
      const viaRing = openWithKeyRing(ring, row.envelope, row.identity);
      try {
        expect(viaRing.epoch).toBe(TO_EPOCH);
        expect(Buffer.from(viaRing.secret.bytes)).toEqual(expected);
      } finally {
        viaRing.secret.wipe();
      }
    }

    // Canonical order preserved.
    const ids = committed.map((r) => r.identity.walletId);
    expect(ids).toEqual([...ids].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));
  });

  it("resume without journal marks still handles mixed census via key-ring", async () => {
    // Crash left durable rows under NEW but journal marks were lost (restored to empty ROTATING).
    const f1 = makeRow(0x61, 1, NEW_ROOT);
    const f2 = makeRow(0x62, 2, OLD_ROOT);
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    // Fresh begin — empty rewrapped set, but census is mixed.
    let committed: readonly WalletVaultRewrapRow[] = [];

    const result = await rotateMasterKey({
      sealedStores: registry(),
      ...census([f1.row, f2.row]),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal,
      interlock: makeInterlock(),
      commitWalletVault: async (rows) => {
        committed = rows;
      },
      unitOfWork: makeUow(),
    });

    expect(result.committed).toBe(true);
    expect(committed).toHaveLength(2);
    for (const row of committed) {
      expect(() => openWalletSecret(NEW_ROOT, row.envelope, row.identity)).not.toThrow();
    }
  });
});

describe("D-B1 — false journal marks must not poison resume", () => {
  it("ROTATING + mark present + census still OLD reaches COMPLETE under new root", async () => {
    // Crash window the orchestrator used to open: markRewrapped flushed while vault
    // ciphertext remained under OLD. Resume must key-ring-open + reseal, not ROTATION_STATE.
    const f1 = makeRow(0x71, 1, OLD_ROOT);
    const f2 = makeRow(0x72, 2, OLD_ROOT);
    const secrets = new Map([
      [f1.row.identity.walletId, f1.secretKey],
      [f2.row.identity.walletId, f2.secretKey],
    ]);

    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await journal.begin({ fromEpoch: FROM_EPOCH, toEpoch: TO_EPOCH });
    // Poison marks — claim both wallets rewrapped while envelopes are still OLD.
    await journal.markRewrapped(f1.row.identity.walletId);
    await journal.markRewrapped(f2.row.identity.walletId);
    expect((await journal.read()).rewrappedWalletIds).toEqual([
      f1.row.identity.walletId,
      f2.row.identity.walletId,
    ]);

    let committed: readonly WalletVaultRewrapRow[] = [];
    const result = await rotateMasterKey({
      sealedStores: registry(),
      ...census([f1.row, f2.row]),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal,
      interlock: makeInterlock(),
      commitWalletVault: async (rows) => {
        committed = rows;
      },
      unitOfWork: makeUow(),
    });

    expect(result.committed).toBe(true);
    expect(committed).toHaveLength(2);
    const j = await journal.read();
    expect(j.phase).toBe("STABLE");
    expect(j.writerEpoch).toBe(TO_EPOCH);

    for (const row of committed) {
      const expected = secrets.get(row.identity.walletId)!;
      const opened = openWalletSecret(NEW_ROOT, row.envelope, row.identity);
      try {
        expect(Buffer.from(opened.bytes)).toEqual(expected);
      } finally {
        opened.wipe();
      }
      expect(() => openWalletSecret(OLD_ROOT, row.envelope, row.identity)).toThrow();
    }
  });

  it("does not markRewrapped before commitWalletVault succeeds", async () => {
    const fixtures = [makeRow(0x73, 1)];
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const events: string[] = [];
    const proxied = {
      read: () => journal.read(),
      begin: (input: { fromEpoch: number; toEpoch: number }) => {
        events.push("journal.begin");
        return journal.begin(input);
      },
      async markRewrapped(id: string) {
        events.push(`mark:${id}`);
        return journal.markRewrapped(id);
      },
      complete: () => journal.complete(),
      settleStable: () => journal.settleStable(),
    };

    await rotateMasterKey({
      sealedStores: registry(),
      ...census(fixtures.map((f) => f.row)),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal: proxied,
      interlock: makeInterlock(),
      commitWalletVault: async () => {
        // At vault-write time, journal must still have empty marks (no false durability).
        const mid = await journal.read();
        expect(mid.rewrappedWalletIds).toEqual([]);
        events.push("vault.commit");
      },
      unitOfWork: makeUow(),
    });

    const markIdx = events.findIndex((e) => e.startsWith("mark:"));
    const vaultIdx = events.indexOf("vault.commit");
    expect(vaultIdx).toBeGreaterThanOrEqual(0);
    expect(markIdx).toBeGreaterThan(vaultIdx);
  });
});

describe("D-B2 — SQL UoW commit-throw keeps rollback meaningful", () => {
  it("commit() reject leaves active handle so rollback() invokes factory rollback", async () => {
    let txStillOpen = false;
    let rollbackCalls = 0;
    let commitCalls = 0;

    const factory = {
      async begin() {
        txStillOpen = true;
        return {
          client: {
            async query() {
              return { rows: [] };
            },
          },
          async commit() {
            commitCalls += 1;
            throw new Error("commit transport failure");
          },
          async rollback() {
            rollbackCalls += 1;
            txStillOpen = false;
          },
        };
      },
    };

    const uow = createSqlRotationUnitOfWork(factory);
    await uow.begin();
    await expect(uow.commit()).rejects.toThrow("commit transport failure");
    expect(commitCalls).toBe(1);
    // Handle must still be live — rollback is not a silent no-op.
    await uow.rollback();
    expect(rollbackCalls).toBe(1);
    expect(txStillOpen).toBe(false);
    // Second rollback is a no-op (already cleared).
    await uow.rollback();
    expect(rollbackCalls).toBe(1);
  });

  it("orchestrator abort after SQL commit-throw still calls unit rollback", async () => {
    const fixtures = [makeRow(0x74, 1)];
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    let rollbackCalls = 0;
    let txStillOpen = false;

    const factory = {
      async begin() {
        txStillOpen = true;
        return {
          client: {
            async query() {
              return { rows: [] };
            },
          },
          async commit() {
            throw new Error("commit transport failure");
          },
          async rollback() {
            rollbackCalls += 1;
            txStillOpen = false;
          },
        };
      },
    };
    const uow = createSqlRotationUnitOfWork(factory);

    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock: makeInterlock(),
        commitWalletVault: async () => {
          /* vault write "same TX" intent — rows not durable if UoW rolls back */
        },
        unitOfWork: uow,
      }),
    ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });

    expect(rollbackCalls).toBe(1);
    expect(txStillOpen).toBe(false);
    const j = await journal.read();
    expect(j.writerEpoch).toBe(FROM_EPOCH);
    expect(j.phase).toBe("STABLE");
  });
});


describe("D-B4 — ceremony session lock spans journal.complete", () => {
  it("session lock still held while journal.complete runs; concurrent begin refuses", async () => {
    const fixtures = [makeRow(0x81, 1)];
    const journalBase = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    let releaseComplete!: () => void;
    const completeGate = new Promise<void>((resolve) => {
      releaseComplete = resolve;
    });
    let insideComplete = false;

    const journal = {
      read: () => journalBase.read(),
      begin: (input: { fromEpoch: number; toEpoch: number }) => journalBase.begin(input),
      markRewrapped: (id: string) => journalBase.markRewrapped(id),
      async complete() {
        insideComplete = true;
        await completeGate;
        return journalBase.complete();
      },
      settleStable: () => journalBase.settleStable(),
    };

    const uowA = makeUow();
    const runA = rotateMasterKey({
      sealedStores: registry(),
      ...census(fixtures.map((f) => f.row)),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal,
      interlock: makeInterlock(),
      commitWalletVault: async () => {},
      unitOfWork: uowA,
    });

    for (let i = 0; i < 80 && !insideComplete; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(insideComplete).toBe(true);
    // Vault TX committed, but ceremony session lease MUST still be held (D-B4).
    expect(uowA.commits).toBe(1);
    expect(uowA.sessionHeld).toBe(true);
    expect(uowA.lockAcquired).toBe(true);
    expect(InMemoryRotationUnitOfWork).toBeDefined();

    const uowB = makeUow();
    await expect(uowB.begin()).rejects.toMatchObject({ code: "ROTATION_REFUSED" });

    // Full second rotate also refuses (session + interlock).
    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal: new InMemoryMasterKeyRotationJournal(FROM_EPOCH),
        interlock: makeInterlock(),
        commitWalletVault: async () => {
          throw new Error("B must never commit");
        },
        unitOfWork: uowB,
      }),
    ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });

    releaseComplete();
    const resultA = await runA;
    expect(resultA.committed).toBe(true);
    expect(uowA.sessionHeld).toBe(false);
    expect(uowA.ends).toBe(1);
    expect((await journalBase.read()).phase).toBe("STABLE");
    expect((await journalBase.read()).writerEpoch).toBe(TO_EPOCH);

    // After A ends, B can begin.
    await uowB.begin();
    expect(uowB.sessionHeld).toBe(true);
    await uowB.rollback();
  });

  it("InMemory commit keeps global holder until end()", async () => {
    const a = makeUow();
    const b = makeUow();
    await a.begin();
    await a.commit();
    expect(a.sessionHeld).toBe(true);
    await expect(b.begin()).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
    await a.end();
    expect(a.sessionHeld).toBe(false);
    await b.begin();
    await b.rollback();
  });
});

describe("D-B5 — ROTATION_COMPLETE resume + honest abort log", () => {
  it("settle-throw strands COMPLETE; re-invoke settles to STABLE without error", async () => {
    const fixtures = [makeRow(0x91, 1, NEW_ROOT)]; // already under new root (post-vault)
    const journalBase = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await journalBase.begin({ fromEpoch: FROM_EPOCH, toEpoch: TO_EPOCH });
    await journalBase.complete();
    // Strand at COMPLETE @ toEpoch (settle never ran).
    expect((await journalBase.read()).phase).toBe("ROTATION_COMPLETE");
    expect((await journalBase.read()).writerEpoch).toBe(TO_EPOCH);

    const result = await rotateMasterKey({
      sealedStores: registry(),
      ...census(fixtures.map((f) => f.row)),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal: journalBase,
      interlock: makeInterlock(),
      commitWalletVault: async () => {
        throw new Error("finalize must not re-commit vault");
      },
      unitOfWork: makeUow(),
    });

    expect(result.committed).toBe(true);
    const j = await journalBase.read();
    expect(j.phase).toBe("STABLE");
    expect(j.writerEpoch).toBe(TO_EPOCH);
  });

  it("settle throw mid-run leaves COMPLETE; second rotateMasterKey finalizes", async () => {
    const fixtures = [makeRow(0x92, 1)];
    const journalBase = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    let settleCalls = 0;
    const journal = {
      read: () => journalBase.read(),
      begin: (input: { fromEpoch: number; toEpoch: number }) => journalBase.begin(input),
      markRewrapped: (id: string) => journalBase.markRewrapped(id),
      complete: () => journalBase.complete(),
      async settleStable() {
        settleCalls += 1;
        if (settleCalls === 1) {
          // complete already advanced epoch; throw before settle mutates.
          throw new Error("settle transport failure");
        }
        return journalBase.settleStable();
      },
    };

    let committed: readonly WalletVaultRewrapRow[] = [];
    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock: makeInterlock(),
        commitWalletVault: async (rows) => {
          committed = rows;
        },
        unitOfWork: makeUow(),
      }),
    ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });

    expect(committed).toHaveLength(1);
    expect((await journalBase.read()).phase).toBe("ROTATION_COMPLETE");
    expect((await journalBase.read()).writerEpoch).toBe(TO_EPOCH);

    // Resume finalize with census under NEW (as durable vault left it).
    const result = await rotateMasterKey({
      sealedStores: registry(),
      ...census(committed),
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal,
      interlock: makeInterlock(),
      commitWalletVault: async () => {
        throw new Error("must not re-commit");
      },
      unitOfWork: makeUow(),
    });
    expect(result.committed).toBe(true);
    expect((await journalBase.read()).phase).toBe("STABLE");
    expect((await journalBase.read()).writerEpoch).toBe(TO_EPOCH);
    expect(settleCalls).toBe(2);
  });

  it("abort log after vaultDurable does not claim nothing committed", async () => {
    const fixtures = [makeRow(0x93, 1)];
    const journalBase = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const logLines: Array<{ obj: Record<string, unknown>; msg?: string }> = [];
    const journal = {
      read: () => journalBase.read(),
      begin: (input: { fromEpoch: number; toEpoch: number }) => journalBase.begin(input),
      markRewrapped: (id: string) => journalBase.markRewrapped(id),
      async complete() {
        throw new Error("complete transport failure");
      },
      settleStable: () => journalBase.settleStable(),
    };

    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock: makeInterlock(),
        commitWalletVault: async () => {},
        unitOfWork: makeUow(),
        logger: {
          info: (obj, msg) => logLines.push({ obj, msg }),
          error: (obj, msg) => logLines.push({ obj, msg }),
        },
      }),
    ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });

    const fail = logLines.find((l) => l.obj.event === "rotate.failed");
    expect(fail).toBeDefined();
    expect(fail!.obj.vaultDurable).toBe(true);
    expect(fail!.msg).not.toMatch(/nothing committed/i);
    expect(fail!.msg).toMatch(/durable vault commit/i);
  });
});

describe("VaultKeyRing mixed-population open (guard 3)", () => {
  it("opens a row sealed under the retained old root while writer is the new epoch", () => {
    const { row, secretKey } = makeRow(0x71, 1);
    const ring = buildKeyRing({
      writerEpoch: TO_EPOCH,
      writerRoot: NEW_ROOT,
      retained: [{ epoch: FROM_EPOCH, root: OLD_ROOT }],
    });

    const { secret, epoch } = openWithKeyRing(ring, row.envelope, row.identity);
    try {
      expect(epoch).toBe(FROM_EPOCH);
      expect(Buffer.from(secret.bytes)).toEqual(secretKey);
    } finally {
      secret.wipe();
    }
  });

  it("opens a row sealed under the new writer root", () => {
    const { secretKey, publicKey } = makeSecret(0x72);
    const identity: WalletIdentity = {
      nodeId: "11111111-1111-4111-8111-111111111111",
      walletId: "bbbbbbbb-0000-4000-8000-000000000001",
      keyVersion: 1,
      publicKey,
      keyOrigin: "node_generated",
    };
    const envelope = sealWalletSecret(NEW_ROOT, identity, secretKey);
    const ring = buildKeyRing({
      writerEpoch: TO_EPOCH,
      writerRoot: NEW_ROOT,
      retained: [{ epoch: FROM_EPOCH, root: OLD_ROOT }],
    });

    const { secret, epoch } = openWithKeyRing(ring, envelope, identity);
    try {
      expect(epoch).toBe(TO_EPOCH);
      expect(Buffer.from(secret.bytes)).toEqual(secretKey);
    } finally {
      secret.wipe();
    }
  });

  it("fails closed when no root authenticates", () => {
    const { row } = makeRow(0x73, 1);
    const other = deriveRootKey(Buffer.from("entirely-other-master-key-bytes!"), SALT);
    const ring = buildKeyRing({
      writerEpoch: 9,
      writerRoot: other,
    });
    expect(() => openWithKeyRing(ring, row.envelope, row.identity)).toThrow(/no key-ring root/);
  });
});

describe("InMemoryMasterKeyRotationJournal", () => {
  it("advances writer epoch only on complete()", async () => {
    const j = new InMemoryMasterKeyRotationJournal(1);
    await j.begin({ fromEpoch: 1, toEpoch: 2 });
    expect((await j.read()).writerEpoch).toBe(1);
    expect((await j.read()).phase).toBe("ROTATING");
    await j.markRewrapped("w1");
    await j.complete();
    expect((await j.read()).phase).toBe("ROTATION_COMPLETE");
    expect((await j.read()).writerEpoch).toBe(2);
    await j.settleStable();
    expect((await j.read()).phase).toBe("STABLE");
    expect((await j.read()).writerEpoch).toBe(2);
  });

  it("abort via settleStable from ROTATING keeps writer epoch", async () => {
    const j = new InMemoryMasterKeyRotationJournal(3);
    await j.begin({ fromEpoch: 3, toEpoch: 4 });
    await j.markRewrapped("w1");
    await j.settleStable();
    const r = await j.read();
    expect(r.phase).toBe("STABLE");
    expect(r.writerEpoch).toBe(3);
    expect(r.rewrappedWalletIds).toEqual([]);
  });
});

// ─── D-A1 / D-B8 — plaintext hygiene on EVERY per-row exit ───────────────────
//
// The orchestrator copies each opened wallet secret into a module-owned buffer
// (`secretBytes`). Before the fix that copy was wiped only inside the reseal branch, so the
// already-under-new-root `continue` — which IS the crash-resume branch — and the
// unexpected-epoch `throw` both left a live 64-byte plaintext Ed25519 signing key on the
// heap. guard 5 + its carried-forward invariant ("plaintext in memory only,
// zeroed after use"). Two independent assertions, both of which fail if the wipe is
// narrowed back to the reseal branch or reverted to a bare `secretBytes.fill(0)`:
//
//   1. the hygiene seam count — proves the module's own copy goes through
//      keyMaterialHygiene.zeroize and not a raw fill (which is unassertable);
//   2. the live-buffer probe — proves no 64-byte buffer minted during the ceremony still
//      holds a wallet secret once it returns. Envelope-internals-independent.
describe("D-A1 / D-B8 — module-owned plaintext wiped on every per-row exit", () => {
  /**
   * Records the CONTENTS of every buffer handed to the hygiene seam, before the wipe
   * lands, then wipes for real. Counting by content lets the assertions attribute wipes to
   * a specific wallet's secret.
   */
  function spyZeroize(): { wiped: Buffer[]; restore: () => void } {
    const wiped: Buffer[] = [];
    // Snapshot contents then delegate to real zeroize so brand + residual stay enforced.
    const realZeroize = keyMaterialHygiene.zeroize.bind(keyMaterialHygiene);
    const spy = vi.spyOn(keyMaterialHygiene, "zeroize").mockImplementation((buf, role) => {
      wiped.push(Buffer.from(buf));
      realZeroize(buf, role);
    });
    return { wiped, restore: () => spy.mockRestore() };
  }

  const wipesOf = (wiped: readonly Buffer[], secret: Buffer): number =>
    wiped.filter((b) => b.length === secret.length && b.equals(secret)).length;

  it("routes the skipped (already-new) row's plaintext copy through keyMaterialHygiene", async () => {
    // Mixed census — the shape a resumed rotation sees: wallet 1 already rewrapped under
    // the new root (skip branch), wallet 2 still under the old root (reseal branch).
    const already = makeRow(0xa1, 1, NEW_ROOT);
    const stillOld = makeRow(0xa2, 2, OLD_ROOT);
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await journal.begin({ fromEpoch: FROM_EPOCH, toEpoch: TO_EPOCH });

    const { wiped, restore } = spyZeroize();
    try {
      const result = await rotateMasterKey({
        sealedStores: registry(),
        ...census([already.row, stillOld.row]),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock: makeInterlock(),
        commitWalletVault: async () => {},
        unitOfWork: makeUow(),
      });
      expect(result.committed).toBe(true);
    } finally {
      restore();
    }

    // The skip branch takes no reseal, so exactly three buffers ever hold this wallet's
    // plaintext: the GCM update intermediate and the released plaintext (both envelope-owned,
    // envelope.ts:286 / :306) plus the orchestrator's own `secretBytes` copy. A lower bound,
    // so an added envelope wipe cannot break this — but dropping the orchestrator's wipe,
    // or bypassing the seam with a raw fill(0), takes it to 2 and fails.
    expect(wipesOf(wiped, already.secretKey)).toBeGreaterThanOrEqual(3);
    // The reseal branch was already covered before the fix; it must not regress.
    expect(wipesOf(wiped, stillOld.secretKey)).toBeGreaterThanOrEqual(3);
  });

  it("leaves no live buffer holding a wallet secret after a resumed rotation", async () => {
    // The reviewers' probe, kept as a regression: every 64-byte buffer minted from a
    // Uint8Array during the ceremony is retained, then checked against the known secrets
    // AFTER rotateMasterKey returns. A missed wipe shows up as a live plaintext key.
    const already = makeRow(0xb1, 1, NEW_ROOT);
    const stillOld = makeRow(0xb2, 2, OLD_ROOT);
    const secrets = [already.secretKey, stillOld.secretKey];
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await journal.begin({ fromEpoch: FROM_EPOCH, toEpoch: TO_EPOCH });

    const minted: Buffer[] = [];
    // Overload-erased view of the real constructor so the patch needs no `any`.
    const bufferCtor = Buffer as unknown as { from: (...args: unknown[]) => Buffer };
    const realFrom = bufferCtor.from;
    bufferCtor.from = (...args: unknown[]): Buffer => {
      const out = realFrom(...args);
      if (out.length === 64 && args[0] instanceof Uint8Array) minted.push(out);
      return out;
    };
    try {
      await rotateMasterKey({
        sealedStores: registry(),
        ...census([already.row, stillOld.row]),
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock: makeInterlock(),
        commitWalletVault: async () => {},
        unitOfWork: makeUow(),
      });
    } finally {
      bufferCtor.from = realFrom;
    }

    expect(minted.length).toBeGreaterThan(0);
    const live = minted.filter((b) => secrets.some((s) => b.equals(s)));
    expect(live).toEqual([]);
  });

  it("wipes the plaintext copy when a row opens under an unexpected epoch", async () => {
    // Third exit from the per-row body: openedEpoch is neither fromEpoch nor toEpoch. The
    // ring retains a stale third epoch, the row is sealed under it, so the row opens and
    // the orchestrator then aborts — and must still wipe the copy it already made.
    const STALE_EPOCH = 5;
    const STALE_ROOT = deriveRootKey(Buffer.from("stale-third-epoch-master-key-!!!!"), SALT);
    const stale = makeRow(0xc1, 1, STALE_ROOT);
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const { wiped, restore } = spyZeroize();
    try {
      await expect(
        rotateMasterKey({
          sealedStores: registry(),
          ...census([stale.row]),
          keyRing: buildKeyRing({
            writerEpoch: TO_EPOCH,
            writerRoot: NEW_ROOT,
            retained: [
              { epoch: FROM_EPOCH, root: OLD_ROOT },
              { epoch: STALE_EPOCH, root: STALE_ROOT },
            ],
          }),
          fromEpoch: FROM_EPOCH,
          toEpoch: TO_EPOCH,
          oldRootKey: OLD_ROOT,
          newRootKey: NEW_ROOT,
          journal,
          interlock: makeInterlock(),
          commitWalletVault: async () => {},
          unitOfWork: makeUow(),
        }),
      ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });
    } finally {
      restore();
    }
    // Aborted on the unexpected epoch, but the plaintext copy still went through the seam:
    // envelope's update intermediate + released plaintext + the orchestrator's own copy.
    expect(wipesOf(wiped, stale.secretKey)).toBeGreaterThanOrEqual(3);
  });
});

// ─── D-A2 — parity proven against the STORE, inside the ceremony fence ───────
//
// `walletVault` is a snapshot the caller reads before acquire()/begin(). The old guard
// compared it to `out`, a set derived from that same snapshot where every branch pushes
// exactly once — so it could never fire. A `vault` row inserted between the census read and
// the TX commit was silently skipped, stayed sealed under the old root, and became
// permanently unopenable at OPERATOR_SEQUENCE step 5. exit criterion ("rotation
// cannot orphan a wallet") / custody ("any unreadable row aborts the whole rotation").
describe("D-A2 — census/store parity", () => {
  const inputFor = (
    rows: readonly WalletVaultRewrapRow[],
    storeRows: number,
    extra: { journal: InMemoryMasterKeyRotationJournal; uow: RotationUnitOfWork; commit: () => Promise<void>; dryRun?: boolean },
  ) => ({
    sealedStores: registry(),
    walletVault: { rows },
    countWalletVaultRows: async () => storeRows,
    nodeSigningKeys: { rows: [] as const },
    countNodeSigningKeyRows: async () => 0,
    pushReceiverSecrets: { rows: [] as const },
    countPushSecretRows: async () => 0,
    totpSecrets: { rows: [] as const },
    countTotpSecretRows: async () => 0,
    keyRing: makeKeyRing(),
    fromEpoch: FROM_EPOCH,
    toEpoch: TO_EPOCH,
    oldRootKey: OLD_ROOT,
    newRootKey: NEW_ROOT,
    journal: extra.journal,
    interlock: makeInterlock(),
    commitWalletVault: extra.commit,
    unitOfWork: extra.uow,
    dryRun: extra.dryRun,
  });

  it("aborts with zero mutation when the store holds a row the census omits", async () => {
    const fixtures = [1, 2].map((n) => makeRow(0xd0 + n, n));
    const before = fixtures.map((f) => ({ ...f.row.envelope }));
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const uow = makeUow();
    const commit = vi.fn(async () => {});

    await expect(
      rotateMasterKey(
        // A third wallet was created after the census was taken.
        inputFor(fixtures.map((f) => f.row), 3, { journal, uow, commit }),
      ),
    ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });

    expect(commit).not.toHaveBeenCalled();
    expect(uow.commits).toBe(0);
    expect(uow.rollbacks).toBe(1);
    const j = await journal.read();
    expect(j.phase).toBe("STABLE");
    expect(j.writerEpoch).toBe(FROM_EPOCH);
    // Envelopes byte-identical — nothing was rewrapped.
    fixtures.forEach((f, i) => {
      expect(f.row.envelope.nonce).toEqual(before[i]!.nonce);
      expect(f.row.envelope.ciphertext).toEqual(before[i]!.ciphertext);
      expect(() => openWalletSecret(OLD_ROOT, f.row.envelope, f.row.identity)).not.toThrow();
    });
  });

  it("dry-run does not report success on a stale census", async () => {
    // The operator's pre-flight check must refuse too, or it green-lights the losing run.
    const fixtures = [1, 2].map((n) => makeRow(0xe0 + n, n));
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await expect(
      rotateMasterKey(
        inputFor(fixtures.map((f) => f.row), 5, {
          journal,
          uow: makeUow(),
          commit: async () => {
            throw new Error("dry-run must not commit");
          },
          dryRun: true,
        }),
      ),
    ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });
    expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
  });

  it("aborts on a census carrying the same wallet id twice", async () => {
    // Reported {rowsBefore:2, rowsAfter:2, rewrapped:2} and committed two rows for one
    // distinct wallet, passing round-trip verification.
    const dup = makeRow(0xf0, 1);
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const commit = vi.fn(async () => {});
    await expect(
      rotateMasterKey(inputFor([dup.row, dup.row], 2, { journal, uow: makeUow(), commit })),
    ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });
    expect(commit).not.toHaveBeenCalled();
    expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
  });

  it("reports rowsBefore from the store, not from the census", async () => {
    const fixtures = [1, 2].map((n) => makeRow(0x40 + n, n));
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const result = await rotateMasterKey(
      inputFor(fixtures.map((f) => f.row), 2, {
        journal,
        uow: makeUow(),
        commit: async () => {},
      }),
    );
    const vault = result.stores.find((s) => s.storeId === "WALLET_VAULT");
    expect(vault?.result).toEqual({ rowsBefore: 2, rowsAfter: 2, rewrapped: 2 });
  });

  it("refuses when countWalletVaultRows is absent (fail-closed)", async () => {
    const fixtures = [makeRow(0x41, 1)];
    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        walletVault: { rows: fixtures.map((f) => f.row) },
        nodeSigningKeys: { rows: [] },
        countNodeSigningKeyRows: async () => 0,
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal: new InMemoryMasterKeyRotationJournal(FROM_EPOCH),
        interlock: makeInterlock(),
        commitWalletVault: async () => {},
        // @ts-expect-error — deliberate missing port for the fail-closed proof
        countWalletVaultRows: undefined,
        unitOfWork: makeUow(),
      }),
    ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
  });

  it("refuses when NODE_SIGNING_KEYS count/census ports are absent (fail-closed)", async () => {
    const fixtures = [makeRow(0x42, 1)];
    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        nodeSigningKeys: undefined,
        countNodeSigningKeyRows: undefined,
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal: new InMemoryMasterKeyRotationJournal(FROM_EPOCH),
        interlock: makeInterlock(),
        commitWalletVault: async () => {},
        unitOfWork: makeUow(),
      }),
    ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
  });

  it("rewraps NODE_SIGNING_KEYS envelopes when census + ports are wired", async () => {
    const { sealNodeSigningSeed, rewrapNodeSigningKeyStore, openNodeSigningSeed, publicKeyFromEd25519Seed } =
      await import("../src/signing-keys/index.js");
    const seed = Buffer.alloc(32, 0x5a);
    const identity = {
      nodeId: "11111111-1111-4111-8111-111111111111",
      purpose: "NODE_IDENTITY" as const,
      publicKey: publicKeyFromEd25519Seed(seed),
      keyVersion: 1,
    };
    const envelope = sealNodeSigningSeed(OLD_ROOT, identity, seed, "aaaaaaaa-0000-4000-8000-000000000099");
    const nskRow = { identity, envelope };
    let committedNsk: typeof nskRow[] = [];

    const result = await rotateMasterKey({
      sealedStores: registry(),
      walletVault: { rows: [] },
      countWalletVaultRows: async () => 0,
      nodeSigningKeys: { rows: [nskRow] },
      countNodeSigningKeyRows: async () => 1,
      pushReceiverSecrets: { rows: [] },
      countPushSecretRows: async () => 0,
      totpSecrets: { rows: [] },
      countTotpSecretRows: async () => 0,
      rewrapNodeSigningKeyStore: ({ oldRootKey, newRootKey, rows }) =>
        rewrapNodeSigningKeyStore({ oldRootKey, newRootKey, rows }),
      commitNodeSigningKeys: async (rows) => {
        committedNsk = [...rows];
      },
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal: new InMemoryMasterKeyRotationJournal(FROM_EPOCH),
      interlock: makeInterlock(),
      commitWalletVault: async () => {},
      unitOfWork: makeUow(),
    });

    expect(result.committed).toBe(true);
    expect(result.stores.find((s) => s.storeId === "NODE_SIGNING_KEYS")?.result).toEqual({
      rowsBefore: 1,
      rowsAfter: 1,
      rewrapped: 1,
    });
    expect(committedNsk).toHaveLength(1);
    const opened = openNodeSigningSeed(NEW_ROOT, committedNsk[0]!.envelope, committedNsk[0]!.identity);
    try {
      expect(Buffer.from(opened.bytes)).toEqual(seed);
    } finally {
      opened.wipe();
    }
  });


  it("finalize of a stranded ROTATION_COMPLETE refuses a census short of the store", async () => {
    // Resume path: the census is still a pre-fence snapshot. A row created during the
    // interrupted ceremony would be declared rotated without ever being rewrapped.
    const fixtures = [makeRow(0x42, 1, NEW_ROOT)];
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await journal.begin({ fromEpoch: FROM_EPOCH, toEpoch: TO_EPOCH });
    await journal.complete();
    expect((await journal.read()).phase).toBe("ROTATION_COMPLETE");

    await expect(
      rotateMasterKey(
        inputFor(fixtures.map((f) => f.row), 2, {
          journal,
          uow: makeUow(),
          commit: async () => {
            throw new Error("finalize must not commit");
          },
        }),
      ),
    ).rejects.toMatchObject({ code: "ROTATION_STATE" });
    // Left at COMPLETE for a resume with a fresh census — not settled on a false success.
    expect((await journal.read()).phase).toBe("ROTATION_COMPLETE");
  });

  it("a dry run that loses the finalize race still reports dryRun, never a commit", async () => {
    // M2. The lost-race branch returns `committed: true` because another finalizer
    // really did settle STABLE. A caller that asked to PROVE the rotation and roll back must
    // not be handed that other run's success as its own outcome — `--dry-run` reporting
    // `{ committed: true, dryRun: false }` would tell an operator the key is live when this
    // process wrote nothing. The dry-run branch therefore sits ahead of the race branch.
    const fixtures = [makeRow(0x51, 1, NEW_ROOT)];
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await journal.begin({ fromEpoch: FROM_EPOCH, toEpoch: TO_EPOCH });
    await journal.complete();
    expect((await journal.read()).phase).toBe("ROTATION_COMPLETE");

    const uow = makeUow();
    const result = await rotateMasterKey({
      ...inputFor(fixtures.map((f) => f.row), 1, {
        journal,
        uow,
        commit: async () => {
          throw new Error("a dry run must never commit");
        },
        dryRun: true,
      }),
      // The other finalizer wins mid-verification: this run entered on ROTATION_COMPLETE and
      // re-reads the journal after the census, by which time STABLE@toEpoch is durable.
      countWalletVaultRows: async () => {
        await journal.settleStable();
        return 1;
      },
    });

    expect(result.dryRun).toBe(true);
    expect(result.committed).toBe(false);
    expect(uow.commits).toBe(0);
    expect(uow.rollbacks).toBe(1);
    // The winner's settlement is untouched — a dry run reports, it does not rewind.
    expect(await journal.read()).toMatchObject({ phase: "STABLE", writerEpoch: TO_EPOCH });
  });
});


describe("ZTR-1177 r3 — boot canary crash-resume / D-B5 live envelope", () => {
  const CANARY_OLD = "canary-envelope-under-old-root";
  const CANARY_NEW = "canary-envelope-under-new-root";

  function canaryPorts(live: { envelope: string | null }) {
    return {
      bootCanary: { envelope: CANARY_OLD }, // deliberately stale pre-rotation snapshot
      countBootCanaryRows: async () => (live.envelope === null ? 0 : 1),
      loadBootCanaryEnvelope: async () => live.envelope,
      rewrapBootCanary: async (input: {
        readonly oldRootKey: Uint8Array;
        readonly newRootKey: Uint8Array;
        readonly envelope: string;
      }) => {
        // Minimal key-ring parity stub: open "new" if envelope is CANARY_NEW;
        // open "old" if CANARY_OLD; else refuse.
        if (input.envelope === CANARY_NEW) {
          // already under writer — carry through
          if (input.newRootKey !== NEW_ROOT) {
            throw new Error("new-root mismatch on already-new canary");
          }
          return {
            result: { rowsBefore: 1, rowsAfter: 1, rewrapped: 1 },
            rewrappedEnvelope: input.envelope,
          };
        }
        if (input.envelope === CANARY_OLD) {
          // Ceremony (old≠new): open under old and reseal under new.
          // Finalize open-proof (old===new===new): cannot open still-old durable row.
          if (input.oldRootKey === input.newRootKey) {
            throw new Error(
              "VAULT_BOOT_CANARY_DOES_NOT_OPEN: finalize new-only proof cannot open still-old canary",
            );
          }
          if (input.oldRootKey !== OLD_ROOT) {
            throw new Error("old-root mismatch on still-old canary");
          }
          return {
            result: { rowsBefore: 1, rowsAfter: 1, rewrapped: 1 },
            rewrappedEnvelope: CANARY_NEW,
          };
        }
        throw new Error("VAULT_BOOT_CANARY_DOES_NOT_OPEN: neither root");
      },
      commitBootCanary: async (envelope: string) => {
        live.envelope = envelope;
      },
    };
  }

  it("ROTATING resume with durable canary already under new completes despite stale census", async () => {
    // Guard-3: vault TX durable (canary under NEW), journal still ROTATING.
    const fixtures = [makeRow(0xb1, 1, NEW_ROOT)];
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await journal.begin({ fromEpoch: FROM_EPOCH, toEpoch: TO_EPOCH });
    expect((await journal.read()).phase).toBe("ROTATING");

    const live = { envelope: CANARY_NEW as string | null };
    let committedCanary: string | null = null;
    const ports = canaryPorts(live);
    ports.commitBootCanary = async (envelope: string) => {
      committedCanary = envelope;
      live.envelope = envelope;
    };

    const result = await rotateMasterKey({
      sealedStores: registry(),
      ...census(fixtures.map((f) => f.row)),
      ...ports,
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal,
      interlock: makeInterlock(),
      commitWalletVault: async () => {},
      unitOfWork: makeUow(),
    });

    expect(result.committed).toBe(true);
    expect((await journal.read()).phase).toBe("STABLE");
    expect((await journal.read()).writerEpoch).toBe(TO_EPOCH);
    // Carry-through commit of the already-new envelope (or skip-equivalent).
    expect(committedCanary).toBe(CANARY_NEW);
    expect(live.envelope).toBe(CANARY_NEW);
    const canaryReport = result.stores.find((s) => s.storeId === "VAULT_BOOT_CANARY");
    expect(canaryReport?.status).toBe("REWRAPPED");
    expect(canaryReport?.result).toEqual({ rowsBefore: 1, rowsAfter: 1, rewrapped: 1 });
  });

  it("D-B5 finalize after vault-durable with stale census snapshot still verifies live row", async () => {
    const fixtures = [makeRow(0xb2, 1, NEW_ROOT)];
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await journal.begin({ fromEpoch: FROM_EPOCH, toEpoch: TO_EPOCH });
    await journal.complete();
    expect((await journal.read()).phase).toBe("ROTATION_COMPLETE");
    expect((await journal.read()).writerEpoch).toBe(TO_EPOCH);

    // Live row is under NEW; caller still holds pre-rotation OLD snapshot in bootCanary.
    const live = { envelope: CANARY_NEW as string | null };
    let rewrapSaw: {
      envelope: string;
      oldRootKey: Uint8Array;
      newRootKey: Uint8Array;
    } | null = null;
    const ports = canaryPorts(live);
    const baseRewrap = ports.rewrapBootCanary;
    ports.rewrapBootCanary = async (input) => {
      rewrapSaw = {
        envelope: input.envelope,
        oldRootKey: input.oldRootKey,
        newRootKey: input.newRootKey,
      };
      return baseRewrap(input);
    };

    const result = await rotateMasterKey({
      sealedStores: registry(),
      ...census(fixtures.map((f) => f.row)),
      ...ports,
      // Stale snapshot — must NOT be used for finalize proof.
      bootCanary: { envelope: CANARY_OLD },
      keyRing: makeKeyRing(),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal,
      interlock: makeInterlock(),
      commitWalletVault: async () => {
        throw new Error("finalize must not re-commit vault");
      },
      unitOfWork: makeUow(),
    });

    expect(result.committed).toBe(true);
    expect((await journal.read()).phase).toBe("STABLE");
    expect(rewrapSaw?.envelope).toBe(CANARY_NEW);
    expect(rewrapSaw?.envelope).not.toBe(CANARY_OLD);
    // Finalize open-proof is new-root only (r2 shape) — never both roots.
    expect(rewrapSaw?.oldRootKey).toBe(NEW_ROOT);
    expect(rewrapSaw?.newRootKey).toBe(NEW_ROOT);
  });

  it("D-B5 refuses settle when live canary is still under OLD (no in-memory reseal false-STABLE)", async () => {
    // Review B r3: durable still-old + ROTATION_COMPLETE must not settle via
    // rewrap(old,new) that reseals in memory without commitBootCanary.
    const fixtures = [makeRow(0xb4, 1, NEW_ROOT)];
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await journal.begin({ fromEpoch: FROM_EPOCH, toEpoch: TO_EPOCH });
    await journal.complete();
    expect((await journal.read()).phase).toBe("ROTATION_COMPLETE");

    const live = { envelope: CANARY_OLD as string | null };
    let commitCalled = false;
    const ports = canaryPorts(live);
    ports.commitBootCanary = async () => {
      commitCalled = true;
    };

    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        ...ports,
        bootCanary: { envelope: CANARY_OLD },
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock: makeInterlock(),
        commitWalletVault: async () => {
          throw new Error("finalize must not re-commit vault");
        },
        unitOfWork: makeUow(),
      }),
    ).rejects.toMatchObject({ code: "ROTATION_STATE" });

    // Journal must remain ROTATION_COMPLETE (not false-settled STABLE).
    expect((await journal.read()).phase).toBe("ROTATION_COMPLETE");
    expect((await journal.read()).writerEpoch).toBe(TO_EPOCH);
    expect(live.envelope).toBe(CANARY_OLD);
    expect(commitCalled).toBe(false);
  });

  it("refuses when countBootCanaryRows is wired without loadBootCanaryEnvelope", async () => {
    const fixtures = [makeRow(0xb3, 1)];
    const journal = new InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    await expect(
      rotateMasterKey({
        sealedStores: registry(),
        ...census(fixtures.map((f) => f.row)),
        bootCanary: { envelope: CANARY_OLD },
        countBootCanaryRows: async () => 1,
        rewrapBootCanary: async () => ({
          result: { rowsBefore: 1, rowsAfter: 1, rewrapped: 1 },
          rewrappedEnvelope: CANARY_NEW,
        }),
        commitBootCanary: async () => {},
        keyRing: makeKeyRing(),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock: makeInterlock(),
        commitWalletVault: async () => {},
        unitOfWork: makeUow(),
      }),
    ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
  });
});
