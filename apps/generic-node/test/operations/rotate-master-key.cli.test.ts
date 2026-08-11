// Operator CLI entry for master-key rotation.
// Synthetic keys only; in-memory journal + census. No live DB.

import { createPrivateKey, createPublicKey } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  InMemoryMasterKeyRotationJournal,
  InMemoryRotationUnitOfWork,
  createPushSecretSealer,
  deriveRootKey,
  keyMaterialHygiene,
  openWalletSecret,
  sealWalletSecret,
  toBase64UrlPadded,
  type PushSecretRewrapRow,
  type RotationUnitOfWork,
  type WalletIdentity,
  type WalletVaultRewrapRow,
} from "@zucoins/node-core";

import {
  OPERATOR_SEQUENCE,
  runRotateMasterKeyCli,
} from "../../src/operations/rotate-master-key.cli.js";
import {
  sealVaultBootCanary,
  openVaultBootCanary,
  VAULT_BOOT_CANARY_PLAINTEXT,
} from "../../src/vault/boot-canary.js";
import {
  HISTORICAL_ROOT_KDF_SALT,
  resolveCeremonyRootKdfSalt,
  type RootKdfSaltSource,
  type RootKdfSaltSqlExecutor,
} from "../../src/vault/root-kdf-salt.js";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const OLD_MASTER = "old-cli-master-key-material-32b!!";
const NEW_MASTER = "new-cli-master-key-material-32b!!";
const SALT = Buffer.from("cli-rotation-salt-16");
const SALT_B64 = SALT.toString("base64");

const OLD_ROOT = deriveRootKey(OLD_MASTER, SALT);
const NEW_ROOT = deriveRootKey(NEW_MASTER, SALT);

function makeRow(seedByte: number, ordinal: number): {
  row: WalletVaultRewrapRow;
  secretKey: Buffer;
} {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const rawPub = Buffer.from(spki).subarray(-32);
  const publicKey = toBase64UrlPadded(rawPub);
  const secretKey = Buffer.concat([seed, rawPub]);
  const identity: WalletIdentity = {
    nodeId: "11111111-1111-4111-8111-111111111111",
    walletId: `cccccccc-0000-4000-8000-00000000000${ordinal}`,
    keyVersion: 1,
    publicKey,
    keyOrigin: "node_generated",
  };
  return {
    row: { identity, envelope: sealWalletSecret(OLD_ROOT, identity, secretKey) },
    secretKey,
  };
}

/** Same fixture, sealed under an arbitrary root — used to seal under the historical salt. */
function makeRowUnder(root: Uint8Array, seedByte: number, ordinal: number): {
  row: WalletVaultRewrapRow;
  secretKey: Buffer;
} {
  const base = makeRow(seedByte, ordinal);
  return {
    row: { identity: base.row.identity, envelope: sealWalletSecret(root, base.row.identity, base.secretKey) },
    secretKey: base.secretKey,
  };
}

async function makePushRow(root: Uint8Array = OLD_ROOT): Promise<{
  row: PushSecretRewrapRow;
  secret: Buffer;
}> {
  const identity = {
    nodeId: "11111111-1111-4111-8111-111111111111",
    walletId: "dddddddd-0000-4000-8000-000000000001",
    materialKind: "AUTH_SECRET" as const,
    keyVersion: 1,
  };
  const secret = Buffer.alloc(16, 0x5a);
  const envelope = await createPushSecretSealer({
    rootKey: root,
    nodeId: identity.nodeId,
    walletId: identity.walletId,
  }).seal(secret, "AUTH_SECRET");
  return { row: { identity, envelope }, secret };
}

const NODE_ID = "11111111-1111-4111-8111-111111111111";

/**
 * The salt port a composition root wires (ZTR-1159): `resolveCeremonyRootKdfSalt` bound to the
 * live connection, exactly as both recovery ceremonies bind it. Rotation must derive under the
 * salt persisted beside the envelopes — a node whose salt was minted at genesis keeps it there
 * and nowhere else, so a config-only resolver would derive the historical literal and unwrap
 * nothing.
 */
function saltPort(options: {
  persisted?: { salt: Buffer; source: RootKdfSaltSource };
  env?: NodeJS.ProcessEnv;
}) {
  const sql: RootKdfSaltSqlExecutor = {
    async query<T>(): Promise<{ rows: T[] }> {
      return { rows: (options.persisted === undefined ? [] : [options.persisted]) as T[] };
    },
  };
  return () => resolveCeremonyRootKdfSalt({ sql, nodeId: NODE_ID, env: options.env ?? {} });
}

function env(): NodeJS.ProcessEnv {
  return {
    VAULT_MASTER_KEY: OLD_MASTER,
    VAULT_MASTER_KEY_NEW: NEW_MASTER,
    VAULT_ROOT_SALT_B64: SALT_B64,
  };
}

describe("runRotateMasterKeyCli", () => {
  it("wipes both derived roots exactly once when the push census rejects", async () => {
    const expectedRoots = [OLD_ROOT, NEW_ROOT];
    const wipes = new Map(expectedRoots.map((root) => [root.toString("hex"), 0]));
    const bufferPrototype = Buffer.prototype as unknown as {
      fill(this: Buffer, ...args: unknown[]): Buffer;
    };
    const originalFill = bufferPrototype.fill;
    bufferPrototype.fill = function (this: Buffer, ...args: unknown[]): Buffer {
      const before = this.toString("hex");
      if (wipes.has(before) && args[0] === 0) wipes.set(before, wipes.get(before)! + 1);
      return Reflect.apply(originalFill, this, args) as Buffer;
    };

    try {
      await expect(runRotateMasterKeyCli({
        loadCensus: { rows: [] },
        countWalletVaultRows: async () => 0,
        countNodeSigningKeyRows: async () => 0,
        loadPushSecretsCensus: async () => { throw new Error("injected push census failure"); },
        countPushSecretRows: async () => 0,
        loadTotpSecretsCensus: { rows: [] },
        countTotpSecretRows: async () => 0,
        nodeId: "11111111-1111-4111-8111-111111111111",
        loadBootCanaryCensus: { envelope: null },
        countBootCanaryRows: async () => 0,
        journal: new InMemoryMasterKeyRotationJournal(1),
        interlock: { async acquire() {}, async release() {} },
        resolveRootKdfSalt: saltPort({ persisted: { salt: SALT, source: "environment" } }),
        unitOfWork: new InMemoryRotationUnitOfWork(),
        commitWalletVault: async () => {},
        fromEpoch: 1,
        env: env(),
        argv: ["node", "cli.js"],
        logger: { info() {}, error() {} },
      })).rejects.toThrow("injected push census failure");
    } finally {
      bufferPrototype.fill = originalFill;
    }

    expect([...wipes.values()]).toEqual([1, 1]);
  });

  it("dry-run proves non-empty wallet and push rotation without persistence", async () => {
    const fixtures = [1, 2].map((n) => makeRow(0x30 + n, n));
    const push = await makePushRow();
    const journal = new InMemoryMasterKeyRotationJournal(1);
    const commit = vi.fn();
    const commitPush = vi.fn();

    const result = await runRotateMasterKeyCli({
      loadCensus: { rows: fixtures.map((f) => f.row) },
      countWalletVaultRows: async () => fixtures.length,
      countNodeSigningKeyRows: async () => 0,
      loadPushSecretsCensus: { rows: [push.row] },
      countPushSecretRows: async () => 1,
      loadTotpSecretsCensus: { rows: [] },
      countTotpSecretRows: async () => 0,
      nodeId: "11111111-1111-4111-8111-111111111111",
      loadBootCanaryCensus: { envelope: null },
      countBootCanaryRows: async () => 0,
      journal,
      interlock: { async acquire() {}, async release() {} },
      resolveRootKdfSalt: saltPort({ persisted: { salt: SALT, source: "environment" } }),
      unitOfWork: new InMemoryRotationUnitOfWork(),
      commitWalletVault: commit,
      commitPushSecrets: commitPush,
      fromEpoch: 1,
      env: env(),
      argv: ["node", "rotate-master-key.cli.js", "--dry-run"],
      logger: { info() {}, error() {} },
    });

    expect(result.dryRun).toBe(true);
    expect(result.committed).toBe(false);
    expect(result.walletCount).toBe(2);
    expect(commit).not.toHaveBeenCalled();
    expect(commitPush).not.toHaveBeenCalled();
    expect((await journal.read()).writerEpoch).toBe(1);
    expect(OPERATOR_SEQUENCE.length).toBeGreaterThanOrEqual(5);
  });

  it("commit advances the journal and persists wallet and push rows under the new root", async () => {
    const fixtures = [makeRow(0x41, 1)];
    const push = await makePushRow();
    const journal = new InMemoryMasterKeyRotationJournal(1);
    let committed: readonly WalletVaultRewrapRow[] = [];
    let committedPush: readonly PushSecretRewrapRow[] = [];

    const result = await runRotateMasterKeyCli({
      loadCensus: { rows: fixtures.map((f) => f.row) },
      countWalletVaultRows: async () => fixtures.length,
      countNodeSigningKeyRows: async () => 0,
      loadPushSecretsCensus: { rows: [push.row] },
      countPushSecretRows: async () => 1,
      loadTotpSecretsCensus: { rows: [] },
      countTotpSecretRows: async () => 0,
      nodeId: "11111111-1111-4111-8111-111111111111",
      loadBootCanaryCensus: { envelope: null },
      countBootCanaryRows: async () => 0,
      journal,
      interlock: { async acquire() {}, async release() {} },
      resolveRootKdfSalt: saltPort({ persisted: { salt: SALT, source: "environment" } }),
      unitOfWork: new InMemoryRotationUnitOfWork(),
      commitWalletVault: async (rows) => { committed = rows; },
      commitPushSecrets: async (rows) => { committedPush = rows; },
      fromEpoch: 1,
      env: env(),
      argv: ["node", "rotate-master-key.cli.js"],
      logger: { info() {}, error() {} },
    });

    expect(result.committed).toBe(true);
    expect(result.walletCount).toBe(1);
    expect((await journal.read()).writerEpoch).toBe(2);

    const opened = openWalletSecret(NEW_ROOT, committed[0]!.envelope, committed[0]!.identity);
    try {
      expect(Buffer.from(opened.bytes)).toEqual(fixtures[0]!.secretKey);
    } finally {
      opened.wipe();
    }
    const openedPush = await createPushSecretSealer({
      rootKey: NEW_ROOT,
      nodeId: committedPush[0]!.identity.nodeId,
      walletId: committedPush[0]!.identity.walletId,
    }).open(committedPush[0]!.envelope, "AUTH_SECRET");
    try {
      expect(openedPush).toEqual(push.secret);
      expect(committedPush[0]!.envelope).not.toEqual(push.row.envelope);
    } finally {
      openedPush.fill(0);
    }
  });

  it("rolls back staged wallet and push writes together when push persistence fails", async () => {
    const wallet = makeRow(0x51, 1);
    const push = await makePushRow();
    const journal = new InMemoryMasterKeyRotationJournal(1);
    const durable = {
      wallets: [wallet.row] as readonly WalletVaultRewrapRow[],
      push: [push.row] as readonly PushSecretRewrapRow[],
    };
    const staged: {
      wallets?: readonly WalletVaultRewrapRow[];
      push?: readonly PushSecretRewrapRow[];
    } = {};
    const unitOfWork: RotationUnitOfWork = {
      async begin() {},
      async commit() {
        durable.wallets = staged.wallets ?? durable.wallets;
        durable.push = staged.push ?? durable.push;
      },
      async end() {},
      async rollback() {
        delete staged.wallets;
        delete staged.push;
      },
    };

    await expect(runRotateMasterKeyCli({
      loadCensus: { rows: durable.wallets },
      countWalletVaultRows: async () => durable.wallets.length,
      countNodeSigningKeyRows: async () => 0,
      loadPushSecretsCensus: { rows: durable.push },
      countPushSecretRows: async () => durable.push.length,
      loadTotpSecretsCensus: { rows: [] },
      countTotpSecretRows: async () => 0,
      nodeId: "11111111-1111-4111-8111-111111111111",
      loadBootCanaryCensus: { envelope: null },
      countBootCanaryRows: async () => 0,
      journal,
      interlock: { async acquire() {}, async release() {} },
      resolveRootKdfSalt: saltPort({ persisted: { salt: SALT, source: "environment" } }),
      unitOfWork,
      commitWalletVault: async (rows) => { staged.wallets = rows; },
      commitPushSecrets: async () => { throw new Error("injected push write failure"); },
      fromEpoch: 1,
      env: env(),
      argv: ["node", "rotate-master-key.cli.js"],
      logger: { info() {}, error() {} },
    })).rejects.toMatchObject({ code: "ROTATION_ABORTED" });

    expect(durable.wallets[0]!.envelope).toEqual(wallet.row.envelope);
    expect(durable.push[0]!.envelope).toEqual(push.row.envelope);
    expect((await journal.read()).phase).toBe("STABLE");
    expect((await journal.read()).writerEpoch).toBe(1);
  });

  // A store with live rows and no commit port would rewrap under the new root and drop
  // the result, so the CLI refuses up front. The refusal must beat key adoption: the
  // master keys below are deliberately too short, so if `parseMasterKey` ran first we
  // would see its length refusal instead of the wiring one.
  it.each([
    {
      store: "NODE_SIGNING_KEYS",
      port: "commitNodeSigningKeys",
      counts: { countNodeSigningKeyRows: async () => 1, countPushSecretRows: async () => 0, countTotpSecretRows: async () => 0 },
    },
    {
      store: "PUSH_RECEIVER_SECRETS",
      port: "commitPushSecrets",
      counts: { countNodeSigningKeyRows: async () => 0, countPushSecretRows: async () => 1, countTotpSecretRows: async () => 0 },
    },
  ])("refuses when $store has rows but $port is unwired, before adopting key material", async ({
    store,
    port,
    counts,
  }) => {
    const journal = new InMemoryMasterKeyRotationJournal(1);
    const liveBefore = keyMaterialHygiene.liveOwnedCount();
    await expect(
      runRotateMasterKeyCli({
        loadCensus: { rows: [] },
        countWalletVaultRows: async () => 0,
        loadPushSecretsCensus: { rows: [] },
        loadTotpSecretsCensus: { rows: [] },
        countTotpSecretRows: async () => 0,
        nodeId: "11111111-1111-4111-8111-111111111111",
        loadBootCanaryCensus: { envelope: null },
        countBootCanaryRows: async () => 0,
        ...counts,
        journal,
        interlock: { async acquire() {}, async release() {} },
        resolveRootKdfSalt: saltPort({ persisted: { salt: SALT, source: "environment" } }),
        unitOfWork: new InMemoryRotationUnitOfWork(),
        commitWalletVault: async () => {},
        fromEpoch: 1,
        env: {
          VAULT_MASTER_KEY: "short-old",
          VAULT_MASTER_KEY_NEW: "short-new",
          VAULT_ROOT_SALT_B64: SALT_B64,
        },
        argv: ["node", "cli.js"],
        logger: { info() {}, error() {} },
      }),
    ).rejects.toMatchObject({
      code: "ROTATION_REFUSED",
      message: `${store} rows present but ${port} port is not wired`,
    });
    expect(keyMaterialHygiene.liveOwnedCount()).toBe(liveBefore);
    expect((await journal.read()).writerEpoch).toBe(1);
  });

  // ZTR-1159. This CLI used to REQUIRE VAULT_ROOT_SALT_B64 and accept almost any value for
  // it, while boot and both recovery ceremonies derived under a hardcoded literal. An
  // operator following this CLI's own error message therefore re-sealed every envelope under
  // a root key nothing else could reproduce, and found out at the next boot or at the
  // recovery ceremony. Unset now means the salt the node is already deriving under, so the
  // rewrapped envelopes stay openable on every other path.
  it("rotates without VAULT_ROOT_SALT_B64, under the node's own salt", async () => {
    const historicalRoot = deriveRootKey(OLD_MASTER, HISTORICAL_ROOT_KDF_SALT);
    const wallet = makeRowUnder(historicalRoot, 0x41, 1);
    let committed: readonly WalletVaultRewrapRow[] = [];

    const result = await runRotateMasterKeyCli({
      loadCensus: { rows: [wallet.row] },
      countWalletVaultRows: async () => 1,
      countNodeSigningKeyRows: async () => 0,
      loadPushSecretsCensus: { rows: [] },
      countPushSecretRows: async () => 0,
      loadTotpSecretsCensus: { rows: [] },
      countTotpSecretRows: async () => 0,
      nodeId: "11111111-1111-4111-8111-111111111111",
      loadBootCanaryCensus: { envelope: null },
      countBootCanaryRows: async () => 0,
      journal: new InMemoryMasterKeyRotationJournal(1),
      interlock: { async acquire() {}, async release() {} },
      // A node that predates ZTR-1159: no persisted row, so the resolver answers the literal.
      resolveRootKdfSalt: saltPort({}),
      unitOfWork: new InMemoryRotationUnitOfWork(),
      commitWalletVault: async (rows) => { committed = rows; },
      fromEpoch: 1,
      // No VAULT_ROOT_SALT_B64 — the trap the ticket describes cannot be sprung.
      env: { VAULT_MASTER_KEY: OLD_MASTER, VAULT_MASTER_KEY_NEW: NEW_MASTER },
      argv: ["node", "cli.js"],
      logger: { info() {}, error() {} },
    });

    expect(result.committed).toBe(true);
    expect(result.walletCount).toBe(1);
    // The rewrapped envelope opens under the NEW master and the SAME salt — which is exactly
    // what boot will derive at the next start with VAULT_ROOT_SALT_B64 still unset.
    const bootRoot = deriveRootKey(NEW_MASTER, HISTORICAL_ROOT_KDF_SALT);
    const opened = openWalletSecret(bootRoot, committed[0]!.envelope, committed[0]!.identity);
    try {
      expect(Buffer.from(opened.bytes).equals(wallet.secretKey)).toBe(true);
    } finally {
      opened.wipe();
    }
  });

  it("refuses a VAULT_ROOT_SALT_B64 that cannot decode to a usable salt", async () => {
    await expect(
      runRotateMasterKeyCli({
        loadCensus: { rows: [] },
        countWalletVaultRows: async () => 0,
        countNodeSigningKeyRows: async () => 0,
        loadPushSecretsCensus: { rows: [] },
        countPushSecretRows: async () => 0,
        loadTotpSecretsCensus: { rows: [] },
        countTotpSecretRows: async () => 0,
        nodeId: "11111111-1111-4111-8111-111111111111",
        loadBootCanaryCensus: { envelope: null },
        countBootCanaryRows: async () => 0,
        journal: new InMemoryMasterKeyRotationJournal(1),
        interlock: { async acquire() {}, async release() {} },
        resolveRootKdfSalt: saltPort({
          env: { VAULT_ROOT_SALT_B64: Buffer.from("tiny").toString("base64") },
        }),
        unitOfWork: new InMemoryRotationUnitOfWork(),
        commitWalletVault: async () => {},
        fromEpoch: 1,
        env: {
          VAULT_MASTER_KEY: OLD_MASTER,
          VAULT_MASTER_KEY_NEW: NEW_MASTER,
          VAULT_ROOT_SALT_B64: Buffer.from("tiny").toString("base64"),
        },
        argv: ["node", "cli.js"],
        logger: { info() {}, error() {} },
      }),
    ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
  });

  // ZTR-1159 r1 / D2. The CLI used to resolve the salt from configuration alone, which is a
  // DIFFERENT value from the one boot derives on any node whose salt was minted at genesis —
  // the exact divergence the ticket exists to remove, reintroduced on the fourth path.
  it("derives under the PERSISTED salt on a genesis_random node, not the historical literal", async () => {
    const minted = Buffer.alloc(32, 0x7c);
    const mintedOldRoot = deriveRootKey(OLD_MASTER, minted);
    const wallet = makeRowUnder(mintedOldRoot, 0x42, 1);
    let committed: readonly WalletVaultRewrapRow[] = [];

    const result = await runRotateMasterKeyCli({
      loadCensus: { rows: [wallet.row] },
      countWalletVaultRows: async () => 1,
      countNodeSigningKeyRows: async () => 0,
      loadPushSecretsCensus: { rows: [] },
      countPushSecretRows: async () => 0,
      loadTotpSecretsCensus: { rows: [] },
      countTotpSecretRows: async () => 0,
      nodeId: "11111111-1111-4111-8111-111111111111",
      loadBootCanaryCensus: { envelope: null },
      countBootCanaryRows: async () => 0,
      journal: new InMemoryMasterKeyRotationJournal(1),
      interlock: { async acquire() {}, async release() {} },
      resolveRootKdfSalt: saltPort({ persisted: { salt: minted, source: "genesis_random" } }),
      unitOfWork: new InMemoryRotationUnitOfWork(),
      commitWalletVault: async (rows) => {
        committed = rows;
      },
      fromEpoch: 1,
      // Unset, as the CLI header instructs. The config-only resolver would answer the
      // historical literal here and unwrap nothing.
      env: { VAULT_MASTER_KEY: OLD_MASTER, VAULT_MASTER_KEY_NEW: NEW_MASTER },
      argv: ["node", "cli.js"],
      logger: { info() {}, error() {} },
    });

    expect(result.committed).toBe(true);
    // What boot will derive at the next start: the persisted salt under the new master.
    const bootRoot = deriveRootKey(NEW_MASTER, minted);
    const opened = openWalletSecret(bootRoot, committed[0]!.envelope, committed[0]!.identity);
    try {
      expect(Buffer.from(opened.bytes).equals(wallet.secretKey)).toBe(true);
    } finally {
      opened.wipe();
    }
  });

  it("refuses when VAULT_ROOT_SALT_B64 disagrees with the persisted salt", async () => {
    await expect(
      runRotateMasterKeyCli({
        loadCensus: { rows: [] },
        countWalletVaultRows: async () => 0,
        countNodeSigningKeyRows: async () => 0,
        loadPushSecretsCensus: { rows: [] },
        countPushSecretRows: async () => 0,
        loadTotpSecretsCensus: { rows: [] },
        countTotpSecretRows: async () => 0,
        nodeId: "11111111-1111-4111-8111-111111111111",
        loadBootCanaryCensus: { envelope: null },
        countBootCanaryRows: async () => 0,
        journal: new InMemoryMasterKeyRotationJournal(1),
        interlock: { async acquire() {}, async release() {} },
        resolveRootKdfSalt: saltPort({
          persisted: { salt: Buffer.alloc(32, 0x7c), source: "genesis_random" },
          env: { VAULT_ROOT_SALT_B64: SALT_B64 },
        }),
        unitOfWork: new InMemoryRotationUnitOfWork(),
        commitWalletVault: async () => {},
        fromEpoch: 1,
        env: { VAULT_MASTER_KEY: OLD_MASTER, VAULT_MASTER_KEY_NEW: NEW_MASTER },
        argv: ["node", "cli.js"],
        logger: { info() {}, error() {} },
      }),
    ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
  });

  it("refuses missing env without touching the journal", async () => {
    const journal = new InMemoryMasterKeyRotationJournal(1);
    await expect(
      runRotateMasterKeyCli({
        loadCensus: { rows: [] },
        countWalletVaultRows: async () => 0,
        countNodeSigningKeyRows: async () => 0,
        loadPushSecretsCensus: { rows: [] },
        countPushSecretRows: async () => 0,
        loadTotpSecretsCensus: { rows: [] },
        countTotpSecretRows: async () => 0,
        nodeId: "11111111-1111-4111-8111-111111111111",
        loadBootCanaryCensus: { envelope: null },
        countBootCanaryRows: async () => 0,
        journal,
        interlock: { async acquire() {}, async release() {} },
        resolveRootKdfSalt: saltPort({ persisted: { salt: SALT, source: "environment" } }),
        unitOfWork: new InMemoryRotationUnitOfWork(),
        commitWalletVault: async () => {},
        fromEpoch: 1,
        env: {},
        argv: ["node", "cli.js"],
        logger: { info() {}, error() {} },
      }),
    ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
    expect((await journal.read()).writerEpoch).toBe(1);
  });
});

describe("runRotateMasterKeyCli boot canary rewrap (ZTR-1177 r2)", () => {
  const NODE_ID = "11111111-1111-4111-8111-111111111111";

  it("rewrites the durable canary under the new root inside the ceremony", async () => {
    const { row: w1 } = makeRow(1, 1);
    const journal = new InMemoryMasterKeyRotationJournal(1);
    const sealedA = sealVaultBootCanary(OLD_ROOT, NODE_ID);
    let durableCanary = sealedA;
    let committedCanary: string | null = null;

    const result = await runRotateMasterKeyCli({
      loadCensus: { rows: [w1] },
      countWalletVaultRows: async () => 1,
      countNodeSigningKeyRows: async () => 0,
      loadPushSecretsCensus: { rows: [] },
      countPushSecretRows: async () => 0,
      loadTotpSecretsCensus: { rows: [] },
      countTotpSecretRows: async () => 0,
      nodeId: NODE_ID,
      loadBootCanaryCensus: { envelope: sealedA },
      countBootCanaryRows: async () => 1,
      commitBootCanary: async (envelope) => {
        committedCanary = envelope;
        durableCanary = envelope;
      },
      journal,
      interlock: { async acquire() {}, async release() {} },
      resolveRootKdfSalt: saltPort({ persisted: { salt: SALT, source: "environment" } }),
      unitOfWork: new InMemoryRotationUnitOfWork(),
      commitWalletVault: async () => {},
      fromEpoch: 1,
      env: env(),
      argv: ["node", "rotate-master-key.cli.js"],
      logger: { info() {}, error() {} },
    });

    expect(result.committed).toBe(true);
    expect(committedCanary).not.toBeNull();
    expect(committedCanary).not.toBe(sealedA);
    // New root opens; old root does not.
    const opened = openVaultBootCanary(NEW_ROOT, NODE_ID, committedCanary!);
    try {
      expect(Buffer.from(opened).toString("utf8")).toBe(VAULT_BOOT_CANARY_PLAINTEXT);
    } finally {
      opened.fill(0);
    }
    expect(() => openVaultBootCanary(OLD_ROOT, NODE_ID, committedCanary!)).toThrow(
      /VAULT_BOOT_CANARY_DOES_NOT_OPEN/,
    );
    expect(durableCanary).toBe(committedCanary);
  });

  it("refuses rotation when canary row exists but commitBootCanary is unwired", async () => {
    const { row: w1 } = makeRow(1, 1);
    await expect(
      runRotateMasterKeyCli({
        loadCensus: { rows: [w1] },
        countWalletVaultRows: async () => 1,
        countNodeSigningKeyRows: async () => 0,
        loadPushSecretsCensus: { rows: [] },
        countPushSecretRows: async () => 0,
        loadTotpSecretsCensus: { rows: [] },
        countTotpSecretRows: async () => 0,
        nodeId: NODE_ID,
        loadBootCanaryCensus: { envelope: "zp-vault-boot-canary-v1.dGVzdA==" },
        countBootCanaryRows: async () => 1,
        // commitBootCanary intentionally omitted
        journal: new InMemoryMasterKeyRotationJournal(1),
        interlock: { async acquire() {}, async release() {} },
        resolveRootKdfSalt: saltPort({ persisted: { salt: SALT, source: "environment" } }),
        unitOfWork: new InMemoryRotationUnitOfWork(),
        commitWalletVault: async () => {},
        fromEpoch: 1,
        env: env(),
        argv: ["node", "rotate-master-key.cli.js"],
        logger: { info() {}, error() {} },
      }),
    ).rejects.toThrow(/commitBootCanary port is not wired/);
  });
});

