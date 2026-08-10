// Shared fixtures for the master-key rotation fault-injection suite.
//
// Targets the public surface:
//   packages/node-core/src/vault/{master-key-rotation,key-ring,rotation-journal}.ts
//   packages/node-core/src/schema/sealed-store-registry.contract.ts → SEALED_STORES
//
// When those symbols are absent from the vault barrel the suite self-skips; once they
// resolve it executes in full.
//
// Synthetic keys only — never log key/ciphertext bytes.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";

import { SEALED_STORES, type SealedStoreId } from "../src/schema/sealed-store-registry.contract.js";
import {
  deriveRootKey,
  openWalletSecret,
  sealWalletSecret,
  toBase64UrlPadded,
  type SealedEnvelope,
  type WalletIdentity,
  type WalletVaultRewrapRow,
} from "../src/vault/index.js";

// ── Conditional load of public surface ────────────────────────────────

/** Public rotation symbols exports from `src/vault/index.ts`. */
export interface RotationPublicApi {
  readonly rotateMasterKey: (input: Record<string, unknown>) => Promise<RotationResultLike>;
  readonly MasterKeyRotationError: new (
    code: string,
    message: string,
    cause?: unknown,
  ) => Error & { readonly code: string };
  readonly ProcessLocalMasterKeyRotationInterlock: new () => MasterKeyRotationInterlockLike;
  readonly InMemoryRotationUnitOfWork: (new () => RotationUnitOfWorkLike) & {
    resetGlobalHolder(): void;
  };
  readonly InMemoryMasterKeyRotationJournal: new (
    writerEpoch: number,
  ) => MasterKeyRotationJournalLike;
  readonly buildKeyRing: (input: {
    readonly writerEpoch: number;
    readonly writerRoot: Uint8Array;
    readonly retained?: readonly { readonly epoch: number; readonly root: Uint8Array }[];
  }) => VaultKeyRingLike;
  readonly openWithKeyRing: (
    ring: VaultKeyRingLike,
    envelope: SealedEnvelope,
    identity: WalletIdentity,
  ) => { readonly secret: { readonly bytes: Uint8Array; wipe(): void }; readonly epoch: number };
}

export interface RotationResultLike {
  readonly committed: boolean;
  readonly dryRun: boolean;
  readonly fromEpoch: number;
  readonly toEpoch: number;
  readonly walletCount: number;
  readonly stores: readonly {
    readonly storeId: string;
    readonly status: string;
    readonly result: {
      readonly rowsBefore: number;
      readonly rowsAfter: number;
      readonly rewrapped: number;
    } | null;
  }[];
  readonly journal: {
    readonly phase: string;
    readonly writerEpoch: number;
    readonly rewrappedWalletIds: readonly string[];
  };
  readonly durationMs: number;
}

export interface MasterKeyRotationInterlockLike {
  acquire(): Promise<void>;
  release(): Promise<void>;
  readonly held: boolean;
  readonly acquireCount: number;
  readonly releaseCount: number;
  assertSigningAdmitted?(purpose?: string): void;
}

export interface RotationUnitOfWorkLike {
  begin(): Promise<void>;
  commit(): Promise<void>;
  end(): Promise<void>;
  rollback(): Promise<void>;
  readonly begins: number;
  readonly commits: number;
  readonly rollbacks: number;
  readonly ends: number;
  readonly lockAcquired: boolean;
  readonly sessionHeld: boolean;
}

export interface MasterKeyRotationJournalLike {
  read(): Promise<{
    phase: string;
    writerEpoch: number;
    fromEpoch: number | null;
    toEpoch: number | null;
    rewrappedWalletIds: readonly string[];
  }>;
  begin(input: { fromEpoch: number; toEpoch: number }): Promise<unknown>;
  markRewrapped(walletId: string): Promise<void>;
  complete(): Promise<unknown>;
  settleStable(): Promise<unknown>;
}

export interface VaultKeyRingLike {
  readonly writerEpoch: number;
  readonly entries: readonly { readonly epoch: number; readonly root: Uint8Array }[];
}

/**
 * Probe the vault barrel for the rotation API. Returns null when the symbols
 * are not yet merged (origin/main without) so the suite can self-skip.
 */
export function asRotationApi(barrel: Record<string, unknown>): RotationPublicApi | null {
  const required = [
    "rotateMasterKey",
    "MasterKeyRotationError",
    "ProcessLocalMasterKeyRotationInterlock",
    "InMemoryRotationUnitOfWork",
    "InMemoryMasterKeyRotationJournal",
    "buildKeyRing",
    "openWithKeyRing",
  ] as const;
  for (const name of required) {
    if (typeof barrel[name] !== "function") return null;
  }
  return barrel as unknown as RotationPublicApi;
}

// ── Constants / roots ────────────────────────────────────────────────────────

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export const MASTER_OLD = Buffer.from("old-master-key-for-fault-inject!!"); // 32 bytes
export const MASTER_NEW = Buffer.from("new-master-key-for-fault-inject!!"); // 32 bytes
export const MASTER_WRONG = Buffer.from("wrong-master-key-for-fault-inj!!"); // 32 bytes
export const SALT = Buffer.from("fault-inject-rotation-salt-v1");

export const OLD_ROOT = deriveRootKey(MASTER_OLD, SALT);
export const NEW_ROOT = deriveRootKey(MASTER_NEW, SALT);
export const WRONG_ROOT = deriveRootKey(MASTER_WRONG, SALT);

export const FROM_EPOCH = 1;
export const TO_EPOCH = 2;

export const NODE_ID = "11111111-1111-4111-8111-111111111111";

/** Every registered sealed-store id from the census. */
export const REGISTERED_STORE_IDS: readonly SealedStoreId[] = SEALED_STORES.map((s) => s.id);

export function registrySnapshot(): readonly {
  readonly id: string;
  readonly rewrapStatus: "IMPLEMENTED" | "DEFERRED_NO_SEAL_RUNTIME";
}[] {
  return SEALED_STORES.map((s) => ({ id: s.id, rewrapStatus: s.rewrapStatus }));
}

// ── Wallet fixtures ──────────────────────────────────────────────────────────

export interface WalletFixture {
  readonly row: WalletVaultRewrapRow;
  readonly secretKey: Buffer;
  /** Monotonic recovery stamp — rotation must never clear or rewrite this. */
  recoveryVerifiedAt: string | null;
}

export function makeSecret(seedByte: number): { secretKey: Buffer; publicKey: string } {
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

export function makeRow(
  seedByte: number,
  walletOrdinal: number,
  root: Uint8Array = OLD_ROOT,
): WalletFixture {
  const { secretKey, publicKey } = makeSecret(seedByte);
  // Lexicographic order deliberately non-insertion so mid-population ≠ middle of input array.
  const walletId = `aaaaaaaa-0000-4000-8000-00000000000${walletOrdinal}`;
  const identity: WalletIdentity = {
    nodeId: NODE_ID,
    walletId,
    keyVersion: 1,
    publicKey,
    keyOrigin: "node_generated",
  };
  const envelope = sealWalletSecret(root, identity, secretKey);
  return {
    row: { identity, envelope },
    secretKey,
    recoveryVerifiedAt: "2026-01-15T12:00:00.000Z",
  };
}

export function censusPorts(rows: readonly WalletVaultRewrapRow[]): {
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

export function makeKeyRing(
  api: RotationPublicApi,
  opts?: { wrongOld?: boolean; equalRoots?: boolean },
) {
  const oldRoot = opts?.wrongOld ? WRONG_ROOT : OLD_ROOT;
  const newRoot = opts?.equalRoots ? oldRoot : NEW_ROOT;
  return api.buildKeyRing({
    writerEpoch: TO_EPOCH,
    writerRoot: newRoot,
    retained: [{ epoch: FROM_EPOCH, root: oldRoot }],
  });
}

// ── Readable-state sweep (AC7 — every abort path) ────────────────────────────

export type KeySide = "old" | "new" | "neither" | "both";

/**
 * For every row, classify which root(s) open it. AC7 requires each row decrypts under
 * exactly one key after any induced abort — never a mixed population across the store,
 * and never a single row readable under both (or neither) when the ceremony aborted
 * before vault durability.
 */
export function classifyRow(
  row: WalletVaultRewrapRow,
  oldRoot: Uint8Array = OLD_ROOT,
  newRoot: Uint8Array = NEW_ROOT,
): KeySide {
  let underOld = false;
  let underNew = false;
  try {
    const o = openWalletSecret(oldRoot, row.envelope, row.identity);
    o.wipe();
    underOld = true;
  } catch {
    // unreadable under old
  }
  try {
    const n = openWalletSecret(newRoot, row.envelope, row.identity);
    n.wipe();
    underNew = true;
  } catch {
    // unreadable under new
  }
  if (underOld && underNew) return "both";
  if (underOld) return "old";
  if (underNew) return "new";
  return "neither";
}

export function assertNoMixedReadableState(
  rows: readonly WalletVaultRewrapRow[],
  expectSide: "old" | "new" = "old",
): void {
  const sides = rows.map((r) => classifyRow(r));
  for (const side of sides) {
    if (side === "both" || side === "neither") {
      throw new Error(
        `mixed/unreadable vault row: expected every row under '${expectSide}' only, saw ${JSON.stringify(sides)}`,
      );
    }
  }
  const distinct = new Set(sides);
  if (distinct.size !== 1 || !distinct.has(expectSide)) {
    throw new Error(
      `mixed readable state across store: expected all '${expectSide}', saw ${JSON.stringify(sides)}`,
    );
  }
}

export function envelopeFingerprint(envelope: SealedEnvelope): string {
  return createHash("sha256")
    .update(envelope.ciphertext)
    .update(envelope.nonce)
    .update(envelope.authTag)
    .digest("hex");
}

// ── Audited recovery export stub (AC6) ───────────────────────────────────────
//
// Recovery export matching public key + recorded digest must succeed
// identically immediately before and after a committed rotation.
// recovery_verified_at monotonicity is DEFERRED: no durable stamp column/port is
// on the rotation/census path yet — do not assert fixture re-carry as
// proof. export is not yet built — this stub seals the invariant
// over the public key + a sha256 of the opened secret (the "recorded digest").

export interface RecoveryExportRecord {
  readonly walletId: string;
  readonly publicKey: string;
  readonly secretDigest: string;
  readonly recoveryVerifiedAt: string | null;
}

export function auditedRecoveryExport(
  fixtures: readonly WalletFixture[],
  root: Uint8Array,
): readonly RecoveryExportRecord[] {
  return fixtures.map((f) => {
    const opened = openWalletSecret(root, f.row.envelope, f.row.identity);
    try {
      return {
        walletId: f.row.identity.walletId,
        publicKey: f.row.identity.publicKey,
        secretDigest: createHash("sha256").update(opened.bytes).digest("hex"),
        recoveryVerifiedAt: f.recoveryVerifiedAt,
      };
    } finally {
      opened.wipe();
    }
  });
}

// ── Minimal backup/export stub sharing the rotation interlock (AC4) ──────────
//
// is downstream and not yet built. Exclusion point: the
// same ProcessLocalMasterKeyRotationInterlock.acquire() gate that rotation holds.
// A concurrent export attempt that also takes the interlock must refuse while
// rotation holds it, and proceed once released.

export async function exportUnderInterlock(
  interlock: MasterKeyRotationInterlockLike,
  build: () => string,
): Promise<string> {
  await interlock.acquire();
  try {
    return build();
  } finally {
    await interlock.release();
  }
}

/** Build a deterministic export digest over public keys + ciphertext fingerprints. */
export function buildExportDigest(fixtures: readonly WalletFixture[]): string {
  const h = createHash("sha256");
  const sorted = [...fixtures].sort((a, b) =>
    a.row.identity.walletId < b.row.identity.walletId
      ? -1
      : a.row.identity.walletId > b.row.identity.walletId
        ? 1
        : 0,
  );
  for (const f of sorted) {
    h.update(f.row.identity.walletId);
    h.update(f.row.identity.publicKey);
    h.update(envelopeFingerprint(f.row.envelope));
  }
  return h.digest("hex");
}

export function makeEd25519Signer(): {
  publicKey: string;
  privateKey: KeyObject;
  sign: (preimage: Uint8Array) => Uint8Array;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPub = Buffer.from(spki).subarray(-32);
  return {
    publicKey: toBase64UrlPadded(rawPub),
    privateKey,
    sign: (preimage: Uint8Array) => new Uint8Array(nodeSign(null, Buffer.from(preimage), privateKey)),
  };
}
