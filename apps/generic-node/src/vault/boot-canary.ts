// Boot-time vault unlock canary (ZTR-1177).
//
// The vault-unlock boot step used to succeed whenever EncryptedWalletKeyStore
// constructed — which is always true and proves nothing about VAULT_MASTER_KEY.
// assertRootKeyOpensSealedEnvelope (ZTR-1159) closes that gap when the node has
// already sealed a wallet or signing key, but returns checked:false on a virgin
// node (the restore-onto-fresh-secret case the audit names).
//
// This module seals a fixed, non-secret plaintext under the derived root key and
// persists the envelope in node_settings. Every subsequent boot opens that same
// envelope. First boot writes it; every later boot fails closed when the master
// key (or salt) is not the one that sealed it — before readiness opens the vault
// gate and before money workers start.
//
// Design constraints (ticket + sealed-store discipline):
// - Fixed non-secret plaintext; never log ciphertext, root key, or VAULT_MASTER_KEY.
// - node_settings row (no new table / migration).
// - AES-256-GCM under a store-unique HKDF label (same shape as TOTP / push seals).
// - AAD binds nodeId so a row cannot be transplanted between nodes.
// - Failure names the vault-unlock step and carries no key material.
// - Master-key rotation MUST rewrap (or delete+reseal) this envelope under the new
//   root in the same ceremony UoW as other root-keyed stores — insert-only first-boot
//   semantics intentionally have no overwrite path outside rotation (ZTR-1177 r2).

import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

import { DEK_LENGTH_BYTES, keyMaterialHygiene } from "@zucoins/node-core";

const NONCE_BYTES = 12;
const TAG_BYTES = 16;

/** node_settings key — namespaced under vault.; insert-or-keep on first write. */
export const VAULT_BOOT_CANARY_SETTING_KEY = "vault.boot_canary_v1" as const;

/**
 * Envelope version prefix. Layout bumps take a new vN (and a new settings key),
 * never a silent append to the blob.
 */
export const VAULT_BOOT_CANARY_ENVELOPE_PREFIX = "zp-vault-boot-canary-v1" as const;

/**
 * Frozen HKDF domain label. Globally unique across sealed stores; byte-exact —
 * never reformat. Not registered in packages/node-core sealed-store-registry
 * because the seal site lives under apps/ (that census is packages/** only);
 * the label still must not collide with any registered store.
 */
export const VAULT_BOOT_CANARY_HKDF_LABEL = "zupayments/vault-boot-canary/v1" as const;

/**
 * Fixed non-secret plaintext. Public by design — proving the root opens this
 * value is the whole point. Never treat it as confidential.
 */
export const VAULT_BOOT_CANARY_PLAINTEXT = "zupayments-vault-boot-canary-v1" as const;

export type VaultBootCanaryErrorCode =
  /** Persisted envelope is truncated, wrong-prefix, or not decodable. */
  | "VAULT_BOOT_CANARY_MALFORMED"
  /** Root key does not authenticate the canary (wrong master key or salt). */
  | "VAULT_BOOT_CANARY_DOES_NOT_OPEN"
  /** Opened plaintext does not match the fixed canary constant. */
  | "VAULT_BOOT_CANARY_PLAINTEXT_MISMATCH";

/**
 * Named early failure for the vault-unlock step. Message names the step and the
 * failure class; never includes key material, ciphertext, or configuration values.
 */
export class VaultBootCanaryError extends Error {
  readonly code: VaultBootCanaryErrorCode;

  constructor(code: VaultBootCanaryErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = "VaultBootCanaryError";
    this.code = code;
  }
}

export interface VaultBootCanarySqlExecutor {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

export interface VaultBootCanaryResult {
  /** True when an existing canary was opened; false when this boot sealed the first one. */
  readonly verified: boolean;
  /** "opened" on a returning node; "sealed" on first sight. */
  readonly action: "opened" | "sealed";
}

function assertRootKey(rootKey: Uint8Array): void {
  if (rootKey.length !== DEK_LENGTH_BYTES) {
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_MALFORMED",
      "vault root key length is not 32 bytes",
    );
  }
}

function assertNodeId(nodeId: string): void {
  if (typeof nodeId !== "string" || nodeId.length === 0) {
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_MALFORMED",
      "node id is required for vault boot canary AAD",
    );
  }
}

/** Exact UTF-8 HKDF info text. Byte contract — never reformat. */
export function buildVaultBootCanaryDekInfo(): string {
  return VAULT_BOOT_CANARY_HKDF_LABEL;
}

/**
 * GCM AAD = node id. Reconstructed at open; never stored.
 * Wrong node → AUTH_TAG failure (fail closed).
 */
export function buildVaultBootCanaryAad(nodeId: string): string {
  return nodeId;
}

function deriveVaultBootCanaryDek(rootKey: Uint8Array): Buffer {
  const info = buildVaultBootCanaryDekInfo();
  return keyMaterialHygiene.adopt(
    Buffer.from(
      hkdfSync(
        "sha256",
        Buffer.from(rootKey),
        Buffer.alloc(0),
        Buffer.from(info, "utf8"),
        DEK_LENGTH_BYTES,
      ),
    ),
  );
}

/**
 * Seal the fixed canary plaintext under the vault root with node-id AAD.
 * Returns opaque `zp-vault-boot-canary-v1.<base64(nonce||tag||ciphertext)>`.
 */
export function sealVaultBootCanary(rootKey: Uint8Array, nodeId: string): string {
  assertRootKey(rootKey);
  assertNodeId(nodeId);
  const aad = Buffer.from(buildVaultBootCanaryAad(nodeId), "utf8");
  const nonce = randomBytes(NONCE_BYTES);
  const dek = deriveVaultBootCanaryDek(rootKey);
  const plaintext = keyMaterialHygiene.adopt(Buffer.from(VAULT_BOOT_CANARY_PLAINTEXT, "utf8"));
  try {
    const cipher = createCipheriv("aes-256-gcm", dek, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${VAULT_BOOT_CANARY_ENVELOPE_PREFIX}.${Buffer.concat([nonce, tag, ciphertext]).toString("base64")}`;
  } finally {
    keyMaterialHygiene.zeroize(dek, "dek");
    keyMaterialHygiene.zeroize(plaintext, "seal_plaintext");
  }
}

/**
 * Open a sealed canary envelope. Wrong node / root / tamper → VaultBootCanaryError.
 * Returns a fresh Buffer the caller must wipe after comparing.
 */
export function openVaultBootCanary(
  rootKey: Uint8Array,
  nodeId: string,
  sealed: string,
): Buffer {
  assertRootKey(rootKey);
  assertNodeId(nodeId);
  if (typeof sealed !== "string" || sealed.length === 0) {
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_MALFORMED",
      "vault boot canary envelope is missing",
    );
  }
  const dot = sealed.indexOf(".");
  if (dot < 0 || sealed.slice(0, dot) !== VAULT_BOOT_CANARY_ENVELOPE_PREFIX) {
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_MALFORMED",
      "vault boot canary has an unrecognised envelope prefix",
    );
  }
  const blob = Buffer.from(sealed.slice(dot + 1), "base64");
  if (blob.length < NONCE_BYTES + TAG_BYTES + 1) {
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_MALFORMED",
      "vault boot canary envelope is truncated",
    );
  }
  const nonce = blob.subarray(0, NONCE_BYTES);
  const tag = blob.subarray(NONCE_BYTES, NONCE_BYTES + TAG_BYTES);
  const ciphertext = blob.subarray(NONCE_BYTES + TAG_BYTES);
  const aad = Buffer.from(buildVaultBootCanaryAad(nodeId), "utf8");
  const dek = deriveVaultBootCanaryDek(rootKey);
  try {
    const decipher = createDecipheriv("aes-256-gcm", dek, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    if (err instanceof VaultBootCanaryError) throw err;
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_DOES_NOT_OPEN",
      "vault-unlock: the derived root key does not open the boot canary — " +
        "VAULT_MASTER_KEY or the root-KDF salt is not the one this node sealed under",
    );
  } finally {
    keyMaterialHygiene.zeroize(dek, "dek");
  }
}

function plaintextsEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

async function loadCanary(
  sql: VaultBootCanarySqlExecutor,
): Promise<string | null> {
  const { rows } = await sql.query<{ setting_value: string }>(
    "SELECT setting_value FROM node_settings WHERE setting_key = $1",
    [VAULT_BOOT_CANARY_SETTING_KEY],
  );
  const value = rows[0]?.setting_value;
  if (value === undefined || value.length === 0) return null;
  return value;
}

/**
 * Persist the canary. Insert-only semantics: ON CONFLICT DO NOTHING so a racing
 * sibling (or a retry after a crash between seal and read-back) cannot replace
 * an envelope sealed under a different root. The caller always re-reads and
 * opens after this write.
 */
async function tryInsertCanary(
  sql: VaultBootCanarySqlExecutor,
  sealed: string,
): Promise<void> {
  await sql.query(
    `INSERT INTO node_settings (setting_key, setting_value, row_version, updated_at)
     VALUES ($1, $2, 1, now())
     ON CONFLICT (setting_key) DO NOTHING`,
    [VAULT_BOOT_CANARY_SETTING_KEY, sealed],
  );
}

/**
 * Prove the derived root key can seal and unseal the boot canary.
 *
 * - Existing row → open it under the current root; throw if AEAD fails or the
 *   plaintext is not the fixed constant.
 * - Missing row → seal under the current root, insert-or-keep, then open the
 *   durable row (which may be a sibling's concurrent insert) so the gate never
 *   opens on a write-only success.
 *
 * Call only after the root key is final (post salt reconcile / rederive). A throw
 * here aborts vault-unlock; boot-lane leaves readiness.vault false and never
 * starts money workers.
 */
export async function proveVaultRootWithBootCanary(deps: {
  readonly sql: VaultBootCanarySqlExecutor;
  readonly nodeId: string;
  readonly rootKey: Uint8Array;
}): Promise<VaultBootCanaryResult> {
  assertRootKey(deps.rootKey);
  assertNodeId(deps.nodeId);

  let sealed = await loadCanary(deps.sql);
  let action: "opened" | "sealed" = "opened";

  if (sealed === null) {
    action = "sealed";
    const candidate = sealVaultBootCanary(deps.rootKey, deps.nodeId);
    await tryInsertCanary(deps.sql, candidate);
    sealed = await loadCanary(deps.sql);
    if (sealed === null) {
      throw new VaultBootCanaryError(
        "VAULT_BOOT_CANARY_MALFORMED",
        "vault-unlock: boot canary row missing immediately after insert",
      );
    }
  }

  let opened: Buffer;
  try {
    opened = openVaultBootCanary(deps.rootKey, deps.nodeId, sealed);
  } catch (err) {
    if (err instanceof VaultBootCanaryError) throw err;
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_DOES_NOT_OPEN",
      "vault-unlock: the derived root key does not open the boot canary — " +
        "VAULT_MASTER_KEY or the root-KDF salt is not the one this node sealed under",
    );
  }

  try {
    const expected = Buffer.from(VAULT_BOOT_CANARY_PLAINTEXT, "utf8");
    if (!plaintextsEqual(opened, expected)) {
      throw new VaultBootCanaryError(
        "VAULT_BOOT_CANARY_PLAINTEXT_MISMATCH",
        "vault-unlock: boot canary opened but plaintext does not match the fixed constant",
      );
    }
  } finally {
    opened.fill(0);
  }

  return { verified: action === "opened", action };
}

/**
 * Load the durable boot-canary envelope, or null when absent.
 * Used by unlock prove and by master-key rotation census.
 */
export async function loadVaultBootCanary(
  sql: VaultBootCanarySqlExecutor,
): Promise<string | null> {
  return loadCanary(sql);
}

/**
 * Authoritative 0-or-1 count of the boot-canary row inside the ceremony fence.
 * Parity is against this count, never a pre-fence snapshot length alone.
 */
export async function countVaultBootCanaryRows(
  sql: VaultBootCanarySqlExecutor,
): Promise<number> {
  const { rows } = await sql.query<{ n: string | number }>(
    "SELECT COUNT(*)::int AS n FROM node_settings WHERE setting_key = $1",
    [VAULT_BOOT_CANARY_SETTING_KEY],
  );
  const n = rows[0]?.n;
  if (n === undefined) return 0;
  return typeof n === "number" ? n : Number(n);
}

/**
 * Persist a rewrapped canary envelope under the existing settings key.
 * UPDATE only — rotation never inserts a first canary (first seal is unlock's job).
 * Bumps row_version; fails closed when the row disappeared mid-ceremony.
 */
export async function commitVaultBootCanary(
  sql: VaultBootCanarySqlExecutor,
  sealed: string,
): Promise<void> {
  if (typeof sealed !== "string" || sealed.length === 0) {
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_MALFORMED",
      "rotation commit refused an empty boot canary envelope",
    );
  }
  const { rows } = await sql.query<{ setting_key: string }>(
    `UPDATE node_settings
        SET setting_value = $2,
            row_version = row_version + 1,
            updated_at = now()
      WHERE setting_key = $1
      RETURNING setting_key`,
    [VAULT_BOOT_CANARY_SETTING_KEY, sealed],
  );
  if (rows.length !== 1) {
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_MALFORMED",
      "rotation commit could not update the boot canary row",
    );
  }
}

export interface VaultBootCanaryRewrapInput {
  readonly oldRootKey: Uint8Array;
  readonly newRootKey: Uint8Array;
  readonly nodeId: string;
  /**
   * Existing durable envelope. Crash-resume may already be under newRootKey
   * (writer-first open, push/TOTP key-ring parity).
   */
  readonly envelope: string;
}

export interface VaultBootCanaryRewrapReport {
  readonly result: {
    readonly rowsBefore: number;
    readonly rowsAfter: number;
    readonly rewrapped: number;
  };
  readonly rewrappedEnvelope: string;
}

function assertCanaryPlaintext(opened: Buffer, where: string): void {
  const expected = Buffer.from(VAULT_BOOT_CANARY_PLAINTEXT, "utf8");
  if (!plaintextsEqual(opened, expected)) {
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_PLAINTEXT_MISMATCH",
      `master-key rotation: boot canary plaintext mismatch ${where}`,
    );
  }
}

/**
 * Value-preserving master-key rewrap for the boot canary (0-or-1 row).
 *
 * Crash-resume / key-ring parity with push + TOTP:
 * 1. Try open under **new** root first (writer). If it authenticates, the durable
 *    row is already under the writer — skip reseal and carry the envelope through.
 * 2. Else open under **old** root. On success, reseal under new + round-trip.
 * 3. If neither root opens, refuse (would brick vault-unlock after advance).
 *
 * Pure over the envelope — caller owns the DB commit boundary (same UoW as other
 * sealed-store commits). Caller must pass the **live** node_settings envelope on
 * resume/finalize, not a pre-rotation census snapshot alone.
 */
export function rewrapVaultBootCanary(
  input: VaultBootCanaryRewrapInput,
): VaultBootCanaryRewrapReport {
  assertRootKey(input.oldRootKey);
  assertRootKey(input.newRootKey);
  assertNodeId(input.nodeId);

  // Writer-first (new), then retained old — same sequence as orderEntriesForOpen.
  let openedUnder: "new" | "old" | null = null;
  let opened: Buffer | null = null;

  try {
    opened = openVaultBootCanary(input.newRootKey, input.nodeId, input.envelope);
    assertCanaryPlaintext(opened, "under the new root");
    openedUnder = "new";
  } catch (err) {
    if (!(err instanceof VaultBootCanaryError)) throw err;
    // fall through to old
  } finally {
    if (openedUnder !== "new" && opened !== null) {
      opened.fill(0);
      opened = null;
    }
  }

  if (openedUnder !== "new") {
    try {
      opened = openVaultBootCanary(input.oldRootKey, input.nodeId, input.envelope);
      assertCanaryPlaintext(opened, "under the old root");
      openedUnder = "old";
    } catch (err) {
      if (err instanceof VaultBootCanaryError) {
        throw new VaultBootCanaryError(
          err.code,
          "master-key rotation: boot canary does not open under the new or old root — " +
            "refusing to advance (canary would brick vault-unlock under the new key)",
        );
      }
      throw err;
    } finally {
      if (opened !== null) {
        opened.fill(0);
        opened = null;
      }
    }
  } else if (opened !== null) {
    opened.fill(0);
    opened = null;
  }

  if (openedUnder === "new") {
    // Already under writer — no reseal (push/TOTP carry-through).
    return {
      result: { rowsBefore: 1, rowsAfter: 1, rewrapped: 1 },
      rewrappedEnvelope: input.envelope,
    };
  }

  const resealed = sealVaultBootCanary(input.newRootKey, input.nodeId);
  if (resealed === input.envelope) {
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_MALFORMED",
      "master-key rotation: boot canary reseal produced an identical envelope",
    );
  }

  let roundTrip: Buffer;
  try {
    roundTrip = openVaultBootCanary(input.newRootKey, input.nodeId, resealed);
  } catch (err) {
    if (err instanceof VaultBootCanaryError) throw err;
    throw new VaultBootCanaryError(
      "VAULT_BOOT_CANARY_DOES_NOT_OPEN",
      "master-key rotation: rewrapped boot canary does not open under the new root",
    );
  }
  try {
    assertCanaryPlaintext(roundTrip, "under the new root after reseal");
  } finally {
    roundTrip.fill(0);
  }

  return {
    result: { rowsBefore: 1, rowsAfter: 1, rewrapped: 1 },
    rewrappedEnvelope: resealed,
  };
}

