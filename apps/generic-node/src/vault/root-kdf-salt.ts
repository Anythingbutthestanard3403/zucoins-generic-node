// The single source of truth for the vault root-KDF salt (ZTR-1159).
//
// Before this module the salt existed four ways: an identical string literal copy-pasted into
// main.ts, ops/run-recovery-ceremony.ts and ops/admin-recovery-ceremony.ts, plus an
// unvalidated `VAULT_ROOT_SALT_B64` read straight from process.env by
// operations/rotate-master-key.cli.ts. Rotation under a salt the other three paths could not
// reproduce sealed every envelope against a root key that boot and both recovery ceremonies
// derive differently — a key-loss trap that only surfaces at the next boot, or at the
// ceremony that is the last thing standing between the operator and total loss.
//
// The salt is not secret. It must be *correct*, and it must be the same value on every path
// that derives the root key. That is what this module exists to guarantee:
//
//   resolveConfiguredRootKdfSalt   env `VAULT_ROOT_SALT_B64`, else the historical literal.
//                                  Pure and synchronous — usable before the database exists.
//   reconcileRootKdfSalt           post-migration: bind that resolution to the row persisted
//                                  beside the sealed material, or write the row on first sight.
//   assertRootKeyOpensSealedEnvelope
//                                  derive-and-prove against a real envelope before any
//                                  further step, so a mismatch is a named error in the first
//                                  second rather than a decrypt failure three steps in.
//
// The KDF itself is untouched: `deriveRootKey` (node-core vault/envelope.ts) stays
// PBKDF2-SHA256 at ROOT_KDF_ITERATIONS = 600_000, feeding the same HKDF-SHA256 per-wallet DEK
// and the same AES-256-GCM envelope. This module chooses the salt and nothing else.

import { randomBytes, timingSafeEqual } from "node:crypto";

import {
  deriveEd25519PublicKeyBase64Url,
  openWalletSecret,
  type SealedEnvelope,
  type WalletIdentity,
} from "@zucoins/node-core";

/**
 * The salt every node shipped before ZTR-1159 derived under, hardcoded at three composition
 * roots. This is the only production occurrence of the literal, and it must never change:
 * every envelope sealed by every deployment to date opens only under this value.
 *
 * `zupayments` is one unbroken token and is deliberately not a forbidden-terms violation
 * (scan/forbidden-terms.ts, the compatibility-literal preservation rule).
 *
 * NEVER hand this buffer to a caller that wipes its inputs — `resolveConfiguredRootKdfSalt`
 * returns a copy for exactly that reason. The master-key rotation CLI zeroes its salt in a
 * `finally` (operations/rotate-master-key.cli.ts), and zeroing this module-level constant
 * would leave every later derivation in the process running on 33 zero bytes.
 */
export const HISTORICAL_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");

/** Matches the floor the rotation CLI has always enforced on operator-supplied salts. */
export const MIN_ROOT_KDF_SALT_BYTES = 8;

/** Width of a salt minted at genesis: full CSPRNG output, one per deployment. */
export const GENESIS_ROOT_KDF_SALT_BYTES = 32;

/** Where the authoritative salt came from. Persisted verbatim so provenance survives a restart. */
export type RootKdfSaltSource =
  /** Operator-supplied `VAULT_ROOT_SALT_B64`. */
  | "environment"
  /** No configuration and sealed material already present — the pre-ZTR-1159 literal. */
  | "historical_default"
  /** Minted at genesis on a node that had sealed nothing yet. */
  | "genesis_random";

export interface ResolvedRootKdfSalt {
  readonly salt: Buffer;
  readonly source: RootKdfSaltSource;
}

export type VaultRootSaltErrorCode =
  /** `VAULT_ROOT_SALT_B64` is present but not decodable to a usable salt. */
  | "VAULT_ROOT_SALT_MALFORMED"
  /** The configured salt disagrees with the one persisted beside the sealed material. */
  | "VAULT_ROOT_SALT_MISMATCH"
  /** The derived root key does not open an envelope this node already sealed. */
  | "VAULT_ROOT_KEY_DOES_NOT_OPEN";

/**
 * The named, early failure the acceptance criteria require. Every path that derives a root key
 * throws this rather than letting a wrong salt surface later as a generic decrypt failure.
 * Carries no key material and no salt bytes — only the provenance labels.
 */
export class VaultRootSaltError extends Error {
  readonly code: VaultRootSaltErrorCode;

  constructor(code: VaultRootSaltErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = "VaultRootSaltError";
    this.code = code;
  }
}

/** Byte comparison that does not leak a prefix length through timing. */
function saltsEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Decode `VAULT_ROOT_SALT_B64`. Accepts standard and URL-safe base64, exactly as the rotation
 * CLI always has, so an operator who already recorded a salt keeps the encoding they wrote down.
 * The message names the field and the constraint, never the rejected value.
 */
export function decodeRootKdfSaltB64(raw: string): Buffer {
  const normalized = raw.trim().replace(/-/g, "+").replace(/_/g, "/");
  if (normalized.length === 0) {
    throw new VaultRootSaltError("VAULT_ROOT_SALT_MALFORMED", "VAULT_ROOT_SALT_B64 is blank");
  }
  const decoded = Buffer.from(normalized, "base64");
  if (decoded.length < MIN_ROOT_KDF_SALT_BYTES) {
    throw new VaultRootSaltError(
      "VAULT_ROOT_SALT_MALFORMED",
      `VAULT_ROOT_SALT_B64 decodes to fewer than ${MIN_ROOT_KDF_SALT_BYTES} bytes`,
    );
  }
  return decoded;
}

/**
 * The salt as configuration alone knows it. Pure and synchronous: it is the value every path
 * derives under before (and, on an unchanged node, after) the database has a say.
 *
 * Unset falls back to {@link HISTORICAL_ROOT_KDF_SALT} — that fallback is what makes this
 * change deployable. An existing node with no `VAULT_ROOT_SALT_B64` derives byte-identically
 * to what it derived before ZTR-1159.
 *
 * The returned buffer is always a private copy: callers own it and several of them zero it
 * when done, which must never reach the module-level historical constant.
 */
export function resolveConfiguredRootKdfSalt(
  env: { readonly VAULT_ROOT_SALT_B64?: string | undefined },
): ResolvedRootKdfSalt {
  const raw = env.VAULT_ROOT_SALT_B64;
  if (raw === undefined || raw.trim().length === 0) {
    return { salt: Buffer.from(HISTORICAL_ROOT_KDF_SALT), source: "historical_default" };
  }
  return { salt: decodeRootKdfSaltB64(raw), source: "environment" };
}

export interface RootKdfSaltSqlExecutor {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

/** pg hands bytea back as Buffer; the string branches cover a driver configured otherwise. */
function toBytes(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === "string") {
    return value.startsWith("\\x")
      ? Buffer.from(value.slice(2), "hex")
      : Buffer.from(value, "base64");
  }
  throw new VaultRootSaltError(
    "VAULT_ROOT_SALT_MALFORMED",
    "persisted vault_root_kdf_salt.salt is not bytes",
  );
}

function isSaltSource(value: unknown): value is RootKdfSaltSource {
  return value === "environment" || value === "historical_default" || value === "genesis_random";
}

/** Read the persisted salt for a node. Never writes. Returns null when the node has no row. */
export async function loadPersistedRootKdfSalt(
  sql: RootKdfSaltSqlExecutor,
  nodeId: string,
): Promise<ResolvedRootKdfSalt | null> {
  const { rows } = await sql.query<{ salt: unknown; source: unknown }>(
    `SELECT salt, source FROM vault_root_kdf_salt WHERE node_id = $1::uuid LIMIT 1`,
    [nodeId],
  );
  const row = rows[0];
  if (row === undefined) return null;
  const salt = toBytes(row.salt);
  if (salt.length < MIN_ROOT_KDF_SALT_BYTES) {
    throw new VaultRootSaltError(
      "VAULT_ROOT_SALT_MALFORMED",
      `persisted salt for node ${nodeId} is shorter than ${MIN_ROOT_KDF_SALT_BYTES} bytes`,
    );
  }
  return { salt, source: isSaltSource(row.source) ? row.source : "historical_default" };
}

/**
 * True when this node has already sealed something under a root key. Drives the one decision
 * this module cannot make from configuration: whether an absent salt row means "brand new
 * deployment, mint one" or "node that predates ZTR-1159, it has been deriving under the
 * historical literal all along".
 *
 * Both sealed stores count. The push receiver's per-wallet ECDH secret
 * (push/subscription-service.ts) is sealed under the same root key as the wallet envelopes, so
 * a node with push secrets and no wallets is still not a virgin deployment.
 */
async function hasSealedMaterial(sql: RootKdfSaltSqlExecutor, nodeId: string): Promise<boolean> {
  const { rows } = await sql.query<{ present: boolean }>(
    `SELECT EXISTS (
       SELECT 1 FROM vault v INNER JOIN wallets w ON w.id = v.wallet_id WHERE w.node_id = $1::uuid
       UNION ALL
       SELECT 1 FROM node_signing_key_sealed_store s
         INNER JOIN node_signing_keys k ON k.vault_secret_ref = s.vault_secret_ref
        WHERE k.node_id = $1::uuid
     ) AS present`,
    [nodeId],
  );
  return rows[0]?.present === true;
}

export interface RootKdfSaltReconciliation extends ResolvedRootKdfSalt {
  /**
   * True when the authoritative salt is not the one configuration resolved, so the caller must
   * re-derive its root key before using it. Only ever true on a node whose persisted salt was
   * minted at genesis (or written by a prior boot) while `VAULT_ROOT_SALT_B64` stays unset.
   */
  readonly rederive: boolean;
  /** True when this call wrote the row. */
  readonly persisted: boolean;
}

/**
 * Bind the configured salt to the durable one, writing the row the first time this node is
 * seen. Runs after migrations — `vault_root_kdf_salt` is a money-pack slice.
 *
 * The row is insert-only (the slice carries UPDATE/DELETE/TRUNCATE guards), so once written it
 * is the node's answer forever. A configured salt that disagrees with it is refused here, which
 * is the whole point: the mismatch is reported before anything tries to open an envelope.
 */
export async function reconcileRootKdfSalt(deps: {
  readonly sql: RootKdfSaltSqlExecutor;
  readonly nodeId: string;
  readonly configured: ResolvedRootKdfSalt;
  readonly randomSalt?: () => Buffer;
}): Promise<RootKdfSaltReconciliation> {
  const persisted = await loadPersistedRootKdfSalt(deps.sql, deps.nodeId);

  if (persisted !== null) {
    if (deps.configured.source === "environment" && !saltsEqual(persisted.salt, deps.configured.salt)) {
      throw new VaultRootSaltError(
        "VAULT_ROOT_SALT_MISMATCH",
        `VAULT_ROOT_SALT_B64 does not match the salt persisted for node ${deps.nodeId} ` +
          `(persisted source=${persisted.source}). The persisted value is the one this node's ` +
          `envelopes were sealed under; unset VAULT_ROOT_SALT_B64 or restore the recorded salt.`,
      );
    }
    return {
      ...persisted,
      rederive: !saltsEqual(persisted.salt, deps.configured.salt),
      persisted: false,
    };
  }

  // No row yet. Configuration wins when the operator supplied one; otherwise the node's own
  // history decides, and only a node that has sealed nothing may be given a fresh salt.
  const chosen: ResolvedRootKdfSalt =
    deps.configured.source === "environment"
      ? deps.configured
      : (await hasSealedMaterial(deps.sql, deps.nodeId))
        ? { salt: Buffer.from(HISTORICAL_ROOT_KDF_SALT), source: "historical_default" }
        : {
            salt: (deps.randomSalt ?? (() => randomBytes(GENESIS_ROOT_KDF_SALT_BYTES)))(),
            source: "genesis_random",
          };

  // ON CONFLICT DO NOTHING, then re-read: two replicas racing first boot must converge on one
  // salt rather than one of them proceeding under a value the insert did not keep.
  await deps.sql.query(
    `INSERT INTO vault_root_kdf_salt (node_id, salt, source)
     VALUES ($1::uuid, $2, $3)
     ON CONFLICT (node_id) DO NOTHING`,
    [deps.nodeId, chosen.salt, chosen.source],
  );
  const durable = await loadPersistedRootKdfSalt(deps.sql, deps.nodeId);
  if (durable === null) {
    throw new VaultRootSaltError(
      "VAULT_ROOT_SALT_MISMATCH",
      `vault_root_kdf_salt row for node ${deps.nodeId} vanished immediately after insert`,
    );
  }
  if (deps.configured.source === "environment" && !saltsEqual(durable.salt, deps.configured.salt)) {
    throw new VaultRootSaltError(
      "VAULT_ROOT_SALT_MISMATCH",
      `VAULT_ROOT_SALT_B64 lost the first-boot race for node ${deps.nodeId} ` +
        `(persisted source=${durable.source}); another process persisted a different salt.`,
    );
  }
  return {
    ...durable,
    rederive: !saltsEqual(durable.salt, deps.configured.salt),
    persisted: true,
  };
}

/**
 * The salt a recovery ceremony must derive under. Identical to {@link reconcileRootKdfSalt}
 * except that it never writes: a ceremony reads what the node already decided, and a node with
 * no persisted row is one that predates ZTR-1159 and has been deriving under the historical
 * literal. Minting a salt mid-ceremony could only ever produce a key that opens nothing.
 */
export async function resolveCeremonyRootKdfSalt(deps: {
  readonly sql: RootKdfSaltSqlExecutor;
  readonly nodeId: string;
  readonly env: { readonly VAULT_ROOT_SALT_B64?: string | undefined };
}): Promise<ResolvedRootKdfSalt> {
  const configured = resolveConfiguredRootKdfSalt(deps.env);
  const persisted = await loadPersistedRootKdfSalt(deps.sql, deps.nodeId);
  if (persisted === null) return configured;
  if (configured.source === "environment" && !saltsEqual(persisted.salt, configured.salt)) {
    throw new VaultRootSaltError(
      "VAULT_ROOT_SALT_MISMATCH",
      `VAULT_ROOT_SALT_B64 does not match the salt persisted for node ${deps.nodeId} ` +
        `(persisted source=${persisted.source}). The persisted value is the one this node's ` +
        `envelopes were sealed under; unset VAULT_ROOT_SALT_B64 or restore the recorded salt.`,
    );
  }
  return persisted;
}

export interface RootKeySelfCheckResult {
  /** False when the node has sealed nothing yet — there was no envelope to prove against. */
  readonly checked: boolean;
  readonly walletId?: string;
  readonly saltSource: RootKdfSaltSource;
}

const SELECT_ONE_SEALED_WALLET = `
  SELECT w.id, w.node_id, w.public_key, w.key_origin,
         v.key_version, v.ciphertext, v.nonce, v.auth_tag, v.ciphertext_sha256
    FROM wallets w
    INNER JOIN vault v ON v.wallet_id = w.id
   WHERE w.node_id = $1::uuid
     AND w.key_origin = 'node_generated'
   ORDER BY w.id ASC -- contract-allow:order:frozen structural vocabulary
   LIMIT 1
`;

/**
 * Prove the derived root key opens something this node actually sealed, before any caller does
 * real work with it. This is the check that turns a salt mismatch from a mid-ceremony
 * catastrophe into a named refusal in the first second.
 *
 * A node with no sealed wallet returns `checked: false` rather than throwing — there is nothing
 * to disagree with yet, and a fresh deployment must still boot.
 */
export async function assertRootKeyOpensSealedEnvelope(deps: {
  readonly sql: RootKdfSaltSqlExecutor;
  readonly nodeId: string;
  readonly rootKey: Uint8Array;
  readonly saltSource: RootKdfSaltSource;
}): Promise<RootKeySelfCheckResult> {
  const { rows } = await deps.sql.query<{
    id: string;
    node_id: string;
    public_key: string;
    key_origin: string;
    key_version: number | string;
    ciphertext: unknown;
    nonce: unknown;
    auth_tag: unknown;
    ciphertext_sha256: string;
  }>(SELECT_ONE_SEALED_WALLET, [deps.nodeId]);

  const row = rows[0];
  if (row === undefined) return { checked: false, saltSource: deps.saltSource };

  const keyVersion = Number(row.key_version);
  const identity: WalletIdentity = {
    nodeId: row.node_id,
    walletId: row.id,
    keyVersion,
    publicKey: row.public_key,
    keyOrigin: row.key_origin,
  };
  const envelope: SealedEnvelope = {
    walletId: row.id,
    keyVersion,
    ciphertext: toBytes(row.ciphertext),
    nonce: toBytes(row.nonce),
    authTag: toBytes(row.auth_tag),
    ciphertextSha256: row.ciphertext_sha256,
  };

  try {
    const secret = openWalletSecret(deps.rootKey, envelope, identity);
    try {
      if (deriveEd25519PublicKeyBase64Url(secret.bytes) !== row.public_key) {
        throw new Error("opened secret does not derive the wallet's authoritative public key");
      }
    } finally {
      secret.wipe();
    }
  } catch (err) {
    throw new VaultRootSaltError(
      "VAULT_ROOT_KEY_DOES_NOT_OPEN",
      `the root key derived under salt source=${deps.saltSource} does not open the envelope ` +
        `already sealed for wallet ${row.id}. The master key or the salt is not the one this ` +
        `node sealed under — do not proceed. (${err instanceof Error ? err.message : String(err)})`,
    );
  }

  return { checked: true, walletId: row.id, saltSource: deps.saltSource };
}
