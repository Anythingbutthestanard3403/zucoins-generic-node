// Build a zp-node-backup-v1 archive from the LIVE node SQL + operator master key.
// Wallet export proofs are signed by opening each vault envelope (real possession).
// NODE_IDENTITY signs from the sealed-store seed (never a placeholder digest / env-only path).
// Never prints private keys (the key-custody rule).

import { createPrivateKey, randomUUID, sign as edSign } from "node:crypto";

import {
  buildBackupArchive,
  deriveEd25519PublicKeyBase64Url,
  openNodeSigningSeed,
  openWalletSecret,
  toBase64UrlPadded,
  type BackupArchive,
  type BackupEvidenceRow,
  type BackupSnapshot,
  type BackupWalletInput,
  type NodeSigningKeyIdentity,
  type NodeSigningKeySealedEnvelope,
  type SealedEnvelope,
  type WalletIdentity,
} from "@zucoins/node-core";

type BackupVaultRow = BackupWalletInput["vault"];

import { parseNodeIdentitySeed } from "../bootstrap/genesis.js";
import { publicKeyFromSeed, signWithSecret64 } from "./ed25519-ops.js";

export interface SqlExecutor {
  query<R>(text: string, params?: readonly unknown[]): Promise<{ rows: R[] }>;
}

export interface ExportLiveBackupArchiveInput {
  readonly sql: SqlExecutor;
  readonly rootKey: Uint8Array;
  readonly nodeId: string;
  /**
   * Optional 32-byte seed — if provided, must match the active sealed NODE_IDENTITY
   * public key (verify-only). Signing always opens the sealed store.
   */
  readonly identitySeed?: Uint8Array;
  readonly exportId?: string;
  readonly exportedAt?: string;
}

export interface ExportLiveBackupArchiveResult {
  readonly archiveText: string;
  readonly archive: BackupArchive;
  readonly walletCount: number;
  readonly exportId: string;
}

function canonicalTs(value: Date | string): string {
  const d = typeof value === "string" ? new Date(value) : value;
  if (Number.isNaN(d.getTime())) throw new Error("invalid timestamp");
  return d.toISOString();
}

function asBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Buffer.isBuffer(value)) return new Uint8Array(value);
  if (typeof value === "string") {
    if (value.startsWith("\\x")) return new Uint8Array(Buffer.from(value.slice(2), "hex"));
    return new Uint8Array(Buffer.from(value, "base64"));
  }
  throw new Error("vault byte column is not bytes");
}

interface LiveWalletJoinRow {
  readonly id: string;
  readonly node_id: string;
  readonly public_key: string;
  readonly key_origin: string;
  readonly key_version: number | string;
  readonly ciphertext: unknown;
  readonly nonce: unknown;
  readonly auth_tag: unknown;
  readonly ciphertext_sha256: string;
  readonly created_at: Date | string;
  readonly rotated_at: Date | string | null;
}

interface LiveNodeSigningJoinRow {
  readonly id: string;
  readonly purpose: string;
  readonly public_key: string;
  readonly vault_secret_ref: string;
  readonly key_version: number | string;
  readonly ciphertext: unknown;
  readonly nonce: unknown;
  readonly auth_tag: unknown;
  readonly ciphertext_sha256: string;
}

const SELECT_WALLETS_VAULT = `
  SELECT w.id, w.node_id, w.public_key, w.key_origin,
         v.key_version, v.ciphertext, v.nonce, v.auth_tag,
         v.ciphertext_sha256, v.created_at, v.rotated_at
    FROM wallets w
    INNER JOIN vault v ON v.wallet_id = w.id
   WHERE w.node_id = $1::uuid
     AND w.key_origin = 'node_generated'
`;

const SELECT_NODE_SIGNING_SEALED = `
  SELECT k.id, k.purpose, k.public_key, k.vault_secret_ref,
         s.key_version, s.ciphertext, s.nonce, s.auth_tag, s.ciphertext_sha256
    FROM node_signing_keys k
    INNER JOIN node_signing_key_sealed_store s
      ON s.vault_secret_ref = k.vault_secret_ref
   WHERE k.node_id = $1::uuid
     AND k.retired_at IS NULL
     AND k.activated_at <= now()
   ORDER BY k.purpose ASC, k.activated_at ASC, k.id ASC -- contract-allow:order:frozen structural vocabulary
`;

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function signWithOpenedSeed(seed: Uint8Array, preimageBytes: Uint8Array): Uint8Array {
  const seedBuf = Buffer.from(seed);
  try {
    const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, seedBuf]);
    try {
      const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
      return edSign(null, preimageBytes, privateKey);
    } finally {
      pkcs8.fill(0);
    }
  } finally {
    seedBuf.fill(0);
  }
}

export async function exportLiveBackupArchive(
  input: ExportLiveBackupArchiveInput,
): Promise<ExportLiveBackupArchiveResult> {
  const exportId = input.exportId ?? randomUUID();
  const exportedAt = input.exportedAt ?? new Date().toISOString();

  const { rows } = await input.sql.query<LiveWalletJoinRow>(SELECT_WALLETS_VAULT, [input.nodeId]);
  if (rows.length === 0) {
    throw new Error("no node_generated wallets with vault rows for this node");
  }

  const { rows: signingRows } = await input.sql.query<LiveNodeSigningJoinRow>(
    SELECT_NODE_SIGNING_SEALED,
    [input.nodeId],
  );
  const identityRow = signingRows.find((r) => r.purpose === "NODE_IDENTITY");
  if (identityRow === undefined) {
    throw new Error(
      "no active sealed NODE_IDENTITY row — refuse backup with placeholder identity (run ensureActiveNodeSigningKey first)",
    );
  }

  const identityKeyVersion = Number(identityRow.key_version);
  const identityEnvelope: NodeSigningKeySealedEnvelope = {
    vaultSecretRef: identityRow.vault_secret_ref,
    keyVersion: identityKeyVersion,
    ciphertext: asBytes(identityRow.ciphertext),
    nonce: asBytes(identityRow.nonce),
    authTag: asBytes(identityRow.auth_tag),
    ciphertextSha256: identityRow.ciphertext_sha256,
  };
  const identityMeta: NodeSigningKeyIdentity = {
    nodeId: input.nodeId,
    purpose: "NODE_IDENTITY",
    publicKey: identityRow.public_key,
    keyVersion: identityKeyVersion,
  };

  // Open once to prove the envelope under root and (optionally) match override seed.
  const identityOpened = openNodeSigningSeed(input.rootKey, identityEnvelope, identityMeta);
  let identitySeedHeld: Buffer;
  try {
    identitySeedHeld = Buffer.from(identityOpened.bytes);
  } finally {
    identityOpened.wipe();
  }

  if (input.identitySeed !== undefined) {
    if (input.identitySeed.length !== 32) {
      identitySeedHeld.fill(0);
      throw new Error("identitySeed must be exactly 32 bytes when provided");
    }
    const seedPub = publicKeyFromSeed(input.identitySeed);
    if (seedPub !== identityRow.public_key) {
      identitySeedHeld.fill(0);
      throw new Error("identitySeed does not match active sealed NODE_IDENTITY public key");
    }
  }

  const heldSecrets: Buffer[] = [identitySeedHeld];
  const wallets: BackupWalletInput[] = [];
  const walletEvidence: BackupEvidenceRow[] = [];

  try {
    for (const row of rows) {
      const keyVersion = Number(row.key_version);
      const ciphertext = asBytes(row.ciphertext);
      const nonce = asBytes(row.nonce);
      const authTag = asBytes(row.auth_tag);
      const vaultRow: BackupVaultRow = {
        wallet_id: row.id,
        key_version: keyVersion,
        ciphertext: toBase64UrlPadded(ciphertext),
        nonce: toBase64UrlPadded(nonce),
        auth_tag: toBase64UrlPadded(authTag),
        ciphertext_sha256: row.ciphertext_sha256,
        created_at: canonicalTs(row.created_at),
        rotated_at: row.rotated_at === null ? null : canonicalTs(row.rotated_at),
      };

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
        ciphertext,
        nonce,
        authTag,
        ciphertextSha256: row.ciphertext_sha256,
      };

      let held: Buffer;
      try {
        const secret = openWalletSecret(input.rootKey, envelope, identity);
        try {
          const derived = deriveEd25519PublicKeyBase64Url(secret.bytes);
          if (derived !== row.public_key) {
            throw new Error(`public key census failed for wallet ${row.id}`);
          }
          held = Buffer.from(secret.bytes);
        } finally {
          secret.wipe();
        }
      } catch (err) {
        throw new Error(
          `vault open failed for wallet ${row.id}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      heldSecrets.push(held);

      wallets.push({
        walletId: row.id,
        publicKey: row.public_key,
        keyOrigin: row.key_origin,
        keyVersion,
        vault: vaultRow,
        signer: {
          sign: (preimageBytes: Uint8Array) => signWithSecret64(held, preimageBytes),
        },
      });

      walletEvidence.push({
        id: row.id,
        wallet_id: row.id,
        public_key: row.public_key,
        key_origin: row.key_origin,
        key_version: keyVersion,
      });
    }

    const nodeSigningKeys = signingRows.map((r) => ({
      signingKeyId: r.id,
      purpose: r.purpose,
      publicKey: r.public_key,
      vaultSecretRef: r.vault_secret_ref,
      sealedCiphertextSha256: r.ciphertext_sha256,
    }));

    const snapshot: BackupSnapshot = {
      nodeId: input.nodeId,
      exportId,
      exportedAt,
      wallets,
      nodeSigningKeys,
      evidenceTables: [
        {
          table: "wallets",
          primaryKey: [{ column: "id", kind: "uuid" }],
          rows: walletEvidence,
        },
      ],
      settingsValues: { source: "run-recovery-ceremony-live-export" },
      identitySigner: {
        sign: (preimageBytes: Uint8Array) => signWithOpenedSeed(identitySeedHeld, preimageBytes),
      },
    };

    const { archiveJson, archive } = buildBackupArchive(snapshot);
    return {
      archiveText: archiveJson,
      archive,
      walletCount: wallets.length,
      exportId,
    };
  } finally {
    for (const secret of heldSecrets) secret.fill(0);
  }
}

/**
 * @deprecated Prefer sealed-store-backed export (identitySeed optional verify-only).
 * Retained for recovery ceremony env wiring; backup refuses without an openable sealed row.
 */
export function resolveIdentitySeedFromEnv(
  env: { readonly NODE_IDENTITY_SEED?: string } = process.env,
): Uint8Array {
  const raw = env.NODE_IDENTITY_SEED?.trim();
  if (raw === undefined || raw === "") {
    throw new Error(
      "NODE_IDENTITY_SEED is optional for sealed-store backup; set only to verify public key match",
    );
  }
  const seed = parseNodeIdentitySeed(raw);
  if (seed === null) {
    throw new Error("NODE_IDENTITY_SEED must be ≥32 bytes as hex or base64/base64url");
  }
  return seed;
}
