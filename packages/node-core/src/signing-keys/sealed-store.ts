// NODE_SIGNING_KEYS seal/open — AES-256-GCM envelopes for node identity / event-signing
// Ed25519 seeds (32 bytes). Shares boot root (PBKDF2 of VAULT_MASTER_KEY) with the wallet
// vault under a store-unique HKDF label (cross-store domain separation; sealed-store rewrap census).
//
// Governing: items 4–5;
// wallet-vault AAD and HKDF-info. Never logs seed or private key material.

import {
  createCipheriv,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  randomBytes,
} from "node:crypto";

import {
  AUTH_TAG_LENGTH_BYTES,
  DEK_LENGTH_BYTES,
  ED25519_SEED_BYTES,
  NONCE_LENGTH_BYTES,
  VaultOpenError,
  VaultSealError,
  gcmCrypto,
  keyMaterialHygiene,
  type SecureBuffer,
  type VaultOpenFailureCode,
} from "../vault/envelope.js";
import { sha256Hex, toBase64UrlPadded } from "../vault/serialization.js";
import type { NodeSigningKeyPurpose } from "./registry-store.js";
import { assertExactPurpose } from "./registry-store.js";

/** Frozen wallet-vault AAD and HKDF-info cross-store HKDF domain label for NODE_SIGNING_KEYS. */
export const NODE_SIGNING_DEK_HKDF_LABEL = "zp-node-signing-dek-v1" as const;

/** AAD domain label — wire/format epoch; format bumps take a new vN label, never silent append. */
export const NODE_SIGNING_SECRET_AAD_DOMAIN = "zp-node-signing-secret-v1" as const;

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const CANONICAL_PUBLIC_KEY = /^[A-Za-z0-9_-]{43}=$/;

export interface NodeSigningKeyIdentity {
  readonly nodeId: string;
  readonly purpose: NodeSigningKeyPurpose;
  readonly publicKey: string;
  readonly keyVersion: number;
}

export interface NodeSigningKeySealedEnvelope {
  readonly vaultSecretRef: string;
  readonly keyVersion: number;
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly authTag: Uint8Array;
  readonly ciphertextSha256: string;
}

export type {
  SecureBuffer,
  VaultOpenFailureCode,
};

export function buildNodeSigningDekInfo(identity: {
  readonly nodeId: string;
  readonly purpose: string;
  readonly publicKey: string;
  readonly keyVersion: number;
}): string {
  return [
    NODE_SIGNING_DEK_HKDF_LABEL,
    identity.nodeId,
    identity.purpose,
    identity.publicKey,
    String(identity.keyVersion),
  ].join("\n");
}

export function buildNodeSigningSecretAad(identity: NodeSigningKeyIdentity): string {
  return [
    NODE_SIGNING_SECRET_AAD_DOMAIN,
    identity.nodeId,
    identity.purpose,
    identity.publicKey,
    String(identity.keyVersion),
  ].join("\n");
}

function deriveNodeSigningDek(rootKey: Uint8Array, identity: NodeSigningKeyIdentity): Buffer {
  const info = buildNodeSigningDekInfo(identity);
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

/** Derive padded base64url Ed25519 public key from a 32-byte seed. */
export function publicKeyFromEd25519Seed(seed: Uint8Array): string {
  if (seed.length !== ED25519_SEED_BYTES) {
    throw new VaultSealError("ed25519 seed must be 32 bytes");
  }
  const seedOwned = keyMaterialHygiene.adopt(Buffer.from(seed));
  const pkcs8 = keyMaterialHygiene.adopt(Buffer.concat([ED25519_PKCS8_PREFIX, seedOwned]));
  try {
    const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
    const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
    return toBase64UrlPadded(Buffer.from(spki).subarray(-32));
  } finally {
    keyMaterialHygiene.zeroize(seedOwned, "seed");
    keyMaterialHygiene.zeroize(pkcs8, "pkcs8");
  }
}

function assertSealInputs(identity: NodeSigningKeyIdentity, seed: Uint8Array): void {
  assertExactPurpose(identity.purpose);
  if (seed.length !== ED25519_SEED_BYTES) {
    throw new VaultSealError("ed25519 seed must be 32 bytes");
  }
  if (!Number.isInteger(identity.keyVersion) || identity.keyVersion < 1) {
    throw new VaultSealError("keyVersion must be a positive integer");
  }
  if (!CANONICAL_PUBLIC_KEY.test(identity.publicKey)) {
    throw new VaultSealError("publicKey is not canonical padded base64url");
  }
  const derived = publicKeyFromEd25519Seed(seed);
  if (derived !== identity.publicKey) {
    throw new VaultSealError("seed does not match the authoritative public key");
  }
}

/**
 * Seal a 32-byte Ed25519 seed under a fresh CSPRNG nonce. AAD binds node_id + purpose +
 * public_key + key_version so a purpose/public-key smuggle fails at open. Never logs seed.
 */
export function sealNodeSigningSeed(
  rootKey: Uint8Array,
  identity: NodeSigningKeyIdentity,
  seed: Uint8Array,
  vaultSecretRef: string,
): NodeSigningKeySealedEnvelope {
  assertSealInputs(identity, seed);
  const dek = deriveNodeSigningDek(rootKey, identity);
  const plaintext = keyMaterialHygiene.adopt(Buffer.from(seed));
  try {
    const aad = Buffer.from(buildNodeSigningSecretAad(identity), "utf8");
    const nonce = randomBytes(NONCE_LENGTH_BYTES);
    const cipher = createCipheriv("aes-256-gcm", dek, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
      vaultSecretRef,
      keyVersion: identity.keyVersion,
      ciphertext,
      nonce,
      authTag,
      ciphertextSha256: sha256Hex(ciphertext),
    };
  } finally {
    keyMaterialHygiene.zeroize(dek, "dek");
    keyMaterialHygiene.zeroize(plaintext, "seal_plaintext");
  }
}

/**
 * Open a sealed seed envelope. Fails closed on length/tag/AAD/pubkey mismatch.
 * Returns a SecureBuffer — caller must wipe after signing.
 */
export function openNodeSigningSeed(
  rootKey: Uint8Array,
  envelope: NodeSigningKeySealedEnvelope,
  authoritative: NodeSigningKeyIdentity,
): SecureBuffer {
  assertExactPurpose(authoritative.purpose);
  if (
    envelope.ciphertext.length !== ED25519_SEED_BYTES ||
    envelope.nonce.length !== NONCE_LENGTH_BYTES ||
    envelope.authTag.length !== AUTH_TAG_LENGTH_BYTES
  ) {
    throw new VaultOpenError("LENGTH_MISMATCH", "envelope field length mismatch");
  }
  if (!CANONICAL_PUBLIC_KEY.test(authoritative.publicKey)) {
    throw new VaultOpenError("NON_CANONICAL_PUBLIC_KEY", "authoritative public key is not canonical");
  }
  if (envelope.keyVersion !== authoritative.keyVersion) {
    throw new VaultOpenError("LENGTH_MISMATCH", "keyVersion mismatch");
  }

  const dek = deriveNodeSigningDek(rootKey, authoritative);
  const aad = Buffer.from(buildNodeSigningSecretAad(authoritative), "utf8");
  let updateOut: Buffer | undefined;
  let plaintext: Buffer | undefined;
  try {
    try {
      const decipher = gcmCrypto.createDecipheriv("aes-256-gcm", dek, envelope.nonce);
      decipher.setAAD(aad);
      decipher.setAuthTag(Buffer.from(envelope.authTag));
      updateOut = decipher.update(Buffer.from(envelope.ciphertext));
      const finalOut = decipher.final();
      plaintext = keyMaterialHygiene.adopt(Buffer.concat([updateOut, finalOut]));
      keyMaterialHygiene.zeroize(updateOut, "gcm_update");
      updateOut = undefined;
    } catch {
      throw new VaultOpenError("AUTH_TAG_FAILURE", "envelope authentication failed");
    }

    if (plaintext.length !== ED25519_SEED_BYTES) {
      throw new VaultOpenError("LENGTH_MISMATCH", "decrypted seed length mismatch");
    }

    const derived = publicKeyFromEd25519Seed(plaintext);
    if (derived !== authoritative.publicKey) {
      throw new VaultOpenError("PUBLIC_KEY_MISMATCH", "decrypted seed does not match the public key");
    }

    const released = plaintext;
    plaintext = undefined;
    return {
      bytes: released,
      wipe: () => keyMaterialHygiene.zeroize(released, "secure_buffer"),
    };
  } catch (err) {
    if (plaintext) keyMaterialHygiene.zeroize(plaintext, "failure_plaintext");
    throw err;
  } finally {
    if (updateOut) keyMaterialHygiene.zeroize(updateOut, "gcm_update");
    keyMaterialHygiene.zeroize(dek, "dek");
  }
}

/** Mint a fresh CSPRNG 32-byte Ed25519 seed (caller owns wipe). */
export function generateEd25519Seed(): Buffer {
  return randomBytes(ED25519_SEED_BYTES);
}
