/**
 * SOURCE: the wallet-vault envelope freeze guard 1 (per-wallet AES-256-GCM seal under DEK_wallet, fresh
 * 96-bit CSPRNG nonce, 128-bit tag, sealed material = 64-byte Ed25519 secret) and guard 2 (the
 * six-field AAD reconstructed at open); the signing-custody-security spec the vault-envelope rules (envelope), the DEK-derivation rule
 * (archive carries verbatim vault rows, no new ciphertext); the data model wallet/vault schema (table `vault`).
 *
 * This is a drill-grade reproduction of the frozen vault envelope for the recovery-drill lane destroy-restore
 * and corrupt-recovery proofs: it seals and opens the SAME bytes the live vault would, so the
 * wrong-key / corrupt-ciphertext / mismatched-AAD drills exercise real GCM authentication failures
 * (not mocks). It introduces NO new KDF and NO new ciphertext class — the DEK comes from
 * `deriveWalletDek` (the wallet-DEK HKDF rule) and the AAD from the frozen the vault schema freeze `buildWalletSecretAad`.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

import { buildWalletSecretAad, type WalletSecretAadInputs } from "../vault/aad-serialization.ts";

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
export const WALLET_SECRET_BYTES = 64;

export interface SealedEnvelope {
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly authTag: Uint8Array;
  readonly ciphertextSha256: string;
}

const sha256Hex = (bytes: Uint8Array): string =>
  createHash("sha256").update(Buffer.from(bytes)).digest("hex");

/** Seal a 64-byte Ed25519 secret under `dek` with the six-field AAD and a fresh 96-bit nonce. */
export const sealWalletSecret = (
  dek: Uint8Array,
  aadInputs: WalletSecretAadInputs,
  secret64: Uint8Array,
  nonce: Uint8Array = new Uint8Array(randomBytes(NONCE_BYTES)),
): SealedEnvelope => {
  if (secret64.length !== WALLET_SECRET_BYTES) {
    throw new Error(`vault seal: secret must be ${WALLET_SECRET_BYTES} bytes, got ${secret64.length}`);
  }
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`vault seal: nonce must be ${NONCE_BYTES} bytes, got ${nonce.length}`);
  }
  const aad = new TextEncoder().encode(buildWalletSecretAad(aadInputs));
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(dek), Buffer.from(nonce), {
    authTagLength: TAG_BYTES,
  });
  cipher.setAAD(Buffer.from(aad));
  const ciphertext = new Uint8Array(Buffer.concat([cipher.update(Buffer.from(secret64)), cipher.final()]));
  const authTag = new Uint8Array(cipher.getAuthTag());
  return { ciphertext, nonce, authTag, ciphertextSha256: sha256Hex(ciphertext) };
};

/**
 * Open a sealed envelope, reconstructing the AAD from the authoritative inputs (never a stored
 * column). Any GCM tag failure, AAD mismatch, or wrong DEK throws — this is the fail-closed
 * primitive every wrong-key / corrupt-ciphertext / mismatched-AAD drill asserts against. The
 * caller performs the decrypt -> derive-pubkey -> match `wallets.public_key` step (the vault-envelope rules primary
 * substitution control) on the returned bytes.
 */
export const openWalletSecret = (
  dek: Uint8Array,
  aadInputs: WalletSecretAadInputs,
  envelope: Pick<SealedEnvelope, "ciphertext" | "nonce" | "authTag">,
): Uint8Array => {
  if (envelope.nonce.length !== NONCE_BYTES) {
    throw new Error(`vault open: nonce must be ${NONCE_BYTES} bytes, got ${envelope.nonce.length}`);
  }
  if (envelope.authTag.length !== TAG_BYTES) {
    throw new Error(`vault open: auth tag must be ${TAG_BYTES} bytes, got ${envelope.authTag.length}`);
  }
  const aad = new TextEncoder().encode(buildWalletSecretAad(aadInputs));
  const decipher = createDecipheriv("aes-256-gcm", Buffer.from(dek), Buffer.from(envelope.nonce), {
    authTagLength: TAG_BYTES,
  });
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(envelope.authTag));
  try {
    const plain = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext)), decipher.final()]);
    return new Uint8Array(plain);
  } catch {
    throw new Error("vault open: GCM authentication failed (wrong key, AAD, or corrupt ciphertext)");
  }
};

export const VAULT_ENVELOPE_CONTRACT = {
  algorithm: "AES-256-GCM",
  nonce_bytes: NONCE_BYTES,
  tag_bytes: TAG_BYTES,
  sealed_material_bytes: WALLET_SECRET_BYTES,
  aad: "six-field, reconstructed at open (the vault concern buildWalletSecretAad), never stored",
  new_ciphertext_class_introduced: false,
} as const;
