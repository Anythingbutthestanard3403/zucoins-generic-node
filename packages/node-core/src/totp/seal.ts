// At-rest sealing for RFC 6238 TOTP shared secrets (TOTP_SECRET sealed store).
//
// Follows packages/node-core/src/push/seal.ts: AES-256-GCM under a store-unique
// HKDF-SHA256 DEK derived from the vault root. Cipher, label and AAD shape are
// frozen in sealed-store-registry.contract.ts (TOTP_SECRET):
//   hkdfLabel: "zupayments/totp-secret/v1"
//   aad:       admin-row id (binds ciphertext to its admin_operators row)
//
// Never logs secret material. Caller owns rootKey lifetime; DEK is zeroized in finally.

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

import { DEK_LENGTH_BYTES, keyMaterialHygiene } from "../vault/envelope.js";

const NONCE_BYTES = 12;
const TAG_BYTES = 16;

/** Envelope version prefix — layout bumps take a new vN, never silent append. */
export const TOTP_SECRET_ENVELOPE_PREFIX = "zp-totp-seal-v1" as const;

/**
 * Frozen cross-store HKDF domain label for TOTP_SECRET.
 * Byte-exact with sealed-store-registry.contract.ts and the independent census token.
 */
export const TOTP_SECRET_HKDF_LABEL = "zupayments/totp-secret/v1" as const;

export class TotpSealError extends Error {
  readonly code = "TOTP_SEAL_FAILED";
  constructor(message: string) {
    super(message);
    this.name = "TotpSealError";
  }
}

export class TotpOpenError extends Error {
  readonly code = "TOTP_OPEN_FAILED";
  constructor(message: string) {
    super(message);
    this.name = "TotpOpenError";
  }
}

/** Exact UTF-8 HKDF info text. Byte contract — never reformat. */
export function buildTotpSecretDekInfo(): string {
  return TOTP_SECRET_HKDF_LABEL;
}

/**
 * GCM AAD = admin operator row id. Reconstructed at open; never stored.
 * Wrong id → AUTH_TAG failure (fail closed).
 */
export function buildTotpSecretAad(adminOperatorId: string): string {
  return adminOperatorId;
}

function deriveTotpSecretDek(rootKey: Uint8Array): Buffer {
  const info = buildTotpSecretDekInfo();
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

function assertRootKey(rootKey: Uint8Array): void {
  if (rootKey.length !== 32) {
    throw new TotpSealError(`vault root key must be 32 bytes, got ${rootKey.length}`);
  }
}

function assertAdminId(adminOperatorId: string): void {
  if (typeof adminOperatorId !== "string" || adminOperatorId.length === 0) {
    throw new TotpSealError("admin operator id is required for TOTP AAD");
  }
}

/**
 * Seal raw TOTP secret bytes under the vault root with admin-row-id AAD.
 * Returns opaque `zp-totp-seal-v1.<base64(nonce||tag||ciphertext)>`.
 */
export function sealTotpSecret(
  rootKey: Uint8Array,
  adminOperatorId: string,
  secret: Uint8Array,
): string {
  assertRootKey(rootKey);
  assertAdminId(adminOperatorId);
  if (secret.length < 10) {
    throw new TotpSealError("TOTP secret must be at least 10 bytes");
  }
  const aad = Buffer.from(buildTotpSecretAad(adminOperatorId), "utf8");
  const nonce = randomBytes(NONCE_BYTES);
  const dek = deriveTotpSecretDek(rootKey);
  const plaintext = keyMaterialHygiene.adopt(Buffer.from(secret));
  try {
    const cipher = createCipheriv("aes-256-gcm", dek, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${TOTP_SECRET_ENVELOPE_PREFIX}.${Buffer.concat([nonce, tag, ciphertext]).toString("base64")}`;
  } finally {
    keyMaterialHygiene.zeroize(dek, "dek");
    keyMaterialHygiene.zeroize(plaintext, "seal_plaintext");
  }
}

/**
 * Open a sealed TOTP envelope. Wrong admin id / root / tamper → TotpOpenError.
 * Returns a fresh Buffer the caller must wipe after use.
 */
export function openTotpSecret(
  rootKey: Uint8Array,
  adminOperatorId: string,
  sealed: string,
): Buffer {
  assertRootKey(rootKey);
  assertAdminId(adminOperatorId);
  const dot = sealed.indexOf(".");
  if (dot < 0 || sealed.slice(0, dot) !== TOTP_SECRET_ENVELOPE_PREFIX) {
    throw new TotpOpenError("sealed TOTP secret has an unrecognised envelope prefix");
  }
  const blob = Buffer.from(sealed.slice(dot + 1), "base64");
  if (blob.length < NONCE_BYTES + TAG_BYTES + 10) {
    throw new TotpOpenError("sealed TOTP secret is truncated");
  }
  const nonce = blob.subarray(0, NONCE_BYTES);
  const tag = blob.subarray(NONCE_BYTES, NONCE_BYTES + TAG_BYTES);
  const ciphertext = blob.subarray(NONCE_BYTES + TAG_BYTES);
  const aad = Buffer.from(buildTotpSecretAad(adminOperatorId), "utf8");
  const dek = deriveTotpSecretDek(rootKey);
  try {
    const decipher = createDecipheriv("aes-256-gcm", dek, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.length < 10) {
      plaintext.fill(0);
      throw new TotpOpenError("decrypted TOTP secret length mismatch");
    }
    return plaintext;
  } catch (err) {
    if (err instanceof TotpOpenError) throw err;
    throw new TotpOpenError("envelope authentication failed");
  } finally {
    keyMaterialHygiene.zeroize(dek, "dek");
  }
}
