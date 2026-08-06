// Operator recovery pack v1 (create + prove).
//
// Format: zp-node-recovery-pack-v1 — Argon2id → AES-256-GCM seal of
// {"v":1,"vault_master_key":"..."}. TOTP is NOT the file key (session+CSRF+TOTP
// gate HTTP only). Ceremony engine remains sole writer of recovery_verified_at.
// Server zeroizes key material after create/prove.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

import { argon2id } from "@noble/hashes/argon2.js";

/** Frozen outer discriminator. */
export const RECOVERY_PACK_FORMAT = "zp-node-recovery-pack-v1" as const;

/** Frozen Argon2id params. */
export const RECOVERY_PACK_KDF = {
  alg: "argon2id",
  memory_kib: 65_536,
  iterations: 3,
  parallelism: 1,
  hash_len: 32,
} as const;

export const RECOVERY_PACK_AEAD_ALG = "aes-256-gcm" as const;
export const RECOVERY_PACK_SALT_BYTES = 16; // ≥128-bit
export const RECOVERY_PACK_NONCE_BYTES = 12;
export const RECOVERY_PACK_TAG_BYTES = 16;
export const RECOVERY_PACK_PASSCODE_MIN = 4;
export const RECOVERY_PACK_PASSCODE_MAX = 6;

/** Online prove lockout. */
export const RECOVERY_PACK_PROVE_FAIL_THRESHOLD = 5;
export const RECOVERY_PACK_PROVE_LOCKOUT_MS = 15 * 60 * 1000;
export const RECOVERY_PACK_PROVE_WINDOW_MS = 15 * 60 * 1000;

export interface RecoveryPackKdfPublic {
  readonly alg: "argon2id";
  readonly salt_b64url: string;
  readonly memory_kib: 65536;
  readonly iterations: 3;
  readonly parallelism: 1;
  readonly hash_len: 32;
}

export interface RecoveryPackAeadPublic {
  readonly alg: "aes-256-gcm";
  readonly nonce_b64url: string;
}

/** Wire envelope — public fields only; exact names frozen. */
export interface RecoveryPackEnvelope {
  readonly format: typeof RECOVERY_PACK_FORMAT;
  readonly kdf: RecoveryPackKdfPublic;
  readonly aead: RecoveryPackAeadPublic;
  readonly ciphertext_b64url: string;
  /** Hex SHA-256 of ciphertext bytes (decoded). */
  readonly pack_content_sha256: string;
}

export interface RecoveryPackSecretPayload {
  readonly v: 1;
  readonly vault_master_key: string;
}

export class RecoveryPackError extends Error {
  readonly code:
    | "invalid_passcode"
    | "invalid_format"
    | "decrypt_failed"
    | "invalid_payload"
    | "master_key_too_short";
  constructor(code: RecoveryPackError["code"], message: string) {
    super(message);
    this.name = "RecoveryPackError";
    this.code = code;
  }
}

const PASSCODE_RE = /^\d{4,6}$/;

export function isValidRecoveryPasscode(passcode: string): boolean {
  return PASSCODE_RE.test(passcode);
}

function wipe(buf: Uint8Array | Buffer | undefined): void {
  if (buf === undefined) return;
  buf.fill(0);
}

function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function deriveKey(passcode: string, salt: Uint8Array): Uint8Array {
  const passBytes = Buffer.from(passcode, "utf8");
  try {
    return argon2id(passBytes, salt, {
      m: RECOVERY_PACK_KDF.memory_kib,
      t: RECOVERY_PACK_KDF.iterations,
      p: RECOVERY_PACK_KDF.parallelism,
      dkLen: RECOVERY_PACK_KDF.hash_len,
    });
  } finally {
    wipe(passBytes);
  }
}

/**
 * Build a recovery pack file (UTF-8 JSON bytes). Caller supplies vault master;
 * this never logs it. Zeroizes derived key material before return.
 */
export function createRecoveryPack(input: {
  readonly vaultMasterKey: string;
  readonly passcode: string;
  /** Test hook — fixed salt (must be ≥16 bytes). */
  readonly salt?: Uint8Array;
  /** Test hook — fixed 12-byte nonce. */
  readonly nonce?: Uint8Array;
}): { readonly envelope: RecoveryPackEnvelope; readonly fileBytes: Buffer } {
  if (!isValidRecoveryPasscode(input.passcode)) {
    throw new RecoveryPackError(
      "invalid_passcode",
      `passcode must be ${RECOVERY_PACK_PASSCODE_MIN}–${RECOVERY_PACK_PASSCODE_MAX} digits`,
    );
  }
  if (input.vaultMasterKey.length < 32) {
    throw new RecoveryPackError(
      "master_key_too_short",
      "vault_master_key must be at least 32 characters",
    );
  }

  const salt = input.salt
    ? Uint8Array.from(input.salt)
    : new Uint8Array(randomBytes(RECOVERY_PACK_SALT_BYTES));
  if (salt.byteLength < RECOVERY_PACK_SALT_BYTES) {
    throw new RecoveryPackError("invalid_passcode", "salt must be ≥128-bit");
  }
  const nonce = input.nonce
    ? Buffer.from(input.nonce)
    : randomBytes(RECOVERY_PACK_NONCE_BYTES);
  if (nonce.byteLength !== RECOVERY_PACK_NONCE_BYTES) {
    throw new RecoveryPackError("invalid_passcode", "nonce must be 12 bytes");
  }

  const payload: RecoveryPackSecretPayload = {
    v: 1,
    vault_master_key: input.vaultMasterKey,
  };
  // Byte-exact JSON.stringify of fixed key sequence (the byte-exact signing rule).
  const plaintext = Buffer.from(
    JSON.stringify({ v: payload.v, vault_master_key: payload.vault_master_key }),
    "utf8",
  );

  let key: Uint8Array | undefined;
  let keyBuf: Buffer | undefined;
  try {
    key = deriveKey(input.passcode, salt);
    keyBuf = Buffer.from(key);
    const cipher = createCipheriv("aes-256-gcm", keyBuf, nonce);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const ciphertext = Buffer.concat([ct, tag]);

    const envelope: RecoveryPackEnvelope = {
      format: RECOVERY_PACK_FORMAT,
      kdf: {
        alg: "argon2id",
        salt_b64url: b64urlEncode(salt),
        memory_kib: RECOVERY_PACK_KDF.memory_kib,
        iterations: RECOVERY_PACK_KDF.iterations,
        parallelism: RECOVERY_PACK_KDF.parallelism,
        hash_len: RECOVERY_PACK_KDF.hash_len,
      },
      aead: {
        alg: RECOVERY_PACK_AEAD_ALG,
        nonce_b64url: b64urlEncode(nonce),
      },
      ciphertext_b64url: b64urlEncode(ciphertext),
      pack_content_sha256: sha256Hex(ciphertext),
    };

    // Pretty-print not used — compact JSON for stable download bytes.
    const fileBytes = Buffer.from(JSON.stringify(envelope), "utf8");
    return { envelope, fileBytes };
  } finally {
    wipe(plaintext);
    wipe(key);
    wipe(keyBuf);
    wipe(salt);
    wipe(nonce);
  }
}

/**
 * Decrypt a pack file. Returns master key on success; throws RecoveryPackError
 * on any failure (generic — no decrypt oracle). Zeroizes KDF/AEAD key material.
 */
export function openRecoveryPack(input: {
  readonly fileBytes: Uint8Array | string;
  readonly passcode: string;
}): RecoveryPackSecretPayload {
  if (!isValidRecoveryPasscode(input.passcode)) {
    throw new RecoveryPackError(
      "invalid_passcode",
      `passcode must be ${RECOVERY_PACK_PASSCODE_MIN}–${RECOVERY_PACK_PASSCODE_MAX} digits`,
    );
  }

  let parsed: unknown;
  try {
    const text =
      typeof input.fileBytes === "string"
        ? input.fileBytes
        : Buffer.from(input.fileBytes).toString("utf8");
    parsed = JSON.parse(text);
  } catch {
    throw new RecoveryPackError("invalid_format", "recovery pack is not valid JSON");
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new RecoveryPackError("invalid_format", "recovery pack envelope invalid");
  }
  const env = parsed as Record<string, unknown>;
  if (env.format !== RECOVERY_PACK_FORMAT) {
    throw new RecoveryPackError("invalid_format", "unknown recovery pack format");
  }

  const kdf = env.kdf as Record<string, unknown> | undefined;
  const aead = env.aead as Record<string, unknown> | undefined;
  if (
    kdf === undefined ||
    aead === undefined ||
    typeof env.ciphertext_b64url !== "string" ||
    typeof env.pack_content_sha256 !== "string"
  ) {
    throw new RecoveryPackError("invalid_format", "recovery pack missing fields");
  }
  if (
    kdf.alg !== "argon2id" ||
    kdf.memory_kib !== RECOVERY_PACK_KDF.memory_kib ||
    kdf.iterations !== RECOVERY_PACK_KDF.iterations ||
    kdf.parallelism !== RECOVERY_PACK_KDF.parallelism ||
    kdf.hash_len !== RECOVERY_PACK_KDF.hash_len ||
    typeof kdf.salt_b64url !== "string"
  ) {
    throw new RecoveryPackError("invalid_format", "recovery pack kdf rejected");
  }
  if (aead.alg !== RECOVERY_PACK_AEAD_ALG || typeof aead.nonce_b64url !== "string") {
    throw new RecoveryPackError("invalid_format", "recovery pack aead rejected");
  }

  let salt: Buffer | undefined;
  let nonce: Buffer | undefined;
  let ciphertext: Buffer | undefined;
  let key: Uint8Array | undefined;
  let keyBuf: Buffer | undefined;
  let plaintext: Buffer | undefined;

  try {
    salt = b64urlDecode(kdf.salt_b64url);
    nonce = b64urlDecode(aead.nonce_b64url);
    ciphertext = b64urlDecode(env.ciphertext_b64url);

    if (salt.byteLength < RECOVERY_PACK_SALT_BYTES) {
      throw new RecoveryPackError("invalid_format", "salt too short");
    }
    if (nonce.byteLength !== RECOVERY_PACK_NONCE_BYTES) {
      throw new RecoveryPackError("invalid_format", "nonce length invalid");
    }
    if (ciphertext.byteLength <= RECOVERY_PACK_TAG_BYTES) {
      throw new RecoveryPackError("invalid_format", "ciphertext too short");
    }

    const claimedSha = String(env.pack_content_sha256).toLowerCase();
    const actualSha = sha256Hex(ciphertext);
    const a = Buffer.from(claimedSha, "utf8");
    const b = Buffer.from(actualSha, "utf8");
    if (a.byteLength !== b.byteLength || !timingSafeEqual(a, b)) {
      throw new RecoveryPackError("invalid_format", "pack content digest mismatch");
    }

    const tag = ciphertext.subarray(ciphertext.byteLength - RECOVERY_PACK_TAG_BYTES);
    const ct = ciphertext.subarray(0, ciphertext.byteLength - RECOVERY_PACK_TAG_BYTES);

    key = deriveKey(input.passcode, salt);
    keyBuf = Buffer.from(key);
    const decipher = createDecipheriv("aes-256-gcm", keyBuf, nonce);
    decipher.setAuthTag(tag);
    try {
      plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
    } catch {
      throw new RecoveryPackError("decrypt_failed", "recovery pack decrypt failed");
    }

    let payload: unknown;
    try {
      payload = JSON.parse(plaintext.toString("utf8"));
    } catch {
      throw new RecoveryPackError("invalid_payload", "recovery pack payload invalid");
    }
    if (
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload) ||
      (payload as { v?: unknown }).v !== 1 ||
      typeof (payload as { vault_master_key?: unknown }).vault_master_key !== "string"
    ) {
      throw new RecoveryPackError("invalid_payload", "recovery pack payload shape invalid");
    }
    const master = (payload as { vault_master_key: string }).vault_master_key;
    if (master.length < 32) {
      throw new RecoveryPackError("invalid_payload", "vault_master_key too short");
    }
    return { v: 1, vault_master_key: master };
  } finally {
    wipe(salt);
    wipe(nonce);
    wipe(ciphertext);
    wipe(key);
    wipe(keyBuf);
    wipe(plaintext);
  }
}

/** Extract pack_content_sha256 from file bytes without decrypting (audit only). */
export function peekPackContentSha256(fileBytes: Uint8Array | string): string | null {
  try {
    const text =
      typeof fileBytes === "string" ? fileBytes : Buffer.from(fileBytes).toString("utf8");
    const parsed = JSON.parse(text) as { pack_content_sha256?: unknown };
    if (typeof parsed.pack_content_sha256 === "string" && /^[0-9a-f]{64}$/i.test(parsed.pack_content_sha256)) {
      return parsed.pack_content_sha256.toLowerCase();
    }
    return null;
  } catch {
    return null;
  }
}
