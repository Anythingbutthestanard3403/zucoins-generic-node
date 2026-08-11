// Operator recovery pack v2 (create + open + re-issue).
//
// Format: zp-node-recovery-pack-v2 — Argon2id → AES-256-GCM seal of
// {"v":2,"vault_master_key":"..."}. TOTP is NOT the file key (session+CSRF+TOTP
// gate HTTP only). Ceremony engine remains sole writer of recovery_verified_at.
// Server zeroizes key material after create/prove.
//
// Threat model: the artifact is designed to leave the host, so it must survive
// being in hostile hands. The seal key therefore has to be a high-entropy secret —
// the online prove lockout governs API attempts only and is irrelevant to an
// attacker holding a copy of the file. v1 sealed under a 4–6 digit passcode
// (≤10^6 keyspace, enumerable offline against the same Argon2id); every v1 pack
// ever exported is compromised-if-leaked and must be re-issued and destroyed.
// v1 packs still open, but only through the explicit legacy opt-in below.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomInt,
  timingSafeEqual,
} from "node:crypto";

import { argon2id } from "@noble/hashes/argon2.js";

/** Frozen outer discriminator (current). */
export const RECOVERY_PACK_FORMAT = "zp-node-recovery-pack-v2" as const;
/** Frozen outer discriminator of the superseded digit-passcode pack. */
export const RECOVERY_PACK_FORMAT_LEGACY_V1 = "zp-node-recovery-pack-v1" as const;
/** Sealed payload version written by createRecoveryPack. */
export const RECOVERY_PACK_PAYLOAD_VERSION = 2 as const;

/** Frozen Argon2id params — unchanged from v1; the KDF was never the weakness. */
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

/**
 * Entropy floor for the pack secret, enforced at creation. 128 bits is the
 * conventional infeasible-search level and matches the rest of the envelope
 * (AES-256-GCM tag, ≥128-bit salt); Argon2id per-guess cost is on top of it.
 * Creation no longer trusts a charset×length proxy (ZTR-1220): the secret must
 * be exactly the generated shape — Crockford base32 × 26 chars (≥130 bits when
 * drawn i.i.d.) — plus structure guards against tiled / monotone draws.
 */
export const RECOVERY_PACK_MIN_ENTROPY_BITS = 128;
/**
 * Degenerate-input guard. Even inside the sanctioned alphabet a short cycle
 * ("ABABAB…") or a narrow character set is not a CSPRNG draw — require spread.
 */
export const RECOVERY_PACK_MIN_DISTINCT_CHARS = 10;
/**
 * Reject pure period-tilings and long monotone runs inside the alphabet. A real
 * CSPRNG draw almost never trips these; a hand-rolled "ABCDEF…" or
 * "ABCDABCD…" always does.
 */
export const RECOVERY_PACK_MAX_MONOTONE_RUN = 8;
/** Bound on secret length accepted on the *open* path (create is fixed-length). */
export const RECOVERY_PACK_SECRET_MAX_CHARS = 1024;

/**
 * Crockford base32 — 32 symbols, no I/L/O/U, so transcription is unambiguous.
 * Creation accepts only this alphabet (exact case); generateRecoverySecret draws
 * from it. Exported so callers / tests pin the same set the node enforces.
 */
export const RECOVERY_PACK_SECRET_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** 26 × log2(32) = 130 bits, drawn one symbol at a time. */
export const RECOVERY_PACK_GENERATED_SECRET_CHARS = 26;

/** Online prove lockout. Governs API attempts only — never offline possession. */
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
  /** 1 only when the caller opted into the legacy path. */
  readonly v: 1 | 2;
  readonly vault_master_key: string;
}

export class RecoveryPackError extends Error {
  readonly code:
    | "invalid_passcode"
    | "invalid_format"
    | "decrypt_failed"
    | "invalid_payload"
    | "master_key_too_short"
    | "weak_secret"
    | "legacy_pack_v1";
  constructor(code: RecoveryPackError["code"], message: string) {
    super(message);
    this.name = "RecoveryPackError";
    this.code = code;
  }
}

const DIGITS_ONLY_RE = /^\d+$/;
const SECRET_ALPHABET_RE = new RegExp(
  `^[${RECOVERY_PACK_SECRET_ALPHABET.replace(/[-\\]/g, "\\$&")}]{${RECOVERY_PACK_GENERATED_SECRET_CHARS}}$`,
);

/**
 * Conservative charset estimate: length × log2(observed character-class union).
 * Kept for diagnostics / tests. Creation acceptance is the alphabet×length
 * shape check below — this proxy alone is not an accept path (ZTR-1220).
 */
export function estimateRecoverySecretEntropyBits(secret: string): number {
  if (secret.length === 0) return 0;
  let pool = 0;
  if (/[a-z]/.test(secret)) pool += 26;
  if (/[A-Z]/.test(secret)) pool += 26;
  if (/\d/.test(secret)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(secret)) pool += 33; // ASCII punctuation + space
  return secret.length * Math.log2(pool);
}

/** True when `secret` is an exact tiling of a shorter non-empty unit. */
function isPeriodicTiling(secret: string): boolean {
  const n = secret.length;
  for (let period = 1; period <= Math.floor(n / 2); period++) {
    if (n % period !== 0) continue;
    const unit = secret.slice(0, period);
    if (unit.repeat(n / period) === secret) return true;
  }
  return false;
}

/**
 * True when ≥ RECOVERY_PACK_MAX_MONOTONE_RUN consecutive symbols step by ±1
 * through the Crockford alphabet (e.g. "0123456789AB").
 */
function hasMonotoneAlphabetRun(secret: string): boolean {
  const indexOf = (c: string): number => RECOVERY_PACK_SECRET_ALPHABET.indexOf(c);
  let up = 1;
  let down = 1;
  for (let i = 1; i < secret.length; i++) {
    const delta = indexOf(secret[i]!) - indexOf(secret[i - 1]!);
    up = delta === 1 ? up + 1 : 1;
    down = delta === -1 ? down + 1 : 1;
    if (up >= RECOVERY_PACK_MAX_MONOTONE_RUN || down >= RECOVERY_PACK_MAX_MONOTONE_RUN) {
      return true;
    }
  }
  return false;
}

/**
 * Named reason the secret is unfit to seal a pack, or null when it passes.
 * The message names the rule that failed — it says nothing about any pack.
 *
 * Creation accepts only the generateRecoverySecret() shape (ZTR-1220): the
 * charset×length proxy that previously cleared long patterned / dictionary
 * phrases is not an accept path.
 */
export function recoverySecretWeakness(secret: string): string | null {
  if (secret.length === 0) return "recovery secret is required";
  if (secret.length > RECOVERY_PACK_SECRET_MAX_CHARS) {
    return `recovery secret must be at most ${RECOVERY_PACK_SECRET_MAX_CHARS} characters`;
  }
  if (DIGITS_ONLY_RE.test(secret)) {
    return "recovery secret must not be digits only — a numeric passcode is enumerable offline against the pack";
  }
  if (!SECRET_ALPHABET_RE.test(secret)) {
    return `recovery secret must be exactly ${RECOVERY_PACK_GENERATED_SECRET_CHARS} characters from the Crockford base32 alphabet (0-9 A-Z except I L O U) — use generateRecoverySecret()`;
  }
  if (new Set(secret).size < RECOVERY_PACK_MIN_DISTINCT_CHARS) {
    return `recovery secret must use at least ${RECOVERY_PACK_MIN_DISTINCT_CHARS} distinct characters`;
  }
  if (isPeriodicTiling(secret)) {
    return "recovery secret must not be a repeated substring";
  }
  if (hasMonotoneAlphabetRun(secret)) {
    return "recovery secret must not contain a long sequential run";
  }
  // Belt: i.i.d. Crockford×26 is 130 bits; keep the named floor so a future
  // alphabet shrink cannot silently drop below it.
  const bits = RECOVERY_PACK_GENERATED_SECRET_CHARS * Math.log2(RECOVERY_PACK_SECRET_ALPHABET.length);
  if (bits < RECOVERY_PACK_MIN_ENTROPY_BITS) {
    return `recovery secret must carry at least ${RECOVERY_PACK_MIN_ENTROPY_BITS} bits of entropy (estimated ${Math.floor(bits)})`;
  }
  return null;
}

/** Shape check for a secret offered on the *open* path — v1 packs are digits. */
export function isAcceptableRecoverySecretShape(secret: string): boolean {
  return secret.length > 0 && secret.length <= RECOVERY_PACK_SECRET_MAX_CHARS;
}

/**
 * The sanctioned way to obtain a pack secret: generate, never accept. Each symbol
 * is an independent CSPRNG draw from a 32-symbol alphabet, so the estimator above
 * agrees exactly with the true entropy (130 bits).
 */
export function generateRecoverySecret(): string {
  // A draw can in principle land under the distinct-character / structure
  // guards; redraw rather than emit a secret the creation path would refuse.
  for (let attempt = 0; attempt < 8; attempt++) {
    let out = "";
    for (let i = 0; i < RECOVERY_PACK_GENERATED_SECRET_CHARS; i++) {
      out += RECOVERY_PACK_SECRET_ALPHABET[randomInt(0, RECOVERY_PACK_SECRET_ALPHABET.length)];
    }
    if (recoverySecretWeakness(out) === null) return out;
  }
  throw new RecoveryPackError("weak_secret", "recovery secret generation failed");
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

function deriveKey(secret: string, salt: Uint8Array): Uint8Array {
  const passBytes = Buffer.from(secret, "utf8");
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
 *
 * Omit `secret` to get a generated 130-bit one — that is the intended call. A
 * caller-supplied secret must clear the entropy floor at *creation*: once the
 * artifact exists the seal is fixed and no server-side control can help it.
 */
export function createRecoveryPack(input: {
  readonly vaultMasterKey: string;
  /** Optional — generated when omitted. Must clear the entropy floor. */
  readonly secret?: string;
  /** Test hook — fixed salt (must be ≥16 bytes). */
  readonly salt?: Uint8Array;
  /** Test hook — fixed 12-byte nonce. */
  readonly nonce?: Uint8Array;
}): {
  readonly envelope: RecoveryPackEnvelope;
  readonly fileBytes: Buffer;
  /** The secret the pack is sealed under — show once, never persist. */
  readonly secret: string;
} {
  const secret = input.secret ?? generateRecoverySecret();
  const weakness = recoverySecretWeakness(secret);
  if (weakness !== null) {
    throw new RecoveryPackError("weak_secret", weakness);
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
    throw new RecoveryPackError("invalid_format", "salt must be ≥128-bit");
  }
  const nonce = input.nonce
    ? Buffer.from(input.nonce)
    : randomBytes(RECOVERY_PACK_NONCE_BYTES);
  if (nonce.byteLength !== RECOVERY_PACK_NONCE_BYTES) {
    throw new RecoveryPackError("invalid_format", "nonce must be 12 bytes");
  }

  const payload: RecoveryPackSecretPayload = {
    v: RECOVERY_PACK_PAYLOAD_VERSION,
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
    key = deriveKey(secret, salt);
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
    return { envelope, fileBytes, secret };
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
 *
 * A v1 payload is never silently reinterpreted: it opens only when the caller
 * passes `allowLegacyV1`, and the returned `v` reports which path was taken.
 * The floor is deliberately NOT enforced here — a legacy pack legitimately
 * carries a digit passcode, and refusing to open it would strand the operator.
 */
export function openRecoveryPack(input: {
  readonly fileBytes: Uint8Array | string;
  readonly secret: string;
  /** Explicit opt-in to the superseded digit-passcode pack. */
  readonly allowLegacyV1?: boolean;
}): RecoveryPackSecretPayload {
  if (!isAcceptableRecoverySecretShape(input.secret)) {
    throw new RecoveryPackError(
      "invalid_passcode",
      `recovery secret must be 1–${RECOVERY_PACK_SECRET_MAX_CHARS} characters`,
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
  if (env.format !== RECOVERY_PACK_FORMAT && env.format !== RECOVERY_PACK_FORMAT_LEGACY_V1) {
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

    key = deriveKey(input.secret, salt);
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
      typeof (payload as { vault_master_key?: unknown }).vault_master_key !== "string"
    ) {
      throw new RecoveryPackError("invalid_payload", "recovery pack payload shape invalid");
    }
    // Payload version is authoritative — it is inside the AEAD, the outer
    // `format` label is not. Relabelling a v1 file as v2 lands here, not past it.
    const version = (payload as { v?: unknown }).v;
    if (version !== RECOVERY_PACK_PAYLOAD_VERSION && version !== 1) {
      throw new RecoveryPackError("invalid_payload", "recovery pack payload shape invalid");
    }
    if (version === 1 && input.allowLegacyV1 !== true) {
      throw new RecoveryPackError(
        "legacy_pack_v1",
        "this is a superseded v1 recovery pack sealed under a digit passcode — restore it only through the explicit legacy path, then re-issue and destroy it",
      );
    }
    const master = (payload as { vault_master_key: string }).vault_master_key;
    if (master.length < 32) {
      throw new RecoveryPackError("invalid_payload", "vault_master_key too short");
    }
    return { v: version === 1 ? 1 : RECOVERY_PACK_PAYLOAD_VERSION, vault_master_key: master };
  } finally {
    wipe(salt);
    wipe(nonce);
    wipe(ciphertext);
    wipe(key);
    wipe(keyBuf);
    wipe(plaintext);
  }
}

/**
 * Re-seal an existing pack as v2. The master never leaves this call — it is the
 * only way to replace a compromised-if-leaked v1 artifact without the operator
 * handling the raw vault master key. `newSecret` is generated when omitted and
 * is held to the same entropy floor as any other creation.
 */
export function reissueRecoveryPack(input: {
  readonly fileBytes: Uint8Array | string;
  /** Secret the *existing* pack is sealed under (a v1 digit passcode is fine). */
  readonly secret: string;
  /** Secret for the replacement pack — generated when omitted. */
  readonly newSecret?: string;
  /** Explicit opt-in when the existing pack is v1. */
  readonly allowLegacyV1?: boolean;
  /** Test hook — fixed salt (must be ≥16 bytes). */
  readonly salt?: Uint8Array;
  /** Test hook — fixed 12-byte nonce. */
  readonly nonce?: Uint8Array;
}): {
  readonly envelope: RecoveryPackEnvelope;
  readonly fileBytes: Buffer;
  /** The secret the *new* pack is sealed under — show once, never persist. */
  readonly secret: string;
  /** Payload version of the pack that was replaced. */
  readonly previousVersion: 1 | 2;
  readonly previousPackContentSha256: string | null;
} {
  // Check the replacement secret before decrypting anything: a re-issue that is
  // going to be refused should never unseal the master in the first place.
  if (input.newSecret !== undefined) {
    const weakness = recoverySecretWeakness(input.newSecret);
    if (weakness !== null) throw new RecoveryPackError("weak_secret", weakness);
  }
  const previousPackContentSha256 = peekPackContentSha256(input.fileBytes);
  const opened = openRecoveryPack({
    fileBytes: input.fileBytes,
    secret: input.secret,
    allowLegacyV1: input.allowLegacyV1,
  });
  const holder = { master: opened.vault_master_key };
  try {
    const built = createRecoveryPack({
      vaultMasterKey: holder.master,
      ...(input.newSecret === undefined ? {} : { secret: input.newSecret }),
      salt: input.salt,
      nonce: input.nonce,
    });
    return { ...built, previousVersion: opened.v, previousPackContentSha256 };
  } finally {
    holder.master = "";
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
