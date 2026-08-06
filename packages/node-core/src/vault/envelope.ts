// Per-wallet AES-256-GCM envelope: seal a wallet's 64-byte Ed25519 secret key at rest and
// open it only inside the signing path. Key hierarchy (frozen, generic-node-contracts
// /src/vault/crypto.contract.ts): a PBKDF2-SHA256 root derived once from the operator-held
// master key, then a per-wallet DEK via HKDF-SHA256 over that root. The master key is required
// secret configuration and is never database-resident; this module never logs key material.
//
//
// Key-memory hygiene (wallet-vault model guard 5: "zeroes temporary key buffers where the runtime
// permits"; proof contract sealed-store rewrap census Option A):
// - Derived DEKs and any module-owned plaintext / seed / PKCS#8 / GCM-update intermediates
// are `adopt`ed then wiped in `try/finally` on every success and failure path via
// `keyMaterialHygiene.zeroize(buf, role)`. `zeroize` accepts only module-adopted buffers
// (brand check) so a plain `Buffer` decoy under the correct role string cannot discharge
// the obligation (forbidden shape 3). Each call site tags the wipe role
// (`dek` | `gcm_update` | `failure_plaintext` | `seal_plaintext` | `seed` | `pkcs8` |
// `secure_buffer`). Tests assert the role set **and** `liveOwnedCount === 0` (or 1
// across a successful open before `SecureBuffer.wipe`) — not harness Buffer identity
// pins (forbids wipedRefs.has / first-pin concat / nth-in-sequence capture).
// - `openWalletSecret` returns a `SecureBuffer`; the decrypted secret stays adopted
// (live count 1) until the signer calls `wipe` (post-sign). Failure paths wipe every
// module-owned decrypt output (GCM `update` intermediate and assembled plaintext).
// - Process-lifetime root key (boot-derived) is intentionally NOT wiped here — the store
// holds it for the node lifetime.
// - Caller-owned master-key input to `deriveRootKey` is intentionally NOT wiped here — the
// caller retains custody of that buffer (audit review: wiping it would be an overclaim).
// - JS runtimes cannot guarantee physical RAM erasure; `buf.fill(0)` is best-effort and the
// required deterministic hygiene when libsodium secure buffers are unavailable
// in this package (no libsodium dependency; node:crypto only). node:crypto / OpenSSL
// internal copies are outside module ownership.

import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  pbkdf2Sync,
  randomBytes,
} from "node:crypto";

import {
  buildWalletDekInfo,
  buildWalletSecretAad,
  sha256Hex,
  toBase64UrlPadded,
  type WalletSecretAadFields,
} from "./serialization.js";

export const ROOT_KDF_ITERATIONS = 600_000;
export const ROOT_KDF_HASH = "sha256";
export const DEK_LENGTH_BYTES = 32;
export const NONCE_LENGTH_BYTES = 12; // 96-bit CSPRNG nonce
export const AUTH_TAG_LENGTH_BYTES = 16; // 128-bit GCM tag
export const ED25519_SECRET_KEY_BYTES = 64;
export const ED25519_SEED_BYTES = 32;
// Wire/format epoch for the AAD domain label (`zp-wallet-secret-v1`). This is NOT
// `vault.key_version` / `WalletIdentity.keyVersion` (the wallet key-rotation epoch; wallet-vault model).
// Format bumps land as a new AAD domain label (e.g. `zp-wallet-secret-v2`), not by gating
// open on the wallet's key-rotation integer.
export const SUPPORTED_ENVELOPE_VERSION = 1;

// RFC 8410 PKCS#8 prefix wrapping a raw 32-byte Ed25519 seed as a private key.
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/**
 * Role tag for a production wipe obligation (Option A). Tests spy
 * `keyMaterialHygiene.zeroize` and assert the set of roles fired for a path — not that a
 * harness-pinned Buffer identity appears among wipe arguments.
 *
 * - `dek` — per-wallet HKDF-derived DEK
 * - `gcm_update` — Buffer returned by `decipher.update` (pre-tag intermediate)
 * - `failure_plaintext` — assembled open plaintext wiped on exception (not transferred)
 * - `seal_plaintext` — module-owned seal plaintext copy
 * - `seed` / `pkcs8` — Ed25519 derive scratch buffers
 * - `secure_buffer` — caller-invoked `SecureBuffer.wipe` after successful open ownership transfer
 */
export type KeyMaterialWipeRole =
  | "dek"
  | "gcm_update"
  | "failure_plaintext"
  | "seal_plaintext"
  | "seed"
  | "pkcs8"
  | "secure_buffer";

/**
 * Module-owned key-material brand + single wipe entry point (Option A).
 *
 * Production paths `adopt` every temporary key buffer at the allocation / GCM-update
 * source. `zeroize(buf, role)` refuses buffers that were never adopted, so
 * `zeroize(Buffer.from(real), role)` / `zeroize(Buffer.alloc(...), role)` cannot
 * discharge the obligation while the real owned buffer stays live. `liveOwnedCount`
 * is the path-exit residual: 0 after every failure path and after `SecureBuffer.wipe`;
 * 1 after a successful open (transferred secret) until the caller wipes.
 *
 * Not Option B: no owned-buffer identity registry is reported for census — only a scalar
 * residual count + role tags on the wipe entry point. Spyable in tests.
 */
const ownedKeyMaterial = new WeakSet<Uint8Array>();
let liveOwnedKeyMaterial = 0;

export const keyMaterialHygiene = {
  /** Brand `buf` as module-owned temporary key material. Idempotent on the same buffer. */
  adopt<T extends Uint8Array>(buf: T): T {
    if (!ownedKeyMaterial.has(buf)) {
      ownedKeyMaterial.add(buf);
      liveOwnedKeyMaterial += 1;
    }
    return buf;
  },

  /**
   * Wipe entry point. Requires a prior `adopt` on the same buffer instance (brand check).
   * `role` tags the obligation for proof; it does not select which buffer is wiped.
   */
  zeroize(buf: Uint8Array, role: KeyMaterialWipeRole): void {
    if (!ownedKeyMaterial.has(buf)) {
      throw new TypeError(
        `keyMaterialHygiene.zeroize: buffer is not module-owned key material (role ${role})`,
      );
    }
    buf.fill(0);
    ownedKeyMaterial.delete(buf);
    liveOwnedKeyMaterial -= 1;
  },

  /**
   * Outstanding adopted buffers not yet passed through `zeroize`. Path-exit post-condition
   * for sealed-store rewrap census shape 3 (not an identity census).
   */
  liveOwnedCount(): number {
    return liveOwnedKeyMaterial;
  },
};

/**
 * Spyable AES-GCM factory (node:crypto ESM exports are not spyable). Production always
 * delegates to node:crypto; do not call this outside vault envelope open/seal.
 *
 * `update` return values are adopted at the factory so a `Buffer.from(decipher.update)`
 * orphan leaves the real GCM intermediate branded and live (`liveOwnedCount` stays high /
 * decoy wipe under `gcm_update` fails the brand check).
 */
export const gcmCrypto = {
  createDecipheriv: ((
    algorithm: Parameters<typeof createDecipheriv>[0],
    key: Parameters<typeof createDecipheriv>[1],
    iv: Parameters<typeof createDecipheriv>[2],
    options?: Parameters<typeof createDecipheriv>[3],
  ) => {
    const decipher = createDecipheriv(algorithm, key, iv, options);
    const origUpdate = decipher.update.bind(decipher) as (...args: unknown[]) => Buffer | string;
    decipher.update = ((...args: unknown[]) => {
      const out = origUpdate(...args);
      // Buffer-mode update (vault open) returns Buffer — brand it. String-mode is unused here.
      return typeof out === "string" ? out : keyMaterialHygiene.adopt(out);
    }) as typeof decipher.update;
    return decipher;
  }) as typeof createDecipheriv,
};

// Frozen open-failure vocabulary (generic-node-contracts/src/vault/failure-behavior.ts).
// Every open failure fails closed; there is no fallback to a shared-key or single-blob path.
export type VaultOpenFailureCode =
  | "LENGTH_MISMATCH"
  | "UNSUPPORTED_VERSION"
  | "NON_CANONICAL_PUBLIC_KEY"
  | "AUTH_TAG_FAILURE"
  | "AAD_MISMATCH"
  | "PUBLIC_KEY_MISMATCH";

export class VaultOpenError extends Error {
  readonly code: VaultOpenFailureCode;
  constructor(code: VaultOpenFailureCode, message: string) {
    super(message);
    this.name = "VaultOpenError";
    this.code = code;
  }
}

export class VaultSealError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultSealError";
  }
}

// Decrypted secret held in a caller-owned buffer that can be zeroed once signing completes.
export interface SecureBuffer {
  readonly bytes: Uint8Array;
  wipe(): void;
}

export interface WalletIdentity {
  readonly nodeId: string;
  readonly walletId: string;
  readonly keyVersion: number;
  readonly publicKey: string;
  readonly keyOrigin: string;
}

// The persisted envelope row (table `vault`). No AAD column: the AAD is reconstructed at open
// from the wallet's authoritative columns.
export interface SealedEnvelope {
  readonly walletId: string;
  readonly keyVersion: number;
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly authTag: Uint8Array;
  readonly ciphertextSha256: string;
}

// PBKDF2-SHA256 root key, derived once at boot from the operator-held master key. The salt is
// store-unique boot material; the master key itself is never persisted by this module.
// Caller owns `masterKey` — this function does not wipe it (see module header).
export function deriveRootKey(masterKey: Uint8Array | string, salt: Uint8Array): Buffer {
  return pbkdf2Sync(
    Buffer.from(masterKey),
    Buffer.from(salt),
    ROOT_KDF_ITERATIONS,
    DEK_LENGTH_BYTES,
    ROOT_KDF_HASH,
  );
}

function deriveWalletDek(rootKey: Uint8Array, identity: WalletIdentity): Buffer {
  const info = buildWalletDekInfo({
    nodeId: identity.nodeId,
    walletId: identity.walletId,
    keyVersion: identity.keyVersion,
  });
  return keyMaterialHygiene.adopt(
    Buffer.from(
      hkdfSync("sha256", Buffer.from(rootKey), Buffer.alloc(0), Buffer.from(info, "utf8"), DEK_LENGTH_BYTES),
    ),
  );
}

// Derive the padded base64url Ed25519 public key from a 64-byte libsodium-format secret key
// (seed || pubkey). Returns null on malformed input. Used as the primary substitution control:
// every open derives the public key and asserts it equals the wallet's authoritative public key.
// Owned seed + PKCS#8 DER copies are wiped on every path before return.
export function deriveEd25519PublicKeyBase64Url(secretKey: Uint8Array): string | null {
  if (secretKey.length !== ED25519_SECRET_KEY_BYTES) return null;
  const seed = keyMaterialHygiene.adopt(Buffer.alloc(ED25519_SEED_BYTES));
  seed.set(secretKey.subarray(0, ED25519_SEED_BYTES));
  const pkcs8 = keyMaterialHygiene.adopt(Buffer.concat([ED25519_PKCS8_PREFIX, seed]));
  try {
    const privateKey = createPrivateKey({
      key: pkcs8,
      format: "der",
      type: "pkcs8",
    });
    const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
    return toBase64UrlPadded(Buffer.from(spki).subarray(-ED25519_SEED_BYTES));
  } catch {
    return null;
  } finally {
    keyMaterialHygiene.zeroize(seed, "seed");
    keyMaterialHygiene.zeroize(pkcs8, "pkcs8");
  }
}

const CANONICAL_PUBLIC_KEY = /^[A-Za-z0-9_-]{43}=$/;

function assertSealInputs(identity: WalletIdentity, secretKey: Uint8Array): void {
  if (secretKey.length !== ED25519_SECRET_KEY_BYTES) {
    throw new VaultSealError("ed25519 secret key must be 64 bytes");
  }
  if (!Number.isInteger(identity.keyVersion) || identity.keyVersion < 1) {
    throw new VaultSealError("keyVersion must be a positive integer");
  }
  if (!CANONICAL_PUBLIC_KEY.test(identity.publicKey)) {
    throw new VaultSealError("publicKey is not canonical padded base64url");
  }
  const derived = deriveEd25519PublicKeyBase64Url(secretKey);
  if (derived !== identity.publicKey) {
    throw new VaultSealError("secret key does not match the authoritative public key");
  }
}

// Seal a wallet's 64-byte Ed25519 secret under a fresh CSPRNG nonce. The AAD binds the wallet's
// authoritative fields so a rolled-back key version or an imported→node-generated origin smuggle
// fails the envelope's own decrypt. Derived DEK and the module-owned plaintext copy are wiped
// before return on every path; the caller's `secretKey` buffer is not touched.
export function sealWalletSecret(
  rootKey: Uint8Array,
  identity: WalletIdentity,
  secretKey: Uint8Array,
): SealedEnvelope {
  assertSealInputs(identity, secretKey);
  const dek = deriveWalletDek(rootKey, identity);
  // Own a copy so cipher.update cannot retain a live view into caller memory, and so we can
  // wipe module-owned plaintext independently of the caller's buffer.
  const plaintext = keyMaterialHygiene.adopt(Buffer.from(secretKey));
  try {
    const aad = Buffer.from(buildWalletSecretAad(identity as WalletSecretAadFields), "utf8");
    const nonce = randomBytes(NONCE_LENGTH_BYTES);
    const cipher = createCipheriv("aes-256-gcm", dek, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
      walletId: identity.walletId,
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

// Open a sealed envelope, returning the secret in a wipeable buffer. Fails closed on any
// mismatch; the check sequence mirrors the frozen classifier (first failing check wins).
// node:crypto's GCM verifies tag and AAD in one authenticated step, so a tag failure and an
// AAD mismatch both surface as AUTH_TAG_FAILURE here — both fail closed with no plaintext
// released to the caller.
//
// GCM note: `decipher.update` emits decrypted bytes *before* `final` checks the auth
// tag. On AUTH_TAG_FAILURE those intermediate bytes must still be wiped — "not released"
// is not the same as "zeroized". `updateOut` binds the *actual* `decipher.update` return
// (not a `Buffer.from` copy of it — that would orphan the real GCM plaintext buffer to GC
// still holding secret bytes). `updateOut` + assembled `plaintext` are forced through
// `keyMaterialHygiene.zeroize` in `finally` on every failure path. Derived DEK is always
// wiped. On success, ownership of the assembled plaintext transfers to SecureBuffer
// (signer must wipe post-sign); the GCM update intermediate is wiped after concat.
export function openWalletSecret(
  rootKey: Uint8Array,
  envelope: SealedEnvelope,
  authoritative: WalletIdentity,
): SecureBuffer {
  if (
    envelope.ciphertext.length !== ED25519_SECRET_KEY_BYTES ||
    envelope.nonce.length !== NONCE_LENGTH_BYTES ||
    envelope.authTag.length !== AUTH_TAG_LENGTH_BYTES
  ) {
    throw new VaultOpenError("LENGTH_MISMATCH", "envelope field length mismatch");
  }
  // Do NOT treat envelope.keyVersion as a format version. It is the wallet key-rotation
  // epoch (positive integer; wallet-vault model; wallet-vault AAD and HKDF-info): values 2, 3, … are normal and required after
  // rotation. Format versioning lives in the AAD domain label (SUPPORTED_ENVELOPE_VERSION /
  // zp-wallet-secret-v1), reconstructed via buildWalletSecretAad — not this column.
  if (!CANONICAL_PUBLIC_KEY.test(authoritative.publicKey)) {
    throw new VaultOpenError("NON_CANONICAL_PUBLIC_KEY", "authoritative public key is not canonical");
  }

  const dek = deriveWalletDek(rootKey, authoritative);
  const aad = Buffer.from(buildWalletSecretAad(authoritative as WalletSecretAadFields), "utf8");
  // Named so AUTH_TAG_FAILURE (final throw after update returned secret bytes) still
  // routes the *actual* update Buffer through keyMaterialHygiene.zeroize — concat never
  // assigns `plaintext` when final fails. Do not Buffer.from(update): that orphans the
  // real (already-adopted) GCM intermediate; a decoy wipe cannot clear its brand / residual.
  let updateOut: Buffer | undefined;
  let plaintext: Buffer | undefined;
  try {
    try {
      const decipher = gcmCrypto.createDecipheriv("aes-256-gcm", dek, envelope.nonce);
      decipher.setAAD(aad);
      decipher.setAuthTag(Buffer.from(envelope.authTag));
      // Bind the real update return — factory adopts it; this intermediate must hit
      // zeroize on every path (success, AUTH_TAG_FAILURE, PUBLIC_KEY_MISMATCH).
      updateOut = decipher.update(Buffer.from(envelope.ciphertext));
      const finalOut = decipher.final();
      // Assemble into a fresh module-owned buffer (concat allocates; brand it).
      plaintext = keyMaterialHygiene.adopt(Buffer.concat([updateOut, finalOut]));
      // Concat copied updateOut into plaintext; drop the intermediate now.
      keyMaterialHygiene.zeroize(updateOut, "gcm_update");
      updateOut = undefined;
    } catch {
      throw new VaultOpenError("AUTH_TAG_FAILURE", "envelope authentication failed");
    }

    if (plaintext.length !== ED25519_SECRET_KEY_BYTES) {
      throw new VaultOpenError("LENGTH_MISMATCH", "decrypted secret length mismatch");
    }

    const derived = deriveEd25519PublicKeyBase64Url(plaintext);
    if (derived !== authoritative.publicKey) {
      throw new VaultOpenError("PUBLIC_KEY_MISMATCH", "decrypted secret does not match the public key");
    }

    // Transfer ownership to the caller; buffer stays adopted until SecureBuffer.wipe.
    // Residual liveOwnedCount is 1 (released secret) after open returns successfully.
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
