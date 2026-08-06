// At-rest sealing for push receive-crypto material (destination binding; never persist or log key material; wallet-vault AAD and HKDF-info).
//
// The vault's own `sealWalletSecret` cannot be reused here: it asserts a 64-byte Ed25519
// secret whose public half must derive from it, whereas these are a 32-byte P-256 ECDH
// scalar and a 16-byte RFC 8291 auth secret. So this is a separate, deliberately small
// envelope over the SAME vault root — but never keyed on that root directly. wallet-vault AAD and HKDF-info (i):
// under a shared root the store-unique HKDF label is the only thing stopping two sealed
// stores deriving the same AES key, and a cross-store nonce collision under one key is a
// GCM catastrophe no per-table UNIQUE(nonce) can catch. So this store derives its own DEK
// under `zp-push-receiver-dek-v1`, in the same `-dek-` family shape as the wallet vault and
// node signing keys: LF-joined info, empty salt, HKDF-SHA256, L=32.
//
// `key_version` is deliberately absent from the info: the DB column is tracking only, and
// master-key rotation trial-decrypts across the key ring (push/rewrap.ts), so the label must
// not move when the row's version does.
//
// The AAD binds node, wallet and purpose, so a sealed blob lifted from one wallet's row
// and pasted into another's fails its own decrypt rather than silently yielding the wrong
// wallet's push keys.

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

import { DEK_LENGTH_BYTES, keyMaterialHygiene } from "../vault/envelope.js";
import type { PushSecretPurpose, PushSecretSealer } from "./store.js";

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
/** Envelope version prefix, so the layout can change without ambiguity. */
const ENVELOPE_PREFIX = "zp-push-seal-v1";

/** Frozen wallet-vault AAD and HKDF-info cross-store HKDF domain label for PUSH_RECEIVER_SECRETS (schema discipline). */
export const PUSH_RECEIVER_DEK_HKDF_LABEL = "zp-push-receiver-dek-v1" as const;

export class PushSealError extends Error {
  readonly code = "PUSH_SEAL_FAILED";
  constructor(message: string) {
    super(message);
    this.name = "PushSealError";
  }
}

/** Exact UTF-8 HKDF info text. Byte contract (the byte-exact signing rule) — never reformat. */
export function buildPushReceiverDekInfo(fields: {
  readonly nodeId: string;
  readonly walletId: string;
}): string {
  return [PUSH_RECEIVER_DEK_HKDF_LABEL, fields.nodeId, fields.walletId].join("\n");
}

export function buildPushSecretAad(fields: {
  readonly nodeId: string;
  readonly walletId: string;
  readonly purpose: PushSecretPurpose;
}): string {
  return `${ENVELOPE_PREFIX}|${fields.nodeId}|${fields.walletId}|${fields.purpose}`;
}

function derivePushReceiverDek(
  rootKey: Uint8Array,
  nodeId: string,
  walletId: string,
): Buffer {
  const info = buildPushReceiverDekInfo({ nodeId, walletId });
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
 * Seal/open one wallet's push secret of a single purpose under a per-store, per-wallet DEK.
 * `rootKey` must be the 32-byte derived vault root; the caller owns its lifetime and this
 * module keeps no copy of it. The DEK is derived per call and zeroized in `finally`, so no
 * derived key outlives the operation that needed it and the factory needs no dispose port.
 */
export function createPushSecretSealer(input: {
  readonly rootKey: Uint8Array;
  readonly nodeId: string;
  readonly walletId: string;
}): PushSecretSealer {
  const { rootKey, nodeId, walletId } = input;
  if (rootKey.length !== 32) {
    throw new PushSealError(`vault root key must be 32 bytes, got ${rootKey.length}`);
  }
  const aadFor = (purpose: PushSecretPurpose): Buffer =>
    Buffer.from(buildPushSecretAad({ nodeId, walletId, purpose }), "utf8");

  return {
    async seal(plaintext, purpose) {
      const aad = aadFor(purpose);
      const nonce = randomBytes(NONCE_BYTES);
      const dek = derivePushReceiverDek(rootKey, nodeId, walletId);
      try {
        const cipher = createCipheriv("aes-256-gcm", dek, nonce);
        cipher.setAAD(aad);
        const ciphertext = Buffer.concat([
          cipher.update(Buffer.from(plaintext)),
          cipher.final(),
        ]);
        const tag = cipher.getAuthTag();
        return `${ENVELOPE_PREFIX}.${Buffer.concat([nonce, tag, ciphertext]).toString("base64")}`;
      } finally {
        keyMaterialHygiene.zeroize(dek, "dek");
      }
    },

    async open(sealed, purpose) {
      const aad = aadFor(purpose);
      const dot = sealed.indexOf(".");
      if (dot < 0 || sealed.slice(0, dot) !== ENVELOPE_PREFIX) {
        throw new PushSealError("sealed push secret has an unrecognised envelope prefix");
      }
      const blob = Buffer.from(sealed.slice(dot + 1), "base64");
      if (blob.length < NONCE_BYTES + TAG_BYTES) {
        throw new PushSealError("sealed push secret is truncated");
      }
      const nonce = blob.subarray(0, NONCE_BYTES);
      const tag = blob.subarray(NONCE_BYTES, NONCE_BYTES + TAG_BYTES);
      const ciphertext = blob.subarray(NONCE_BYTES + TAG_BYTES);
      const dek = derivePushReceiverDek(rootKey, nodeId, walletId);
      try {
        const decipher = createDecipheriv("aes-256-gcm", dek, nonce);
        decipher.setAAD(aad);
        decipher.setAuthTag(tag);
        // Throws on tag mismatch — a wrong root, a tampered column, or a blob moved
        // between wallets all fail closed here rather than returning partial plaintext.
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      } finally {
        keyMaterialHygiene.zeroize(dek, "dek");
      }
    },
  };
}
