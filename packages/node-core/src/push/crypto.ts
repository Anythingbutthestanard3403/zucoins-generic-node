// Per-wallet Web Push receive-crypto material (push API base; detection channels (push primary); destination binding).
//
// This is the node's half of a standard Web Push subscription: a P-256 ECDH keypair
// (the subscription's `p256dh`) and a 16-byte `auth` secret, generated FRESH PER WALLET.
// is explicit that there is no node-wide VAPID keypair and no env-sourced key
// material — the private half is sealed under the vault root before it touches the
// database, and inbound push verification uses SplitChain's app-server key instead.
//
// Node's built-in `crypto.createECDH` supplies the P-256 primitive (keygen + ECDH);
// no elliptic-curve maths is hand-rolled here. RFC 8291 record framing is NOT hand-rolled
// either: `decryptWebPushPayload` (aes128gcm.ts) wraps the maintained `http_ece` library.
// The app still injects a `WebPushPayloadDecryptor` port (store.ts) so the receiver can
// stay free of the library import — the port's production binding is that single function.

import { createECDH, randomBytes } from "node:crypto";

/** P-256, a.k.a. secp256r1 — the Web Push-mandated curve (RFC 8291). */
const CURVE = "prime256v1";

/** RFC 8291 the `auth` secret is exactly 16 bytes. */
const AUTH_SECRET_LENGTH = 16;

export interface EcdhKeypair {
  /**
   * Raw uncompressed P-256 public point (65 bytes: `0x04 || X || Y`), base64url with no
   * padding. This is the subscription's `p256dh` value handed to the push service.
   */
  readonly publicKeyB64url: string;
  /**
   * Raw 32-byte P-256 private scalar. The caller owns its lifetime and must seal it
   * (vault root) before persistence and wipe its plaintext copy — it is never logged
   * and never returned on any read path.
   */
  readonly privateKeyBytes: Buffer;
}

/** Generate a fresh P-256 ECDH keypair for one wallet's push subscription. */
export function generateEcdhKeypair(): EcdhKeypair {
  const ecdh = createECDH(CURVE);
  ecdh.generateKeys();
  return {
    publicKeyB64url: ecdh.getPublicKey().toString("base64url"),
    privateKeyBytes: ecdh.getPrivateKey(),
  };
}

/** Generate a fresh 16-byte Web Push `auth` secret (RFC 8291). */
export function generateAuthSecret(): Buffer {
  return randomBytes(AUTH_SECRET_LENGTH);
}

/**
 * Rebuild a `crypto.ECDH` from stored raw private-key bytes. This is the shape an ECE
 * decryptor needs (it calls `.computeSecret` on the sender's ephemeral key), and is
 * only ever constructed after the sealed private half has been opened.
 */
export function ecdhFromPrivateKeyBytes(privateKeyBytes: Buffer): ReturnType<typeof createECDH> {
  const ecdh = createECDH(CURVE);
  ecdh.setPrivateKey(privateKeyBytes);
  return ecdh;
}
