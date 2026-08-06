/**
 * SOURCE: the wallet-vault envelope freeze guard 1 (sealed material = 64-byte Ed25519 secret), guard 2
 * (primary substitution control = decrypt -> derive-pubkey -> match wallets.public_key);
 * the signing-custody-security spec the vault-envelope rules, the ceremony procedure step (b).
 *
 * Drill-grade Ed25519 helpers over the package's independent libsodium testkit. The sealed wallet
 * secret is the libsodium 64-byte secret key (seed[32] || pubkey[32]); "derive the public key from
 * the opened secret" re-derives from the seed half and asserts it equals both the pubkey half and
 * `wallets.public_key` — the vault-envelope rules primary substitution control re-run post-restore. Every key here
 * is a synthetic test seed that MUST never touch live ZKZ.
 */
import {
  ready,
  keypairFromSeed,
  keypairFromSeedByte,
  encodeBase64Url,
  decodeBase64Url,
  signPreimage,
  verifyPreimageSignature,
  type RawKeypair,
} from "../testkit/independentCrypto.ts";

export { ready };

/** A wallet key material bundle: the 64-byte secret (sealed in the vault) plus its public key. */
export interface WalletKey {
  readonly seedByte: number;
  readonly secret64: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly publicKeyB64Url: string;
}

const SEED_LEN = 32;

const toWalletKey = (seedByte: number, keypair: RawKeypair): WalletKey => ({
  seedByte,
  secret64: keypair.privateKey,
  publicKey: keypair.publicKey,
  publicKeyB64Url: encodeBase64Url(keypair.publicKey),
});

/** Deterministic wallet key from a filled seed byte. Caller must have awaited `ready()`. */
export const walletKeyFromSeedByte = (seedByte: number): WalletKey =>
  toWalletKey(seedByte, keypairFromSeedByte(seedByte));

/**
 * Derive the public key from an opened 64-byte secret and assert internal consistency (the seed
 * half re-derives the pubkey half). Returns the pubkey bytes; throws if inconsistent. Caller must
 * have awaited `ready()`.
 */
export const derivePublicKey = (secret64: Uint8Array): Uint8Array => {
  if (secret64.length !== 64) {
    throw new Error(`derive-pubkey: secret must be 64 bytes, got ${secret64.length}`);
  }
  const seed = secret64.slice(0, SEED_LEN);
  const embedded = secret64.slice(SEED_LEN);
  const derived = keypairFromSeed(seed).publicKey;
  if (encodeBase64Url(derived) !== encodeBase64Url(embedded)) {
    throw new Error("derive-pubkey: secret seed half does not re-derive its pubkey half");
  }
  return derived;
};

/** True iff `publicKey` byte-equals the canonical padded-base64url `expectedB64Url`. */
export const publicKeyMatches = (publicKey: Uint8Array, expectedB64Url: string): boolean =>
  encodeBase64Url(publicKey) === expectedB64Url;

/** Sign a suite preimage with an opened 64-byte secret (padded base64url signature). */
export const signWithSecret64 = (preimageText: string, secret64: Uint8Array): string =>
  signPreimage(preimageText, secret64);

/** Verify a padded-base64url suite signature against a public key. */
export const verifyWithPublicKey = (
  preimageText: string,
  signatureB64Url: string,
  publicKey: Uint8Array,
): boolean => verifyPreimageSignature(preimageText, signatureB64Url, publicKey);

export const decodePublicKey = (b64Url: string): Uint8Array => decodeBase64Url(b64Url);
