// Per-store master-key rewrap primitives for the sealed-store registry.
//
// Structural template (re-verified, not copy-trusted): apps/node rotate-master-key-stores.ts.
//
// Scope of THIS module (sealed-store rewrap census):
// - WALLET_VAULT — IMPLEMENTED. Production seal-write runtime exists
// (sealWalletSecret / openWalletSecret in envelope.ts). N>1 wallet rows, not a singleton.
// NODE_SIGNING_KEYS — IMPLEMENTED. Crypto rewrap lives in
// signing-keys/rewrap.ts (vault is a leaf; the rotation coordinator injects the port).
// - TOTP_SECRET / SESSION_SECRETS — no v2 production seal-write runtime yet.
// rewrapStatus DEFERRED_NO_SEAL_RUNTIME; a future createCipheriv site fails the
// structural census until registered with a real rewrap.
//
// Atomic multi-store coordination, exclusive signing interlock, dry-run, and rollback live
// in master-key-rotation.ts. This module is the per-store primitive.
//
// The key-custody rule: runs on the self-hosted node; never logs key material.
// The byte-exact signing rule: orthogonal — rewrap is a storage-envelope operation, not a signing preimage.

import {
  openWalletSecret,
  sealWalletSecret,
  type SealedEnvelope,
  type WalletIdentity,
} from "./envelope.js";

/** Count-parity result returned by every store rewrap (v1 SEALED_STORES shape). */
export interface SealedStoreRewrapResult {
  /** Rows present before the re-wrap. */
  readonly rowsBefore: number;
  /** Rows present after the re-wrap — must equal `rowsBefore`. */
  readonly rowsAfter: number;
  /** Rows re-sealed + verified under the new key — must equal the sealed subset count. */
  readonly rewrapped: number;
}

/**
 * One wallet row + the authoritative identity fields used to reconstruct AAD / HKDF info.
 * AAD-forming columns (nodeId, walletId, keyVersion, publicKey, keyOrigin) are READ-ONLY
 * inputs: rewrap never mutates them on the identity (wallet-vault AAD and HKDF-info guard (ii)).
 */
export interface WalletVaultRewrapRow {
  readonly identity: WalletIdentity;
  readonly envelope: SealedEnvelope;
}

export interface WalletVaultRewrapInput {
  /** Process-lifetime root derived from the OLD master key (PBKDF2 already applied). */
  readonly oldRootKey: Uint8Array;
  /** Process-lifetime root derived from the NEW master key. */
  readonly newRootKey: Uint8Array;
  /** Every vault row to rewrap — full census, not a singleton. */
  readonly rows: readonly WalletVaultRewrapRow[];
}

/**
 * Rewrap every wallet-vault envelope under a new root key.
 *
 * Mechanics (per row, sequential):
 * 1. open under `oldRootKey` (fail-closed on wrong key / tamper);
 * 2. reseal under `newRootKey` with a FRESH nonce at the SAME key_version
 * (master-key rotation is value-preserving on the wallet epoch — wallet-vault model per-row epoch
 * advances only on wallet-key rotation, not on master-key rewrap of the envelope);
 * 3. round-trip open under `newRootKey` and assert byte-identical secret;
 * 4. assert AAD source fields on the new envelope equal the input identity
 * (walletId + keyVersion unchanged; ciphertext/nonce/tag are the only mutable bytes).
 *
 * Fail-closed: any single-row failure throws BEFORE returning partial results. The caller
 * (the rotation coordinator) owns the DB transaction / commit boundary; this function is pure
 * over the in-memory row set and returns the full rewrapped set only on total success.
 *
 * Note on key_version: EncryptedWalletKeyStore.rotate preserves keyVersion (same identity).
 * core/recovery/rotation.ts advances keyVersion — that path is wallet-key lifecycle, not
 * master-key envelope rewrap. This primitive matches EncryptedWalletKeyStore.rotate.
 */
export function rewrapWalletVaultStore(
  input: WalletVaultRewrapInput,
): {
  readonly result: SealedStoreRewrapResult;
  readonly rewrappedRows: readonly WalletVaultRewrapRow[];
} {
  const { oldRootKey, newRootKey, rows } = input;
  const rowsBefore = rows.length;

  if (oldRootKey.length === 0 || newRootKey.length === 0) {
    throw new Error("rewrapWalletVaultStore: root key must be non-empty");
  }

  const rewrappedRows: WalletVaultRewrapRow[] = [];

  for (const row of rows) {
    const { identity, envelope } = row;

    // Guard (ii): envelope identity columns must already match the authoritative identity.
    if (envelope.walletId !== identity.walletId) {
      throw new Error(
        `rewrapWalletVaultStore: envelope.walletId does not match identity for wallet ${identity.walletId}`,
      );
    }
    if (envelope.keyVersion !== identity.keyVersion) {
      throw new Error(
        `rewrapWalletVaultStore: envelope.keyVersion does not match identity for wallet ${identity.walletId}`,
      );
    }

    // 1. Open under OLD — throws VaultOpenError on wrong key / tamper / AAD mismatch.
    const secret = openWalletSecret(oldRootKey, envelope, identity);
    try {
      // 2. Reseal under NEW at the SAME key_version (fresh nonce inside sealWalletSecret).
      const resealed = sealWalletSecret(newRootKey, identity, secret.bytes);

      // AAD-source immutability: reseal must not invent a different walletId/keyVersion.
      if (resealed.walletId !== identity.walletId) {
        throw new Error(
          `rewrapWalletVaultStore: reseal changed walletId for ${identity.walletId}`,
        );
      }
      if (resealed.keyVersion !== identity.keyVersion) {
        throw new Error(
          `rewrapWalletVaultStore: reseal changed keyVersion for ${identity.walletId}`,
        );
      }
      // Ciphertext/nonce must actually change (fresh nonce) — a no-op "rewrap" is a bug.
      if (buffersEqual(resealed.nonce, envelope.nonce)) {
        throw new Error(
          `rewrapWalletVaultStore: reseal reused nonce for ${identity.walletId}`,
        );
      }

      // 3. Round-trip verify under NEW before accepting the row.
      const verified = openWalletSecret(newRootKey, resealed, identity);
      try {
        if (!buffersEqual(verified.bytes, secret.bytes)) {
          throw new Error(
            `rewrapWalletVaultStore: round-trip secret mismatch for ${identity.walletId}`,
          );
        }
      } finally {
        verified.wipe();
      }

      rewrappedRows.push({ identity, envelope: resealed });
    } finally {
      secret.wipe();
    }
  }

  const result: SealedStoreRewrapResult = {
    rowsBefore,
    rowsAfter: rewrappedRows.length,
    rewrapped: rewrappedRows.length,
  };

  if (result.rowsBefore !== result.rowsAfter || result.rewrapped !== result.rowsBefore) {
    throw new Error(
      `rewrapWalletVaultStore: count parity failed (before=${result.rowsBefore} after=${result.rowsAfter} rewrapped=${result.rewrapped})`,
    );
  }

  return { result, rewrappedRows };
}

function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
