// NODE_SIGNING_KEYS master-key rewrap primitive (sealed-store rewrap census).
// Open under old root, reseal under new root at the SAME key_version with a fresh nonce.
// AAD source fields (nodeId, purpose, publicKey, keyVersion) never change.

import {
  openNodeSigningSeed,
  sealNodeSigningSeed,
  type NodeSigningKeyIdentity,
  type NodeSigningKeySealedEnvelope,
} from "./sealed-store.js";

export interface SealedStoreRewrapResult {
  readonly rowsBefore: number;
  readonly rowsAfter: number;
  readonly rewrapped: number;
}

export interface NodeSigningKeyRewrapRow {
  readonly identity: NodeSigningKeyIdentity;
  readonly envelope: NodeSigningKeySealedEnvelope;
}

export interface NodeSigningKeyRewrapInput {
  readonly oldRootKey: Uint8Array;
  readonly newRootKey: Uint8Array;
  readonly rows: readonly NodeSigningKeyRewrapRow[];
}

function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Rewrap every NODE_SIGNING_KEYS envelope under a new root key.
 * Fail-closed: any single-row failure throws before returning partial results.
 * Count-parity: rowsBefore == rowsAfter == rewrapped.
 */
export function rewrapNodeSigningKeyStore(
  input: NodeSigningKeyRewrapInput,
): {
  readonly result: SealedStoreRewrapResult;
  readonly rewrappedRows: readonly NodeSigningKeyRewrapRow[];
} {
  const { oldRootKey, newRootKey, rows } = input;
  const rowsBefore = rows.length;

  if (oldRootKey.length === 0 || newRootKey.length === 0) {
    throw new Error("rewrapNodeSigningKeyStore: root key must be non-empty");
  }

  const rewrappedRows: NodeSigningKeyRewrapRow[] = [];

  for (const row of rows) {
    const { identity, envelope } = row;

    if (envelope.keyVersion !== identity.keyVersion) {
      throw new Error(
        `rewrapNodeSigningKeyStore: envelope.keyVersion does not match identity for ${identity.publicKey}`,
      );
    }

    const seed = openNodeSigningSeed(oldRootKey, envelope, identity);
    try {
      const resealed = sealNodeSigningSeed(
        newRootKey,
        identity,
        seed.bytes,
        envelope.vaultSecretRef,
      );

      if (resealed.keyVersion !== identity.keyVersion) {
        throw new Error(
          `rewrapNodeSigningKeyStore: reseal changed keyVersion for ${identity.publicKey}`,
        );
      }
      if (buffersEqual(resealed.nonce, envelope.nonce)) {
        throw new Error(
          `rewrapNodeSigningKeyStore: reseal reused nonce for ${identity.publicKey}`,
        );
      }

      const verified = openNodeSigningSeed(newRootKey, resealed, identity);
      try {
        if (!buffersEqual(verified.bytes, seed.bytes)) {
          throw new Error(
            `rewrapNodeSigningKeyStore: round-trip seed mismatch for ${identity.publicKey}`,
          );
        }
      } finally {
        verified.wipe();
      }

      rewrappedRows.push({ identity, envelope: resealed });
    } finally {
      seed.wipe();
    }
  }

  const result: SealedStoreRewrapResult = {
    rowsBefore,
    rowsAfter: rewrappedRows.length,
    rewrapped: rewrappedRows.length,
  };

  if (result.rowsBefore !== result.rowsAfter || result.rewrapped !== result.rowsBefore) {
    throw new Error(
      `rewrapNodeSigningKeyStore: count parity failed (before=${result.rowsBefore} after=${result.rowsAfter} rewrapped=${result.rewrapped})`,
    );
  }

  return { result, rewrappedRows };
}
