// Boot key-ring for mixed-`key_version` vault populations during crash-resumable
// master-key rotation (wallet-vault model guard 3; lifecycle.contract.ts
// `boot_reads_mixed_version_via_key_ring`).
//
// During ROTATING the vault may hold rows sealed under either the old or the new root.
// Open attempts the roots in a deterministic ordering (writer epoch first, then retained
// prior epoch) and fails closed if none authenticate. The ring never logs key material
// and never persists a root (the key-custody rule).

import {
  openWalletSecret,
  VaultOpenError,
  type SealedEnvelope,
  type SecureBuffer,
  type WalletIdentity,
} from "./envelope.js";

/** One epoch's process-lifetime root. Caller owns the buffer and its wipe. */
export interface KeyRingEntry {
  /** Integer epoch this root seals/opens (matches journal writer/from/to epochs). */
  readonly epoch: number;
  readonly root: Uint8Array;
}

/**
 * Ordered set of roots available for open. At most one entry is the *writer* root
 * (new seals); every other entry is retained for open of pre-rotation ciphertext.
 */
export interface VaultKeyRing {
  readonly entries: readonly KeyRingEntry[];
  /** Epoch used for NEW seals. Must be present in `entries`. */
  readonly writerEpoch: number;
}

export class KeyRingOpenError extends Error {
  readonly code = "KEY_RING_OPEN_FAILED";
  constructor(message: string) {
    super(message);
    this.name = "KeyRingOpenError";
  }
}

/** Resolve the writer root. Throws if the ring is misconfigured. */
export function writerRoot(ring: VaultKeyRing): Uint8Array {
  const entry = ring.entries.find((e) => e.epoch === ring.writerEpoch);
  if (entry === undefined) {
    throw new KeyRingOpenError(
      `key-ring has no entry for writerEpoch ${ring.writerEpoch}`,
    );
  }
  return entry.root;
}

/**
 * Open a sealed envelope by trying each root in deterministic ordering:
 * writer epoch first, then remaining epochs ascending. Returns the opened secret
 * plus the epoch that authenticated. Throws {@link KeyRingOpenError} when no root
 * authenticates (fail-closed — never returns a partial or guessed secret).
 */
export function openWithKeyRing(
  ring: VaultKeyRing,
  envelope: SealedEnvelope,
  identity: WalletIdentity,
): { readonly secret: SecureBuffer; readonly epoch: number } {
  if (ring.entries.length === 0) {
    throw new KeyRingOpenError("key-ring is empty");
  }

  const ordered = orderEntriesForOpen(ring);
  const failures: string[] = [];

  for (const entry of ordered) {
    try {
      const secret = openWalletSecret(entry.root, envelope, identity);
      return { secret, epoch: entry.epoch };
    } catch (err) {
      if (err instanceof VaultOpenError) {
        failures.push(`${entry.epoch}:${err.code}`);
        continue;
      }
      throw err;
    }
  }

  throw new KeyRingOpenError(
    `no key-ring root opened wallet ${identity.walletId} (tried ${failures.join(",")})`,
  );
}

/** Writer first, then other epochs ascending — stable across boots. */
export function orderEntriesForOpen(ring: VaultKeyRing): readonly KeyRingEntry[] {
  const writer = ring.entries.filter((e) => e.epoch === ring.writerEpoch);
  const rest = ring.entries
    .filter((e) => e.epoch !== ring.writerEpoch)
    .slice()
    .sort((a, b) => a.epoch - b.epoch);
  return [...writer, ...rest];
}

/**
 * Build a ring for a STABLE journal (single root) or a ROTATING / COMPLETE journal
 * (old + new roots retained until settle).
 */
export function buildKeyRing(input: {
  readonly writerEpoch: number;
  readonly writerRoot: Uint8Array;
  readonly retained?: readonly KeyRingEntry[];
}): VaultKeyRing {
  const retained = input.retained ?? [];
  const seen = new Set<number>([input.writerEpoch]);
  for (const entry of retained) {
    if (entry.epoch === input.writerEpoch) {
      throw new KeyRingOpenError(
        `retained entry collides with writerEpoch ${input.writerEpoch}`,
      );
    }
    if (seen.has(entry.epoch)) {
      throw new KeyRingOpenError(`duplicate key-ring epoch ${entry.epoch}`);
    }
    seen.add(entry.epoch);
  }
  return {
    writerEpoch: input.writerEpoch,
    entries: [{ epoch: input.writerEpoch, root: input.writerRoot }, ...retained],
  };
}
