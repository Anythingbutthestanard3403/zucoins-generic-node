// PUSH_RECEIVER_SECRETS master-key rewrap primitive (destination binding; push_subscriptions).
// The canonical envelope is push/seal.ts. keyVersion remains DB tracking only and is
// deliberately absent from that envelope's nodeId|walletId|purpose AAD.

import { timingSafeEqual } from "node:crypto";

import { createPushSecretSealer } from "./seal.js";
import type { PushSecretPurpose } from "./store.js";
import {
  KeyRingOpenError,
  orderEntriesForOpen,
  type VaultKeyRing,
} from "../vault/key-ring.js";
import type { SealedStoreRewrapResult } from "../vault/rewrap.js";

export type PushSecretMaterialKind = "ECDH_PRIVATE_KEY" | "AUTH_SECRET";

export interface PushSecretRewrapRow {
  readonly identity: {
    readonly nodeId: string;
    readonly walletId: string;
    readonly materialKind: PushSecretMaterialKind;
    /** Database epoch/version tracking only; never part of canonical push AAD. */
    readonly keyVersion: number;
  };
  /** Opaque zp-push-seal-v1 envelope from push/seal.ts. */
  readonly envelope: string;
}

export interface PushSecretRewrapInput {
  readonly keyRing: VaultKeyRing;
  readonly newRootKey: Uint8Array;
  readonly fromEpoch: number;
  readonly toEpoch: number;
  readonly rows: readonly PushSecretRewrapRow[];
}

function purposeFor(materialKind: PushSecretMaterialKind): PushSecretPurpose {
  return materialKind === "ECDH_PRIVATE_KEY" ? "ECDH_PRIVATE" : "AUTH_SECRET";
}

function rowKey(row: PushSecretRewrapRow): string {
  const { nodeId, walletId, materialKind, keyVersion } = row.identity;
  return `${nodeId}\u0000${walletId}\u0000${materialKind}\u0000${keyVersion}`;
}

async function openWithPushKeyRing(
  keyRing: VaultKeyRing,
  row: PushSecretRewrapRow,
): Promise<{ readonly secret: Buffer; readonly epoch: number }> {
  const purpose = purposeFor(row.identity.materialKind);
  const failures: number[] = [];
  for (const entry of orderEntriesForOpen(keyRing)) {
    try {
      const sealer = createPushSecretSealer({
        rootKey: entry.root,
        nodeId: row.identity.nodeId,
        walletId: row.identity.walletId,
      });
      return { secret: await sealer.open(row.envelope, purpose), epoch: entry.epoch };
    } catch {
      failures.push(entry.epoch);
    }
  }
  throw new KeyRingOpenError(
    `no key-ring root opened push secret (tried epochs ${failures.join(",")})`,
  );
}

/**
 * Open each census row with the old/new crash-resume key ring and, when old, seal the
 * exact plaintext under the new root using the canonical node+wallet+purpose AAD.
 */
export async function rewrapPushSecretStore(
  input: PushSecretRewrapInput,
): Promise<{
  readonly result: SealedStoreRewrapResult;
  readonly rewrappedRows: readonly PushSecretRewrapRow[];
}> {
  const seen = new Set<string>();
  const rewrappedRows: PushSecretRewrapRow[] = [];

  for (const row of input.rows) {
    const key = rowKey(row);
    if (seen.has(key)) throw new Error("rewrapPushSecretStore: duplicate push secret identity");
    seen.add(key);

    const opened = await openWithPushKeyRing(input.keyRing, row);
    try {
      if (opened.epoch === input.toEpoch) {
        rewrappedRows.push(row);
        continue;
      }
      if (opened.epoch !== input.fromEpoch) {
        throw new Error("rewrapPushSecretStore: unexpected key-ring epoch for push secret");
      }

      const purpose = purposeFor(row.identity.materialKind);
      const newSealer = createPushSecretSealer({
        rootKey: input.newRootKey,
        nodeId: row.identity.nodeId,
        walletId: row.identity.walletId,
      });
      const envelope = await newSealer.seal(opened.secret, purpose);
      const verified = await newSealer.open(envelope, purpose);
      try {
        if (
          verified.length !== opened.secret.length ||
          !timingSafeEqual(verified, opened.secret)
        ) {
          throw new Error("rewrapPushSecretStore: round-trip secret mismatch");
        }
      } finally {
        verified.fill(0);
      }
      rewrappedRows.push({ identity: row.identity, envelope });
    } finally {
      opened.secret.fill(0);
    }
  }

  const result: SealedStoreRewrapResult = {
    rowsBefore: input.rows.length,
    rowsAfter: rewrappedRows.length,
    rewrapped: rewrappedRows.length,
  };
  if (result.rowsBefore !== result.rowsAfter || result.rewrapped !== result.rowsBefore) {
    throw new Error("rewrapPushSecretStore: count parity failed");
  }
  return { result, rewrappedRows };
}
