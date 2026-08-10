// TOTP_SECRET master-key rewrap primitive.
// Canonical envelope: totp/seal.ts. AAD is the admin operator row id.

import { timingSafeEqual } from "node:crypto";

import {
  KeyRingOpenError,
  orderEntriesForOpen,
  type VaultKeyRing,
} from "../vault/key-ring.js";
import type { SealedStoreRewrapResult } from "../vault/rewrap.js";
import { openTotpSecret, sealTotpSecret } from "./seal.js";

export interface TotpSecretRewrapRow {
  readonly identity: {
    /** admin_operators.id — GCM AAD source. */
    readonly adminOperatorId: string;
  };
  /** Opaque zp-totp-seal-v1 envelope text. */
  readonly envelope: string;
}

export interface TotpSecretRewrapInput {
  readonly keyRing: VaultKeyRing;
  readonly newRootKey: Uint8Array;
  readonly fromEpoch: number;
  readonly toEpoch: number;
  readonly rows: readonly TotpSecretRewrapRow[];
}

function openWithTotpKeyRing(
  keyRing: VaultKeyRing,
  row: TotpSecretRewrapRow,
): { readonly secret: Buffer; readonly epoch: number } {
  const failures: number[] = [];
  for (const entry of orderEntriesForOpen(keyRing)) {
    try {
      return {
        secret: openTotpSecret(entry.root, row.identity.adminOperatorId, row.envelope),
        epoch: entry.epoch,
      };
    } catch {
      failures.push(entry.epoch);
    }
  }
  throw new KeyRingOpenError(
    `no key-ring root opened TOTP secret (tried epochs ${failures.join(",")})`,
  );
}

/**
 * Open each census row with the crash-resume key ring and reseal under the new root
 * with the same admin-row-id AAD. Value-preserving; count parity enforced.
 */
export function rewrapTotpSecretStore(input: TotpSecretRewrapInput): {
  readonly result: SealedStoreRewrapResult;
  readonly rewrappedRows: readonly TotpSecretRewrapRow[];
} {
  const seen = new Set<string>();
  const rewrappedRows: TotpSecretRewrapRow[] = [];

  for (const row of input.rows) {
    const key = row.identity.adminOperatorId;
    if (seen.has(key)) throw new Error("rewrapTotpSecretStore: duplicate admin operator id");
    seen.add(key);

    const opened = openWithTotpKeyRing(input.keyRing, row);
    try {
      if (opened.epoch === input.toEpoch) {
        rewrappedRows.push(row);
        continue;
      }
      if (opened.epoch !== input.fromEpoch) {
        throw new Error("rewrapTotpSecretStore: unexpected key-ring epoch for TOTP secret");
      }

      const envelope = sealTotpSecret(
        input.newRootKey,
        row.identity.adminOperatorId,
        opened.secret,
      );
      const verified = openTotpSecret(input.newRootKey, row.identity.adminOperatorId, envelope);
      try {
        if (
          verified.length !== opened.secret.length ||
          !timingSafeEqual(verified, opened.secret)
        ) {
          throw new Error("rewrapTotpSecretStore: round-trip secret mismatch");
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
    throw new Error("rewrapTotpSecretStore: count parity failed");
  }
  return { result, rewrappedRows };
}
