// Vault master-key rotation ceremony (wallet-vault model guards 3–4;
// generic-node-contracts `src/vault/lifecycle.contract.ts`).
//
// Vault master-key rotation rewraps every ciphertext under an exclusive node signing
// interlock, verifies each round trip, and commits value-preservingly. Any unreadable row
// aborts the whole rotation.
//
// Rotation preserves the underlying key, so it NEVER touches `wallets.recovery_verified_at` or
// `recovery_verification_id` — those are monotonic and only the restore /
// recovery-verification ceremony writes them. Replacement key generation is a different flow
// entirely: mint a new wallet, move funds via the blessed sink, retire the old one (autoscale floor and cap).
// `commit` here accepts `vault` rows only, so rotation has no way to reach those columns, or
// `wallets.public_key` / `key_origin`, at all.
//
// CRASH SAFETY: the whole rotation is rewrapped and verified in memory first and committed in
// ONE transaction, so a crash or an abort at any point leaves every row at its pre-rotation
// key version — never a row readable under neither key, and never a mixed old/new population.
// That is the strictest reading of the lifecycle contract's
// `unreadable_or_failed_pubkey_row_aborts_without_advancing_writer_version`: the ROTATING state
// is simply never observable.
// ponytail: one transaction over the whole vault. If a vault ever grows past what a single
// transaction can hold, the upgrade path is the lifecycle contract's resumable ROTATING state
// with a committed rotation-complete marker and a boot key-ring that reads a mixed key_version
// population — strictly more machinery, and only worth it at that scale.

import {
  backupSha256HexBytes,
  compareBackupByteSequence,
  decodeBackupBase64Url,
} from "../backup/crypto.js";
import type {
  RotateVaultMasterKeyInput,
  RotationAbortReason,
  RotationResult,
  RotationVaultRow,
  RotationWallet,
} from "./types.js";

function aborted(reason: RotationAbortReason, walletId: string | null): RotationResult {
  return { state: "ABORTED", rowsRewrapped: 0, abort: { reason, walletId } };
}

const nonceKey = (row: Pick<RotationVaultRow, "keyVersion" | "nonce">): string =>
  `${row.keyVersion} ${row.nonce}`;

/** Rewrap one wallet and prove the round trip: open under the old key, assert the derived
 * public key still equals the authoritative `wallets.public_key`, re-seal under the new key,
 * then open the NEW envelope and assert the same public key again. Returns the new row, or
 * the abort reason for the whole rotation. */
async function rewrapAndVerify(
  wallet: RotationWallet,
  crypto: RotateVaultMasterKeyInput["crypto"],
): Promise<{ row: RotationVaultRow } | { reason: RotationAbortReason }> {
  const oldHandle = await crypto.open(wallet.row, "old");
  if (oldHandle === null) return { reason: "row_unreadable" };

  let rewrapped: RotationVaultRow;
  try {
    if ((await crypto.derivePublicKey(oldHandle)) !== wallet.publicKey) {
      return { reason: "public_key_mismatch_before" };
    }
    try {
      rewrapped = await crypto.reseal(oldHandle, wallet.row.keyVersion + 1);
    } catch {
      return { reason: "reseal_failed" };
    }
  } finally {
    await crypto.wipe(oldHandle);
  }

  if (rewrapped.walletId !== wallet.walletId) return { reason: "reseal_failed" };
  if (rewrapped.keyVersion !== wallet.row.keyVersion + 1) {
    return { reason: "key_version_not_advanced" };
  }

  // The re-sealed row must carry the digest of its own ciphertext: a mismatch means the row
  // that would be committed does not describe the bytes it contains.
  const ciphertextBytes = decodeBackupBase64Url(rewrapped.ciphertext);
  if (ciphertextBytes === null) return { reason: "ciphertext_digest_mismatch" };
  if (backupSha256HexBytes(ciphertextBytes) !== rewrapped.ciphertextSha256) {
    return { reason: "ciphertext_digest_mismatch" };
  }

  const newHandle = await crypto.open(rewrapped, "new");
  if (newHandle === null) return { reason: "round_trip_unreadable" };
  try {
    if ((await crypto.derivePublicKey(newHandle)) !== wallet.publicKey) {
      return { reason: "public_key_mismatch_after" };
    }
  } finally {
    await crypto.wipe(newHandle);
  }

  return { row: rewrapped };
}

export async function rotateVaultMasterKey(
  input: RotateVaultMasterKeyInput,
): Promise<RotationResult> {
  // Rotation is the only all-envelope writer and quiesces signing for its whole duration.
  await input.interlock.acquire();
  try {
    // Canonical wallet-id sequence, matching the lifecycle contract's
    // QUIESCES_SIGNING_LOCKS_CANONICAL_WALLET_ID_SEQUENCE.
    const wallets = [...input.wallets].sort((a, b) =>
      compareBackupByteSequence(a.walletId, b.walletId),
    );

    // The `vault` UNIQUE (key_version, nonce) guard has to hold ACROSS the rotation, not just
    // within it: a re-sealed row may not reuse any nonce already present at its new key
    // version, including one carried by a pre-rotation row.
    const seenNonces = new Set(input.wallets.map((wallet) => nonceKey(wallet.row)));

    const rewrappedRows: RotationVaultRow[] = [];
    for (const wallet of wallets) {
      const outcome = await rewrapAndVerify(wallet, input.crypto);
      if ("reason" in outcome) return aborted(outcome.reason, wallet.walletId);
      if (seenNonces.has(nonceKey(outcome.row))) return aborted("nonce_reuse", wallet.walletId);
      seenNonces.add(nonceKey(outcome.row));
      rewrappedRows.push(outcome.row);
    }

    try {
      await input.commit(rewrappedRows);
    } catch {
      return aborted("commit_failed", null);
    }
    return { state: "ROTATION_COMPLETE", rowsRewrapped: rewrappedRows.length, abort: null };
  } finally {
    await input.interlock.release();
  }
}
