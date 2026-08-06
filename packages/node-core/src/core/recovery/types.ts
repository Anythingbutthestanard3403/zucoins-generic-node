// Seams and result types for the restore / recovery-verification ceremony and the
// vault master-key rotation ceremony.
//
// CUSTODY: no seam in this file ever hands a private key or the vault master key to the
// ceremony. The master key enters the seam implementation FRESH from the operator through an
// interactive secret channel — never argv, never a persistent env var, never the live
// node's boot-derived root — and per-wallet secrets exist only inside the seam's own process
// memory behind an opaque handle. The ceremony receives derived PUBLIC keys, digests, and
// signatures only, so nothing it holds, returns, or persists can leak key material (golden
// rule 5).

import type { ActiveLeaseRecord, VaultSigner } from "../signer-boundary.js";
import type { BackupArchive } from "../backup/types.js";

// ---------------------------------------------------------------------------
// Restore / recovery-verification ceremony
// ---------------------------------------------------------------------------

/** The authoritative `wallets` columns the ceremony reads. Never written by this ceremony
 * except through the step (e) stamping transaction. */
export interface RecoveryWalletRow {
  readonly walletId: string;
  readonly publicKey: string;
  readonly recoveryVerifiedAt: string | null;
}

/** Restored-instance access to per-wallet key material. Both members keep the 64-byte secret
 * inside the seam: `openAndDerivePublicKey` returns only the derived public key, and `sign`
 * (the `VaultSigner` seam) returns only a signature. */
export interface RestoredVaultAccess extends VaultSigner {
  /** Open the restored `vault` row in seam-process memory, derive the public key, and return
   * it as padded base64url. Returns null on any GCM / AAD / version / length failure so the
   * wallet fails closed (step a). */
  openAndDerivePublicKey(walletId: string): Promise<string | null>;
}

/** The fresh isolated restore instance. It holds no operational role for its
 * whole life: it never joins a network, never runs money workers, never takes signer
 * leadership, and never reports readiness (Phase 1). */
export interface RestoredInstance {
  /** Phase 1 — load every covered row. All-or-nothing: a failure must leave the instance with
   * no partially-populated vault. The ceremony independently audits completeness afterwards
   * and aborts if the instance disagrees with the manifest. */
  restore(archive: BackupArchive): Promise<void>;
  /** Restored row count per covered table, compared against the manifest evidence index. */
  readRestoredRowCounts(): Promise<ReadonlyMap<string, number>>;
  /** Exclusion witness: restore creates NO `wallet_active_leases` rows. */
  countActiveLeases(): Promise<number>;
  readWallet(walletId: string): Promise<RecoveryWalletRow | null>;
  /** Acquire the per-wallet `RECONCILIATION` lease the probe signs under — one wallet at a
   * time, never two concurrently (Phase 2). */
  acquireReconciliationLease(walletId: string): Promise<ActiveLeaseRecord>;
  releaseReconciliationLease(walletId: string): Promise<void>;
  /** Re-read of the current lease row the signer boundary performs before decrypting. */
  readActiveLease(walletId: string): Promise<ActiveLeaseRecord | null>;
  /** Phase 3 HARD STEP — the instance is itself a secret-class artifact and never persists
   * beyond the ceremony (Phase 3). Must be idempotent: the ceremony calls it on every
   * exit path, including aborts before any restore ran. */
  destroy(): Promise<void>;
}

/** The one live-database transaction per stamped wallet (step e): one `audit_log`
 * insert, one `wallet_recovery_verifications` insert, and the two-column `wallets` stamp.
 * `verified_at` and `recovery_verified_at` are the SAME value, written together. Carries only
 * public keys, digests, and signatures — no key-derived value. */
export interface RecoveryStampInput {
  readonly ceremonyId: string;
  readonly walletId: string;
  readonly method: "AUDITED_EXPORT";
  readonly publicKey: string;
  readonly keyVersion: number;
  readonly exportId: string;
  readonly exportSha256: string;
  readonly verifierIdentity: string;
  readonly censusMatchedRestored: true;
  readonly censusMatchedLive: true;
  readonly archivedProofVerified: true;
  readonly probeSignature: string;
  readonly probePreimageSha256: string;
  readonly probeVerified: true;
}

/** The Phase 3 ceremony-summary `audit_log` row. */
export interface RecoveryCeremonySummary {
  readonly ceremonyId: string;
  readonly exportId: string;
  readonly manifestSha256: string;
  readonly verifierIdentity: string;
  readonly stamped: readonly string[];
  readonly failedClosed: readonly string[];
  readonly skipped: readonly string[];
  readonly bornBlocked: readonly string[];
}

/** Live-database seam. Least privilege (step e): read-only cross-checks plus INSERT on
 * `audit_log` / `wallet_recovery_verifications` and UPDATE of exactly the two stamp columns
 * on `wallets`. There is no other live-database write anywhere in the ceremony. */
export interface RecoveryLiveDatabase {
  /** Read-only. Every live `wallets` row, keyed by `wallet_id`. */
  readWallets(): Promise<ReadonlyMap<string, RecoveryWalletRow>>;
  /** Read-only possession proof for the CURRENT master key (Phase 2 preamble). Opens
   * one current-epoch live `vault` row inside the seam and compares the derived public key.
   * Never a recovery probe against the live vault, and never a live write. */
  proveCurrentKeyPossession(): Promise<boolean>;
  /** Existing evidence for `(wallet_id, export_sha256)` — drives the idempotent skip
   *. */
  hasRecoveryVerification(walletId: string, exportSha256: string): Promise<boolean>;
  stampRecoveryVerification(input: RecoveryStampInput): Promise<void>;
  appendCeremonySummary(summary: RecoveryCeremonySummary): Promise<void>;
}

export interface RestoreCeremonyInput {
  readonly ceremonyId: string;
  /** 128-bit CSPRNG value minted once per ceremony run — what makes the probe fresh. */
  readonly ceremonyNonce: string;
  readonly issuedAt: string;
  /** The authenticated node-local operator admin identity. Never key-derived, never a
   * platform identity. */
  readonly verifierIdentity: string;
  readonly liveNodeId: string;
  readonly archiveText: string;
  readonly restoredInstance: RestoredInstance;
  readonly restoredVault: RestoredVaultAccess;
  readonly liveDatabase: RecoveryLiveDatabase;
}

/** Static abort reasons — never the rejected value, so a log cannot echo secret-class
 * material. An abort is all-or-nothing: zero stamps and zero evidence rows. */
export type RestoreAbortReason =
  | "archive_rejected"
  | "cross_node_mismatch"
  | "restore_incomplete"
  | "restored_active_lease_present"
  | "current_key_possession_failed";

export type WalletCeremonyOutcome = "stamped" | "failed_closed" | "skipped";

export interface RestoreCeremonyResult {
  readonly ceremonyId: string;
  /** True only when Phase 0 acceptance, cross-node acceptance, and the restore-completeness
   * audit all passed. False means zero stamps were written. */
  readonly accepted: boolean;
  readonly abortReasons: readonly RestoreAbortReason[];
  /** The rejection reasons behind an `archive_rejected` abort. */
  readonly archiveRejectionReasons: readonly string[];
  /** Live `wallets` rows absent from the manifest: reported born-blocked, never stamped
   * (Phase 0b). */
  readonly bornBlocked: readonly string[];
  readonly outcomes: ReadonlyMap<string, WalletCeremonyOutcome>;
  readonly restoreComplete: boolean;
  readonly restoredActiveLeaseCount: number;
  readonly summaryWritten: boolean;
  readonly instanceDestroyed: boolean;
}

// ---------------------------------------------------------------------------
// Vault master-key rotation ceremony
// ---------------------------------------------------------------------------

/** A `vault` row as the rotation ceremony sees it. Encoded values are padded base64url;
 * `ciphertextSha256` is 64 lowercase hex. */
export interface RotationVaultRow {
  readonly walletId: string;
  readonly keyVersion: number;
  readonly ciphertext: string;
  readonly nonce: string;
  readonly authTag: string;
  readonly ciphertextSha256: string;
}

/** The immutable `wallets` columns rotation reads and never writes. */
export interface RotationWallet {
  readonly walletId: string;
  readonly publicKey: string;
  readonly keyOrigin: string;
  readonly row: RotationVaultRow;
}

/** Opaque handle to a decrypted secret held inside the crypto seam's own memory. The ceremony
 * can pass it back to the seam but can never read key bytes through it. */
export interface RotationSecretHandle {
  readonly walletId: string;
}

/** Custody seam for rotation. Every key operation happens inside the seam; the ceremony owns
 * only the discipline (sequence, verification, abort). */
export interface RotationCrypto {
  /** Open a sealed row under the given epoch's master key. Returns null on any GCM / AAD /
   * version / length failure — an unreadable row aborts the whole rotation. */
  open(row: RotationVaultRow, epoch: "old" | "new"): Promise<RotationSecretHandle | null>;
  /** Derive the public key from the handle's secret, as padded base64url. */
  derivePublicKey(handle: RotationSecretHandle): Promise<string>;
  /** Re-seal the handle's secret under the NEW master key at `nextKeyVersion`, with a fresh
   * 96-bit CSPRNG nonce. Returns the new envelope; never the secret. */
  reseal(handle: RotationSecretHandle, nextKeyVersion: number): Promise<RotationVaultRow>;
  /** Zeroize the handle's buffers where the runtime permits (guard 5). */
  wipe(handle: RotationSecretHandle): Promise<void>;
}

/** The exclusive node signing interlock rotation runs under: rotation is the sole
 * all-envelope writer and quiesces signing for the whole ceremony (guard 4). */
export interface NodeSigningInterlock {
  acquire(): Promise<void>;
  release(): Promise<void>;
}

export interface RotateVaultMasterKeyInput {
  readonly wallets: readonly RotationWallet[];
  readonly crypto: RotationCrypto;
  readonly interlock: NodeSigningInterlock;
  /** Commit every rewrapped row value-preservingly. Takes `vault` rows ONLY — rotation has no
   * way to reach `wallets.recovery_verified_at`, `recovery_verification_id`, `public_key`, or
   * `key_origin`, which rotation must never touch (monotonic and immutable).
   * Called exactly once, after every row has round-tripped; never called on an abort. */
  commit(rows: readonly RotationVaultRow[]): Promise<void>;
}

export type RotationAbortReason =
  | "row_unreadable"
  | "public_key_mismatch_before"
  | "reseal_failed"
  | "key_version_not_advanced"
  | "ciphertext_digest_mismatch"
  | "nonce_reuse"
  | "round_trip_unreadable"
  | "public_key_mismatch_after"
  | "commit_failed";

/** SOURCE: generic-node-contracts `src/vault/lifecycle.contract.ts` ROTATION_STATES. This
 * ceremony commits in one transaction, so an abort rolls back to STABLE and the intermediate
 * ROTATING state is never observable as a mixed old/new `key_version` population. */
export type RotationState = "ROTATION_COMPLETE" | "ABORTED";

export interface RotationResult {
  readonly state: RotationState;
  readonly rowsRewrapped: number;
  readonly abort: { readonly reason: RotationAbortReason; readonly walletId: string | null } | null;
}
