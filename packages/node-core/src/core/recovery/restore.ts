// The restore and recovery-verification ceremony — the only mechanism that may write
// `wallets.recovery_verified_at` / `recovery_verification_id`. It consumes a backup
// archive and nothing else, and it is FULLY OFFLINE:
// no gateway interaction and no chain read anywhere.
//
// Two disjoint failure classes govern the whole ceremony: an ACCEPTANCE failure
// aborts everything with ZERO stamps and zero evidence writes; a POST-ACCEPTANCE per-wallet
// probe failure fails THAT wallet closed and unstamped and leaves siblings unaffected.
//
// Restore confers no trust: the restored instance never takes signer leadership and is
// destroyed at Phase 3, and a node booting from a restored database still re-runs the whole
// boot sequence — including step 2's open-probe, which quarantines any failing wallet
// regardless of this ceremony's earlier pass.
// What this ceremony enables is per-wallet: a wallet is born blocked, and only the step (e)
// stamp lets it be leased, armed, or made an automatic sink.

import {
  BACKUP_WALLET_PREIMAGE_FIELD_SEQUENCE,
  verifyBackupArchive,
} from "../backup/index.js";
import {
  backupSha256HexUtf8,
  buildManifestPreimageText,
  buildWalletExportPreimageText,
  compareBackupByteSequence,
  verifyBackupSignature,
} from "../backup/crypto.js";
import type { BackupArchive, BackupWalletSection } from "../backup/types.js";
import {
  signUnderLease,
  type MoneyPathSignerGates,
  type SignerAuditEntryOf,
  type SigningResult,
} from "../signer-boundary.js";
import {
  buildRecoveryProbePayload,
  buildRecoveryProbePreimageText,
  RECOVERY_VERIFICATION_PURPOSE,
  type RecoveryVerificationPurpose,
} from "./probe.js";
import type {
  RecoveryWalletRow,
  RestoreAbortReason,
  RestoreCeremonyInput,
  RestoreCeremonyResult,
  RestoredInstance,
  WalletCeremonyOutcome,
} from "./types.js";

/** The signed preimage for a wallet section: purpose + LF + JSON.stringify(fields 1–9).
 * The section object already carries its keys in the frozen sequence, so rebuilding it from
 * that sequence and stringifying once emits the exact bytes (the byte-exact signing rule). */
function walletExportPreimage(section: BackupWalletSection): string {
  const payload = Object.fromEntries(
    BACKUP_WALLET_PREIMAGE_FIELD_SEQUENCE.map((field) => [
      field,
      (section as unknown as Record<string, unknown>)[field],
    ]),
  );
  return buildWalletExportPreimageText(payload);
}

function abortResult(
  input: RestoreCeremonyInput,
  reasons: readonly RestoreAbortReason[],
  extra: Partial<RestoreCeremonyResult> = {},
): RestoreCeremonyResult {
  return {
    ceremonyId: input.ceremonyId,
    accepted: false,
    abortReasons: reasons,
    archiveRejectionReasons: [],
    bornBlocked: [],
    outcomes: new Map<string, WalletCeremonyOutcome>(),
    restoreComplete: false,
    restoredActiveLeaseCount: 0,
    summaryWritten: false,
    instanceDestroyed: false,
    ...extra,
  };
}

// Phase 1 completeness audit. The restore seam promises all-or-nothing, but a partially
// populated instance is the exact failure this ceremony exists to prevent — a node that signs
// with a wrong, stale, or missing key — so the ceremony verifies the claim itself rather than
// trusting it: every covered table's restored row count must equal the manifest's declared
// count, and every wallet section must have a restored `wallets` row whose public key is
// byte-equal to the section's.
async function restoreIsComplete(
  instance: RestoredInstance,
  archive: BackupArchive,
): Promise<boolean> {
  const counts = await instance.readRestoredRowCounts();
  for (const entry of archive.manifest.evidence_index) {
    if (counts.get(entry.table) !== entry.row_count) return false;
  }
  for (const section of archive.wallet_sections) {
    const restored = await instance.readWallet(section.wallet_id);
    if (restored === null || restored.publicKey !== section.public_key) return false;
  }
  return true;
}

export async function runRestoreRecoveryCeremony(
  input: RestoreCeremonyInput,
): Promise<RestoreCeremonyResult> {
  let result: RestoreCeremonyResult;
  try {
    result = await runCeremonyPhases(input);
  } finally {
    // Phase 3 HARD STEP — the restored instance carries everything the archive carries and
    // never persists beyond the ceremony, on every exit path including aborts and throws.
    await input.restoredInstance.destroy();
  }
  return { ...result, instanceDestroyed: true };
}

async function runCeremonyPhases(
  input: RestoreCeremonyInput,
): Promise<RestoreCeremonyResult> {
  const { restoredInstance, liveDatabase } = input;

  // Phase 0a — archive acceptance (all-or-nothing). Nothing is restored or stamped
  // until this passes, so a partial or tampered archive can never partially stamp.
  const acceptance = verifyBackupArchive(input.archiveText);
  if (!acceptance.ok) {
    return abortResult(input, ["archive_rejected"], {
      archiveRejectionReasons: acceptance.reasons,
    });
  }
  const archive = JSON.parse(input.archiveText) as BackupArchive;

  // Phase 0b — cross-node acceptance, read-only against the live database, plus the
  // born-blocked census. A wallet minted after `exported_at` has no section and no provable
  // coverage: it is reported, never silently omitted and never stamped.
  const liveWallets = await liveDatabase.readWallets();
  const sectionIds = new Set(archive.wallet_sections.map((section) => section.wallet_id));
  const bornBlocked = [...liveWallets.keys()]
    .filter((walletId) => !sectionIds.has(walletId))
    .sort(compareBackupByteSequence);

  const crossNodeOk =
    archive.manifest.node_id === input.liveNodeId &&
    archive.wallet_sections.every((section) => {
      const live = liveWallets.get(section.wallet_id);
      return (
        section.node_id === input.liveNodeId &&
        live !== undefined &&
        live.publicKey === section.public_key
      );
    });
  if (!crossNodeOk) {
    return abortResult(input, ["cross_node_mismatch"], { bornBlocked });
  }

  // Phase 1 — fresh-database restore, then the completeness audit.
  await restoredInstance.restore(archive);
  const restoredActiveLeaseCount = await restoredInstance.countActiveLeases();
  if (restoredActiveLeaseCount !== 0) {
    // The archive excludes `wallet_active_leases`; exclusivity is re-derived by boot
    // reconciliation, never from the archive.
    return abortResult(input, ["restored_active_lease_present"], {
      bornBlocked,
      restoredActiveLeaseCount,
    });
  }
  if (!(await restoreIsComplete(restoredInstance, archive))) {
    return abortResult(input, ["restore_incomplete"], { bornBlocked });
  }

  // Phase 2 preamble — CURRENT-key possession, once per ceremony. The gate must not stamp when
  // the current key is lost, however recoverable the archive epoch is.
  if (!(await liveDatabase.proveCurrentKeyPossession())) {
    return abortResult(input, ["current_key_possession_failed"], {
      bornBlocked,
      restoreComplete: true,
    });
  }

  // Phase 2 — per-wallet proof, ascending `wallet_id` byte sequence, one wallet at a time.
  const outcomes = new Map<string, WalletCeremonyOutcome>();
  const sections = [...archive.wallet_sections].sort((a, b) =>
    compareBackupByteSequence(a.wallet_id, b.wallet_id),
  );
  for (const section of sections) {
    outcomes.set(
      section.wallet_id,
      await proveAndStampWallet(input, archive, section, liveWallets),
    );
  }

  // Phase 3 — one ceremony-summary audit row on the live database.
  const byOutcome = (want: WalletCeremonyOutcome): string[] =>
    [...outcomes.entries()].filter(([, outcome]) => outcome === want).map(([id]) => id);
  await liveDatabase.appendCeremonySummary({
    ceremonyId: input.ceremonyId,
    exportId: archive.manifest.export_id,
    manifestSha256: backupSha256HexUtf8(buildManifestPreimageText(archive.manifest)),
    verifierIdentity: input.verifierIdentity,
    stamped: byOutcome("stamped"),
    failedClosed: byOutcome("failed_closed"),
    skipped: byOutcome("skipped"),
    bornBlocked,
  });

  return {
    ceremonyId: input.ceremonyId,
    accepted: true,
    abortReasons: [],
    archiveRejectionReasons: [],
    bornBlocked,
    outcomes,
    restoreComplete: true,
    restoredActiveLeaseCount,
    summaryWritten: true,
    instanceDestroyed: false,
  };
}

/** Steps (a)–(e) for one wallet. Any failure in (a)–(d) means the step (e) transaction never
 * begins: that wallet has no evidence row and no stamp, and siblings are unaffected. */
async function proveAndStampWallet(
  input: RestoreCeremonyInput,
  archive: BackupArchive,
  section: BackupWalletSection,
  liveWallets: ReadonlyMap<string, RecoveryWalletRow>,
): Promise<WalletCeremonyOutcome> {
  const walletId = section.wallet_id;
  const proofPreimage = walletExportPreimage(section);
  const exportSha256 = backupSha256HexUtf8(proofPreimage);

  // A repeat ceremony over an already-recorded (wallet_id, export_sha256)
  // skips that wallet: the existing evidence and stamp are untouched, and a skip is not an
  // error. Evidence is append-only; there is never a delete-and-reinsert.
  if (await input.liveDatabase.hasRecoveryVerification(walletId, exportSha256)) {
    return "skipped";
  }

  // Fresh live export always produces a new export_sha256. Without this gate, a second
  // ceremony after a partial first run re-probes already-stamped wallets, the stamp UPDATE
  // matches zero rows (`recovery_verified_at IS NULL`), and stampRecoveryVerification throws —
  // aborting the whole run before any still-unstamped sibling (e.g. a destination mint) can
  // stamp. Live stamp is monotonic; skip is correct, not a second stamp.
  const livePrecheck = liveWallets.get(walletId);
  if (livePrecheck !== undefined && livePrecheck.recoveryVerifiedAt !== null) {
    return "skipped";
  }

  await input.restoredInstance.acquireReconciliationLease(walletId);
  try {
    // (a) Open the restored vault row in seam-process memory.
    const derivedPublicKey = await input.restoredVault.openAndDerivePublicKey(walletId);
    if (derivedPublicKey === null) return "failed_closed";

    // (b) Public-key census — the primary substitution control re-run post-restore,
    // against BOTH the restored row and the live authoritative row.
    const restoredWallet = await input.restoredInstance.readWallet(walletId);
    const liveWallet = liveWallets.get(walletId);
    if (restoredWallet === null || liveWallet === undefined) return "failed_closed";
    if (derivedPublicKey !== restoredWallet.publicKey) return "failed_closed";
    if (derivedPublicKey !== liveWallet.publicKey) return "failed_closed";
    // Re-check after the lease window: a concurrent ceremony may have stamped this wallet.
    if (liveWallet.recoveryVerifiedAt !== null) {
      return "skipped";
    }

    // (c) Archived-proof verification against the RECOMPUTED digest, never a node-reported one.
    const manifestEntry = archive.manifest.wallets.find((entry) => entry.wallet_id === walletId);
    if (manifestEntry === undefined || manifestEntry.export_sha256 !== exportSha256) {
      return "failed_closed";
    }
    if (
      !verifyBackupSignature({
        publicKeyBase64Url: derivedPublicKey,
        preimageText: proofPreimage,
        signatureBase64Url: section.export_proof_signature,
      })
    ) {
      return "failed_closed";
    }

    // (d) Fresh sign-capability probe. It goes through the PRODUCTION signer boundary
    // — `signUnderLease`, the same function the money path calls — so the probe proves the
    // real signing path works post-restore, not a parallel restore-only path. The boundary
    // re-reads the restored `RECONCILIATION` lease before the seam decrypts.
    // Recovery is fully offline; money-admission gates are omitted here because readiness and
    // storage backpressure are not meaningful. The boundary always requires gates (
    // AC8); internal callers supply gates with appropriate behaviour.
    const offlineMoneyGates: MoneyPathSignerGates = {
      assertMoneyAdmitted: () => {},
      assertCanOperate: () => {},
      assertWalletMaySign: async () => {},
    };
    const probePreimage = buildRecoveryProbePreimageText(
      buildRecoveryProbePayload({
        nodeId: input.liveNodeId,
        walletId,
        publicKey: derivedPublicKey,
        keyVersion: section.key_version,
        exportId: archive.manifest.export_id,
        exportSha256,
        ceremonyId: input.ceremonyId,
        ceremonyNonce: input.ceremonyNonce,
        issuedAt: input.issuedAt,
      }),
    );
    const lease = await input.restoredInstance.readActiveLease(walletId);
    if (lease === null) return "failed_closed";

    const probeAudit: SignerAuditEntryOf<RecoveryVerificationPurpose>[] = [];
    let probe: SigningResult;
    try {
      probe = await signUnderLease<RecoveryVerificationPurpose>(
        {
          // The ONE standing latch in the codebase. The restored instance is isolated, holds
          // its own database, and by frozen contract never takes process leadership — so
          // there is no lock for it to consult and no second signer to exclude. Every
          // other caller of this boundary must pass the real latch.
          leadership: { held: true },
          leaseReader: input.restoredInstance,
          vaultSigner: input.restoredVault,
          auditLog: {
            append: async (entry) => {
              probeAudit.push(entry);
            },
          },
          now: () => input.issuedAt,
          ...offlineMoneyGates,
        },
        {
          walletId,
          operationId: lease.operationId,
          leaseEpoch: lease.epoch,
          purpose: RECOVERY_VERIFICATION_PURPOSE,
          preimageText: probePreimage,
          expectedPreimageSha256: backupSha256HexUtf8(probePreimage),
        },
      );
    } catch {
      return "failed_closed";
    }
    if (probeAudit.at(-1)?.outcome !== "SIGNED") return "failed_closed";
    if (
      !verifyBackupSignature({
        publicKeyBase64Url: liveWallet.publicKey,
        preimageText: probePreimage,
        signatureBase64Url: probe.signature,
      })
    ) {
      return "failed_closed";
    }

    // (e) The one live-database transaction for this wallet.
    await input.liveDatabase.stampRecoveryVerification({
      ceremonyId: input.ceremonyId,
      walletId,
      method: "AUDITED_EXPORT",
      publicKey: derivedPublicKey,
      keyVersion: section.key_version,
      exportId: archive.manifest.export_id,
      exportSha256,
      verifierIdentity: input.verifierIdentity,
      censusMatchedRestored: true,
      censusMatchedLive: true,
      archivedProofVerified: true,
      probeSignature: probe.signature,
      probePreimageSha256: probe.preimageSha256,
      probeVerified: true,
    });
    return "stamped";
  } finally {
    await input.restoredInstance.releaseReconciliationLease(walletId);
  }
}
