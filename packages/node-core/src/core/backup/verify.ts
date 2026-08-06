// Backup archive verifier. Validates archive integrity WITHOUT a full restore: it
// re-derives every digest from the archived bytes, checks the wallet-key proofs and the node
// identity manifest signature using only public keys carried in the archive, and enforces the
// frozen field/coverage sequence. Acceptance is all-or-nothing and fail-closed — any violation
// rejects the whole archive. No private key is required or touched (the key-custody rule).

import {
  BACKUP_ARCHIVE_FIELD_SEQUENCE,
  BACKUP_CANONICAL_VERSION,
  BACKUP_COVERAGE_TABLES,
  BACKUP_EVIDENCE_INDEX_FIELD_SEQUENCE,
  BACKUP_EVIDENCE_SECTION_FIELD_SEQUENCE,
  BACKUP_FORMAT,
  BACKUP_MANIFEST_FIELD_SEQUENCE,
  BACKUP_MANIFEST_PURPOSE,
  BACKUP_MANIFEST_SIGNING_KEY_FIELD_SEQUENCE,
  BACKUP_MANIFEST_WALLET_FIELD_SEQUENCE,
  BACKUP_NODE_GENERATED_ORIGIN,
  BACKUP_VAULT_FIELD_SEQUENCE,
  BACKUP_WALLET_EXPORT_PURPOSE,
  BACKUP_WALLET_PREIMAGE_FIELD_SEQUENCE,
  BACKUP_WALLET_SECTION_FIELD_SEQUENCE,
} from "./format.js";
import {
  backupSha256HexUtf8,
  buildManifestPreimageText,
  buildWalletExportPreimageText,
  compareBackupByteSequence,
  computeBackupSettingsDigest,
  computeBackupTableDigest,
  verifyBackupSignature,
} from "./crypto.js";
import type {
  BackupArchive,
  BackupManifest,
  BackupRejectionReason,
  BackupVerificationResult,
  BackupWalletSection,
} from "./types.js";

function keysMatchSequence(object: object, expected: readonly string[]): boolean {
  const keys = Object.keys(object);
  if (keys.length !== expected.length) return false;
  return keys.every((key, i) => key === expected[i]);
}

export function verifyBackupArchive(archiveText: string): BackupVerificationResult {
  const reasons = new Set<BackupRejectionReason>();
  const add = (reason: BackupRejectionReason): void => {
    reasons.add(reason);
  };

  let parsed: unknown;
  try {
    parsed = JSON.parse(archiveText);
  } catch {
    return { ok: false, reasons: ["malformed_json"] };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, reasons: ["malformed_json"] };
  }

  // Canonical-byte check: a conforming archive is a single compact JSON.stringify pass, so a
  // parse→stringify round trip must reproduce the input bytes exactly (catches BOM, whitespace,
  // trailing newline, and any re-serialization drift).
  if (JSON.stringify(parsed) !== archiveText) add("non_canonical_bytes");

  const archive = parsed as BackupArchive;
  if (!keysMatchSequence(archive, BACKUP_ARCHIVE_FIELD_SEQUENCE)) add("field_set_mismatch");
  if (archive.format !== BACKUP_FORMAT) add("unknown_format");

  const manifest = archive.manifest;
  if (typeof manifest !== "object" || manifest === null) {
    add("field_set_mismatch");
    return finish(reasons);
  }
  if (!keysMatchSequence(manifest, BACKUP_MANIFEST_FIELD_SEQUENCE)) add("field_set_mismatch");
  if (manifest.purpose !== BACKUP_MANIFEST_PURPOSE) add("field_set_mismatch");
  if (manifest.canonical_version !== BACKUP_CANONICAL_VERSION) add("field_set_mismatch");
  if (manifest.format !== BACKUP_FORMAT) add("unknown_format");

  verifyWalletSections(archive, manifest, add);
  verifyEvidence(archive, manifest, add);
  verifySettings(archive, manifest, add);
  verifyManifestSignature(manifest, archive.manifest_signature, add);

  return finish(reasons);
}

function finish(reasons: Set<BackupRejectionReason>): BackupVerificationResult {
  if (reasons.size === 0) return { ok: true };
  return { ok: false, reasons: [...reasons] };
}

function walletPreimageText(section: BackupWalletSection): string {
  const payload: Record<string, unknown> = {};
  for (const key of BACKUP_WALLET_PREIMAGE_FIELD_SEQUENCE) {
    payload[key] = (section as unknown as Record<string, unknown>)[key];
  }
  return buildWalletExportPreimageText(payload);
}

function verifyWalletSections(
  archive: BackupArchive,
  manifest: BackupManifest,
  add: (reason: BackupRejectionReason) => void,
): void {
  const sections = archive.wallet_sections;
  if (!Array.isArray(sections)) {
    add("field_set_mismatch");
    return;
  }

  const walletsRowPublicKey = new Map<string, string>();
  const walletsSection = (archive.evidence_sections ?? []).find((s) => s.table === "wallets");
  if (walletsSection !== undefined) {
    for (const row of walletsSection.rows) {
      const walletId = row.wallet_id;
      const publicKey = row.public_key;
      if (typeof walletId === "string" && typeof publicKey === "string") {
        walletsRowPublicKey.set(walletId, publicKey);
      }
    }
  }

  const manifestByWallet = new Map<string, string>();
  for (const entry of manifest.wallets ?? []) {
    if (!keysMatchSequence(entry, BACKUP_MANIFEST_WALLET_FIELD_SEQUENCE)) add("field_set_mismatch");
    manifestByWallet.set(entry.wallet_id, entry.export_sha256);
  }

  const sectionWalletIds = new Set<string>();
  for (let i = 0; i < sections.length; i += 1) {
    const section = sections[i]!;
    if (!keysMatchSequence(section, BACKUP_WALLET_SECTION_FIELD_SEQUENCE)) add("field_set_mismatch");
    if (!keysMatchSequence(section.vault, BACKUP_VAULT_FIELD_SEQUENCE)) add("field_set_mismatch");
    if (section.purpose !== BACKUP_WALLET_EXPORT_PURPOSE) add("field_set_mismatch");

    if (i > 0 && compareBackupByteSequence(sections[i - 1]!.wallet_id, section.wallet_id) >= 0) {
      add("bad_wallet_sequence");
    }
    if (sectionWalletIds.has(section.wallet_id)) add("duplicate_wallet_section");
    sectionWalletIds.add(section.wallet_id);

    if (section.key_origin !== BACKUP_NODE_GENERATED_ORIGIN) add("bad_key_origin");

    const coveredPublicKey = walletsRowPublicKey.get(section.wallet_id);
    if (coveredPublicKey !== undefined && coveredPublicKey !== section.public_key) {
      add("public_key_mismatch");
    }

    const exportSha256 = backupSha256HexUtf8(walletPreimageText(section));
    const manifestDigest = manifestByWallet.get(section.wallet_id);
    if (manifestDigest === undefined) {
      add("manifest_section_mismatch");
    } else if (manifestDigest !== exportSha256) {
      add("export_digest_mismatch");
    }

    const proofValid = verifyBackupSignature({
      publicKeyBase64Url: section.public_key,
      preimageText: walletPreimageText(section),
      signatureBase64Url: section.export_proof_signature,
    });
    if (!proofValid) add("wallet_proof_signature_invalid");
  }

  if (manifestByWallet.size !== sectionWalletIds.size) add("manifest_section_mismatch");
  for (const walletId of manifestByWallet.keys()) {
    if (!sectionWalletIds.has(walletId)) add("manifest_section_mismatch");
  }
}

function verifyEvidence(
  archive: BackupArchive,
  manifest: BackupManifest,
  add: (reason: BackupRejectionReason) => void,
): void {
  const sections = archive.evidence_sections;
  const index = manifest.evidence_index;
  if (!Array.isArray(sections) || !Array.isArray(index)) {
    add("field_set_mismatch");
    return;
  }

  if (sections.length !== BACKUP_COVERAGE_TABLES.length) add("coverage_sequence_mismatch");
  if (index.length !== BACKUP_COVERAGE_TABLES.length) add("coverage_sequence_mismatch");

  for (let i = 0; i < BACKUP_COVERAGE_TABLES.length; i += 1) {
    const expectedTable = BACKUP_COVERAGE_TABLES[i]!;
    const section = sections[i];
    const entry = index[i];

    if (section === undefined || entry === undefined) {
      add("coverage_sequence_mismatch");
      continue;
    }
    if (!keysMatchSequence(section, BACKUP_EVIDENCE_SECTION_FIELD_SEQUENCE)) add("field_set_mismatch");
    if (!keysMatchSequence(entry, BACKUP_EVIDENCE_INDEX_FIELD_SEQUENCE)) add("field_set_mismatch");

    if (section.table !== expectedTable || entry.table !== expectedTable) {
      add("coverage_sequence_mismatch");
      continue;
    }

    const rows = Array.isArray(section.rows) ? section.rows : [];
    const tableSha256 = computeBackupTableDigest(rows);
    if (entry.table_sha256 !== tableSha256) add("table_digest_mismatch");
    if (entry.row_count !== rows.length) add("row_count_mismatch");
  }
}

function verifySettings(
  archive: BackupArchive,
  manifest: BackupManifest,
  add: (reason: BackupRejectionReason) => void,
): void {
  const snapshot = archive.settings_snapshot;
  if (typeof snapshot !== "object" || snapshot === null || !keysMatchSequence(snapshot, ["values"])) {
    add("field_set_mismatch");
    return;
  }
  const settingsSha256 = computeBackupSettingsDigest(snapshot);
  if (manifest.settings_sha256 !== settingsSha256) add("settings_digest_mismatch");
}

function verifyManifestSignature(
  manifest: BackupManifest,
  manifestSignature: string,
  add: (reason: BackupRejectionReason) => void,
): void {
  const preimageText = buildManifestPreimageText(manifest);
  const signingKeys = manifest.node_signing_keys ?? [];
  if (signingKeys.length === 0 || typeof manifestSignature !== "string") {
    add("manifest_signature_invalid");
    return;
  }
  const verified = signingKeys.some((key) => {
    if (!keysMatchSequence(key, BACKUP_MANIFEST_SIGNING_KEY_FIELD_SEQUENCE)) {
      add("field_set_mismatch");
    }
    return verifyBackupSignature({
      publicKeyBase64Url: key.public_key,
      preimageText,
      signatureBase64Url: manifestSignature,
    });
  });
  if (!verified) add("manifest_signature_invalid");
}
