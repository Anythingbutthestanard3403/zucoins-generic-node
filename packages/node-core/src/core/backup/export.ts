// Backup archive exporter. Builds the single canonical `zp-node-backup-v1` JSON text
// from one consistent snapshot: per-wallet export sections with a wallet-key proof, whole-table
// evidence sections in the frozen coverage sequence, a settings snapshot, and a manifest signed
// by the node identity key. The module never holds a private key — signatures arrive through the
// caller-held signer seam (the key-custody rule); every key-material byte stays as verbatim vault /
// sealed-store ciphertext — no whole-archive wrap, no new KDF.

import {
  parseEd25519Signature,
  parseSha256Hex,
  parseUuid,
  parseWalletPublicKey,
} from "../../protocol/scalars.js";
import { encodeCanonicalTimestamp } from "../../protocol/suite/encoders.js";
import {
  BACKUP_CANONICAL_VERSION,
  BACKUP_COVERAGE_TABLES,
  BACKUP_FORMAT,
  BACKUP_MANIFEST_PURPOSE,
  BACKUP_NODE_GENERATED_ORIGIN,
  BACKUP_WALLET_EXPORT_PURPOSE,
} from "./format.js";
import {
  backupSha256HexUtf8,
  buildManifestPreimageText,
  buildWalletExportPreimageText,
  compareBackupByteSequence,
  compareBackupRows,
  computeBackupSettingsDigest,
  computeBackupTableDigest,
  decodeBackupBase64Url,
  encodeBackupBase64Url,
} from "./crypto.js";
import { BackupExportError } from "./types.js";
import type {
  BackupArchive,
  BackupArchiveVault,
  BackupEvidenceIndexEntry,
  BackupEvidenceRow,
  BackupEvidenceSection,
  BackupEvidenceTableInput,
  BackupExportResult,
  BackupManifest,
  BackupManifestSigningKeyEntry,
  BackupManifestWalletEntry,
  BackupNodeSigningKeyInput,
  BackupSnapshot,
  BackupWalletInput,
  BackupWalletSection,
} from "./types.js";

const UTF8 = new TextEncoder();

function reject(field: string, reason: string): never {
  throw new BackupExportError(field, reason);
}

function requireNonEmptyString(field: string, value: unknown): string {
  if (typeof value !== "string" || value.length === 0) reject(field, "not_a_non_empty_string");
  return value;
}

function requireBase64Url(field: string, value: unknown): string {
  if (typeof value !== "string" || decodeBackupBase64Url(value) === null) {
    reject(field, "bad_base64url");
  }
  return value;
}

function buildVault(field: string, wallet: BackupWalletInput): BackupArchiveVault {
  const vault = wallet.vault;
  if (typeof vault !== "object" || vault === null) reject(`${field}.vault`, "not_an_object");
  if (parseUuid(vault.wallet_id) !== wallet.walletId) reject(`${field}.vault.wallet_id`, "wallet_id_mismatch");
  if (vault.key_version !== wallet.keyVersion) reject(`${field}.vault.key_version`, "key_version_mismatch");
  requireBase64Url(`${field}.vault.ciphertext`, vault.ciphertext);
  requireBase64Url(`${field}.vault.nonce`, vault.nonce);
  requireBase64Url(`${field}.vault.auth_tag`, vault.auth_tag);
  parseSha256Hex(vault.ciphertext_sha256);
  encodeCanonicalTimestamp(vault.created_at);
  if (vault.rotated_at !== null) encodeCanonicalTimestamp(vault.rotated_at);
  // Schema-declared column sequence; a single JSON.stringify emits it byte-exact.
  return {
    wallet_id: vault.wallet_id,
    key_version: vault.key_version,
    ciphertext: vault.ciphertext,
    nonce: vault.nonce,
    auth_tag: vault.auth_tag,
    ciphertext_sha256: vault.ciphertext_sha256,
    created_at: vault.created_at,
    rotated_at: vault.rotated_at,
  };
}

function buildWalletSection(
  snapshot: BackupSnapshot,
  wallet: BackupWalletInput,
  index: number,
): { section: BackupWalletSection; exportSha256: string } {
  const field = `wallets[${index}]`;
  const walletId = parseUuid(wallet.walletId);
  const publicKey = parseWalletPublicKey(wallet.publicKey);
  if (wallet.keyOrigin !== BACKUP_NODE_GENERATED_ORIGIN) reject(`${field}.keyOrigin`, "not_node_generated");
  if (!Number.isInteger(wallet.keyVersion) || wallet.keyVersion <= 0) {
    reject(`${field}.keyVersion`, "not_positive_integer");
  }
  const vault = buildVault(field, wallet);

  const payload = {
    purpose: BACKUP_WALLET_EXPORT_PURPOSE,
    canonical_version: BACKUP_CANONICAL_VERSION,
    node_id: snapshot.nodeId,
    export_id: snapshot.exportId,
    wallet_id: walletId,
    public_key: publicKey,
    key_origin: wallet.keyOrigin,
    key_version: wallet.keyVersion,
    vault,
  };
  const preimageText = buildWalletExportPreimageText(payload);
  const exportSha256 = backupSha256HexUtf8(preimageText);
  const signatureBytes = wallet.signer.sign(UTF8.encode(preimageText));
  const exportProofSignature = parseEd25519Signature(encodeBackupBase64Url(signatureBytes));

  const section: BackupWalletSection = { ...payload, export_proof_signature: exportProofSignature };
  return { section, exportSha256 };
}

function sortEvidenceRows(table: BackupEvidenceTableInput): BackupEvidenceRow[] {
  const rows = [...table.rows];
  rows.sort((a, b) => compareBackupRows(a, b, table.primaryKey));
  return rows;
}

function buildEvidence(snapshot: BackupSnapshot): {
  sections: BackupEvidenceSection[];
  index: BackupEvidenceIndexEntry[];
} {
  const byTable = new Map<string, BackupEvidenceTableInput>();
  for (const table of snapshot.evidenceTables) {
    if (!BACKUP_COVERAGE_TABLES.includes(table.table)) reject("evidenceTables", "table_not_in_coverage");
    if (byTable.has(table.table)) reject("evidenceTables", "duplicate_table");
    byTable.set(table.table, table);
  }

  const sections: BackupEvidenceSection[] = [];
  const index: BackupEvidenceIndexEntry[] = [];
  for (const tableName of BACKUP_COVERAGE_TABLES) {
    const input = byTable.get(tableName);
    const rows = input === undefined ? [] : sortEvidenceRows(input);
    const tableSha256 = computeBackupTableDigest(rows);
    sections.push({ table: tableName, rows });
    index.push({ table: tableName, row_count: rows.length, table_sha256: tableSha256 });
  }
  return { sections, index };
}

function buildSettingsSnapshot(values: Record<string, string>): {
  snapshot: { values: Record<string, string> };
  settingsSha256: string;
} {
  const sortedKeys = Object.keys(values).sort((a, b) => compareBackupByteSequence(a, b));
  const sortedValues: Record<string, string> = {};
  for (const key of sortedKeys) {
    const value = values[key];
    if (typeof value !== "string") reject("settingsValues", "value_not_string");
    sortedValues[key] = value;
  }
  const snapshot = { values: sortedValues };
  return { snapshot, settingsSha256: computeBackupSettingsDigest(snapshot) };
}

function buildNodeSigningKeys(keys: readonly BackupNodeSigningKeyInput[]): BackupManifestSigningKeyEntry[] {
  const entries = keys.map((key, index) => {
    const field = `nodeSigningKeys[${index}]`;
    return {
      signing_key_id: parseUuid(key.signingKeyId),
      purpose: requireNonEmptyString(`${field}.purpose`, key.purpose),
      public_key: parseWalletPublicKey(key.publicKey),
      vault_secret_ref: requireNonEmptyString(`${field}.vaultSecretRef`, key.vaultSecretRef),
      sealed_ciphertext_sha256: parseSha256Hex(key.sealedCiphertextSha256),
    };
  });
  entries.sort((a, b) => compareBackupByteSequence(a.signing_key_id, b.signing_key_id));
  return entries;
}

export function buildBackupArchive(snapshot: BackupSnapshot): BackupExportResult {
  const nodeId = parseUuid(snapshot.nodeId);
  const exportId = parseUuid(snapshot.exportId);
  encodeCanonicalTimestamp(snapshot.exportedAt);
  const exportedAt = snapshot.exportedAt;
  const normalized: BackupSnapshot = { ...snapshot, nodeId, exportId, exportedAt };

  const walletInputs = [...snapshot.wallets];
  walletInputs.sort((a, b) => compareBackupByteSequence(a.walletId, b.walletId));
  for (let i = 1; i < walletInputs.length; i += 1) {
    if (walletInputs[i - 1]!.walletId === walletInputs[i]!.walletId) {
      reject("wallets", "duplicate_wallet_id");
    }
  }

  const walletSections: BackupWalletSection[] = [];
  const manifestWallets: BackupManifestWalletEntry[] = [];
  walletInputs.forEach((wallet, index) => {
    const { section, exportSha256 } = buildWalletSection(normalized, wallet, index);
    walletSections.push(section);
    manifestWallets.push({
      wallet_id: section.wallet_id,
      public_key: section.public_key,
      key_version: section.key_version,
      export_sha256: exportSha256,
    });
  });

  const evidence = buildEvidence(snapshot);
  const settings = buildSettingsSnapshot(snapshot.settingsValues);
  const nodeSigningKeys = buildNodeSigningKeys(snapshot.nodeSigningKeys);

  const manifest: BackupManifest = {
    purpose: BACKUP_MANIFEST_PURPOSE,
    canonical_version: BACKUP_CANONICAL_VERSION,
    format: BACKUP_FORMAT,
    node_id: nodeId,
    export_id: exportId,
    exported_at: exportedAt,
    wallets: manifestWallets,
    node_signing_keys: nodeSigningKeys,
    evidence_index: evidence.index,
    settings_sha256: settings.settingsSha256,
  };

  const manifestPreimageText = buildManifestPreimageText(manifest);
  const manifestSignature = parseEd25519Signature(
    encodeBackupBase64Url(snapshot.identitySigner.sign(UTF8.encode(manifestPreimageText))),
  );

  const archive: BackupArchive = {
    format: BACKUP_FORMAT,
    manifest,
    manifest_signature: manifestSignature,
    wallet_sections: walletSections,
    evidence_sections: evidence.sections,
    settings_snapshot: settings.snapshot,
  };

  return { archiveJson: JSON.stringify(archive), archive };
}
