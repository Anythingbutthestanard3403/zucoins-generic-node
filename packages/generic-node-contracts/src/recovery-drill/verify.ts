/**
 * SOURCE: the signing-custody-security spec the all-or-nothing acceptance rules
 * (acceptance rules — all-or-nothing, fail-closed), the archive-envelope encoding (field sequence + canonical encodings),
 * the wallet-export section (export digest + proof), the manifest/digest rules (manifest + digests); the backup-archive freeze.
 *
 * The archive VERIFIER path — deliberately independent of the `archive.ts` producer: it re-derives
 * every digest and re-checks every signature from the archive bytes alone, sharing no builder
 * state, so the census test is a genuine second-path check (anti-self-dealing). Acceptance is
 * all-or-nothing: any rejection aborts the whole archive with the accumulated reasons. Caller must
 * have awaited `ready()` (Ed25519 verification).
 */
import { sha256Hex, utf8Bytes, verifyPreimageSignature, decodeBase64Url } from "../testkit/independentCrypto.ts";
import {
  isCanonicalUuid,
  isSha256Hex,
  isPaddedBase64Url,
  isCanonicalTimestamp,
  serializeRow,
} from "./canonical.ts";
import {
  BACKUP_ARCHIVE_FORMAT,
  BACKUP_ARCHIVE_TOP_LEVEL_FIELDS,
  BACKUP_MANIFEST_FIELDS,
  BACKUP_WALLET_EXPORT_FIELDS,
  BACKUP_WALLET_EXPORT_VAULT_FIELDS,
  BACKUP_MANIFEST_PURPOSE,
  BACKUP_WALLET_EXPORT_PURPOSE,
} from "./purposes.contract.ts";
import { COVERAGE_TABLES } from "./coverage.contract.ts";

type Json = Record<string, unknown>;

export interface VerifyResult {
  readonly ok: boolean;
  readonly reasons: readonly string[];
}

const keys = (obj: Json): string[] => Object.keys(obj);

const decodeKey = (b64Url: string): Uint8Array => decodeBase64Url(b64Url);

const orderOk = (obj: Json, expected: readonly string[]): boolean =>
  JSON.stringify(keys(obj)) === JSON.stringify([...expected]);

/** Recompute the wallet-export section export digest from a parsed section's fields 1-9, in frozen sequence. */
const recomputeExportSha256 = (section: Json): string => {
  const payload: Json = {};
  for (const field of BACKUP_WALLET_EXPORT_FIELDS) payload[field] = section[field];
  return sha256Hex(utf8Bytes(`${BACKUP_WALLET_EXPORT_PURPOSE}\n${JSON.stringify(payload)}`));
};

const rowDigest = (row: Json): string => sha256Hex(utf8Bytes(serializeRow(row)));
const tableDigest = (rows: readonly Json[]): string =>
  sha256Hex(utf8Bytes(rows.map((row) => rowDigest(row)).join("")));

/** the all-or-nothing acceptance rules — verify the whole archive. Returns accumulated rejection reasons; `ok` is all-or-nothing. */
export const verifyArchive = (archiveText: string): VerifyResult => {
  const reasons: string[] = [];
  let archive: Json;
  try {
    archive = JSON.parse(archiveText) as Json;
  } catch {
    return { ok: false, reasons: ["archive is not a single valid JSON text"] };
  }

  if (archive.format !== BACKUP_ARCHIVE_FORMAT) {
    reasons.push(`unknown or missing format discriminator: ${String(archive.format)}`);
  }
  if (!orderOk(archive, BACKUP_ARCHIVE_TOP_LEVEL_FIELDS)) {
    reasons.push(`top-level field sequence mismatch: ${keys(archive).join(",")}`);
  }

  const manifest = archive.manifest as Json;
  const walletSections = archive.wallet_sections as readonly Json[];
  const evidenceSections = archive.evidence_sections as readonly Json[];

  if (!orderOk(manifest, BACKUP_MANIFEST_FIELDS)) {
    reasons.push(`manifest field sequence mismatch: ${keys(manifest).join(",")}`);
  }
  if (manifest.format !== BACKUP_ARCHIVE_FORMAT) reasons.push("manifest format mismatch");
  if (!isCanonicalUuid(String(manifest.node_id))) reasons.push("manifest node_id non-canonical");
  if (!isCanonicalUuid(String(manifest.export_id))) reasons.push("manifest export_id non-canonical");
  if (!isCanonicalTimestamp(String(manifest.exported_at))) reasons.push("manifest exported_at non-canonical");

  // Manifest signature under the covered node identity key.
  const manifestPreimage = `${BACKUP_MANIFEST_PURPOSE}\n${JSON.stringify(manifest)}`;
  const signingKeys = manifest.node_signing_keys as readonly Json[];
  const identityKey = signingKeys.find((key) => key.purpose === "NODE_IDENTITY");
  const manifestSig = String(archive.manifest_signature);
  try {
    if (
      identityKey === undefined ||
      !verifyPreimageSignature(manifestPreimage, manifestSig, decodeKey(String(identityKey.public_key)))
    ) {
      reasons.push("manifest signature does not verify under a covered node identity key");
    }
  } catch {
    reasons.push("manifest signature is malformed (fail closed)");
  }

  // Evidence sections: frozen coverage sequence + recomputed table digests vs the manifest index.
  const evidenceIndex = manifest.evidence_index as readonly Json[];
  if (evidenceSections.length !== COVERAGE_TABLES.length) {
    reasons.push(`evidence section count ${evidenceSections.length} != coverage ${COVERAGE_TABLES.length}`);
  }
  evidenceSections.forEach((section, index) => {
    if (!orderOk(section, ["table", "rows"])) reasons.push(`evidence section ${index} field sequence mismatch`);
    if (section.table !== COVERAGE_TABLES[index]) {
      reasons.push(`evidence section ${index} out of frozen sequence: ${String(section.table)}`);
    }
    const indexEntry = evidenceIndex[index] as Json | undefined;
    const rows = section.rows as readonly Json[];
    const recomputed = tableDigest(rows);
    if (indexEntry?.table_sha256 !== recomputed) {
      reasons.push(`table_sha256 mismatch for ${String(section.table)}`);
    }
    if (indexEntry?.row_count !== rows.length) {
      reasons.push(`row_count mismatch for ${String(section.table)}`);
    }
  });

  // Settings digest.
  if (manifest.settings_sha256 !== sha256Hex(utf8Bytes(JSON.stringify(archive.settings_snapshot)))) {
    reasons.push("settings_sha256 mismatch");
  }

  // Wallets evidence rows, keyed by id, for the public-key cross-check.
  const walletsEvidence = (evidenceSections.find((section) => section.table === "wallets")?.rows ?? []) as readonly Json[];
  const walletsById = new Map(walletsEvidence.map((row) => [String(row.id), row]));

  // Wallet sections: sequence, completeness, per-section proof + digest + pubkey + key_origin.
  const manifestWallets = manifest.wallets as readonly Json[];
  const seenWalletIds = new Set<string>();
  walletSections.forEach((section, index) => {
    const expectedFields = [...BACKUP_WALLET_EXPORT_FIELDS, "export_proof_signature"];
    if (!orderOk(section, expectedFields)) {
      reasons.push(`wallet section ${index} field sequence mismatch: ${keys(section).join(",")}`);
    }
    const walletId = String(section.wallet_id);
    if (seenWalletIds.has(walletId)) reasons.push(`duplicate wallet_id section: ${walletId}`);
    seenWalletIds.add(walletId);
    if (index > 0 && !(walletId > String(walletSections[index - 1].wallet_id))) {
      reasons.push(`wallet sections not in ascending wallet_id sequence at ${walletId}`);
    }
    if (section.purpose !== BACKUP_WALLET_EXPORT_PURPOSE) reasons.push(`section ${index} purpose mismatch`);
    if (section.key_origin !== "node_generated") reasons.push(`section ${index} key_origin not node_generated`);

    const vault = section.vault as Json;
    if (!orderOk(vault, BACKUP_WALLET_EXPORT_VAULT_FIELDS)) {
      reasons.push(`section ${index} vault field sequence mismatch`);
    }
    if (!isPaddedBase64Url(String(vault.ciphertext))) reasons.push(`section ${index} ciphertext non-canonical`);
    if (!isSha256Hex(String(vault.ciphertext_sha256))) reasons.push(`section ${index} ciphertext_sha256 non-canonical`);

    const recomputed = recomputeExportSha256(section);
    const manifestEntry = manifestWallets.find((entry) => entry.wallet_id === walletId);
    if (manifestEntry === undefined) {
      reasons.push(`wallet section ${walletId} has no manifest entry`);
    } else if (manifestEntry.export_sha256 !== recomputed) {
      reasons.push(`export_sha256 mismatch for ${walletId}`);
    }
    if (recomputed !== recomputeExportSha256(section)) reasons.push(`section ${index} digest unstable`);

    const proofPreimage = `${BACKUP_WALLET_EXPORT_PURPOSE}\n${JSON.stringify(
      Object.fromEntries(BACKUP_WALLET_EXPORT_FIELDS.map((field) => [field, section[field]])),
    )}`;
    const pubkeyB64 = String(section.public_key);
    try {
      if (!verifyPreimageSignature(proofPreimage, String(section.export_proof_signature), decodeKey(pubkeyB64))) {
        reasons.push(`export_proof_signature fails for ${walletId}`);
      }
    } catch {
      reasons.push(`export_proof_signature malformed for ${walletId} (fail closed)`);
    }
    const evidenceRow = walletsById.get(walletId);
    if (evidenceRow === undefined) {
      reasons.push(`wallet section ${walletId} has no covered wallets row`);
    } else if (evidenceRow.public_key !== pubkeyB64) {
      reasons.push(`section ${walletId} public_key differs from covered wallets row`);
    }
  });

  // Manifest entries each have a section.
  for (const entry of manifestWallets) {
    if (!seenWalletIds.has(String(entry.wallet_id))) {
      reasons.push(`manifest entry ${String(entry.wallet_id)} has no wallet section`);
    }
  }

  return { ok: reasons.length === 0, reasons };
};
