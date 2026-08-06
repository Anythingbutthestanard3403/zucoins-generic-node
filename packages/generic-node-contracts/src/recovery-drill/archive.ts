/**
 * SOURCE: the signing-custody-security spec the archive-envelope encoding (envelope),
 * the wallet-export section (per-wallet section + export digest + proof), the manifest/digest rules (manifest + digests + archive
 * signature); the suite-tuple preimage rule; the backup-archive freeze.
 *
 * The archive PRODUCER path. Builds the `zp-node-backup-v1` archive byte-exact per the archive section: one
 * `JSON.stringify` over an object built in the frozen insertion sequence, per-wallet export sections
 * signed by the wallet key, the manifest signed by the node identity key, and the manifest/digest rules row/table
 * digests. The independent VERIFIER path is `verify.ts`; the census test proves the committed
 * golden archive passes that verifier and restores byte-equal.
 *
 * SCOPE — this is CONTRACT_FREEZE drill machinery. It is a MODEL of the archive section producer; the node
 * runs `packages/node-core/src/core/backup/*` instead, and nothing here executes on that path. A
 * green run here proves the model and its goldens, never production behaviour. The production
 * exporter is held to these same committed goldens separately, by
 * `packages/node-core/test/recovery-golden-binding.test.ts` (ask 2).
 */
import { sha256Hex, utf8Bytes, signPreimage } from "../testkit/independentCrypto.ts";
import { serializeRow } from "./canonical.ts";
import {
  BACKUP_ARCHIVE_FORMAT,
  BACKUP_WALLET_EXPORT_PURPOSE,
  BACKUP_MANIFEST_PURPOSE,
} from "./purposes.contract.ts";
import { COVERAGE_TABLES } from "./coverage.contract.ts";
import {
  NODE_ID,
  EXPORT_ID,
  EXPORTED_AT,
  KEY_VERSION,
  IDENTITY_SIGNING_KEY_ID,
  SETTINGS_SNAPSHOT,
  type DrillWorld,
} from "./fixtures.ts";

export interface WalletSection {
  readonly section: Record<string, unknown>;
  readonly preimageText: string;
  readonly exportSha256: string;
  readonly proofSignature: string;
}

/** the wallet-export section — build one per-wallet export section: payload fields 1-9, the preimage, the
 *  `export_sha256` digest, and the wallet-key `export_proof_signature` (field 10). */
export const buildWalletSection = (
  world: DrillWorld,
  wallet: DrillWorld["wallets"][number],
): WalletSection => {
  const payload = {
    purpose: BACKUP_WALLET_EXPORT_PURPOSE,
    canonical_version: 1,
    node_id: NODE_ID,
    export_id: EXPORT_ID,
    wallet_id: wallet.def.id,
    public_key: wallet.publicKeyB64Url,
    key_origin: "node_generated",
    key_version: KEY_VERSION,
    vault: wallet.vaultRow,
  };
  const preimageText = `${BACKUP_WALLET_EXPORT_PURPOSE}\n${JSON.stringify(payload)}`;
  const exportSha256 = sha256Hex(utf8Bytes(preimageText));
  const proofSignature = signPreimage(preimageText, wallet.secret64);
  const section = { ...payload, export_proof_signature: proofSignature };
  return { section, preimageText, exportSha256, proofSignature };
};

/** the manifest/digest rules — `row_sha256 = SHA256(JSON.stringify(row))`; rows are supplied in PK sequence. */
export const rowSha256 = (row: Record<string, unknown>): string => sha256Hex(utf8Bytes(serializeRow(row)));

/** the manifest/digest rules — `table_sha256 = SHA256(concat(row_sha256 …))`; the empty table hashes as SHA-256(""). */
export const tableSha256 = (rows: readonly Record<string, unknown>[]): string =>
  sha256Hex(utf8Bytes(rows.map((row) => rowSha256(row)).join("")));

export const settingsSha256 = (settings: unknown): string =>
  sha256Hex(utf8Bytes(JSON.stringify(settings)));

export interface BuiltArchive {
  readonly archiveText: string;
  readonly archiveSha256: string;
  readonly manifestPreimageText: string;
  readonly manifestSha256: string;
  readonly manifestSignature: string;
  readonly walletSections: readonly WalletSection[];
}

/** the manifest/digest rules / the archive-envelope encoding — build the whole archive: wallet sections, evidence sections in frozen
 *  coverage sequence, the signed manifest, and the single top-level `JSON.stringify`. */
export const buildArchive = (world: DrillWorld): BuiltArchive => {
  const walletSections = world.wallets.map((wallet) => buildWalletSection(world, wallet));

  const evidenceSections = COVERAGE_TABLES.map((table) => ({
    table,
    rows: world.evidenceByTable[table] ?? [],
  }));

  const evidenceIndex = COVERAGE_TABLES.map((table) => {
    const rows = world.evidenceByTable[table] ?? [];
    return { table, row_count: rows.length, table_sha256: tableSha256(rows) };
  });

  const sealedRow = world.sealedStoreRows[0];
  const sealedCiphertextB64 = sealedRow?.sealed_ciphertext as string;
  const nodeSigningKeys = [
    {
      signing_key_id: IDENTITY_SIGNING_KEY_ID,
      purpose: "NODE_IDENTITY",
      public_key: world.identityPublicKeyB64Url,
      vault_secret_ref: `sealed://${IDENTITY_SIGNING_KEY_ID}`,
      sealed_ciphertext_sha256: sha256Hex(utf8Bytes(sealedCiphertextB64)),
    },
  ];

  const manifestPayload = {
    purpose: BACKUP_MANIFEST_PURPOSE,
    canonical_version: 1,
    format: BACKUP_ARCHIVE_FORMAT,
    node_id: NODE_ID,
    export_id: EXPORT_ID,
    exported_at: EXPORTED_AT,
    wallets: walletSections.map((built, index) => ({
      wallet_id: world.wallets[index].def.id,
      public_key: world.wallets[index].publicKeyB64Url,
      key_version: KEY_VERSION,
      export_sha256: built.exportSha256,
    })),
    node_signing_keys: nodeSigningKeys,
    evidence_index: evidenceIndex,
    settings_sha256: settingsSha256(SETTINGS_SNAPSHOT),
  };
  const manifestPreimageText = `${BACKUP_MANIFEST_PURPOSE}\n${JSON.stringify(manifestPayload)}`;
  const manifestSignature = signPreimage(manifestPreimageText, world.identitySecret64);

  const archive = {
    format: BACKUP_ARCHIVE_FORMAT,
    manifest: manifestPayload,
    manifest_signature: manifestSignature,
    wallet_sections: walletSections.map((built) => built.section),
    evidence_sections: evidenceSections,
    settings_snapshot: SETTINGS_SNAPSHOT,
  };
  const archiveText = JSON.stringify(archive);
  return {
    archiveText,
    archiveSha256: sha256Hex(utf8Bytes(archiveText)),
    manifestPreimageText,
    manifestSha256: sha256Hex(utf8Bytes(manifestPreimageText)),
    manifestSignature,
    walletSections,
  };
};
