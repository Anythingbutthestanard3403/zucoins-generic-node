// production binding (ask 2).
//
// The recovery goldens under `packages/generic-node-contracts/goldens/recovery/` were
// frozen alongside a MODEL of the archive and the ceremony
// (`generic-node-contracts/src/recovery-drill/`). That model has no production consumer, so on its
// own it can only regression-detect drift in itself: the production exporter could diverge from
// the frozen bytes and every drill would stay green.
//
// This file closes that gap in one direction only — it drives the PRODUCTION modules the node
// actually runs (`src/core/backup/*` for export/verify, `src/core/recovery/probe.ts` for the
// fresh probe) and requires them to reproduce the committed goldens byte-for-byte. Any
// change to a field sequence, a digest rule, a sort order, or a preimage construction in those
// production modules fails here.
//
// What this does NOT cover, stated so a green run is not over-read: the ceremony's
// procedure, its stamp discipline, and its failure-class behaviour are exercised by
// `recovery-restore-ceremony.test.ts` against its own fixtures, not against a committed golden —
// no golden of a ceremony RUN exists to bind them to. This file binds the two signed ARTIFACTS
// and the whole archive, nothing more.
//
// Offline and key-free by construction: the only key material is the frozen synthetic seed bytes
// recorded in the goldens' own provenance (`manifest.json` → `provenance.key_material`), derived
// here through `node:crypto` alone. No live chain, no vault, no real key.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import {
  BACKUP_NODE_GENERATED_ORIGIN,
  buildBackupArchive,
  verifyBackupArchive,
  type BackupArchive,
  type BackupEvidenceRow,
  type BackupEvidenceTableInput,
  type BackupNodeSigningKeyInput,
  type BackupSigner,
  type BackupSnapshot,
  type BackupWalletInput,
} from "../src/core/backup/index.js";
import {
  backupSha256HexUtf8,
  buildWalletExportPreimageText,
  encodeBackupBase64Url,
  verifyBackupSignature,
} from "../src/core/backup/crypto.js";
import {
  buildRecoveryProbePayload,
  buildRecoveryProbePreimageText,
} from "../src/core/recovery/index.js";

const goldenPath = (name: string): string =>
  fileURLToPath(new URL(`../../generic-node-contracts/goldens/recovery/${name}`, import.meta.url));

const readGolden = (name: string): string => readFileSync(goldenPath(name), "utf8");

const GOLDEN_ARCHIVE_TEXT = readGolden("archive.json.txt");
const GOLDEN_MANIFEST = JSON.parse(readGolden("manifest.json")) as {
  archive: { format: string; sha256: string };
  chained_golden: { export_digest_sha256: string; recovery_verification_field_8_export_sha256: string };
};
const GOLDEN_EXPORT_PREIMAGE = readGolden("zp-backup-wallet-export-v1.preimage.txt");
const GOLDEN_EXPORT_DIGEST = readGolden("zp-backup-wallet-export-v1.digest.hex");
const GOLDEN_EXPORT_SIGNATURE = readGolden("zp-backup-wallet-export-v1.sig.b64");
const GOLDEN_EXPORT_META = JSON.parse(readGolden("zp-backup-wallet-export-v1.meta.json")) as {
  wallet_id: string;
  wallet_public_key_b64: string;
};
const GOLDEN_PROBE_PREIMAGE = readGolden("zp-recovery-verification-v1.preimage.txt");
const GOLDEN_PROBE_SIGNATURE = readGolden("zp-recovery-verification-v1.sig.b64");
const GOLDEN_PROBE_PAYLOAD = JSON.parse(
  GOLDEN_PROBE_PREIMAGE.slice(GOLDEN_PROBE_PREIMAGE.indexOf("\n") + 1),
) as {
  node_id: string;
  wallet_id: string;
  public_key: string;
  key_version: number;
  export_id: string;
  export_sha256: string;
  ceremony_id: string;
  ceremony_nonce: string;
  issued_at: string;
};

const GOLDEN_ARCHIVE = JSON.parse(GOLDEN_ARCHIVE_TEXT) as BackupArchive;

// The goldens' own recorded key material: node identity seed 0x00, wallet seeds 0x11/0x12/0x13,
// each a 32-byte filled Ed25519 seed. Synthetic test material — never live.
const IDENTITY_SEED_BYTE = 0x00;
const WALLET_SEED_BYTES = [0x11, 0x12, 0x13] as const;

// PKCS#8 DER prefix for an Ed25519 private key carrying a raw 32-byte seed (RFC 8410).
const ED25519_PKCS8_DER_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

interface SeedKey {
  readonly publicKey: string;
  readonly signer: BackupSigner;
}

function keyFromSeedByte(seedByte: number): SeedKey {
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_DER_PREFIX, Buffer.alloc(32, seedByte)]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return {
    publicKey: encodeBackupBase64Url(new Uint8Array(spki.subarray(spki.length - 32))),
    signer: {
      sign: (preimageBytes: Uint8Array) =>
        new Uint8Array(nodeSign(null, Buffer.from(preimageBytes), privateKey)),
    },
  };
}

const WALLET_KEYS = WALLET_SEED_BYTES.map(keyFromSeedByte);

/** The seed-derived key whose public key matches the golden section — never a positional guess. */
function keyForPublicKey(publicKey: string): SeedKey {
  const match = WALLET_KEYS.find((key) => key.publicKey === publicKey);
  if (match === undefined) {
    throw new Error(`no frozen seed byte derives golden public key ${publicKey}`);
  }
  return match;
}

// Feeding the exporter its inputs REVERSED proves the production sort produces the golden
// sequence, rather than the test handing it an already-canonical order to copy through.
const reversed = <T>(items: readonly T[]): T[] => [...items].reverse();

function goldenWalletInputs(): BackupWalletInput[] {
  return reversed(GOLDEN_ARCHIVE.wallet_sections).map((section) => ({
    walletId: section.wallet_id,
    publicKey: section.public_key,
    keyOrigin: section.key_origin,
    keyVersion: section.key_version,
    vault: section.vault,
    signer: keyForPublicKey(section.public_key).signer,
  }));
}

function goldenEvidenceTables(): BackupEvidenceTableInput[] {
  const primaryKeys: Record<string, BackupEvidenceTableInput["primaryKey"]> = {
    node_signing_key_sealed_store: [{ column: "vault_secret_ref", kind: "text" }],
    wallets: [{ column: "id", kind: "uuid" }],
  };
  return GOLDEN_ARCHIVE.evidence_sections
    .filter((section) => section.rows.length > 0)
    .map((section) => {
      const primaryKey = primaryKeys[section.table];
      if (primaryKey === undefined) {
        throw new Error(`golden archive carries rows for unmapped table ${section.table}`);
      }
      return {
        table: section.table as BackupEvidenceTableInput["table"],
        primaryKey,
        rows: reversed(section.rows) as BackupEvidenceRow[],
      };
    });
}

function goldenSettingsValues(): Record<string, string> {
  const values: Record<string, string> = {};
  for (const key of reversed(Object.keys(GOLDEN_ARCHIVE.settings_snapshot.values))) {
    values[key] = GOLDEN_ARCHIVE.settings_snapshot.values[key]!;
  }
  return values;
}

function goldenNodeSigningKeys(): BackupNodeSigningKeyInput[] {
  return GOLDEN_ARCHIVE.manifest.node_signing_keys.map((entry) => ({
    signingKeyId: entry.signing_key_id,
    purpose: entry.purpose,
    publicKey: entry.public_key,
    vaultSecretRef: entry.vault_secret_ref,
    sealedCiphertextSha256: entry.sealed_ciphertext_sha256,
  }));
}

function goldenSnapshot(): BackupSnapshot {
  return {
    nodeId: GOLDEN_ARCHIVE.manifest.node_id,
    exportId: GOLDEN_ARCHIVE.manifest.export_id,
    exportedAt: GOLDEN_ARCHIVE.manifest.exported_at,
    wallets: goldenWalletInputs(),
    nodeSigningKeys: goldenNodeSigningKeys(),
    evidenceTables: goldenEvidenceTables(),
    settingsValues: goldenSettingsValues(),
    identitySigner: keyFromSeedByte(IDENTITY_SEED_BYTE).signer,
  };
}

describe("goldens bind the production backup exporter", () => {
  it("derives the goldens' recorded seed keys, so the fixture provenance is real", () => {
    expect(keyFromSeedByte(IDENTITY_SEED_BYTE).publicKey).toBe(
      GOLDEN_ARCHIVE.manifest.node_signing_keys[0]!.public_key,
    );
    expect(WALLET_KEYS.map((key) => key.publicKey).sort()).toEqual(
      GOLDEN_ARCHIVE.wallet_sections.map((section) => section.public_key).sort(),
    );
  });

  it("reproduces the committed archive byte-for-byte from the production exporter", () => {
    const { archiveJson } = buildBackupArchive(goldenSnapshot());

    expect(archiveJson).toBe(GOLDEN_ARCHIVE_TEXT);
    expect(createHash("sha256").update(archiveJson, "utf8").digest("hex")).toBe(
      GOLDEN_MANIFEST.archive.sha256,
    );
    expect(GOLDEN_MANIFEST.archive.format).toBe(GOLDEN_ARCHIVE.format);
  });

  it("accepts the committed archive through the production verifier", () => {
    expect(verifyBackupArchive(GOLDEN_ARCHIVE_TEXT)).toEqual({ ok: true });
  });

  it("emits the committed wallet-export preimage, digest and signature", () => {
    const { archive } = buildBackupArchive(goldenSnapshot());
    const section = archive.wallet_sections.find(
      (candidate) => candidate.wallet_id === GOLDEN_EXPORT_META.wallet_id,
    );
    expect(section).toBeDefined();
    expect(section!.public_key).toBe(GOLDEN_EXPORT_META.wallet_public_key_b64);
    expect(section!.key_origin).toBe(BACKUP_NODE_GENERATED_ORIGIN);

    // Fields 1–9 only; field 10 (export_proof_signature) is never in the preimage.
    const { export_proof_signature: signature, ...preimageFields } = section!;
    const preimageText = buildWalletExportPreimageText(preimageFields);

    expect(preimageText).toBe(GOLDEN_EXPORT_PREIMAGE);
    expect(backupSha256HexUtf8(preimageText)).toBe(GOLDEN_EXPORT_DIGEST);
    expect(signature).toBe(GOLDEN_EXPORT_SIGNATURE);
    expect(
      verifyBackupSignature({
        publicKeyBase64Url: section!.public_key,
        preimageText,
        signatureBase64Url: GOLDEN_EXPORT_SIGNATURE,
      }),
    ).toBe(true);
  });
});

describe("goldens bind the production recovery probe", () => {
  it("emits the committed probe preimage and verifies the committed signature", () => {
    const preimageText = buildRecoveryProbePreimageText(
      buildRecoveryProbePayload({
        nodeId: GOLDEN_PROBE_PAYLOAD.node_id,
        walletId: GOLDEN_PROBE_PAYLOAD.wallet_id,
        publicKey: GOLDEN_PROBE_PAYLOAD.public_key,
        keyVersion: GOLDEN_PROBE_PAYLOAD.key_version,
        exportId: GOLDEN_PROBE_PAYLOAD.export_id,
        exportSha256: GOLDEN_PROBE_PAYLOAD.export_sha256,
        ceremonyId: GOLDEN_PROBE_PAYLOAD.ceremony_id,
        ceremonyNonce: GOLDEN_PROBE_PAYLOAD.ceremony_nonce,
        issuedAt: GOLDEN_PROBE_PAYLOAD.issued_at,
      }),
    );

    expect(preimageText).toBe(GOLDEN_PROBE_PREIMAGE);
    expect(
      verifyBackupSignature({
        publicKeyBase64Url: GOLDEN_PROBE_PAYLOAD.public_key,
        preimageText,
        signatureBase64Url: GOLDEN_PROBE_SIGNATURE,
      }),
    ).toBe(true);
  });

  it("keeps the chain invariant: the exporter's digest is the probe's field 8", () => {
    const { archive } = buildBackupArchive(goldenSnapshot());
    const manifestEntry = archive.manifest.wallets.find(
      (entry) => entry.wallet_id === GOLDEN_PROBE_PAYLOAD.wallet_id,
    );
    expect(manifestEntry).toBeDefined();

    // Production export digest === probe field 8 === both goldens' recorded chain values.
    expect(manifestEntry!.export_sha256).toBe(GOLDEN_PROBE_PAYLOAD.export_sha256);
    expect(manifestEntry!.export_sha256).toBe(GOLDEN_EXPORT_DIGEST);
    expect(GOLDEN_MANIFEST.chained_golden.export_digest_sha256).toBe(
      GOLDEN_MANIFEST.chained_golden.recovery_verification_field_8_export_sha256,
    );
    expect(GOLDEN_MANIFEST.chained_golden.export_digest_sha256).toBe(GOLDEN_EXPORT_DIGEST);
  });
});
