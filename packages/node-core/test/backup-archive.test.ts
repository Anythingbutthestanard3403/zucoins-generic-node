import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import {
  BACKUP_COVERAGE_TABLES,
  BACKUP_FORMAT,
  buildBackupArchive,
  verifyBackupArchive,
  type BackupArchive,
  type BackupEvidenceRow,
  type BackupEvidenceTableInput,
  type BackupSigner,
  type BackupSnapshot,
  type BackupWalletInput,
} from "../src/core/backup/index.js";

function b64url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

// Flip a middle character to a guaranteed-different base64url char so the decoded bytes change.
function flipSignatureChar(signature: string): string {
  const index = Math.floor(signature.length / 2);
  const replacement = signature[index] === "B" ? "C" : "B";
  return signature.slice(0, index) + replacement + signature.slice(index + 1);
}

interface Ed25519Key {
  readonly publicKeyBase64Url: string;
  readonly signer: BackupSigner;
}

function makeEd25519Key(): Ed25519Key {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPublicKey = new Uint8Array(spki.subarray(spki.length - 32));
  return {
    publicKeyBase64Url: b64url(rawPublicKey),
    signer: {
      sign: (preimageBytes: Uint8Array) =>
        new Uint8Array(nodeSign(null, Buffer.from(preimageBytes), privateKey)),
    },
  };
}

const NODE_ID = "00000000-0000-4000-8000-000000000001";
const EXPORT_ID = "00000000-0000-4000-8000-000000000002";
const EXPORTED_AT = "2026-01-02T03:04:05.678Z";

function makeVaultRow(walletId: string, keyVersion: number) {
  const ciphertext = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const nonce = new Uint8Array([9, 10, 11, 12]);
  const authTag = new Uint8Array([13, 14, 15, 16]);
  return {
    wallet_id: walletId,
    key_version: keyVersion,
    ciphertext: b64url(ciphertext),
    nonce: b64url(nonce),
    auth_tag: b64url(authTag),
    ciphertext_sha256: sha256Hex(ciphertext),
    created_at: "2026-01-01T00:00:00.000Z",
    rotated_at: null,
  };
}

function makeWallet(walletId: string): { input: BackupWalletInput; publicKey: string } {
  const key = makeEd25519Key();
  const input: BackupWalletInput = {
    walletId,
    publicKey: key.publicKeyBase64Url,
    keyOrigin: "node_generated",
    keyVersion: 1,
    vault: makeVaultRow(walletId, 1),
    signer: key.signer,
  };
  return { input, publicKey: key.publicKeyBase64Url };
}

function makeSnapshot(): BackupSnapshot {
  const walletA = makeWallet("00000000-0000-4000-8000-00000000000a");
  const walletB = makeWallet("00000000-0000-4000-8000-00000000000b");
  const identity = makeEd25519Key();

  const walletsRows: BackupEvidenceRow[] = [
    {
      id: walletA.input.walletId,
      wallet_id: walletA.input.walletId,
      public_key: walletA.publicKey,
      key_origin: "node_generated",
      key_version: 1,
    },
    {
      id: walletB.input.walletId,
      wallet_id: walletB.input.walletId,
      public_key: walletB.publicKey,
      key_origin: "node_generated",
      key_version: 1,
    },
  ];

  const operationsRows: BackupEvidenceRow[] = [
    { id: "00000000-0000-4000-8000-0000000000ff", kind: "SEND_EXTERNAL", state: "SUBMITTED" },
    { id: "00000000-0000-4000-8000-0000000000ee", kind: "RECEIVE_EXTERNAL", state: "ARMED" },
  ];

  const evidenceTables: BackupEvidenceTableInput[] = [
    {
      table: "nodes",
      primaryKey: [{ column: "id", kind: "uuid" }],
      rows: [{ id: NODE_ID, created_at: "2026-01-01T00:00:00.000Z" }],
    },
    {
      table: "wallets",
      primaryKey: [{ column: "id", kind: "uuid" }],
      rows: walletsRows,
    },
    {
      table: "operations",
      primaryKey: [{ column: "id", kind: "uuid" }],
      rows: operationsRows,
    },
  ];

  return {
    nodeId: NODE_ID,
    exportId: EXPORT_ID,
    exportedAt: EXPORTED_AT,
    wallets: [walletB.input, walletA.input],
    nodeSigningKeys: [
      {
        signingKeyId: "00000000-0000-4000-8000-0000000000aa",
        purpose: "node_identity",
        publicKey: identity.publicKeyBase64Url,
        vaultSecretRef: "sealed-store/node-identity",
        sealedCiphertextSha256: sha256Hex(new Uint8Array([42, 42, 42])),
      },
    ],
    evidenceTables,
    settingsValues: { network: "splitchain", log_level: "info" },
    identitySigner: identity.signer,
  };
}

describe("backup archive export", () => {
  it("produces a canonical zp-node-backup-v1 archive that verifies", () => {
    const { archiveJson, archive } = buildBackupArchive(makeSnapshot());

    expect(archive.format).toBe(BACKUP_FORMAT);
    expect(archiveJson).toBe(JSON.stringify(archive));
    expect(verifyBackupArchive(archiveJson)).toEqual({ ok: true });
  });

  it("covers every frozen table in the frozen sequence, empty tables included", () => {
    const { archive } = buildBackupArchive(makeSnapshot());
    const tables = archive.evidence_sections.map((section) => section.table);
    expect(tables).toEqual([...BACKUP_COVERAGE_TABLES]);
    expect(archive.manifest.evidence_index.map((entry) => entry.table)).toEqual([
      ...BACKUP_COVERAGE_TABLES,
    ]);
  });

  it("sorts wallet sections ascending by wallet_id byte sequence", () => {
    const { archive } = buildBackupArchive(makeSnapshot());
    const walletIds = archive.wallet_sections.map((section) => section.wallet_id);
    expect(walletIds).toEqual([
      "00000000-0000-4000-8000-00000000000a",
      "00000000-0000-4000-8000-00000000000b",
    ]);
  });

  it("sorts evidence rows by primary key", () => {
    const { archive } = buildBackupArchive(makeSnapshot());
    const operations = archive.evidence_sections.find((section) => section.table === "operations");
    expect(operations?.rows.map((row) => row.id)).toEqual([
      "00000000-0000-4000-8000-0000000000ee",
      "00000000-0000-4000-8000-0000000000ff",
    ]);
  });

  it("sorts settings keys lexicographically", () => {
    const { archive } = buildBackupArchive(makeSnapshot());
    expect(Object.keys(archive.settings_snapshot.values)).toEqual(["log_level", "network"]);
  });

  it("rejects a non-node_generated wallet at export time", () => {
    const snapshot = makeSnapshot();
    const bad: BackupSnapshot = {
      ...snapshot,
      wallets: [
        {
          ...snapshot.wallets[0]!,
          keyOrigin: "imported",
        },
      ],
    };
    expect(() => buildBackupArchive(bad)).toThrow(/not_node_generated/);
  });

  it("rejects duplicate wallet ids at export time", () => {
    const snapshot = makeSnapshot();
    const duplicated = snapshot.wallets[0]!;
    const bad: BackupSnapshot = { ...snapshot, wallets: [duplicated, duplicated] };
    expect(() => buildBackupArchive(bad)).toThrow(/duplicate_wallet_id/);
  });
});

describe("backup archive integrity verification", () => {
  function tamper(archiveJson: string, mutate: (archive: BackupArchive) => void): string {
    const parsed = JSON.parse(archiveJson) as BackupArchive;
    mutate(parsed);
    return JSON.stringify(parsed);
  }

  it("rejects malformed JSON", () => {
    expect(verifyBackupArchive("{not json")).toEqual({ ok: false, reasons: ["malformed_json"] });
  });

  it("rejects an unknown format", () => {
    const { archiveJson } = buildBackupArchive(makeSnapshot());
    const tampered = tamper(archiveJson, (archive) => {
      (archive as { format: string }).format = "zp-node-backup-v2";
      archive.manifest.format = "zp-node-backup-v2" as never;
    });
    const result = verifyBackupArchive(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasons).toContain("unknown_format");
  });

  it("rejects non-canonical bytes (trailing whitespace)", () => {
    const { archiveJson } = buildBackupArchive(makeSnapshot());
    const result = verifyBackupArchive(`${archiveJson}\n`);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasons).toContain("non_canonical_bytes");
  });

  it("rejects a tampered evidence row via table digest mismatch", () => {
    const { archiveJson } = buildBackupArchive(makeSnapshot());
    const tampered = tamper(archiveJson, (archive) => {
      const wallets = archive.evidence_sections.find((section) => section.table === "wallets");
      (wallets?.rows[0] as BackupEvidenceRow).public_key =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    });
    const result = verifyBackupArchive(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reasons).toContain("table_digest_mismatch");
      expect(result.reasons).toContain("public_key_mismatch");
    }
  });

  it("rejects a tampered settings snapshot via settings digest mismatch", () => {
    const { archiveJson } = buildBackupArchive(makeSnapshot());
    const tampered = tamper(archiveJson, (archive) => {
      archive.settings_snapshot.values.network = "other-chain";
    });
    const result = verifyBackupArchive(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasons).toContain("settings_digest_mismatch");
  });

  it("rejects a tampered wallet export proof signature", () => {
    const { archiveJson } = buildBackupArchive(makeSnapshot());
    const tampered = tamper(archiveJson, (archive) => {
      const section = archive.wallet_sections[0]!;
      (section as { export_proof_signature: string }).export_proof_signature = flipSignatureChar(
        section.export_proof_signature,
      );
    });
    const result = verifyBackupArchive(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reasons).toContain("wallet_proof_signature_invalid");
    }
  });

  it("rejects a tampered manifest signature", () => {
    const { archiveJson } = buildBackupArchive(makeSnapshot());
    const tampered = tamper(archiveJson, (archive) => {
      (archive as { manifest_signature: string }).manifest_signature = flipSignatureChar(
        archive.manifest_signature,
      );
    });
    const result = verifyBackupArchive(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasons).toContain("manifest_signature_invalid");
  });

  it("rejects a reordered top-level field set", () => {
    const { archive } = buildBackupArchive(makeSnapshot());
    const reordered = JSON.stringify({
      manifest: archive.manifest,
      format: archive.format,
      manifest_signature: archive.manifest_signature,
      wallet_sections: archive.wallet_sections,
      evidence_sections: archive.evidence_sections,
      settings_snapshot: archive.settings_snapshot,
    });
    const result = verifyBackupArchive(reordered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasons).toContain("field_set_mismatch");
  });

  it("rejects evidence sections out of the frozen coverage sequence", () => {
    const { archiveJson } = buildBackupArchive(makeSnapshot());
    const tampered = tamper(archiveJson, (archive) => {
      const sections = [...archive.evidence_sections];
      const first = sections.shift()!;
      sections.push(first);
      (archive as { evidence_sections: typeof sections }).evidence_sections = sections;
    });
    const result = verifyBackupArchive(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasons).toContain("coverage_sequence_mismatch");
  });
});
