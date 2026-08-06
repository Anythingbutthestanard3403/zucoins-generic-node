import { beforeAll, describe, expect, it } from "vitest";

import { ready, sha256Hex, utf8Bytes } from "../testkit/independentCrypto.ts";
import { readGoldenText, sha256OfGolden } from "../testkit/byteGolden.ts";
import { buildDrillWorld, ROOT_EPOCH_1 } from "./fixtures.ts";
import { buildArchive } from "./archive.ts";
import { verifyArchive } from "./verify.ts";
import { serializeRow } from "./canonical.ts";
import {
  BACKUP_ARCHIVE_TOP_LEVEL_FIELDS,
  BACKUP_MANIFEST_FIELDS,
  BACKUP_WALLET_EXPORT_FIELDS,
  BACKUP_WALLET_EXPORT_PURPOSE,
} from "./purposes.contract.ts";
import { buildArtifacts } from "./emit.ts";

/**
 * the recovery-drill lane census: the archive UNDER TEST is the committed golden under `goldens/recovery/`, pinned
 * to a hand-recorded sha256 (never read back from the file or from the producer). Producer
 * (`archive.ts`) and verifier (`verify.ts`) are independent paths; this test proves (a) the golden
 * bytes hash to the pinned literal, (b) the independent verifier accepts the golden, (c) the
 * independent producer reproduces the golden BYTE-FOR-BYTE, and (d) restore is byte-equal via the
 * the archive-envelope encoding canonical re-serialization — never parsed-object deep-equal (the operations-recovery byte rule). Tests never write
 * goldens (A8); the `--check` emitter guard below fails if the committed bytes ever drift.
 */

const PINNED = {
  archiveSha256: "4037e574a0f823a37acbe2d0154b6bd90631700c64d921125eea812697e71dbc",
  exportPreimageSha256: "62055b5120268032d64e94e5a9210e3693fa7d4f143978cc00769ce4b6d44e44",
  exportDigestFileSha256: "7ec0132968e1cecb5c9303bbf4dbdf4a261133516360c90c328a61e863e58dbc",
  exportSigFileSha256: "0396b761eb3d4507e32a5ddc2132e30f9ef8e01e1f80637e3ce5f9e0325843f1",
  recoveryPreimageSha256: "f5c08d42c72656b056445f9c3d559fd2cc767e10abf56494de355bc665a7dd8a",
  recoveryDigestFileSha256: "188903c11e074e9d093d884dcd38f579dc386ab1ded178047ea32b70bf81cb94",
  recoverySigFileSha256: "a8d14c8697da790588ca7bfc0f95caf9ac215f05577d0aae3d94bf9790d2a8bc",
} as const;

type Json = Record<string, unknown>;

describe("recovery archive census (archive and drill-matrix freezes)", () => {
  beforeAll(async () => {
    await ready();
  });

  it("the committed archive golden hashes to the pinned sha256 (independent of producer and verifier)", () => {
    expect(sha256OfGolden("recovery/archive.json.txt")).toBe(PINNED.archiveSha256);
  });

  it("the independent verifier (the all-or-nothing acceptance rules all-or-nothing) accepts the committed golden archive", () => {
    const result = verifyArchive(readGoldenText("recovery/archive.json.txt"));
    expect(result.reasons).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("the independent producer reproduces the committed golden archive byte-for-byte", () => {
    const built = buildArchive(buildDrillWorld(ROOT_EPOCH_1));
    expect(built.archiveText).toBe(readGoldenText("recovery/archive.json.txt"));
    expect(built.archiveSha256).toBe(PINNED.archiveSha256);
  });

  it("restore is byte-equal via canonical re-serialization, never parsed-object deep-equal", () => {
    const goldenText = readGoldenText("recovery/archive.json.txt");
    const archive = JSON.parse(goldenText) as Json;

    // Rebuild the top-level object in the frozen insertion sequence from the parsed components and
    // re-serialize; byte-equality with the golden proves the canonical encoding round-trips exactly.
    const rebuilt: Json = {};
    for (const field of BACKUP_ARCHIVE_TOP_LEVEL_FIELDS) rebuilt[field] = archive[field];
    expect(JSON.stringify(rebuilt)).toBe(goldenText);

    // Manifest re-serialization in frozen field sequence is byte-equal.
    const manifest = archive.manifest as Json;
    const rebuiltManifest: Json = {};
    for (const field of BACKUP_MANIFEST_FIELDS) rebuiltManifest[field] = manifest[field];
    expect(JSON.stringify(rebuiltManifest)).toBe(JSON.stringify(manifest));

    // Each wallet section's export preimage, re-serialized from the parsed fields in frozen sequence,
    // hashes to the manifest's pinned export_sha256 — byte-equality of the signed bytes, not a
    // deep-equal of parsed objects.
    const sections = archive.wallet_sections as readonly Json[];
    const manifestWallets = manifest.wallets as readonly Json[];
    expect(sections).toHaveLength(3);
    sections.forEach((section, index) => {
      const payload: Json = {};
      for (const field of BACKUP_WALLET_EXPORT_FIELDS) payload[field] = section[field];
      const preimage = `${BACKUP_WALLET_EXPORT_PURPOSE}\n${JSON.stringify(payload)}`;
      const recomputed = sha256Hex(utf8Bytes(preimage));
      expect(recomputed).toBe(String(manifestWallets[index].export_sha256));
    });

    // Each covered evidence row re-serializes (serializeRow) to bytes whose digest matches the
    // manifest evidence_index table digest — the restore byte-equality witness per table.
    const evidenceSections = archive.evidence_sections as readonly Json[];
    const evidenceIndex = manifest.evidence_index as readonly Json[];
    evidenceSections.forEach((section, index) => {
      const rows = section.rows as readonly Json[];
      const tableDigest = sha256Hex(utf8Bytes(rows.map((row) => sha256Hex(utf8Bytes(serializeRow(row)))).join("")));
      expect(tableDigest).toBe(String(evidenceIndex[index].table_sha256));
    });
  });

  it("negative: flipping one byte of the golden archive makes the independent verifier fail closed", () => {
    const goldenText = readGoldenText("recovery/archive.json.txt");
    const at = goldenText.indexOf('"node_generated"');
    expect(at).toBeGreaterThan(0);
    const mutated = `${goldenText.slice(0, at)}"node_GENERATED"${goldenText.slice(at + '"node_generated"'.length)}`;
    const result = verifyArchive(mutated);
    expect(result.ok).toBe(false);
    expect(result.reasons.length).toBeGreaterThan(0);
  });

  it("negative: reordering the top-level archive fields makes the verifier fail closed", () => {
    const archive = JSON.parse(readGoldenText("recovery/archive.json.txt")) as Json;
    // Genuine reorder: settings_snapshot moved to the front (frozen sequence has it last).
    const reordered: Json = {
      settings_snapshot: archive.settings_snapshot,
      format: archive.format,
      manifest: archive.manifest,
      manifest_signature: archive.manifest_signature,
      wallet_sections: archive.wallet_sections,
      evidence_sections: archive.evidence_sections,
    };
    const result = verifyArchive(JSON.stringify(reordered));
    expect(result.ok).toBe(false);
  });

  it("the committed export and recovery-verification golden files hash to their pinned literals", () => {
    expect(sha256OfGolden("recovery/zp-backup-wallet-export-v1.preimage.txt")).toBe(PINNED.exportPreimageSha256);
    expect(sha256OfGolden("recovery/zp-backup-wallet-export-v1.digest.hex")).toBe(PINNED.exportDigestFileSha256);
    expect(sha256OfGolden("recovery/zp-backup-wallet-export-v1.sig.b64")).toBe(PINNED.exportSigFileSha256);
    expect(sha256OfGolden("recovery/zp-recovery-verification-v1.preimage.txt")).toBe(PINNED.recoveryPreimageSha256);
    expect(sha256OfGolden("recovery/zp-recovery-verification-v1.digest.hex")).toBe(PINNED.recoveryDigestFileSha256);
    expect(sha256OfGolden("recovery/zp-recovery-verification-v1.sig.b64")).toBe(PINNED.recoverySigFileSha256);
  });

  it("CHAINED GOLDEN: recovery-verification field 8 (export_sha256) IS the export golden's digest", () => {
    const exportDigest = readGoldenText("recovery/zp-backup-wallet-export-v1.digest.hex");
    expect(exportDigest).toBe(PINNED.exportPreimageSha256);

    const probePreimage = readGoldenText("recovery/zp-recovery-verification-v1.preimage.txt");
    const probeJson = probePreimage.slice(probePreimage.indexOf("\n") + 1);
    const probe = JSON.parse(probeJson) as Json;
    // Field 8 by frozen sequence is export_sha256; it must byte-equal the export golden digest.
    expect(Object.keys(probe)[7]).toBe("export_sha256");
    expect(probe.export_sha256).toBe(exportDigest);

    // The probe preimage's own sha256 equals the recovery digest.hex content.
    expect(sha256Hex(utf8Bytes(probePreimage))).toBe(readGoldenText("recovery/zp-recovery-verification-v1.digest.hex"));
  });

  it("the emitter reproduces the committed goldens byte-for-byte, in-process (tests never write goldens)", async () => {
    // Invoke the emitter's pure builder in-process — never via a child process, and never by a
    // committed test writing a golden (A8). Every freshly-built artifact must byte-match its
    // committed file, read back through the testkit golden reader.
    const artifacts = await buildArtifacts();
    for (const [name, body] of Object.entries(artifacts)) {
      expect(body, name).toBe(readGoldenText(`recovery/${name}`));
    }
  });
});
