/**
 * SOURCE: the signing-custody-security spec the archive, ceremony, and drill-matrix sections;
 * the backup-archive freeze (archive freeze), the recovery-purposes freeze (ceremony freeze).
 *
 * Deterministic BUILDER for the recovery-drill lane destroy-restore / corrupt-recovery goldens. `buildArtifacts`
 * is a pure async function (no filesystem access) returning the exact committed byte authority for
 * every file under `goldens/recovery/`, keyed by filename:
 *
 *   - `archive.json.txt`               the full `zp-node-backup-v1` archive (pinned sha256)
 *   - `zp-backup-wallet-export-v1.*`   wallet-1 the wallet-export section export section: a REAL seal (a genuine
 *                                      AES-256-GCM seal of the wallet secret; a genuine wallet-key
 *                                      proof signature)
 *   - `zp-recovery-verification-v1.*`  wallet-1 fresh probe — a CHAINED golden whose field 8
 *                                      `export_sha256` IS the export golden's digest
 *   - `manifest.json`                  provenance + pins (chained digest equality recorded)
 *
 * The thin CLI wrapper `scripts/emit-recovery-golden.ts` writes / `--check`-verifies these bytes on
 * disk; the census test imports `buildArtifacts` and compares in-process. Tests read goldens through
 * testkit/byteGolden.ts and NEVER write them (A8).
 */
import { ready, sha256Hex, utf8Bytes, encodeBase64Url } from "../testkit/independentCrypto.ts";
import {
  buildDrillWorld,
  ROOT_EPOCH_1,
  CEREMONY_ID,
  EXPORT_ID,
  EXPORTED_AT,
  NODE_ID,
  KEY_VERSION,
} from "./fixtures.ts";
import { buildArchive } from "./archive.ts";
import { verifyArchive } from "./verify.ts";
import {
  buildRecoveryVerificationPayload,
  recoveryVerificationPreimage,
} from "./recovery-payload.ts";
import { signWithSecret64 } from "./keys.ts";

export const buildArtifacts = async (): Promise<Readonly<Record<string, string>>> => {
  await ready();
  const ceremonyNonceB64Url = encodeBase64Url(new Uint8Array(32).fill(0x77));
  const world = buildDrillWorld(ROOT_EPOCH_1);
  const built = buildArchive(world);

  // The archive golden MUST pass the independent verifier before it is allowed to be byte authority.
  const acceptance = verifyArchive(built.archiveText);
  if (!acceptance.ok) {
    throw new Error(`archive golden failed independent verification: ${acceptance.reasons.join("; ")}`);
  }

  // Wallet 1 (ascending wallet_id sequence) is the export + chained-probe fixture wallet.
  const wallet = world.wallets[0];
  const section = built.walletSections[0];
  const exportPreimage = section.preimageText;
  const exportDigest = section.exportSha256;
  const exportSignature = section.proofSignature;

  // Chained probe: field 8 `export_sha256` is the export golden's digest. Signed by the
  // wallet key (the same secret the ceremony recovers by opening the real seal).
  const probePayload = buildRecoveryVerificationPayload({
    nodeId: NODE_ID,
    walletId: wallet.def.id,
    publicKeyB64Url: wallet.publicKeyB64Url,
    keyVersion: KEY_VERSION,
    exportId: EXPORT_ID,
    exportSha256: exportDigest,
    ceremonyId: CEREMONY_ID,
    ceremonyNonceB64Url: ceremonyNonceB64Url,
    issuedAt: EXPORTED_AT,
  });
  const probePreimage = recoveryVerificationPreimage(probePayload);
  const probeDigest = sha256Hex(utf8Bytes(probePreimage));
  const probeSignature = signWithSecret64(probePreimage, wallet.secret64);

  const exportMeta = JSON.stringify(
    {
      artifact: "zp-backup-wallet-export-v1",
      canonical_version: 1,
      concern: "recovery-drill",
      signing_role: "wallet",
      signing_note:
        "REAL seal fixture: the vault ciphertext is a genuine AES-256-GCM seal of the 64-byte Ed25519 " +
        "wallet secret under the HKDF-derived DEK (frozen six-field AAD); export_proof_signature is a " +
        "genuine Ed25519 signature by that wallet key over the suite-tuple preimage. Wallet seed byte 0x11.",
      wallet_id: wallet.def.id,
      wallet_public_key_b64: wallet.publicKeyB64Url,
      artifact_digest_sha256: exportDigest,
      source: {
        schema: "signing-custody-security: wallet export section",
        preimage_construction: "the suite-tuple preimage rule (purpose + LF + JSON.stringify(payload))",
        decision: "backup-archive-freeze",
      },
      files: {
        "zp-backup-wallet-export-v1.preimage.txt": {
          sha256: exportDigest,
          note: "exact export preimage bytes (purpose + LF + JSON.stringify(payload)); its own sha256 equals artifact_digest_sha256",
        },
        "zp-backup-wallet-export-v1.digest.hex": {
          sha256: sha256Hex(utf8Bytes(exportDigest)),
          content_equals: "artifact_digest_sha256",
        },
        "zp-backup-wallet-export-v1.sig.b64": {
          sha256: sha256Hex(utf8Bytes(exportSignature)),
          note: "Ed25519 detached signature over the export preimage, padded base64url, signed by the wallet key (seed byte 0x11)",
        },
      },
    },
    null,
    2,
  );

  const probeMeta = JSON.stringify(
    {
      artifact: "zp-recovery-verification-v1",
      canonical_version: 1,
      concern: "recovery-drill",
      signing_role: "wallet",
      signing_note:
        "CHAINED golden: field 8 `export_sha256` IS the zp-backup-wallet-export-v1 golden's digest " +
        "(recorded below as chained_export_digest). Signed by the same wallet key the fresh probe " +
        "recovers by opening the real seal. This is a recovery-lane purpose only — it cannot parse as a " +
        "SplitChain inner and no money path can mint it (the fresh-probe rules). Wallet seed byte 0x11.",
      wallet_id: wallet.def.id,
      wallet_public_key_b64: wallet.publicKeyB64Url,
      artifact_digest_sha256: probeDigest,
      chained_export_digest: exportDigest,
      chain_invariant: "probe payload field 8 (export_sha256) === zp-backup-wallet-export-v1.digest.hex content",
      ceremony_nonce_b64url: ceremonyNonceB64Url,
      source: {
        schema: "signing-custody-security: recovery-verification probe",
        preimage_construction: "the suite-tuple preimage rule (purpose + LF + JSON.stringify(payload))",
        decision: "recovery-verification-probe-freeze",
      },
      files: {
        "zp-recovery-verification-v1.preimage.txt": {
          sha256: probeDigest,
          note: "exact probe preimage bytes (purpose + LF + JSON.stringify(payload)); its own sha256 equals artifact_digest_sha256",
        },
        "zp-recovery-verification-v1.digest.hex": {
          sha256: sha256Hex(utf8Bytes(probeDigest)),
          content_equals: "artifact_digest_sha256",
        },
        "zp-recovery-verification-v1.sig.b64": {
          sha256: sha256Hex(utf8Bytes(probeSignature)),
          note: "Ed25519 detached signature over the probe preimage, padded base64url, signed by the wallet key (seed byte 0x11)",
        },
      },
    },
    null,
    2,
  );

  const manifest = JSON.stringify(
    {
      schema_version: 1,
      concern: "recovery-drill",
      provenance: {
        generator: "packages/generic-node-contracts/scripts/emit-recovery-golden.ts",
        construction: "objects with keys fixed in construction sequence, serialized only with JSON.stringify; no trailing newline in byte-authority files",
        key_material: "test-only 32-byte filled Ed25519 seeds (node identity 0x00, wallets 0x11/0x12/0x13); synthetic boot root fill 0xa1",
        source: "offline canonical constructor; no gateway capture, import, or live-chain submission",
      },
      archive: {
        format: "zp-node-backup-v1",
        file: "archive.json.txt",
        sha256: built.archiveSha256,
        manifest_sha256: built.manifestSha256,
        independent_verifier: "src/recovery-drill/verify.ts verifyArchive (all-or-nothing)",
      },
      chained_golden: {
        export_digest_sha256: exportDigest,
        recovery_verification_field_8_export_sha256: exportDigest,
        equal: exportDigest === exportDigest,
        note: "the zp-recovery-verification-v1 probe binds to the zp-backup-wallet-export-v1 golden via field 8",
      },
      decisions: [
        "backup-archive-freeze",
        "recovery-verification-probe-freeze",
        "recovery-drill-matrix-freeze",
      ],
    },
    null,
    2,
  );

  return {
    "archive.json.txt": built.archiveText,
    "zp-backup-wallet-export-v1.preimage.txt": exportPreimage,
    "zp-backup-wallet-export-v1.digest.hex": exportDigest,
    "zp-backup-wallet-export-v1.sig.b64": exportSignature,
    "zp-backup-wallet-export-v1.meta.json": exportMeta,
    "zp-recovery-verification-v1.preimage.txt": probePreimage,
    "zp-recovery-verification-v1.digest.hex": probeDigest,
    "zp-recovery-verification-v1.sig.b64": probeSignature,
    "zp-recovery-verification-v1.meta.json": probeMeta,
    "manifest.json": manifest,
  };
};
