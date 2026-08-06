import type { FixtureProvenanceRecord } from "../types.ts";

/**
 * the recovery-drill destroy-restore / corrupt-recovery drill goldens — the canonical-constructor
 * provenance case. Three fixture families share the `goldens/recovery/` directory: the
 * `zp-node-backup-v1` archive (indexed by `manifest.json`), the wallet export section, and
 * the recovery-verification probe. All bytes are V2 suite canonical tuples (domain-separated
 * `zp-*-v1` purposes), emitted offline by the quarantined generator; NONE
 * of the key material ever touches live ZKZ.
 */
const RECOVERY_DRILL_GENERATOR = "packages/generic-node-contracts/scripts/emit-recovery-golden.ts";

const RECOVERY_DRILL_WALLET_VERSION = "n/a — offline canonical constructor; no wallet capture";

const RECOVERY_DRILL_KEY_MATERIAL =
  "deterministic test-only 32-byte filled Ed25519 seeds (node identity 0x00; wallets 0x11/0x12/0x13) " +
  "and a synthetic boot root fill 0xa1 (already-derived PBKDF2 output); MUST never be used with live ZKZ";

const RECOVERY_DRILL_CONSTRUCTION =
  "objects built with keys fixed in construction sequence and serialized only with JSON.stringify; " +
  "no gateway capture, import, or live-chain submission; the generator is quarantined from the committed " +
  "test path (no committed test writes a golden)";

export const RECOVERY_DRILL_FIXTURE_RECORDS: readonly FixtureProvenanceRecord[] = [
  {
    fixtureId: "recovery/manifest",
    byteClass: "suite-tuple",
    indexPath: "goldens/recovery/manifest.json",
    files: [
      { path: "goldens/recovery/manifest.json", sha256: "19cf91fba2c46dcf8afd40724f0196f1456754535a26f0f8f8a4143d06902d20" },
      { path: "goldens/recovery/archive.json.txt", sha256: "4037e574a0f823a37acbe2d0154b6bd90631700c64d921125eea812697e71dbc" },
    ],
    provenance: {
      originKind: "canonical-constructor",
      captureMethod:
        "Offline canonical constructor emitted the `zp-node-backup-v1` archive over the synthetic " +
        "drill world; the archive passes the independent all-or-nothing verifier before it is admitted " +
        "as byte authority; " +
        RECOVERY_DRILL_CONSTRUCTION,
      captureDate: "2026-07-21",
      walletVersion: RECOVERY_DRILL_WALLET_VERSION,
      source: RECOVERY_DRILL_GENERATOR,
      keyMaterial: RECOVERY_DRILL_KEY_MATERIAL,
      specCitations: [
        "signing-custody-security: backup archive contents",
        "signing-custody-security: backup signing rules",
        "signing-custody-security: all-or-nothing archive verification",
        "build-test plan: destroy-restore and corrupt-recovery drills",
      ],
      decisionRefs: ["backup-archive-freeze"],
      details: {
        generator: RECOVERY_DRILL_GENERATOR,
        concern: "recovery-drill",
        manifest_note: "manifest.json is the provenance index; archive.json.txt is the frozen zp-node-backup-v1 archive it pins",
        independent_verifier: "src/recovery-drill/verify.ts verifyArchive (all-or-nothing)",
      },
    },
  },
  {
    fixtureId: "recovery/zp-backup-wallet-export-v1",
    byteClass: "suite-tuple",
    indexPath: "goldens/recovery/zp-backup-wallet-export-v1.meta.json",
    files: [
      { path: "goldens/recovery/zp-backup-wallet-export-v1.meta.json", sha256: "dd56195e315775836444756cc61abe32d36f847d2942490032c8ad91d75aac8d" },
      { path: "goldens/recovery/zp-backup-wallet-export-v1.digest.hex", sha256: "7ec0132968e1cecb5c9303bbf4dbdf4a261133516360c90c328a61e863e58dbc" },
      { path: "goldens/recovery/zp-backup-wallet-export-v1.preimage.txt", sha256: "62055b5120268032d64e94e5a9210e3693fa7d4f143978cc00769ce4b6d44e44" },
      { path: "goldens/recovery/zp-backup-wallet-export-v1.sig.b64", sha256: "0396b761eb3d4507e32a5ddc2132e30f9ef8e01e1f80637e3ce5f9e0325843f1" },
    ],
    provenance: {
      originKind: "canonical-constructor",
      captureMethod:
        "Offline canonical constructor emitted the wallet export section: a REAL AES-256-GCM " +
        "seal of the 64-byte Ed25519 wallet secret under the HKDF-Expand-only DEK (frozen six-field AAD), with a " +
        "genuine Ed25519 wallet-key proof signature over the suite-tuple preimage; " +
        RECOVERY_DRILL_CONSTRUCTION,
      captureDate: "2026-07-21",
      walletVersion: RECOVERY_DRILL_WALLET_VERSION,
      source: RECOVERY_DRILL_GENERATOR,
      keyMaterial:
        "deterministic test-only 32-byte filled Ed25519 seed byte 0x11 (wallet 1) and a synthetic boot root " +
        "fill 0xa1; MUST never be used with live ZKZ",
      specCitations: [
        "signing-custody-security: wallet export section",
        "canonical-fields reference: suite-tuple preimage fields",
      ],
      decisionRefs: ["backup-archive-freeze"],
      details: {
        generator: RECOVERY_DRILL_GENERATOR,
        concern: "recovery-drill",
        seal_note: "REAL seal fixture — the vault ciphertext is a genuine GCM seal and export_proof_signature a genuine wallet-key signature",
      },
    },
  },
  {
    fixtureId: "recovery/zp-recovery-verification-v1",
    byteClass: "suite-tuple",
    indexPath: "goldens/recovery/zp-recovery-verification-v1.meta.json",
    files: [
      { path: "goldens/recovery/zp-recovery-verification-v1.meta.json", sha256: "97574e68b4526f1d4e3d6e058c9c7eda7a9852b6b4f8ba9acf30209771f757f5" },
      { path: "goldens/recovery/zp-recovery-verification-v1.digest.hex", sha256: "188903c11e074e9d093d884dcd38f579dc386ab1ded178047ea32b70bf81cb94" },
      { path: "goldens/recovery/zp-recovery-verification-v1.preimage.txt", sha256: "f5c08d42c72656b056445f9c3d559fd2cc767e10abf56494de355bc665a7dd8a" },
      { path: "goldens/recovery/zp-recovery-verification-v1.sig.b64", sha256: "a8d14c8697da790588ca7bfc0f95caf9ac215f05577d0aae3d94bf9790d2a8bc" },
    ],
    provenance: {
      originKind: "canonical-constructor",
      captureMethod:
        "Offline canonical constructor emitted the fresh recovery-verification probe: field 8 " +
        "`export_sha256` chains to the zp-backup-wallet-export-v1 golden's wallet-export digest, signed by the same " +
        "wallet key the ceremony recovers by opening the real seal; a recovery-lane purpose only — it cannot " +
        "parse as a SplitChain inner and no money path can mint it; " +
        RECOVERY_DRILL_CONSTRUCTION,
      captureDate: "2026-07-21",
      walletVersion: RECOVERY_DRILL_WALLET_VERSION,
      source: RECOVERY_DRILL_GENERATOR,
      keyMaterial:
        "deterministic test-only 32-byte filled Ed25519 seed byte 0x11 (wallet 1, the recovered signer); " +
        "MUST never be used with live ZKZ",
      specCitations: [
        "signing-custody-security: recovery-verification probe",
        "canonical-fields reference: suite-tuple preimage fields",
      ],
      decisionRefs: ["recovery-verification-probe-freeze"],
      details: {
        generator: RECOVERY_DRILL_GENERATOR,
        concern: "recovery-drill",
        chain_invariant: "probe field 8 (export_sha256) === zp-backup-wallet-export-v1.digest.hex content",
      },
    },
  },
];
