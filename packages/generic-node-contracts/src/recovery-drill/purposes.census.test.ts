import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { ZP_V1_PURPOSES } from "../compat-literals/compat-literals.contract.ts";
import {
  BACKUP_ARCHIVE_FORMAT,
  BACKUP_WALLET_EXPORT_PURPOSE,
  BACKUP_MANIFEST_PURPOSE,
  RECOVERY_VERIFICATION_PURPOSE,
  RECOVERY_LANE_PURPOSES,
  RECOVERY_PROBE_IS_NOT_MONEY_PATH,
  BACKUP_WALLET_EXPORT_FIELDS,
  BACKUP_WALLET_EXPORT_VAULT_FIELDS,
  BACKUP_MANIFEST_FIELDS,
  RECOVERY_VERIFICATION_FIELDS,
  BACKUP_ARCHIVE_TOP_LEVEL_FIELDS,
} from "./purposes.contract.ts";

/**
 * the recovery-drill lane purposes census. The three the recovery-drill concern backup/restore/recovery purposes are a SEPARATE
 * registry from `ZP_V1_PURPOSES`, which is frozen at exactly ten (the A.3-A.7 signed/hashed
 * suite-tuple family). This lane MUST NOT append to `ZP_V1_PURPOSES` — doing so would mutate a
 * frozen closed set and contaminate the signing-capability money-path capability union. The recovery probe is a
 * recovery-lane purpose only: it is not money-path, cannot parse as a SplitChain inner, and no
 * money-path capability can mint it (the fresh-probe rules).
 */
describe("recovery purposes census (archive, ceremony, drill matrix)", () => {
  it("freezes the three the recovery-drill concern-lane purposes in registration sequence", () => {
    assertFieldOrder(RECOVERY_LANE_PURPOSES, [
      "zp-backup-wallet-export-v1",
      "zp-node-backup-manifest-v1",
      "zp-recovery-verification-v1",
    ]);
  });

  it("ZP_V1_PURPOSES is UNCHANGED at exactly ten (this lane never appends to the money-path registry)", () => {
    expect(ZP_V1_PURPOSES).toHaveLength(10);
    for (const purpose of RECOVERY_LANE_PURPOSES) {
      expect(ZP_V1_PURPOSES).not.toContain(purpose);
    }
  });

  it("the recovery probe is pinned as NOT money-path / NOT a SplitChain inner", () => {
    expect(RECOVERY_PROBE_IS_NOT_MONEY_PATH.purpose).toBe(RECOVERY_VERIFICATION_PURPOSE);
    expect(RECOVERY_PROBE_IS_NOT_MONEY_PATH.in_wallet_signing_capability_union).toBe(false);
    expect(RECOVERY_PROBE_IS_NOT_MONEY_PATH.parseable_as_splitchain_inner).toBe(false);
    expect(RECOVERY_PROBE_IS_NOT_MONEY_PATH.chain_valid).toBe(false);
  });

  it("freezes the archive format discriminator and the three purpose literals", () => {
    expect(BACKUP_ARCHIVE_FORMAT).toBe("zp-node-backup-v1");
    expect(BACKUP_WALLET_EXPORT_PURPOSE).toBe("zp-backup-wallet-export-v1");
    expect(BACKUP_MANIFEST_PURPOSE).toBe("zp-node-backup-manifest-v1");
    expect(RECOVERY_VERIFICATION_PURPOSE).toBe("zp-recovery-verification-v1");
  });

  it("freezes the wallet-export section export field sequence (fields 1-9; field 10 signature is never in the preimage)", () => {
    assertFieldOrder(BACKUP_WALLET_EXPORT_FIELDS, [
      "purpose",
      "canonical_version",
      "node_id",
      "export_id",
      "wallet_id",
      "public_key",
      "key_origin",
      "key_version",
      "vault",
    ]);
    expect(BACKUP_WALLET_EXPORT_FIELDS).toHaveLength(9);
  });

  it("freezes the verbatim vault-row field sequence carried inside export field 9", () => {
    assertFieldOrder(BACKUP_WALLET_EXPORT_VAULT_FIELDS, [
      "wallet_id",
      "key_version",
      "ciphertext",
      "nonce",
      "auth_tag",
      "ciphertext_sha256",
      "created_at",
      "rotated_at",
    ]);
  });

  it("freezes the manifest/digest rules manifest field sequence (fields 1-10)", () => {
    assertFieldOrder(BACKUP_MANIFEST_FIELDS, [
      "purpose",
      "canonical_version",
      "format",
      "node_id",
      "export_id",
      "exported_at",
      "wallets",
      "node_signing_keys",
      "evidence_index",
      "settings_sha256",
    ]);
    expect(BACKUP_MANIFEST_FIELDS).toHaveLength(10);
  });

  it("freezes the fresh-probe rules recovery-verification field sequence (fields 1-11; field 8 is the chain link)", () => {
    assertFieldOrder(RECOVERY_VERIFICATION_FIELDS, [
      "purpose",
      "canonical_version",
      "node_id",
      "wallet_id",
      "public_key",
      "key_version",
      "export_id",
      "export_sha256",
      "ceremony_id",
      "ceremony_nonce",
      "issued_at",
    ]);
    expect(RECOVERY_VERIFICATION_FIELDS[7]).toBe("export_sha256");
  });

  it("freezes the archive-envelope encoding top-level archive field sequence", () => {
    assertFieldOrder(BACKUP_ARCHIVE_TOP_LEVEL_FIELDS, [
      "format",
      "manifest",
      "manifest_signature",
      "wallet_sections",
      "evidence_sections",
      "settings_snapshot",
    ]);
  });

  it("rejects a fourth the recovery-drill concern-lane purpose (closed registry, negative path)", () => {
    expectRejects(
      () => [...RECOVERY_LANE_PURPOSES, "zp-fourth-recovery-v1"],
      (mutated) => assertFieldOrder(mutated, [...RECOVERY_LANE_PURPOSES]),
    );
  });

  it("rejects appending the recovery-drill concern purpose onto ZP_V1_PURPOSES (negative path)", () => {
    expectRejects(
      () => [...ZP_V1_PURPOSES, RECOVERY_VERIFICATION_PURPOSE],
      (mutated) => assertFieldOrder(mutated, [...ZP_V1_PURPOSES]),
    );
  });
});
