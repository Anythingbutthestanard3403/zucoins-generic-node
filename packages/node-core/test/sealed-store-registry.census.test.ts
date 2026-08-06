// sealed-store registry completeness census.
//
// Two layers:
//   1. Descriptor census — each registered store binds to an INDEPENDENT source of truth
// (vault sub-freeze, COVERAGE_TABLES / COVERAGE_EXCLUSIONS, token). A
//      self-mirrored expected list is the defect the prior FAIL closed.
//   2. Structural seal-site SOURCE census — git greps packages/** for createCipheriv(
//      / createDecipheriv( and asserts equality with REGISTERED_SEAL_SITE_PATHS both ways.
//
// Governing: signing custody; the data model.

import { execFileSync } from "node:child_process";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  AAD_DOMAIN,
  AAD_SERIALIZATION,
  ENVELOPE_STRUCTURE,
  HKDF_DEK_LABEL,
  KEY_DERIVATION,
  KEY_ISOLATION,
  STORAGE_RESOLUTION,
  VAULT_STORAGE_GRAIN,
  VAULT_TABLE_NAME,
} from "@zucoins/generic-node-contracts/vault";

// recovery-drill is not a package export; bind via source path (vitest resolves .ts).
import {
  COVERAGE_EXCLUSIONS,
  COVERAGE_TABLES,
} from "../../generic-node-contracts/src/recovery-drill/coverage.contract.ts";

import { BACKUP_COVERAGE_TABLES } from "../src/core/backup/format.js";
// The push seal site itself — the independent source of truth for its HKDF label.
import {
  PUSH_RECEIVER_DEK_HKDF_LABEL,
  buildPushReceiverDekInfo,
} from "../src/push/seal.js";
import {
  NON_NODE_SEALED_SECRET_IDS,
  admitNonNodeSealedSecret,
  excludedSealSiteHits,
} from "../src/schema/sealed-store-exclusions.contract.js";
import {
  REGISTERED_SEAL_SITES,
  REGISTERED_SEAL_SITE_PATHS,
  ROOT_KEY_MATERIAL,
  SEALED_STORES,
  SEALED_STORE_IDS,
  sealSiteCensus,
  sealedStore,
  type SealedStoreId,
} from "../src/schema/sealed-store-registry.contract.js";

// ── Independent expected set (NOT copied from SEALED_STORES) ─────────────────
//
// Each id is justified by a citation outside this PR's manifest:
//   WALLET_VAULT  — VAULT_TABLE_NAME + vault sub-freeze
// NODE_SIGNING_KEYS — COVERAGE_TABLES contains node_signing_key_sealed_store
//   TOTP_SECRET  — COVERAGE_EXCLUSIONS.totp_and_session_secrets + label
//   SESSION_SECRETS  — same exclusion key (auth factor, not custody material)

const INDEPENDENT_STORE_ANCHORS: Record<
  SealedStoreId,
  { readonly reason: string; readonly check: () => void }
> = {
  WALLET_VAULT: {
    reason: "vault sub-freeze VAULT_TABLE_NAME === 'vault'",
    check: () => {
      expect(VAULT_TABLE_NAME).toBe("vault");
      expect(VAULT_STORAGE_GRAIN).toBe("PER_WALLET_ENVELOPE_ROW");
    },
  },
  NODE_SIGNING_KEYS: {
    reason: "COVERAGE_TABLES includes node_signing_key_sealed_store",
    check: () => {
      expect(COVERAGE_TABLES).toContain("node_signing_key_sealed_store");
      expect(COVERAGE_TABLES).toContain("node_signing_keys");
    },
  },
  PUSH_RECEIVER_SECRETS: {
    reason:
      "freezes per-wallet push receive material in push_subscriptions; the seal " +
      "site's own exported label is the shared-root domain anchor",
    check: () => {
      const push = sealedStore("PUSH_RECEIVER_SECRETS");
      expect(push?.storage.table).toBe("push_subscriptions");
      // Independence: the label comes from the production seal site, not the registry.
      expect(push?.encryption.hkdfLabel).toBe(PUSH_RECEIVER_DEK_HKDF_LABEL);
      expect(push?.encryption.hkdfLabelState).toBe("FROZEN");
      expect(push?.encryption.aad).toBe("zp-push-seal-v1|<node_id>|<wallet_id>|<purpose>");
      expect(push?.productionSealSite).toBe("packages/node-core/src/push/seal.ts");
    },
  },
  TOTP_SECRET: {
    reason: "COVERAGE_EXCLUSIONS.totp_and_session_secrets + label",
    check: () => {
      expect(COVERAGE_EXCLUSIONS.totp_and_session_secrets).toMatch(/authentication factors/i);
    },
  },
  SESSION_SECRETS: {
    reason: "COVERAGE_EXCLUSIONS.totp_and_session_secrets",
    check: () => {
      expect(COVERAGE_EXCLUSIONS.totp_and_session_secrets).toMatch(/authentication factors/i);
    },
  },
};

// frozen TOTP HKDF info — independent of the registry string (also shipped at
// apps/node/src/auth/totp-secret.ts TOTP_SECRET_HKDF_INFO; node-core cannot import apps/node).
const D8_119_TOTP_HKDF_INFO = "zupayments/totp-secret/v1";

describe("sealed-store registry — closed set completeness (independent anchors)", () => {
  it("registers exactly the five independently-anchored stores", () => {
    const anchoredIds = Object.keys(INDEPENDENT_STORE_ANCHORS).sort();
    expect([...SEALED_STORE_IDS].sort()).toEqual(anchoredIds);
    for (const anchor of Object.values(INDEPENDENT_STORE_ANCHORS)) {
      anchor.check();
    }
  });

  it("does not register reporting or webhook secrets; push receive secrets are admitted", () => {
    const excludedClasses = [
      "REPORTING_PRIVATE_KEY",
      "WEBHOOK_SIGNING_SECRET",
    ] as const;
    const forbiddenNames = [
      ...excludedClasses,
      "reporting_signing_key",
      "webhook_endpoints",
    ];
    for (const id of forbiddenNames) {
      expect(SEALED_STORE_IDS as readonly string[]).not.toContain(id);
    }
    for (const id of excludedClasses) {
      expect(admitNonNodeSealedSecret(id).admitted).toBe(false);
    }
    expect(NON_NODE_SEALED_SECRET_IDS).toEqual([...excludedClasses]);
    expect(SEALED_STORE_IDS).toContain("PUSH_RECEIVER_SECRETS");
    expect(admitNonNodeSealedSecret("PUSH_RECEIVER_SECRETS").admitted).toBe(true);
  });

  it("VAULT_MASTER_KEY is root key material, never a sealed store", () => {
    expect(SEALED_STORE_IDS as readonly string[]).not.toContain("VAULT_MASTER_KEY");
    expect(ROOT_KEY_MATERIAL.storage.databaseResident).toBe(false);
    expect(ROOT_KEY_MATERIAL.backupCoverage).toBe("EXCLUDED_ROOT_KEY");
    expect(ROOT_KEY_MATERIAL.derivation.iterations).toBe(600_000);
    expect(COVERAGE_EXCLUSIONS.master_key_and_plaintext_private_keys).toMatch(/never/i);
  });

  it("every database-resident store declares grain *_ENVELOPE_ROW (signing custody item 5)", () => {
    for (const s of SEALED_STORES) {
      expect(s.storage.databaseResident).toBe(true);
      expect(s.storage.grain, s.id).toMatch(/_ENVELOPE_ROW$/);
      if (s.storage.tableState === "FROZEN") {
        expect(s.storage.table, s.id).toBeTruthy();
      } else {
        expect(s.storage.table, s.id).toBeNull();
      }
    }
  });

  it("frozen HKDF labels are globally unique and non-null (i)", () => {
    const frozen = SEALED_STORES.filter((s) => s.encryption.hkdfLabelState === "FROZEN");
    const labels = frozen.map((s) => s.encryption.hkdfLabel);
    expect(labels.every((l) => typeof l === "string" && l.length > 0)).toBe(true);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("wallet, signing, and push stores have IMPLEMENTED rewrap support", () => {
    const implemented = SEALED_STORES.filter((s) => s.rewrapStatus === "IMPLEMENTED");
    expect(implemented.map((s) => s.id).sort()).toEqual([
      "NODE_SIGNING_KEYS",
      "PUSH_RECEIVER_SECRETS",
      "WALLET_VAULT",
    ]);
    expect(sealedStore("WALLET_VAULT")?.productionSealSite).toBe(
      "packages/node-core/src/vault/envelope.ts",
    );
    expect(sealedStore("NODE_SIGNING_KEYS")?.productionSealSite).toBe(
      "packages/node-core/src/signing-keys/sealed-store.ts",
    );
    expect(sealedStore("PUSH_RECEIVER_SECRETS")?.productionSealSite).toBe(
      "packages/node-core/src/push/seal.ts",
    );
    for (const s of SEALED_STORES) {
      if (
        s.id === "WALLET_VAULT" ||
        s.id === "NODE_SIGNING_KEYS" ||
        s.id === "PUSH_RECEIVER_SECRETS"
      ) continue;
      expect(s.rewrapStatus).toBe("DEFERRED_NO_SEAL_RUNTIME");
      expect(s.productionSealSite).toBeNull();
    }
  });
});

describe("wallet vault store bound to frozen vault sub-freeze", () => {
  const wallet = sealedStore("WALLET_VAULT");

  it("table, grain, cipher match the independent vault contract", () => {
    expect(wallet?.storage.table).toBe(VAULT_TABLE_NAME);
    expect(wallet?.storage.tableState).toBe("FROZEN");
    expect(wallet?.storage.grain).toBe(VAULT_STORAGE_GRAIN);
    expect(wallet?.storage.grain).toBe(STORAGE_RESOLUTION.v2_grain);
    expect(wallet?.encryption.cipher).toBe(ENVELOPE_STRUCTURE.cipher);
    expect(ENVELOPE_STRUCTURE.nonce_bits).toBe(96);
    expect(ENVELOPE_STRUCTURE.tag_bits).toBe(128);
    expect(ENVELOPE_STRUCTURE.stored_aad_column).toBe(false);
  });

  it("HKDF label is the independent wallet DEK label", () => {
    expect(wallet?.encryption.hkdfLabel).toBe(HKDF_DEK_LABEL);
    expect(wallet?.encryption.hkdfLabelState).toBe("FROZEN");
    expect(KEY_DERIVATION.wallet_dek.algorithm).toBe("HKDF-SHA256");
    expect(KEY_DERIVATION.wallet_dek.info_binds).toEqual(["node_id", "wallet_id", "key_version"]);
  });

  it("AAD uses real single-LF (0x0A) joiners, not backslash-n literals", () => {
    const aad = wallet?.encryption.aad ?? "";
    expect(aad).not.toContain("\\n");
    expect(aad.split("\n")[0]).toBe(AAD_DOMAIN);
    for (const field of AAD_SERIALIZATION.field_sequence.slice(1)) {
      expect(aad, `AAD binds ${field}`).toContain(field);
    }
    expect(KEY_ISOLATION.per_wallet_dek).toBe(true);
  });
});

describe("TOTP_SECRET binds frozen HKDF label (independent token)", () => {
  it("hkdfLabel equals the register token, state FROZEN", () => {
    const totp = sealedStore("TOTP_SECRET");
    expect(totp?.encryption.hkdfLabel).toBe(D8_119_TOTP_HKDF_INFO);
    expect(totp?.encryption.hkdfLabelState).toBe("FROZEN");
    // Independence: the constant above is local to this test file, not imported from the registry.
    expect(D8_119_TOTP_HKDF_INFO).toBe("zupayments/totp-secret/v1");
  });
});

describe("NODE_SIGNING_KEYS frozen shape and SESSION_SECRETS deferred", () => {
  it("NODE_SIGNING_KEYS table and HKDF label are FROZEN", () => {
    const n = sealedStore("NODE_SIGNING_KEYS");
    expect(n?.storage.tableState).toBe("FROZEN");
    expect(n?.storage.table).toBe("node_signing_key_sealed_store");
    expect(n?.encryption.hkdfLabelState).toBe("FROZEN");
    expect(n?.encryption.hkdfLabel).toBe("zp-node-signing-dek-v1");
    expect(n?.encryption.aad.split("\n")[0]).toBe("zp-node-signing-secret-v1");
    expect(n?.encryption.aad).not.toContain("\\n");
    expect(n?.rewrapStatus).toBe("IMPLEMENTED");
    expect(n?.name).toBe("node_signing_key_sealed_store");
    expect(COVERAGE_TABLES).toContain(n?.name);
  });

  it("SESSION_SECRETS is DEFERRED and backup-excluded as an auth factor", () => {
    const s = sealedStore("SESSION_SECRETS");
    expect(s?.storage.tableState).toBe("DEFERRED");
    expect(s?.encryption.hkdfLabelState).toBe("DEFERRED");
    expect(s?.backupCoverage).toBe("EXCLUDED_AUTH_FACTOR");
  });
});

describe("PUSH_RECEIVER_SECRETS frozen HKDF domain and backup posture", () => {
  const push = sealedStore("PUSH_RECEIVER_SECRETS");

  it("derives under its own i label, distinct from every other store's", () => {
    expect(PUSH_RECEIVER_DEK_HKDF_LABEL).toBe("zp-push-receiver-dek-v1");
    expect(PUSH_RECEIVER_DEK_HKDF_LABEL).not.toBe(HKDF_DEK_LABEL);
    expect(push?.encryption.hkdfLabel).toBe(PUSH_RECEIVER_DEK_HKDF_LABEL);
    expect(push?.encryption.hkdfLabelState).toBe("FROZEN");
    expect(push?.rewrapStatus).toBe("IMPLEMENTED");
  });

  it("HKDF info uses real single-LF joiners and binds node_id then wallet_id", () => {
    const info = buildPushReceiverDekInfo({ nodeId: "<node_id>", walletId: "<wallet_id>" });
    expect(info).toBe("zp-push-receiver-dek-v1\n<node_id>\n<wallet_id>");
    expect(info).not.toContain("\\n");
    // No key_version segment: rotation is trial-decrypt over a key ring, not a versioned info.
    expect(info.split("\n")).toHaveLength(3);
  });

  it("is backup-EXCLUDED as node-regenerable, its table never in COVERAGE_TABLES", () => {
    expect(push?.backupCoverage).toBe("EXCLUDED_REGENERABLE");
    // Not an amendment to(2): push_subscriptions is absent from the data model
    // mandated set, so COVERAGE_TABLES was never wrong to omit it.
    expect(COVERAGE_TABLES as readonly string[]).not.toContain("push_subscriptions");
    // frozen backup format is likewise untouched — no new table, no new goldens.
    expect(BACKUP_COVERAGE_TABLES as readonly string[]).not.toContain("push_subscriptions");
    expect(COVERAGE_EXCLUSIONS.push_receive_material).toMatch(/re-minted and re-registered/i);
    expect(COVERAGE_EXCLUSIONS.push_receive_material).toMatch(/never archived/i);
  });
});

describe("seal-site SOURCE census — every packages/** AES-GCM site is registered", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], { cwd: here })
    .toString()
    .trim();

  const scanSealSites = (): string[] =>
    execFileSync(
      "git",
      ["grep", "-lE", "createCipheriv\\(|createDecipheriv\\(", "--", "packages"],
      { cwd: repoRoot },
    )
      .toString()
      .trim()
      .split("\n")
      .filter((p) => p.endsWith(".ts") && !p.endsWith(".test.ts") && !p.includes("/test/"))
      .sort();

  it("scan finds every production seal site and the recovery-drill envelope", () => {
    const found = scanSealSites();
    expect(found).toContain("packages/node-core/src/vault/envelope.ts");
    expect(found).toContain("packages/node-core/src/signing-keys/sealed-store.ts");
    expect(found).toContain("packages/node-core/src/push/seal.ts");
    expect(found).toContain("packages/generic-node-contracts/src/recovery-drill/envelope.ts");
  });

  it("every found seal site is registered and no registration is stale (both directions)", () => {
    const found = scanSealSites();
    const { unregistered, stale } = sealSiteCensus(found);
    expect(
      unregistered,
      "unregistered seal sites — master-key rotation would ORPHAN these",
    ).toEqual([]);
    expect(stale, "stale seal-site registrations").toEqual([]);
    // Exact set equality (permutation-invariant).
    expect([...found].sort()).toEqual([...REGISTERED_SEAL_SITE_PATHS].sort());
  });

  it("every registered seal site binds to a store present in the registry", () => {
    for (const site of REGISTERED_SEAL_SITES) {
      expect(SEALED_STORE_IDS, `${site.path} -> ${site.store}`).toContain(site.store);
    }
  });

  it("FAILS when a new seal site is present but unregistered (negative path)", () => {
    const synthetic = "packages/node-core/src/schema/__unregistered_seal_site__.ts";
    const { unregistered } = sealSiteCensus([...REGISTERED_SEAL_SITE_PATHS, synthetic]);
    expect(unregistered).toEqual([synthetic]);
    expect(() => expect(unregistered).toEqual([])).toThrow();
  });

  it("FAILS when a registered site is removed from source (stale negative path)", () => {
    const foundWithoutProd = REGISTERED_SEAL_SITE_PATHS.filter(
      (p) => p !== "packages/node-core/src/vault/envelope.ts",
    );
    const { stale } = sealSiteCensus(foundWithoutProd);
    expect(stale).toContain("packages/node-core/src/vault/envelope.ts");
  });

  it("excluded-by-canon classes have no seal-site hits under packages/**", () => {
    const hits = excludedSealSiteHits(scanSealSites());
    expect(hits).toEqual([]);
  });
});
