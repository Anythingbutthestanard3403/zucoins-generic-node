// Residual — v2 generic node does NOT seal reporting / webhook
// secrets. Push receive secrets are admitted to the live registry and tested there.
// packages/** AES-GCM seal site currently sits under an exclusion marker path,
// and (3) fails closed if a future unregistered seal site appears under those
// markers while disposition remains EXCLUDED_BY_CANON.
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  NON_NODE_SEALED_SECRETS,
  NON_NODE_SEALED_SECRET_IDS,
  SEALED_STORE_EXCLUSIONS_SOURCE,
  admitNonNodeSealedSecret,
  excludedSealSiteHits,
  type NonNodeSealedSecretClass,
} from "../src/schema/sealed-store-exclusions.contract.ts";

/**
 * Structural scan — same primitive family as the v1 rotate-master-key census and
 * the seal-site register: you cannot AES-256-GCM-seal without
 * createCipheriv/createDecipheriv. Scoped to packages/** (v2 generic-node +
 * contracts); apps/node and apps/platform own their own censuses.
 */
function scanPackageSealSites(): string[] {
  const out = execFileSync(
    "git",
    [
      "grep",
      "-lE",
      "createCipheriv\\(|createDecipheriv\\(",
      "--",
      "packages",
      ":!*.test.ts",
      ":!**/test/**",
      ":!**/__vectors__/**",
      ":!**/__fuzz-corpus__/**",
    ],
    {
      encoding: "utf8",
      cwd: resolve(dirname(fileURLToPath(import.meta.url)), "../../.."),
    },
  ).trim();
  if (out.length === 0) {
    return [];
  }
  return out.split("\n").filter((line) => line.length > 0).sort();
}

describe("sealed-store exclusions", () => {
  it("closed set retains exactly reporting and webhook after push admission", () => {
    expect([...NON_NODE_SEALED_SECRET_IDS]).toEqual([
      "REPORTING_PRIVATE_KEY",
      "WEBHOOK_SIGNING_SECRET",
    ]);
    expect(NON_NODE_SEALED_SECRETS).toHaveLength(2);
    expect(SEALED_STORE_EXCLUSIONS_SOURCE).toContain("sealed-store census residual");
  });

  it("every entry is EXCLUDED_BY_CANON with a non-empty authority citation", () => {
    for (const entry of NON_NODE_SEALED_SECRETS) {
      expect(entry.disposition).toBe("EXCLUDED_BY_CANON");
      expect(entry.authority.length).toBeGreaterThan(20);
      expect(entry.sharedRootHkdfReconciliation.length).toBeGreaterThan(20);
      expect(entry.sealSitePathMarkers.length).toBeGreaterThan(0);
    }
  });

  it("admission refuses excluded ids and admits registered or unrelated ids", () => {
    for (const id of NON_NODE_SEALED_SECRET_IDS) {
      const result = admitNonNodeSealedSecret(id);
      expect(result.admitted).toBe(false);
      if (!result.admitted) {
        expect(result.reason).toContain(id);
        expect(result.reason).toContain("EXCLUDED_BY_CANON");
      }
    }
    expect(admitNonNodeSealedSecret("WALLET_VAULT").admitted).toBe(true);
    expect(admitNonNodeSealedSecret("NODE_SIGNING_KEYS").admitted).toBe(true);
    expect(admitNonNodeSealedSecret("PUSH_RECEIVER_SECRETS").admitted).toBe(true);
    expect(admitNonNodeSealedSecret("TOTP_SECRET").admitted).toBe(true);
  });

  it("structural packages/** seal-site scan finds zero hits under exclusion markers", () => {
    const found = scanPackageSealSites();
    // Sanity: production vault + drill envelope exist on main today.
    expect(found.some((p) => p.includes("vault/envelope.ts"))).toBe(true);
    expect(found.some((p) => p.includes("recovery-drill/envelope.ts"))).toBe(true);

    const hits = excludedSealSiteHits(found);
    expect(hits).toEqual([]);
  });

  it("negative path: a synthetic seal site under a marker fails the exclusion census", () => {
    const synthetic = [
      "packages/node-core/src/webhooks/secret.ts",
      "packages/node-core/src/vault/envelope.ts",
    ];
    const hits = excludedSealSiteHits(synthetic);
    expect(hits.some((h) => h.id === "WEBHOOK_SIGNING_SECRET")).toBe(true);
    expect(hits.some((h) => h.path.includes("webhooks/secret"))).toBe(true);
    // Vault path is not an exclusion marker — must not false-positive.
    expect(hits.some((h) => h.path.includes("vault/envelope"))).toBe(false);
  });

  it("negative path: reporting-key-store trips while admitted push crypto does not", () => {
    const reportingHits = excludedSealSiteHits([
      "packages/node-core/src/reporting/reporting-key-store.ts",
    ]);
    expect(reportingHits.map((h) => h.id)).toContain("REPORTING_PRIVATE_KEY");

    const pushHits = excludedSealSiteHits([
      "packages/node-core/src/receivers/push/crypto/at-rest.ts",
    ]);
    expect(pushHits).toEqual([]);
  });

  it("ids are unique and marker sets are non-empty unique strings", () => {
    const ids = new Set<NonNodeSealedSecretClass>();
    for (const entry of NON_NODE_SEALED_SECRETS) {
      expect(ids.has(entry.id)).toBe(false);
      ids.add(entry.id);
      const markers = new Set(entry.sealSitePathMarkers);
      expect(markers.size).toBe(entry.sealSitePathMarkers.length);
      for (const marker of entry.sealSitePathMarkers) {
        expect(marker.length).toBeGreaterThan(3);
        expect(marker.includes(" ")).toBe(false);
      }
    }
  });
});
