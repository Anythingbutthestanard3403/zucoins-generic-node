import { describe, expect, it } from "vitest";
import {
  FORBIDDEN_NAV_LABELS,
  FORBIDDEN_NAV_PATHS,
  LEGACY_PRODUCTION_NAV_LABELS,
  LEGACY_PRODUCTION_NAV_PATHS,
  LEGACY_ROUTE_REDIRECTS,
  PRIMARY_NAV_KEYS,
  PRIMARY_NAV_SECTIONS,
  PRODUCTION_NAV_LABELS,
  PRODUCTION_NAV_PATHS,
  resolveNavRoute,
} from "./nav.js";

describe("5-Section Admin SPA Navigation Consolidation (GN-402 / ZTR-1340)", () => {
  it("defines exactly 5 primary navigation sections: overview, wallets, connectors, activity, settings", () => {
    expect([...PRIMARY_NAV_KEYS]).toEqual([
      "overview",
      "wallets",
      "connectors",
      "activity",
      "settings",
    ]);
    expect(PRIMARY_NAV_SECTIONS).toHaveLength(5);
    expect(PRIMARY_NAV_SECTIONS.map((s) => s.key)).toEqual([
      "overview",
      "wallets",
      "connectors",
      "activity",
      "settings",
    ]);
    expect([...PRODUCTION_NAV_LABELS]).toEqual([
      "Overview",
      "Wallets",
      "Connectors",
      "Activity",
      "Settings",
    ]);
    expect([...PRODUCTION_NAV_PATHS]).toEqual([
      "/",
      "/wallets",
      "/connectors",
      "/activity",
      "/settings",
    ]);
  });

  it("maps all 17 legacy route paths and keys deterministically to their primary section and sub-tab", () => {
    expect(LEGACY_PRODUCTION_NAV_LABELS).toHaveLength(17);
    expect(LEGACY_PRODUCTION_NAV_PATHS).toHaveLength(17);

    for (const legacyPath of LEGACY_PRODUCTION_NAV_PATHS) {
      const resolved = resolveNavRoute(legacyPath);
      expect(PRIMARY_NAV_KEYS).toContain(resolved.section);
      expect(PRODUCTION_NAV_PATHS).toContain(resolved.path);
      expect(resolved.subTab.length).toBeGreaterThan(0);
    }

    expect(resolveNavRoute("#/approve-inbox")).toEqual({
      section: "overview",
      path: "/",
      subTab: "approve-inbox",
      legacyKey: "approve-inbox",
    });
    expect(resolveNavRoute("#/integrations")).toEqual({
      section: "connectors",
      path: "/connectors",
      subTab: "connectors",
      legacyKey: "integrations",
    });
    expect(resolveNavRoute("#/api-keys")).toEqual({
      section: "connectors",
      path: "/connectors",
      subTab: "api-keys",
      legacyKey: "api-keys",
    });
    expect(resolveNavRoute("#/implementer-policy")).toEqual({
      section: "connectors",
      path: "/connectors",
      subTab: "implementer-policy",
      legacyKey: "implementer-policy",
    });
    expect(resolveNavRoute("#/auto-approve")).toEqual({
      section: "connectors",
      path: "/connectors",
      subTab: "auto-approve",
      legacyKey: "auto-approve",
    });
    expect(resolveNavRoute("#/operations")).toEqual({
      section: "activity",
      path: "/activity",
      subTab: "operations",
      legacyKey: "operations",
    });
    expect(resolveNavRoute("#/ledger")).toEqual({
      section: "activity",
      path: "/activity",
      subTab: "ledger",
      legacyKey: "ledger",
    });
    expect(resolveNavRoute("#/audit")).toEqual({
      section: "activity",
      path: "/activity",
      subTab: "audit",
      legacyKey: "audit",
    });
    expect(resolveNavRoute("#/reconcile")).toEqual({
      section: "activity",
      path: "/activity",
      subTab: "reconcile",
      legacyKey: "reconcile",
    });
    expect(resolveNavRoute("#/passkeys")).toEqual({
      section: "settings",
      path: "/settings",
      subTab: "vault-passkeys",
      legacyKey: "passkeys",
    });
    expect(resolveNavRoute("#/vault")).toEqual({
      section: "settings",
      path: "/settings",
      subTab: "vault-passkeys",
      legacyKey: "vault",
    });
    expect(resolveNavRoute("#/backup")).toEqual({
      section: "settings",
      path: "/settings",
      subTab: "backup-recovery",
      legacyKey: "backup",
    });
    expect(resolveNavRoute("#/alerts")).toEqual({
      section: "settings",
      path: "/settings",
      subTab: "alerts",
      legacyKey: "alerts",
    });
    expect(resolveNavRoute("#/consolidation")).toEqual({
      section: "wallets",
      path: "/wallets",
      subTab: "consolidation",
      legacyKey: "consolidation",
    });
  });

  it("keeps forbidden navigation labels and paths excluded from primary nav", () => {
    for (const forbidden of FORBIDDEN_NAV_LABELS) {
      expect(PRODUCTION_NAV_LABELS).not.toContain(forbidden);
    }
    for (const forbiddenPath of FORBIDDEN_NAV_PATHS) {
      expect(PRODUCTION_NAV_PATHS).not.toContain(forbiddenPath);
    }
    expect(Object.keys(LEGACY_ROUTE_REDIRECTS).length).toBeGreaterThanOrEqual(17);
  });
});
