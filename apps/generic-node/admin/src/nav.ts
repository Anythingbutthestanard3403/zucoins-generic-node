/**
 * 5-Section Admin SPA Navigation Consolidation (GN-402 / ZTR-1340).
 * Consolidates the 17 legacy routes into 5 task-oriented primary sections
 * (`overview`, `wallets`, `connectors`, `activity`, `settings`) while
 * preserving deterministic deep-link resolution for all 17 legacy routes.
 */

export const PRIMARY_NAV_KEYS = [
  "overview",
  "wallets",
  "connectors",
  "activity",
  "settings",
] as const;

export type PrimaryNavKey = (typeof PRIMARY_NAV_KEYS)[number];

export interface PrimaryNavSection {
  readonly key: PrimaryNavKey;
  readonly label: "Overview" | "Wallets" | "Connectors" | "Activity" | "Settings";
  readonly path: "/" | "/wallets" | "/connectors" | "/activity" | "/settings";
  readonly description: string;
  readonly subTabs: readonly string[];
}

export const PRIMARY_NAV_SECTIONS: readonly PrimaryNavSection[] = [
  {
    key: "overview",
    label: "Overview",
    path: "/",
    description:
      "Unified home dashboard with reserve balance, action-required inbox, and quick operator actions.",
    subTabs: ["dashboard", "approve-inbox"],
  },
  {
    key: "wallets",
    label: "Wallets",
    path: "/wallets",
    description:
      "Named Reserve Wallets plus collapsible internal worker pool and consolidation controls.",
    subTabs: ["reserves", "worker-pool", "consolidation", "destinations"],
  },
  {
    key: "connectors",
    label: "Connectors",
    path: "/connectors",
    description:
      "Unified API Connectors combining integrations, API keys, implementer policy, and spend rules.",
    subTabs: ["connectors", "api-keys", "implementer-policy", "auto-approve", "verification-mode"],
  },
  {
    key: "activity",
    label: "Activity",
    path: "/activity",
    description:
      "Unified operation feed across receive, internal move, and external send with audit log and reconcile tabs.",
    subTabs: ["operations", "ledger", "audit", "reconcile"],
  },
  {
    key: "settings",
    label: "Settings",
    path: "/settings",
    description:
      "System settings for vault and passkeys, backup and recovery, operator sessions, and node identity.",
    subTabs: ["node-identity", "vault-passkeys", "backup-recovery", "operator-sessions", "alerts"],
  },
] as const;

/** Production SPA nav — 5 consolidated top-level sections (GN-402). */
export const PRODUCTION_NAV_LABELS = [
  "Overview",
  "Wallets",
  "Connectors",
  "Activity",
  "Settings",
] as const;

/** Legacy 17-item nav label census preserved for deep-link mapping. */
export const LEGACY_PRODUCTION_NAV_LABELS = [
  "Overview",
  "Approve",
  "Operations",
  "Wallets",
  "Transfers",
  "Destinations",
  "Backup",
  "Recovery",
  "Keys",
  "Integrations",
  "Auto-approve",
  "Node-verified",
  "Devices",
  "Reporting",
  "Connect",
  "Audit",
  "Settings",
] as const;

/** v1 product-projection chrome — must not appear in production nav. */
export const FORBIDDEN_NAV_LABELS = [
  "Sessions",
  "Sweeps", // contract-allow:sweep:retired-nav-label-citation
  "Webhooks",
  "Recent sessions",
] as const;

export type ProductionNavLabel = (typeof PRODUCTION_NAV_LABELS)[number];

/** Closed production path set for the 5 primary sections. */
export const PRODUCTION_NAV_PATHS = [
  "/",
  "/wallets",
  "/connectors",
  "/activity",
  "/settings",
] as const;

/** Legacy 17-route path list preserved for router mounting and deep-link redirects. */
export const LEGACY_PRODUCTION_NAV_PATHS = [
  "/",
  "/approve",
  "/operations",
  "/wallets",
  "/transfers",
  "/destinations",
  "/backup",
  "/recovery-ceremony",
  "/api-keys",
  "/integrations",
  "/auto-approve",
  "/verification-mode",
  "/devices",
  "/reporting-keys",
  "/integration",
  "/audit",
  "/settings",
] as const;

export interface ResolvedNavRoute {
  readonly section: PrimaryNavKey;
  readonly path: PrimaryNavSection["path"];
  readonly subTab: string;
  readonly legacyKey: string;
}

/**
 * Deterministic mapping of all 17 legacy route keys/paths (plus canonical
 * section keys) to their consolidated 5-section primary target and sub-tab.
 */
export const LEGACY_ROUTE_REDIRECTS: Readonly<Record<string, ResolvedNavRoute>> = {
  overview: { section: "overview", path: "/", subTab: "dashboard", legacyKey: "overview" },
  "/": { section: "overview", path: "/", subTab: "dashboard", legacyKey: "overview" },
  approve: { section: "overview", path: "/", subTab: "approve-inbox", legacyKey: "approve" },
  "approve-inbox": {
    section: "overview",
    path: "/",
    subTab: "approve-inbox",
    legacyKey: "approve-inbox",
  },
  "/approve": { section: "overview", path: "/", subTab: "approve-inbox", legacyKey: "approve" },
  "/approve-inbox": {
    section: "overview",
    path: "/",
    subTab: "approve-inbox",
    legacyKey: "approve-inbox",
  },

  wallets: { section: "wallets", path: "/wallets", subTab: "reserves", legacyKey: "wallets" },
  "/wallets": { section: "wallets", path: "/wallets", subTab: "reserves", legacyKey: "wallets" },
  consolidation: {
    section: "wallets",
    path: "/wallets",
    subTab: "consolidation",
    legacyKey: "consolidation",
  },
  "/consolidation": {
    section: "wallets",
    path: "/wallets",
    subTab: "consolidation",
    legacyKey: "consolidation",
  },
  destinations: {
    section: "wallets",
    path: "/wallets",
    subTab: "destinations",
    legacyKey: "destinations",
  },
  "/destinations": {
    section: "wallets",
    path: "/wallets",
    subTab: "destinations",
    legacyKey: "destinations",
  },

  connectors: {
    section: "connectors",
    path: "/connectors",
    subTab: "connectors",
    legacyKey: "connectors",
  },
  "/connectors": {
    section: "connectors",
    path: "/connectors",
    subTab: "connectors",
    legacyKey: "connectors",
  },
  integrations: {
    section: "connectors",
    path: "/connectors",
    subTab: "connectors",
    legacyKey: "integrations",
  },
  "/integrations": {
    section: "connectors",
    path: "/connectors",
    subTab: "connectors",
    legacyKey: "integrations",
  },
  "api-keys": {
    section: "connectors",
    path: "/connectors",
    subTab: "api-keys",
    legacyKey: "api-keys",
  },
  "/api-keys": {
    section: "connectors",
    path: "/connectors",
    subTab: "api-keys",
    legacyKey: "api-keys",
  },
  keys: { section: "connectors", path: "/connectors", subTab: "api-keys", legacyKey: "keys" },
  "implementer-policy": {
    section: "connectors",
    path: "/connectors",
    subTab: "implementer-policy",
    legacyKey: "implementer-policy",
  },
  "/implementer-policy": {
    section: "connectors",
    path: "/connectors",
    subTab: "implementer-policy",
    legacyKey: "implementer-policy",
  },
  "auto-approve": {
    section: "connectors",
    path: "/connectors",
    subTab: "auto-approve",
    legacyKey: "auto-approve",
  },
  "/auto-approve": {
    section: "connectors",
    path: "/connectors",
    subTab: "auto-approve",
    legacyKey: "auto-approve",
  },
  "verification-mode": {
    section: "connectors",
    path: "/connectors",
    subTab: "verification-mode",
    legacyKey: "verification-mode",
  },
  "/verification-mode": {
    section: "connectors",
    path: "/connectors",
    subTab: "verification-mode",
    legacyKey: "verification-mode",
  },
  "node-verified": {
    section: "connectors",
    path: "/connectors",
    subTab: "verification-mode",
    legacyKey: "node-verified",
  },
  integration: {
    section: "connectors",
    path: "/connectors",
    subTab: "connectors",
    legacyKey: "integration",
  },
  "/integration": {
    section: "connectors",
    path: "/connectors",
    subTab: "connectors",
    legacyKey: "integration",
  },
  connect: {
    section: "connectors",
    path: "/connectors",
    subTab: "connectors",
    legacyKey: "connect",
  },
  "/connect": {
    section: "connectors",
    path: "/connectors",
    subTab: "connectors",
    legacyKey: "connect",
  },

  activity: {
    section: "activity",
    path: "/activity",
    subTab: "operations",
    legacyKey: "activity",
  },
  "/activity": {
    section: "activity",
    path: "/activity",
    subTab: "operations",
    legacyKey: "activity",
  },
  operations: {
    section: "activity",
    path: "/activity",
    subTab: "operations",
    legacyKey: "operations",
  },
  "/operations": {
    section: "activity",
    path: "/activity",
    subTab: "operations",
    legacyKey: "operations",
  },
  transfers: {
    section: "activity",
    path: "/activity",
    subTab: "operations",
    legacyKey: "transfers",
  },
  "/transfers": {
    section: "activity",
    path: "/activity",
    subTab: "operations",
    legacyKey: "transfers",
  },
  ledger: { section: "activity", path: "/activity", subTab: "ledger", legacyKey: "ledger" },
  "/ledger": { section: "activity", path: "/activity", subTab: "ledger", legacyKey: "ledger" },
  audit: { section: "activity", path: "/activity", subTab: "audit", legacyKey: "audit" },
  "audit-log": {
    section: "activity",
    path: "/activity",
    subTab: "audit",
    legacyKey: "audit-log",
  },
  "/audit": { section: "activity", path: "/activity", subTab: "audit", legacyKey: "audit" },
  reconcile: {
    section: "activity",
    path: "/activity",
    subTab: "reconcile",
    legacyKey: "reconcile",
  },
  "/reconcile": {
    section: "activity",
    path: "/activity",
    subTab: "reconcile",
    legacyKey: "reconcile",
  },

  settings: {
    section: "settings",
    path: "/settings",
    subTab: "node-identity",
    legacyKey: "settings",
  },
  "/settings": {
    section: "settings",
    path: "/settings",
    subTab: "node-identity",
    legacyKey: "settings",
  },
  passkeys: {
    section: "settings",
    path: "/settings",
    subTab: "vault-passkeys",
    legacyKey: "passkeys",
  },
  "/passkeys": {
    section: "settings",
    path: "/settings",
    subTab: "vault-passkeys",
    legacyKey: "passkeys",
  },
  devices: {
    section: "settings",
    path: "/settings",
    subTab: "vault-passkeys",
    legacyKey: "devices",
  },
  "/devices": {
    section: "settings",
    path: "/settings",
    subTab: "vault-passkeys",
    legacyKey: "devices",
  },
  vault: {
    section: "settings",
    path: "/settings",
    subTab: "vault-passkeys",
    legacyKey: "vault",
  },
  "/vault": {
    section: "settings",
    path: "/settings",
    subTab: "vault-passkeys",
    legacyKey: "vault",
  },
  backup: {
    section: "settings",
    path: "/settings",
    subTab: "backup-recovery",
    legacyKey: "backup",
  },
  "/backup": {
    section: "settings",
    path: "/settings",
    subTab: "backup-recovery",
    legacyKey: "backup",
  },
  recovery: {
    section: "settings",
    path: "/settings",
    subTab: "backup-recovery",
    legacyKey: "recovery",
  },
  "recovery-ceremony": {
    section: "settings",
    path: "/settings",
    subTab: "backup-recovery",
    legacyKey: "recovery-ceremony",
  },
  "/recovery-ceremony": {
    section: "settings",
    path: "/settings",
    subTab: "backup-recovery",
    legacyKey: "recovery-ceremony",
  },
  reporting: {
    section: "settings",
    path: "/settings",
    subTab: "node-identity",
    legacyKey: "reporting",
  },
  "reporting-keys": {
    section: "settings",
    path: "/settings",
    subTab: "node-identity",
    legacyKey: "reporting-keys",
  },
  "/reporting-keys": {
    section: "settings",
    path: "/settings",
    subTab: "node-identity",
    legacyKey: "reporting-keys",
  },
  sessions: {
    section: "settings",
    path: "/settings",
    subTab: "operator-sessions",
    legacyKey: "sessions",
  },
  "operator-security": {
    section: "settings",
    path: "/settings",
    subTab: "operator-sessions",
    legacyKey: "operator-security",
  },
  "/operator-security": {
    section: "settings",
    path: "/settings",
    subTab: "operator-sessions",
    legacyKey: "operator-security",
  },
  alerts: { section: "settings", path: "/settings", subTab: "alerts", legacyKey: "alerts" },
  "/alerts": { section: "settings", path: "/settings", subTab: "alerts", legacyKey: "alerts" },
};

export function resolveNavRoute(rawKeyOrPath: string): ResolvedNavRoute {
  const trimmed = rawKeyOrPath.trim().replace(/^#/, "");
  const normalized = trimmed.toLowerCase();
  const direct = LEGACY_ROUTE_REDIRECTS[normalized] ?? LEGACY_ROUTE_REDIRECTS[trimmed];
  if (direct) return direct;
  const withoutSlash = normalized.replace(/^\/+/, "").replace(/\/+$/, "");
  const bySlug = LEGACY_ROUTE_REDIRECTS[withoutSlash];
  if (bySlug) return bySlug;
  return LEGACY_ROUTE_REDIRECTS.overview!;
}

/**
 * /settings is the secret-safe effective-config read model.
 * Allowlisted DTO only — never env dump / secrets.
 */

export const FORBIDDEN_NAV_PATHS = [
  "/sessions",
  "/sweeps", // contract-allow:sweep:retired-nav-path-citation
  "/webhooks",
] as const;

