/** Production SPA nav — generic custody model only. */
export const PRODUCTION_NAV_LABELS = [
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

/** Closed production path set (no retired product-projection routes). */
export const PRODUCTION_NAV_PATHS = [
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

/**
 * /settings is the secret-safe effective-config read model.
 * Allowlisted DTO only — never env dump / secrets.
 */

export const FORBIDDEN_NAV_PATHS = [
  "/sessions",
  "/sweeps", // contract-allow:sweep:retired-nav-path-citation
  "/webhooks",
] as const;
