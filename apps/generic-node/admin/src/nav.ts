/** Production SPA nav — generic treasury model only. */
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
  "Devices",
  "Reporting",
  "Connect",
  "Audit",
  "Settings",
] as const;

/** v1 checkout / payment-product chrome — must not appear in production nav. */
export const FORBIDDEN_NAV_LABELS = [
  "Sessions",
  "Sweeps",
  "Webhooks",
  "Recent sessions",
] as const;

export type ProductionNavLabel = (typeof PRODUCTION_NAV_LABELS)[number];

/** Closed production path set (no sessions/sweeps/webhooks product routes). */
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
  "/sweeps",
  "/webhooks",
] as const;
