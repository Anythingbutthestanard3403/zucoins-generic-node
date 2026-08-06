// Two-tier placeholder-secret gate, lifted from the
// verified Zukaz config (ZUT-13 there) and adapted to the v2 node.
//
// Tier 1 — HARD-REFUSE production boot only on values known with certainty to
// be placeholders: the exact literals shipped in apps/generic-node/.env.example
// and single-repeated-character strings (no entropy) for the metrics scrape
// token, where a placeholder would mount an effectively unauthenticated
// /metrics route (fail-closed design).
//
// Tier 2 — WARN-ONLY (never refuse) on anything merely dev-shaped-looking,
// per the lifted file's own governing comment: "never refuse boot on a value
// that merely LOOKS dev-shaped; warn and let the operator decide." A real
// operator-generated secret can legitimately look unusual, and refusing boot
// on a false-positive heuristic is itself an availability bug.
//
// No secret value is ever included in a refusal or warning message — messages
// name the field and the placeholder class only.

import type { NodeConfig } from "./env-schema.js";

// Exact literals shipped in apps/generic-node/.env.example. A test asserts
// these stay in sync with that file.
export const PLACEHOLDER_DATABASE_URL =
  "postgresql://CHANGE_ME:CHANGE_ME@db.example.invalid:5432/zunode";
export const PLACEHOLDER_GATEWAY_URL = "https://gateway-entry-1.example.invalid/";
export const PLACEHOLDER_PUBLIC_BASE_URL = "https://node.example.invalid/";
export const PLACEHOLDER_METRICS_SCRAPE_TOKEN = "0".repeat(64);
export const PLACEHOLDER_INITIAL_ADMIN_PASSWORD = "change-me-to-a-long-random-passphrase";

// True when the string is one character repeated (e.g. 64 zeros) — no entropy,
// cannot be real operator-generated secret material.
export function isSingleRepeatedChar(value: string): boolean {
  return value.length > 0 && /^(.)\1*$/.test(value);
}

export class PlaceholderSecretError extends Error {
  readonly fields: readonly string[];

  constructor(fields: readonly string[], detail: readonly string[]) {
    super(
      `Refusing to boot in production with placeholder configuration (${fields.join(", ")}):\n` +
        detail.map((line) => `  - ${line}`).join("\n"),
    );
    this.name = "PlaceholderSecretError";
    this.fields = fields;
  }
}

export function assertNoPlaceholderConfiguration(
  config: NodeConfig,
  warn: (message: string) => void,
): void {
  if (config.NODE_ENV !== "production") return;

  const fatalFields: string[] = [];
  const fatalDetail: string[] = [];

  if (config.DATABASE_URL === PLACEHOLDER_DATABASE_URL) {
    fatalFields.push("DATABASE_URL");
    fatalDetail.push(
      "DATABASE_URL is the exact .env.example placeholder. Set the real postgres connection string.",
    );
  }
  if (config.SPLITCHAIN_GATEWAY_URLS.includes(PLACEHOLDER_GATEWAY_URL)) {
    fatalFields.push("SPLITCHAIN_GATEWAY_URLS");
    fatalDetail.push(
      "SPLITCHAIN_GATEWAY_URLS contains the exact .env.example placeholder endpoint. Set the real SplitChain gateway endpoint(s); there is no sandbox fallback.",
    );
  }
  if (config.PUBLIC_BASE_URL === PLACEHOLDER_PUBLIC_BASE_URL) {
    fatalFields.push("PUBLIC_BASE_URL");
    fatalDetail.push(
      "PUBLIC_BASE_URL is the exact .env.example placeholder. Set the node's real externally reachable base URL.",
    );
  }
  if (
    config.METRICS_SCRAPE_TOKEN !== undefined &&
    (config.METRICS_SCRAPE_TOKEN === PLACEHOLDER_METRICS_SCRAPE_TOKEN ||
      isSingleRepeatedChar(config.METRICS_SCRAPE_TOKEN))
  ) {
    fatalFields.push("METRICS_SCRAPE_TOKEN");
    fatalDetail.push(
      "METRICS_SCRAPE_TOKEN is the .env.example placeholder (or a single repeated character). A placeholder token would mount /metrics with effectively no authentication. Set a real token or leave the variable unset so the route is not mounted.",
    );
  }

  if (fatalFields.length > 0) {
    throw new PlaceholderSecretError(fatalFields, fatalDetail);
  }

  if (config.INITIAL_ADMIN_PASSWORD === PLACEHOLDER_INITIAL_ADMIN_PASSWORD) {
    warn(
      "[config] PLACEHOLDER VALUE IN PRODUCTION: INITIAL_ADMIN_PASSWORD is the .env.example placeholder.",
    );
  }
}
