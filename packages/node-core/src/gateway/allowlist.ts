import { GatewayConfigurationError } from "./client.js";

export class GatewayEndpointNotAllowedError extends Error {
  constructor(endpoint: string) {
    super(`gateway endpoint not in allowlist: ${endpoint}`);
    this.name = "GatewayEndpointNotAllowedError";
  }
}

declare const gatewayEndpointAllowlistBrand: unique symbol;

export type GatewayEndpointAllowlist = readonly string[] & {
  readonly [gatewayEndpointAllowlistBrand]: true;
};

const LOOPBACK_HOSTNAMES = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

function normalizeEndpointKey(endpoint: string): string {
  const parsed = new URL(endpoint);
  return `${parsed.origin}${parsed.pathname}`;
}

function isLoopback(hostname: string): boolean {
  return LOOPBACK_HOSTNAMES.has(hostname);
}

export function createGatewayEndpointAllowlist(
  endpoints: readonly string[],
): GatewayEndpointAllowlist {
  if (endpoints.length === 0) {
    throw new GatewayConfigurationError("gateway endpoint allowlist must not be empty");
  }

  const seen = new Set<string>();
  const validated: string[] = [];

  for (const entry of endpoints) {
    let parsed: URL;
    try {
      parsed = new URL(entry);
    } catch {
      throw new GatewayConfigurationError(
        `gateway endpoint allowlist entry is not a valid URL: ${entry}`,
      );
    }

    if (parsed.username !== "" || parsed.password !== "") {
      throw new GatewayConfigurationError(
        `gateway endpoint allowlist entry must not contain credentials: ${entry}`,
      );
    }

    if (parsed.protocol === "http:" && !isLoopback(parsed.hostname)) {
      throw new GatewayConfigurationError(
        `gateway endpoint allowlist entry must use https (http allowed for loopback only): ${entry}`,
      );
    }

    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new GatewayConfigurationError(
        `gateway endpoint allowlist entry must use https or loopback http: ${entry}`,
      );
    }

    const key = normalizeEndpointKey(entry);
    if (seen.has(key)) {
      throw new GatewayConfigurationError(
        `gateway endpoint allowlist contains a duplicate entry: ${entry}`,
      );
    }
    seen.add(key);
    validated.push(parsed.toString());
  }

  return Object.freeze(validated) as GatewayEndpointAllowlist;
}

export function assertEndpointAllowed(
  allowlist: GatewayEndpointAllowlist,
  endpoint: string,
): void {
  const key = normalizeEndpointKey(endpoint);
  for (const allowed of allowlist) {
    if (normalizeEndpointKey(allowed) === key) {
      return;
    }
  }
  throw new GatewayEndpointNotAllowedError(endpoint);
}
