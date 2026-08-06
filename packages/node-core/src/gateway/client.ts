import { createHash } from "node:crypto";

import type { GatewayRequest, GatewayResponse } from "../protocol/index.js";
import {
  assertEndpointAllowed,
  createGatewayEndpointAllowlist,
  type GatewayEndpointAllowlist,
} from "./allowlist.js";
import type {
  GatewayClient,
  GatewayConfiguration,
  GatewayLimits,
  GatewayReadCredentials,
  GatewaySubmitCapability,
  GatewaySubmitCredentials,
  GatewaySubmitTransport,
} from "./types.js";

const submitCapabilityBrand = Symbol("gateway-submit-capability");

// Implementer-judgment transport bounds. The specification fixes no numeric
// caps, so these are conservative
// named defaults, overridable via GatewayConfiguration — never silent fallbacks for a
// missing endpoint list, which still fails closed.
export const DEFAULT_GATEWAY_READ_TIMEOUT_MS = 10_000;
export const DEFAULT_GATEWAY_MAX_REQUEST_BYTES = 1_048_576;
export const DEFAULT_GATEWAY_MAX_RESPONSE_BYTES = 4_194_304;

type BrandedGatewaySubmitCapability = GatewaySubmitCapability & {
  readonly [submitCapabilityBrand]: true;
};

export class GatewayConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GatewayConfigurationError";
  }
}

export class GatewaySubmitDisabledError extends Error {
  constructor() {
    super("gateway submit capability is disabled");
    this.name = "GatewaySubmitDisabledError";
  }
}

const readCredentialsBrand = Symbol("gateway.read-credentials");
const submitCredentialsBrand = Symbol("gateway.submit-credentials");

export function createGatewayReadCredentials(): GatewayReadCredentials {
  return Object.freeze({ [readCredentialsBrand]: true }) as unknown as GatewayReadCredentials;
}

export function createGatewaySubmitCredentials(): GatewaySubmitCredentials {
  return Object.freeze({ [submitCredentialsBrand]: true }) as unknown as GatewaySubmitCredentials;
}

function requireEndpoints(gatewayUrls: string | undefined): readonly string[] {
  if (gatewayUrls === undefined || gatewayUrls.trim() === "") {
    throw new GatewayConfigurationError("gateway URL list is required");
  }

  const entries = gatewayUrls
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
  if (entries.length === 0) {
    throw new GatewayConfigurationError("gateway URL list is required");
  }

  return Object.freeze(
    entries.map((entry) => {
      let parsed: URL;
      try {
        parsed = new URL(entry);
      } catch (cause) {
        throw new GatewayConfigurationError(`gateway URL is invalid: ${String(cause)}`);
      }
      if (parsed.protocol !== "https:") {
        throw new GatewayConfigurationError("gateway URL must use https");
      }
      return parsed.toString();
    }),
  );
}

// Canonical preimage: the endpoint URL string exactly as requireEndpoints validated and
// normalized it (new URL(entry).toString) — deterministic per configured endpoint and
// byte-identical to the form the transport actually dials.
export function fingerprintEndpoint(endpoint: string): string {
  return createHash("sha256").update(endpoint, "utf8").digest("hex");
}

function requireConfiguredLimit(
  field: string,
  configured: number | undefined,
  fallback: number,
  unit: "milliseconds" | "bytes",
): number {
  if (configured === undefined) {
    return fallback;
  }
  if (typeof configured !== "number" || !Number.isFinite(configured) || configured <= 0) {
    throw new GatewayConfigurationError(
      `gateway ${field} must be a positive finite number of ${unit}`,
    );
  }
  if (unit === "bytes" && !Number.isInteger(configured)) {
    throw new GatewayConfigurationError(`gateway ${field} must be a whole number of bytes`);
  }
  return configured;
}

function resolveLimits(configuration: GatewayConfiguration): GatewayLimits {
  return Object.freeze({
    readTimeoutMs: requireConfiguredLimit(
      "readTimeoutMs",
      configuration.readTimeoutMs,
      DEFAULT_GATEWAY_READ_TIMEOUT_MS,
      "milliseconds",
    ),
    maxRequestBytes: requireConfiguredLimit(
      "maxRequestBytes",
      configuration.maxRequestBytes,
      DEFAULT_GATEWAY_MAX_REQUEST_BYTES,
      "bytes",
    ),
    maxResponseBytes: requireConfiguredLimit(
      "maxResponseBytes",
      configuration.maxResponseBytes,
      DEFAULT_GATEWAY_MAX_RESPONSE_BYTES,
      "bytes",
    ),
  });
}

function isSubmitCapability(
  value: GatewaySubmitCapability | undefined,
): value is BrandedGatewaySubmitCapability {
  if (value === undefined) {
    return false;
  }
  return (
    value.enabled === true &&
    typeof value.transport?.submit === "function" &&
    (value as BrandedGatewaySubmitCapability)[submitCapabilityBrand] === true
  );
}

export function enableGatewaySubmit(
  transport: GatewaySubmitTransport,
): GatewaySubmitCapability {
  if (transport === undefined || typeof transport.submit !== "function") {
    throw new GatewayConfigurationError("gateway submit transport is required");
  }
  return Object.freeze({
    enabled: true,
    transport,
    [submitCapabilityBrand]: true,
  }) as BrandedGatewaySubmitCapability;
}

export function createGatewayClient(
  configuration: GatewayConfiguration,
): GatewayClient {
  if (configuration === undefined) {
    throw new GatewayConfigurationError("gateway configuration is required");
  }
  if (
    configuration.readTransport === undefined ||
    typeof configuration.readTransport.read !== "function"
  ) {
    throw new GatewayConfigurationError("gateway read transport is required");
  }
  if (
    configuration.submitCapability !== undefined &&
    !isSubmitCapability(configuration.submitCapability)
  ) {
    throw new GatewayConfigurationError("gateway submit capability is invalid");
  }

  const limits = resolveLimits(configuration);
  const endpoints = requireEndpoints(configuration.gatewayUrls);
  // retired the live-chain construction approval gate. Submit still
  // requires a branded submitCapability via enableGatewaySubmit; without it, submit throws
  // GatewaySubmitDisabledError. Real-ZKZ controls remain deploy sequencing dual control + deploy sequencing cap.
  const endpointFingerprints = Object.freeze(
    endpoints.map((endpoint) => fingerprintEndpoint(endpoint)),
  );
  const allowlist: GatewayEndpointAllowlist = createGatewayEndpointAllowlist(endpoints);
  const readTransport = configuration.readTransport;
  const submitCapability = configuration.submitCapability;

  async function read(request: GatewayRequest): Promise<GatewayResponse> {
    for (const endpoint of endpoints) {
      assertEndpointAllowed(allowlist, endpoint);
    }
    return await readTransport.read(endpoints, request);
  }

  async function submit(request: GatewayRequest): Promise<GatewayResponse> {
    if (!isSubmitCapability(submitCapability)) {
      throw new GatewaySubmitDisabledError();
    }
    for (const endpoint of endpoints) {
      assertEndpointAllowed(allowlist, endpoint);
    }
    return await submitCapability.transport.submit(endpoints, request);
  }

  return Object.freeze({
    endpoints,
    endpointFingerprints,
    limits,
    canSubmit: isSubmitCapability(submitCapability),
    read,
    submit,
  });
}
