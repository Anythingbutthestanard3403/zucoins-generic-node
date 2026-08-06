import type { GatewayRequest, GatewayResponse } from "../protocol/index.js";

declare const gatewayReadCredentialsBrand: unique symbol;
declare const gatewaySubmitCredentialsBrand: unique symbol;

export interface GatewayReadCredentials {
  readonly [gatewayReadCredentialsBrand]: true;
}

export interface GatewaySubmitCredentials {
  readonly [gatewaySubmitCredentialsBrand]: true;
}

export interface GatewayReadTransport {
  readonly credentials: GatewayReadCredentials;
  read(endpoints: readonly string[], request: GatewayRequest): Promise<GatewayResponse>;
}

export interface GatewaySubmitTransport {
  readonly credentials: GatewaySubmitCredentials;
  submit(endpoints: readonly string[], request: GatewayRequest): Promise<GatewayResponse>;
}

declare const gatewaySubmitCapabilityBrand: unique symbol;

export interface GatewaySubmitCapability {
  readonly enabled: true;
  readonly transport: GatewaySubmitTransport;
  readonly [gatewaySubmitCapabilityBrand]: true;
}

// Transport bounds resolved by createGatewayClient. Units are part of each name:
// readTimeoutMs is milliseconds; maxRequestBytes / maxResponseBytes are bytes.
export interface GatewayLimits {
  readonly readTimeoutMs: number;
  readonly maxRequestBytes: number;
  readonly maxResponseBytes: number;
}

export interface GatewayConfiguration {
  readonly gatewayUrls: string;
  readonly readTransport: GatewayReadTransport;
  // Branded via enableGatewaySubmit. Absent → canSubmit false / GatewaySubmitDisabledError.
  // No separate live-chain approval flag (deploy sequencing retired that gate).
  readonly submitCapability?: GatewaySubmitCapability;
  // Optional transport bounds; absent values resolve to the named DEFAULT_GATEWAY_*
  // constants in client.js, and a present-but-invalid value fails closed.
  readonly readTimeoutMs?: number;
  readonly maxRequestBytes?: number;
  readonly maxResponseBytes?: number;
}

export interface GatewayClient {
  readonly endpoints: readonly string[];
  // sha256_hex fingerprint of each resolved endpoint, index-aligned with endpoints
  // (observers.gateway_endpoint_fingerprint /
  // gateway_observations.endpoint_fingerprint).
  readonly endpointFingerprints: readonly string[];
  readonly limits: GatewayLimits;
  readonly canSubmit: boolean;
  read(request: GatewayRequest): Promise<GatewayResponse>;
  submit(request: GatewayRequest): Promise<GatewayResponse>;
}
