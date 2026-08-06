// Proxy TLS and request-transport hardening for the node API.
// Framework-agnostic hardened configuration plus pure transport guards a server
// adapter applies at the socket and intake layers. Layer 1 stays decoupled.

import { DEFAULT_MAX_BODY_BYTES } from "./strict-json.js";

// TLS 1.2 is the floor; TLS 1.3 is preferred and negotiated when the peer supports it.
export const MIN_TLS_VERSION = "TLSv1.2";
export const MAX_TLS_VERSION = "TLSv1.3";

// AEAD-only suites with forward secrecy. TLS 1.3 suites are fixed by the protocol and
// need not be listed; these govern TLS 1.2 negotiation. Anything not here is refused.
export const HARDENED_CIPHER_SUITES: readonly string[] = Object.freeze([
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-CHACHA20-POLY1305",
]);

export interface HardenedTlsConfig {
  readonly minVersion: typeof MIN_TLS_VERSION;
  readonly maxVersion: typeof MAX_TLS_VERSION;
  readonly ciphers: readonly string[];
  readonly honorCipherOrder: boolean;
  readonly rejectUnauthorized: boolean;
  readonly requestCert: boolean;
}

export interface TlsOverrides {
  readonly ciphers?: readonly string[];
  readonly requestCert?: boolean;
}

// Certificate validation is enforced unconditionally: rejectUnauthorized is never
// overridable, so a misconfigured caller cannot silently disable peer verification.
export function buildHardenedTlsConfig(overrides: TlsOverrides = {}): HardenedTlsConfig {
  return {
    minVersion: MIN_TLS_VERSION,
    maxVersion: MAX_TLS_VERSION,
    ciphers: overrides.ciphers ?? HARDENED_CIPHER_SUITES,
    honorCipherOrder: true,
    rejectUnauthorized: true,
    requestCert: overrides.requestCert ?? false,
  };
}

export const JSON_MEDIA_TYPE = "application/json";
export const JSON_CONTENT_TYPE_HEADER = "application/json; charset=utf-8";

// HTTP/1.0 is refused outright; the node serves HTTP/1.1 and HTTP/2 only.
export const MIN_HTTP_VERSION = "1.1";

export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
export const DEFAULT_HEADERS_TIMEOUT_MS = 10_000;
/** Cap on cumulative request-header bytes (name+value pairs). */
export const DEFAULT_MAX_HEADER_BYTES = 16_384;

export interface TransportHardeningConfig {
  readonly minHttpVersion: typeof MIN_HTTP_VERSION;
  readonly maxBodyBytes: number;
  readonly maxHeaderBytes: number;
  readonly requestTimeoutMs: number;
  readonly headersTimeoutMs: number;
  readonly requireJsonContentType: boolean;
}

export interface TransportOverrides {
  readonly maxBodyBytes?: number;
  readonly maxHeaderBytes?: number;
  readonly requestTimeoutMs?: number;
  readonly headersTimeoutMs?: number;
  readonly requireJsonContentType?: boolean;
}

export function buildTransportHardeningConfig(
  overrides: TransportOverrides = {},
): TransportHardeningConfig {
  return {
    minHttpVersion: MIN_HTTP_VERSION,
    maxBodyBytes: overrides.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES,
    maxHeaderBytes: overrides.maxHeaderBytes ?? DEFAULT_MAX_HEADER_BYTES,
    requestTimeoutMs: overrides.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
    headersTimeoutMs: overrides.headersTimeoutMs ?? DEFAULT_HEADERS_TIMEOUT_MS,
    requireJsonContentType: overrides.requireJsonContentType ?? true,
  };
}

export type TransportRejectionCode =
  | "http_version_too_old"
  | "unsupported_content_type"
  | "request_too_large"
  | "headers_too_large";

export type TransportGuardOutcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: TransportRejectionCode };

// Compare dotted HTTP version strings numerically ("1.10" > "1.9").
function httpVersionAtLeast(actual: string, minimum: string): boolean {
  const parse = (value: string): readonly number[] =>
    value.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const a = parse(actual);
  const b = parse(minimum);
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    const left = a[i] ?? 0;
    const right = b[i] ?? 0;
    if (left !== right) return left > right;
  }
  return true;
}

export function guardHttpVersion(
  httpVersion: string,
  config: TransportHardeningConfig,
): TransportGuardOutcome {
  return httpVersionAtLeast(httpVersion, config.minHttpVersion)
    ? { ok: true }
    : { ok: false, code: "http_version_too_old" };
}

// The media type is the header value up to the first parameter (e.g. the charset),
// trimmed and case-insensitive. SSE endpoints are not JSON and bypass this guard.
export function guardContentType(
  contentTypeHeader: string | undefined,
  config: TransportHardeningConfig,
): TransportGuardOutcome {
  if (!config.requireJsonContentType) return { ok: true };
  const mediaType = (contentTypeHeader ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
  return mediaType === JSON_MEDIA_TYPE
    ? { ok: true }
    : { ok: false, code: "unsupported_content_type" };
}

export function guardRequestSize(
  contentLength: number,
  config: TransportHardeningConfig,
): TransportGuardOutcome {
  return contentLength <= config.maxBodyBytes
    ? { ok: true }
    : { ok: false, code: "request_too_large" };
}

export function guardHeaderSize(
  headerBytes: number,
  config: TransportHardeningConfig,
): TransportGuardOutcome {
  return headerBytes <= config.maxHeaderBytes
    ? { ok: true }
    : { ok: false, code: "headers_too_large" };
}

// Fixed sequence: protocol version → content type → header size → body size.
// First failure wins. JSON strictness remains the strict-json gateway.
export function enforceTransportGuards(
  request: {
    readonly httpVersion: string;
    readonly contentType?: string;
    readonly contentLength: number;
    readonly headerBytes?: number;
  },
  config: TransportHardeningConfig,
): TransportGuardOutcome {
  const version = guardHttpVersion(request.httpVersion, config);
  if (!version.ok) return version;

  const contentType = guardContentType(request.contentType, config);
  if (!contentType.ok) return contentType;

  if (request.headerBytes !== undefined) {
    const headers = guardHeaderSize(request.headerBytes, config);
    if (!headers.ok) return headers;
  }

  return guardRequestSize(request.contentLength, config);
}

export interface HardenedServerConfig {
  readonly tls: HardenedTlsConfig;
  readonly transport: TransportHardeningConfig;
}

export interface HardenedServerOverrides {
  readonly tls?: TlsOverrides;
  readonly transport?: TransportOverrides;
}

// The single hardened configuration object a server adapter spreads into its TLS
// listener options and intake middleware.
export function buildHardenedServerConfig(
  overrides: HardenedServerOverrides = {},
): HardenedServerConfig {
  return {
    tls: buildHardenedTlsConfig(overrides.tls),
    transport: buildTransportHardeningConfig(overrides.transport),
  };
}
