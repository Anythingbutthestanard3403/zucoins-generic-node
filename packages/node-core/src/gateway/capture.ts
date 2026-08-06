// shared low-level single-exchange gateway transport. One exchange
// call is exactly ONE HTTP request against exactly ONE endpoint — no iteration, no retry,
// no failover; those belong to read.ts (bounded, jittered, ambiguity-only) and are
// structurally absent here. Both the read and the single-shot submit path build on this
// exchange so each captures the EXACT request bytes and the EXACT response bytes with
// their SHA-256 digests: the complete response body is evidence, captured raw before
// any decode, and persisted as raw_response_bytes / raw_response_sha256 alongside
// request_sha256 / response_sha256.
//
// Outcome semantics at this layer are deliberately minimal: any complete HTTP response
// (2xx, 4xx, 5xx — whatever the status) is a CAPTURED exchange and is returned with its
// exact bytes; only a failure that leaves the exchange's effect unknown (network failure,
// timeout, an unreadable or over-limit body) raises GatewayTransportAmbiguityError. The
// read path treats that ambiguity as the sole retry trigger; the submit path classifies
// it as INDETERMINATE (reconcile-only, never re-attempted). Status classification
// (ACK / REJECT / INDETERMINATE) is submit.ts's job — this module interprets no status.

import { createHash } from "node:crypto";
import https from "node:https";
import tls from "node:tls";

import type { GatewayRequest } from "../protocol/index.js";
import { fingerprintEndpoint } from "./client.js";
import type { GatewayLimits } from "./types.js";

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

// One completed exchange with the exact bytes that crossed the wire in each direction.
// requestBytes are the exact bytes handed to the transport layer (the signed form body,
// never re-serialized); responseBytes are the exact bytes received, captured before any
// parse. Each carries its SHA-256 so persistence stores digest + bytes
// together without recomputation elsewhere.
export interface GatewayExchangeCapture {
  readonly endpoint: string;
  readonly endpointFingerprint: string;
  readonly requestBytes: Uint8Array;
  readonly requestSha256: string;
  readonly responseBytes: Uint8Array;
  readonly responseSha256: string;
  readonly statusCode: number;
}

// The exchange's effect is UNKNOWN: the request may or may not have reached the gateway,
// and no complete response body was captured. This is the only error both transport
// paths treat as "no definitive answer" — for reads it is the sole retry trigger, for
// the single-shot submit it is INDETERMINATE (reconcile-only; the never-blind-retry rule / never-blind-retry submit:
// never blind-retry a submit). `cause` preserves the underlying transport error.
export class GatewayTransportAmbiguityError extends Error {
  constructor(
    message: string,
    override readonly cause: unknown,
  ) {
    super(message);
    this.name = "GatewayTransportAmbiguityError";
  }
}

// The request body exceeds the configured byte cap BEFORE anything is sent. This is a
// definite local failure, not an ambiguity: nothing reached the gateway, so neither path
// treats it as a transport outcome (the read path does not retry it; the submit path
// raises it to the caller without recording an attempt).
export class GatewayRequestTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GatewayRequestTooLargeError";
  }
}

// Minimal structural fetch surface (Node's global fetch satisfies it) so tests inject a
// fake under the network-containment guard and production uses the real thing.
export interface GatewayFetchResponse {
  readonly status: number;
  arrayBuffer(): Promise<ArrayBuffer>;
}

export interface GatewayFetchInit {
  readonly method: "POST";
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
  readonly signal: AbortSignal;
}

export type GatewayFetchFn = (url: string, init: GatewayFetchInit) => Promise<GatewayFetchResponse>;

const defaultGatewayFetch: GatewayFetchFn = async (url, init) => await fetch(url, init);

// GATEWAY_TLS_CERT_SHA256_PINS entries are already validated 64-lowercase-hex by the config
// schema; normalize defensively anyway since this primitive is not bound to that one schema,
// and a cert's own fingerprint256 (from Node's TLS layer) arrives colon-separated and uppercase.
function normalizeFingerprint(fingerprint: string): string {
  return fingerprint.replace(/:/g, "").toLowerCase();
}

// Pure pin-comparison, split out from checkServerIdentity so the pin/rotation logic is
// unit-testable without a live TLS socket (this package's tests deny node:https/fetch
// outright — network containment). Never a substitute for hostname validation —
// callers must run tls.checkServerIdentity first.
export function evaluateGatewayCertificatePin(
  pins: ReadonlySet<string>,
  fingerprint256: string,
  host: string,
): Error | undefined {
  const fingerprint = normalizeFingerprint(fingerprint256);
  if (!pins.has(fingerprint)) {
    return new Error(
      `gateway TLS certificate pin mismatch for ${host}: ${fingerprint} is not in the configured pin set`,
    );
  }
  return undefined;
}

// Certificate pinning on top of standard TLS trust (never in place of it): the built-in
// hostname check still runs, then the leaf cert's SHA-256 fingerprint must also be in the
// configured pin set. A gateway TLS rotation to an unpinned cert is a hard reject, not a
// silent fall-through.
export function createPinnedGatewayFetch(pins: readonly string[]): GatewayFetchFn {
  const normalizedPins = new Set(pins.map(normalizeFingerprint));
  return async (url, init) =>
    await new Promise<GatewayFetchResponse>((resolve, reject) => {
      const req = https.request(
        url,
        {
          method: init.method,
          headers: init.headers,
          signal: init.signal,
          checkServerIdentity: (host, cert) => {
            const hostnameError = tls.checkServerIdentity(host, cert);
            if (hostnameError) {
              return hostnameError;
            }
            return evaluateGatewayCertificatePin(normalizedPins, cert.fingerprint256, host);
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("end", () => {
            const body = Buffer.concat(chunks);
            const status = res.statusCode ?? 0;
            resolve({
              status,
              arrayBuffer: async () =>
                body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
            });
          });
          res.on("error", reject);
        },
      );
      req.on("error", reject);
      req.write(init.body);
      req.end();
    });
}

export interface GatewayExchangeTransport {
  exchange(endpoint: string, request: GatewayRequest): Promise<GatewayExchangeCapture>;
}

export interface GatewayExchangeTransportOptions {
  readonly limits: GatewayLimits;
  readonly fetchFn?: GatewayFetchFn;
  // GATEWAY_TLS_CERT_SHA256_PINS: lowercase-hex SHA-256 leaf-cert pins. Absent/empty = standard
  // TLS trust only (no pinning). Ignored when fetchFn is explicitly supplied (tests / the
  // network-containment guard own that seam).
  readonly tlsCertSha256Pins?: readonly string[];
}

function describeCause(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

export function createGatewayExchangeTransport(
  options: GatewayExchangeTransportOptions,
): GatewayExchangeTransport {
  const limits = options.limits;
  const fetchFn =
    options.fetchFn ??
    (options.tlsCertSha256Pins !== undefined && options.tlsCertSha256Pins.length > 0
      ? createPinnedGatewayFetch(options.tlsCertSha256Pins)
      : defaultGatewayFetch);

  async function exchange(endpoint: string, request: GatewayRequest): Promise<GatewayExchangeCapture> {
    const requestBytes = request.bodyBytes;
    if (requestBytes.byteLength > limits.maxRequestBytes) {
      throw new GatewayRequestTooLargeError(
        `gateway request body is ${requestBytes.byteLength} bytes, exceeding the configured maximum of ${limits.maxRequestBytes} bytes`,
      );
    }
    const requestSha256 = sha256Hex(requestBytes);

    // The timeout spans the whole exchange (connect, headers, AND full body read): a
    // partial body is as unverifiable as no response at all.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), limits.readTimeoutMs);
    let response: GatewayFetchResponse;
    let responseBuffer: ArrayBuffer;
    try {
      response = await fetchFn(endpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: requestBytes,
        signal: controller.signal,
      });
      responseBuffer = await response.arrayBuffer();
    } catch (cause) {
      const reason = controller.signal.aborted
        ? `timed out after ${limits.readTimeoutMs}ms`
        : describeCause(cause);
      throw new GatewayTransportAmbiguityError(
        `gateway exchange with ${endpoint} is ambiguous: ${reason}`,
        cause,
      );
    } finally {
      clearTimeout(timer);
    }

    const responseBytes = new Uint8Array(responseBuffer);
    if (responseBytes.byteLength > limits.maxResponseBytes) {
      throw new GatewayTransportAmbiguityError(
        `gateway exchange with ${endpoint} is ambiguous: response body is ${responseBytes.byteLength} bytes, exceeding the configured maximum of ${limits.maxResponseBytes} bytes`,
        new Error("response body exceeds the configured byte cap"),
      );
    }

    return {
      endpoint,
      endpointFingerprint: fingerprintEndpoint(endpoint),
      requestBytes,
      requestSha256,
      responseBytes,
      responseSha256: sha256Hex(responseBytes),
      statusCode: response.status,
    };
  }

  return { exchange };
}
