//  — the raw-capture HTTP adapter for signed reporting routes. Plain
// node:http only, no framework: any router parses/decodes the path before user code and would
// silently desynchronize the signed target bytes from the verified bytes (the single most
// common way a signed-request verifier breaks in production — request-target.ts's contract).
//
// Capture rules (absolute): `url` is taken VERBATIM before anything else — never `new URL()`,
// never decoded, never rebuilt from components, and Host/X-Forwarded-*/X-Original-URL are
// never consulted for routing or target. The five signed headers are counted on the raw
// header array (duplicates are rejected downstream, where node would have comma-joined them).
// The body is the concatenation of raw chunks with a streaming byte cap; a non-identity
// Content-Encoding is rejected because any transformation would desync body_sha256. The
// single ingress wall-clock instant is captured first and threaded into the pipeline.
//
// The listener works against a structural seam (RawTransportRequest/RawTransportResponse) so
// the entire capture path is testable without sockets; `createNodeHttpListener` binds it to a
// real node:http (IncomingMessage, ServerResponse) pair.
//
// Long-lived SSE — openSink side-channel + liveStream hold-open; client close
// stops the stream connection (poll timers) without headers-already-sent on denials.

import {
  reportingErrorResponse,
  type CapturedReportRequest,
  type ReportingHttpResponse,
  type ReportingTransportSideChannel,
} from "@zucoins/node-core";

export interface RawTransportRequest {
  readonly method: string | undefined;
  readonly url: string | undefined;
  readonly rawHeaders: readonly string[];
  readonly bodyChunks: AsyncIterable<Uint8Array>;
  /** Optional: wire client disconnect for SSE cleanup. */
  readonly onceClose?: (cb: () => void) => void;
}

export interface RawTransportResponse {
  writeHead(status: number, headers: Readonly<Record<string, string>>): unknown;
  write?(chunk: string | Uint8Array): unknown;
  end(body?: Uint8Array): unknown;
  onceClose?: (cb: () => void) => void;
}

export type ReportingTransportHandler = (
  captured: CapturedReportRequest,
  transport?: ReportingTransportSideChannel,
) => Promise<ReportingHttpResponse>;

export type ReportingHttpListener = (
  request: RawTransportRequest,
  response: RawTransportResponse,
) => Promise<void>;

export interface ReportingHttpListenerConfig {
  readonly handle: ReportingTransportHandler;
  readonly nowMs: () => number;
  readonly maxBodyBytes: number;
  readonly newRequestId: () => string;
}

function headerValues(rawHeaders: readonly string[], name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    if (rawHeaders[index]!.toLowerCase() === name) values.push(rawHeaders[index + 1]!);
  }
  return values;
}

function write(response: RawTransportResponse, produced: ReportingHttpResponse): void {
  response.writeHead(produced.status, {
    ...produced.headers,
    "content-length": produced.bodyBytes.length.toString(),
  });
  response.end(produced.bodyBytes);
}

export function createReportingHttpListener(
  config: ReportingHttpListenerConfig,
): ReportingHttpListener {
  const badRequest = (code: "request_too_large" | "unsupported_content_encoding" | "invalid_reporting_headers") =>
    reportingErrorResponse(code, config.newRequestId());

  return async (request, response) => {
    // The ingress instant is the first observable, before any header or body inspection.
    const receivedAtMs = config.nowMs();

    const encodings = headerValues(request.rawHeaders, "content-encoding");
    if (encodings.some((value) => value.trim().toLowerCase() !== "identity")) {
      write(response, badRequest("unsupported_content_encoding"));
      return;
    }

    const contentLengths = headerValues(request.rawHeaders, "content-length");
    if (new Set(contentLengths).size > 1) {
      write(response, badRequest("invalid_reporting_headers"));
      return;
    }
    const declared = contentLengths.length === 1 ? Number(contentLengths[0]) : null;
    if (declared !== null && Number.isSafeInteger(declared) && declared > config.maxBodyBytes) {
      write(response, badRequest("request_too_large"));
      return;
    }

    const chunks: Uint8Array[] = [];
    let total = 0;
    let oversized = false;
    for await (const chunk of request.bodyChunks) {
      total += chunk.length;
      if (total > config.maxBodyBytes) {
        oversized = true;
        break;
      }
      chunks.push(chunk);
    }
    if (oversized) {
      write(response, badRequest("request_too_large"));
      return;
    }
    const bodyBytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bodyBytes.set(chunk, offset);
      offset += chunk.length;
    }

    const captured: CapturedReportRequest = {
      method: request.method ?? "",
      rawTarget: request.url ?? "",
      rawHeaders: request.rawHeaders,
      bodyBytes,
      receivedAtMs,
    };

    const transport: ReportingTransportSideChannel = {
      openSink: (sseHeaders) => {
        response.writeHead(200, { ...sseHeaders });
        return {
          write(chunk: string) {
            response.write?.(chunk);
          },
          close() {
            response.end();
          },
        };
      },
    };

    let produced: ReportingHttpResponse;
    try {
      produced = await config.handle(captured, transport);
    } catch {
      produced = reportingErrorResponse("internal_error", config.newRequestId());
    }

    if (produced.liveStream !== undefined) {
      // openSink already committed 200 + SSE headers; hold open and drop pollers on disconnect.
      let closed = false;
      const cleanup = (): void => {
        if (closed) return;
        closed = true;
        try {
          produced.liveStream!.close();
        } catch {
          /* already closed */
        }
      };
      request.onceClose?.(cleanup);
      response.onceClose?.(cleanup);
      return;
    }

    write(response, produced);
  };
}

// Bind the structural seam to a real node:http request/response pair. IncomingMessage.url is
// the raw, undecoded origin-form request target; rawHeaders preserves occurrence counts and
// case. This wrapper performs no inspection of its own — capture rules live in the listener.
export function createNodeHttpListener(listener: ReportingHttpListener): (
  request: import("node:http").IncomingMessage,
  response: import("node:http").ServerResponse,
) => Promise<void> {
  return async (incoming, outgoing) => {
    await listener(
      {
        method: incoming.method,
        url: incoming.url,
        rawHeaders: incoming.rawHeaders,
        bodyChunks: incoming,
        onceClose: (cb) => {
          incoming.once("close", cb);
        },
      },
      {
        writeHead: (status, headers) => outgoing.writeHead(status, headers),
        write: (chunk) => outgoing.write(chunk),
        end: (body) => {
          if (body === undefined) outgoing.end();
          else outgoing.end(body);
        },
        onceClose: (cb) => {
          outgoing.once("close", cb);
        },
      },
    );
  };
}
