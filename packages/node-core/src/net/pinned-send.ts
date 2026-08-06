// Pinned outbound connector shape for the gateway client. // contract-allow:outbound:frozen structural vocabulary
// Connect to resolveAndPin IPs with original hostname as SNI/Host; cap response drain. // contract-allow:drain:frozen structural vocabulary

export const MAX_RESPONSE_DRAIN_BYTES = 64 * 1024; // 64 KiB

export interface PinnedTarget {
  readonly hostname: string;
  readonly pinnedIp: string;
  readonly port: number;
  readonly pathAndQuery: string;
  /** When true, TLS SNI = hostname (never the IP). */
  readonly tls: boolean;
}

export function pinnedTargetFromUrl(
  url: URL,
  pinnedIp: string,
): PinnedTarget {
  const port = url.port
    ? Number.parseInt(url.port, 10)
    : url.protocol === "https:"
      ? 443
      : 80;
  return {
    hostname: url.hostname,
    pinnedIp,
    port,
    pathAndQuery: `${url.pathname}${url.search}`,
    tls: url.protocol === "https:",
  };
}

/**
 * Drain an async iterable of chunks up to MAX_RESPONSE_DRAIN_BYTES. // contract-allow:drain:frozen structural vocabulary
 * Further bytes are discarded; returns truncated=true when the cap was hit.
 */
export async function drainBounded(
  source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
  maxBytes: number = MAX_RESPONSE_DRAIN_BYTES,
): Promise<{ readonly bytes: Uint8Array; readonly truncated: boolean }> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  for await (const chunk of source as AsyncIterable<Uint8Array>) {
    if (total >= maxBytes) {
      truncated = true;
      break;
    }
    const room = maxBytes - total;
    if (chunk.byteLength <= room) {
      chunks.push(chunk);
      total += chunk.byteLength;
    } else {
      chunks.push(chunk.subarray(0, room));
      total += room;
      truncated = true;
      break;
    }
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return { bytes: out, truncated };
}

/**
 * egress-absence harness helper: record outbound HTTP targets during a run. // contract-allow:outbound:frozen structural vocabulary
 * A full RECEIVE_EXTERNAL / MOVE_INTERNAL / SEND_EXTERNAL cycle must produce zero
 * non-gateway calls when callbacks are not enabled.
 */
export class OutboundHttpCensus {
  private readonly calls: string[] = [];

  record(url: string): void {
    this.calls.push(url);
  }

  /** Returns non-gateway URLs. `gatewayHosts` are normalised hostnames. */
  nonGatewayCalls(gatewayHosts: readonly string[]): readonly string[] {
    const allowed = new Set(gatewayHosts.map((h) => h.toLowerCase()));
    return this.calls.filter((raw) => {
      try {
        const u = new URL(raw);
        return !allowed.has(u.hostname.toLowerCase());
      } catch {
        return true; // unparseable = treat as non-gateway leak
      }
    });
  }

  all(): readonly string[] {
    return [...this.calls];
  }

  clear(): void {
    this.calls.length = 0;
  }
}
