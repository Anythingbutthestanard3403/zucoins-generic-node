// /metrics mount adapter for the v2 node shell.
//
// Route logic (bearer gate, constant-time compare, fail-closed unmount) lives in
// `@zucoins/node-core`. This module is the node:http bind + composition of the
// registry snapshot source (DB + readiness/halt/leadership stamps).
//
// FAIL-CLOSED: createMetricsHttpListener returns undefined when no scrape token
// is configured — the runtime listener must skip the path entirely (not 404).

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  createMetricsRoute,
  createNodeMetrics,
  emptyOperationalSnapshot,
  renderMetrics,
  type MetricsRouteHandler,
  type MetricsSnapshotSource,
  type NodeMetrics,
} from "@zucoins/node-core";

export interface MetricsRouteDeps {
  /** Configured scrape token. Falsy => route unmounted. */
  readonly scrapeToken: string | undefined;
  /**
   * Optional shared registry (so call-seam hooks and /metrics share one
   * instance). When omitted a fresh registry is created for this mount.
   */
  readonly metrics?: NodeMetrics;
  /**
   * Per-scrape snapshot source. When omitted, gauges stay at zero (event
   * counters and process defaults still render). Production main supplies a
   * DB-backed collector when the database adapter is live; until then a
   * process-stamps-only source is fine.
   */
  readonly snapshotSource?: MetricsSnapshotSource;
}

export interface MetricsMount {
  readonly metrics: NodeMetrics;
  readonly handler: MetricsRouteHandler;
  readonly listener: (request: IncomingMessage, response: ServerResponse) => void;
}

/**
 * Build the /metrics mount, or `undefined` when no scrape token is configured.
 * The caller MUST NOT register a /metrics path when this returns undefined.
 */
export function createMetricsMount(deps: MetricsRouteDeps): MetricsMount | undefined {
  const metrics = deps.metrics ?? createNodeMetrics();
  if (deps.snapshotSource) {
    metrics.setSnapshotSource(deps.snapshotSource);
  } else if (!metrics.getSnapshotSource()) {
    // Ensure process defaults still collect; gauges stay zero without a source.
    metrics.setSnapshotSource(async () => emptyOperationalSnapshot());
  }

  const handler = createMetricsRoute({
    scrapeToken: deps.scrapeToken,
    render: () => renderMetrics(metrics),
  });
  if (!handler) return undefined;

  const listener = (request: IncomingMessage, response: ServerResponse): void => {
    const authorization = (() => {
      // Prefer rawHeaders so a duplicate Authorization is visible; take the first
      // value only for the compare (duplicate is still a single presented token
      // for metrics — scrapers send one). Lowercase name match.
      const raw = request.rawHeaders;
      for (let i = 0; i + 1 < raw.length; i += 2) {
        if (raw[i]!.toLowerCase() === "authorization") return raw[i + 1];
      }
      return undefined;
    })();

    void handler(authorization).then((result) => {
      response.writeHead(result.status, {
        ...result.headers,
        "content-length": Buffer.byteLength(result.body).toString(),
      });
      response.end(result.body);
    });
  };

  return { metrics, handler, listener };
}
