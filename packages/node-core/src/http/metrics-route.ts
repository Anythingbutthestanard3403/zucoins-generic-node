// GET /metrics — bearer-gated, fail-closed operational-metrics scrape route for the
// generic node. Framework-neutral: it returns a plain response value and the app
// shell binds it to raw node:http (matching apps/generic-node/src/http-adapter.ts and
// health/routes.ts). packages/node-core carries no web-framework dependency, so this
// route imports only node:crypto — no internal cross-directory import, no Hono.
//
// The reporting-key enrolment ceremony admits a PULL scrape endpoint only — this route is
// node-served, never node-initiated, so it carries no egress/callback.
//
// FAIL-CLOSED MOUNTING (the load-bearing property, proof #2): createMetricsRoute
// returns `undefined` when no scrape token is configured, and the caller MUST skip
// mounting the route entirely in that case. An unauthenticated /metrics would leak
// operational custody signal (lease counts, queue depth, quarantine counts) from a
// live node, so the absence of a configured token degrades to "off", never to "open".
// No token => no handler => no route: unmountable, not a mounted-but-404 path.
//
// AUTH (proof #1): `Authorization: Bearer <token>` is compared against the configured
// token in CONSTANT TIME. Both sides are hashed to fixed 32-byte SHA-256 digests
// BEFORE timingSafeEqual, so the compare never sees unequal-length inputs
// (timingSafeEqual throws on a length mismatch — an accidental oracle) and never
// short-circuits on the first differing byte (a timing oracle). A missing or malformed
// header yields an empty presented token that still flows through the same
// constant-time compare: there is no length-based early return ahead of it, so
// "no header", "malformed header", and "wrong token" are indistinguishable. The token
// is never logged (eslint no-restricted-syntax guards this repo-wide).

import { createHash, timingSafeEqual } from "node:crypto";

/** Prometheus text-exposition content type (matches core/metrics.ts renderMetrics). */
export const METRICS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";

const BEARER_PREFIX = "Bearer ";

/** Framework-neutral response the app shell writes to its transport. */
export interface MetricsRouteResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

export interface MetricsRouteConfig {
  /** Configured scrape token. Falsy => the route is unmountable (returns undefined). */
  readonly scrapeToken: string | undefined;
  /** Produces the rendered metrics body; invoked only AFTER auth passes. */
  readonly render: () => string | Promise<string>;
}

/** Handler over the raw Authorization header; the framework binds request/response. */
export type MetricsRouteHandler = (
  authorizationHeader: string | undefined,
) => Promise<MetricsRouteResponse>;

// A single frozen 401 value: every failure mode returns byte-identical bytes, leaving
// no distinguishing oracle between "no header", "malformed header", and "wrong token".
const UNAUTHORIZED: MetricsRouteResponse = Object.freeze({
  status: 401,
  headers: Object.freeze({}),
  body: "",
});

/** Constant-time token equality over fixed-length (32-byte) SHA-256 digests. */
function constantTimeEquals(presented: string, configured: string): boolean {
  const presentedDigest = createHash("sha256").update(presented).digest();
  const configuredDigest = createHash("sha256").update(configured).digest();
  return timingSafeEqual(presentedDigest, configuredDigest);
}

/** Extract the bearer token, or "" for a missing/malformed header (no early return). */
function presentedBearerToken(header: string | undefined): string {
  if (header === undefined) return "";
  if (!header.startsWith(BEARER_PREFIX)) return "";
  return header.slice(BEARER_PREFIX.length);
}

/**
 * Build the /metrics handler, or `undefined` when no scrape token is configured — the
 * caller MUST NOT mount the route in that case (fail-closed; see the file header).
 */
export function createMetricsRoute(
  config: MetricsRouteConfig,
): MetricsRouteHandler | undefined {
  const configured = config.scrapeToken;
  if (!configured) return undefined;

  return async (authorizationHeader) => {
    const presented = presentedBearerToken(authorizationHeader);
    if (!constantTimeEquals(presented, configured)) {
      return UNAUTHORIZED;
    }
    return {
      status: 200,
      headers: { "content-type": METRICS_CONTENT_TYPE },
      body: await config.render(),
    };
  };
}
