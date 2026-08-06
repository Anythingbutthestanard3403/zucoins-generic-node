/**
 * Client for GET /health/ready — the v2 node's own readiness probe
 * (apps/generic-node/src/health/routes.ts, the readiness gate / the readiness-split rule).
 *
 * Deliberately NOT routed through api()/apiOrDemo(): those unconditionally
 * prefix every request with ADMIN_BASE ("/admin/v1"), but /health/ready is
 * mounted at the bare top level by the same listener (runtime-listener.ts
 * dispatches it only when the path does not start with "/admin/v1"), and a
 * 503 body here is a real, verified "not ready" signal — not a failure to be
 * collapsed into a generic ApiError the way api() treats every non-2xx.
 */

export type NodeReadinessStatus = "ready" | "degraded" | "not_ready";

export interface NodeReadinessCheck {
  readonly name: string;
  readonly ready: boolean;
  readonly gating: boolean;
}

export interface NodeReadinessBody {
  readonly status: NodeReadinessStatus;
  readonly version: string;
  readonly timestamp: string;
  readonly checks: readonly NodeReadinessCheck[];
}

const READINESS_STATUSES: readonly NodeReadinessStatus[] = ["ready", "degraded", "not_ready"];

function isNodeReadinessBody(value: unknown): value is NodeReadinessBody {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    (READINESS_STATUSES as readonly string[]).includes((value as { status: unknown }).status as string)
  );
}

/**
 * Fetch node readiness. HTTP 200 ("ready") and HTTP 503 ("degraded" /
 * "not_ready") both carry a real, verified body — only a genuine transport
 * failure or a malformed/non-JSON body throws. Callers must render a thrown
 * result as offline/unavailable, never as healthy.
 */
export async function fetchNodeReadiness(): Promise<NodeReadinessBody> {
  const res = await fetch("/health/ready", { headers: { accept: "application/json" } });
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    throw new Error(`/health/ready returned a non-JSON body (HTTP ${res.status})`);
  }
  if (!isNodeReadinessBody(body)) {
    throw new Error(`/health/ready returned an unexpected response shape (HTTP ${res.status})`);
  }
  return body;
}

export type NodeHealthUiState = "checking" | "healthy" | "degraded" | "offline";

export interface NodeReadinessQueryState {
  readonly isPending: boolean;
  readonly isError: boolean;
  readonly data: NodeReadinessBody | undefined;
}

/**
 * Derive the shell's health state. Demo mode is the only path allowed to show
 * "healthy" without a real probe (it is fixture data, already flagged by the
 * design-preview banner). Everywhere else: no data yet → "checking", a failed
 * fetch → "offline", a verified non-ready body → "degraded". "Healthy" is
 * reachable only via a verified `status: "ready"` response.
 */
export function deriveNodeHealthUiState(
  demoMode: boolean,
  query: NodeReadinessQueryState,
): NodeHealthUiState {
  if (demoMode) return "healthy";
  if (query.isPending) return "checking";
  if (query.isError || query.data === undefined) return "offline";
  return query.data.status === "ready" ? "healthy" : "degraded";
}
