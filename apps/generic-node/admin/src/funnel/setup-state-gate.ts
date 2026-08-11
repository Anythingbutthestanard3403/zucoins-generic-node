/**
 * Day-0 setup-state gate decision (ZTR-1168).
 * Fail open only on a genuine 404 (older nodes without the API).
 * Fail closed on 5xx, other HTTP errors, and network rejection.
 */

export type SetupGateDecision =
  | { readonly kind: "open_legacy" }
  | { readonly kind: "closed"; readonly reason: "http_error" | "network" | "invalid_body" }
  | { readonly kind: "body"; readonly status: number };

/**
 * Map a fetch outcome for GET /admin/v1/setup-state into a gate decision
 * *before* parsing the body. Callers still parse JSON when kind === "body".
 */
export function decideSetupStateHttp(res: { readonly ok: boolean; readonly status: number }): SetupGateDecision {
  if (res.ok) return { kind: "body", status: res.status };
  if (res.status === 404) return { kind: "open_legacy" };
  return { kind: "closed", reason: "http_error" };
}

export function decideSetupStateNetworkError(): SetupGateDecision {
  return { kind: "closed", reason: "network" };
}
