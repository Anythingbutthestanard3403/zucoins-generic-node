/**
 * The frozen API route inventory, in its canonical sequence. `authMode` is a neutral label
 * for this package's census purposes, not a wire value.
 */
export const AUTH_MODES = [
  "implementer_bearer",
  "implementer_bearer_or_signed_reporting",
  "signed_reporting_credential",
  "subscription_handle",
  "operator_session",
  "operator_session_totp",
  "operator_session_totp_device",
  "public",
] as const;

export type AuthMode = (typeof AUTH_MODES)[number];

export interface RouteEntry {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly authMode: AuthMode;
}

/** Implementer/reporting/browser/discovery routes under `/v1`. */
export const PUBLIC_ROUTES: readonly RouteEntry[] = [
  { method: "POST", path: "/v1/receives", authMode: "implementer_bearer" },
  { method: "GET", path: "/v1/receives/:operation_id", authMode: "implementer_bearer" },
  { method: "POST", path: "/v1/internal-moves", authMode: "implementer_bearer" },
  { method: "GET", path: "/v1/internal-moves/:operation_id", authMode: "implementer_bearer" },
  { method: "POST", path: "/v1/external-sends", authMode: "implementer_bearer" },
  { method: "GET", path: "/v1/external-sends/:operation_id", authMode: "implementer_bearer" },
  { method: "POST", path: "/v1/destinations", authMode: "implementer_bearer" },
  { method: "GET", path: "/v1/destinations", authMode: "implementer_bearer_or_signed_reporting" },
  { method: "GET", path: "/v1/events", authMode: "signed_reporting_credential" },
  { method: "GET", path: "/v1/events/stream", authMode: "signed_reporting_credential" },
  { method: "GET", path: "/v1/state/snapshot", authMode: "signed_reporting_credential" },
  {
    method: "GET",
    path: "/v1/operations/:operation_id/subscribe",
    authMode: "subscription_handle",
  },
  {
    method: "POST",
    path: "/v1/operations/:operation_id/armed",
    authMode: "signed_reporting_credential",
  },
  {
    method: "POST",
    path: "/v1/operations/:operation_id/verification-complete",
    authMode: "signed_reporting_credential",
  },
  {
    method: "GET",
    path: "/v1/operations/:operation_id/verification-material",
    authMode: "signed_reporting_credential",
  },
  { method: "GET", path: "/.well-known/zupay-node", authMode: "public" },
  { method: "GET", path: "/health", authMode: "public" },
] as const;

/** Node-origin operator routes under `/admin/v1`. */
export const ADMIN_ROUTES: readonly RouteEntry[] = [
  {
    method: "GET",
    path: "/admin/v1/external-sends/:operation_id/approval-challenge",
    authMode: "operator_session",
  },
  {
    method: "POST",
    path: "/admin/v1/external-sends/:operation_id/approve",
    authMode: "operator_session_totp",
  },
  {
    method: "POST",
    path: "/admin/v1/external-sends/:operation_id/reject",
    authMode: "operator_session_totp",
  },
  {
    method: "POST",
    path: "/admin/v1/destinations/:destination_id/bless",
    authMode: "operator_session_totp_device",
  },
  {
    method: "POST",
    path: "/admin/v1/destinations/:destination_id/retire",
    authMode: "operator_session",
  },
  { method: "GET", path: "/admin/v1/operations/needs-attention", authMode: "operator_session" },
  {
    method: "GET",
    path: "/admin/v1/operations/:operation_id/recovery",
    authMode: "operator_session",
  },
  {
    method: "POST",
    path: "/admin/v1/operations/:operation_id/recovery-actions",
    authMode: "operator_session_totp",
  },
] as const;

/**
 * Retired paths — must never be implemented as aliases, redirects, or compatibility shims.
 * Five concrete path patterns plus one non-path category are transcribed verbatim; the
 * latter carries no concrete path and none is invented here. Each literal below is a
 * deliberate historical quote of retired legacy vocabulary carrying zero authority — hence
 * the inline `contract-allow` markers (forbidden-terms scan exemption).
 */
export const RETIRED_ROUTES = [
  "/v1/reservations*", // contract-allow:retired-route-citation
  "/v1/outbound-requests*", // contract-allow:retired-route-citation
  "/v1/payments*", // contract-allow:retired-route-citation
  "/v1/refunds*", // contract-allow:retired-route-citation
  "/admin/v1/drains*", // contract-allow:retired-route-citation
] as const;

export const RETIRED_ROUTES_NON_PATH_CATEGORY = "any import endpoint" as const;

/**
 * The retired non-path category ("any import endpoint") as a path classifier: a route whose
 * path carries an import-prefixed segment (e.g. /v1/wallets/import, /v1/import-wallet) is an
 * import endpoint and must never ship. The category names no concrete path, so it is enforced
 * structurally — segment-prefix matching is deliberately broad; a false positive forces a
 * rename, which is the safe direction for a forbidden category.
 */
export const isRetiredImportEndpoint = (path: string): boolean =>
  path.split("/").some((segment) => segment.startsWith("import"));

export const SOURCE = "API contract: route inventory and retired paths" as const;
