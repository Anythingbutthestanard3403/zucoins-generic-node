// Origin-based CSRF protection for state-mutating requests.
// Node admin CORS defaults to no cross-origin access; allowed origins are
// explicit exact origins, never `*` with credentials.

export interface CsrfConfig {
  readonly allowedOrigins: readonly string[];
}

export interface CsrfRequest {
  readonly method: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
}

export type CsrfOutcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: "origin_mismatch" | "origin_missing" };

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function extractOrigin(headers: Readonly<Record<string, string | undefined>>): string | null {
  const origin = headers["origin"];
  if (origin !== undefined && origin !== "") return origin;

  const referer = headers["referer"];
  if (referer !== undefined && referer !== "") {
    try {
      return new URL(referer).origin;
    } catch {
      return null;
    }
  }
  return null;
}

export function checkCsrf(config: CsrfConfig, request: CsrfRequest): CsrfOutcome {
  if (SAFE_METHODS.has(request.method.toUpperCase())) {
    return { ok: true };
  }

  const origin = extractOrigin(request.headers);
  if (origin === null) {
    return { ok: false, reason: "origin_missing" };
  }

  if (config.allowedOrigins.includes(origin)) {
    return { ok: true };
  }

  return { ok: false, reason: "origin_mismatch" };
}

// API-key-authenticated requests bypass CSRF because they do not rely on
// ambient cookie credentials.
export function checkCsrfWithApiBypass(
  config: CsrfConfig,
  request: CsrfRequest,
  isApiAuthenticated: boolean,
): CsrfOutcome {
  if (isApiAuthenticated) return { ok: true };
  return checkCsrf(config, request);
}
