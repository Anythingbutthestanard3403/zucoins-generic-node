import { useAuth } from "../store/auth.js";

const ADMIN_BASE = "/admin/v1";

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    param?: string;
    request_id?: string;
    /** Present on server envelopes (ZTR-1196); always {} today. */
    details?: Record<string, never>;
  };
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;
  /** Optional structured extras (e.g. lab receive checklist_links). */
  readonly extras?: Readonly<Record<string, unknown>>;
  constructor(status: number, body: ApiErrorBody, extras?: Readonly<Record<string, unknown>>) {
    super(body.error.message);
    this.name = "ApiError";
    this.status = status;
    this.code = body.error.code;
    this.requestId = body.error.request_id;
    this.extras = extras;
  }
}

/**
 * Structured detail an unavailable `apiOrDemo` read carries through to callers
 * (API error envelope: code/message/request_id survive the client).
 * Absent when the fallback came from demo mode rather than a caught failure.
 */
export interface ApiFailureDetail {
  readonly code: string;
  readonly message: string;
  readonly requestId?: string;
  readonly status: number;
}

export interface ApiOptions extends RequestInit {
  /** Attach X-ZP-TOTP for operator_session_totp money mutations. */
  totp?: string;
  /** Idempotency-Key (required for recovery-actions). */
  idempotencyKey?: string;
}

function requireCsrfToken(): string {
  const csrf = useAuth.getState().user?.csrfToken ?? "";
  if (typeof csrf !== "string" || csrf.length === 0) {
    throw new ApiError(403, {
      error: {
        code: "csrf_required",
        message: "CSRF token missing — cannot mutate without a session token",
      },
    });
  }
  return csrf;
}

/** Money mutations that opt into TOTP must send a 6-digit code (fail-closed). */
export function assertTotpCode(totp: string | undefined): string {
  if (typeof totp !== "string" || !/^\d{6}$/.test(totp)) {
    throw new ApiError(401, {
      error: {
        code: "totp_required",
        message: "6-digit TOTP required",
      },
    });
  }
  return totp;
}

async function doFetch(path: string, init: ApiOptions = {}): Promise<Response> {
  const { totp, idempotencyKey, ...rest } = init;
  const headers = new Headers(rest.headers);
  const method = (rest.method ?? "GET").toUpperCase();
  const isMutation = method !== "GET" && method !== "HEAD";
  if (isMutation) {
    headers.set("X-CSRF-Token", requireCsrfToken());
  }
  // Caller opted into TOTP (money paths pass the key). Empty/invalid never omit silently.
  if (totp !== undefined) {
    headers.set("X-ZP-TOTP", assertTotpCode(totp));
  }
  if (idempotencyKey) headers.set("Idempotency-Key", idempotencyKey);
  if (!headers.has("Content-Type") && rest.body && !(rest.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  return fetch(`${ADMIN_BASE}${path}`, {
    ...rest,
    headers,
    credentials: "include",
  });
}

/**
 * Ambiguous-401 recovery. The server deliberately collapses session-gone,
 * CSRF-token-fail and wrong-TOTP into one `invalid_credentials` envelope
 * (`node-core/src/http/admin-mutation-chain.ts` header — they "must not oracle"),
 * so the client cannot, and must not try to, tell them apart from the response.
 * It asks the authoritative endpoint instead: `me()` re-reads /admin/v1/me and
 * returns null once the session is gone; only then does it force re-auth through
 * the existing `logout()` (clears the user *and* the in-memory CSRF token, then
 * lands on /login). A still-live session leaves the store untouched, so a
 * mistyped code keeps its re-prompt.
 *
 * Awaitable + coalesced so callers (esp. `withTotpRetry`) only see the 401
 * throw after the session decision has settled — fire-and-forget let the
 * step-up loop re-prompt before logout finished (ZTR-1195).
 */
export type SessionRecheckResult = "skipped" | "alive" | "dead";

let sessionRecheck: Promise<SessionRecheckResult> | null = null;

export function recheckSessionOn401(): Promise<SessionRecheckResult> {
  if (sessionRecheck) return sessionRecheck;
  const { user, me, logout } = useAuth.getState();
  // No session held — a failed login has nothing to expire and nowhere to send.
  if (user === null) return Promise.resolve("skipped");
  // One probe covers a whole page of parallel 401s failing together.
  sessionRecheck = (async (): Promise<SessionRecheckResult> => {
    try {
      const live = await me();
      if (live === null) {
        await logout();
        return "dead";
      }
      return "alive";
    } catch {
      // Probe itself failed — treat as dead so money UX cannot loop on a
      // half-known session (fail-closed; logout is local-clear-first).
      try {
        await logout();
      } catch {
        /* offline */
      }
      return "dead";
    } finally {
      sessionRecheck = null;
    }
  })();
  return sessionRecheck;
}

export async function api<T>(path: string, init?: ApiOptions): Promise<T> {
  const res = await doFetch(path, init);
  if (!res.ok) {
    let body: ApiErrorBody = {
      error: { code: "http_error", message: res.statusText || `HTTP ${res.status}` },
    };
    let extras: Record<string, unknown> | undefined;
    try {
      const raw = (await res.json()) as Record<string, unknown>;
      if (raw && typeof raw === "object" && raw.error && typeof raw.error === "object") {
        body = raw as unknown as ApiErrorBody;
        const { error: _e, ...rest } = raw;
        if (Object.keys(rest).length > 0) extras = rest;
      }
    } catch {
      /* keep default */
    }
    if (res.status === 401) await recheckSessionOn401();
    throw new ApiError(res.status, body, extras);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/**
 * Prefer live JSON. Demo fallback is for **reads** only (design-preview or
 * unmounted inventory). Money **mutations** must use `api()` — never this helper
 * (no fixture success on 404/503 for approve/reject/bless/recovery).
 */
export async function apiOrDemo<T>(
  path: string,
  fallback: T,
  init?: ApiOptions,
): Promise<{ data: T; live: boolean; error?: ApiFailureDetail }> {
  const method = (init?.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    throw new Error(
      "apiOrDemo is read-only; money mutations must call api() so 404/503 never looks like success",
    );
  }
  if (useAuth.getState().demoMode) {
    return { data: fallback, live: false };
  }
  try {
    const data = await api<T>(path, init);
    return { data, live: true };
  } catch (err) {
    if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
      throw err;
    }
    return { data: fallback, live: false, error: toApiFailureDetail(err) };
  }
}

/** Render an `ApiFailureDetail` for operator-actionable unavailable-state copy. */
export function formatApiFailureDetail(error: ApiFailureDetail | undefined): string | null {
  if (!error) return null;
  const rid = error.requestId ? ` · request ${error.requestId}` : "";
  return `${error.code} (${error.status}) — ${error.message}${rid}`;
}

/** Shared caught-error → `ApiFailureDetail` conversion for any read that swallows a failure. */
export function toApiFailureDetail(error: unknown): ApiFailureDetail {
  if (error instanceof ApiError) {
    return { code: error.code, message: error.message, requestId: error.requestId, status: error.status };
  }
  return {
    code: "network_error",
    message: error instanceof Error ? error.message : "Network request failed",
    status: 0,
  };
}
