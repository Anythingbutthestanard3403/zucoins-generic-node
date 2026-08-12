// Guarded admin money-mutation chain — the whole guard sequence as one callable.
//
// Ordering is load-bearing:
// 1. session + CSRF origin + CSRF token
// 2. parse and validate the whole request BEFORE inspecting a TOTP
// 3. verify + atomically reserve (node_id, timestep)
// 4. run the mutation; timestep stays burned on downstream failure
//
// Auth-factor failures that must not oracle (password / session / CSRF token /
// TOTP) collapse to the same 401 envelope. Password-change posture stays 403
// (already authenticated; UI must name the gate). Origin mismatch is
// a distinct 403 so a same-origin SPA can distinguish CORS/CSRF-origin policy
// from credential failure without learning which credential failed.

import {
  extractSessionIdFromCookie,
  requireActiveTotpFactor,
  requirePasswordChanged,
  requireSessionCsrf,
  type AdminSession,
  type AdminSessionService,
  type AdminUser,
  type AdminUserStore,
  type AuthRequest,
} from "./admin-session.js";
import { checkCsrf, type CsrfConfig } from "./csrf.js";
import { resolveOperatorTotpConfig } from "./admin-auth-handlers.js";
import {
  verifyTotp,
  type TotpBurnStore,
  type TotpConfig,
} from "./totp-chain.js";

/** Generic 401 envelope — shared by session / CSRF-token / TOTP / password-login failures. */
export const AUTH_FACTOR_FAILURE = Object.freeze({
  status: 401 as const,
  code: "invalid_credentials",
  message: "authentication required",
});

export type BodyValidationResult<T> =
  | { readonly ok: true; readonly body: T }
  | {
      readonly ok: false;
      readonly status: 400 | 422;
      readonly code: string;
      readonly message: string;
    };

export interface GuardedAdminMutationInput<TBody, TResult> {
  readonly sessions: AdminSessionService;
  readonly request: AuthRequest;
  readonly csrf: CsrfConfig;
  /**
   * Lab/process fallback secret. Prefer per-operator factor via `userStore`
   * (enrol/confirm). When both absent, TOTP fails closed.
   */
  readonly totp?: TotpConfig | null;
  /** When set, resolve active enrolled secret before lab fallback. */
  readonly userStore?: AdminUserStore;
  readonly totpLog: TotpBurnStore;
  readonly nodeId: string;
  /** Raw body bytes/text the caller has not yet parsed — validated before TOTP. */
  readonly rawBody: unknown;
  readonly validateBody: (raw: unknown) => BodyValidationResult<TBody>;
  /** Header carrying the fresh single-use code (X-ZP-TOTP). */
  readonly totpHeaderName?: string;
  readonly nowMs?: number;
  readonly mutate: (args: {
    readonly body: TBody;
    readonly session: AdminSession;
    readonly user: AdminUser;
    readonly timestep: number;
  }) => Promise<TResult>;
}

export type GuardedAdminMutationOutcome<TResult> =
  | {
      readonly ok: true;
      readonly result: TResult;
      readonly session: AdminSession;
      readonly user: AdminUser;
      readonly timestep: number;
    }
  | {
      readonly ok: false;
      readonly status: number;
      readonly code: string;
      readonly message: string;
      readonly reason:
        | "session"
        | "csrf_origin"
        | "csrf_token"
        | "password_change_required"
        | "totp_enrolment_required"
        | "body_invalid"
        | "totp"
        | "mutation_threw";
      readonly error?: unknown;
    };

function factorFail(
  reason: "session" | "csrf_token" | "totp",
): Extract<GuardedAdminMutationOutcome<never>, { ok: false }> {
  return {
    ok: false,
    status: AUTH_FACTOR_FAILURE.status,
    code: AUTH_FACTOR_FAILURE.code,
    message: AUTH_FACTOR_FAILURE.message,
    reason,
  };
}

/**
 * Full guarded mutation for the node-origin admin surface.
 * Shells mount this (or an equivalent sequence-preserving wrapper) on money routes.
 */
export async function runGuardedAdminMutation<TBody, TResult>(
  input: GuardedAdminMutationInput<TBody, TResult>,
): Promise<GuardedAdminMutationOutcome<TResult>> {
  // --- 1a. Session (cookie only) ---
  const sessionId = extractSessionIdFromCookie(input.request.headers["cookie"]);
  if (sessionId === null) return factorFail("session");

  const validated = await input.sessions.validateSession(sessionId);
  if (!validated.ok) return factorFail("session");

  // --- 1b. CSRF origin (state-mutating methods) ---
  const originCheck = checkCsrf(input.csrf, input.request);
  if (!originCheck.ok) {
    return {
      ok: false,
      status: 403,
      code: "origin_forbidden",
      message: "origin not allowed",
      reason: "csrf_origin",
    };
  }

  // --- 1c. CSRF double-submit token ---
  const csrfToken = requireSessionCsrf(validated.session, input.request);
  if (!csrfToken.ok) return factorFail("csrf_token");

  // --- 1d. First-login password gate (money mutations) ---
  const pw = requirePasswordChanged(validated.user);
  if (!pw.ok) {
    return {
      ok: false,
      status: pw.status,
      code: pw.code,
      message: pw.message,
      reason: "password_change_required",
    };
  }

  // --- 1e. First-login TOTP enrolment + active factor gate ---
  // Active factor is required whenever userStore is bound (production path).
  // Without userStore, lab-only TotpConfig path cannot prove enrolment authenticity
  // beyond the process secret — still require mustEnrol cleared via lab bind.
  if (input.userStore !== undefined) {
    const factorGate = await requireActiveTotpFactor(input.userStore, validated.user);
    if (!factorGate.ok) {
      return {
        ok: false,
        status: factorGate.status,
        code: factorGate.code,
        message: factorGate.message,
        reason: "totp_enrolment_required",
      };
    }
  } else if (validated.user.mustEnrolTotp) {
    return {
      ok: false,
      status: 401,
      code: "totp_required",
      message: "totp enrolment required",
      reason: "totp_enrolment_required",
    };
  }

  // --- 2. Parse + validate whole body BEFORE any TOTP inspection (step 2) ---
  const bodyResult = input.validateBody(input.rawBody);
  if (!bodyResult.ok) {
    return {
      ok: false,
      status: bodyResult.status,
      code: bodyResult.code,
      message: bodyResult.message,
      reason: "body_invalid",
    };
  }

  // --- 3–4. TOTP verify+burn, then mutation (burn retained on throw) ---
  const headerName = (input.totpHeaderName ?? "x-zp-totp").toLowerCase();
  const code = input.request.headers[headerName];
  if (typeof code !== "string" || code.length === 0) {
    return factorFail("totp");
  }

  const totpConfig =
    input.userStore !== undefined
      ? await resolveOperatorTotpConfig(input.userStore, validated.user.id, input.totp)
      : input.totp !== undefined && input.totp !== null && input.totp.secret.length >= 16
        ? input.totp
        : null;
  if (totpConfig === null) return factorFail("totp");

  // Verify + burn BEFORE mutation (C-08). Failure paths never restore.
  const totpResult = await verifyTotp(
    totpConfig,
    { nodeId: input.nodeId, code, nowMs: input.nowMs },
    input.totpLog,
  );
  if (!totpResult.ok) return factorFail("totp");

  try {
    const result = await input.mutate({
      body: bodyResult.body,
      session: validated.session,
      user: validated.user,
      timestep: totpResult.timestep,
    });
    return {
      ok: true,
      result,
      session: validated.session,
      user: validated.user,
      timestep: totpResult.timestep,
    };
  } catch (error) {
    // Timestep already consumed; never restored (step 8).
    return {
      ok: false,
      status: 500,
      code: "mutation_failed",
      message: "mutation failed",
      reason: "mutation_threw",
      error,
    };
  }
}
