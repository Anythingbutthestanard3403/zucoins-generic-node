/**
 * Session + CSRF + enrolment gates for admin routes.
 *
 * Relocated off frozen apps/node. Drives the same decision
 * logic the fuzz suite measures — Hono MiddlewareHandler shape without a Hono
 * dependency (compatible with the alphabet's Context stub).
 */
import { createHash, timingSafeEqual } from "node:crypto";

import { errorBody } from "./errors.js";

export type AuthMode = "session" | "action_key";

export interface AuthUser {
  id: string;
  role: "admin" | "viewer";
  mustEnrolTotp: boolean;
  mustChangePassword: boolean;
}

/** Minimal Hono-alike context the gates touch. */
export interface GateContext {
  req: { header: (n: string) => string | undefined };
  get: (k: string) => unknown;
  set: (k: string, v: unknown) => void;
  json: (body: unknown, status?: number) => unknown;
}

export type GateNext = () => Promise<void>;
export type GateHandler = (c: GateContext, next: GateNext) => Promise<unknown>;

function safeEqual(a: string, b: string): boolean {
  const da = createHash("sha256").update(a).digest();
  const db = createHash("sha256").update(b).digest();
  return timingSafeEqual(da, db);
}

export function requireCsrf(): GateHandler {
  return async (c, next) => {
    const provided = c.req.header("x-csrf-token");
    const expected = c.get("sessionCsrfToken") as string | undefined;
    if (!provided || !expected || !safeEqual(provided, expected)) {
      return c.json(errorBody("invalid_credentials", "csrf token missing or invalid"), 401);
    }
    await next();
  };
}

export function requireTotpConfirmed(): GateHandler {
  return async (c, next) => {
    const user = c.get("authUser") as AuthUser;
    if (user.mustEnrolTotp) {
      return c.json(errorBody("totp_required", "totp enrolment required"), 401);
    }
    await next();
  };
}

export function requirePasswordChanged(): GateHandler {
  return async (c, next) => {
    const user = c.get("authUser") as AuthUser;
    if (user.mustChangePassword) {
      return c.json(
        errorBody("password_change_required", "password change required before this action"),
        403,
      );
    }
    await next();
  };
}

/**
 * CSRF for dual-credential routers: stood down only for explicit `action_key`.
 * Unset / session modes take the full requireCsrf check (fail closed).
 */
export function requireCsrfUnlessActionKey(): GateHandler {
  const csrf = requireCsrf();
  return async (c, next) => {
    if (c.get("authMode") === "action_key") return next();
    return csrf(c, next);
  };
}
