// First-admin bootstrap for the node-origin operator surface.
//
// Seeds EXACTLY ONCE: a node boots with zero admin users exactly once. The check
// is "does any admin exist yet", not "does the default username exist" — an
// operator who has since renamed or replaced the seeded row must never be
// re-seeded by a later boot.
//
// Forced rotation (platform auth model): the seeded row is written with mustChangePassword:true
// and mustEnrolTotp:true. The password-change gate (requirePasswordChanged) and
// the later TOTP enrolment gate block money mutations until both clear.
//
// Pattern ported from apps/node/src/auth/bootstrap.ts (v1) — field names are
// GN-neutral; no ZuPayments-branded routes.

import { hashPassword } from "./password.js";
import {
  newAdminUserId,
  type AdminUser,
  type AdminUserStore,
} from "./admin-session.js";

/** Fixed username for the node's one seeded admin — never an env var. */
export const DEFAULT_ADMIN_USERNAME = "admin";

/** Floor for INITIAL_ADMIN_PASSWORD and POST /password new_password. */
export const MIN_PASSWORD_LENGTH = 12;

export interface BootstrapAdminLogger {
  info(obj: unknown, msg?: string): void;
}

export interface BootstrapAdminEnv {
  readonly INITIAL_ADMIN_PASSWORD?: string;
}

export type BootstrapOutcome =
  | { readonly seeded: false; readonly reason: "already_bootstrapped" }
  | { readonly seeded: true; readonly userId: string; readonly username: string };

/**
 * No-op unless the user store is empty. On a fresh node seeds one admin from
 * INITIAL_ADMIN_PASSWORD with mustChangePassword + mustEnrolTotp both true.
 * Fatal (throws) on a first boot missing that env var or under the length floor.
 */
export async function bootstrapInitialAdmin(
  userStore: AdminUserStore,
  env: BootstrapAdminEnv = {},
  logger?: BootstrapAdminLogger,
  now: () => number = () => Date.now(),
): Promise<BootstrapOutcome> {
  if (await userStore.anyExists()) {
    return { seeded: false, reason: "already_bootstrapped" };
  }

  const password = env.INITIAL_ADMIN_PASSWORD;
  if (password === undefined || password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(
      `INITIAL_ADMIN_PASSWORD is required on first boot (no admin user exists yet) ` +
        `and must be at least ${MIN_PASSWORD_LENGTH} characters`,
    );
  }

  const userId = newAdminUserId();
  const user: AdminUser = {
    id: userId,
    username: DEFAULT_ADMIN_USERNAME,
    passwordHash: await hashPassword(password),
    role: "admin",
    mustChangePassword: true,
    mustEnrolTotp: true,
    disabledAt: null,
    createdAt: now(),
  };
  await userStore.insert(user);

  // Never the password itself — only that a seed happened.
  logger?.info(
    { event: "boot.admin_bootstrapped", username: DEFAULT_ADMIN_USERNAME },
    `boot: seeded default admin '${DEFAULT_ADMIN_USERNAME}' — must change password + enrol TOTP on first login`,
  );

  return { seeded: true, userId, username: DEFAULT_ADMIN_USERNAME };
}
