/**
 * Day-0 funnel routing.
 *
 * Sequence after login: password → totp → install → device → vault → backup → prove → home.
 * Server `next_step` is authoritative for money-route gating. SPA may soft-split
 * backup vs prove with a local create marker; recovery_proven still requires a real recovery_verified_at stamp.
 */

export const DAY0_STEPS = [
  "password",
  "totp",
  "install",
  "device",
  "vault",
  "backup",
  "prove",
  "home",
] as const;

export type Day0Step = (typeof DAY0_STEPS)[number];

export function isDay0Step(value: unknown): value is Day0Step {
  return typeof value === "string" && (DAY0_STEPS as readonly string[]).includes(value);
}

/** SPA path for a day-0 step. `home` → `/`; auth steps share `/setup`. */
export function pathForNextStep(step: Day0Step | string | null | undefined): string {
  switch (step) {
    case "password":
    case "totp":
      return "/setup";
    case "install":
      return "/start/install";
    case "device":
      return "/start/device";
    case "vault":
      return "/start/vault";
    case "backup":
      return "/start/backup";
    case "prove":
      return "/start/prove";
    case "home":
      return "/";
    default:
      return "/setup";
  }
}

/** Map a pathname to a day-0 step (or null if not a funnel path). */
export function stepFromPath(pathname: string): Day0Step | null {
  const p = pathname.replace(/\/+$/, "") || "/";
  if (p === "/setup") return null; // auth — password/totp resolved via user flags
  if (p === "/start/install") return "install";
  if (p === "/start/device") return "device";
  if (p === "/start/vault") return "vault";
  if (p === "/start/backup") return "backup";
  if (p === "/start/prove") return "prove";
  if (p === "/" || p === "") return "home";
  return null;
}

export function day0StepIndex(step: Day0Step): number {
  return DAY0_STEPS.indexOf(step);
}

/**
 * Enforce sequence: visiting a step ahead of server `next_step` bounces back;
 * visiting a completed earlier step advances to `next_step`.
 * Returns null when the current path is allowed.
 */
export function redirectForFunnelPath(
  pathname: string,
  nextStep: Day0Step,
): string | null {
  const here = stepFromPath(pathname);
  if (here === null) {
    // /setup is only for password/totp; if auth done, send to next day-0 path.
    if (pathname.replace(/\/+$/, "") === "/setup" && nextStep !== "password" && nextStep !== "totp") {
      return pathForNextStep(nextStep);
    }
    return null;
  }
  if (nextStep === "home") {
    // Setup complete — leave funnel paths for Home.
    if (here !== "home") return "/";
    return null;
  }
  const hi = day0StepIndex(here);
  const ni = day0StepIndex(nextStep);
  if (hi < 0 || ni < 0) return pathForNextStep(nextStep);
  if (hi !== ni) return pathForNextStep(nextStep);
  return null;
}

/** Money / app routes that require complete day-0 setup. */
export function isMoneyOrAppPath(pathname: string): boolean {
  const p = pathname.replace(/\/+$/, "") || "/";
  if (p === "/login" || p === "/setup") return false;
  if (p.startsWith("/start/")) return false;
  return true;
}

/** Local marker: operator downloaded a pack this browser (soft-gate prove). */
export const PACK_CREATE_MARKER_KEY = "zp-day0-pack-created";

export function markPackCreated(storage: Storage = localStorage): void {
  try {
    storage.setItem(PACK_CREATE_MARKER_KEY, new Date().toISOString());
  } catch {
    /* private mode */
  }
}

export function hasPackCreateMarker(storage: Storage = localStorage): boolean {
  try {
    return Boolean(storage.getItem(PACK_CREATE_MARKER_KEY));
  } catch {
    return false;
  }
}

export function clearPackCreateMarker(storage: Storage = localStorage): void {
  try {
    storage.removeItem(PACK_CREATE_MARKER_KEY);
  } catch {
    /* ignore */
  }
}

/**
 * Refine server next_step=backup into prove when a local create marker exists.
 * Never invents recovery_proven — server still owns complete.
 */
export function refineNextStep(
  serverNext: Day0Step | string | null | undefined,
  opts: { readonly packCreatedLocally?: boolean } = {},
): Day0Step {
  const step: Day0Step = isDay0Step(serverNext) ? serverNext : "password";
  if (step === "backup" && opts.packCreatedLocally === true) return "prove";
  return step;
}

export interface SetupStateDay0 {
  readonly complete?: boolean;
  readonly next_step?: string;
  readonly password_ok?: boolean;
  readonly totp_ok?: boolean;
  readonly pwa_installed?: boolean;
  readonly device_enrolled?: boolean;
  readonly vault_ready?: boolean;
  readonly recovery_proven?: boolean;
  readonly allow_browser_tab_setup?: boolean;
}
