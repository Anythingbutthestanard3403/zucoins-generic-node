/**
 * Operator PWA helpers.
 *
 * Shell-only service worker registration + install affordance.
 * Never treats cached API JSON as live money state — SW is network-only for
 * /admin/v1, /v1, and /health*. Same-origin only (PUBLIC_BASE_URL).
 */

export const INSTALL_DISMISS_KEY = "zu-node-pwa-install-dismissed";
export const INSTALL_OFFERED_KEY = "zu-node-pwa-install-offered";

/** Closed evidence enum posted to POST /admin/v1/setup/pwa-installed. */
export type PwaInstallEvidenceKind = "standalone" | "fullscreen" | "appinstalled";

/**
 * Observe real display-mode / iOS standalone evidence.
 * Returns null in a normal browser tab — never invents install.
 */
export function observePwaInstallEvidence(): PwaInstallEvidenceKind | null {
  if (typeof window === "undefined") return null;
  try {
    if (window.matchMedia?.("(display-mode: standalone)")?.matches) return "standalone";
    if (window.matchMedia?.("(display-mode: fullscreen)")?.matches) return "fullscreen";
  } catch {
    /* matchMedia unavailable */
  }
  const nav = window.navigator as Navigator & { standalone?: boolean };
  if (nav.standalone === true) return "standalone";
  return null;
}

/** True when the page is already running as an installed PWA. */
export function isStandaloneDisplay(): boolean {
  return observePwaInstallEvidence() !== null;
}

/**
 * Node origin URL only — QR payload for the mandatory install wall.
 * No tokens, query secrets, or path fragments beyond origin + trailing slash.
 */
export function nodeOriginInstallUrl(
  loc: Pick<Location, "origin"> = typeof window !== "undefined" ? window.location : { origin: "" },
): string {
  const origin = (loc.origin ?? "").replace(/\/+$/u, "");
  if (!origin) return "/";
  return `${origin}/`;
}

/** POST durable install evidence (session + CSRF). */
export async function reportPwaInstalled(
  evidence: PwaInstallEvidenceKind,
  csrf: string,
): Promise<{ pwa_installed?: boolean; complete?: boolean }> {
  const res = await fetch("/admin/v1/setup/pwa-installed", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf,
    },
    body: JSON.stringify({ evidence }),
  });
  if (!res.ok) {
    let msg = `${res.status}`;
    try {
      const b = (await res.json()) as { error?: { message?: string } };
      msg = b.error?.message ?? msg;
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  return (await res.json()) as { pwa_installed?: boolean; complete?: boolean };
}

export function wasInstallDismissed(storage: Storage = localStorage): boolean {
  try {
    return storage.getItem(INSTALL_DISMISS_KEY) === "1";
  } catch {
    return false;
  }
}

export function dismissInstall(storage: Storage = localStorage): void {
  try {
    storage.setItem(INSTALL_DISMISS_KEY, "1");
  } catch {
    /* private mode */
  }
}

export function clearInstallDismiss(storage: Storage = localStorage): void {
  try {
    storage.removeItem(INSTALL_DISMISS_KEY);
  } catch {
    /* private mode */
  }
}

export function markInstallOffered(storage: Storage = localStorage): void {
  try {
    storage.setItem(INSTALL_OFFERED_KEY, "1");
  } catch {
    /* private mode */
  }
}

export function wasInstallOffered(storage: Storage = localStorage): boolean {
  try {
    return storage.getItem(INSTALL_OFFERED_KEY) === "1";
  } catch {
    return false;
  }
}

/**
 * Register the shell SW when running under a secure context on the node origin.
 * Skipped in vitest/jsdom (no serviceWorker) and plain HTTP non-loopback.
 */
export async function registerShellServiceWorker(
  swPath = "/sw.js",
): Promise<ServiceWorkerRegistration | null> {
  if (typeof window === "undefined") return null;
  if (!("serviceWorker" in navigator)) return null;
  // Secure context required for SW (https or localhost).
  if (!window.isSecureContext) return null;
  try {
    return await navigator.serviceWorker.register(swPath, { scope: "/" });
  } catch {
    return null;
  }
}

/** Chromium beforeinstallprompt event shape (not in all TS libs). */
export interface BeforeInstallPromptEvent extends Event {
  readonly platforms: ReadonlyArray<string>;
  prompt(): Promise<void>;
  readonly userChoice: Promise<{ outcome: "accepted" | "dismissed"; platform: string }>;
}

export function isBeforeInstallPromptEvent(ev: Event): ev is BeforeInstallPromptEvent {
  return (
    typeof (ev as BeforeInstallPromptEvent).prompt === "function" &&
    "userChoice" in ev
  );
}

/** Capture beforeinstallprompt at module scope so Setup/App share one deferred event. */
let deferredInstallPrompt: BeforeInstallPromptEvent | null = null;
const deferredListeners = new Set<(ev: BeforeInstallPromptEvent | null) => void>();

export function getDeferredInstallPrompt(): BeforeInstallPromptEvent | null {
  return deferredInstallPrompt;
}

export function subscribeDeferredInstallPrompt(
  fn: (ev: BeforeInstallPromptEvent | null) => void,
): () => void {
  deferredListeners.add(fn);
  return () => {
    deferredListeners.delete(fn);
  };
}

export function consumeDeferredInstallPrompt(): void {
  deferredInstallPrompt = null;
  for (const fn of deferredListeners) fn(null);
}

export function bindBeforeInstallPromptListener(): () => void {
  if (typeof window === "undefined") return () => undefined;
  const handler = (ev: Event) => {
    if (!isBeforeInstallPromptEvent(ev)) return;
    ev.preventDefault();
    deferredInstallPrompt = ev;
    for (const fn of deferredListeners) fn(ev);
  };
  window.addEventListener("beforeinstallprompt", handler);
  return () => window.removeEventListener("beforeinstallprompt", handler);
}

