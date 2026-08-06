import { afterEach, describe, expect, it, vi } from "vitest";
import {
  INSTALL_DISMISS_KEY,
  clearInstallDismiss,
  dismissInstall,
  isStandaloneDisplay,
  nodeOriginInstallUrl,
  observePwaInstallEvidence,
  registerShellServiceWorker,
  wasInstallDismissed,
} from "./pwa.js";

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

describe("pwa install dismiss", () => {
  it("tracks skip so the prompt stays dismissible", () => {
    expect(wasInstallDismissed()).toBe(false);
    dismissInstall();
    expect(wasInstallDismissed()).toBe(true);
    expect(localStorage.getItem(INSTALL_DISMISS_KEY)).toBe("1");
    clearInstallDismiss();
    expect(wasInstallDismissed()).toBe(false);
  });
});

describe("isStandaloneDisplay", () => {
  it("is false under default jsdom (browser tab)", () => {
    expect(isStandaloneDisplay()).toBe(false);
    expect(observePwaInstallEvidence()).toBeNull();
  });

  it("returns standalone when matchMedia matches", () => {
    vi.spyOn(window, "matchMedia").mockImplementation((q: string) => {
      return {
        matches: q.includes("display-mode: standalone"),
        media: q,
        onchange: null,
        addListener: () => undefined,
        removeListener: () => undefined,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        dispatchEvent: () => false,
      } as MediaQueryList;
    });
    expect(observePwaInstallEvidence()).toBe("standalone");
    expect(isStandaloneDisplay()).toBe(true);
  });
});

describe("nodeOriginInstallUrl", () => {
  it("emits secret-free origin slash URL", () => {
    expect(nodeOriginInstallUrl({ origin: "https://node.test" })).toBe("https://node.test/");
  });
});

describe("registerShellServiceWorker", () => {
  it("returns null when serviceWorker is unavailable", async () => {
    const desc = Object.getOwnPropertyDescriptor(navigator, "serviceWorker");
    // jsdom may lack serviceWorker entirely
    if (desc) {
      Object.defineProperty(navigator, "serviceWorker", { configurable: true, value: undefined });
    }
    await expect(registerShellServiceWorker()).resolves.toBeNull();
  });

  it("registers /sw.js with scope / when SW API is present", async function registerWhenPresent() {
    if (!window.isSecureContext) {
      // jsdom is usually a secure context for localhost — if not, skip body.
      Object.defineProperty(window, "isSecureContext", { configurable: true, value: true });
    }
    const register = vi.fn(async () => ({ scope: "/" }));
    Object.defineProperty(navigator, "serviceWorker", {
      configurable: true,
      value: { register },
    });
    const reg = await registerShellServiceWorker();
    expect(register).toHaveBeenCalledWith("/sw.js", { scope: "/" });
    expect(reg).toEqual({ scope: "/" });
  });
});
