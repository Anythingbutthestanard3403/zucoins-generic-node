import { afterEach, describe, expect, it } from "vitest";
import {
  clearPackCreateMarker,
  DAY0_STEPS,
  hasPackCreateMarker,
  isMoneyOrAppPath,
  markPackCreated,
  pathForNextStep,
  redirectForFunnelPath,
  refineNextStep,
  stepFromPath,
} from "./day0.js";

describe("day0 funnel path map", () => {
  it("maps every next_step to a stable path", () => {
    expect(pathForNextStep("password")).toBe("/setup");
    expect(pathForNextStep("totp")).toBe("/setup");
    expect(pathForNextStep("install")).toBe("/start/install");
    expect(pathForNextStep("device")).toBe("/start/device");
    expect(pathForNextStep("vault")).toBe("/start/vault");
    expect(pathForNextStep("backup")).toBe("/start/backup");
    expect(pathForNextStep("prove")).toBe("/start/prove");
    expect(pathForNextStep("home")).toBe("/");
  });

  it("round-trips start paths", () => {
    for (const step of ["install", "device", "vault", "backup", "prove"] as const) {
      expect(stepFromPath(pathForNextStep(step))).toBe(step);
    }
  });

  it("money routes are gated; funnel paths are not", () => {
    expect(isMoneyOrAppPath("/")).toBe(true);
    expect(isMoneyOrAppPath("/destinations")).toBe(true);
    expect(isMoneyOrAppPath("/transfers")).toBe(true);
    expect(isMoneyOrAppPath("/wallets")).toBe(true);
    expect(isMoneyOrAppPath("/start/install")).toBe(false);
    expect(isMoneyOrAppPath("/setup")).toBe(false);
    expect(isMoneyOrAppPath("/login")).toBe(false);
  });
});

describe("day0 redirect matrix", () => {
  it("bounces incomplete operators off Home to current next_step", () => {
    expect(redirectForFunnelPath("/", "install")).toBe("/start/install");
    expect(redirectForFunnelPath("/destinations", "device")).toBeNull(); // not a funnel path — RequireAuth handles
    expect(redirectForFunnelPath("/start/device", "install")).toBe("/start/install");
    expect(redirectForFunnelPath("/start/install", "install")).toBeNull();
    expect(redirectForFunnelPath("/start/backup", "backup")).toBeNull();
    expect(redirectForFunnelPath("/start/prove", "backup")).toBe("/start/backup");
    expect(redirectForFunnelPath("/setup", "install")).toBe("/start/install");
    expect(redirectForFunnelPath("/setup", "password")).toBeNull();
    expect(redirectForFunnelPath("/start/install", "home")).toBe("/");
  });

  it("refines backup→prove only with local create marker", () => {
    expect(refineNextStep("backup", { packCreatedLocally: false })).toBe("backup");
    expect(refineNextStep("backup", { packCreatedLocally: true })).toBe("prove");
    expect(refineNextStep("install", { packCreatedLocally: true })).toBe("install");
    expect(refineNextStep("home")).toBe("home");
  });

  it("pack create marker is local-only", () => {
    const mem = new Map<string, string>();
    const storage = {
      getItem: (k: string) => mem.get(k) ?? null,
      setItem: (k: string, v: string) => {
        mem.set(k, v);
      },
      removeItem: (k: string) => {
        mem.delete(k);
      },
    } as Storage;
    expect(hasPackCreateMarker(storage)).toBe(false);
    markPackCreated(storage);
    expect(hasPackCreateMarker(storage)).toBe(true);
    clearPackCreateMarker(storage);
    expect(hasPackCreateMarker(storage)).toBe(false);
  });

  it("DAY0_STEPS sequence is stable product sequence", () => {
    expect([...DAY0_STEPS]).toEqual([
      "password",
      "totp",
      "install",
      "device",
      "vault",
      "backup",
      "prove",
      "home",
    ]);
  });
});

afterEach(() => {
  /* no env */
});
