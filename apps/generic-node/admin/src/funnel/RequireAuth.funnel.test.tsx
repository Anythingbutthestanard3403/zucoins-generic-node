/**
 * Day-0 funnel redirect matrix — SPA gate behavior.
 * Uses the same pure helpers as main.tsx RequireAuth / RequireFunnel.
 */
import { describe, expect, it } from "vitest";
import {
  isMoneyOrAppPath,
  pathForNextStep,
  redirectForFunnelPath,
  refineNextStep,
  type Day0Step,
} from "./day0.js";

/** Mirrors RequireAuth: money path + incomplete → pathForNextStep. */
function requireAuthRedirect(
  pathname: string,
  opts: {
    readonly authed: boolean;
    readonly mustChangePassword?: boolean;
    readonly mustEnrolTotp?: boolean;
        readonly complete?: boolean;
    readonly next_step?: Day0Step;
    readonly packCreatedLocally?: boolean;
  },
): string | null {
  if (!opts.authed) return "/login";
  if (opts.mustChangePassword || opts.mustEnrolTotp) return "/setup";
  if (opts.complete) return null;
  const next = refineNextStep(opts.next_step ?? "install", {
    packCreatedLocally: opts.packCreatedLocally === true,
  });
  if (isMoneyOrAppPath(pathname)) return pathForNextStep(next);
  return null;
}

/** Mirrors RequireFunnel sequence bounce. */
function requireFunnelRedirect(
  pathname: string,
  next_step: Day0Step,
  packCreatedLocally = false,
): string | null {
  const next = refineNextStep(next_step, { packCreatedLocally });
  if (next === "home") return "/";
  return redirectForFunnelPath(pathname, next);
}

describe("RequireAuth money-route matrix", () => {
  const money = ["/", "/destinations", "/transfers", "/wallets", "/approve", "/operations"];

  it("unauthenticated → login", () => {
    for (const p of money) {
      expect(requireAuthRedirect(p, { authed: false })).toBe("/login");
    }
  });

  it("password/TOTP incomplete → /setup", () => {
    expect(
      requireAuthRedirect("/", { authed: true, mustChangePassword: true }),
    ).toBe("/setup");
    expect(requireAuthRedirect("/", { authed: true, mustEnrolTotp: true })).toBe("/setup");
  });

  it("incomplete day-0 blocks every money route via next_step", () => {
    const steps: Day0Step[] = ["install", "device", "vault", "backup", "prove"];
    for (const step of steps) {
      for (const p of money) {
        expect(requireAuthRedirect(p, { authed: true, next_step: step })).toBe(
          pathForNextStep(step),
        );
      }
    }
  });

  it("local pack create refines backup → prove for money gate", () => {
    expect(
      requireAuthRedirect("/transfers", {
        authed: true,
        next_step: "backup",
        packCreatedLocally: true,
      }),
    ).toBe("/start/prove");
  });
});

describe("RequireFunnel sequence matrix", () => {
  it("cannot skip ahead of server next_step", () => {
    expect(requireFunnelRedirect("/start/device", "install")).toBe("/start/install");
    expect(requireFunnelRedirect("/start/backup", "device")).toBe("/start/device");
    expect(requireFunnelRedirect("/start/prove", "backup")).toBe("/start/backup");
    expect(requireFunnelRedirect("/start/install", "install")).toBeNull();
  });

  it("cannot linger on earlier step once advanced", () => {
    expect(requireFunnelRedirect("/start/install", "device")).toBe("/start/device");
    expect(requireFunnelRedirect("/start/vault", "backup")).toBe("/start/backup");
  });

  it("complete funnel leaves /start/* for Home", () => {
    expect(requireFunnelRedirect("/start/prove", "home")).toBe("/");
  });

  it("prove allowed after local create when server still says backup", () => {
    expect(requireFunnelRedirect("/start/prove", "backup", true)).toBeNull();
    expect(requireFunnelRedirect("/start/backup", "backup", true)).toBe("/start/prove");
  });
});
