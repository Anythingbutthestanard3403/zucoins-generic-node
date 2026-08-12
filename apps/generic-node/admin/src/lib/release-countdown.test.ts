import { describe, expect, it } from "vitest";
import {
  deriveReleaseCountdown,
  formatRemaining,
  parseExpiryUnixSecs,
  RELEASE_SAFETY_MARGIN_SECS,
} from "./release-countdown.js";

describe("parseExpiryUnixSecs", () => {
  it("parses text unix seconds", () => {
    expect(parseExpiryUnixSecs("1700000000")).toBe(1700000000);
    expect(parseExpiryUnixSecs(null)).toBeNull();
    expect(parseExpiryUnixSecs("")).toBeNull();
    expect(parseExpiryUnixSecs("nope")).toBeNull();
  });
});

describe("formatRemaining", () => {
  it("formats mm:ss under an hour", () => {
    expect(formatRemaining(65_000)).toBe("01:05");
    expect(formatRemaining(0)).toBe("00:00");
  });
});

describe("deriveReleaseCountdown", () => {
  const expiry = "1_700_000_000".replace(/_/g, "");
  const releaseAtMs = (Number(expiry) + RELEASE_SAFETY_MARGIN_SECS) * 1000;

  it("pre-release counts to expiry + safety margin", () => {
    const s = deriveReleaseCountdown({
      expiryUnixTimeSecs: expiry,
      status: "READY",
      terminalAt: null,
      nowMs: releaseAtMs - 90_000,
    });
    expect(s.kind).toBe("pre_release");
    if (s.kind === "pre_release") {
      expect(s.releaseAtMs).toBe(releaseAtMs);
      expect(s.label).toMatch(/^auto-releases in /);
    }
  });

  it("post-expiry flips to awaiting release proof (no fake released)", () => {
    const s = deriveReleaseCountdown({
      expiryUnixTimeSecs: expiry,
      status: "READY",
      terminalAt: null,
      attentionRequired: true,
      nowMs: releaseAtMs + 1_000,
    });
    expect(s).toMatchObject({
      kind: "awaiting_release_proof",
      label: "awaiting release proof — check attention",
    });
  });

  it("landed holds show verification-complete wait", () => {
    const s = deriveReleaseCountdown({
      expiryUnixTimeSecs: expiry,
      status: "RECEIVE_LANDED",
      terminalAt: "2026-08-01T00:00:00.000Z",
      nowMs: releaseAtMs,
    });
    expect(s.kind).toBe("awaiting_verification");
  });

  it("null expiry is none", () => {
    expect(
      deriveReleaseCountdown({
        expiryUnixTimeSecs: null,
        status: "CREATED",
        terminalAt: null,
      }).kind,
    ).toBe("none");
  });
});
