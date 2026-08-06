// canonical Unix-time conversion.
//
// The production helper may not use Math.floor / String / Number / Date (the and
// ratchets ban them across protocol production). This colocated test is excluded from
// both scans, so it can hold the independent oracles those bans exclude from production:
// `Math.floor` for the truncation property and the platform `Date` for the RFC3339 projection.
// If the hand-rolled BigInt arithmetic ever drifts from either oracle, these fail.

import { describe, expect, it } from "vitest";

import {
  MIN_PLAUSIBLE_UNIX_SECS,
  rfc3339FromUnixSecsText,
  unixSecsTextFromClockMs,
} from "./unix-secs.js";

const PLAUSIBLE_MS = 1_784_937_600_000;

describe("unixSecsTextFromClockMs", () => {
  it("agrees with Math.floor(ms / 1000) across the plausible range", () => {
    const samples = [
      PLAUSIBLE_MS,
      PLAUSIBLE_MS + 1,
      PLAUSIBLE_MS + 999,
      PLAUSIBLE_MS + 1000,
      1_600_000_000_000,
      1_600_000_000_999,
      Number.MAX_SAFE_INTEGER - 1,
    ];
    for (const ms of samples) {
      expect(unixSecsTextFromClockMs("t", ms), `ms=${ms}`).toBe(`${Math.floor(ms / 1000)}`);
    }
  });

  it("drops the sub-second remainder rather than rounding it", () => {
    expect(unixSecsTextFromClockMs("t", PLAUSIBLE_MS + 999)).toBe(
      unixSecsTextFromClockMs("t", PLAUSIBLE_MS),
    );
  });

  it("adds the whole-second window in integer space", () => {
    expect(unixSecsTextFromClockMs("t", PLAUSIBLE_MS, 300)).toBe(
      `${Math.floor(PLAUSIBLE_MS / 1000) + 300}`,
    );
    expect(unixSecsTextFromClockMs("t", PLAUSIBLE_MS, 0)).toBe(
      unixSecsTextFromClockMs("t", PLAUSIBLE_MS),
    );
  });

  it("returns digits only, never exponential or separator-formatted text", () => {
    expect(unixSecsTextFromClockMs("t", PLAUSIBLE_MS, 86_400)).toMatch(/^[0-9]+$/);
  });

  it("rejects a seconds-valued clock, naming MILLISECONDS", () => {
    expect(() => unixSecsTextFromClockMs("t", PLAUSIBLE_MS / 1000)).toThrow(/MILLISECONDS/);
    expect(() => unixSecsTextFromClockMs("t", Number(MIN_PLAUSIBLE_UNIX_SECS) - 1)).toThrow(
      /MILLISECONDS/,
    );
  });

  it("rejects non-integer, non-finite, and negative-window input fail-closed", () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, PLAUSIBLE_MS + 0.5]) {
      expect(() => unixSecsTextFromClockMs("t", bad), `clock=${bad}`).toThrow(RangeError);
    }
    for (const bad of [-1, 1.5, Number.NaN]) {
      expect(() => unixSecsTextFromClockMs("t", PLAUSIBLE_MS, bad), `plus=${bad}`).toThrow(
        RangeError,
      );
    }
  });

  it("names the calling deriver in the diagnostic", () => {
    expect(() => unixSecsTextFromClockMs("deriveExpiryUnixTimeSecs", 1)).toThrow(
      /deriveExpiryUnixTimeSecs/,
    );
  });
});

describe("rfc3339FromUnixSecsText", () => {
  it("is byte-identical to new Date(secs * 1000).toISOString() over a wide range", () => {
    // Epoch, the plausibility floor, a leap day, a century non-leap year, and a long
    // pseudo-random-but-deterministic spread across ~150 years.
    const fixed = [0, 951_782_400, 1_600_000_000, 1_784_937_600, 4_102_444_800, 951_868_799];
    const swept: number[] = [];
    for (let i = 0; i < 4000; i += 1) {
      swept.push((i * 1_193_047) % 4_700_000_000);
    }
    for (const secs of [...fixed, ...swept]) {
      expect(rfc3339FromUnixSecsText("t", `${secs}`), `secs=${secs}`).toBe(
        new Date(secs * 1000).toISOString(),
      );
    }
  });

  it("covers every month boundary and both leap-year rules", () => {
    for (const iso of [
      "2000-02-29T00:00:00.000Z", // divisible by 400 -> leap
      "2100-02-28T23:59:59.000Z", // divisible by 100, not 400 -> not leap
      "2100-03-01T00:00:00.000Z", // the day after, proving Feb 29 does not exist in 2100
      "2024-02-29T23:59:59.000Z",
      "2023-12-31T23:59:59.000Z",
      "2024-01-01T00:00:00.000Z",
    ]) {
      const secs = Date.parse(iso) / 1000;
      expect(rfc3339FromUnixSecsText("t", `${secs}`), iso).toBe(iso);
    }
  });

  it("always emits whole seconds with a zero millisecond field", () => {
    expect(rfc3339FromUnixSecsText("t", "1784937600")).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$/,
    );
  });

  it("rejects anything that is not integer-seconds decimal text", () => {
    for (const bad of ["", "-1", "1.5", "1e9", " 12", "12 ", "0x10", "abc"]) {
      expect(() => rfc3339FromUnixSecsText("ctx", bad), `input=${JSON.stringify(bad)}`).toThrow(
        RangeError,
      );
    }
    expect(() => rfc3339FromUnixSecsText("ctx", "1.5")).toThrow(/ctx/);
  });
});
