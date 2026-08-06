// Parity vectors for the canonical TOTP matcher.
import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";

import { matchTotp, type TotpConfig } from "./match.js";

function hotp(secret: Uint8Array, counter: number, digits = 6): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", secret).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    (hmac[offset + 1]! << 16) |
    (hmac[offset + 2]! << 8) |
    hmac[offset + 3]!;
  return (code % 10 ** digits).toString().padStart(digits, "0");
}

const SECRET = new TextEncoder().encode("parity-secret-key!!!!!!!!!!");
const NOW_MS = 1_700_000_000_000;
const DEFAULT_CFG: TotpConfig = {
  secret: SECRET,
  periodSeconds: 30,
  digits: 6,
  windowSteps: 1,
};

describe("matchTotp — parity vectors", () => {
  it("accepts the center timestep", () => {
    const center = Math.floor(NOW_MS / 1000 / 30);
    const code = hotp(SECRET, center);
    expect(matchTotp(DEFAULT_CFG, { code, nowMs: NOW_MS })).toEqual({
      ok: true,
      timestep: center,
    });
  });

  it("accepts −window and +window edges", () => {
    const center = Math.floor(NOW_MS / 1000 / 30);
    for (const delta of [-1, 1] as const) {
      const step = center + delta;
      const code = hotp(SECRET, step);
      expect(matchTotp(DEFAULT_CFG, { code, nowMs: NOW_MS })).toEqual({
        ok: true,
        timestep: step,
      });
    }
  });

  it("rejects codes outside the window", () => {
    const center = Math.floor(NOW_MS / 1000 / 30);
    const code = hotp(SECRET, center - 2);
    expect(matchTotp(DEFAULT_CFG, { code, nowMs: NOW_MS })).toEqual({
      ok: false,
      reason: "invalid_code",
    });
  });

  it("rejects an invalid code", () => {
    expect(matchTotp(DEFAULT_CFG, { code: "000000", nowMs: NOW_MS })).toEqual({
      ok: false,
      reason: "invalid_code",
    });
  });

  it("honours non-default period / digits / window", () => {
    const cfg: TotpConfig = {
      secret: SECRET,
      periodSeconds: 60,
      digits: 8,
      windowSteps: 2,
    };
    const center = Math.floor(NOW_MS / 1000 / 60);
    const far = center - 2;
    const code = hotp(SECRET, far, 8);
    expect(matchTotp(cfg, { code, nowMs: NOW_MS })).toEqual({
      ok: true,
      timestep: far,
    });
    const tooFar = hotp(SECRET, center - 3, 8);
    expect(matchTotp(cfg, { code: tooFar, nowMs: NOW_MS })).toEqual({
      ok: false,
      reason: "invalid_code",
    });
  });

  it("skips negative timesteps near epoch", () => {
    const cfg: TotpConfig = { secret: SECRET, windowSteps: 1 };
    const nowMs = 5_000; // center = 0
    const centerCode = hotp(SECRET, 0);
    expect(matchTotp(cfg, { code: centerCode, nowMs })).toEqual({
      ok: true,
      timestep: 0,
    });
  });

  it("applies defaults when config omits period/digits/window", () => {
    const cfg: TotpConfig = { secret: SECRET };
    const center = Math.floor(NOW_MS / 1000 / 30);
    const code = hotp(SECRET, center);
    expect(matchTotp(cfg, { code, nowMs: NOW_MS })).toEqual({
      ok: true,
      timestep: center,
    });
  });
});
