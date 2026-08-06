// Canonical TOTP window matcher (RFC 6238 HOTP + ±skew walk).
// Single production HOTP/window-matching implementation for node-core.
// Callers that enforce single-use via a durable UNIQUE index must match here
// first, then insert the burn row as the arbiter (step 6).
//

import { createHmac } from "node:crypto";

export interface TotpConfig {
  readonly secret: Uint8Array;
  readonly periodSeconds?: number;
  readonly digits?: number;
  readonly windowSteps?: number;
}

export type TotpMatchOutcome =
  | { readonly ok: true; readonly timestep: number }
  | { readonly ok: false; readonly reason: "invalid_code" };

const DEFAULT_PERIOD = 30;
const DEFAULT_DIGITS = 6;
const DEFAULT_WINDOW = 1;

function hotp(secret: Uint8Array, counter: number, digits: number): string {
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

function currentTimestep(nowMs: number, periodSeconds: number): number {
  return Math.floor(nowMs / 1000 / periodSeconds);
}

/** Match a code to a timestep within the clock-skew window WITHOUT consuming. */
export function matchTotp(
  config: TotpConfig,
  request: { readonly code: string; readonly nowMs?: number },
): TotpMatchOutcome {
  const period = config.periodSeconds ?? DEFAULT_PERIOD;
  const digits = config.digits ?? DEFAULT_DIGITS;
  const window = config.windowSteps ?? DEFAULT_WINDOW;
  const now = request.nowMs ?? Date.now();
  const center = currentTimestep(now, period);

  for (let offset = -window; offset <= window; offset++) {
    const step = center + offset;
    if (step < 0) continue;
    const expected = hotp(config.secret, step, digits);
    if (request.code === expected) {
      return { ok: true, timestep: step };
    }
  }
  return { ok: false, reason: "invalid_code" };
}
