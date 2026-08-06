import { describe, it, expect, beforeEach } from "vitest";
import { createHmac } from "node:crypto";
import {
  checkCsrf,
  checkCsrfWithApiBypass,
  TotpConsumptionLog,
  verifyTotp,
  guardedMutation,
} from "../src/http/index.js";
import type { CsrfConfig, TotpConfig } from "../src/http/index.js";

describe("checkCsrf", () => {
  const config: CsrfConfig = { allowedOrigins: ["https://node.example.com"] };

  it("allows safe methods regardless of origin", () => {
    for (const method of ["GET", "HEAD", "OPTIONS"]) {
      const result = checkCsrf(config, { method, headers: {} });
      expect(result.ok).toBe(true);
    }
  });

  it("allows same-origin POST via Origin header", () => {
    const result = checkCsrf(config, {
      method: "POST",
      headers: { origin: "https://node.example.com" },
    });
    expect(result.ok).toBe(true);
  });

  it("allows same-origin POST via Referer header", () => {
    const result = checkCsrf(config, {
      method: "POST",
      headers: { referer: "https://node.example.com/admin/dashboard" },
    });
    expect(result.ok).toBe(true);
  });

  it("rejects cross-origin POST", () => {
    const result = checkCsrf(config, {
      method: "POST",
      headers: { origin: "https://evil.com" },
    });
    expect(result).toEqual({ ok: false, reason: "origin_mismatch" });
  });

  it("rejects state-mutating request with no origin or referer", () => {
    const result = checkCsrf(config, { method: "POST", headers: {} });
    expect(result).toEqual({ ok: false, reason: "origin_missing" });
  });

  it("rejects PUT and DELETE cross-origin", () => {
    for (const method of ["PUT", "DELETE", "PATCH"]) {
      const result = checkCsrf(config, {
        method,
        headers: { origin: "https://attacker.io" },
      });
      expect(result).toEqual({ ok: false, reason: "origin_mismatch" });
    }
  });

  it("rejects malformed referer", () => {
    const result = checkCsrf(config, {
      method: "POST",
      headers: { referer: "not-a-url" },
    });
    expect(result).toEqual({ ok: false, reason: "origin_missing" });
  });
});

describe("checkCsrfWithApiBypass", () => {
  const config: CsrfConfig = { allowedOrigins: ["https://node.example.com"] };

  it("bypasses CSRF for API-key-authenticated requests", () => {
    const result = checkCsrfWithApiBypass(
      config,
      { method: "POST", headers: { origin: "https://evil.com" } },
      true,
    );
    expect(result.ok).toBe(true);
  });

  it("still enforces CSRF when not API-authenticated", () => {
    const result = checkCsrfWithApiBypass(
      config,
      { method: "POST", headers: { origin: "https://evil.com" } },
      false,
    );
    expect(result).toEqual({ ok: false, reason: "origin_mismatch" });
  });
});

function generateTotp(secret: Uint8Array, timestep: number, digits = 6): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timestep));
  const hmac = createHmac("sha1", secret).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    (hmac[offset + 1]! << 16) |
    (hmac[offset + 2]! << 8) |
    hmac[offset + 3]!;
  return (code % 10 ** digits).toString().padStart(digits, "0");
}

describe("verifyTotp", () => {
  const secret = new TextEncoder().encode("test-secret-key-32-bytes-long!!");
  const config: TotpConfig = { secret, periodSeconds: 30, digits: 6, windowSteps: 1 };
  let log: TotpConsumptionLog;

  beforeEach(() => {
    log = new TotpConsumptionLog();
  });

  it("accepts a valid code for the current timestep", async () => {
    const nowMs = 1_700_000_000_000;
    const timestep = Math.floor(nowMs / 1000 / 30);
    const code = generateTotp(secret, timestep);
    const result = await verifyTotp(config, { nodeId: "node-1", code, nowMs }, log);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.timestep).toBe(timestep);
  });

  it("accepts a code from an adjacent window step", async () => {
    const nowMs = 1_700_000_000_000;
    const timestep = Math.floor(nowMs / 1000 / 30) - 1;
    const code = generateTotp(secret, timestep);
    const result = await verifyTotp(config, { nodeId: "node-1", code, nowMs }, log);
    expect(result.ok).toBe(true);
  });

  it("rejects an invalid code", async () => {
    const result = await verifyTotp(
      config,
      { nodeId: "node-1", code: "000000", nowMs: 1_700_000_000_000 },
      log,
    );
    expect(result).toEqual({ ok: false, reason: "invalid_code" });
  });

  it("rejects replay of the same code in the same timestep", async () => {
    const nowMs = 1_700_000_000_000;
    const timestep = Math.floor(nowMs / 1000 / 30);
    const code = generateTotp(secret, timestep);
    const first = await verifyTotp(config, { nodeId: "node-1", code, nowMs }, log);
    expect(first.ok).toBe(true);
    const second = await verifyTotp(config, { nodeId: "node-1", code, nowMs }, log);
    expect(second).toEqual({ ok: false, reason: "replay" });
  });

  it("allows the same code for a different node", async () => {
    const nowMs = 1_700_000_000_000;
    const timestep = Math.floor(nowMs / 1000 / 30);
    const code = generateTotp(secret, timestep);
    const first = await verifyTotp(config, { nodeId: "node-1", code, nowMs }, log);
    expect(first.ok).toBe(true);
    const second = await verifyTotp(config, { nodeId: "node-2", code, nowMs }, log);
    expect(second.ok).toBe(true);
  });
});

describe("TotpConsumptionLog", () => {
  it("consume returns false on second call for same key", () => {
    const log = new TotpConsumptionLog();
    expect(log.consume("n1", 100)).toBe(true);
    expect(log.consume("n1", 100)).toBe(false);
  });

  it("isConsumed reflects state", async () => {
    const log = new TotpConsumptionLog();
    expect(log.isConsumed("n1", 50)).toBe(false);
    log.consume("n1", 50);
    expect(log.isConsumed("n1", 50)).toBe(true);
  });
});

describe("guardedMutation", () => {
  const secret = new TextEncoder().encode("test-secret-key-32-bytes-long!!");
  const config: TotpConfig = { secret, periodSeconds: 30, digits: 6, windowSteps: 1 };
  let log: TotpConsumptionLog;

  beforeEach(() => {
    log = new TotpConsumptionLog();
  });

  it("executes the mutation after successful TOTP verification", async () => {
    const nowMs = 1_700_000_000_000;
    const timestep = Math.floor(nowMs / 1000 / 30);
    const code = generateTotp(secret, timestep);
    let executed = false;
    const result = await guardedMutation(
      config,
      { nodeId: "node-1", code, nowMs },
      log,
      async () => { executed = true; return "done"; },
    );
    expect(result.ok).toBe(true);
    expect(executed).toBe(true);
    if (result.ok) expect(result.result).toBe("done");
  });

  it("does not execute the mutation on invalid TOTP", async () => {
    let executed = false;
    const result = await guardedMutation(
      config,
      { nodeId: "node-1", code: "999999", nowMs: 1_700_000_000_000 },
      log,
      async () => { executed = true; return "done"; },
    );
    expect(result.ok).toBe(false);
    expect(executed).toBe(false);
  });

  it("burns the TOTP even if the mutation throws", async () => {
    const nowMs = 1_700_000_000_000;
    const timestep = Math.floor(nowMs / 1000 / 30);
    const code = generateTotp(secret, timestep);
    await expect(
      guardedMutation(
        config,
        { nodeId: "node-1", code, nowMs },
        log,
        async () => { throw new Error("mutation failed"); },
      ),
    ).rejects.toThrow("mutation failed");
    const replay = await verifyTotp(config, { nodeId: "node-1", code, nowMs }, log);
    expect(replay).toEqual({ ok: false, reason: "replay" });
  });
});
