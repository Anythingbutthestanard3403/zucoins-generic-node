// ZTR-1210 — login and confirm-TOTP share one lockout IP identity.
// Default: socket peer (ZTR-1192). Proxied: TRUST_PROXY_HOPS + resolveClientIp.
// XFF must not reset the pair when proxy trust is off.

import { createHmac, randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  IP_LOCK_THRESHOLD,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  _resetIpLockoutForTests,
  _resetLoginRateLimitForTests,
  createAdminSessionService,
  createFailClosedDestinationService,
  hashPassword,
  isIpPairLocked,
  totpSecretBytes,
  type AdminUser,
} from "@zucoins/node-core";

import {
  createAdminRouter,
  createFailClosedAdminRouteDeps,
  resolveAdminLockoutIp,
} from "../src/admin-router.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const PASSWORD = "bootstrap-secret-lockout-1";
const SOCKET = "198.51.100.77";
const SPOOF_A = "203.0.113.1";
const SPOOF_B = "203.0.113.99";
const USERNAME = "admin";

function hotp(secret: Uint8Array, counter: number): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", secret).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    (hmac[offset + 1]! << 16) |
    (hmac[offset + 2]! << 8) |
    hmac[offset + 3]!;
  return (code % 1_000_000).toString().padStart(6, "0");
}

function codeFor(secretBase32: string, nowMs = Date.now()): string {
  const bytes = totpSecretBytes(secretBase32)!;
  const step = Math.floor(nowMs / 1000 / 30);
  return hotp(bytes, step);
}

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  return setCookie.split(";")[0] ?? "";
}

async function seedAdmin(
  store: InMemoryAdminUserStore,
  opts: { mustEnrolTotp?: boolean } = {},
): Promise<AdminUser> {
  const user: AdminUser = {
    id: randomUUID(),
    username: USERNAME,
    passwordHash: await hashPassword(PASSWORD),
    role: "admin",
    mustChangePassword: false,
    mustEnrolTotp: opts.mustEnrolTotp ?? true,
    disabledAt: null,
    createdAt: Date.now(),
  };
  await store.insert(user);
  return user;
}

function buildRouter(
  userStore: InMemoryAdminUserStore,
  sessionStore = new InMemoryAdminSessionStore(),
) {
  const sessions = createAdminSessionService({ nodeId: NODE_ID }, sessionStore, userStore);
  const deps = createFailClosedAdminRouteDeps({
    sessions,
    userStore,
    csrf: { allowedOrigins: ["https://node.example"] },
    totp: { secret: new Uint8Array(32), windowSteps: 1 },
    nodeId: NODE_ID,
    destinationService: createFailClosedDestinationService(),
    newRequestId: () => randomUUID(),
  });
  return { router: createAdminRouter(deps), sessions };
}

describe("resolveAdminLockoutIp", () => {
  const prevHops = process.env.TRUST_PROXY_HOPS;
  const prevDirect = process.env.TRUST_PROXY_DIRECT_EXPOSURE;

  afterEach(() => {
    if (prevHops === undefined) delete process.env.TRUST_PROXY_HOPS;
    else process.env.TRUST_PROXY_HOPS = prevHops;
    if (prevDirect === undefined) delete process.env.TRUST_PROXY_DIRECT_EXPOSURE;
    else process.env.TRUST_PROXY_DIRECT_EXPOSURE = prevDirect;
  });

  it("defaults to socket peer and ignores X-Forwarded-For", () => {
    delete process.env.TRUST_PROXY_HOPS;
    expect(
      resolveAdminLockoutIp(
        { "x-forwarded-for": SPOOF_A },
        SOCKET,
      ),
    ).toBe(SOCKET);
  });

  it("returns null when socket is absent and proxy trust is off", () => {
    delete process.env.TRUST_PROXY_HOPS;
    expect(resolveAdminLockoutIp({ "x-forwarded-for": SPOOF_A }, null)).toBeNull();
  });

  it("with TRUST_PROXY_HOPS peels rightmost trusted hop from XFF", () => {
    expect(
      resolveAdminLockoutIp(
        { "x-forwarded-for": `${SPOOF_A}, 203.0.113.50` },
        SOCKET,
        { TRUST_PROXY_HOPS: "1" },
      ),
    ).toBe("203.0.113.50");
  });

  it("with TRUST_PROXY_HOPS falls back to socket when XFF is missing", () => {
    expect(
      resolveAdminLockoutIp({}, SOCKET, { TRUST_PROXY_HOPS: "1" }),
    ).toBe(SOCKET);
  });
});

describe("login + confirm-TOTP lockout pair identity (ZTR-1210)", () => {
  const prevHops = process.env.TRUST_PROXY_HOPS;

  beforeEach(() => {
    _resetIpLockoutForTests();
    _resetLoginRateLimitForTests();
    delete process.env.TRUST_PROXY_HOPS;
  });

  afterEach(() => {
    _resetIpLockoutForTests();
    _resetLoginRateLimitForTests();
    if (prevHops === undefined) delete process.env.TRUST_PROXY_HOPS;
    else process.env.TRUST_PROXY_HOPS = prevHops;
  });

  it("both routes lock the same (socket IP, username) pair", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, { mustEnrolTotp: true });
    const { router } = buildRouter(userStore);

    // Trip lockout on login with the real socket peer.
    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) {
      const res = await router(
        "POST",
        "/admin/v1/login",
        Buffer.from(JSON.stringify({ username: USERNAME, password: "wrong-password-xx" })),
        { "content-type": "application/json", "x-forwarded-for": SPOOF_A },
        SOCKET,
      );
      expect(res.status).toBe(401);
    }
    expect(isIpPairLocked(SOCKET, USERNAME)).toBe(true);
    // Spoofed XFF identity must NOT be the lockout key when proxy trust is off.
    expect(isIpPairLocked(SPOOF_A, USERNAME)).toBe(false);

    // Obtain a session from a different IP so confirm-TOTP is reachable.
    const otherSocket = "198.51.100.10";
    const login = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: USERNAME, password: PASSWORD })),
      { "content-type": "application/json" },
      otherSocket,
    );
    expect(login.status).toBe(200);
    const cookie = cookieFrom(login.headers["set-cookie"]);
    const csrf = (JSON.parse(login.body) as { csrfToken: string }).csrfToken;

    const enrol = await router(
      "POST",
      "/admin/v1/enrol-totp",
      Buffer.from(JSON.stringify({ password: PASSWORD })),
      {
        "content-type": "application/json",
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
      },
      otherSocket,
    );
    expect(enrol.status).toBe(200);
    const secret = (JSON.parse(enrol.body) as { secret: string }).secret;

    // Confirm-TOTP from the locked socket must refuse even a correct code.
    // Varying XFF must not open a fresh pair.
    const lockedConfirm = await router(
      "POST",
      "/admin/v1/confirm-totp",
      Buffer.from(JSON.stringify({ totp: codeFor(secret) })),
      {
        "content-type": "application/json",
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "x-forwarded-for": SPOOF_B,
      },
      SOCKET,
    );
    expect(lockedConfirm.status).toBe(401);
    expect(isIpPairLocked(SOCKET, USERNAME)).toBe(true);
    expect(isIpPairLocked(SPOOF_B, USERNAME)).toBe(false);

    // Confirm-TOTP failures from the locked socket keep the same pair (no XFF key).
    // Use a fresh unlocked peer for failures-then-cross-check on the shared key.
    _resetIpLockoutForTests();
    _resetLoginRateLimitForTests();

    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) {
      const bad = await router(
        "POST",
        "/admin/v1/confirm-totp",
        Buffer.from(JSON.stringify({ totp: "000000" })),
        {
          "content-type": "application/json",
          cookie,
          "x-csrf-token": csrf,
          origin: "https://node.example",
          "x-forwarded-for": `${SPOOF_A}, ${SPOOF_B}`,
        },
        SOCKET,
      );
      expect(bad.status).toBe(401);
    }
    expect(isIpPairLocked(SOCKET, USERNAME)).toBe(true);
    expect(isIpPairLocked(SPOOF_A, USERNAME)).toBe(false);
    expect(isIpPairLocked(SPOOF_B, USERNAME)).toBe(false);

    // Login on the same socket sees the confirm-TOTP lockout.
    const loginBlocked = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: USERNAME, password: PASSWORD })),
      {
        "content-type": "application/json",
        "x-forwarded-for": SPOOF_A,
      },
      SOCKET,
    );
    expect(loginBlocked.status).toBe(401);
    expect(loginBlocked.headers["set-cookie"]).toBeUndefined();
  });

  it("XFF spoof does not reset login lockout when TRUST_PROXY_HOPS is unset", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, { mustEnrolTotp: false });
    const { router } = buildRouter(userStore);

    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) {
      const res = await router(
        "POST",
        "/admin/v1/login",
        Buffer.from(JSON.stringify({ username: USERNAME, password: "nope" })),
        { "content-type": "application/json", "x-forwarded-for": SPOOF_A },
        SOCKET,
      );
      expect(res.status).toBe(401);
    }

    // Same socket, different XFF — still locked (ZTR-1192 behaviour preserved).
    const still = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: USERNAME, password: PASSWORD })),
      { "content-type": "application/json", "x-forwarded-for": SPOOF_B },
      SOCKET,
    );
    expect(still.status).toBe(401);
    expect(isIpPairLocked(SOCKET, USERNAME)).toBe(true);
  });

  it("TRUST_PROXY_HOPS keys both routes on the trusted XFF hop", async () => {
    process.env.TRUST_PROXY_HOPS = "1";
    const client = "203.0.113.50";
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, { mustEnrolTotp: true });
    const { router } = buildRouter(userStore);

    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) {
      const res = await router(
        "POST",
        "/admin/v1/login",
        Buffer.from(JSON.stringify({ username: USERNAME, password: "wrong" })),
        {
          "content-type": "application/json",
          "x-forwarded-for": `${SPOOF_A}, ${client}`,
        },
        SOCKET,
      );
      expect(res.status).toBe(401);
    }
    expect(isIpPairLocked(client, USERNAME)).toBe(true);
    expect(isIpPairLocked(SOCKET, USERNAME)).toBe(false);

    // Session from a different client hop so we can hit confirm-TOTP.
    const otherClient = "203.0.113.60";
    const login = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: USERNAME, password: PASSWORD })),
      {
        "content-type": "application/json",
        "x-forwarded-for": otherClient,
      },
      SOCKET,
    );
    expect(login.status).toBe(200);
    const cookie = cookieFrom(login.headers["set-cookie"]);
    const csrf = (JSON.parse(login.body) as { csrfToken: string }).csrfToken;
    const enrol = await router(
      "POST",
      "/admin/v1/enrol-totp",
      Buffer.from(JSON.stringify({ password: PASSWORD })),
      {
        "content-type": "application/json",
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
      },
      SOCKET,
    );
    expect(enrol.status).toBe(200);
    const secret = (JSON.parse(enrol.body) as { secret: string }).secret;

    const lockedConfirm = await router(
      "POST",
      "/admin/v1/confirm-totp",
      Buffer.from(JSON.stringify({ totp: codeFor(secret) })),
      {
        "content-type": "application/json",
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "x-forwarded-for": `${SPOOF_B}, ${client}`,
      },
      SOCKET,
    );
    expect(lockedConfirm.status).toBe(401);
    expect(isIpPairLocked(client, USERNAME)).toBe(true);
  });
});
