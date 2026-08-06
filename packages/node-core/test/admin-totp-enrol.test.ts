/**
 * first-boot TOTP enrol + confirm HTTP path (Review B rework).
 *
 * AC: cold boot → login → password → enrol → confirm clears mustEnrolTotp;
 * X-ZP-TOTP then verifies the enrolled secret without ADMIN_TOTP_SECRET env.
 * Review B FAIL fixes:
 *   1. confirm burns code (cannot reuse on money)
 *   2. confirm lockout after repeated fails
 *   3. session rotate on activate
 *   4. factor survives reboot snapshot (durable store)
 */
import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  ADMIN_SESSION_COOKIE,
  DEFAULT_ADMIN_USERNAME,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  TotpConsumptionLog,
  _resetIpLockoutForTests,
  bootstrapInitialAdmin,
  createAdminSessionService,
  encodeBase32,
  handleAdminChangePassword,
  handleAdminConfirmTotp,
  handleAdminEnrolTotp,
  handleAdminLogin,
  handleAdminMe,
  resolveOperatorTotpConfig,
  runGuardedAdminMutation,
  totpSecretBytes,
  type AuthRequest,
  type TotpConfig,
  matchTotp,
} from "../src/http/index.js";
import {
  APPROVAL_CHALLENGE_FRESHNESS_MS,
  APPROVAL_PURPOSE,
  approveExternalSend,
  buildApprovalPreimage,
  toCanonicalTimestamp,
  type ApprovalOperationSnapshot,
} from "../src/send/approve.js";
import { InMemoryApprovalChallengeStore } from "../src/send/approval-store.js";
import { InMemoryDeviceKeyStore } from "../src/device/in-memory-store.js";

const NODE = "node-fixture";
const BOOT_PW = "correct-horse-battery-staple";
const NEW_PW = "new-correct-horse-battery";

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

function cookieHeader(setCookie: string): string {
  const m = new RegExp(`${ADMIN_SESSION_COOKIE}=([^;]+)`).exec(setCookie);
  if (m === null || m[1] === undefined) {
    throw new Error("missing session cookie");
  }
  return `${ADMIN_SESSION_COOKIE}=${m[1]}`;
}

function req(opts: {
  method?: string;
  path?: string;
  cookie?: string;
  csrf?: string;
  totp?: string;
}): AuthRequest {
  return {
    method: opts.method ?? "GET",
    path: opts.path ?? "/admin/v1/me",
    headers: {
      cookie: opts.cookie,
      "x-csrf-token": opts.csrf,
      "x-zp-totp": opts.totp,
      origin: "https://node.example",
    },
  };
}

describe("first-boot TOTP enrol → confirm", () => {
  beforeEach(() => {
    _resetIpLockoutForTests();
  });
  afterEach(() => {
    _resetIpLockoutForTests();
  });

  async function seeded() {
    const users = new InMemoryAdminUserStore();
    const sessionStore = new InMemoryAdminSessionStore();
    const sessions = createAdminSessionService({ nodeId: NODE }, sessionStore, users);
    const totpLog = new TotpConsumptionLog();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: BOOT_PW });
    return { users, sessions, sessionStore, totpLog };
  }

  it("AC path: login → password → enrol → confirm clears mustEnrolTotp; secret not in audit", async () => {
    const { users, sessions, totpLog } = await seeded();
    const audit: Array<{ eventType: string }> = [];

    const login = await handleAdminLogin(
      { userStore: users, sessions },
      { username: DEFAULT_ADMIN_USERNAME, password: BOOT_PW },
    );
    expect(login.status).toBe(200);
    const loginBody = login.body as {
      mustChangePassword: boolean;
      mustEnrolTotp: boolean;
      csrfToken: string;
    };
    expect(loginBody.mustChangePassword).toBe(true);
    expect(loginBody.mustEnrolTotp).toBe(true);
    let cookie = cookieHeader(login.headers["set-cookie"]!);
    let csrf = loginBody.csrfToken;

    const changed = await handleAdminChangePassword(
      { userStore: users, sessions },
      req({ method: "POST", path: "/admin/v1/password", cookie, csrf }),
      { current_password: BOOT_PW, new_password: NEW_PW },
    );
    expect(changed.status).toBe(200);
    cookie = cookieHeader(changed.headers["set-cookie"]!);
    csrf = (changed.body as { csrfToken: string }).csrfToken;

    const enrol = await handleAdminEnrolTotp(
      {
        userStore: users,
        sessions,
        audit: {
          record(e) {
            audit.push({ eventType: e.eventType });
          },
        },
      },
      req({ method: "POST", path: "/admin/v1/enrol-totp", cookie, csrf }),
      { password: NEW_PW },
    );
    expect(enrol.status).toBe(200);
    const enrolBody = enrol.body as { secret: string; otpauthUrl: string };
    expect(enrolBody.secret.length).toBeGreaterThanOrEqual(16);
    expect(enrolBody.otpauthUrl).toMatch(/^otpauth:\/\/totp\//);

    const meMid = await handleAdminMe(sessions, req({ cookie }));
    expect((meMid.body as { mustEnrolTotp: boolean }).mustEnrolTotp).toBe(true);

    const nowMs = Date.now();
    const code = codeFor(enrolBody.secret, nowMs);
    const confirm = await handleAdminConfirmTotp(
      {
        userStore: users,
        sessions,
        totpLog,
        nodeId: NODE,
        nowMs: () => nowMs,
        audit: {
          record(e) {
            audit.push({ eventType: e.eventType });
          },
        },
      },
      req({ method: "POST", path: "/admin/v1/confirm-totp", cookie, csrf }),
      { totp: code },
    );
    expect(confirm.status).toBe(200);
    expect((confirm.body as { mustEnrolTotp: boolean }).mustEnrolTotp).toBe(false);
    // Session rotate on activate — new cookie + csrf
    expect(confirm.headers["set-cookie"]).toBeDefined();
    cookie = cookieHeader(confirm.headers["set-cookie"]!);
    csrf = (confirm.body as { csrfToken: string }).csrfToken;
    expect(csrf.length).toBeGreaterThan(10);

    const me = await handleAdminMe(sessions, req({ cookie }));
    expect((me.body as { mustEnrolTotp: boolean }).mustEnrolTotp).toBe(false);
    const userId = (me.body as { userId: string }).userId;

    expect(audit.map((a) => a.eventType)).toEqual([
      "user.totp_enrol_started",
      "user.totp_enrolled",
    ]);
    for (const a of audit) {
      expect(JSON.stringify(a)).not.toContain(enrolBody.secret);
    }

    const cfg = await resolveOperatorTotpConfig(users, userId, null);
    expect(cfg).not.toBeNull();

    // Confirm burned the step — same code cannot open money.
    const replayMoney = await runGuardedAdminMutation({
      sessions,
      request: req({
        method: "POST",
        path: "/admin/v1/external-sends/x/reject",
        cookie,
        csrf,
        totp: code,
      }),
      csrf: { allowedOrigins: ["https://node.example"] },
      userStore: users,
      totp: null,
      totpLog,
      nodeId: NODE,
      nowMs,
      rawBody: { expected_row_version: 1, reason: "test" },
      validateBody: (raw) => ({ ok: true as const, body: raw }),
      mutate: async () => ({ ok: true }),
    });
    expect(replayMoney.ok).toBe(false);

    // Fresh code in a later step still works (window±1; bump clock by 60s)
    const laterMs = nowMs + 60_000;
    const fresh = codeFor(enrolBody.secret, laterMs);
    const g = await runGuardedAdminMutation({
      sessions,
      request: req({
        method: "POST",
        path: "/admin/v1/external-sends/x/reject",
        cookie,
        csrf,
        totp: fresh,
      }),
      csrf: { allowedOrigins: ["https://node.example"] },
      userStore: users,
      totp: null,
      totpLog,
      nodeId: NODE,
      nowMs: laterMs,
      rawBody: { expected_row_version: 1, reason: "test" },
      validateBody: (raw) => ({ ok: true as const, body: raw }),
      mutate: async () => ({ ok: true }),
    });
    expect(g.ok).toBe(true);
  });

  it("pre-confirm session cookie is revoked after activate", async () => {
    const { users, sessions, totpLog } = await seeded();
    const u0 = (await users.findByUsername(DEFAULT_ADMIN_USERNAME))!;
    await users.updatePassword(u0.id, u0.passwordHash, false);
    const login = await handleAdminLogin(
      { userStore: users, sessions },
      { username: DEFAULT_ADMIN_USERNAME, password: BOOT_PW },
    );
    const preCookie = cookieHeader(login.headers["set-cookie"]!);
    const csrf = (login.body as { csrfToken: string }).csrfToken;
    const enrol = await handleAdminEnrolTotp(
      { userStore: users, sessions },
      req({ method: "POST", path: "/admin/v1/enrol-totp", cookie: preCookie, csrf }),
      { password: BOOT_PW },
    );
    const secret = (enrol.body as { secret: string }).secret;
    const nowMs = Date.now();
    const confirm = await handleAdminConfirmTotp(
      { userStore: users, sessions, totpLog, nodeId: NODE, nowMs: () => nowMs },
      req({ method: "POST", path: "/admin/v1/confirm-totp", cookie: preCookie, csrf }),
      { totp: codeFor(secret, nowMs) },
    );
    expect(confirm.status).toBe(200);
    const staleMe = await handleAdminMe(sessions, req({ cookie: preCookie }));
    expect(staleMe.status).toBe(401);
    const newCookie = cookieHeader(confirm.headers["set-cookie"]!);
    const freshMe = await handleAdminMe(sessions, req({ cookie: newCookie }));
    expect(freshMe.status).toBe(200);
  });

  it("wrong confirm codes lock out after IP pair threshold", async () => {
    const { users, sessions, totpLog } = await seeded();
    const u0 = (await users.findByUsername(DEFAULT_ADMIN_USERNAME))!;
    await users.updatePassword(u0.id, u0.passwordHash, false);
    const login = await handleAdminLogin(
      { userStore: users, sessions },
      { username: DEFAULT_ADMIN_USERNAME, password: BOOT_PW },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    const csrf = (login.body as { csrfToken: string }).csrfToken;
    const enrol = await handleAdminEnrolTotp(
      { userStore: users, sessions },
      req({ method: "POST", path: "/admin/v1/enrol-totp", cookie, csrf }),
      { password: BOOT_PW },
    );
    expect(enrol.status).toBe(200);
    const secret = (enrol.body as { secret: string }).secret;

    for (let i = 0; i < 5; i++) {
      const bad = await handleAdminConfirmTotp(
        {
          userStore: users,
          sessions,
          totpLog,
          nodeId: NODE,
          ip: "203.0.113.50",
        },
        req({ method: "POST", path: "/admin/v1/confirm-totp", cookie, csrf }),
        { totp: "000000" },
      );
      expect(bad.status).toBe(401);
    }
    // 6th attempt still locked with same generic envelope
    const locked = await handleAdminConfirmTotp(
      {
        userStore: users,
        sessions,
        totpLog,
        nodeId: NODE,
        ip: "203.0.113.50",
        nowMs: () => Date.now(),
      },
      req({ method: "POST", path: "/admin/v1/confirm-totp", cookie, csrf }),
      { totp: codeFor(secret) },
    );
    expect(locked.status).toBe(401);
    expect((locked.body as { error: { code: string } }).error.code).toBe("totp_invalid");
    // Still pending — lockout does not clear or activate
    const admin = (await users.findByUsername(DEFAULT_ADMIN_USERNAME))!;
    expect(admin.mustEnrolTotp).toBe(true);
    expect((await users.getTotpFactor(admin.id)).status).toBe("pending");
  });

  it("wrong confirm code refuses; pending stays; mustEnrolTotp remains", async () => {
    const { users, sessions, totpLog } = await seeded();
    const u0 = (await users.findByUsername(DEFAULT_ADMIN_USERNAME))!;
    await users.updatePassword(u0.id, u0.passwordHash, false);
    const login = await handleAdminLogin(
      { userStore: users, sessions },
      { username: DEFAULT_ADMIN_USERNAME, password: BOOT_PW },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    const csrf = (login.body as { csrfToken: string }).csrfToken;

    const enrol = await handleAdminEnrolTotp(
      { userStore: users, sessions },
      req({ method: "POST", path: "/admin/v1/enrol-totp", cookie, csrf }),
      { password: BOOT_PW },
    );
    expect(enrol.status).toBe(200);
    const secret = (enrol.body as { secret: string }).secret;

    const bad = await handleAdminConfirmTotp(
      { userStore: users, sessions, totpLog, nodeId: NODE, ip: "198.51.100.1" },
      req({ method: "POST", path: "/admin/v1/confirm-totp", cookie, csrf }),
      { totp: "000000" },
    );
    expect(bad.status).toBe(401);
    expect((bad.body as { error: { code: string } }).error.code).toBe("totp_invalid");

    const admin = (await users.findByUsername(DEFAULT_ADMIN_USERNAME))!;
    const factor = await users.getTotpFactor(admin.id);
    expect(factor.status).toBe("pending");
    if (factor.status === "pending") {
      expect(factor.secretBase32).toBe(secret);
    }
    expect(admin.mustEnrolTotp).toBe(true);
  });

  it("money gate refuses while mustEnrolTotp before confirm", async () => {
    const { users, sessions } = await seeded();
    const u = (await users.findByUsername(DEFAULT_ADMIN_USERNAME))!;
    await users.updatePassword(u.id, u.passwordHash, false);
    const login = await handleAdminLogin(
      { userStore: users, sessions },
      { username: DEFAULT_ADMIN_USERNAME, password: BOOT_PW },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    const csrf = (login.body as { csrfToken: string }).csrfToken;
    const g = await runGuardedAdminMutation({
      sessions,
      request: req({
        method: "POST",
        path: "/admin/v1/x",
        cookie,
        csrf,
        totp: "123456",
      }),
      csrf: { allowedOrigins: ["https://node.example"] },
      userStore: users,
      totpLog: new TotpConsumptionLog(),
      nodeId: NODE,
      rawBody: {},
      validateBody: () => ({ ok: true as const, body: {} }),
      mutate: async () => ({ ok: true }),
    });
    expect(g.ok).toBe(false);
    if (!g.ok) {
      expect(g.code).toBe("totp_required");
      expect(g.reason).toBe("totp_enrolment_required");
    }
  });

  it("factor rehydrates after simulated reboot; money still resolves", async () => {
    const { users, sessions, totpLog } = await seeded();
    const u0 = (await users.findByUsername(DEFAULT_ADMIN_USERNAME))!;
    await users.updatePassword(u0.id, u0.passwordHash, false);
    const login = await handleAdminLogin(
      { userStore: users, sessions },
      { username: DEFAULT_ADMIN_USERNAME, password: BOOT_PW },
    );
    let cookie = cookieHeader(login.headers["set-cookie"]!);
    let csrf = (login.body as { csrfToken: string }).csrfToken;
    const enrol = await handleAdminEnrolTotp(
      { userStore: users, sessions },
      req({ method: "POST", path: "/admin/v1/enrol-totp", cookie, csrf }),
      { password: BOOT_PW },
    );
    const secret = (enrol.body as { secret: string }).secret;
    const nowMs = Date.now();
    const confirm = await handleAdminConfirmTotp(
      { userStore: users, sessions, totpLog, nodeId: NODE, nowMs: () => nowMs },
      req({ method: "POST", path: "/admin/v1/confirm-totp", cookie, csrf }),
      { totp: codeFor(secret, nowMs) },
    );
    expect(confirm.status).toBe(200);

    // Simulate process restart: new stores, hydrate user+factor snapshot
    const snap = users.snapshot();
    const users2 = new InMemoryAdminUserStore();
    users2.hydrate(snap);
    const sessions2 = createAdminSessionService(
      { nodeId: NODE },
      new InMemoryAdminSessionStore(),
      users2,
    );
    const login2 = await handleAdminLogin(
      { userStore: users2, sessions: sessions2 },
      { username: DEFAULT_ADMIN_USERNAME, password: BOOT_PW },
    );
    expect(login2.status).toBe(200);
    expect((login2.body as { mustEnrolTotp: boolean }).mustEnrolTotp).toBe(false);
    cookie = cookieHeader(login2.headers["set-cookie"]!);
    csrf = (login2.body as { csrfToken: string }).csrfToken;

    const laterMs = nowMs + 90_000;
    const g = await runGuardedAdminMutation({
      sessions: sessions2,
      request: req({
        method: "POST",
        path: "/admin/v1/x",
        cookie,
        csrf,
        totp: codeFor(secret, laterMs),
      }),
      csrf: { allowedOrigins: ["https://node.example"] },
      userStore: users2,
      totpLog: new TotpConsumptionLog(),
      nodeId: NODE,
      nowMs: laterMs,
      rawBody: {},
      validateBody: () => ({ ok: true as const, body: {} }),
      mutate: async () => ({ ok: true }),
    });
    expect(g.ok).toBe(true);

    // Wipe without hydrate → money fail-closed even if mustEnrol falsified
    const wiped = new InMemoryAdminUserStore();
    wiped.hydrate({
      users: snap.users.map((u) => ({ ...u, mustEnrolTotp: false })),
      factors: [],
    });
    const sessions3 = createAdminSessionService(
      { nodeId: NODE },
      new InMemoryAdminSessionStore(),
      wiped,
    );
    const login3 = await handleAdminLogin(
      { userStore: wiped, sessions: sessions3 },
      { username: DEFAULT_ADMIN_USERNAME, password: BOOT_PW },
    );
    cookie = cookieHeader(login3.headers["set-cookie"]!);
    csrf = (login3.body as { csrfToken: string }).csrfToken;
    const closed = await runGuardedAdminMutation({
      sessions: sessions3,
      request: req({
        method: "POST",
        path: "/admin/v1/x",
        cookie,
        csrf,
        totp: codeFor(secret, laterMs + 30_000),
      }),
      csrf: { allowedOrigins: ["https://node.example"] },
      userStore: wiped,
      totpLog: new TotpConsumptionLog(),
      nodeId: NODE,
      nowMs: laterMs + 30_000,
      rawBody: {},
      validateBody: () => ({ ok: true as const, body: {} }),
      mutate: async () => ({ ok: true }),
    });
    expect(closed.ok).toBe(false);
    if (!closed.ok) expect(closed.code).toBe("totp_required");
  });

  it("rejects re-enrol once active", async () => {
    const { users, sessions } = await seeded();
    const u = (await users.findByUsername(DEFAULT_ADMIN_USERNAME))!;
    await users.updatePassword(u.id, u.passwordHash, false);
    await users.setActiveTotpSecret(u.id, encodeBase32(Buffer.alloc(20, 9)));

    const login = await handleAdminLogin(
      { userStore: users, sessions },
      { username: DEFAULT_ADMIN_USERNAME, password: BOOT_PW },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    const csrf = (login.body as { csrfToken: string }).csrfToken;
    const enrol = await handleAdminEnrolTotp(
      { userStore: users, sessions },
      req({ method: "POST", path: "/admin/v1/enrol-totp", cookie, csrf }),
      { password: BOOT_PW },
    );
    expect(enrol.status).toBe(400);
    expect((enrol.body as { error: { message: string } }).error.message).toMatch(
      /already enrolled/i,
    );
  });

  it("base32 secret round-trips through matchTotp", () => {
    const secret = encodeBase32(Buffer.alloc(20, 3));
    const bytes = totpSecretBytes(secret)!;
    const nowMs = 1_700_000_000_000;
    const step = Math.floor(nowMs / 1000 / 30);
    const code = hotp(bytes, step);
    const cfg: TotpConfig = { secret: bytes, windowSteps: 1 };
    expect(matchTotp(cfg, { code, nowMs })).toEqual({ ok: true, timestep: step });
  });

  it("confirm-burned step S rejects SEND approve with same step (shared burn registry)", async () => {
    // Residual FAIL#2: approve used matchTotp + operation_approvals only — process
    // TotpConsumptionLog did not block money. Shared TotpBurnStore closes the hop.
    // nodeId must be a UUID (approval preimage parseUuid) and identical on confirm/approve.
    const nodeId = "11111111-1111-4111-8111-111111111111";
    const users = new InMemoryAdminUserStore();
    const sessionStore = new InMemoryAdminSessionStore();
    const sessions = createAdminSessionService({ nodeId }, sessionStore, users);
    const totpLog = new TotpConsumptionLog();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: BOOT_PW });
    const u0 = (await users.findByUsername(DEFAULT_ADMIN_USERNAME))!;
    await users.updatePassword(u0.id, u0.passwordHash, false);

    const login = await handleAdminLogin(
      { userStore: users, sessions },
      { username: DEFAULT_ADMIN_USERNAME, password: BOOT_PW },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    const csrf = (login.body as { csrfToken: string }).csrfToken;

    const enrol = await handleAdminEnrolTotp(
      { userStore: users, sessions },
      req({ method: "POST", path: "/admin/v1/enrol-totp", cookie, csrf }),
      { password: BOOT_PW },
    );
    expect(enrol.status).toBe(200);
    const secretBase32 = (enrol.body as { secret: string }).secret;
    const secretBytes = totpSecretBytes(secretBase32)!;

    const nowMs = 1_700_000_000_000;
    const stepS = Math.floor(nowMs / 1000 / 30);
    const codeS = codeFor(secretBase32, nowMs);

    const confirm = await handleAdminConfirmTotp(
      { userStore: users, sessions, totpLog, nodeId, nowMs: () => nowMs },
      req({ method: "POST", path: "/admin/v1/confirm-totp", cookie, csrf }),
      { totp: codeS },
    );
    expect(confirm.status).toBe(200);
    expect(totpLog.isConsumed(nodeId, stepS)).toBe(true);

    // Prove matchTotp alone still accepts (the bug path) — burn gate must block approve.
    expect(matchTotp({ secret: secretBytes, windowSteps: 1 }, { code: codeS, nowMs })).toEqual({
      ok: true,
      timestep: stepS,
    });

    const opId = "33333333-3333-4333-8333-333333333333";
    const walletId = "55555555-5555-4555-8555-555555555555";
    const nonce = "99999999-9999-4999-8999-999999999999";
    const sourcePub = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
    const dest = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
    const op: ApprovalOperationSnapshot = {
      operationId: opId,
      nodeId,
      status: "CREATED",
      rowVersion: 1,
      sourceWalletId: walletId,
      sourcePubkey: sourcePub,
      destinationAddress: dest,
      amountZkz: "0.01",
      referencesOperationId: null,
    };
    const store = new InMemoryApprovalChallengeStore();
    store.seedOperation(op.operationId, op.status, op.rowVersion);
    const issuedAt = toCanonicalTimestamp(nowMs);
    const expiresAt = toCanonicalTimestamp(nowMs + APPROVAL_CHALLENGE_FRESHNESS_MS);
    const preimage = buildApprovalPreimage({
      nodeId: op.nodeId,
      operationId: op.operationId,
      sourceWalletId: op.sourceWalletId,
      sourcePubkey: op.sourcePubkey,
      destinationAddress: op.destinationAddress,
      amountZkz: op.amountZkz,
      referencesOperationId: op.referencesOperationId,
      nonce,
      issuedAt,
      expiresAt,
    });
    await store.insertIssued(
      {
        id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        nodeId: op.nodeId,
        operationId: op.operationId,
        status: "ISSUED",
        purpose: APPROVAL_PURPOSE,
        canonicalVersion: 1,
        nonce,
        preimageText: preimage.preimageText,
        preimageSha256: preimage.preimageSha256,
        issuedAt,
        expiresAt,
        supersededBy: null,
      },
      null,
    );

    const hop = await approveExternalSend(
      {
        operationId: opId,
        challengeNonce: nonce,
        expectedRowVersion: 1,
        preimageSha256: preimage.preimageSha256,
        deviceKeyId: null,
        deviceSignature: null,
        totpCode: codeS,
      },
      {
        challengeStore: store,
        loadOperation: async () => op,
        deviceStore: new InMemoryDeviceKeyStore(),
        totpConfig: { secret: secretBytes, windowSteps: 1 },
        totpBurnStore: totpLog,
        requireDeviceSignature: false,
        nowMs: () => nowMs,
      },
    );
    expect(hop).toEqual({ outcome: "REJECTED", reason: "totp_replay" });
    // Challenge untouched — no CAS applied.
    expect((await store.findByNonce(nonce))?.status).toBe("ISSUED");

    // Next-step code still authorises money after confirm burned S.
    const laterMs = nowMs + 60_000;
    const fresh = codeFor(secretBase32, laterMs);
    const okMoney = await runGuardedAdminMutation({
      sessions,
      request: req({
        method: "POST",
        path: "/admin/v1/external-sends/x/reject",
        cookie: cookieHeader(confirm.headers["set-cookie"]!),
        csrf: (confirm.body as { csrfToken: string }).csrfToken,
        totp: fresh,
      }),
      csrf: { allowedOrigins: ["https://node.example"] },
      userStore: users,
      totp: null,
      totpLog,
      nodeId,
      nowMs: laterMs,
      rawBody: { expected_row_version: 1, reason: "test" },
      validateBody: (raw) => ({ ok: true as const, body: raw }),
      mutate: async () => ({ ok: true }),
    });
    expect(okMoney.ok).toBe(true);
  });
});
