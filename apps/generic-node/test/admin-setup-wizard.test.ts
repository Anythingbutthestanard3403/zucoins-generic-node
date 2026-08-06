// HTTP surface: setup-state + vault-master show-once.

import {
  ADMIN_SESSION_COOKIE,
  createAdminSessionService,
  createFailClosedDestinationService,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  type AdminUser,
} from "@zucoins/node-core";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { createAdminRouter, createFailClosedAdminRouteDeps } from "../src/admin-router.js";
import { createMemorySetupStateStore } from "../src/setup-state-store.js";
import { createVirginVaultMasterState } from "../src/setup-vault-master.js";

afterEach(() => {
  delete process.env.SETUP_ACK_WIZARD_LEGACY;
});

const NODE_ID = "11111111-1111-4111-8111-111111111111";

async function seedAdmin(
  store: InMemoryAdminUserStore,
  password: string,
  opts: { mustChangePassword?: boolean; mustEnrolTotp?: boolean } = {},
): Promise<AdminUser> {
  const user: AdminUser = {
    id: randomUUID(),
    username: "admin",
    passwordHash: await hashPassword(password),
    role: "admin",
    mustChangePassword: opts.mustChangePassword ?? false,
    mustEnrolTotp: opts.mustEnrolTotp ?? false,
    disabledAt: null,
    createdAt: Date.now(),
  };
  await store.insert(user);
  if (!user.mustEnrolTotp) {
    await store.setActiveTotpSecret(user.id, "JBSWY3DPEHPK3PXP");
  }
  return user;
}

function build(opts: {
  userStore: InMemoryAdminUserStore;
  setupSignals?: () => {
    recoveryVerifiedEligibleCount?: number;
    reportingKeyActive?: boolean;
    deviceEnrolled?: boolean;
    pwaInstalled?: boolean;
    vaultConfigured?: boolean;
  };
  backupMasterKey?: string;
}) {
  const sessionStore = new InMemoryAdminSessionStore();
  const sessions = createAdminSessionService({ nodeId: NODE_ID }, sessionStore, opts.userStore);
  const vaultMasterBootstrap = createVirginVaultMasterState();
  const setupStateStore = createMemorySetupStateStore();
  const deps = createFailClosedAdminRouteDeps({
    sessions,
    userStore: opts.userStore,
    csrf: { allowedOrigins: ["https://node.example"] },
    totp: { secret: new Uint8Array(32), windowSteps: 1 },
    nodeId: NODE_ID,
    destinationService: createFailClosedDestinationService(),
    newRequestId: () => randomUUID(),
    setupStateStore,
    vaultMasterBootstrap,
    backupMasterKey: opts.backupMasterKey ?? "backup-kek-different-from-vault-32xx",
    setupSignals: opts.setupSignals,
  });
  return {
    router: createAdminRouter(deps),
    vaultMasterBootstrap,
    setupStateStore,
  };
}

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  return setCookie.split(";")[0] ?? "";
}

async function login(router: ReturnType<typeof createAdminRouter>, password: string) {
  const res = await router(
    "POST",
    "/admin/v1/login",
    Buffer.from(JSON.stringify({ username: "admin", password })),
    { "content-type": "application/json", origin: "https://node.example" },
  );
  expect(res.status).toBe(200);
  const body = JSON.parse(res.body) as { csrfToken: string };
  return {
    cookie: cookieFrom(res.headers["set-cookie"]),
    csrf: body.csrfToken,
  };
}

describe("admin setup-state + vault-master HTTP", () => {
  it("GET setup-state resumes W0 for fresh flags; reachable mid password change", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-long", {
      mustChangePassword: true,
      mustEnrolTotp: true,
    });
    const { router } = build({ userStore });
    const { cookie } = await login(router, "bootstrap-secret-long");
    const res = await router("GET", "/admin/v1/setup-state", new Uint8Array(), {
      cookie,
      origin: "https://node.example",
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      object: string;
      current_step: string;
      complete: boolean;
      ceremony_master_key_blocked: boolean;
      password_ok: boolean;
      totp_ok: boolean;
      pwa_installed: boolean;
      device_enrolled: boolean;
      vault_ready: boolean;
      recovery_proven: boolean;
      next_step: string;
    };
    expect(body.object).toBe("setup_state");
    expect(body.current_step).toBe("W0");
    expect(body.complete).toBe(false);
    expect(body.ceremony_master_key_blocked).toBe(true);
    // Day-0 fact board
    expect(body.password_ok).toBe(false);
    expect(body.totp_ok).toBe(false);
    expect(body.pwa_installed).toBe(false);
    expect(body.device_enrolled).toBe(false);
    expect(body.vault_ready).toBe(false);
    expect(body.recovery_proven).toBe(false);
    expect(body.next_step).toBe("password");
    // No secret-bearing field names or high-entropy key material (prose may say "password").
    expect(res.body).not.toMatch(/"master_key"\s*:/);
    expect(res.body).not.toMatch(/"password"\s*:/);
    expect(res.body).not.toMatch(/"secret"\s*:/);
  });

  it("PATCH accepts W0; production no-ops hollow PWA skip; durable evidence advances", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-long2");
    const { router } = build({ userStore });
    const { cookie, csrf } = await login(router, "bootstrap-secret-long2");

    const w0 = await router(
      "PATCH",
      "/admin/v1/setup-state",
      Buffer.from(JSON.stringify({ w0_secure_context_ok: true })),
      {
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "content-type": "application/json",
      },
    );
    expect(w0.status).toBe(200);
    expect(JSON.parse(w0.body).current_step).toBe("W3");
    expect(JSON.parse(w0.body).pwa_installed).toBe(false);
    expect(JSON.parse(w0.body).next_step).toBe("install");
    expect(JSON.parse(w0.body).password_ok).toBe(true);
    expect(JSON.parse(w0.body).totp_ok).toBe(true);

    // w3_pwa_skipped is stripped — step stays W3, flag stays false.
    const hollow = await router(
      "PATCH",
      "/admin/v1/setup-state",
      Buffer.from(JSON.stringify({ w3_pwa_skipped: true })),
      {
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "content-type": "application/json",
      },
    );
    expect(hollow.status).toBe(200);
    const hollowBody = JSON.parse(hollow.body) as {
      current_step: string;
      complete: boolean;
      flags: { w3_pwa_skipped: boolean };
      pwa_installed: boolean;
    };
    expect(hollowBody.current_step).toBe("W3");
    expect(hollowBody.complete).toBe(false);
    expect(hollowBody.flags.w3_pwa_skipped).toBe(false);
    expect(hollowBody.pwa_installed).toBe(false);

    // Reject ack body on pwa-installed.
    const ackReject = await router(
      "POST",
      "/admin/v1/setup/pwa-installed",
      Buffer.from(JSON.stringify({ ack: true })),
      {
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "content-type": "application/json",
      },
    );
    expect(ackReject.status).toBe(400);

    const w3 = await router(
      "POST",
      "/admin/v1/setup/pwa-installed",
      Buffer.from(JSON.stringify({ evidence: "standalone" })),
      {
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "content-type": "application/json",
      },
    );
    expect(w3.status).toBe(200);
    const w3Body = JSON.parse(w3.body) as {
      current_step: string;
      pwa_installed: boolean;
      flags: { pwa_installed_at: string | null; pwa_install_evidence: string | null };
    };
    expect(w3Body.pwa_installed).toBe(true);
    expect(w3Body.flags.pwa_install_evidence).toBe("standalone");
    expect(w3Body.flags.pwa_installed_at).toBeTruthy();
    expect(w3Body.current_step).toBe("W4");
  });

  it("pwa-installed requires session CSRF and rejects bad enum", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-pwa-csrf");
    const { router } = build({ userStore });
    const { cookie, csrf } = await login(router, "bootstrap-pwa-csrf");

    const noCsrf = await router(
      "POST",
      "/admin/v1/setup/pwa-installed",
      Buffer.from(JSON.stringify({ evidence: "standalone" })),
      {
        cookie,
        origin: "https://node.example",
        "content-type": "application/json",
      },
    );
    expect(noCsrf.status).toBe(401);

    const badEnum = await router(
      "POST",
      "/admin/v1/setup/pwa-installed",
      Buffer.from(JSON.stringify({ evidence: "pinky-promise" })),
      {
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "content-type": "application/json",
      },
    );
    expect(badEnum.status).toBe(400);
  });


  it("rejects master_key on PATCH (ceremony blocked)", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-long3");
    const { router } = build({ userStore });
    const { cookie, csrf } = await login(router, "bootstrap-secret-long3");
    const res = await router(
      "PATCH",
      "/admin/v1/setup-state",
      Buffer.from(JSON.stringify({ master_key: "x".repeat(40) })),
      {
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(422);
    expect(JSON.parse(res.body).error.code).toBe("operation_not_armable");
  });

  it("vault master generate show-once; second GET has no key; ack seals", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-long4");
    const { router, vaultMasterBootstrap } = build({ userStore });
    const { cookie, csrf } = await login(router, "bootstrap-secret-long4");

    const gen = await router(
      "POST",
      "/admin/v1/vault-master/generate",
      Buffer.from("{}"),
      {
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "content-type": "application/json",
      },
    );
    expect(gen.status).toBe(200);
    const genBody = JSON.parse(gen.body) as { master_key: string; phase: string };
    expect(genBody.master_key.length).toBeGreaterThanOrEqual(32);
    expect(genBody.phase).toBe("shown");

    // Status GET — no key
    const st = await router("GET", "/admin/v1/vault-master", new Uint8Array(), {
      cookie,
      origin: "https://node.example",
    });
    expect(st.status).toBe(200);
    expect(st.body).not.toContain(genBody.master_key);
    expect(JSON.parse(st.body).plaintext_pending_ack).toBe(true);

    // Second generate refused
    const gen2 = await router(
      "POST",
      "/admin/v1/vault-master/generate",
      Buffer.from("{}"),
      {
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "content-type": "application/json",
      },
    );
    expect(gen2.status).toBe(409);

    // Ack offline
    const ack = await router(
      "POST",
      "/admin/v1/vault-master/ack-offline",
      Buffer.from(JSON.stringify({ offline_backup_ack: true })),
      {
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "content-type": "application/json",
      },
    );
    expect(ack.status).toBe(200);
    expect(JSON.parse(ack.body).phase).toBe("sealed");
    expect(vaultMasterBootstrap.pendingPlaintext).toBeNull();
    expect(JSON.stringify(vaultMasterBootstrap)).not.toContain(genBody.master_key);

    // setup-state reflects W5
    const setup = await router("GET", "/admin/v1/setup-state", new Uint8Array(), {
      cookie,
      origin: "https://node.example",
    });
    const flags = JSON.parse(setup.body).flags as {
      w5_vault_ready: boolean;
      w5_offline_backup_ack: boolean;
    };
    expect(flags.w5_vault_ready).toBe(true);
    expect(flags.w5_offline_backup_ack).toBe(true);
  });

  it("ack without prior generate is 409", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-long5");
    const { router } = build({ userStore });
    const { cookie, csrf } = await login(router, "bootstrap-secret-long5");
    const ack = await router(
      "POST",
      "/admin/v1/vault-master/ack-offline",
      Buffer.from(JSON.stringify({ offline_backup_ack: true })),
      {
        cookie,
        "x-csrf-token": csrf,
        origin: "https://node.example",
        "content-type": "application/json",
      },
    );
    expect(ack.status).toBe(409);
  });

  it("ack-only PATCH leaves complete false", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-long6");
    const { router } = build({
      userStore,
      setupSignals: () => ({
        // Intentionally no pwaInstalled / deviceEnrolled / recovery count.
        reportingKeyActive: true,
      }),
    });
    const { cookie, csrf } = await login(router, "bootstrap-secret-long6");
    const hdr = {
      cookie,
      "x-csrf-token": csrf,
      origin: "https://node.example",
      "content-type": "application/json",
    };
    const patch = async (body: Record<string, boolean>) => {
      const r = await router("PATCH", "/admin/v1/setup-state", Buffer.from(JSON.stringify(body)), hdr);
      expect(r.status).toBe(200);
      return JSON.parse(r.body) as {
        current_step: string;
        complete: boolean;
        flags: Record<string, boolean | string | null>;
      };
    };

    await patch({ w0_secure_context_ok: true });
    // Hollow PWA/ceremony/recovery acks no-op under production (200, flags unchanged).
    const v = await patch({
      w3_pwa_ack: true,
      w3_pwa_skipped: true,
      w6_ceremony_placeholder_ack: true,
      w7_recovery_wallet_ok: true,
    });
    expect(v.complete).toBe(false);
    expect(v.flags.w3_pwa_ack).toBe(false);
    expect(v.flags.w4_break_glass_ack).toBe(false);
    expect(v.flags.w6_ceremony_placeholder_ack).toBe(false);
    expect(v.flags.w7_recovery_wallet_ok).toBe(false);

    // Quiet w4_* client acks are refused with conflict.
    const quietW4 = await router(
      "PATCH",
      "/admin/v1/setup-state",
      Buffer.from(JSON.stringify({ w4_break_glass_ack: true, w4_device_enrolled: true })),
      hdr,
    );
    expect(quietW4.status).toBe(409);
    // Optional skips still require verified W7 — cannot leapfrog via PATCH.
    const leap = await router(
      "PATCH",
      "/admin/v1/setup-state",
      Buffer.from(JSON.stringify({ w8_implementer_skipped: true })),
      hdr,
    );
    expect(leap.status).toBe(409);

    // Vault seal still works but cannot alone complete.
    await router("POST", "/admin/v1/vault-master/generate", Buffer.from("{}"), hdr);
    await router(
      "POST",
      "/admin/v1/vault-master/ack-offline",
      Buffer.from(JSON.stringify({ offline_backup_ack: true })),
      hdr,
    );
    const setup = await router("GET", "/admin/v1/setup-state", new Uint8Array(), {
      cookie,
      origin: "https://node.example",
    });
    expect(JSON.parse(setup.body).complete).toBe(false);
  });

  it("complete when live verified facts + optional flags (not ack booleans)", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-long7");
    const { router } = build({
      userStore,
      setupSignals: () => ({
        pwaInstalled: true,
        deviceEnrolled: true,
        vaultConfigured: true,
        recoveryVerifiedEligibleCount: 2,
        reportingKeyActive: true,
      }),
    });
    const { cookie, csrf } = await login(router, "bootstrap-secret-long7");
    const hdr = {
      cookie,
      "x-csrf-token": csrf,
      origin: "https://node.example",
      "content-type": "application/json",
    };
    const patch = async (body: Record<string, boolean>) => {
      const r = await router("PATCH", "/admin/v1/setup-state", Buffer.from(JSON.stringify(body)), hdr);
      expect(r.status).toBe(200);
      return JSON.parse(r.body) as { current_step: string; complete: boolean };
    };

    await patch({ w0_secure_context_ok: true });
    await router("POST", "/admin/v1/vault-master/generate", Buffer.from("{}"), hdr);
    await router(
      "POST",
      "/admin/v1/vault-master/ack-offline",
      Buffer.from(JSON.stringify({ offline_backup_ack: true })),
      hdr,
    );
    // Day-0 complete after verified facts — W8–W11 optional hollow steps not required.
    const done = await router("GET", "/admin/v1/setup-state", new Uint8Array(), {
      cookie: hdr.cookie,
      origin: hdr.origin,
    });
    expect(done.status).toBe(200);
    const v = JSON.parse(done.body) as {
      current_step: string;
      complete: boolean;
      next_step: string;
      recovery_proven: boolean;
    };
    expect(v.complete).toBe(true);
    expect(v.current_step).toBe("W12");
    expect(v.next_step).toBe("home");
    expect(v.recovery_proven).toBe(true);
  });


  it("typed BREAK GLASS advances W4; quiet PATCH refused", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-long6b");
    const { router } = build({
      userStore,
      setupSignals: () => ({
        pwaInstalled: true,
        recoveryVerifiedEligibleCount: 2,
        reportingKeyActive: true,
      }),
    });
    const { cookie, csrf } = await login(router, "bootstrap-secret-long6b");
    const hdr = {
      cookie,
      "x-csrf-token": csrf,
      origin: "https://node.example",
      "content-type": "application/json",
    };
    const patch = async (body: Record<string, boolean>) => {
      const r = await router("PATCH", "/admin/v1/setup-state", Buffer.from(JSON.stringify(body)), hdr);
      expect(r.status).toBe(200);
      return JSON.parse(r.body) as { current_step: string; complete: boolean };
    };

    await patch({ w0_secure_context_ok: true });

    const quietBg = await router(
      "PATCH",
      "/admin/v1/setup-state",
      Buffer.from(JSON.stringify({ w4_break_glass_ack: true })),
      hdr,
    );
    expect(quietBg.status).toBe(409);

    const bg = await router(
      "POST",
      "/admin/v1/setup-state/device-break-glass",
      Buffer.from(JSON.stringify({ phrase: "BREAK GLASS" })),
      hdr,
    );
    expect(bg.status).toBe(200);
    const bgBody = JSON.parse(bg.body) as {
      current_step: string;
      device_break_glass_active: boolean;
      flags: { w4_break_glass_ack: boolean };
    };
    expect(bgBody.flags.w4_break_glass_ack).toBe(true);
    expect(bgBody.device_break_glass_active).toBe(true);
    expect(bgBody.current_step).toBe("W5");

    const bad = await router(
      "POST",
      "/admin/v1/setup-state/device-break-glass",
      Buffer.from(JSON.stringify({ phrase: "break glass" })),
      hdr,
    );
    expect([400, 409]).toContain(bad.status);

    await router("POST", "/admin/v1/vault-master/generate", Buffer.from("{}"), hdr);
    await router(
      "POST",
      "/admin/v1/vault-master/ack-offline",
      Buffer.from(JSON.stringify({ offline_backup_ack: true })),
      hdr,
    );
    const done = await router("GET", "/admin/v1/setup-state", new Uint8Array(), {
      cookie: hdr.cookie,
      origin: hdr.origin,
    });
    expect(done.status).toBe(200);
    const v = JSON.parse(done.body) as {
      current_step: string;
      complete: boolean;
      next_step: string;
      recovery_proven: boolean;
      device_break_glass_active: boolean;
    };
    expect(v.complete).toBe(true);
    expect(v.current_step).toBe("W12");
    expect(v.next_step).toBe("home");
    expect(v.recovery_proven).toBe(true);
    expect(v.device_break_glass_active).toBe(true);
  });

  it("W4 advances when device store reports active key", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-device9");
    const { router } = build({
      userStore,
      setupSignals: () => ({
        pwaInstalled: true,
        deviceEnrolled: true,
        recoveryVerifiedEligibleCount: 0,
      }),
    });
    const { cookie, csrf } = await login(router, "bootstrap-secret-device9");
    const hdr = {
      cookie,
      "x-csrf-token": csrf,
      origin: "https://node.example",
      "content-type": "application/json",
    };
    await router(
      "PATCH",
      "/admin/v1/setup-state",
      Buffer.from(JSON.stringify({ w0_secure_context_ok: true })),
      hdr,
    );
    const get = await router("GET", "/admin/v1/setup-state", new Uint8Array(), {
      cookie,
      origin: "https://node.example",
    });
    expect(get.status).toBe(200);
    const body = JSON.parse(get.body) as {
      current_step: string;
      device_break_glass_active: boolean;
    };
    expect(body.current_step).toBe("W5");
    expect(body.device_break_glass_active).toBe(false);
  });

  it("legacy SETUP_ACK_WIZARD_LEGACY=1 restores ack complete path", async () => {
    process.env.SETUP_ACK_WIZARD_LEGACY = "1";
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-secret-long8");
    const { router } = build({
      userStore,
      setupSignals: () => ({
        recoveryVerifiedEligibleCount: 2,
        reportingKeyActive: true,
      }),
    });
    const { cookie, csrf } = await login(router, "bootstrap-secret-long8");
    const hdr = {
      cookie,
      "x-csrf-token": csrf,
      origin: "https://node.example",
      "content-type": "application/json",
    };
    const patch = async (body: Record<string, boolean>) => {
      const r = await router("PATCH", "/admin/v1/setup-state", Buffer.from(JSON.stringify(body)), hdr);
      expect(r.status).toBe(200);
      return JSON.parse(r.body) as { current_step: string; complete: boolean };
    };

    await patch({ w0_secure_context_ok: true });
    await patch({ w3_pwa_skipped: true });
    await patch({ w4_break_glass_ack: true });
    await router("POST", "/admin/v1/vault-master/generate", Buffer.from("{}"), hdr);
    await router(
      "POST",
      "/admin/v1/vault-master/ack-offline",
      Buffer.from(JSON.stringify({ offline_backup_ack: true })),
      hdr,
    );
    await patch({ w6_ceremony_placeholder_ack: true });
    let v = await patch({ w8_implementer_skipped: true });
    v = await patch({ w10_packs_skipped: true });
    v = await patch({ w11_mini_steps_skipped: true });
    expect(v.complete).toBe(true);
    expect(v.current_step).toBe("W12");
    expect((v as { next_step?: string }).next_step).toBe("home");
    expect((v as { recovery_proven?: boolean }).recovery_proven).toBe(true);
  });
});

// silence unused import warning if cookie constant used for docs only
void ADMIN_SESSION_COOKIE;

describe("durable setup_state + vault seal across restart", () => {
  it("setup_state resumes from shared store after router rebuild", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-durable-setup-1");
    const setupStateStore = createMemorySetupStateStore();
    const sessionStore = new InMemoryAdminSessionStore();
    const sessions = createAdminSessionService({ nodeId: NODE_ID }, sessionStore, userStore);

    const mkRouter = () =>
      createAdminRouter(
        createFailClosedAdminRouteDeps({
          sessions,
          userStore,
          csrf: { allowedOrigins: ["https://node.example"] },
          totp: { secret: new Uint8Array(32), windowSteps: 1 },
          nodeId: NODE_ID,
          destinationService: createFailClosedDestinationService(),
          newRequestId: () => randomUUID(),
          setupStateStore,
        }),
      );

    const r1 = mkRouter();
    const { cookie, csrf } = await login(r1, "bootstrap-durable-setup-1");
    const hdr = {
      cookie,
      "x-csrf-token": csrf,
      origin: "https://node.example",
      "content-type": "application/json",
    };
    const p1 = await r1(
      "PATCH",
      "/admin/v1/setup-state",
      Buffer.from(JSON.stringify({ w0_secure_context_ok: true })),
      hdr,
    );
    expect(p1.status).toBe(200);
    expect(JSON.parse(p1.body).current_step).toBe("W3");

    // Simulate process restart: new router, same durable store.
    const r2 = mkRouter();
    const resumed = await r2("GET", "/admin/v1/setup-state", new Uint8Array(), {
      cookie,
      origin: "https://node.example",
    });
    expect(resumed.status).toBe(200);
    const body = JSON.parse(resumed.body) as { current_step: string; flags: { w0_secure_context_ok: boolean } };
    expect(body.flags.w0_secure_context_ok).toBe(true);
    expect(body.current_step).toBe("W3");
  });

  it("restart cannot re-issue vault master plaintext after generate", async () => {
    const userStore = new InMemoryAdminUserStore();
    await seedAdmin(userStore, "bootstrap-durable-vault-1");
    const {
      createMemoryVaultMasterSealStore,
      resolveVaultMasterBootstrap,
      bootstrapFromDurableSeal,
    } = await import("../src/setup-vault-master-seal-store.js");
    const setupStateStore = createMemorySetupStateStore();
    const sealStore = createMemoryVaultMasterSealStore();
    const sessionStore = new InMemoryAdminSessionStore();
    const sessions = createAdminSessionService({ nodeId: NODE_ID }, sessionStore, userStore);
    const backupMasterKey = "backup-kek-different-from-vault-32xx";

    const mk = (bootstrap = resolveVaultMasterBootstrap({ durableSeal: null })) => {
      return {
        bootstrap,
        router: createAdminRouter(
          createFailClosedAdminRouteDeps({
            sessions,
            userStore,
            csrf: { allowedOrigins: ["https://node.example"] },
            totp: { secret: new Uint8Array(32), windowSteps: 1 },
            nodeId: NODE_ID,
            destinationService: createFailClosedDestinationService(),
            newRequestId: () => randomUUID(),
            setupStateStore,
            vaultMasterBootstrap: bootstrap,
            vaultMasterSealStore: sealStore,
            backupMasterKey,
          }),
        ),
      };
    };

    const first = mk();
    const { cookie, csrf } = await login(first.router, "bootstrap-durable-vault-1");
    const hdr = {
      cookie,
      "x-csrf-token": csrf,
      origin: "https://node.example",
      "content-type": "application/json",
    };

    const gen = await first.router(
      "POST",
      "/admin/v1/vault-master/generate",
      Buffer.from("{}"),
      hdr,
    );
    expect(gen.status).toBe(200);
    const genBody = JSON.parse(gen.body) as { master_key: string };
    expect(genBody.master_key.length).toBeGreaterThanOrEqual(32);

    // Seal durable without plaintext.
    const seal = await sealStore.load(NODE_ID);
    expect(seal).not.toBeNull();
    expect(seal!.phase).toBe("shown");
    expect(JSON.stringify(seal)).not.toContain(genBody.master_key);

    // Restart: hydrate from seal only (no plaintext).
    const restartedBootstrap = bootstrapFromDurableSeal(seal!);
    expect(restartedBootstrap.pendingPlaintext).toBeNull();
    expect(restartedBootstrap.phase).toBe("shown");

    const second = mk(restartedBootstrap);
    const gen2 = await second.router(
      "POST",
      "/admin/v1/vault-master/generate",
      Buffer.from("{}"),
      hdr,
    );
    expect(gen2.status).toBe(409);
    expect(gen2.body).not.toContain(genBody.master_key);
    expect(JSON.parse(gen2.body).error.code).toBe("already_generated");

    const st = await second.router("GET", "/admin/v1/vault-master", new Uint8Array(), {
      cookie,
      origin: "https://node.example",
    });
    expect(st.status).toBe(200);
    expect(st.body).not.toContain(genBody.master_key);
    expect(JSON.parse(st.body).phase).toBe("shown");
    expect(JSON.parse(st.body).can_generate).toBe(false);

    // Ack still works post-restart (plaintext already wiped).
    const ack = await second.router(
      "POST",
      "/admin/v1/vault-master/ack-offline",
      Buffer.from(JSON.stringify({ offline_backup_ack: true })),
      hdr,
    );
    expect(ack.status).toBe(200);
    expect(JSON.parse(ack.body).phase).toBe("sealed");

    const seal2 = await sealStore.load(NODE_ID);
    expect(seal2!.phase).toBe("sealed");
    expect(seal2!.offlineBackupAcked).toBe(true);
    expect(JSON.stringify(seal2)).not.toContain(genBody.master_key);

    // Third restart after seal — still no generate.
    const third = mk(bootstrapFromDurableSeal(seal2!));
    const gen3 = await third.router(
      "POST",
      "/admin/v1/vault-master/generate",
      Buffer.from("{}"),
      hdr,
    );
    expect(gen3.status).toBe(409);
    expect(gen3.body).not.toContain(genBody.master_key);
  });
});
