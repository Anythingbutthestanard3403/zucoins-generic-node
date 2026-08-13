// Home readiness checklist: truth table + secret-free schema.

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  createAdminSessionService,
  createFailClosedDestinationService,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  InMemoryDeviceKeyStore,
  TotpConsumptionLog,
  type AdminUser,
} from "@zucoins/node-core";

import {
  buildReadinessChecklist,
  collectSecretShapedLeaks,
  READINESS_ROW_IDS,
  type ReadinessSignals,
} from "../src/admin-readiness.js";
import { createAdminRouter } from "../src/admin-router.js";
import {
  createMemoryAdminInventoryStore,
  type MemoryWalletSeed,
} from "../src/admin-inventory/index.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";

function cookieFrom(setCookie: string | undefined): string {
  return setCookie?.split(";")[0] ?? "";
}

describe("buildReadinessChecklist truth table", () => {
  it("emits every canonical row id in order", () => {
    const body = buildReadinessChecklist({});
    expect(body.object).toBe("readiness_checklist");
    expect(body.rows.map((r) => r.id)).toEqual([...READINESS_ROW_IDS]);
  });

  it("marks missing signals unknown — never fake green", () => {
    const body = buildReadinessChecklist({});
    for (const row of body.rows) {
      if (row.id === "backup_health") {
        expect(row.status).toBe("unknown");
      } else {
        expect(["unknown", "optional"]).toContain(row.status);
      }
      expect(row.status).not.toBe("ok");
    }
  });

  it("maps zero recovery-verified wallets to blocked recovery row with plain language", () => {
    const body = buildReadinessChecklist({ recoveryVerifiedEligibleCount: 0 });
    const row = body.rows.find((r) => r.id === "recovery_verified_wallet")!;
    expect(row.status).toBe("blocked");
    expect(row.detail).toMatch(/No recovery stamps yet|Test backup/i);
    expect(row.href).toBe("/recovery-ceremony");
    expect(row.blocks_ops).toContain("RECEIVE_EXTERNAL");
    expect(row.detail).not.toMatch(/^NO_ELIGIBLE_WALLET$/);
  });

  it("ok when ≥1 recovery-verified eligible wallet", () => {
    const body = buildReadinessChecklist({ recoveryVerifiedEligibleCount: 2 });
    const row = body.rows.find((r) => r.id === "recovery_verified_wallet")!;
    expect(row.status).toBe("ok");
  });

  it("never marks recovery ok when stamp count is 0 (even if lastRecoveryVerifiedAt set)", () => {
    const body = buildReadinessChecklist({
      recoveryVerifiedEligibleCount: 0,
      lastRecoveryVerifiedAt: "2026-01-01T00:00:00.000Z",
    });
    const row = body.rows.find((r) => r.id === "recovery_verified_wallet")!;
    expect(row.status).toBe("blocked");
    expect(row.status).not.toBe("ok");
  });

  it("surfaces last pack prove time only when stamps exist", () => {
    const body = buildReadinessChecklist({
      recoveryVerifiedEligibleCount: 1,
      lastRecoveryVerifiedAt: "2026-06-01T12:00:00.000Z",
    });
    const row = body.rows.find((r) => r.id === "recovery_verified_wallet")!;
    expect(row.status).toBe("ok");
    expect(row.detail).toMatch(/Last pack prove: 2026-06-01T12:00:00.000Z/);
    expect(row.detail).toMatch(/Verify backup again/i);
  });

  it("node_healthy blocked when not_ready", () => {
    const body = buildReadinessChecklist({ nodeStatus: "not_ready" });
    const row = body.rows.find((r) => r.id === "node_healthy")!;
    expect(row.status).toBe("blocked");
    expect(row.blocks_ops?.length).toBeGreaterThan(0);
  });

  it("totp blocked when not enrolled", () => {
    const body = buildReadinessChecklist({ totpEnrolled: false });
    expect(body.rows.find((r) => r.id === "totp_enrolled")!.status).toBe("blocked");
  });

  it("device ok via break-glass alone", () => {
    const body = buildReadinessChecklist({
      deviceEnrolled: false,
      breakGlassActive: true,
    });
    expect(body.rows.find((r) => r.id === "device_enrolled")!.status).toBe("ok");
  });

  it("backup unknown when not wired; optional when disabled; amber on RPO breach", () => {
    expect(buildReadinessChecklist({}).rows.find((r) => r.id === "backup_health")!.status).toBe(
      "unknown",
    );
    expect(
      buildReadinessChecklist({
        backup: {
          enabled: false,
          rpoBreached: false,
          lastSuccessAt: null,
          consecutiveFailures: 0,
        },
      }).rows.find((r) => r.id === "backup_health")!.status,
    ).toBe("optional");
    expect(
      buildReadinessChecklist({
        backup: {
          enabled: true,
          rpoBreached: true,
          lastSuccessAt: "2026-01-01T00:00:00.000Z",
          consecutiveFailures: 2,
        },
      }).rows.find((r) => r.id === "backup_health")!.status,
    ).toBe("amber");

    // Schedule on + never succeeded → amber (not fake green), with Recovery CTA copy.
    const never = buildReadinessChecklist({
      backup: {
        enabled: true,
        rpoBreached: false,
        lastSuccessAt: null,
        consecutiveFailures: 0,
      },
    }).rows.find((r) => r.id === "backup_health")!;
    expect(never.status).toBe("amber");
    expect(never.detail).toMatch(/no successful backup/i);
    expect(never.detail).toMatch(/recovery/i);
    expect(never.href).toBe("/recovery-ceremony");

    // Standby (non-leader) is optional — not amber RPO failure (ZTR-1183).
    const standby = buildReadinessChecklist({
      backup: {
        enabled: true,
        ownership: "standby",
        rpoBreached: false,
        lastSuccessAt: null,
        consecutiveFailures: 0,
      },
    }).rows.find((r) => r.id === "backup_health")!;
    expect(standby.status).toBe("optional");
    expect(standby.detail).toMatch(/not the backup owner/i);
  });

  it("all-green signal set yields no blocked rows", () => {
    const green: ReadinessSignals = {
      nodeStatus: "ready",
      totpEnrolled: true,
      deviceEnrolled: true,
      breakGlassActive: false,
      recoveryVerifiedEligibleCount: 1,
      reportingKeyActive: true,
      implementerKeyPresent: true,
      backup: {
        enabled: true,
        rpoBreached: false,
        lastSuccessAt: "2026-08-01T00:00:00.000Z",
        consecutiveFailures: 0,
      },
    };
    const body = buildReadinessChecklist(green);
    expect(body.rows.every((r) => r.status === "ok" || r.status === "optional")).toBe(true);
    expect(body.rows.some((r) => r.status === "blocked")).toBe(false);
  });
});

describe("readiness secret-free schema", () => {
  it("rejects secret-shaped keys and ik_/sh_ bare secrets in payload", () => {
    const clean = buildReadinessChecklist({
      nodeStatus: "ready",
      totpEnrolled: true,
      recoveryVerifiedEligibleCount: 0,
    });
    expect(collectSecretShapedLeaks(clean)).toEqual([]);

    const dirty = {
      ...clean,
      password: "x",
      nested: { totp_secret: "ABC", private_key: "k", token: "t" },
      detail: "ik_thisisalongsecretvalue",
    };
    const leaks = collectSecretShapedLeaks(dirty);
    expect(leaks.length).toBeGreaterThan(0);
    expect(leaks.some((l) => l.includes("password") || l.includes("secret") || l.includes("ik_"))).toBe(
      true,
    );
  });
});

describe("GET /admin/v1/readiness", () => {
  async function login(router: ReturnType<typeof createAdminRouter>, userStore: InMemoryAdminUserStore) {
    const password = "correct-horse-battery-staple";
    const user: AdminUser = {
      id: randomUUID(),
      username: "admin",
      passwordHash: await hashPassword(password),
      role: "admin",
      mustChangePassword: false,
      mustEnrolTotp: false,
      disabledAt: null,
      createdAt: Date.now(),
    };
    await userStore.insert(user);
    await userStore.setActiveTotpSecret(user.id, "JBSWY3DPEHPK3PXP");
    const response = await router(
      "POST",
      "/admin/v1/login",
      Buffer.from(JSON.stringify({ username: user.username, password })),
      { "content-type": "application/json" },
    );
    expect(response.status).toBe(200);
    return {
      cookie: cookieFrom(response.headers["set-cookie"]),
      csrf: (JSON.parse(response.body) as { csrfToken: string }).csrfToken,
      userId: user.id,
    };
  }

  it("requires session", async () => {
    const userStore = new InMemoryAdminUserStore();
    const sessions = createAdminSessionService(
      { nodeId: NODE_ID },
      new InMemoryAdminSessionStore(),
      userStore,
    );
    const router = createAdminRouter({
      sessions,
      userStore,
      csrf: { allowedOrigins: [ORIGIN] },
      totp: { secret: new Uint8Array(32), windowSteps: 1 },
      totpLog: new TotpConsumptionLog(),
      nodeId: NODE_ID,
      challengeStore: {
        findIssuedByOperation: async () => null,
        findByNonce: async () => null,
        insertIssued: async () => {},
        commitApprovalMutation: async () => {
          throw new Error("unused");
        },
      },
      loadOperation: async () => null,
      sendDecisionStore: {
        rejectCreated: async () => {
          throw new Error("unused");
        },
        approveCreated: async () => {
          throw new Error("unused");
        },
      },
      deviceStore: null,
      recoveryStore: {
        listNeedsAttention: async () => [],
        loadRecoveryFacts: async () => null,
        issueRecoveryNonce: async () => {
          throw new Error("unused");
        },
      },
      recoveryActionStore: {
        lookupIdempotency: async () => ({ kind: "miss" }),
        loadRecoveryFactsLocked: async () => null,
        commitRecoveryAction: async () => {
          throw new Error("unused");
        },
        storeIdempotency: async () => {},
      },
      destinationService: createFailClosedDestinationService(),
      newRequestId: () => randomUUID(),
    });
    const res = await router("GET", "/admin/v1/readiness", new Uint8Array(), {});
    expect(res.status).toBe(401);
  });

  it("returns secret-free checklist with recovery blocked when no eligible wallet", async () => {
    const userStore = new InMemoryAdminUserStore();
    const sessions = createAdminSessionService(
      { nodeId: NODE_ID },
      new InMemoryAdminSessionStore(),
      userStore,
    );
    const devices = new InMemoryDeviceKeyStore();
    const inventory = createMemoryAdminInventoryStore({
      wallets: [
        {
          custody: {
            walletId: randomUUID() as never,
            nodeId: NODE_ID as never,
            publicKey: "pk_blocked" as never,
            keyOrigin: "node_generated",
            state: "AVAILABLE",
            createdAt: "2026-08-01T00:00:00.000Z",
            retiredAt: null,
            quarantineReason: null,
            recoveryVerifiedAt: null,
            recoveryVerificationId: null,
          },
          observed_balance_zkz: null,
          holding: {
            holding_operation_id: null,
            holding_operation_status: null,
            holding_operation_expiry_unix_time_secs: null,
            holding_operation_attention_required: false,
            holding_operation_terminal_at: null,
            holding_lease_role: null,
            holding_operation_type: null,
            money_mode: "FULL",
            allow_external_receive: true,
            allow_external_send: true,
            allow_internal_move: true,
            row_version: 1,
          },
        } satisfies MemoryWalletSeed,
      ],
    });

    const router = createAdminRouter({
      sessions,
      userStore,
      csrf: { allowedOrigins: [ORIGIN] },
      totp: {
        secret: new TextEncoder().encode("test-secret-key-32-bytes-long!!"),
        windowSteps: 1,
      },
      totpLog: new TotpConsumptionLog(),
      nodeId: NODE_ID,
      challengeStore: {
        findIssuedByOperation: async () => null,
        findByNonce: async () => null,
        insertIssued: async () => {},
        commitApprovalMutation: async () => {
          throw new Error("unused");
        },
      },
      loadOperation: async () => null,
      sendDecisionStore: {
        rejectCreated: async () => {
          throw new Error("unused");
        },
        approveCreated: async () => {
          throw new Error("unused");
        },
      },
      deviceStore: devices,
      inventoryStore: inventory,
      recoveryStore: {
        listNeedsAttention: async () => [],
        loadRecoveryFacts: async () => null,
        issueRecoveryNonce: async () => {
          throw new Error("unused");
        },
      },
      recoveryActionStore: {
        lookupIdempotency: async () => ({ kind: "miss" }),
        loadRecoveryFactsLocked: async () => null,
        commitRecoveryAction: async () => {
          throw new Error("unused");
        },
        storeIdempotency: async () => {},
      },
      destinationService: createFailClosedDestinationService(),
      newRequestId: () => randomUUID(),
      readinessProbe: {
        nodeStatus: () => "ready",
        backupStatus: () => null,
      },
      resolveImplementerId: async () => null,
    });

    const auth = await login(router, userStore);
    const res = await router("GET", "/admin/v1/readiness", new Uint8Array(), {
      cookie: auth.cookie,
      origin: ORIGIN,
      "x-csrf-token": auth.csrf,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      object: string;
      rows: Array<{ id: string; status: string; detail: string; href: string }>;
    };
    expect(body.object).toBe("readiness_checklist");
    expect(body.rows.map((r) => r.id)).toEqual([...READINESS_ROW_IDS]);
    const recovery = body.rows.find((r) => r.id === "recovery_verified_wallet")!;
    expect(recovery.status).toBe("blocked");
    expect(recovery.detail).toMatch(/No recovery stamps yet|Test backup/i);
    expect(recovery.href).toBe("/recovery-ceremony");

    // Automated secret-leak gate on the live wire body.
    expect(collectSecretShapedLeaks(body)).toEqual([]);
    const raw = res.body.toLowerCase();
    for (const frag of ["password", "private_key", "totp_secret", "raw_key", "master_key"]) {
      expect(raw).not.toContain(frag);
    }
  });
});
