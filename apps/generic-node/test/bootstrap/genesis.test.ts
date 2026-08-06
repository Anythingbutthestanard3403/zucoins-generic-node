import { describe, expect, it, vi } from "vitest";

import { InMemoryAdminUserStore } from "@zucoins/node-core";

import {
  bootstrapGenesisAdmin,
  ensureNodeRow,
  generateEphemeralIdentityPublicKey,
  parseNodeIdentitySeed,
  publicKeyFromEd25519Seed,
} from "../../src/bootstrap/genesis.js";

describe("genesis helpers", () => {
  it("refuses production boot when the admin table is empty and INITIAL_ADMIN_PASSWORD is absent", async () => {
    const store = new InMemoryAdminUserStore();

    await expect(
      bootstrapGenesisAdmin(
        store,
        { initialAdminPassword: undefined, isProduction: true },
        { info: vi.fn(), error: vi.fn() },
      ),
    ).rejects.toThrow(
      "INITIAL_ADMIN_PASSWORD is required on first boot (no admin user exists yet) and must be at least 12 characters",
    );
    expect(await store.count()).toBe(0);
  });

  it("preserves forced password change and TOTP enrolment on the production seeded path", async () => {
    const store = new InMemoryAdminUserStore();

    await bootstrapGenesisAdmin(
      store,
      { initialAdminPassword: "correct-horse-battery-staple", isProduction: true },
      { info: vi.fn(), error: vi.fn() },
    );

    const seeded = await store.findByUsername("admin");
    expect(seeded).toMatchObject({
      username: "admin",
      mustChangePassword: true,
      mustEnrolTotp: true,
    });
  });

  it("allows production restart without INITIAL_ADMIN_PASSWORD when an admin already exists", async () => {
    const store = new InMemoryAdminUserStore();
    const logger = { info: vi.fn(), error: vi.fn() };
    await bootstrapGenesisAdmin(
      store,
      { initialAdminPassword: "correct-horse-battery-staple", isProduction: true },
      logger,
    );

    await expect(
      bootstrapGenesisAdmin(
        store,
        { initialAdminPassword: undefined, isProduction: true },
        logger,
      ),
    ).resolves.toBeUndefined();
    expect(await store.count()).toBe(1);
  });

  it("generateEphemeralIdentityPublicKey returns padded Base64url 44-char key", () => {
    const pk = generateEphemeralIdentityPublicKey();
    expect(pk).toMatch(/^[A-Za-z0-9_-]{43}=$/);
  });

  it("parseNodeIdentitySeed accepts hex and base64 32-byte seeds", () => {
    const hex = "00".repeat(32);
    const fromHex = parseNodeIdentitySeed(hex);
    expect(fromHex).not.toBeNull();
    expect(fromHex!.length).toBe(32);
    const b64 = Buffer.alloc(32, 7).toString("base64");
    const fromB640 = parseNodeIdentitySeed(b64);
    expect(fromB640).not.toBeNull();
    expect(publicKeyFromEd25519Seed(fromHex!).length).toBe(44);
  });

  it("ensureNodeRow is idempotent (ON CONFLICT DO NOTHING)", async () => {
    const queries: unknown[][] = [];
    const pool = {
      query: vi.fn(async (_sql: string, params?: unknown[]) => {
        queries.push(params ?? []);
        // First call returns a row (inserted); second returns empty (conflict).
        if (pool.query.mock.calls.length === 1) {
          return { rows: [{ id: params?.[0] }], rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      }),
    };
    const args = {
      nodeId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
      displayName: "dryrun",
      identityPublicKey: generateEphemeralIdentityPublicKey(),
    };
    const first = await ensureNodeRow(pool as never, args);
    const second = await ensureNodeRow(pool as never, args);
    expect(first.inserted).toBe(true);
    expect(second.inserted).toBe(false);
    expect(pool.query).toHaveBeenCalledTimes(2);
  });
});
