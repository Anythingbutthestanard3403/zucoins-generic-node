// GET/POST /admin/v1/implementers + retire, and multi-implementer api-keys
// issuance. Session+CSRF+TOTP via runGuardedAdminMutation; audit actions
// implementer.created / implementer.retired; retirement is an issuance gate.

import { createHmac, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  CredentialError,
  CredentialService,
  createAdminSessionService,
  createFailClosedDestinationService,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  createInMemoryOperatorHaltStore,
  hashPassword,
  IMPLEMENTER_AUDIT_CREATED,
  IMPLEMENTER_AUDIT_RETIRED,
  IMPLEMENTER_SCOPES,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  InMemoryDefaultFundingWallet,
  InMemoryImplementerRegistry,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
  type CredentialAuditEntry,
  type CredentialStore,
  type DefaultFundingWalletPort,
  type StoredCredential,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");
const GENESIS_ID = "22222222-2222-4222-8222-222222222222";

function generateTotp(secret: Uint8Array, nowMs: number): string {
  const timestep = Math.floor(nowMs / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timestep));
  const h = createHmac("sha1", secret).update(buf).digest();
  const offset = h[h.length - 1]! & 0x0f;
  const code =
    ((h[offset]! & 0x7f) << 24) |
    (h[offset + 1]! << 16) |
    (h[offset + 2]! << 8) |
    h[offset + 3]!;
  return (code % 1_000_000).toString().padStart(6, "0");
}

function encodeBase32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  return setCookie.split(";")[0] ?? "";
}

class MemoryCredentialStore implements CredentialStore {
  readonly rows = new Map<string, StoredCredential>();
  readonly audit: CredentialAuditEntry[] = [];

  async issue(row: StoredCredential, audit: CredentialAuditEntry): Promise<void> {
    this.rows.set(row.id, row);
    this.audit.push(audit);
  }
  async findByHash(hash: string): Promise<StoredCredential | null> {
    for (const row of this.rows.values()) {
      if (row.credential_hash === hash) return row;
    }
    return null;
  }
  async findById(credentialId: string, implementerId: string): Promise<StoredCredential | null> {
    const row = this.rows.get(credentialId);
    if (row === undefined || row.implementer_id !== implementerId) return null;
    return row;
  }
  async findByCredentialId(credentialId: string): Promise<StoredCredential | null> {
    return this.rows.get(credentialId) ?? null;
  }
  async listByImplementer(implementerId: string): Promise<StoredCredential[]> {
    return [...this.rows.values()].filter((r) => r.implementer_id === implementerId);
  }
  async listAll(): Promise<StoredCredential[]> {
    return [...this.rows.values()];
  }
  async rotate(): Promise<boolean> {
    throw new Error("rotate unused");
  }
  async revoke(
    credentialId: string,
    implementerId: string,
    revokedAt: string,
    audit: CredentialAuditEntry,
  ): Promise<boolean> {
    const row = this.rows.get(credentialId);
    if (row === undefined || row.implementer_id !== implementerId) return false;
    this.rows.set(credentialId, {
      ...row,
      status: "REVOKED",
      revoked_at: revokedAt,
    });
    this.audit.push(audit);
    return true;
  }
}

function makeRouter(opts: {
  readonly credentialService?: CredentialService;
  readonly resolveImplementerId?: () => Promise<string | null>;
  readonly implementerRegistry?: InMemoryImplementerRegistry;
  readonly defaultFundingWallet?: DefaultFundingWalletPort;
  readonly mintFundingWallet?: () => Promise<{ walletId: string; publicKey: string }>;
  readonly nowMs?: () => number;
  readonly userStore?: InMemoryAdminUserStore;
}) {
  const userStore = opts.userStore ?? new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const registry = opts.implementerRegistry ?? new InMemoryImplementerRegistry();
  const defaultFunding =
    opts.defaultFundingWallet ?? new InMemoryDefaultFundingWallet();
  const atomic = createTestAdminAtomicDeps({
    credentialService: opts.credentialService as CredentialService,
    implementerRegistry: registry,
    defaultFundingWallet: defaultFunding,
  });
  const router = createAdminRouter({
    sessions,
    userStore,
    csrf: { allowedOrigins: [ORIGIN] },
    totp: { secret: SECRET, windowSteps: 1 },
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
      listNeedsAttention: async () => ({ items: [], total: 0, has_more: false, next_cursor: null }),
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
    nowMs: opts.nowMs ?? (() => 1_700_000_030_000),
    halt: {
      gate: createHaltGate(RUNNING),
      store: createInMemoryOperatorHaltStore(RUNNING),
      evidence: createInMemoryHaltEvidenceRecorder(),
    },
    credentialService: opts.credentialService,
    resolveImplementerId: opts.resolveImplementerId ?? (async () => registry.resolveGenesisId()),
    implementerRegistry: registry,
    defaultFundingWallet: defaultFunding,
    mintFundingWallet: opts.mintFundingWallet,
    adminIdempotencyStore: atomic.adminIdempotencyStore,
    atomicAdminMutation: atomic.atomicAdminMutation,
  });
  return { router, userStore, registry, defaultFunding };
}

async function login(
  router: ReturnType<typeof makeRouter>["router"],
  userStore: InMemoryAdminUserStore,
  password: string,
) {
  const res = await router(
    "POST",
    "/admin/v1/login",
    Buffer.from(JSON.stringify({ username: "admin", password })),
    { "content-type": "application/json" },
  );
  expect(res.status).toBe(200);
  return {
    cookie: cookieFrom(res.headers["set-cookie"]),
    csrf: (JSON.parse(res.body) as { csrfToken: string }).csrfToken,
  };
}

async function enrolAdmin(
  userStore: InMemoryAdminUserStore,
  password: string,
): Promise<AdminUser> {
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
  await userStore.setActiveTotpSecret(user.id, encodeBase32(SECRET));
  return user;
}

describe("admin /admin/v1/implementers", () => {
  it("GET fails closed (503) when the registry is not wired", async () => {
    const userStore = new InMemoryAdminUserStore();
    const sessions = createAdminSessionService(
      { nodeId: NODE_ID },
      new InMemoryAdminSessionStore(),
      userStore,
    );
    const atomic = createTestAdminAtomicDeps({});
    const router = createAdminRouter({
      sessions,
      userStore,
      csrf: { allowedOrigins: [ORIGIN] },
      totp: { secret: SECRET, windowSteps: 1 },
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
        listNeedsAttention: async () => ({ items: [], total: 0, has_more: false, next_cursor: null }),
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
      nowMs: () => 1_700_000_030_000,
      halt: {
        gate: createHaltGate(RUNNING),
        store: createInMemoryOperatorHaltStore(RUNNING),
        evidence: createInMemoryHaltEvidenceRecorder(),
      },
      adminIdempotencyStore: atomic.adminIdempotencyStore,
      atomicAdminMutation: atomic.atomicAdminMutation,
    });
    await enrolAdmin(userStore, "p");
    const { cookie, csrf } = await login(router, userStore, "p");
    const res = await router("GET", "/admin/v1/implementers", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
    });
    expect(res.status).toBe(503);
  });

  it("create/list/retire round-trip with TOTP gating, audit, and idempotency replay", async () => {
    let nowMs = 1_700_000_030_000;
    const registry = new InMemoryImplementerRegistry(() => new Date(nowMs));
    registry.seed({
      id: GENESIS_ID,
      name: "genesis",
      created_at: "2026-01-01T00:00:00.000Z",
      retired_at: null,
    });
    const userStore = new InMemoryAdminUserStore();
    const { router } = makeRouter({
      implementerRegistry: registry,
      nowMs: () => nowMs,
      userStore,
    });
    await enrolAdmin(userStore, "impl-pass");
    const { cookie, csrf } = await login(router, userStore, "impl-pass");

    // Create without TOTP → 401, nothing minted.
    const noTotp = await router(
      "POST",
      "/admin/v1/implementers",
      Buffer.from(JSON.stringify({ name: "payroll-run" })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "content-type": "application/json",
        "idempotency-key": "idem-impl-create-no-totp-abcdefghij",
      },
    );
    expect(noTotp.status).toBe(401);
    expect(registry.rows.size).toBe(1);

    // Create with TOTP → 200 + audit.
    const createKey = "idem-impl-create-ok-abcdefghijklmnop";
    const created = await router(
      "POST",
      "/admin/v1/implementers",
      Buffer.from(JSON.stringify({ name: "payroll-run" })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": createKey,
      },
    );
    expect(created.status).toBe(200);
    const createdBody = JSON.parse(created.body) as {
      id: string;
      name: string;
      created_at: string;
      retired_at: null;
    };
    expect(createdBody.name).toBe("payroll-run");
    expect(createdBody.retired_at).toBeNull();
    expect(createdBody.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(registry.audit.some((a) => a.action === IMPLEMENTER_AUDIT_CREATED)).toBe(true);

    // Idempotency replay returns identical bytes without a second row.
    const replay = await router(
      "POST",
      "/admin/v1/implementers",
      Buffer.from(JSON.stringify({ name: "payroll-run" })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": createKey,
      },
    );
    expect(replay.status).toBe(200);
    expect(replay.headers["idempotency-replayed"]).toBe("true");
    expect(replay.body).toBe(created.body);
    expect(registry.rows.size).toBe(2);

    // List shows both.
    const list = await router("GET", "/admin/v1/implementers", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
    });
    expect(list.status).toBe(200);
    const listed = JSON.parse(list.body) as {
      implementers: { id: string; name: string; retired_at: string | null }[];
    };
    expect(listed.implementers).toHaveLength(2);
    expect(listed.implementers.map((i) => i.name).sort()).toEqual(["genesis", "payroll-run"]);

    // Stale/replayed TOTP is rejected; timestep burn retained on failure.
    const staleTotp = generateTotp(SECRET, nowMs);
    nowMs += 30_000;
    // Burn the fresh code once successfully on a no-op path is not available —
    // reuse the already-burned prior timestep after window advances.
    const retiredNoFresh = await router(
      "POST",
      `/admin/v1/implementers/${createdBody.id}/retire`,
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": staleTotp,
        "content-type": "application/json",
        "idempotency-key": "idem-impl-retire-stale-abcdefghij",
      },
    );
    expect(retiredNoFresh.status).toBe(401);
    expect(registry.rows.get(createdBody.id)!.retired_at).toBeNull();

    // Missing TOTP → 401.
    const retireNoTotp = await router(
      "POST",
      `/admin/v1/implementers/${createdBody.id}/retire`,
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "content-type": "application/json",
        "idempotency-key": "idem-impl-retire-no-totp-abcdefg",
      },
    );
    expect(retireNoTotp.status).toBe(401);

    // Retire with fresh TOTP.
    const retireKey = "idem-impl-retire-ok-abcdefghijklmnop";
    const retired = await router(
      "POST",
      `/admin/v1/implementers/${createdBody.id}/retire`,
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": retireKey,
      },
    );
    expect(retired.status).toBe(200);
    const retiredBody = JSON.parse(retired.body) as { id: string; retired_at: string | null };
    expect(retiredBody.id).toBe(createdBody.id);
    expect(retiredBody.retired_at).not.toBeNull();
    expect(registry.audit.some((a) => a.action === IMPLEMENTER_AUDIT_RETIRED)).toBe(true);

    // Retire idempotency replay.
    const retireReplay = await router(
      "POST",
      `/admin/v1/implementers/${createdBody.id}/retire`,
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": retireKey,
      },
    );
    expect(retireReplay.status).toBe(200);
    expect(retireReplay.headers["idempotency-replayed"]).toBe("true");
    expect(retireReplay.body).toBe(retired.body);
  });

  it("issue under second implementer binds implementer_id; genesis default when omitted", async () => {
    const store = new MemoryCredentialStore();
    let nowMs = 1_700_000_030_000;
    const registry = new InMemoryImplementerRegistry(() => new Date(nowMs));
    registry.seed({
      id: GENESIS_ID,
      name: "genesis",
      created_at: "2026-01-01T00:00:00.000Z",
      retired_at: null,
    });
    const secondId = "33333333-3333-4333-8333-333333333333";
    registry.seed({
      id: secondId,
      name: "second",
      created_at: "2026-02-01T00:00:00.000Z",
      retired_at: null,
    });
    const userStore = new InMemoryAdminUserStore();
    const { router } = makeRouter({
      credentialService: new CredentialService(store),
      implementerRegistry: registry,
      resolveImplementerId: async () => GENESIS_ID,
      nowMs: () => nowMs,
      userStore,
    });
    await enrolAdmin(userStore, "keys-multi");
    const { cookie, csrf } = await login(router, userStore, "keys-multi");

    // Genesis default (no implementer_id).
    const genesisIssue = await router(
      "POST",
      "/admin/v1/api-keys",
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-keys-genesis-default-abcdefg",
      },
    );
    expect(genesisIssue.status).toBe(200);
    const genesisBody = JSON.parse(genesisIssue.body) as {
      id: string;
      implementer_id: string;
      raw_key: string;
    };
    expect(genesisBody.implementer_id).toBe(GENESIS_ID);
    expect(genesisBody.raw_key).toMatch(/^ik_/);

    // Second implementer.
    nowMs += 30_000;
    const secondIssue = await router(
      "POST",
      "/admin/v1/api-keys",
      Buffer.from(JSON.stringify({ implementer_id: secondId })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-keys-second-impl-abcdefghijk",
      },
    );
    expect(secondIssue.status).toBe(200);
    const secondBody = JSON.parse(secondIssue.body) as {
      id: string;
      implementer_id: string;
      raw_key: string;
    };
    expect(secondBody.implementer_id).toBe(secondId);
    expect(store.rows.get(secondBody.id)!.implementer_id).toBe(secondId);

    // Tenant binding proof: validate(raw) → implementer_id of the second key
    // (same principal the external-send path persists on the operation row).
    const credentialService = new CredentialService(store);
    const principal = await credentialService.validate(secondBody.raw_key);
    expect(principal.implementer_id).toBe(secondId);
    expect(principal.scopes).toEqual([...IMPLEMENTER_SCOPES]);

    // List all keys includes both implementer_ids.
    const listAll = await router("GET", "/admin/v1/api-keys", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
    });
    expect(listAll.status).toBe(200);
    const allKeys = JSON.parse(listAll.body) as {
      keys: { id: string; implementer_id: string }[];
    };
    expect(allKeys.keys).toHaveLength(2);
    expect(new Set(allKeys.keys.map((k) => k.implementer_id))).toEqual(
      new Set([GENESIS_ID, secondId]),
    );

    // Filter by implementer_id.
    const filtered = await router(
      "GET",
      `/admin/v1/api-keys?implementer_id=${secondId}`,
      new Uint8Array(),
      { cookie, origin: ORIGIN, "x-csrf-token": csrf },
    );
    expect(filtered.status).toBe(200);
    const filteredKeys = JSON.parse(filtered.body) as { keys: { implementer_id: string }[] };
    expect(filteredKeys.keys).toHaveLength(1);
    expect(filteredKeys.keys[0]!.implementer_id).toBe(secondId);
  });

  it("issuance under a retired implementer is refused; existing keys still authenticate", async () => {
    const store = new MemoryCredentialStore();
    let nowMs = 1_700_000_030_000;
    const registry = new InMemoryImplementerRegistry(() => new Date(nowMs));
    const targetId = "44444444-4444-4444-8444-444444444444";
    registry.seed({
      id: GENESIS_ID,
      name: "genesis",
      created_at: "2026-01-01T00:00:00.000Z",
      retired_at: null,
    });
    registry.seed({
      id: targetId,
      name: "to-retire",
      created_at: "2026-02-01T00:00:00.000Z",
      retired_at: null,
    });
    const userStore = new InMemoryAdminUserStore();
    const { router } = makeRouter({
      credentialService: new CredentialService(store),
      implementerRegistry: registry,
      resolveImplementerId: async () => GENESIS_ID,
      nowMs: () => nowMs,
      userStore,
    });
    await enrolAdmin(userStore, "retire-keys");
    const { cookie, csrf } = await login(router, userStore, "retire-keys");

    // Issue under target before retire.
    const issued = await router(
      "POST",
      "/admin/v1/api-keys",
      Buffer.from(JSON.stringify({ implementer_id: targetId })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-keys-pre-retire-abcdefghijk",
      },
    );
    expect(issued.status).toBe(200);
    const issuedBody = JSON.parse(issued.body) as { raw_key: string; id: string };
    const rawKey = issuedBody.raw_key;

    // Retire.
    nowMs += 30_000;
    const retired = await router(
      "POST",
      `/admin/v1/implementers/${targetId}/retire`,
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-impl-retire-target-abcdefg",
      },
    );
    expect(retired.status).toBe(200);

    // Further issuance refused.
    nowMs += 30_000;
    const refused = await router(
      "POST",
      "/admin/v1/api-keys",
      Buffer.from(JSON.stringify({ implementer_id: targetId })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-keys-post-retire-abcdefghij",
      },
    );
    expect(refused.status).toBe(409);
    expect(JSON.parse(refused.body).error.code).toBe("conflict");

    // Existing key still authenticates.
    const credentialService = new CredentialService(store);
    const principal = await credentialService.validate(rawKey);
    expect(principal.implementer_id).toBe(targetId);
    expect(principal.credential_id).toBe(issuedBody.id);
  });

  it("CredentialError collapse remains CREDENTIAL_NOT_FOUND", () => {
    const err = new CredentialError("credential not found", "CREDENTIAL_NOT_FOUND");
    expect(err.code).toBe("CREDENTIAL_NOT_FOUND");
  });

  it("set funding wallet DEFAULT / WALLET_ID and default funding setting (ZTR-1287)", async () => {
    let nowMs = 1_700_000_030_000;
    const registry = new InMemoryImplementerRegistry(() => new Date(nowMs));
    const WALLET = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const PUB = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    registry.seedWallet({ id: WALLET, public_key: PUB });
    registry.seed({
      id: GENESIS_ID,
      name: "genesis",
      created_at: "2026-01-01T00:00:00.000Z",
      retired_at: null,
    });
    const defaultFunding = new InMemoryDefaultFundingWallet();
    defaultFunding.seedWallet(WALLET, PUB);
    const userStore = new InMemoryAdminUserStore();
    const { router } = makeRouter({
      implementerRegistry: registry,
      defaultFundingWallet: defaultFunding,
      userStore,
      nowMs: () => nowMs,
    });
    await enrolAdmin(userStore, "p");
    const { cookie, csrf } = await login(router, userStore, "p");

    const list0 = await router("GET", "/admin/v1/implementers", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
    });
    expect(list0.status).toBe(200);
    const listed0 = JSON.parse(list0.body) as {
      implementers: { funding_wallet_id: string | null }[];
    };
    expect(listed0.implementers[0]!.funding_wallet_id).toBeNull();

    const setKey = "idem-funding-set-" + "x".repeat(8);
    const setRes = await router(
      "POST",
      `/admin/v1/implementers/${GENESIS_ID}/funding-wallet`,
      Buffer.from(JSON.stringify({ mode: "WALLET_ID", wallet_id: WALLET })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": setKey,
      },
    );
    expect(setRes.status).toBe(200);
    const setBody = JSON.parse(setRes.body) as {
      funding_wallet_id: string | null;
      funding_wallet_public_key: string | null;
    };
    expect(setBody.funding_wallet_id).toBe(WALLET);
    expect(setBody.funding_wallet_public_key).toBe(PUB);

    nowMs += 60_000;
    const clearKey = "idem-funding-clr-" + "y".repeat(8);
    const clearRes = await router(
      "POST",
      `/admin/v1/implementers/${GENESIS_ID}/funding-wallet`,
      Buffer.from(JSON.stringify({ mode: "DEFAULT" })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": clearKey,
      },
    );
    expect(clearRes.status).toBe(200);
    expect(JSON.parse(clearRes.body).funding_wallet_id).toBeNull();

    const getDefault = await router(
      "GET",
      "/admin/v1/default-funding-wallet",
      new Uint8Array(),
      { cookie, origin: ORIGIN, "x-csrf-token": csrf },
    );
    expect(getDefault.status).toBe(200);
    expect(JSON.parse(getDefault.body)).toEqual({
      wallet_id: null,
      public_key: null,
      row_version: 0,
    });

    nowMs += 60_000;
    const putKey = "idem-default-fw-" + "z".repeat(8);
    const putRes = await router(
      "PUT",
      "/admin/v1/default-funding-wallet",
      Buffer.from(JSON.stringify({ wallet_id: WALLET, expected_row_version: 0 })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": putKey,
      },
    );
    expect(putRes.status).toBe(200);
    const putBody = JSON.parse(putRes.body) as {
      wallet_id: string | null;
      public_key: string | null;
      row_version: number;
    };
    expect(putBody.wallet_id).toBe(WALLET);
    expect(putBody.public_key).toBe(PUB);
    expect(putBody.row_version).toBe(1);
  });
});
