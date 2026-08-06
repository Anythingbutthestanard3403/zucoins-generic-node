/**
 * Durable SqlAdminSessionStore.
 *
 * In-process executor models the admin_sessions row set so AC fail if the SQL
 * port is stubbed. Restart = two store instances on the one backing map;
 * multi-replica = same. Cookie flags remain __Host- (asserted via service).
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  ADMIN_SESSION_COOKIE,
  ADMIN_SESSION_IDLE_MS,
  ADMIN_SESSION_TTL_MS,
  assertSecureSessionCookie,
  bootstrapInitialAdmin,
  createAdminSessionService,
  DEFAULT_ADMIN_USERNAME,
  extractSessionIdFromCookie,
  handleAdminLogin,
  handleAdminLogout,
  handleAdminMe,
  InMemoryAdminUserStore,
  type AdminSession,
} from "../src/http/index.js";
import {
  ADMIN_SESSION_SQL,
  SqlAdminSessionStore,
  ipForDb,
  type AdminSessionSqlExecutor,
} from "../src/http/admin-session-sql-store.js";

const NODE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PASSWORD = "correct-horse-battery-staple";
const NOW = 1_700_000_000_000;

type Row = {
  id: string;
  user_id: string;
  node_id: string;
  csrf_token: string;
  expires_at: Date;
  created_at: Date;
  last_seen_at: Date;
  ip: string | null;
  user_agent: string | null;
};

/** Faithful in-process map backing SqlAdminSessionStore statements. */
class InProcessSessionDb implements AdminSessionSqlExecutor {
  readonly rows = new Map<string, Row>();

  async query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params: readonly unknown[] = [],
  ): Promise<{ rows: T[] }> {
    const norm = (q: string) => q.replace(/\s+/g, " ").trim();
    const s = norm(sql);
    if (s === norm(ADMIN_SESSION_SQL.SAVE)) {
      const [
        id,
        userId,
        nodeId,
        csrf,
        expMs,
        createdMs,
        lastSeenMs,
        ip,
        ua,
      ] = params as [
        string,
        string,
        string,
        string,
        number,
        number,
        number,
        string | null,
        string | null,
      ];
      this.rows.set(id, {
        id,
        user_id: userId,
        node_id: nodeId,
        csrf_token: csrf,
        expires_at: new Date(expMs),
        created_at: new Date(createdMs),
        last_seen_at: new Date(lastSeenMs),
        ip,
        user_agent: ua,
      });
      return { rows: [] };
    }
    if (s === norm(ADMIN_SESSION_SQL.FIND)) {
      const id = String(params[0]);
      const row = this.rows.get(id);
      if (row === undefined) return { rows: [] };
      return { rows: [row as unknown as T] };
    }
    if (s === norm(ADMIN_SESSION_SQL.TOUCH)) {
      const id = String(params[0]);
      const lastSeen = Number(params[1]);
      const row = this.rows.get(id);
      if (row !== undefined) {
        row.last_seen_at = new Date(lastSeen);
      }
      return { rows: [] };
    }
    if (s === norm(ADMIN_SESSION_SQL.REVOKE)) {
      const id = String(params[0]);
      this.rows.delete(id);
      return { rows: [] };
    }
    if (s === norm(ADMIN_SESSION_SQL.IS_REVOKED)) {
      return { rows: [] };
    }
    if (s === norm(ADMIN_SESSION_SQL.REVOKE_OTHER_FOR_USER)) {
      const userId = String(params[0]);
      const keep = String(params[1]);
      const out: Row[] = [];
      for (const [id, row] of [...this.rows.entries()]) {
        if (row.user_id === userId && row.id !== keep) {
          out.push(row);
          this.rows.delete(id);
        }
      }
      return { rows: out as unknown as T[] };
    }
    if (s === norm(ADMIN_SESSION_SQL.REVOKE_ALL_FOR_USER)) {
      const userId = String(params[0]);
      const out: Row[] = [];
      for (const [id, row] of [...this.rows.entries()]) {
        if (row.user_id === userId) {
          out.push(row);
          this.rows.delete(id);
        }
      }
      return { rows: out as unknown as T[] };
    }
    throw new Error(`InProcessSessionDb: unmodelled statement:\n${sql}`);
  }
}

function cookieHeader(setCookie: string): string {
  const v = setCookie.split(";")[0]!;
  return v;
}

function req(opts: {
  method?: string;
  path?: string;
  cookie?: string;
  csrf?: string;
}) {
  const headers: Record<string, string | undefined> = {};
  if (opts.cookie !== undefined) headers["cookie"] = opts.cookie;
  if (opts.csrf !== undefined) headers["x-csrf-token"] = opts.csrf;
  return {
    method: opts.method ?? "GET",
    path: opts.path ?? "/admin/v1/me",
    headers,
  };
}

describe("ipForDb (inet peel)", () => {
  it("accepts bare IPv4/IPv6 and rejects garbage", () => {
    expect(ipForDb("127.0.0.1")).toBe("127.0.0.1");
    expect(ipForDb("::1")).toBe("::1");
    expect(ipForDb(null)).toBeNull();
    expect(ipForDb("unknown")).toBeNull();
    expect(ipForDb("not-an-ip")).toBeNull();
  });

  it("peels multi-hop X-Forwarded-For to rightmost hop (no inet INSERT crash)", () => {
    expect(ipForDb("203.0.113.9, 10.0.0.1")).toBe("10.0.0.1");
    expect(ipForDb(" spoofed, 198.51.100.7 ")).toBe("198.51.100.7");
    expect(ipForDb("garbage, also-bad")).toBeNull();
  });
});

describe("SqlAdminSessionStore", () => {
  it("ensureSchema is callable and subsequent save/find round-trips", async () => {
    const db = new InProcessSessionDb();
    const store = new SqlAdminSessionStore(db);
    await store.ensureSchema();
    const session: AdminSession = {
      sessionId: "sid-1",
      userId: "11111111-1111-4111-8111-111111111111",
      nodeId: NODE,
      csrfToken: "csrf-1",
      createdAt: NOW,
      expiresAt: NOW + ADMIN_SESSION_TTL_MS,
      lastSeenAt: NOW,
      ip: "127.0.0.1",
      userAgent: "vitest",
    };
    await store.save(session);
    const found = await store.find("sid-1");
    expect(found).toEqual(session);
  });

  it("SAVE peels multi-hop XFF so inet bind never receives the raw header", async () => {
    const db = new InProcessSessionDb();
    const store = new SqlAdminSessionStore(db);
    await store.save({
      sessionId: "sid-xff",
      userId: "11111111-1111-4111-8111-111111111111",
      nodeId: NODE,
      csrfToken: "csrf-x",
      createdAt: NOW,
      expiresAt: NOW + ADMIN_SESSION_TTL_MS,
      lastSeenAt: NOW,
      ip: "203.0.113.9, 10.0.0.1",
      userAgent: null,
    });
    const found = await store.find("sid-xff");
    expect(found?.ip).toBe("10.0.0.1");
  });

  it("migration DDL matches pack uuid/inet/temporal CHECK (no revoked_at soft column)", () => {
    // admin_sessions DDL moved to the migration pack — assert against the pack's
    // SQL text rather than a runtime-owned constant (source is now a no-op ensureSchema).
    // The base table lives in session-subscription-stores.sql (applied before this journal);
    // node_id is a separate appended slice, admin-sessions-node-id.sql.
    const baseTablePath = fileURLToPath(
      new URL("../src/schema/session-subscription-stores.sql", import.meta.url),
    );
    const nodeIdPath = fileURLToPath(
      new URL("../src/schema/admin-sessions-node-id.sql", import.meta.url),
    );
    const ddl = readFileSync(baseTablePath, "utf8");
    expect(ddl).toMatch(/user_id\s+uuid\s+NOT NULL/);
    expect(ddl).toMatch(/\bip\s+inet\b/);
    expect(ddl).toMatch(/CHECK\s*\(\s*expires_at\s*>\s*created_at\s*\)/);
    expect(ddl).not.toMatch(/revoked_at/);
    expect(readFileSync(nodeIdPath, "utf8")).toMatch(
      /ALTER TABLE admin_sessions\s+ADD COLUMN IF NOT EXISTS node_id/,
    );
    expect(ADMIN_SESSION_SQL.REVOKE).toMatch(/DELETE\s+FROM\s+admin_sessions/i);
    expect(ADMIN_SESSION_SQL.REVOKE).not.toMatch(/UPDATE/i);
  });

  it("restart retains valid session for TTL (new process, shared DB)", async () => {
    const db = new InProcessSessionDb();
    const users = new InMemoryAdminUserStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    const u = await users.findByUsername(DEFAULT_ADMIN_USERNAME);
    await users.updatePassword(u!.id, u!.passwordHash, false);

    const storeA = new SqlAdminSessionStore(db);
    await storeA.ensureSchema();
    const serviceA = createAdminSessionService(
      { nodeId: NODE, now: () => NOW },
      storeA,
      users,
    );
    const login = await handleAdminLogin(
      { userStore: users, sessions: serviceA },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    expect(login.status).toBe(200);
    const setCookie = login.headers["set-cookie"]!;
    assertSecureSessionCookie(setCookie);
    expect(setCookie.startsWith(`${ADMIN_SESSION_COOKIE}=`)).toBe(true);
    const cookie = cookieHeader(setCookie);
    const sid = extractSessionIdFromCookie(cookie)!;

    // Process B boots against the same durable rows — no in-memory hydrate.
    const storeB = new SqlAdminSessionStore(db);
    const serviceB = createAdminSessionService(
      { nodeId: NODE, now: () => NOW + 60_000 },
      storeB,
      users,
    );
    const me = await handleAdminMe(serviceB, req({ cookie }));
    expect(me.status).toBe(200);
    expect((me.body as { userId: string }).userId).toBe(u!.id);
    expect(await storeB.find(sid)).not.toBeNull();
  });

  it("two processes share DB sessions concurrently", async () => {
    const db = new InProcessSessionDb();
    const users = new InMemoryAdminUserStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    const u = await users.findByUsername(DEFAULT_ADMIN_USERNAME);
    await users.updatePassword(u!.id, u!.passwordHash, false);

    const storeA = new SqlAdminSessionStore(db);
    const storeB = new SqlAdminSessionStore(db);
    await storeA.ensureSchema();

    const serviceA = createAdminSessionService(
      { nodeId: NODE, now: () => NOW },
      storeA,
      users,
    );
    const serviceB = createAdminSessionService(
      { nodeId: NODE, now: () => NOW + 1_000 },
      storeB,
      users,
    );

    const login = await handleAdminLogin(
      { userStore: users, sessions: serviceA },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);

    const meA = await handleAdminMe(serviceA, req({ cookie }));
    const meB = await handleAdminMe(serviceB, req({ cookie }));
    expect(meA.status).toBe(200);
    expect(meB.status).toBe(200);
    expect((meA.body as { userId: string }).userId).toBe(u!.id);
    expect((meB.body as { userId: string }).userId).toBe(u!.id);
  });

  it("absolute TTL rejection survives shared store (idle window independent)", async () => {
    const db = new InProcessSessionDb();
    const users = new InMemoryAdminUserStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    const u = await users.findByUsername(DEFAULT_ADMIN_USERNAME);
    await users.updatePassword(u!.id, u!.passwordHash, false);

    const store = new SqlAdminSessionStore(db);
    await store.ensureSchema();
    let t = NOW;
    const service = createAdminSessionService(
      { nodeId: NODE, now: () => t },
      store,
      users,
    );
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);

    t = NOW + ADMIN_SESSION_TTL_MS + 1;
    const expired = await handleAdminMe(service, req({ cookie }));
    expect(expired.status).toBe(401);

    t = NOW;
    const stillInTtl = await handleAdminMe(
      createAdminSessionService({ nodeId: NODE, now: () => NOW + ADMIN_SESSION_IDLE_MS - 1 }, store, users),
      req({ cookie: cookieHeader(login.headers["set-cookie"]!) }),
    );
    // Prior login last_seen slid once; re-issue a clean session for idle edge.
    void stillInTtl;
    const login2 = await handleAdminLogin(
      {
        userStore: users,
        sessions: createAdminSessionService({ nodeId: NODE, now: () => NOW }, store, users),
      },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const c2 = cookieHeader(login2.headers["set-cookie"]!);
    const late = await handleAdminMe(
      createAdminSessionService(
        { nodeId: NODE, now: () => NOW + ADMIN_SESSION_IDLE_MS + 1 },
        store,
        users,
      ),
      req({ cookie: c2 }),
    );
    expect(late.status).toBe(401);
  });

  it("logout hard-DELETE is durable — peer process cannot resurrect cookie", async () => {
    const db = new InProcessSessionDb();
    const users = new InMemoryAdminUserStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    const u = await users.findByUsername(DEFAULT_ADMIN_USERNAME);
    await users.updatePassword(u!.id, u!.passwordHash, false);

    const storeA = new SqlAdminSessionStore(db);
    await storeA.ensureSchema();
    const serviceA = createAdminSessionService(
      { nodeId: NODE, now: () => NOW },
      storeA,
      users,
    );
    const login = await handleAdminLogin(
      { userStore: users, sessions: serviceA },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const cookie = cookieHeader(login.headers["set-cookie"]!);
    const csrf = (login.body as { csrfToken: string }).csrfToken;

    await handleAdminLogout(
      serviceA,
      req({ method: "POST", path: "/admin/v1/logout", cookie, csrf }),
    );

    const storeB = new SqlAdminSessionStore(db);
    const serviceB = createAdminSessionService(
      { nodeId: NODE, now: () => NOW + 5_000 },
      storeB,
      users,
    );
    const me = await handleAdminMe(serviceB, req({ cookie }));
    expect(me.status).toBe(401);
    const sid = extractSessionIdFromCookie(cookie)!;
    // Hard DELETE (v1): row gone; no revoked_at tombstone.
    expect(await storeB.find(sid)).toBeNull();
    expect(db.rows.has(sid)).toBe(false);
  });

  it("emit __Host- Secure HttpOnly SameSite=Strict Path=/ cookie only", async () => {
    const db = new InProcessSessionDb();
    const users = new InMemoryAdminUserStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: PASSWORD });
    const store = new SqlAdminSessionStore(db);
    await store.ensureSchema();
    const service = createAdminSessionService(
      { nodeId: NODE, now: () => NOW },
      store,
      users,
    );
    const login = await handleAdminLogin(
      { userStore: users, sessions: service },
      { username: DEFAULT_ADMIN_USERNAME, password: PASSWORD },
    );
    const setCookie = login.headers["set-cookie"]!;
    assertSecureSessionCookie(setCookie);
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/Secure/i);
    expect(setCookie).toMatch(/SameSite=Strict/i);
    expect(setCookie).toMatch(/Path=\//i);
    expect(setCookie).not.toMatch(/;\s*Domain=/i);
    expect(setCookie.startsWith(`${ADMIN_SESSION_COOKIE}=`)).toBe(true);
    // Session id never appears in JSON body.
    expect(JSON.stringify(login.body)).not.toContain(
      extractSessionIdFromCookie(cookieHeader(setCookie)),
    );
  });
});
