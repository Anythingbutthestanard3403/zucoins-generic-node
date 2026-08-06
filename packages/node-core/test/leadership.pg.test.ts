// Real-PostgreSQL proof that signer-leadership mutual exclusion is arbitrated by the database
// and that leadership loss follows connection death. Exclusion cannot be proven in memory: a
// single-threaded field comparison cannot fail, so the property would be unfalsifiable. Here two
// genuinely concurrent sessions contend for the same session advisory lock and PostgreSQL picks
// the winner.
//
// Each acquirer is a long-lived `psql` child process: one process is one connection, so it is a
// dedicated never-pooled session, and SIGKILLing it is a real connection death that frees the
// lock server-side exactly as a database failover would. Driving PostgreSQL through a child
// process (as migration-integrity.test.ts and node-implementer-registry.pg.test.ts do) keeps the
// in-process network-containment guard intact.
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";

import {
  acquireSignerLeadership,
  RELEASE_LEADERSHIP_SQL,
  SIGNER_LEADERSHIP_LOCK_ID,
  SignerLeadership,
  TRY_ACQUIRE_LEADERSHIP_SQL,
  tryAcquireSignerLeadership,
  type LeadershipLockClient,
  type LeadershipLockPool,
} from "../src/workers/leadership.ts";

describe("signer leadership lock SQL (census — runs without a database)", () => {
  it("is a session advisory lock, non-blocking on acquire", () => {
    expect(TRY_ACQUIRE_LEADERSHIP_SQL).toContain("pg_try_advisory_lock");
    expect(TRY_ACQUIRE_LEADERSHIP_SQL).not.toContain("pg_advisory_xact_lock");
    expect(RELEASE_LEADERSHIP_SQL).toContain("pg_advisory_unlock");
    expect(Number.isSafeInteger(SIGNER_LEADERSHIP_LOCK_ID)).toBe(true);
  });
});

const databaseUrl = process.env.TEST_DATABASE_URL;

function pgEnv(): NodeJS.ProcessEnv {
  const url = new URL(databaseUrl as string);
  return {
    ...process.env,
    PGHOST: url.hostname,
    PGPORT: url.port === "" ? "5432" : url.port,
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
    PGDATABASE: url.pathname.replace(/^\//, ""),
  };
}

/**
 * One `psql` session behind the {@link LeadershipLockClient} seam. Statements go in on stdin and
 * `-A -t` prints exactly one line per single-column row, so replies pair with requests in order.
 */
class PsqlSession implements LeadershipLockClient {
  readonly child: ChildProcessWithoutNullStreams;
  readonly #pending: Array<(line: string) => void> = [];
  readonly #listeners = new Map<string, Array<(err?: Error) => void>>();
  #buffer = "";

  constructor() {
    this.child = spawn("psql", ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"], {
      env: pgEnv(),
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk: string) => {
      this.#buffer += chunk;
      let newline = this.#buffer.indexOf("\n");
      while (newline !== -1) {
        const line = this.#buffer.slice(0, newline).trim();
        this.#buffer = this.#buffer.slice(newline + 1);
        if (line !== "") this.#pending.shift()?.(line);
        newline = this.#buffer.indexOf("\n");
      }
    });
    this.child.on("close", () => this.#emit("end"));
    this.child.on("error", (err) => this.#emit("error", err));
  }

  async query(sql: string, values?: readonly unknown[]): Promise<{ rows: unknown[] }> {
    // psql has no bind parameters; the only value ever substituted is the numeric lock id.
    const statement = values === undefined ? sql : sql.replace("$1", String(Number(values[0])));
    const column = /\bAS\s+(\w+)/i.exec(sql)?.[1] ?? "result";
    const line = await new Promise<string>((resolve, reject) => {
      const onClosed = (): void => reject(new Error("psql session closed"));
      this.child.once("close", onClosed);
      this.#pending.push((value) => {
        this.child.removeListener("close", onClosed);
        resolve(value);
      });
      this.child.stdin.write(`${statement};\n`);
    });
    return { rows: [{ [column]: line === "t" }] };
  }

  on(event: "error" | "end", listener: (err?: Error) => void): void {
    this.#listeners.set(event, [...(this.#listeners.get(event) ?? []), listener]);
  }

  removeListener(event: "error" | "end", listener: (err?: Error) => void): void {
    this.#listeners.set(
      event,
      (this.#listeners.get(event) ?? []).filter((l) => l !== listener),
    );
  }

  release(): void {
    this.child.stdin.end();
    this.child.kill("SIGTERM");
  }

  /** Hard-destroy the session so a session-scoped advisory lock dies with it. */
  end(): void {
    this.child.stdin.end();
    this.child.kill("SIGKILL");
  }

  #emit(event: "error" | "end", err?: Error): void {
    for (const listener of [...(this.#listeners.get(event) ?? [])]) listener(err);
  }
}

const sessions: PsqlSession[] = [];

/** A pool whose every checkout is a brand-new dedicated session — one process, one connection. */
const psqlPool: LeadershipLockPool = {
  connect: async () => {
    const session = new PsqlSession();
    sessions.push(session);
    return session;
  },
};

// A per-run lock id: advisory locks are database-scoped, and TEST_DATABASE_URL may be an
// externally pinned shared database, so a fixed id could collide with a concurrent lane.
const LOCK_ID = 0x300000 + (process.pid % 0x0fffff);

// set true only when the live block has confirmed PostgreSQL is reachable.
// A throwing beforeAll makes vitest report the gated tests as SKIPPED, not failed.
let liveReady = false;

afterEach(() => {
  while (sessions.length > 0) sessions.pop()?.child.kill("SIGKILL");
});

describe.skipIf(databaseUrl === undefined)("against a live PostgreSQL", () => {
  beforeAll(() => {
    // No silent no-op: TEST_DATABASE_URL set but unreachable FAILS the block loudly
    // (caught by the top-level PG_REQUIRED guard) instead of skipping every case.
    try {
      execFileSync("psql", ["-c", "SELECT 1"], {
        env: pgEnv(),
        encoding: "utf8",
        timeout: 10_000,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      const e = err as { stderr?: string };
      throw new Error(
        `TEST_DATABASE_URL is set but PostgreSQL is unreachable: ${e.stderr ?? String(err)}`,
      );
    }
    liveReady = true;
  });

  it("two genuinely concurrent acquirers contend and exactly one wins (AC1)", async () => {
    const latchA = new SignerLeadership();
    const latchB = new SignerLeadership();

    // Both attempts are in flight before either resolves — PostgreSQL, not this process,
    // decides the winner.
    const [a, b] = await Promise.all([
      tryAcquireSignerLeadership(psqlPool, latchA, LOCK_ID),
      tryAcquireSignerLeadership(psqlPool, latchB, LOCK_ID),
    ]);

    expect([a, b].filter((held) => held !== null)).toHaveLength(1);
    expect([latchA.held, latchB.held].filter(Boolean)).toEqual([true]);

    const loser = a === null ? latchA : latchB;
    expect(loser.reason).toBe(SignerLeadership.UNACQUIRED_REASON);
  });

  it("a third acquirer still loses while the leader holds the lock", async () => {
    const leaderLatch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(psqlPool, leaderLatch, LOCK_ID);
    expect(held).not.toBeNull();

    for (const _ of [0, 1]) {
      const latch = new SignerLeadership();
      expect(await tryAcquireSignerLeadership(psqlPool, latch, LOCK_ID)).toBeNull();
      expect(latch.held).toBe(false);
    }
    expect(leaderLatch.held).toBe(true);
  });

  it("graceful release hands leadership to the waiting instance (AC2)", async () => {
    const latchA = new SignerLeadership();
    const heldA = await tryAcquireSignerLeadership(psqlPool, latchA, LOCK_ID);
    expect(heldA).not.toBeNull();

    const latchB = new SignerLeadership();
    expect(await tryAcquireSignerLeadership(psqlPool, latchB, LOCK_ID)).toBeNull();

    await heldA?.release();
    expect(latchA.held).toBe(false);

    const heldB = await tryAcquireSignerLeadership(psqlPool, latchB, LOCK_ID);
    expect(heldB).not.toBeNull();
    expect(latchB.held).toBe(true);
  });

  it("connection death frees the lock server-side and drops the latch (AC5)", async () => {
    const latchA = new SignerLeadership();
    const heldA = await tryAcquireSignerLeadership(psqlPool, latchA, LOCK_ID);
    expect(heldA).not.toBeNull();
    const leaderSession = sessions.at(-1) as PsqlSession;

    const lost = new Promise<string>((resolve) => heldA?.onLost(resolve));

    // A failover, not a shutdown: the process is killed with no unlock and no chance to run
    // any release path.
    leaderSession.child.kill("SIGKILL");

    expect(await lost).toContain("end");
    expect(latchA.held).toBe(false);

    // The standby's jittered backoff acquires within a bounded number of attempts, and only
    // after PostgreSQL confirms the lock — never on the strength of the dead leader's age.
    const latchB = new SignerLeadership();
    const waits: number[] = [];
    const signal = { aborted: false };
    const heldB = await acquireSignerLeadership({
      pool: psqlPool,
      latch: latchB,
      lockId: LOCK_ID,
      baseDelayMs: 25,
      maxDelayMs: 200,
      onWaiting: ({ attempt, delayMs }) => {
        waits.push(delayMs);
        if (attempt >= 40) signal.aborted = true;
      },
      signal,
    });

    expect(heldB).not.toBeNull();
    expect(latchB.held).toBe(true);
    expect(waits.length).toBeLessThan(40);
  });

  it("the leader keeps the lock across an idle period no wall clock can revoke (AC5)", async () => {
    const latch = new SignerLeadership();
    const held = await tryAcquireSignerLeadership(psqlPool, latch, LOCK_ID);
    expect(held).not.toBeNull();

    await new Promise((resolve) => setTimeout(resolve, 1_500));

    const challenger = new SignerLeadership();
    expect(await tryAcquireSignerLeadership(psqlPool, challenger, LOCK_ID)).toBeNull();
    expect(latch.held).toBe(true);
  });
});

registerPgRequiredGuard({
  name: "signer leadership live block",
  databaseUrl,
  isReady: () => liveReady,
  readyMessage:
    "PG_REQUIRED=1 but the leadership beforeAll never completed — concurrent lock proofs skipped, not proven",
});
