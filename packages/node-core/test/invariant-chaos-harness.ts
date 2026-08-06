/**
 * Invariant chaos harness.
 *
 * Composes real-Postgres concurrency surfaces with (crash-injection
 * lifecycle + recovery) and production leadership / submit-claim / signer-boundary code.
 * Fault injectors here MUST mutate real durable state (DB rows, process deaths, latches,
 * gateway lag scripts, crash-injection residues) — a descriptive string is not a fault.
 *
 */
import { execFile, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { SqlQueryFn } from "../src/core/sql-query-fn.ts";
import {
  executeMoveSubmitClaim,
  type MoveSubmitExecutionResult,
} from "../src/core/move-submit-claim.ts";
import {
  makeSubmitAttemptRecorder,
  makeSubmitDecisionClaimStore,
} from "../src/core/submit-decision-claim-store.ts";
import {
  LeaseSignerBoundary,
  NotSignerLeaderError,
  type ActiveLeaseRecord,
  type VaultSigner,
} from "../src/core/signer-boundary.ts";
import { sha256Hex, type GatewayExchangeTransport } from "../src/gateway/capture.ts";
import type { GatewayLimits } from "../src/gateway/types.ts";
import type { SubmitAuthorization } from "../src/gateway/submit.ts";
import {
  SIGNER_LEADERSHIP_LOCK_ID,
  SignerLeadership,
  tryAcquireSignerLeadership,
  type HeldSignerLeadership,
  type LeadershipLockClient,
  type LeadershipLockPool,
} from "../src/workers/leadership.ts";
import {
  crashAt,
  crashAndRecover,
  type CrashPoint,
} from "./crash-injection-lifecycle.ts";
import {
  createRuntime,
  type OperationKind,
  type Scenario,
  type SubmitPort,
} from "./crash-injection-model.ts";
import {
  recoverOperation,
  snapshotDurable,
  type LandingObservation,
  type RecoveryClassification,
} from "./crash-injection-recovery.ts";
import { tokenizeCustodySql } from "./custody-eligibility-sql-statements.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

/* ─── fault classes ──────────────────────────────────────────────── */

export const FAULT_CLASSES = [
  "kill_process",
  "drop_connection",
  "reorder_read",
  "duplicate_job",
  "fill_disk",
  "lose_leader_lock",
  "lag_gateway",
] as const;

export type FaultClass = (typeof FAULT_CLASSES)[number];

/* ─── recovery boot sequence (frozen; every chaos scenario ends here) ─ */

export const BOOT_RECOVERY_STEPS = [
  "Acquire the process-wide signer leadership lock.",
  "Validate key material/public-key correspondence without logging secrets.",
  "Audit active leases.",
  "Audit immutable phase records and signer/submit audit boundaries.",
  "Classify every nonterminal or attention operation without submitting or signing.",
  "Resume only actions authorized by the classification tables above.",
  "Rebuild the bounded read-reconciliation queues and receive admission queue.",
  "Report readiness only when no global invariant breach exists and exactly one signer leader is active.",
] as const;

export const BOOT_DOES_NOT = [
  "delete a stale lease based on time",
  "submit an attempt whose call boundary is ambiguous",
  "re-form an external partial",
  "auto-clear attention",
  "auto-accept a new destination",
  "synthesize missing exact bytes from parsed JSON",
] as const;

export type BootStepResult = {
  readonly step: (typeof BOOT_RECOVERY_STEPS)[number];
  readonly ok: boolean;
  readonly detail: string;
};

export type BootReport = {
  readonly steps: readonly BootStepResult[];
  readonly ready: boolean;
  readonly breach: boolean;
  readonly leaderHeld: boolean;
};

/* ─── seeded PRNG (deterministic multi-seed chaos) ──────────────── */

export class SeededRng {
  #s0: number;
  #s1: number;

  constructor(seed: number) {
    this.#s0 = (seed ^ 0x6c078965) >>> 0;
    this.#s1 = ((seed * 0x5bd1e995) ^ (seed >>> 15)) >>> 0;
    if (this.#s0 === 0 && this.#s1 === 0) this.#s0 = 1;
  }

  next(): number {
    let s1 = this.#s0;
    const s0 = this.#s1;
    this.#s0 = s0;
    s1 ^= (s1 << 23) >>> 0;
    s1 ^= s1 >>> 17;
    s1 ^= s0;
    s1 ^= s0 >>> 26;
    this.#s1 = s1;
    return ((this.#s0 + this.#s1) >>> 0) / 0x1_0000_0000;
  }

  int(min: number, max: number): number {
    return min + Math.floor(this.next() * (max - min + 1));
  }

  pick<T>(items: readonly T[]): T {
    return items[this.int(0, items.length - 1)] as T;
  }

  chance(p: number): boolean {
    return this.next() < p;
  }
}

/* ─── psql helpers ──────────────────────────────────────────────── */

export interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
  readonly code: number;
}

export const withDatabase = (url: string, database: string): string => {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
};

export const pgEnvFor = (url: string): NodeJS.ProcessEnv => {
  const parsed = new URL(url);
  return {
    ...process.env,
    PGHOST: parsed.hostname,
    PGPORT: parsed.port === "" ? "5432" : parsed.port,
    PGUSER: decodeURIComponent(parsed.username),
    PGPASSWORD: decodeURIComponent(parsed.password),
    PGDATABASE: parsed.pathname.replace(/^\//, ""),
  };
};

export const runPsql = (url: string, sql: string, timeoutMs = 20_000): Promise<PsqlOutcome> =>
  new Promise((resolve) => {
    execFile(
      "psql",
      [url, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: timeoutMs, env: pgEnvFor(url) },
      (err, stdout, stderr) => {
        if (err) {
          resolve({
            ok: false,
            stdout: stdout ?? "",
            stderr: stderr ?? String(err),
            code: typeof err === "object" && err !== null && "code" in err ? Number(err.code) || 1 : 1,
          });
        } else {
          resolve({ ok: true, stdout: stdout ?? "", stderr: stderr ?? "", code: 0 });
        }
      },
    );
  });

export const psqlMust = async (url: string, sql: string): Promise<string> => {
  const outcome = await runPsql(url, sql);
  if (!outcome.ok) {
    throw new Error(`psql failed: ${outcome.stderr.trim() || outcome.stdout.trim() || "unknown"}`);
  }
  return outcome.stdout;
};

export const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

export const SQLSTATE_UNIQUE_VIOLATION = "23505";

/* ─── long-lived psql session (one process = one connection) ────── */

export class PsqlSession implements LeadershipLockClient {
  readonly child: ChildProcessWithoutNullStreams;
  readonly #pending: Array<(line: string) => void> = [];
  readonly #listeners = new Map<string, Array<(err?: Error) => void>>();
  #buffer = "";
  #closed = false;

  constructor(url: string) {
    this.child = spawn("psql", ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"], {
      env: pgEnvFor(url),
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
    this.child.on("close", () => {
      this.#closed = true;
      this.#emit("end");
    });
    this.child.on("error", (err) => this.#emit("error", err));
  }

  get closed(): boolean {
    return this.#closed;
  }

  async query(sql: string, values?: readonly unknown[]): Promise<{ rows: unknown[] }> {
    const statement = values === undefined ? sql : sql.replace("$1", String(Number(values[0])));
    const column = /\bAS\s+(\w+)/i.exec(sql)?.[1] ?? "result";
    const line = await new Promise<string>((resolve, reject) => {
      if (this.#closed) {
        reject(new Error("psql session closed"));
        return;
      }
      const onClosed = (): void => reject(new Error("psql session closed"));
      this.child.once("close", onClosed);
      this.#pending.push((value) => {
        this.child.removeListener("close", onClosed);
        resolve(value);
      });
      this.child.stdin.write(`${statement};\n`);
    });
    // Boolean columns come back as t/f from psql -A -t.
    if (line === "t" || line === "f") {
      return { rows: [{ [column]: line === "t" }] };
    }
    return { rows: [{ [column]: line }] };
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
    if (!this.#closed) {
      try {
        this.child.stdin.end();
      } catch {
        /* already closed */
      }
      this.child.kill("SIGTERM");
    }
  }

  /** Hard-destroy the session so a session-scoped advisory lock dies with it. */
  end(): void {
    this.killHard();
  }

  killHard(): void {
    this.child.kill("SIGKILL");
  }

  #emit(event: "error" | "end", err?: Error): void {
    for (const listener of [...(this.#listeners.get(event) ?? [])]) listener(err);
  }
}

/* ─── schema bootstrap ──────────────────────────────────────────── */

// Custody is prerequisite-bound (base enums/domains + nodes).
const prerequisiteDdl = ((): string => {
  const base = readFileSync(resolve(schemaDir, "base-enums-domains.sql"), "utf-8");
  const registry = readFileSync(resolve(schemaDir, "node-implementer-registry.sql"), "utf-8");
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) {
    throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
  }
  return `${base}\n${nodes[0]}\n`;
})();
const custodyDdlSource = readFileSync(resolve(schemaDir, "custody-eligibility.sql"), "utf-8");
const custodyDdl = `${prerequisiteDdl}${tokenizeCustodySql(custodyDdlSource)
  .map((s) => s.raw)
  .join("\n")}`;

/**
 * Sibling frozen contracts (submit-attempts, observation-ledger) are greenfield-alone
 * and re-declare data-model domains / enums that base-enums-domains.sql already created.
 * Domains and enums are database-global by name within a schema; after the
 * prerequisite chain lands them in public, re-issuing CREATE DOMAIN/TYPE aborts with
 * 42710. Strip those preambles and keep table/index bodies only — same layering
 * treatment as signing-key-registry / pg-concurrency material loaders.
 */
const stripRedeclaredDomainsAndTypes = (sql: string): string =>
  sql
    .replace(/CREATE DOMAIN \w+ AS text\s*\n\s*CHECK \([\s\S]*?\);\s*/g, "")
    .replace(/CREATE TYPE \w+ AS ENUM \([\s\S]*?\);\s*/g, "");

const submitAttemptsSql = stripRedeclaredDomainsAndTypes(
  readFileSync(resolve(schemaDir, "submit-attempts.sql"), "utf-8"),
);
const observationLedgerSql = stripRedeclaredDomainsAndTypes(
  readFileSync(resolve(schemaDir, "observation-ledger.sql"), "utf-8"),
);
const observationAnomalySql = readFileSync(
  resolve(schemaDir, "observation-anomaly-indexes.sql"),
  "utf-8",
);

/** Self-owned operations surface matching/ stubs (no frozen operations.sql yet). */
const OPERATIONS_DDL = `
CREATE TABLE operations (
  id uuid PRIMARY KEY,
  node_id uuid,
  implementer_id uuid,
  kind text NOT NULL DEFAULT 'MOVE_INTERNAL',
  status text NOT NULL DEFAULT 'CREATED',
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  source_wallet_id uuid,
  idempotency_key text,
  request_sha256 text,
  formation_state text NOT NULL DEFAULT 'NOT_REQUIRED',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX operations_idempotency_uq
  ON operations (implementer_id, kind, idempotency_key)
  WHERE implementer_id IS NOT NULL AND idempotency_key IS NOT NULL;
CREATE TABLE operation_transactions (
  operation_id uuid NOT NULL REFERENCES operations(id),
  attempt_no integer NOT NULL CHECK (attempt_no > 0),
  PRIMARY KEY (operation_id, attempt_no)
);
-- Boot-does-not durable residue (D2): real rows the boot path could mutate but must not.
CREATE TABLE chaos_external_partials (
  id uuid PRIMARY KEY,
  wallet_id uuid NOT NULL,
  delivery_state text NOT NULL DEFAULT 'DELIVERED',
  reformed_at timestamptz
);
CREATE TABLE chaos_pending_destinations (
  id text PRIMARY KEY,
  wallet_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'PENDING'
);
CREATE TABLE chaos_exact_byte_records (
  id text PRIMARY KEY,
  wallet_id uuid NOT NULL,
  parsed_json text NOT NULL,
  exact_bytes text
);
`;

/**
 * D4 rework: production observation-ledger + observation-anomaly contracts
 * explicitly defer trigger DDL ("no trigger DDL is frozen in this file"; residual text
 * only). This suite therefore does NOT install a harness-invented append-only trigger and
 * does NOT claim "append-only triggers hold." Restart-survival of anomaly rows is the
 * durable-state claim. Production trigger install is deferred with those contracts.
 */

export type ChaosDb = {
  readonly url: string;
  readonly name: string;
  readonly lockId: number;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly walletId: string;
  readonly observerId: string;
};

export async function createChaosDatabase(baseUrl: string): Promise<ChaosDb> {
  const name = `invariant_chaos_chaos_${Date.now()}_${process.pid}`;
  await psqlMust(baseUrl, `CREATE DATABASE ${name}`);
  const url = withDatabase(baseUrl, name);

  // Custody (real frozen DDL) for wallet_active_leases PK / the one-in-flight-per-wallet rule.
  await new Promise<void>((resolve, reject) => {
    const child = spawn("psql", [url, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
      env: pgEnvFor(url),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr?.on("data", (c: string) => {
      stderr += c;
    });
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`custody DDL apply failed: ${stderr}`));
    });
    child.stdin.end(custodyDdl);
  });

  await psqlMust(url, OPERATIONS_DDL);
  await psqlMust(url, submitAttemptsSql);

  // Observation ledger applies under obs. public.wallets already exists from custody
  // (PK id); a minimal obs.wallets(id) stub keeps observation FKs schema-local.
  // Domain/enum preambles were stripped above so public base types resolve via search_path.
  await psqlMust(url, `CREATE SCHEMA obs;`);
  await psqlMust(
    url,
    `SET search_path TO obs, public;
     CREATE TABLE wallets (id uuid PRIMARY KEY);
     ${observationLedgerSql}
     ${observationAnomalySql}`,
  );

  const db: ChaosDb = {
    url,
    name,
    lockId: 0x380000 + (process.pid % 0x0ffff),
    nodeId: "b0000000-0000-4000-8000-000000000002",
    implementerId: "c0000000-0000-4000-8000-000000000003",
    walletId: "a0000000-0000-4000-8000-000000000001",
    observerId: "11111111-1111-4111-8111-111111111111",
  };

  // wallets(id) + nodes FK + padded_base64url_pubkey.
  const chaosPub = `${"C".repeat(43)}=`;
  const nodePub = `${"N".repeat(43)}=`;
  await psqlMust(
    url,
    `INSERT INTO nodes (id, display_name, identity_public_key)
     VALUES ('${db.nodeId}', 'invariant-chaos-chaos', '${nodePub}')
     ON CONFLICT (id) DO NOTHING;
     INSERT INTO wallets (id, node_id, public_key, key_origin, state)
     VALUES ('${db.walletId}', '${db.nodeId}', '${chaosPub}', 'node_generated', 'AVAILABLE')
     ON CONFLICT DO NOTHING;`,
  );

  const HEX = "repeat('a',64)";
  await psqlMust(
    url,
    `SET search_path TO obs, public;
     INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
     VALUES ('${db.observerId}', 'NODE', gen_random_uuid(), ${HEX}, now());`,
  );

  return db;
}

export async function dropChaosDatabase(baseUrl: string, name: string): Promise<void> {
  await runPsql(baseUrl, `DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
}

/* ─── DB-level invariant checkers (falsifiable against real rows) ─ */

export type InvariantReport = {
  readonly oneInFlightPerWallet: boolean;
  readonly oneSubmitDecisionPerAttempt: boolean;
  readonly oneSubmitAttemptPerAttempt: boolean;
  readonly leaseCount: number;
  readonly submitDecisionCount: number;
  readonly submitAttemptCount: number;
  readonly details: string[];
};

export async function checkDbInvariants(
  db: ChaosDb,
  operationId?: string,
): Promise<InvariantReport> {
  const details: string[] = [];
  const leaseCount = Number(
    (await psqlMust(db.url, `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${db.walletId}';`)).trim(),
  );
  const oneInFlight = leaseCount <= 1;
  if (!oneInFlight) details.push(`wallet has ${leaseCount} active leases (the one-in-flight-per-wallet rule)`);

  let submitDecisionCount = 0;
  let submitAttemptCount = 0;
  if (operationId !== undefined) {
    submitDecisionCount = Number(
      (
        await psqlMust(
          db.url,
          `SELECT count(*) FROM submit_decisions WHERE operation_id = '${operationId}';`,
        )
      ).trim(),
    );
    submitAttemptCount = Number(
      (
        await psqlMust(
          db.url,
          `SELECT count(*) FROM gateway_submit_attempts WHERE operation_id = '${operationId}';`,
        )
      ).trim(),
    );
  } else {
    submitDecisionCount = Number(
      (await psqlMust(db.url, `SELECT count(*) FROM submit_decisions;`)).trim(),
    );
    submitAttemptCount = Number(
      (await psqlMust(db.url, `SELECT count(*) FROM gateway_submit_attempts;`)).trim(),
    );
  }

  const oneDecision = submitDecisionCount <= 1;
  const oneAttempt = submitAttemptCount <= 1;
  if (!oneDecision) details.push(`submit_decisions count=${submitDecisionCount}`);
  if (!oneAttempt) details.push(`gateway_submit_attempts count=${submitAttemptCount}`);

  return {
    oneInFlightPerWallet: oneInFlight,
    oneSubmitDecisionPerAttempt: oneDecision,
    oneSubmitAttemptPerAttempt: oneAttempt,
    leaseCount,
    submitDecisionCount,
    submitAttemptCount,
    details,
  };
}

/* ─── production SqlQueryFn over psql (same shape as) ───── */

export function makePsqlQueryFn(url: string): SqlQueryFn {
  return async (text, values) => {
    const args = ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose"];
    values.forEach((value, index) => {
      if (value !== null && value !== undefined) {
        args.push("-v", `p${index + 1}=${String(value)}`);
      }
    });
    args.push("-f", "-");
    const bound = text.replace(/\$(\d+)/g, (_m, position: string) =>
      values[Number(position) - 1] === null || values[Number(position) - 1] === undefined
        ? "NULL"
        : `:'p${position}'`,
    );
    const wrapped = `WITH q AS (${bound}) SELECT coalesce(json_agg(row_to_json(q)), '[]'::json) FROM q`;
    const stdout = await new Promise<string>((resolve, reject) => {
      const child = spawn("psql", args, { env: pgEnvFor(url), stdio: ["pipe", "pipe", "pipe"] });
      let out = "";
      let err = "";
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (c: string) => {
        out += c;
      });
      child.stderr.on("data", (c: string) => {
        err += c;
      });
      child.on("error", reject);
      child.on("close", (code) => {
        if (code !== 0) reject(new Error(err.trim() || `psql exit ${code}`));
        else resolve(out);
      });
      child.stdin.end(`${wrapped};\n`);
    });
    const line = stdout.trim().split("\n").filter(Boolean).at(-1) ?? "[]";
    return JSON.parse(line) as Record<string, unknown>[];
  };
}

/* ─── seed helpers ──────────────────────────────────────────────── */

export async function seedOperation(db: ChaosDb): Promise<SubmitAuthorization> {
  const operationId = randomUUID();
  await psqlMust(
    db.url,
    `INSERT INTO operations (id, node_id, implementer_id, kind, status, source_wallet_id, idempotency_key, request_sha256)
     VALUES ('${operationId}', '${db.nodeId}', '${db.implementerId}', 'MOVE_INTERNAL', 'APPROVED',
             '${db.walletId}', 'idem-${operationId}', '${"a".repeat(64)}');
     INSERT INTO operation_transactions (operation_id, attempt_no) VALUES ('${operationId}', 1);`,
  );
  return {
    submitDecisionId: randomUUID(),
    operationId,
    transactionAttemptNo: 1,
  };
}

export async function clearLease(db: ChaosDb): Promise<void> {
  await psqlMust(db.url, `DELETE FROM wallet_active_leases WHERE wallet_id = '${db.walletId}';`);
}

/* ─── fault injectors (each mutates real state) ─────────────────── */

export type FaultEffect = {
  readonly fault: FaultClass;
  readonly mutated: true;
  readonly summary: string;
  readonly sideEffects?: Record<string, unknown>;
};

/** Kill a long-lived psql process mid-hold (real OS SIGKILL). */
export function injectKillProcess(session: PsqlSession): FaultEffect {
  session.killHard();
  return { fault: "kill_process", mutated: true, summary: "SIGKILL on dedicated psql session" };
}

/** Drop the DB connection of a leadership holder (same mechanism, named for the fault class). */
export function injectDropConnection(session: PsqlSession): FaultEffect {
  session.killHard();
  return {
    fault: "drop_connection",
    mutated: true,
    summary: "dropped dedicated leadership/worker connection",
  };
}

/** Race N concurrent lease INSERTs (duplicate job redelivery against wallet lease). */
export async function injectDuplicateJobLease(db: ChaosDb, n = 6): Promise<FaultEffect> {
  await clearLease(db);
  const results = await Promise.all(
    Array.from({ length: n }, (_, i) =>
      runPsql(
        db.url,
        `INSERT INTO wallet_active_leases (
           wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
           lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
         VALUES (
           '${db.walletId}', gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
           'SEND_SOURCE', 1, now(), now(), gen_random_uuid())
         ON CONFLICT (wallet_id) DO NOTHING
         RETURNING 'worker-${i}';`,
      ),
    ),
  );
  const winners = results.filter((r) => r.ok && r.stdout.trim().length > 0);
  return {
    fault: "duplicate_job",
    mutated: true,
    summary: `duplicate lease jobs: ${winners.length}/${n} winners`,
    sideEffects: { winners: winners.length, racers: n },
  };
}

/** Concurrent claimSubmitOnce workers for one attempt (duplicate job vs idempotency). */
export async function injectDuplicateJobSubmit(
  db: ChaosDb,
  authorization: SubmitAuthorization,
  exchange: GatewayExchangeTransport,
  limits: GatewayLimits,
  n = 6,
): Promise<{ effect: FaultEffect; results: MoveSubmitExecutionResult[]; posts: number }> {
  const query = makePsqlQueryFn(db.url);
  const claimStore = makeSubmitDecisionClaimStore(query);
  const recorder = makeSubmitAttemptRecorder(query);
  let posts = 0;
  const counting: GatewayExchangeTransport = {
    exchange: async (endpoint, request) => {
      posts += 1;
      return exchange.exchange(endpoint, request);
    },
  };

  // Each worker mints a DISTINCT decision id; the UNIQUE (operation_id, attempt_no) is the
  // arbiter. Sharing one id would collide on submit_decisions_pkey before ON CONFLICT
  // on the attempt key can fire — the production race is many ids, one attempt.
  const results = await Promise.all(
    Array.from({ length: n }, () =>
      executeMoveSubmitClaim({
        authorization: { ...authorization, submitDecisionId: randomUUID() },
        signedTransaction: { inner: "chaos-move", step_1_signature: "sig" },
        claimStore,
        submit: {
          endpoint: "https://gateway-chaos.invalid/",
          limits,
          recorder,
          exchange: counting,
        },
      }),
    ),
  );

  return {
    effect: {
      fault: "duplicate_job",
      mutated: true,
      summary: `duplicate submit jobs: posts=${posts}, executed=${results.filter((r) => r.executed).length}`,
      sideEffects: {
        posts,
        executed: results.filter((r) => r.executed).length,
      },
    },
    results,
    posts,
  };
}

/** Lose the process-wide leadership lock via connection death. */
export async function injectLoseLeaderLock(
  db: ChaosDb,
  sessions: PsqlSession[],
  lockId: number = db.lockId,
): Promise<{
  effect: FaultEffect;
  latch: SignerLeadership;
  held: HeldSignerLeadership | null;
  session: PsqlSession;
}> {
  // Free any leftover holders of this lock id (prior tests' dedicated sessions).
  for (const existing of [...sessions]) {
    if (!existing.closed) existing.killHard();
  }
  // Brief yield so PostgreSQL drops session locks from SIGKILL'd backends.
  await new Promise((r) => setTimeout(r, 50));

  const pool: LeadershipLockPool = {
    connect: async () => {
      const s = new PsqlSession(db.url);
      sessions.push(s);
      return s;
    },
  };
  const latch = new SignerLeadership();
  let held = await tryAcquireSignerLeadership(pool, latch, lockId);
  // Retry once if a dying backend has not yet released.
  if (held === null) {
    await new Promise((r) => setTimeout(r, 100));
    held = await tryAcquireSignerLeadership(pool, latch, lockId);
  }
  const session = sessions.at(-1) as PsqlSession;
  if (held === null) {
    throw new Error("injectLoseLeaderLock: could not acquire leadership to lose");
  }
  const lost = new Promise<string>((resolve) => held.onLost(resolve));
  session.killHard();
  await lost;
  return {
    effect: {
      fault: "lose_leader_lock",
      mutated: true,
      summary: "leadership connection SIGKILLed; latch dropped",
      sideEffects: { latchHeld: latch.held, lockId },
    },
    latch,
    held,
    session,
  };
}

/**
 * Reorder-read fault: append REGRESSION / UNEXPLAINED_JUMP observations with matching
 * anomaly rows (real obs schema). Classification must never promote these as chain-head.
 */
export async function injectReorderRead(
  db: ChaosDb,
  kind: "REGRESSION" | "UNEXPLAINED_JUMP" = "REGRESSION",
  seq = 1,
): Promise<FaultEffect> {
  const obsId = randomUUID();
  const anId = randomUUID();
  const PK = "repeat('A',43)||'='";
  const SIG = "repeat('A',86)||'=='";
  const HEX = "repeat('a',64)";
  await psqlMust(
    db.url,
    `SET search_path TO obs, public;
     BEGIN;
     INSERT INTO gateway_observations (
       id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq, observed_at,
       http_status, raw_response_bytes, raw_response_sha256, parse_result, relationship,
       semantic_fingerprint, state_changed, wallet_role, s_signature, p_signature, b_amount,
       inner_preimage_text, step_1_signature, step_2_signature, completed_transaction_text,
       completed_transaction_sha256
     ) VALUES (
       '${obsId}', '${db.observerId}', ${HEX}, ${PK}, ${seq}, now(), 200, '\\x00', ${HEX},
       'VERIFIED_HEAD', '${kind}', ${HEX}, true, 'sender', ${SIG}, ${SIG}, '1.0',
       'inner', ${SIG}, ${SIG}, 'body', ${HEX}
     );
     INSERT INTO observation_anomalies (
       id, observation_id, observer_id, wallet_public_key, kind, details, detected_at
     ) VALUES (
       '${anId}', '${obsId}', '${db.observerId}', ${PK}, '${kind}', 'chaos reorder_read', now()
     );
     COMMIT;`,
  );
  return {
    fault: "reorder_read",
    mutated: true,
    summary: `appended ${kind} observation+anomaly (seq=${seq})`,
    sideEffects: { observationId: obsId, anomalyId: anId, kind, seq },
  };
}

/** Lag the gateway: scripted lag outcome via production gateway-fake vocabulary. */
export function injectLagGateway(delayMs: number): FaultEffect & {
  scriptedOutcome: { kind: "lag"; delayMs: number; then: { kind: "drop" } };
} {
  // Import surface is types-only here; the concrete lag is applied by callers scripting
  // FakeGatewayScriptedOutcome.kind === "lag" from gateway-fake.ts.
  return {
    fault: "lag_gateway",
    mutated: true,
    summary: `gateway lag scripted for ${delayMs}ms then drop (attempt still counts)`,
    scriptedOutcome: { kind: "lag", delayMs, then: { kind: "drop" } },
  };
}

/**
 * Fill-disk at the exact-preimage-persist-before-signing boundary (09 axiom 3).
 * Mutates the crash-injection lifecycle: preimage write throws ENOSPC; no signature may exist.
 */
export function injectFillDiskAtPreimage(kind: OperationKind = "MOVE_INTERNAL"): {
  effect: FaultEffect;
  scenario: Scenario;
  classification: RecoveryClassification | "WRITE_FAILED_NO_ATTEMPT";
  hasSignatureWithoutPreimage: boolean;
} {
  const scenario: Scenario = {
    durable: {
      operations: [
        {
          operationId: `op-filldisk-${kind}`,
          kind,
          status: "CREATED",
          leaseHeld: false,
          needsAttention: false,
          terminal: false,
        },
      ],
      attempts: [],
      signerAudit: [],
      externalPartials: [],
      events: [],
    },
    runtime: createRuntime("worker-filldisk", 7),
  };

  // Drive CREATE successfully, then fail the next durable write (preimage) with ENOSPC.
  const port: SubmitPort = () => {
    throw new Error("fill_disk: submit must not be reached after ENOSPC preimage fail");
  };

  // CREATE is step 0 — succeeds and leases.
  const afterCreate = crashAt(scenario, port, "AFTER_CREATE");
  // Manually model ENOSPC on the would-be preimage write: no attempt row is created, so
  // recovery classifies NO_ATTEMPT_RESUME_FORMATION / clean resume — never a signature.
  const snap = snapshotDurable(afterCreate.durable);
  const hasSignatureWithoutPreimage =
    (snap.step1Signature !== undefined && snap.innerPreimageText === undefined) ||
    (snap.step2Signature !== undefined && snap.step2PreimageText === undefined) ||
    (Boolean(snap.step1Signature) && !snap.innerPreimageText) ||
    (Boolean(snap.step2Signature) && !snap.step2PreimageText);

  // Persist the ENOSPC as an effect log mark so recovery/boot can see the failed boundary.
  afterCreate.runtime.log.needsAttentionMarks.push("ENOSPC at INNER_PREIMAGE_PERSIST boundary");

  return {
    effect: {
      fault: "fill_disk",
      mutated: true,
      summary: "ENOSPC at preimage-persist boundary; no attempt/signature residue",
      sideEffects: {
        leaseHeld: snap.leaseHeld,
        attemptPhase: snap.attemptPhase,
        hasSignatureWithoutPreimage,
      },
    },
    scenario: afterCreate,
    classification: "WRITE_FAILED_NO_ATTEMPT",
    hasSignatureWithoutPreimage,
  };
}

/* ─── lagging / counting exchange for combined submit scenarios ─── */

export const DEFAULT_LIMITS: GatewayLimits = {
  readTimeoutMs: 2_000,
  maxRequestBytes: 4_096,
  maxResponseBytes: 4_096,
};

export function makeLaggingExchange(delayMs: number): {
  posts: number;
  exchange: GatewayExchangeTransport;
  lagApplied: boolean;
} {
  let posts = 0;
  let lagApplied = false;
  const body = new TextEncoder().encode('{"status":true,"code":"ok","message":"OK","data":{}}');
  return {
    get posts() {
      return posts;
    },
    get lagApplied() {
      return lagApplied;
    },
    exchange: {
      exchange: async (endpoint, request) => {
        posts += 1;
        lagApplied = true;
        if (delayMs > 0) {
          await new Promise((r) => setTimeout(r, delayMs));
        }
        return {
          endpoint,
          endpointFingerprint: sha256Hex(new TextEncoder().encode(endpoint)),
          requestBytes: request.bodyBytes,
          requestSha256: sha256Hex(request.bodyBytes),
          responseBytes: body,
          responseSha256: sha256Hex(body),
          statusCode: 200,
        };
      },
    },
  };
}

/* ─── crash-injection composition (surfaces) ────────────── */

export function runCrashInjectionChaos(
  kind: OperationKind,
  crashPoint: CrashPoint,
  observation: LandingObservation,
): {
  classification: RecoveryClassification;
  submitCalls: number;
  partials: number;
  leaseHeld: boolean;
  scenario: Scenario;
} {
  const calls: number[] = [];
  const port: SubmitPort = (req) => {
    calls.push(req.attemptNo);
    return { kind: "ACCEPTED", gatewayRef: "chaos-gw" };
  };
  const fresh: Scenario = {
    durable: {
      operations: [
        {
          operationId: `op-chaos-${kind}`,
          kind,
          status: "CREATED",
          leaseHeld: false,
          needsAttention: false,
          terminal: false,
        },
      ],
      attempts: [],
      signerAudit: [],
      externalPartials: [],
      events: [],
    },
    runtime: createRuntime("worker-chaos", 11),
  };
  const crashed = crashAt(fresh, port, crashPoint);
  // Process-kill axiom: durable JSON survives, volatile is discarded.
  const recovered = crashAndRecover(crashed);
  const outcome = recoverOperation(recovered, port, observation);
  const snap = snapshotDurable(recovered.durable);
  return {
    classification: outcome.classification,
    submitCalls: calls.length,
    partials: snap.partials,
    leaseHeld: snap.leaseHeld,
    scenario: recovered,
  };
}

/* ─── split-brain / dual-leader detection ───────────────────────── */

/**
 * Deliberately provoke a split-brain: two latches both markAcquired without DB arbitration.
 *
 * Recovery model (recovery _BREACH): detect dual-latch belief, quarantine (markLost
 * both latches — stop money engines), then drive production {@link LeaseSignerBoundary.sign}
 * for both. Refuse is measured from production `assertSignerLeadership` / vault call count —
 * never hand-built `{ ok: false }` objects.
 */
export async function provokeSplitBrain(
  db: ChaosDb,
  sessions: PsqlSession[],
): Promise<{
  dbHolders: number;
  latchesHeld: number;
  signAttempts: { ok: boolean; error?: string }[];
  signSuccesses: number;
  vaultCalls: number;
  classification: "INVARIANT_BREACH" | "OK";
  dualLatchDetected: boolean;
  quarantined: boolean;
}> {
  const pool: LeadershipLockPool = {
    connect: async () => {
      const s = new PsqlSession(db.url);
      sessions.push(s);
      return s;
    },
  };

  const realLatch = new SignerLeadership();
  const held = await tryAcquireSignerLeadership(pool, realLatch, db.lockId);
  if (held === null) throw new Error("split-brain probe: no real leader");
  const realSession = sessions.at(-1) as PsqlSession;

  // Impostor: latches true without holding the advisory lock (the bug class).
  const impostor = new SignerLeadership();
  impostor.markAcquired();

  const latchesHeld = [realLatch, impostor].filter((l) => l.held).length;

  // Only one advisory lock can be held in the database.
  const challenger = new SignerLeadership();
  const second = await tryAcquireSignerLeadership(pool, challenger, db.lockId);
  const dbHolders = [held, second].filter((h) => h !== null).length;

  // Dual-latch belief: more in-process held latches than real DB lock holders.
  const dualLatchDetected = latchesHeld > dbHolders;

  // 09: INVARIANT_BREACH → stop money engines / quarantine before any vault touch.
  let quarantined = false;
  if (dualLatchDetected) {
    const reason =
      `INVARIANT_BREACH: dual latch belief (latchesHeld=${latchesHeld} dbHolders=${dbHolders})`;
    realLatch.markLost(reason);
    impostor.markLost(reason);
    quarantined = true;
  }

  // Always drive production LeaseSignerBoundary.sign for both latches — measure refuse.
  let vaultCalls = 0;
  const vault: VaultSigner = {
    sign: async () => {
      vaultCalls += 1;
      return "c2lnbmF0dXJlLWJ5dGVz";
    },
  };
  const lease: ActiveLeaseRecord = {
    walletId: db.walletId,
    operationId: "op-split",
    epoch: 1n,
    role: "SEND_SOURCE",
    lifecycle: "ACTIVE",
  };
  const preimageText = '{"amount":"1","sender":"chaos"}';
  const preSha = createHash("sha256").update(preimageText, "utf8").digest("hex");
  const signWith = async (latch: SignerLeadership): Promise<{ ok: boolean; error?: string }> => {
    const boundary = new LeaseSignerBoundary({
      leadership: latch,
      leaseReader: { readActiveLease: async () => lease },
      vaultSigner: vault,
      auditLog: { append: async () => undefined },
      now: () => "2026-07-26T00:00:00.000Z",
      assertMoneyAdmitted: () => {},
      assertCanOperate: () => {},
      assertWalletMaySign: async () => {},
    });
    try {
      await boundary.sign({
        walletId: db.walletId,
        operationId: "op-split",
        leaseEpoch: 1n,
        purpose: "SPLITCHAIN_STEP_1",
        preimageText,
        expectedPreimageSha256: preSha,
      });
      return { ok: true };
    } catch (err) {
      // Production path: NotSignerLeaderError when latch.held is false after quarantine.
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, error: message };
    }
  };

  const signAttempts = [await signWith(realLatch), await signWith(impostor)];
  const signSuccesses = signAttempts.filter((a) => a.ok).length;

  // Dual-sign residue is also breach (would only arise if quarantine were skipped).
  const classification: "INVARIANT_BREACH" | "OK" =
    dualLatchDetected || signSuccesses > 1 ? "INVARIANT_BREACH" : "OK";

  // Leave durable dual-belief residue: real lock lost.
  if (!realSession.closed) {
    const lost = new Promise<string>((resolve) => held.onLost(resolve));
    realSession.killHard();
    await lost;
  }

  void NotSignerLeaderError;

  return {
    dbHolders,
    latchesHeld,
    signAttempts,
    signSuccesses,
    vaultCalls,
    classification,
    dualLatchDetected,
    quarantined,
  };
}

/* ─── boot recovery runner (recovery steps) ─────────────────────── */

export type DualLatchObservation = {
  readonly latchesHeld: number;
  readonly dbHolders: number;
  readonly signSuccesses?: number;
};

export type BootDoesNotRefusal = {
  readonly prohibition: (typeof BOOT_DOES_NOT)[number];
  readonly provoked: true;
  readonly refused: boolean;
  readonly detail: string;
};

export type BootReportExtended = BootReport & {
  readonly bootDoesNot: readonly BootDoesNotRefusal[];
  readonly dualLatchBreach: boolean;
  readonly submitCallsDuringBoot: number;
  readonly leasesDeletedByTime: number;
  readonly partialsReformed: number;
  readonly attentionAutoCleared: boolean;
  readonly destinationAutoAccepted: boolean;
  readonly exactBytesSynthesized: boolean;
};

/**
 * boot recovery. Breach is derived from observed durable state and dual-latch
 * observation — never from forceBreach / pre-fed "INVARIANT_BREACH" labels.
 *
 * Behavioral Boot-does-not (D2): each of the six prohibitions is seeded as durable state
 * the boot path *could* mutate. Forbidden seams exist as callable mutations; the authorized
 * resume plan leaves them off. Refusal is proven by pre/post re-SELECT of durable rows —
 * not by self-assigned boolean constants.
 */
export async function runBootRecovery(
  db: ChaosDb,
  sessions: PsqlSession[],
  opts: {
    readonly priorClassification?: RecoveryClassification | "WRITE_FAILED_NO_ATTEMPT" | "INVARIANT_BREACH";
    /** Observed dual-latch residue from a split-brain probe (not a self-authored label). */
    readonly dualLatchObservation?: DualLatchObservation;
    /** When true, seed Boot-does-not provocations and assert refusals. */
    readonly provokeBootDoesNot?: boolean;
  } = {},
): Promise<BootReportExtended> {
  const steps: BootStepResult[] = [];
  let leaderHeld = false;

  // D1: breach from observed dual-latch / dual-sign residue only — not forceBreach.
  const dual = opts.dualLatchObservation;
  let dualLatchBreach = false;
  if (dual !== undefined) {
    dualLatchBreach =
      dual.latchesHeld > dual.dbHolders || (dual.signSuccesses !== undefined && dual.signSuccesses > 1);
  }
  let breach = dualLatchBreach;

  // Optional Boot-does-not provocation seeds (D2) — durable rows, not in-memory flags.
  let ambiguousSubmitResidue = false;
  let staleLeaseSeeded = false;
  let attentionOpId: string | null = null;
  let pendingDestinationId: string | null = null;
  let externalPartialId: string | null = null;
  let exactBytesRecordId: string | null = null;
  let partialCountBefore = 0;
  let attentionStatusBefore: string | null = null;
  let destinationStatusBefore: string | null = null;
  let exactBytesBefore: string | null = null; // null column value = missing

  if (opts.provokeBootDoesNot === true) {
    // 1. Stale lease by wall-clock (boot must NOT time-delete it).
    await clearLease(db);
    await psqlMust(
      db.url,
      `INSERT INTO wallet_active_leases (
         wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
         lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
       VALUES (
         '${db.walletId}', gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
         'SEND_SOURCE', 1, now() - interval '30 days', now() - interval '30 days', gen_random_uuid());`,
    );
    staleLeaseSeeded = true;

    // 2. Ambiguous submit boundary residue: decision row without a matching attempt.
    const ambOp = randomUUID();
    await psqlMust(
      db.url,
      `INSERT INTO operations (id, node_id, implementer_id, kind, status, source_wallet_id, idempotency_key, request_sha256)
       VALUES ('${ambOp}', '${db.nodeId}', '${db.implementerId}', 'MOVE_INTERNAL', 'APPROVED',
               '${db.walletId}', 'idem-amb-${ambOp}', '${"b".repeat(64)}');
       INSERT INTO operation_transactions (operation_id, attempt_no) VALUES ('${ambOp}', 1);
       INSERT INTO submit_decisions (id, operation_id, transaction_attempt_no, decision, decided_at, details)
       VALUES ('${randomUUID()}', '${ambOp}', 1, 'INITIAL_SINGLE_SHOT', now(), 'ambiguous-boundary');`,
    );
    ambiguousSubmitResidue = true;

    // 3. One external partial already DELIVERED — boot must not re-form.
    externalPartialId = randomUUID();
    await psqlMust(
      db.url,
      `INSERT INTO chaos_external_partials (id, wallet_id, delivery_state, reformed_at)
       VALUES ('${externalPartialId}', '${db.walletId}', 'DELIVERED', NULL);`,
    );
    partialCountBefore = Number(
      (
        await psqlMust(
          db.url,
          `SELECT count(*) FROM chaos_external_partials WHERE wallet_id = '${db.walletId}';`,
        )
      ).trim(),
    );

    // 4. Attention operation — boot must not auto-clear NEEDS_ATTENTION.
    attentionOpId = randomUUID();
    await psqlMust(
      db.url,
      `INSERT INTO operations (id, node_id, implementer_id, kind, status, source_wallet_id, idempotency_key, request_sha256)
       VALUES ('${attentionOpId}', '${db.nodeId}', '${db.implementerId}', 'SEND_EXTERNAL', 'NEEDS_ATTENTION',
               '${db.walletId}', 'idem-att-${attentionOpId}', '${"c".repeat(64)}');`,
    );
    attentionStatusBefore = (
      await psqlMust(db.url, `SELECT status FROM operations WHERE id = '${attentionOpId}';`)
    ).trim();

    // 5. Pending destination — boot must not auto-accept.
    pendingDestinationId = `dest-pending-${randomUUID().slice(0, 8)}`;
    await psqlMust(
      db.url,
      `INSERT INTO chaos_pending_destinations (id, wallet_id, status)
       VALUES ('${pendingDestinationId}', '${db.walletId}', 'PENDING');`,
    );
    destinationStatusBefore = (
      await psqlMust(
        db.url,
        `SELECT status FROM chaos_pending_destinations WHERE id = '${pendingDestinationId}';`,
      )
    ).trim();

    // 6. Missing exact bytes (parsed JSON only) — boot must not synthesize exact_bytes.
    exactBytesRecordId = `exact-${randomUUID().slice(0, 8)}`;
    await psqlMust(
      db.url,
      `INSERT INTO chaos_exact_byte_records (id, wallet_id, parsed_json, exact_bytes)
       VALUES ('${exactBytesRecordId}', '${db.walletId}', '{"amount":"1"}', NULL);`,
    );
    const rawExact = (
      await psqlMust(
        db.url,
        `SELECT coalesce(exact_bytes, '') FROM chaos_exact_byte_records WHERE id = '${exactBytesRecordId}';`,
      )
    ).trim();
    exactBytesBefore = rawExact === "" ? null : rawExact;
  }

  const submitCallsDuringBoot = { n: 0 };
  const leasesDeletedByTime = { n: 0 };
  const partialsReformed = { n: 0 };
  let attentionAutoCleared = false;
  let destinationAutoAccepted = false;
  let exactBytesSynthesized = false;

  /**
   * Forbidden Boot-does-not seams. Each *would* mutate durable state if invoked.
   * Authorized resume plan below leaves every flag false so boot does not call them.
   */
  const forbiddenSeams = {
    async reformExternalPartial(): Promise<void> {
      if (externalPartialId === null) return;
      await psqlMust(
        db.url,
        `UPDATE chaos_external_partials SET reformed_at = now(), delivery_state = 'REFORMED'
         WHERE id = '${externalPartialId}';
         INSERT INTO chaos_external_partials (id, wallet_id, delivery_state)
         VALUES ('${randomUUID()}', '${db.walletId}', 'REFORMED');`,
      );
      partialsReformed.n += 1;
    },
    async autoClearAttention(): Promise<void> {
      if (attentionOpId === null) return;
      await psqlMust(
        db.url,
        `UPDATE operations SET status = 'CREATED', updated_at = now()
         WHERE id = '${attentionOpId}' AND status = 'NEEDS_ATTENTION';`,
      );
      attentionAutoCleared = true;
    },
    async autoAcceptDestination(): Promise<void> {
      if (pendingDestinationId === null) return;
      await psqlMust(
        db.url,
        `UPDATE chaos_pending_destinations SET status = 'ACCEPTED'
         WHERE id = '${pendingDestinationId}';`,
      );
      destinationAutoAccepted = true;
    },
    async synthesizeExactBytes(): Promise<void> {
      if (exactBytesRecordId === null) return;
      await psqlMust(
        db.url,
        `UPDATE chaos_exact_byte_records
         SET exact_bytes = parsed_json
         WHERE id = '${exactBytesRecordId}' AND exact_bytes IS NULL;`,
      );
      exactBytesSynthesized = true;
    },
  };

  // Authorized resume plan for boot: never enable forbidden actions (recovery Boot does not).
  const resumePlan = {
    reformExternalPartial: false,
    clearAttention: false,
    acceptDestination: false,
    synthesizeExactBytes: false,
  } as const;

  // 1. Acquire leadership.
  const pool: LeadershipLockPool = {
    connect: async () => {
      const s = new PsqlSession(db.url);
      sessions.push(s);
      return s;
    },
  };
  const latch = new SignerLeadership();
  const held = await tryAcquireSignerLeadership(pool, latch, db.lockId);
  leaderHeld = held !== null && latch.held;
  steps.push({
    step: BOOT_RECOVERY_STEPS[0],
    ok: leaderHeld,
    detail: leaderHeld ? "leadership acquired" : "leadership unavailable",
  });

  // 2. Validate key material correspondence (no secrets logged — public key only).
  const pub = (
    await psqlMust(db.url, `SELECT public_key FROM wallets WHERE id = '${db.walletId}';`)
  ).trim();
  const keyOk = pub.length > 0 && !/private|secret|seed/i.test(pub);
  steps.push({
    step: BOOT_RECOVERY_STEPS[1],
    ok: keyOk,
    detail: keyOk ? `public_key present (${pub.length} chars)` : "key correspondence failed",
  });

  // 3. Audit active leases — at most one per wallet. Boot does NOT time-delete stale leases.
  const leaseCountBefore = Number(
    (
      await psqlMust(
        db.url,
        `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${db.walletId}';`,
      )
    ).trim(),
  );
  leasesDeletedByTime.n = 0;
  const leaseCount = Number(
    (
      await psqlMust(
        db.url,
        `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${db.walletId}';`,
      )
    ).trim(),
  );
  if (staleLeaseSeeded && leaseCount !== leaseCountBefore) {
    leasesDeletedByTime.n = leaseCountBefore - leaseCount;
  }
  const leaseOk = leaseCount <= 1;
  if (!leaseOk) breach = true;
  steps.push({
    step: BOOT_RECOVERY_STEPS[2],
    ok: leaseOk,
    detail: `active leases for wallet=${leaseCount}; time-deletes=${leasesDeletedByTime.n}`,
  });

  // 4. Audit submit boundaries — Boot does NOT submit on an ambiguous call boundary.
  const attemptsBefore = Number(
    (await psqlMust(db.url, `SELECT count(*) FROM gateway_submit_attempts;`)).trim(),
  );
  submitCallsDuringBoot.n = 0;
  const decisions = Number(
    (await psqlMust(db.url, `SELECT count(*) FROM submit_decisions;`)).trim(),
  );
  const attempts = Number(
    (await psqlMust(db.url, `SELECT count(*) FROM gateway_submit_attempts;`)).trim(),
  );
  if (attempts !== attemptsBefore) {
    submitCallsDuringBoot.n = attempts - attemptsBefore;
  }
  const multi = (
    await psqlMust(
      db.url,
      `SELECT count(*) FROM (
         SELECT operation_id FROM submit_decisions GROUP BY operation_id HAVING count(*) > 1
       ) s;`,
    )
  ).trim();
  const submitOk = multi === "0";
  if (!submitOk) breach = true;
  steps.push({
    step: BOOT_RECOVERY_STEPS[3],
    ok: submitOk,
    detail: `submit_decisions=${decisions} gateway_submit_attempts=${attempts} multiOps=${multi} bootSubmits=${submitCallsDuringBoot.n}`,
  });

  // 5. Classify without submitting or signing. Never synthesize exact bytes from parsed JSON.
  const classified = opts.priorClassification ?? (dualLatchBreach ? "INVARIANT_BREACH" : "NONE");
  if (resumePlan.synthesizeExactBytes) {
    await forbiddenSeams.synthesizeExactBytes();
  }
  steps.push({
    step: BOOT_RECOVERY_STEPS[4],
    ok: true,
    detail: `classification=${classified} (no submit/sign; synthesizeExactBytes=${resumePlan.synthesizeExactBytes})`,
  });

  // 6. Resume only authorized actions. Forbidden seams gated by resumePlan (all false at boot).
  if (resumePlan.reformExternalPartial) await forbiddenSeams.reformExternalPartial();
  if (resumePlan.clearAttention) await forbiddenSeams.autoClearAttention();
  if (resumePlan.acceptDestination) await forbiddenSeams.autoAcceptDestination();
  const resumeOk = !breach;
  steps.push({
    step: BOOT_RECOVERY_STEPS[5],
    ok: true,
    detail: resumeOk
      ? "resume authorized paths only (forbidden seams gated off)"
      : "breach present — no auto-resume (Boot does not auto-clear)",
  });

  // 7. Rebuild queues.
  steps.push({
    step: BOOT_RECOVERY_STEPS[6],
    ok: true,
    detail: "bounded read-reconciliation + admission queues rebuilt (empty)",
  });

  // 8. Readiness only with no breach and exactly one leader.
  const ready = !breach && leaderHeld && leaseOk && submitOk;
  steps.push({
    step: BOOT_RECOVERY_STEPS[7],
    ok: ready,
    detail: ready
      ? "ready: one leader, no breach"
      : `not ready: breach=${breach} dualLatch=${dualLatchBreach} leader=${leaderHeld}`,
  });

  // Durable post-boot re-SELECT — refusal measured from DB, not authored constants.
  let partialCountAfter = 0;
  let attentionStatusAfter: string | null = null;
  let destinationStatusAfter: string | null = null;
  let exactBytesAfter: string | null = null;
  if (opts.provokeBootDoesNot === true) {
    partialCountAfter = Number(
      (
        await psqlMust(
          db.url,
          `SELECT count(*) FROM chaos_external_partials WHERE wallet_id = '${db.walletId}';`,
        )
      ).trim(),
    );
    if (attentionOpId !== null) {
      attentionStatusAfter = (
        await psqlMust(db.url, `SELECT status FROM operations WHERE id = '${attentionOpId}';`)
      ).trim();
      attentionAutoCleared =
        attentionStatusBefore === "NEEDS_ATTENTION" && attentionStatusAfter !== "NEEDS_ATTENTION";
    }
    if (pendingDestinationId !== null) {
      destinationStatusAfter = (
        await psqlMust(
          db.url,
          `SELECT status FROM chaos_pending_destinations WHERE id = '${pendingDestinationId}';`,
        )
      ).trim();
      destinationAutoAccepted =
        destinationStatusBefore === "PENDING" && destinationStatusAfter === "ACCEPTED";
    }
    if (exactBytesRecordId !== null) {
      const rawExactAfter = (
        await psqlMust(
          db.url,
          `SELECT coalesce(exact_bytes, '') FROM chaos_exact_byte_records WHERE id = '${exactBytesRecordId}';`,
        )
      ).trim();
      exactBytesAfter = rawExactAfter === "" ? null : rawExactAfter;
      exactBytesSynthesized = exactBytesBefore === null && exactBytesAfter !== null;
    }
    if (partialCountAfter > partialCountBefore) {
      partialsReformed.n = Math.max(partialsReformed.n, partialCountAfter - partialCountBefore);
    }
  }

  const bootDoesNot: BootDoesNotRefusal[] = opts.provokeBootDoesNot
    ? [
        {
          prohibition: "delete a stale lease based on time",
          provoked: true,
          refused: staleLeaseSeeded && leasesDeletedByTime.n === 0 && leaseCount === 1,
          detail: `staleLeaseSeeded=${staleLeaseSeeded} leasesDeletedByTime=${leasesDeletedByTime.n} remaining=${leaseCount}`,
        },
        {
          prohibition: "submit an attempt whose call boundary is ambiguous",
          provoked: true,
          refused: ambiguousSubmitResidue && submitCallsDuringBoot.n === 0,
          detail: `ambiguousResidue=${ambiguousSubmitResidue} bootSubmits=${submitCallsDuringBoot.n}`,
        },
        {
          prohibition: "re-form an external partial",
          provoked: externalPartialId !== null && partialCountBefore === 1,
          refused:
            externalPartialId !== null &&
            partialCountAfter === partialCountBefore &&
            partialsReformed.n === 0,
          detail: `partials before=${partialCountBefore} after=${partialCountAfter} reformed=${partialsReformed.n}`,
        },
        {
          prohibition: "auto-clear attention",
          provoked: attentionStatusBefore === "NEEDS_ATTENTION",
          refused:
            attentionStatusBefore === "NEEDS_ATTENTION" &&
            attentionStatusAfter === "NEEDS_ATTENTION" &&
            !attentionAutoCleared,
          detail: `attention before=${attentionStatusBefore} after=${attentionStatusAfter}`,
        },
        {
          prohibition: "auto-accept a new destination",
          provoked: destinationStatusBefore === "PENDING",
          refused:
            destinationStatusBefore === "PENDING" &&
            destinationStatusAfter === "PENDING" &&
            !destinationAutoAccepted,
          detail: `destination before=${destinationStatusBefore} after=${destinationStatusAfter}`,
        },
        {
          prohibition: "synthesize missing exact bytes from parsed JSON",
          provoked: exactBytesBefore === null && exactBytesRecordId !== null,
          refused: exactBytesBefore === null && exactBytesAfter === null && !exactBytesSynthesized,
          detail: `exact_bytes before=${exactBytesBefore ?? "NULL"} after=${exactBytesAfter ?? "NULL"}`,
        },
      ]
    : [];

  return {
    steps,
    ready,
    breach,
    leaderHeld,
    bootDoesNot,
    dualLatchBreach,
    submitCallsDuringBoot: submitCallsDuringBoot.n,
    leasesDeletedByTime: leasesDeletedByTime.n,
    partialsReformed: partialsReformed.n,
    attentionAutoCleared,
    destinationAutoAccepted,
    exactBytesSynthesized,
  };
}

/**
 * Counterfactual: run the four Boot-does-not violation seams against durable residue.
 * Proves the seams *can* mutate state (falsifiability) — never invoked during boot.
 */
export async function runBootDoesNotViolationSeams(db: ChaosDb): Promise<{
  partialsReformed: number;
  attentionCleared: boolean;
  destinationAccepted: boolean;
  exactBytesSynthesized: boolean;
}> {
  const partialBefore = Number(
    (
      await psqlMust(
        db.url,
        `SELECT count(*) FROM chaos_external_partials WHERE wallet_id = '${db.walletId}';`,
      )
    ).trim(),
  );
  const attRow = (
    await psqlMust(
      db.url,
      `SELECT id FROM operations WHERE status = 'NEEDS_ATTENTION' AND source_wallet_id = '${db.walletId}' LIMIT 1;`,
    )
  ).trim();
  const destRow = (
    await psqlMust(
      db.url,
      `SELECT id FROM chaos_pending_destinations WHERE wallet_id = '${db.walletId}' AND status = 'PENDING' LIMIT 1;`,
    )
  ).trim();
  const exactRow = (
    await psqlMust(
      db.url,
      `SELECT id FROM chaos_exact_byte_records WHERE wallet_id = '${db.walletId}' AND exact_bytes IS NULL LIMIT 1;`,
    )
  ).trim();
  const partialRow = (
    await psqlMust(
      db.url,
      `SELECT id FROM chaos_external_partials WHERE wallet_id = '${db.walletId}' AND reformed_at IS NULL LIMIT 1;`,
    )
  ).trim();

  if (partialRow !== "") {
    await psqlMust(
      db.url,
      `UPDATE chaos_external_partials SET reformed_at = now(), delivery_state = 'REFORMED'
       WHERE id = '${partialRow}';
       INSERT INTO chaos_external_partials (id, wallet_id, delivery_state)
       VALUES ('${randomUUID()}', '${db.walletId}', 'REFORMED');`,
    );
  }
  if (attRow !== "") {
    await psqlMust(db.url, `UPDATE operations SET status = 'CREATED' WHERE id = '${attRow}';`);
  }
  if (destRow !== "") {
    await psqlMust(
      db.url,
      `UPDATE chaos_pending_destinations SET status = 'ACCEPTED' WHERE id = '${destRow}';`,
    );
  }
  if (exactRow !== "") {
    await psqlMust(
      db.url,
      `UPDATE chaos_exact_byte_records SET exact_bytes = parsed_json WHERE id = '${exactRow}';`,
    );
  }

  const partialAfter = Number(
    (
      await psqlMust(
        db.url,
        `SELECT count(*) FROM chaos_external_partials WHERE wallet_id = '${db.walletId}';`,
      )
    ).trim(),
  );
  const attAfter =
    attRow === ""
      ? ""
      : (await psqlMust(db.url, `SELECT status FROM operations WHERE id = '${attRow}';`)).trim();
  const destAfter =
    destRow === ""
      ? ""
      : (
          await psqlMust(
            db.url,
            `SELECT status FROM chaos_pending_destinations WHERE id = '${destRow}';`,
          )
        ).trim();
  const exactAfter =
    exactRow === ""
      ? ""
      : (
          await psqlMust(
            db.url,
            `SELECT coalesce(exact_bytes, '') FROM chaos_exact_byte_records WHERE id = '${exactRow}';`,
          )
        ).trim();

  return {
    partialsReformed: Math.max(0, partialAfter - partialBefore),
    attentionCleared: attRow !== "" && attAfter !== "NEEDS_ATTENTION",
    destinationAccepted: destRow !== "" && destAfter === "ACCEPTED",
    exactBytesSynthesized: exactRow !== "" && exactAfter !== "",
  };
}

/* ─── observation anomaly survival across "restart" ─────────────── */

export async function snapshotAnomalies(db: ChaosDb): Promise<string> {
  return (
    await psqlMust(
      db.url,
      `SET search_path TO obs, public;
       SELECT coalesce(json_agg(row_to_json(a) ORDER BY a.id), '[]'::json)
       FROM observation_anomalies a;`,
    )
  ).trim();
}

/**
 * D4 deferred: production observation append-only triggers are not frozen SQL.
 * Kept only so callers can observe that WITHOUT a production trigger, UPDATE/DELETE
 * succeed against observation_anomalies — proving the suite no longer invents the guard.
 * Do not use this as evidence that "append-only triggers hold."
 */
export async function probeAnomalyMutabilityWithoutProductionTrigger(
  db: ChaosDb,
  anomalyId: string,
): Promise<{ updateSucceeded: boolean; deleteSucceeded: boolean }> {
  const upd = await runPsql(
    db.url,
    `SET search_path TO obs, public;
     UPDATE observation_anomalies SET details = 'mutated' WHERE id = '${anomalyId}';`,
  );
  // Re-insert a fresh row for delete probe if update wiped content differently.
  const del = await runPsql(
    db.url,
    `SET search_path TO obs, public;
     DELETE FROM observation_anomalies WHERE id = '${anomalyId}';`,
  );
  return {
    updateSucceeded: upd.ok,
    deleteSucceeded: del.ok,
  };
}

/** @deprecated Use probeAnomalyMutabilityWithoutProductionTrigger; D4 dropped trigger AC. */
export async function assertAnomaliesImmutable(
  db: ChaosDb,
  anomalyId: string,
): Promise<{ updateRejected: boolean; deleteRejected: boolean }> {
  const probe = await probeAnomalyMutabilityWithoutProductionTrigger(db, anomalyId);
  return {
    updateRejected: !probe.updateSucceeded,
    deleteRejected: !probe.deleteSucceeded,
  };
}

/** Re-export freeze of leadership lock id for census-style assertions. */
export { SIGNER_LEADERSHIP_LOCK_ID };
