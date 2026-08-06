// fault-injection harness for two real node instances against one
// real PostgreSQL.
//
// Under test: the boot-recovery procedure, and the obligation that a crash at every
// durable phase boundary produces neither two submit calls for one attempt nor two
// distinct external partials for one operation. Also one active lease per wallet, and one
// process-wide signer leadership lock with its readiness contract.
//
// Shared infrastructure for fault-tests worker ownership over the same
// surfaces; other suites are expected to import from here rather than fork a second harness.
//
// WHAT AN "INSTANCE" IS HERE. A NodeInstance owns, per instance:
//   - its own dedicated never-pooled PostgreSQL session (a `psql` child process — one
//     process is one connection), holding the session advisory lock;
//   - its own SignerLeadership latch;
//   - its own NodeCoreReadinessState and the real health handlers;
//   - the real production code paths: acquireSignerLeadership,
//     runDeterministicBootRecovery, signUnderLease (the signing chokepoint).
// The arbiter under test — `pg_try_advisory_lock` — is CONNECTION-scoped, so two dedicated
// sessions interlock exactly as two operating-system processes would; the exclusion proof is
// real, and PostgreSQL (not this process) picks the winner. Driving PostgreSQL through child
// processes also keeps the in-process network-containment guard intact.
//
// FAULT MODEL.
//   - graceful drain (SIGTERM)  → `sigterm()`: abort the acquire loop, run the real
//     release path, stamp readiness stopping. This is the deploy drain.
//   - process crash (SIGKILL)   → `crash()`: SIGKILL the lock session's child with no
//     unlock and no chance to run any release path. Durable state is exactly what last
//     committed — the same insight the v1 chaos harness (apps/node/src/sweep/chaos) uses.
//   - database failover         → `dropLockConnection()`: `pg_terminate_backend` from a
//     THIRD session. The client process survives; the server kills the backend. This is
//     the fault a SIGKILL of the client cannot model.

import { spawn, execFile, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { LeaseRole } from "@zucoins/generic-node-contracts/wallet-state";

import { createHealthHandlers, type HealthRouteHandlers } from "../../src/api/health.ts";
import { executeMoveSubmitClaim } from "../../src/core/move-submit-claim.ts";
import { NodeCoreReadinessState } from "../../src/core/readiness-state.ts";
import type { SqlQueryFn } from "../../src/core/sql-query-fn.ts";
import {
  NotSignerLeaderError,
  signUnderLease,
  type ActiveLeaseRecord,
  type SignerAuditEntry,
  type SigningPurpose,
} from "../../src/core/signer-boundary.ts";
import {
  makeSubmitAttemptRecorder,
  makeSubmitDecisionClaimStore,
} from "../../src/core/submit-decision-claim-store.ts";
import { sha256Hex, type GatewayExchangeTransport } from "../../src/gateway/capture.ts";
import type { GatewayLimits } from "../../src/gateway/types.ts";
import {
  acquireSignerLeadership,
  SignerLeadership,
  tryAcquireSignerLeadership,
  type HeldSignerLeadership,
  type LeadershipLockClient,
  type LeadershipLockPool,
} from "../../src/workers/leadership.ts";
import {
  runDeterministicBootRecovery,
  type ActiveLeaseRow,
  type AuthorizedResumeAction,
  type BootRecoveryActions,
  type BootRecoveryReport,
  type BootRecoveryStore,
  type BootWalletState,
  type KeyCorrespondenceRow,
  type LeaseGroupOperationRow,
  type ObservationCursorHint,
  type OperationKind,
  type OperationPhaseEvidence,
} from "../../src/workers/boot-recovery.ts";
import { tokenizeCustodySql } from "../custody-eligibility-sql-statements.js";

/* ─── psql plumbing ───────────────────────────────────────────────── */

export interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

export const runPsql = (url: string, sql: string, timeoutMs = 20_000): Promise<PsqlOutcome> =>
  new Promise((resolve) => {
    execFile(
      "psql",
      [url, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: timeoutMs },
      (err, stdout, stderr) => {
        resolve({ ok: !err, stdout: stdout ?? "", stderr: stderr ?? (err ? String(err) : "") });
      },
    );
  });

export const psqlMust = async (url: string, sql: string): Promise<string> => {
  const outcome = await runPsql(url, sql);
  if (!outcome.ok) throw new Error(`psql failed: ${outcome.stderr.trim() || "unknown error"}`);
  return outcome.stdout;
};

export const withDatabase = (url: string, database: string): string => {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
};

/** SQLSTATE out of psql's verbose stderr (`ERROR:  23505: ...`). */
export const sqlstateOf = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const sqlText = (value: string): string => `'${value.replaceAll("'", "''")}'`;
const sqlBool = (value: boolean): string => (value ? "true" : "false");

// wallets.public_key is padded_base64url_pubkey (44 chars, ends with =).
const chaosPubkey = (suffix: string): string =>
  `${"A".repeat(Math.max(0, 43 - suffix.length))}${suffix.slice(0, 43)}=`;

/* ─── schema ──────────────────────────────────────────────────────── */

// custody-eligibility.sql is prerequisite-bound (base-enums-domains + nodes),
// not self-contained. Apply the same prerequisite stack lease-foundation.pg.test uses.
const hereSchema = dirname(fileURLToPath(import.meta.url));
const prerequisiteDdl = ((): string => {
  const base = readFileSync(resolve(hereSchema, "../../src/schema/base-enums-domains.sql"), "utf-8");
  const registry = readFileSync(
    resolve(hereSchema, "../../src/schema/node-implementer-registry.sql"),
    "utf-8",
  );
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) {
    throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
  }
  return `${base}\n${nodes[0]}\n`;
})();

// `wallets`, `wallet_active_leases` and their triggers come from the REAL frozen DDL —
// wallet_active_leases' PRIMARY KEY (wallet_id) is the structural one-lease-per-wallet
// arbiter this suite asserts against, so it is never mirrored by hand.
const custodyDdl = tokenizeCustodySql(
  readFileSync(new URL("../../src/schema/custody-eligibility.sql", import.meta.url), "utf-8"),
)
.map((statement) => statement.raw)
.join("\n");

// Self-owned minimal surfaces, documented exactly as pg-concurrency.test.ts and
// wallet-lease-lock-contention.pg.test.ts do: no frozen `operations` DDL exists yet, and the
// The lease fields the ports read (operation_id, lease_group_id, lease_epoch,
// last_heartbeat_at) are not on the frozen lease table. They live in a SIDECAR keyed by
// wallet_id rather than as ALTERs, so the frozen PK stays the only uniqueness authority.
const CHAOS_DDL = `
CREATE TABLE operations (
  id uuid PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('RECEIVE_EXTERNAL', 'MOVE_INTERNAL', 'SEND_EXTERNAL')),
  status text NOT NULL,
  terminal boolean NOT NULL DEFAULT false,
  attention_required boolean NOT NULL DEFAULT false,
  attention_reason text,
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  lease_epoch bigint NOT NULL DEFAULT 1 CHECK (lease_epoch > 0),
  submit_boundary_recorded boolean NOT NULL DEFAULT false,
  signer_audit_indicates_call boolean NOT NULL DEFAULT false,
  exact_preimage_persisted boolean NOT NULL DEFAULT false,
  exact_preimage_text text,
  signature_persisted boolean NOT NULL DEFAULT false,
  formation_complete boolean NOT NULL DEFAULT false,
  required_roles text[] NOT NULL,
  queued_receive boolean NOT NULL DEFAULT false
);

CREATE TABLE lease_group_operations (
  lease_group_id uuid NOT NULL,
  operation_id uuid NOT NULL REFERENCES operations (id) ON DELETE CASCADE,
  PRIMARY KEY (lease_group_id, operation_id)
);

CREATE TABLE lease_details (
  wallet_id uuid PRIMARY KEY REFERENCES wallet_active_leases (wallet_id) ON DELETE CASCADE,
  operation_id uuid NOT NULL REFERENCES operations (id) ON DELETE CASCADE,
  lease_group_id uuid NOT NULL,
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  last_heartbeat_at timestamptz NOT NULL
);

CREATE TABLE vault_open_probes (
  wallet_id uuid PRIMARY KEY REFERENCES wallets (id) ON DELETE CASCADE,
  derived_public_key text
);

-- No test can produce two submit calls for one attempt. attempt_id is the
-- PRIMARY KEY, so a second submit call for the same attempt is structurally impossible
-- rather than merely unasserted.
CREATE TABLE submit_calls (
  attempt_id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations (id) ON DELETE CASCADE,
  called_at timestamptz NOT NULL DEFAULT now()
);

-- ... nor two distinct external partials for one operation. One row per
-- operation; a second partial over DIFFERENT bytes cannot be inserted.
CREATE TABLE external_partials (
  operation_id uuid PRIMARY KEY REFERENCES operations (id) ON DELETE CASCADE,
  step_1_signature text NOT NULL,
  preimage_sha256 text NOT NULL,
  formed_at timestamptz NOT NULL DEFAULT now()
);

-- FK target for frozen submit-attempts.sql. Stubbed to the columns the FKs
-- reference — same shape as submit-decision-claim-store.pg.test.ts.
CREATE TABLE operation_transactions (
  operation_id uuid NOT NULL REFERENCES operations (id) ON DELETE CASCADE,
  attempt_no integer NOT NULL,
  PRIMARY KEY (operation_id, attempt_no)
);

-- Live-boundary suspension points. A resume path that hits a named barrier parks until
-- the test SIGKILLs the leader (or clears the barrier). This is how "crash at boundary"
-- is forced against a running resume path rather than a seeded quiescent row.
CREATE TABLE crash_hooks (
  name text PRIMARY KEY,
  armed boolean NOT NULL DEFAULT false
);
`;

// Frozen submit claim + attempt evidence. chaos DB now applies
// base-enums-domains first (sha256_hex already present), so strip the domain CREATE
// from the frozen file — same posture as submit-decision-claim-store.pg.test.ts.
const SUBMIT_ATTEMPTS_SQL = readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), "../../src/schema/submit-attempts.sql"),
  "utf-8",
).replace(
  /CREATE DOMAIN sha256_hex AS text\s+CHECK \(VALUE ~ '\^\[0-9a-f\]\{64\}\$'\);\s*/m,
  "",
);

const CHAOS_GATEWAY_LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 4_096,
  maxResponseBytes: 4_096,
};

/** Well-known crash-hook names used by live-boundary proofs. */
export const CRASH_HOOK = {
  /** After preimage is known durable, before signUnderLease returns / signature row lands. */
  BEFORE_SIGNATURE_PERSIST: "before_signature_persist",
  /** After claimSubmitOnce minted, before the gateway exchange. */
  AFTER_CLAIM_BEFORE_EXCHANGE: "after_claim_before_exchange",
  /** After the exchange returned, before the attempt recorder. */
  AFTER_EXCHANGE_BEFORE_RECORDER: "after_exchange_before_recorder",
} as const;

export async function createChaosDatabase(adminUrl: string, name: string): Promise<string> {
  await psqlMust(adminUrl, `CREATE DATABASE ${name}`);
  const url = withDatabase(adminUrl, name);
  await psqlMust(url, prerequisiteDdl);
  await psqlMust(url, custodyDdl);
  await psqlMust(url, CHAOS_DDL);
  await psqlMust(url, SUBMIT_ATTEMPTS_SQL);
  return url;
}

export async function dropChaosDatabase(adminUrl: string, name: string): Promise<void> {
  await runPsql(adminUrl, `DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
}

/** Remove every fixture row so each phase-boundary case starts from a clean instant. */
export async function wipeFixtures(url: string): Promise<void> {
  // custody trigger custody_reject_wallet_mutation forbids clearing recovery
  // once set — disable it for fixture teardown only (never production).
  await psqlMust(
    url,
    `DELETE FROM external_partials;
     DELETE FROM submit_calls;
     DELETE FROM gateway_submit_attempts;
     DELETE FROM submit_decisions;
     DELETE FROM operation_transactions;
     DELETE FROM crash_hooks;
     DELETE FROM lease_details;
     DELETE FROM wallet_active_leases;
     DELETE FROM lease_group_operations;
     DELETE FROM operations;
     DELETE FROM vault_open_probes;
     DELETE FROM destinations;
     ALTER TABLE wallets DISABLE TRIGGER wallets_custody_mutation_guard;
     UPDATE wallets SET recovery_verified_at = NULL, recovery_verification_id = NULL,
                        state = 'AVAILABLE', quarantine_reason = NULL;
     DELETE FROM wallet_recovery_verifications;
     DELETE FROM wallets;
     ALTER TABLE wallets ENABLE TRIGGER wallets_custody_mutation_guard;
     DELETE FROM nodes;`,
  );
}

/**
 * Parameter-bound psql (variables :'pN') — production claim/attempt stores need real binds.
 * Mirrors submit-decision-claim-store.pg.test.ts so makeSubmitDecisionClaimStore runs unaltered.
 */
export const runPsqlParam = (
  url: string,
  sql: string,
  values: readonly unknown[] = [],
  timeoutMs = 20_000,
): Promise<PsqlOutcome> =>
  new Promise((resolvePromise) => {
    const args = ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose"];
    values.forEach((value, index) => {
      if (value !== null && value !== undefined) {
        args.push("-v", `p${index + 1}=${String(value)}`);
      }
    });
    args.push("-f", "-");
    const bound = sql.replace(/\$(\d+)/g, (_m, position: string) =>
      values[Number(position) - 1] === null || values[Number(position) - 1] === undefined
        ? "NULL"
: `:'p${position}'`,
    );
    const child = spawn("psql", args, {
      env: pgEnv(url),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (c: string) => {
      stdout += c;
    });
    child.stderr.on("data", (c: string) => {
      stderr += c;
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolvePromise({ ok: code === 0, stdout, stderr });
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolvePromise({ ok: false, stdout, stderr: String(err) });
    });
    child.stdin.end(`${bound.trimEnd().endsWith(";") ? bound : `${bound};`}\n`);
  });

/** SqlQueryFn over psql — same binding adapter as submit-decision-claim-store.pg.test.ts. */
export function makeChaosSqlQuery(url: string): SqlQueryFn {
  return async (text, values) => {
    const wrapped =
      `WITH q AS (${text}) SELECT coalesce(json_agg(row_to_json(q)), '[]'::json) FROM q`;
    const result = await runPsqlParam(url, wrapped, values);
    if (!result.ok) throw new Error(result.stderr.trim() || "sql query failed");
    const line = result.stdout.trim().split("\n").filter(Boolean).at(-1) ?? "[]";
    return JSON.parse(line) as Record<string, unknown>[];
  };
}

/** Arm a named crash barrier; a resume path that hits it parks until disarmed or process death. */
export async function armCrashHook(url: string, name: string): Promise<void> {
  await psqlMust(
    url,
    `INSERT INTO crash_hooks (name, armed) VALUES (${sqlText(name)}, true)
     ON CONFLICT (name) DO UPDATE SET armed = true`,
  );
}

export async function disarmCrashHook(url: string, name: string): Promise<void> {
  await psqlMust(url, `UPDATE crash_hooks SET armed = false WHERE name = ${sqlText(name)}`);
}

export async function isCrashHookArmed(url: string, name: string): Promise<boolean> {
  // boolean::text is 'true'/'false' (not the single-char psql default).
  const out = await psqlMust(
    url,
    `SELECT coalesce((SELECT armed::text FROM crash_hooks WHERE name = ${sqlText(name)}), 'false')`,
  );
  return out.trim() === "true";
}

/**
 * Park until the named hook is cleared OR `signal.aborted` (process crash / dispose).
 * Holds a resume path at a durable boundary so the test can SIGKILL mid-flight.
 */
export async function awaitCrashHookClear(
  url: string,
  name: string,
  signal: { readonly aborted: boolean },
  pollMs = 15,
): Promise<"cleared" | "aborted"> {
  while (!signal.aborted) {
    if (!(await isCrashHookArmed(url, name))) return "cleared";
    await new Promise((r) => setTimeout(r, pollMs));
  }
  return "aborted";
}

/** Wait until a crash hook is observed armed (resume path has reached the barrier). */
export async function waitUntilHookReached(
  url: string,
  name: string,
  opts: { timeoutMs?: number; pollMs?: number } = {},
): Promise<void> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const pollMs = opts.pollMs ?? 15;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await isCrashHookArmed(url, name)) {
      // Hook starts armed by the test; the resume path "reaches" it by calling
      // awaitCrashHookClear. We additionally write a reached marker via a second row
      // convention: name||':reached'. Prefer that when present.
      const reached = await psqlMust(
        url,
        `SELECT coalesce(
           (SELECT armed::text FROM crash_hooks WHERE name = ${sqlText(name + ":reached")}),
           'false')`,
      );
      if (reached.trim() === "true") return;
    }
    // Fallback: if the test armed the hook and a concurrent waiter is polling, we still
    // need a positive "path entered await". The resume path sets :reached itself.
    const marker = await psqlMust(
      url,
      `SELECT coalesce(
         (SELECT 1::text FROM crash_hooks WHERE name = ${sqlText(name + ":reached")} AND armed),
         '')`,
    );
    if (marker.trim() === "1") return;
    await new Promise((r) => setTimeout(r, pollMs));
  }
  throw new Error(`crash hook ${name} was never reached within ${timeoutMs}ms`);
}

export async function markCrashHookReached(url: string, name: string): Promise<void> {
  await psqlMust(
    url,
    `INSERT INTO crash_hooks (name, armed) VALUES (${sqlText(name + ":reached")}, true)
     ON CONFLICT (name) DO UPDATE SET armed = true`,
  );
}

/* ─── one dedicated connection behind the LeadershipLockClient seam ── */

function pgEnv(url: string): NodeJS.ProcessEnv {
  const u = new URL(url);
  return {
...process.env,
    PGHOST: u.hostname,
    PGPORT: u.port === "" ? "5432" : u.port,
    PGUSER: decodeURIComponent(u.username),
    PGPASSWORD: decodeURIComponent(u.password),
    PGDATABASE: u.pathname.replace(/^\//, ""),
  };
}

/**
 * One `psql` session — one process, one connection, therefore one never-pooled session for
 * the session-scoped advisory lock. `-A -t` prints exactly one line per single-column row,
 * so replies pair with requests in order.
 */
export class PsqlSession implements LeadershipLockClient {
  readonly child: ChildProcessWithoutNullStreams;
  readonly #pending: Array<(line: string) => void> = [];
  readonly #listeners = new Map<string, Array<(err?: Error) => void>>();
  #buffer = "";

  constructor(url: string) {
    this.child = spawn("psql", ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"], {
      env: pgEnv(url),
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
      this.#emit("end");
    });
    this.child.on("error", (err) => {
      this.#emit("error", err);
    });
  }

  /** Raw single-value read (backend pid, counters). Not part of the lock-client seam. */
  async scalar(sql: string): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const onClosed = (): void => {
        reject(new Error("psql session closed"));
      };
      this.child.once("close", onClosed);
      this.#pending.push((value) => {
        this.child.removeListener("close", onClosed);
        resolve(value);
      });
      this.child.stdin.write(`${sql};\n`);
    });
  }

  async query(sql: string, values?: readonly unknown[]): Promise<{ rows: unknown[] }> {
    // psql has no bind parameters; the only value ever substituted is the numeric lock id.
    const statement = values === undefined ? sql : sql.replace("$1", String(Number(values[0])));
    const column = /\bAS\s+(\w+)/i.exec(sql)?.[1] ?? "result";
    const line = await this.scalar(statement);
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

/* ─── PostgreSQL-backed ports ────────────────────────────── */

const ROLE_BY_KIND: Readonly<Record<OperationKind, readonly LeaseRole[]>> = {
  RECEIVE_EXTERNAL: ["RECEIVE_WINDOW"],
  MOVE_INTERNAL: ["MOVE_SOURCE", "MOVE_DESTINATION"],
  SEND_EXTERNAL: ["SEND_SOURCE"],
};

const PURPOSE_BY_KIND: Readonly<Record<OperationKind, SigningPurpose>> = {
  RECEIVE_EXTERNAL: "SPLITCHAIN_STEP_2",
  MOVE_INTERNAL: "SPLITCHAIN_STEP_1",
  SEND_EXTERNAL: "SPLITCHAIN_STEP_1",
};

interface JsonRow {
  readonly [key: string]: unknown;
}

async function jsonRows(url: string, select: string): Promise<JsonRow[]> {
  const out = await psqlMust(
    url,
    `SELECT coalesce(json_agg(row_to_json(t)), '[]'::json) FROM (${select}) t`,
  );
  return JSON.parse(out.trim() === "" ? "[]" : out.trim()) as JsonRow[];
}

/** Reads the exact durable evidence a crash left behind. No writes, no interpretation. */
export class PgBootRecoveryStore implements BootRecoveryStore {
  constructor(private readonly url: string) {}

  async listActiveLeases(): Promise<readonly ActiveLeaseRow[]> {
    const rows = await jsonRows(
      this.url,
      `SELECT l.wallet_id::text AS wallet_id, d.operation_id::text AS operation_id,
              d.lease_group_id::text AS lease_group_id, l.lease_role AS role,
              d.lease_epoch::int AS epoch, w.state::text AS wallet_state,
              (extract(epoch FROM d.last_heartbeat_at) * 1000)::bigint::text AS heartbeat_ms
         FROM wallet_active_leases l
         JOIN lease_details d ON d.wallet_id = l.wallet_id
         JOIN wallets w ON w.id = l.wallet_id`,
    );
    return rows.map((r) => ({
      walletId: String(r.wallet_id),
      operationId: String(r.operation_id),
      leaseGroupId: String(r.lease_group_id),
      role: String(r.role) as LeaseRole,
      epoch: Number(r.epoch),
      walletState: String(r.wallet_state) as BootWalletState,
      lastHeartbeatAtMs: Number(r.heartbeat_ms),
    }));
  }

  async listNonterminalOperations(): Promise<readonly OperationPhaseEvidence[]> {
    const rows = await jsonRows(
      this.url,
      `SELECT o.id::text AS id, o.kind, o.status, o.attention_required, o.row_version::int AS row_version,
              o.lease_epoch::int AS lease_epoch, o.submit_boundary_recorded, o.signer_audit_indicates_call,
              o.exact_preimage_persisted, o.signature_persisted, o.formation_complete, o.required_roles,
              coalesce(
                (SELECT json_agg(d.wallet_id::text) FROM lease_details d WHERE d.operation_id = o.id),
                '[]'::json) AS leased_wallet_ids
         FROM operations o
        WHERE o.terminal = false`,
    );
    return rows.map((r) => ({
      operationId: String(r.id),
      kind: String(r.kind) as OperationKind,
      status: String(r.status),
      attentionRequired: r.attention_required === true,
      rowVersion: Number(r.row_version),
      leaseEpoch: Number(r.lease_epoch),
      submitBoundaryRecorded: r.submit_boundary_recorded === true,
      signerAuditIndicatesCall: r.signer_audit_indicates_call === true,
      exactPreimagePersisted: r.exact_preimage_persisted === true,
      signaturePersisted: r.signature_persisted === true,
      formationComplete: r.formation_complete === true,
      leasedWalletIds: (r.leased_wallet_ids as string[] | null) ?? [],
      requiredRoles: (r.required_roles as LeaseRole[] | null) ?? [],
    }));
  }

  async listLeaseGroupOperations(): Promise<readonly LeaseGroupOperationRow[]> {
    const rows = await jsonRows(
      this.url,
      `SELECT lease_group_id::text AS lease_group_id, operation_id::text AS operation_id
         FROM lease_group_operations`,
    );
    return rows.map((r) => ({
      leaseGroupId: String(r.lease_group_id),
      operationId: String(r.operation_id),
    }));
  }

  async listKeyCorrespondence(): Promise<readonly KeyCorrespondenceRow[]> {
    const rows = await jsonRows(
      this.url,
      `SELECT w.id::text AS wallet_id, w.public_key AS stored, p.derived_public_key AS derived
         FROM vault_open_probes p JOIN wallets w ON w.id = p.wallet_id`,
    );
    return rows.map((r) => ({
      walletId: String(r.wallet_id),
      storedPublicKey: String(r.stored),
      derivedPublicKey: r.derived === null ? null : String(r.derived),
    }));
  }

  // Observation-cursor hydration (raw-byte re-read) is
  // (src/observation/capture.concurrency.test.ts) and own suite; this harness
  // exercises the leadership / lease / phase-boundary axes and reports no streams.
  async listObservationCursors(): Promise<readonly ObservationCursorHint[]> {
    return [];
  }

  async readRawResponseBytes(): Promise<Uint8Array | null> {
    return null;
  }

  async listQueuedReceiveOperationIds(): Promise<readonly string[]> {
    const rows = await jsonRows(
      this.url,
      `SELECT id::text AS id FROM operations WHERE queued_receive = true AND terminal = false`,
    );
    return rows.map((r) => String(r.id));
  }
}

export interface RecordedSignature {
  readonly walletId: string;
  readonly operationId: string;
  readonly preimageText: string;
  readonly preimageSha256: string;
}

/**
 * Applies only what a classification authorized, and records every side effect so a test can
 * assert what recovery did AND what it refused to do.
 *
 * Signing goes through the REAL signing chokepoint (`signUnderLease`), gated on the REAL
 * leadership latch — so a resume on a node that has lost the advisory lock is refused by
 * production code, not by the harness.
 */
export class PgBootRecoveryActions implements BootRecoveryActions {
  readonly quarantined: Array<{ walletId: string; reason: string }> = [];
  readonly repaired: Array<{ walletId: string; to: BootWalletState }> = [];
  readonly attention: Array<{ operationId: string; reason: string }> = [];
  readonly resumed: AuthorizedResumeAction[] = [];
  readonly signatures: RecordedSignature[] = [];
  readonly signerAudit: SignerAuditEntry[] = [];
  /** operationIds that crossed the production submit exchange (one push per POST). */
  readonly submitCalls: string[] = [];
  /** Gateway exchange endpoints actually POSTed (production single-shot path). */
  readonly gatewayPosts: string[] = [];
  readonly moneyEnginesStopped: string[] = [];
  readonly rebuiltReceiveQueues: string[][] = [];

  readonly #query: SqlQueryFn;
  readonly #abort: { readonly aborted: boolean };

  constructor(
    private readonly url: string,
    private readonly leadership: SignerLeadership,
    abort?: { readonly aborted: boolean },
    /**
     * Optional exchange double. Defaults to a counting ACK transport. Tests inject a
     * hanging or post-exchange-failing transport to park at claim/exchange boundaries.
     */
    private readonly exchange: GatewayExchangeTransport = {
      exchange: async (endpoint, request) => {
        // Default ACK — production path still claims, exchanges, and records.
        const responseBytes = new TextEncoder().encode('{"status":true,"code":"ok"}');
        return {
          endpoint,
          endpointFingerprint: sha256Hex(new TextEncoder().encode(endpoint)),
          requestBytes: request.bodyBytes,
          requestSha256: sha256Hex(request.bodyBytes),
          responseBytes,
          responseSha256: sha256Hex(responseBytes),
          statusCode: 200,
        };
      },
    },
  ) {
    this.#query = makeChaosSqlQuery(url);
    this.#abort = abort ?? { aborted: false };
  }

  async quarantineWallet(walletId: string, reason: string): Promise<void> {
    this.quarantined.push({ walletId, reason });
    await psqlMust(
      this.url,
      `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = ${sqlText(reason)}
        WHERE id = '${walletId}'`,
    );
  }

  async repairWalletState(walletId: string, to: BootWalletState): Promise<void> {
    this.repaired.push({ walletId, to });
    await psqlMust(
      this.url,
      `UPDATE wallets SET state = '${to}', quarantine_reason = NULL WHERE id = '${walletId}'`,
    );
  }

  async setAttention(operationId: string, reason: string, expectedRowVersion: number): Promise<void> {
    this.attention.push({ operationId, reason });
    // Guarded transition under the expected row version. A sentinel would silently
    // overwrite a concurrent writer's row.
    const updated = await psqlMust(
      this.url,
      `WITH cas AS (
         UPDATE operations SET attention_required = true, attention_reason = ${sqlText(reason)},
                row_version = row_version + 1
          WHERE id = '${operationId}' AND row_version = ${expectedRowVersion}
        RETURNING 1)
       SELECT count(*)::int FROM cas`,
    );
    if (Number(updated.trim()) !== 1) {
      throw new Error(`setAttention CAS failed for ${operationId} at row_version ${expectedRowVersion}`);
    }
  }

  async resumeAuthorized(action: AuthorizedResumeAction): Promise<void> {
    this.resumed.push(action);
    if (action.kind === "SUBMIT_ONCE") {
      await this.#submitOnceProduction(action.operationId);
      return;
    }
    if (action.kind === "SIGN_PERSISTED_PREIMAGE" || action.kind === "SIGN_PERSISTED_STEP2_PREIMAGE") {
      await this.#signPersistedPreimage(action.operationId, action.operationKind, action.expectedLeaseEpoch);
    }
  }

  /**
   * Production claim → exchange → recorder path (executeMoveSubmitClaim + real claim store).
   * Crash hooks park between claim and exchange, and after exchange before recorder.
   * The chaos `submit_calls` row is written ONLY after a real gateway POST so cardinality
   * tracks exchanges, not toy double invocations. `submit_boundary_recorded` flips when the
   * durable claim exists (claim won), matching "submit claim recorded, response
   * unknown" — which is also what readSubmitAttemptEvidence reports as CLAIMED_UNRETURNED.
   */
  async #submitOnceProduction(operationId: string): Promise<void> {
    // Ensure the FK target for submit_decisions exists for this operation.
    await psqlMust(
      this.url,
      `INSERT INTO operation_transactions (operation_id, attempt_no)
       VALUES ('${operationId}', 1)
       ON CONFLICT DO NOTHING`,
    );

    const claimStore = makeSubmitDecisionClaimStore(this.#query);
    const baseRecorder = makeSubmitAttemptRecorder(this.#query);
    const dbUrl = this.url;
    const abortSignal = this.#abort;
    const exchangeTransport = this.exchange;
    const gatewayPosts = this.gatewayPosts;
    const submitCalls = this.submitCalls;

    // Wrap the exchange so we (a) count real POSTs and (b) honour the after-exchange hook.
    const countingExchange: GatewayExchangeTransport = {
      exchange: async (endpoint, request) => {
        // Claim is durable the instant executeMoveSubmitClaim invokes exchange.
        // Flip the classifier flag here so a crash before/during exchange leaves
        // "submit claim recorded, response unknown" on disk.
        await psqlMust(
          dbUrl,
          `UPDATE operations SET submit_boundary_recorded = true WHERE id = '${operationId}'`,
        );
        // Barrier: claim is durable; exchange has not happened.
        if (await isCrashHookArmed(dbUrl, CRASH_HOOK.AFTER_CLAIM_BEFORE_EXCHANGE)) {
          await markCrashHookReached(dbUrl, CRASH_HOOK.AFTER_CLAIM_BEFORE_EXCHANGE);
          const outcome = await awaitCrashHookClear(
            dbUrl,
            CRASH_HOOK.AFTER_CLAIM_BEFORE_EXCHANGE,
            abortSignal,
          );
          if (outcome === "aborted") {
            throw new Error("crash after claim, before exchange");
          }
        }
        gatewayPosts.push(endpoint);
        submitCalls.push(operationId);
        // Defense-in-depth structural backstop — also used by classification matrix.
        await psqlMust(
          dbUrl,
          `INSERT INTO submit_calls (attempt_id, operation_id)
           VALUES ('${operationId}', '${operationId}')
           ON CONFLICT DO NOTHING`,
        );
        const capture = await exchangeTransport.exchange(endpoint, request);
        if (await isCrashHookArmed(dbUrl, CRASH_HOOK.AFTER_EXCHANGE_BEFORE_RECORDER)) {
          await markCrashHookReached(dbUrl, CRASH_HOOK.AFTER_EXCHANGE_BEFORE_RECORDER);
          const outcome = await awaitCrashHookClear(
            dbUrl,
            CRASH_HOOK.AFTER_EXCHANGE_BEFORE_RECORDER,
            abortSignal,
          );
          if (outcome === "aborted") {
            throw new Error("crash after exchange, before recorder");
          }
        }
        return capture;
      },
    };

    const authorization = {
      submitDecisionId: operationId, // one decision id per attempt — stable across restarts
      operationId,
      transactionAttemptNo: 1,
    };

    // Preimage/signature text is the exact signed transaction bytes under test (the byte-exact signing rule).
    const signedTransactionText = (
      await psqlMust(
        this.url,
        `SELECT coalesce(exact_preimage_text, '') FROM operations WHERE id = '${operationId}'`,
      )
    ).replace(/\n$/, "");
    let signedTransaction: unknown = { operationId };
    if (signedTransactionText !== "") {
      try {
        signedTransaction = JSON.parse(signedTransactionText);
      } catch {
        signedTransaction = { raw: signedTransactionText };
      }
    }

    try {
      const result = await executeMoveSubmitClaim({
        authorization,
        signedTransaction,
        claimStore,
        submit: {
          endpoint: "https://chaos-gateway.invalid/submit",
          limits: CHAOS_GATEWAY_LIMITS,
          recorder: baseRecorder,
          exchange: countingExchange,
        },
      });
      // Claim is durable whenever mint won OR already existed — flip the classifier flag.
      await psqlMust(
        this.url,
        `UPDATE operations SET submit_boundary_recorded = true WHERE id = '${operationId}'`,
      );
      if (!result.executed) {
        // Loser of the mint: zero exchange. Classifier on next boot sees the claim.
        return;
      }
    } catch (err) {
      // Claim may already be durable; always surface the boundary to the classifier.
      await psqlMust(
        this.url,
        `UPDATE operations SET submit_boundary_recorded = true
          WHERE id = '${operationId}'
            AND EXISTS (SELECT 1 FROM submit_decisions WHERE operation_id = '${operationId}')`,
      );
      throw err;
    }
  }

  async seedReconcileCursor(): Promise<void> {
    /* no observation streams in this harness — see PgBootRecoveryStore.listObservationCursors */
  }

  async rebuildReceiveAdmissionQueue(operationIds: readonly string[]): Promise<void> {
    this.rebuiltReceiveQueues.push([...operationIds]);
  }

  async stopMoneyEngines(reason: string): Promise<void> {
    this.moneyEnginesStopped.push(reason);
  }

  /**
   * Re-sign ONLY the identical persisted preimage. The bytes come from the durable column;
   * nothing here can form fresh bytes, and the signature is bound to the exact digest of what
   * was read (`PREIMAGE_PERSISTED` and the matching move/send recovery rows).
   */
  async #signPersistedPreimage(
    operationId: string,
    kind: OperationKind,
    expectedLeaseEpoch: number,
  ): Promise<void> {
    const preimageText = (
      await psqlMust(
        this.url,
        `SELECT coalesce(exact_preimage_text, '') FROM operations WHERE id = '${operationId}'`,
      )
    ).replace(/\n$/, "");
    if (preimageText === "") {
      throw new Error(`resume asked to sign ${operationId} but no exact preimage is persisted`);
    }
    const signingWalletId = (
      await psqlMust(
        this.url,
        `SELECT coalesce((SELECT l.wallet_id::text FROM wallet_active_leases l
                            JOIN lease_details d ON d.wallet_id = l.wallet_id
                           WHERE d.operation_id = '${operationId}'
                             AND l.lease_role IN ('RECEIVE_WINDOW', 'MOVE_SOURCE', 'SEND_SOURCE')
                           LIMIT 1), '')`,
      )
    ).trim();
    if (signingWalletId === "") {
      throw new Error(`resume asked to sign ${operationId} with no signing-capable lease`);
    }

    const preimageSha256 = createHash("sha256").update(preimageText, "utf8").digest("hex");

    // Live mid-signature boundary: preimage is durable; signature row is not yet written.
    if (await isCrashHookArmed(this.url, CRASH_HOOK.BEFORE_SIGNATURE_PERSIST)) {
      await markCrashHookReached(this.url, CRASH_HOOK.BEFORE_SIGNATURE_PERSIST);
      const outcome = await awaitCrashHookClear(
        this.url,
        CRASH_HOOK.BEFORE_SIGNATURE_PERSIST,
        this.#abort,
      );
      if (outcome === "aborted") {
        throw new Error("crash after preimage, before signature persist");
      }
    }

    const result = await signUnderLease(
      {
        leadership: this.leadership,
        leaseReader: { readActiveLease: (walletId) => this.#readActiveLease(walletId) },
        // Deterministic signer double — this harness proves WHICH bytes reach the signer and
        // how often, never Ed25519 itself (owns that).
        vaultSigner: {
          sign: async (walletId, preimageBytes) => {
            this.signatures.push({
              walletId,
              operationId,
              preimageText: new TextDecoder().decode(preimageBytes),
              preimageSha256: createHash("sha256").update(preimageBytes).digest("hex"),
            });
            return `SIG(${createHash("sha256").update(preimageBytes).digest("hex").slice(0, 32)})`;
          },
        },
        auditLog: {
          append: async (entry) => {
            this.signerAudit.push(entry);
          },
        },
        assertMoneyAdmitted: () => {},
        assertCanOperate: () => {},
        assertWalletMaySign: async () => {},
      },
      {
        walletId: signingWalletId,
        operationId,
        leaseEpoch: BigInt(expectedLeaseEpoch),
        purpose: PURPOSE_BY_KIND[kind],
        preimageText,
        expectedPreimageSha256: preimageSha256,
      },
    );

    await psqlMust(
      this.url,
      `UPDATE operations SET signature_persisted = true, signer_audit_indicates_call = true
        WHERE id = '${operationId}'`,
    );
    if (kind === "SEND_EXTERNAL") {
      // One external partial per operation, structurally (PK). A second partial over
      // different bytes cannot land.
      await psqlMust(
        this.url,
        `INSERT INTO external_partials (operation_id, step_1_signature, preimage_sha256)
         VALUES ('${operationId}', ${sqlText(result.signature)}, '${result.preimageSha256}')`,
      );
    }
  }

  async #readActiveLease(walletId: string): Promise<ActiveLeaseRecord | null> {
    const rows = await jsonRows(
      this.url,
      `SELECT l.wallet_id::text AS wallet_id, d.operation_id::text AS operation_id,
              d.lease_epoch::int AS epoch, l.lease_role AS role
         FROM wallet_active_leases l JOIN lease_details d ON d.wallet_id = l.wallet_id
        WHERE l.wallet_id = '${walletId}'`,
    );
    const row = rows[0];
    if (row === undefined) return null;
    return {
      walletId: String(row.wallet_id),
      operationId: String(row.operation_id),
      epoch: BigInt(Number(row.epoch)),
      role: String(row.role) as LeaseRole,
      lifecycle: "ACTIVE",
    };
  }
}

/* ─── one node instance ───────────────────────────────────────────── */

export interface NodeInstanceOptions {
  readonly name: string;
  readonly url: string;
  readonly lockId: number;
  readonly version?: string;
}

export class NodeInstance {
  readonly name: string;
  readonly latch = new SignerLeadership();
  readonly readiness = new NodeCoreReadinessState({ observationFailureBudget: 3 });
  readonly health: HealthRouteHandlers;
  readonly lossReasons: string[] = [];

  readonly #url: string;
  readonly #lockId: number;
  readonly #abort = { aborted: false };
  #session: PsqlSession | null = null;
  #held: HeldSignerLeadership | null = null;

  constructor(options: NodeInstanceOptions) {
    this.name = options.name;
    this.#url = options.url;
    this.#lockId = options.lockId;
    this.health = createHealthHandlers({
      version: options.version ?? "chaos-test",
      getState: () => this.readiness.snapshot(),
      // Real database probe — a liveness/readiness answer here is not a stub.
      pingDb: async () => {
        await psqlMust(this.#url, "SELECT 1");
      },
    });
  }

  get leadershipHeld(): boolean {
    return this.latch.held;
  }

  /** The backend pid of this instance's dedicated lock connection (for failover injection). */
  async lockBackendPid(): Promise<number> {
    if (this.#session === null) throw new Error(`${this.name}: no lock session`);
    return Number(await this.#session.scalar("SELECT pg_backend_pid()"));
  }

  /** A pool whose single checkout is this instance's own dedicated session. */
  #pool(): LeadershipLockPool {
    return {
      connect: async () => {
        const session = new PsqlSession(this.#url);
        this.#session = session;
        return session;
      },
    };
  }

  /** ONE non-blocking attempt. Never waits for the incumbent. */
  async tryAcquireLeadership(): Promise<boolean> {
    const held = await tryAcquireSignerLeadership(this.#pool(), this.latch, this.#lockId);
    if (held === null) return false;
    this.#armLossDetection(held);
    return true;
  }

  /** The overlap-deploy acquire: jittered backoff, abortable, never blocks HTTP bind. */
  async acquireLeadership(opts: { baseDelayMs?: number; maxDelayMs?: number } = {}): Promise<boolean> {
    const held = await acquireSignerLeadership({
      pool: this.#pool(),
      latch: this.latch,
      lockId: this.#lockId,
      signal: this.#abort,
      baseDelayMs: opts.baseDelayMs ?? 25,
      maxDelayMs: opts.maxDelayMs ?? 200,
    });
    if (held === null) return false;
    this.#armLossDetection(held);
    return true;
  }

  #armLossDetection(held: HeldSignerLeadership): void {
    this.#held = held;
    held.onLost((reason) => {
      this.lossReasons.push(reason);
      this.readiness.setLeadershipHeld(false);
    });
    this.readiness.setLeadershipHeld(true);
  }

  /**
   * The boot-recovery steps against the durable state this database currently holds.
   * Optional `exchange` injects a hanging/failing gateway for live claim/exchange crashes.
   */
  async runBootRecovery(opts: {
    exchange?: GatewayExchangeTransport;
  } = {}): Promise<{ report: BootRecoveryReport; actions: PgBootRecoveryActions }> {
    const actions = new PgBootRecoveryActions(this.#url, this.latch, this.#abort, opts.exchange);
    const report = await runDeterministicBootRecovery({
      leadership: this.latch,
      store: new PgBootRecoveryStore(this.#url),
      actions,
    });
    if (report.ready) {
      this.readiness.markSchemaMigrated();
      this.readiness.setVaultAvailable(true);
      this.readiness.recordObservationReadSuccess();
    }
    return { report, actions };
  }

  /** Graceful drain: abort the acquire loop, run the real release path, stop serving ready. */
  async sigterm(): Promise<void> {
    this.#abort.aborted = true;
    this.readiness.beginShutdown();
    await this.#held?.release();
    this.#held = null;
    this.#session = null;
  }

  /**
   * SIGKILL the lock session: no unlock, no release path. Awaits the production latch
   * flip (connection `end` → markLost) so the ex-leader is observably non-leader before
   * a successor is allowed to act. Durable state is whatever last committed.
   */
  async crash(opts: { latchTimeoutMs?: number } = {}): Promise<void> {
    this.#abort.aborted = true;
    const session = this.#session;
    const wasHeld = this.latch.held;
    session?.child.kill("SIGKILL");
    // Do NOT null #held before latch loss — production onLoss must fire markLost first.
    if (wasHeld && session !== null) {
      const timeoutMs = opts.latchTimeoutMs ?? 5_000;
      const deadline = Date.now() + timeoutMs;
      while (this.latch.held && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 5));
      }
      if (this.latch.held) {
        // Idle psql may not emit end until poked (no socket read loop). Probe once.
        try {
          await session.scalar("SELECT 1");
        } catch {
          /* end path */
        }
        const probeDeadline = Date.now() + timeoutMs;
        while (this.latch.held && Date.now() < probeDeadline) {
          await new Promise((r) => setTimeout(r, 5));
        }
      }
      if (this.latch.held) {
        throw new Error(
          `${this.name}.crash(): leadership latch still held after SIGKILL + probe — ` +
            "ex-leader must be non-leader before successor resume (B4)",
        );
      }
    }
    this.#held = null;
    this.#session = null;
  }

  /**
   * Force both TRY-lock probes onto the server concurrently via a server-side barrier.
   * Returns whether THIS instance won. Pair with another instance's call under Promise.all.
   *
   * Mechanism: each session runs `SELECT pg_sleep(delaySec); SELECT pg_try_advisory_lock(...)`
   * so both backends are inside their sleep before either TRY executes. PostgreSQL, not the
   * event loop, serialises the lock grant.
   */
  /**
   * Force both TRY-lock probes onto the server concurrently via a server-side sleep barrier.
   * Pair two instances under Promise.all — each backend sleeps before pg_try_advisory_lock,
   * so both TRY statements are demonstrably concurrent. PostgreSQL picks the winner.
   */
  async tryAcquireLeadershipConcurrent(barrierDelaySec = 0.15): Promise<boolean> {
    const held = await tryAcquireSignerLeadership(
      {
        connect: async () => {
          const s = new PsqlSession(this.#url);
          this.#session = s;
          const rawQuery = s.query.bind(s);
          let first = true;
          s.query = async (sql: string, values?: readonly unknown[]) => {
            if (first) {
              first = false;
              // pg_sleep alone returns no printable row under -A -t; pair with a literal.
              await s.scalar(`SELECT 1 FROM pg_sleep(${barrierDelaySec})`);
            }
            return rawQuery(sql, values);
          };
          return s;
        },
      },
      this.latch,
      this.#lockId,
    );
    if (held === null) return false;
    this.#armLossDetection(held);
    return true;
  }

  /**
   * Attempt signUnderLease on this instance. Used during failover residual sampling:
   * a true residual dual-leader window would let the ex-leader reach the vault; the
   * production latch must refuse first (NotSignerLeaderError).
   */
  async signProbe(preimageText = '{"probe":true}'): Promise<"signed" | "not_leader" | "rejected"> {
    try {
      await signUnderLease(
        {
          leadership: this.latch,
          leaseReader: {
            readActiveLease: async () => ({
              walletId: "00000000-0000-4000-8000-000000000099",
              operationId: "00000000-0000-4000-8000-000000000098",
              epoch: 1n,
              role: "SEND_SOURCE",
              lifecycle: "ACTIVE",
            }),
          },
          vaultSigner: {
            sign: async () => "PROBE_SIG",
          },
          auditLog: { append: async () => undefined },
          assertMoneyAdmitted: () => {},
          assertCanOperate: () => {},
          assertWalletMaySign: async () => {},
        },
        {
          walletId: "00000000-0000-4000-8000-000000000099",
          operationId: "00000000-0000-4000-8000-000000000098",
          leaseEpoch: 1n,
          purpose: "SPLITCHAIN_STEP_1",
          preimageText,
          expectedPreimageSha256: createHash("sha256").update(preimageText, "utf8").digest("hex"),
        },
      );
      return "signed";
    } catch (err) {
      if (err instanceof NotSignerLeaderError) return "not_leader";
      return "rejected";
    }
  }

  /**
   * Database failover: the SERVER kills this instance's backend from a THIRD session. No
   * SIGTERM, no unlock statement, no release path — the advisory lock is freed server-side
   * while this instance still believes it leads.
   *
   * `probe` then touches the dead socket. A real `pg` client learns of the close from its own
   * socket read loop; an idle `psql` child only notices when it next uses the connection, so
   * this single ordered statement stands in for that read loop. It carries no authority: the
   * latch flip is still produced by the connection's `end`/`error` event inside
   * `tryAcquireSignerLeadership`, never by this harness and never by a wall clock.
   */
  async dropLockConnection(opts: { probe?: boolean } = {}): Promise<void> {
    const pid = await this.lockBackendPid();
    await psqlMust(this.#url, `SELECT pg_terminate_backend(${pid})`);
    if (opts.probe !== false) await this.probeLockConnection();
  }

  /** Touch the lock connection; resolves once the session is confirmed dead or alive. */
  async probeLockConnection(): Promise<void> {
    const session = this.#session;
    if (session === null) return;
    try {
      await session.scalar("SELECT 1");
    } catch {
      /* connection gone — the `end` event has already flipped the latch */
    }
    // psql exits on the failed statement (ON_ERROR_STOP=1); wait for `close` to be observed.
    for (let i = 0; i < 200 && this.latch.held; i += 1) {
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  /** Last-resort teardown; safe to call twice. */
  dispose(): void {
    this.#abort.aborted = true;
    this.#session?.child.kill("SIGKILL");
    this.#session = null;
    this.#held = null;
  }
}

/* ─── fixture seeding ─────────────────────────────────────────────── */

export interface SeedOperationOptions {
  readonly kind: OperationKind;
  readonly status: string;
  readonly leaseEpoch?: number;
  readonly submitBoundaryRecorded?: boolean;
  readonly signerAuditIndicatesCall?: boolean;
  readonly exactPreimagePersisted?: boolean;
  readonly exactPreimageText?: string;
  readonly signaturePersisted?: boolean;
  readonly formationComplete?: boolean;
  readonly queuedReceive?: boolean;
  /** Lease this operation's required wallets. Omit for the "crash before assignment" case. */
  readonly leased?: boolean;
}

export interface SeededOperation {
  readonly operationId: string;
  readonly leaseGroupId: string;
  readonly walletIds: readonly string[];
  readonly preimageText: string;
}

/**
 * Seed the exact durable state one crash boundary leaves behind, and nothing else. A crash
 * is not simulated by editing production code: whatever last committed IS the crash state.
 */
export async function seedOperation(
  url: string,
  opts: SeedOperationOptions,
): Promise<SeededOperation> {
  const operationId = randomUUID();
  const leaseGroupId = randomUUID();
  const nodeId = "b0000000-0000-4000-8000-000000000002";
  const epoch = opts.leaseEpoch ?? 1;
  const roles = ROLE_BY_KIND[opts.kind];
  const preimageText = opts.exactPreimageText ?? `{"operation":"${operationId}","step":"persisted"}`;

  const statements: string[] = [
    `INSERT INTO operations (
       id, kind, status, lease_epoch, submit_boundary_recorded, signer_audit_indicates_call,
       exact_preimage_persisted, exact_preimage_text, signature_persisted, formation_complete,
       required_roles, queued_receive)
     VALUES ('${operationId}', '${opts.kind}', ${sqlText(opts.status)}, ${epoch},
       ${sqlBool(opts.submitBoundaryRecorded ?? false)},
       ${sqlBool(opts.signerAuditIndicatesCall ?? false)},
       ${sqlBool(opts.exactPreimagePersisted ?? false)}, ${sqlText(preimageText)},
       ${sqlBool(opts.signaturePersisted ?? false)}, ${sqlBool(opts.formationComplete ?? false)},
       ARRAY[${roles.map((r) => `'${r}'`).join(", ")}]::text[],
       ${sqlBool(opts.queuedReceive ?? false)});`,
    // Always present so production submit claim FKs can land without a separate seed step.
    `INSERT INTO operation_transactions (operation_id, attempt_no) VALUES ('${operationId}', 1);`,
  ];

  // Ensure the tenant node exists (wallets.node_id → nodes.id).
  statements.unshift(
    `INSERT INTO nodes (id, display_name, identity_public_key)
     VALUES ('${nodeId}', 'chaos-node', '${chaosPubkey("NODE")}')
     ON CONFLICT (id) DO NOTHING;`,
  );

  const walletIds: string[] = [];
  if (opts.leased !== false) {
    statements.push(
      `INSERT INTO lease_group_operations (lease_group_id, operation_id)
       VALUES ('${leaseGroupId}', '${operationId}');`,
    );
    for (const role of roles) {
      const walletId = randomUUID();
      walletIds.push(walletId);
      const pk = chaosPubkey(walletId.replace(/-/g, "").slice(0, 8));
      statements.push(
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
         VALUES ('${walletId}', '${nodeId}', '${pk}', 'node_generated', 'PINNED');`,
      );
      if (role === "RECEIVE_WINDOW" || role === "MOVE_DESTINATION") {
        // RECEIVE_WINDOW requires recovery_verified_at + state=AVAILABLE at lease
        // insert; MOVE_DESTINATION additionally needs a BLESSED destination. Seed recovery
        // for both; bless only MOVE_DESTINATION. column names (wallets.id, etc.).
        const recoveryId = randomUUID();
        const auditEventId = randomUUID();
        // RECEIVE_WINDOW claim-time state is AVAILABLE (pin follows lease insert).
        if (role === "RECEIVE_WINDOW") {
          statements.push(
            `UPDATE wallets SET state = 'AVAILABLE' WHERE id = '${walletId}';`,
          );
        }
        statements.push(
          `INSERT INTO wallet_recovery_verifications
             (id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity)
           VALUES ('${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${"a".repeat(64)}', '${pk}',
                   '${auditEventId}', now(), 'chaos-harness');`,
          `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}'
            WHERE id = '${walletId}';`,
        );
        if (role === "MOVE_DESTINATION") {
          statements.push(
            `INSERT INTO destinations
               (id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id)
             VALUES ('${randomUUID()}', '${nodeId}', '${walletId}', 'BLESSED', now(), '${randomUUID()}', '${randomUUID()}');`,
          );
        }
      }
      // full lease fencing columns (NOT NULL). Sidecar lease_details still holds
      // the operation/epoch/heartbeat fields the boot-recovery ports read.
      statements.push(
        `INSERT INTO wallet_active_leases (
           wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
           lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
         ) VALUES (
           '${walletId}', '${randomUUID()}', '${leaseGroupId}', '${operationId}', '${operationId}',
           '${role}', ${epoch}, now(), now(), '${randomUUID()}'
         );`,
      );
      if (role === "RECEIVE_WINDOW") {
        // Post-lease pin: the lease insert happens BEFORE AVAILABLE→PINNED.
        statements.push(`UPDATE wallets SET state = 'PINNED' WHERE id = '${walletId}';`);
      }
      statements.push(
        `INSERT INTO lease_details (wallet_id, operation_id, lease_group_id, lease_epoch, last_heartbeat_at)
         VALUES ('${walletId}', '${operationId}', '${leaseGroupId}', ${epoch}, now());`,
      );
    }
  }

  await psqlMust(url, statements.join("\n"));
  return { operationId, leaseGroupId, walletIds, preimageText };
}

/** Age a lease's heartbeat far past any staleness threshold (axiom 5 probe). */
export async function ageHeartbeat(url: string, walletId: string, hours: number): Promise<void> {
  await psqlMust(
    url,
    `UPDATE lease_details SET last_heartbeat_at = now() - interval '${hours} hours'
      WHERE wallet_id = '${walletId}'`,
  );
}

export async function countRows(url: string, table: string, where = "true"): Promise<number> {
  return Number((await psqlMust(url, `SELECT count(*)::int FROM ${table} WHERE ${where}`)).trim());
}

/** Sessions currently granted the signer-leadership advisory lock, as PostgreSQL sees it. */
export async function advisoryLockHolders(url: string, lockId: number): Promise<number> {
  const out = await psqlMust(
    url,
    `SELECT count(*)::int FROM pg_locks
      WHERE locktype = 'advisory' AND classid = 0 AND objid = ${lockId} AND granted`,
  );
  return Number(out.trim());
}

/** Every wallet with more than one active lease row. Must always be empty. */
export async function walletsWithDuplicateLeases(url: string): Promise<string[]> {
  const rows = await jsonRows(
    url,
    `SELECT wallet_id::text AS wallet_id FROM wallet_active_leases
      GROUP BY wallet_id HAVING count(*) > 1`,
  );
  return rows.map((r) => String(r.wallet_id));
}
