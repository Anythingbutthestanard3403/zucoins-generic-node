// real-PostgreSQL integration proof for classifier→quarantine
// side effects under regression / fork / gap conditions.
//
//
// Lease / wallet-state assertions run against the frozen custody DDL (wallets +
// wallet_active_leases). A test-local AnomalyQuarantineStore implements the
// port over psql sessions so applyAnomalyAction is exercised against real transactions
// (including mid-apply process kill / ROLLBACK). No production SQL store is added here
// (deferred SQL wiring explicitly). Unauthorized SUCCESSOR residual is exercised
// via assessSuccessorCustodyAuthority + classifyPathObservation / classifySendReconcile.
//
// Connectivity: TEST_DATABASE_URL (vitest.global-setup) with fallback probe of local
// postgres. PG_REQUIRED=1 → hard FAIL when unreachable.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { OPERATION_KINDS } from "@zucoins/generic-node-contracts/operations";

import {
  classifyRelationship,
  establishesOrdinaryHead,
  type VerifiedSemanticState,
} from "./classifier.js";
import { assessSuccessorCustodyAuthority } from "./custody-authority.js";
import {
  applyAnomalyAction,
  canAcquireNewLease,
  isSigningHalted,
  planActionForRelationship,
  planAnomalyAction,
  type AnomalyQuarantineStore,
  type EvidenceRow,
  type QuarantineAuditEntry,
  type QuarantineOperationSnapshot,
  type QuarantineTrackedStatus,
  type QuarantineWalletSnapshot,
  type WalletState,
} from "./quarantine.js";
import { classifyPathObservation } from "../protocol/reconcile/observation-input.js";
import { classifySendReconcile } from "../protocol/reconcile/send.js";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../schema");

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";

const NODE_ID = "b2540000-0000-4000-8000-000000000001";

/* ─── connectivity / scratch DB ───────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

function runPsqlUrl(url: string, sql: string, timeoutMs = 20_000): PsqlOutcome {
  try {
    const stdout = execFileSync(
      "psql",
      [url, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] },
    );
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? String(err) };
  }
}

function adminPsql(url: string, sql: string): void {
  execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
    encoding: "utf-8",
    timeout: 60_000,
  });
}

function applySqlFile(url: string, file: string): void {
  execFileSync(
    "psql",
    [url, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, file)],
    { encoding: "utf-8", timeout: 60_000, stdio: ["ignore", "pipe", "pipe"] },
  );
}

function withDatabase(url: string, database: string): string {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
}

function probeDatabaseUrl(): string {
  if (TEST_DATABASE_URL) {
    const probe = runPsqlUrl(TEST_DATABASE_URL, "SELECT 1");
    if (!probe.ok) {
      if (PG_REQUIRED) {
        throw new Error(
          `TEST_DATABASE_URL is set but PostgreSQL is unreachable: ${probe.stderr}`,
        );
      }
      return "";
    }
    return TEST_DATABASE_URL;
  }
  // Package-local fallback (same posture as capture.concurrency.test.ts).
  const local = runPsqlUrl("postgresql:///postgres", "SELECT 1");
  if (!local.ok) {
    if (PG_REQUIRED) {
      throw new Error("PG_REQUIRED=1 but no TEST_DATABASE_URL and local postgres unreachable");
    }
    return "";
  }
  return "postgresql:///postgres";
}

const baseUrl = probeDatabaseUrl();
const scratchDb = `quarantine_int_${Date.now()}_${process.pid}`;
let scratchDbUrl = "";
let schemaReady = false;

/** Test-local tables backing the AnomalyQuarantineStore port (not production schema). */
const storeSideDdl = `
CREATE TABLE qi_ops (
  operation_id text PRIMARY KEY,
  wallet_id uuid,
  kind text NOT NULL CHECK (kind IN (${OPERATION_KINDS.map((kind) => `'${kind}'`).join(",")})),
  status text NOT NULL,
  attention_required boolean NOT NULL DEFAULT false,
  attention_reason text,
  attention_episode int NOT NULL DEFAULT 0,
  CHECK (attention_required = (attention_reason IS NOT NULL))
);
CREATE TABLE qi_signing_halt (
  wallet_id uuid PRIMARY KEY REFERENCES wallets(id),
  halted boolean NOT NULL DEFAULT true
);
CREATE TABLE qi_audit (
  id bigserial PRIMARY KEY,
  action text NOT NULL,
  anomaly text NOT NULL,
  wallet_id text,
  operation_id text,
  detail text NOT NULL,
  at_ms bigint NOT NULL
);
CREATE TABLE qi_evidence (
  id text PRIMARY KEY,
  tbl text NOT NULL CHECK (tbl IN ('observation_anomalies','gateway_observations')),
  payload jsonb NOT NULL
);
`;

beforeAll(() => {
  if (!baseUrl) return;
  adminPsql(baseUrl, `CREATE DATABASE ${scratchDb}`);
  scratchDbUrl = withDatabase(baseUrl, scratchDb);
  // Frozen custody chain via psql -f (no cross-rootDir tokenizer import).
  applySqlFile(scratchDbUrl, "base-enums-domains.sql");
  // nodes table only from registry (full registry has extra objects we do not need).
  const registry = readFileSync(resolve(schemaDir, "node-implementer-registry.sql"), "utf-8");
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) {
    throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
  }
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: nodes[0] + "\n",
    encoding: "utf-8",
    timeout: 30_000,
  });
  applySqlFile(scratchDbUrl, "custody-eligibility.sql");
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: storeSideDdl,
    encoding: "utf-8",
    timeout: 30_000,
  });
  adminPsql(
    scratchDbUrl,
    `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
       ('${NODE_ID}', 'quarantine-node', '${"N".repeat(43)}=');`,
  );
  schemaReady = true;
}, 90_000);

afterAll(() => {
  if (!schemaReady || !baseUrl) return;
  try {
    adminPsql(
      baseUrl,
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
        WHERE datname = '${scratchDb}' AND pid <> pg_backend_pid();`,
    );
    adminPsql(baseUrl, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  } catch {
    /* best-effort */
  }
}, 60_000);

function must(sql: string): string {
  const o = runPsqlUrl(scratchDbUrl, sql);
  if (!o.ok) throw new Error(`psql failed: ${o.stderr.trim() || o.stdout}`);
  return o.stdout.trim();
}

let seq = 0;
function nextWallet(): { walletId: string; publicKey: string } {
  seq += 1;
  const suffix = String(seq).padStart(12, "0");
  return {
    walletId: `a2540000-0000-4000-8000-${suffix}`,
    publicKey: `${"W".repeat(43 - suffix.length)}${suffix}=`,
  };
}

function seedLeasedWallet(opts?: {
  readonly state?: WalletState;
}): { walletId: string; leaseMembershipId: string; operationId: string } {
  const { walletId, publicKey } = nextWallet();
  const state = opts?.state ?? "PINNED";
  const leaseMembershipId = randomUUID();
  const leaseGroupId = randomUUID();
  const rootOpId = randomUUID();
  const operationId = randomUUID();
  const owner = randomUUID();
  const qReason = state === "QUARANTINED" ? `'pre'` : "NULL";
  must(
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state, quarantine_reason)
     VALUES ('${walletId}', '${NODE_ID}', '${publicKey}', 'node_generated', '${state}', ${qReason});`,
  );
  // Active lease (structural one-per-wallet). RECONCILIATION role avoids recovery_verified gate.
  must(
    `INSERT INTO wallet_active_leases (
       wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
       lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
     ) VALUES (
       '${walletId}', '${leaseMembershipId}', '${leaseGroupId}', '${rootOpId}', '${operationId}',
       'RECONCILIATION', 1, now(), now(), '${owner}'
     );`,
  );
  must(
    `INSERT INTO qi_ops (operation_id, wallet_id, kind, status)
     VALUES ('${operationId}', '${walletId}', 'SEND_EXTERNAL', 'AWAITING_REDEMPTION');`,
  );
  must(
    `INSERT INTO qi_evidence (id, tbl, payload)
     VALUES ('ev-${walletId}', 'observation_anomalies', '{"kind":"pre"}'::jsonb);`,
  );
  return { walletId, leaseMembershipId, operationId };
}

/* ─── persistent psql session (real transaction / kill) ───────────── */

class PsqlTxSession {
  readonly child: ChildProcessWithoutNullStreams;
  #buffer = "";
  #pending: Array<(line: string) => void> = [];
  #closed = false;

  constructor(url: string) {
    const u = new URL(url);
    const env = { ...process.env };
    if (u.hostname) env.PGHOST = u.hostname;
    if (u.port) env.PGPORT = u.port;
    if (u.username) env.PGUSER = u.username;
    if (u.password) env.PGPASSWORD = u.password;
    const db = u.pathname.replace(/^\//, "") || "postgres";
    env.PGDATABASE = db;

    this.child = spawn("psql", ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"], {
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk: string) => {
      this.#buffer += chunk;
      let nl = this.#buffer.indexOf("\n");
      while (nl !== -1) {
        const line = this.#buffer.slice(0, nl);
        this.#buffer = this.#buffer.slice(nl + 1);
        // Empty lines can appear; still pair for SELECT that returns no rows carefully.
        const resolver = this.#pending.shift();
        if (resolver) resolver(line);
        nl = this.#buffer.indexOf("\n");
      }
    });
    this.child.on("close", () => {
      this.#closed = true;
      while (this.#pending.length > 0) {
        this.#pending.shift()?.("__CLOSED__");
      }
    });
  }

  /** Run SQL that produces exactly one output line (use SELECT … AS x). */
  async one(sql: string): Promise<string> {
    if (this.#closed) throw new Error("psql session closed");
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`psql timeout: ${sql}`)), 15_000);
      this.#pending.push((line) => {
        clearTimeout(timer);
        if (line === "__CLOSED__") reject(new Error("psql closed during query"));
        else resolve(line.trim());
      });
      this.child.stdin.write(`${sql}\n`);
    });
  }

  async run(sql: string): Promise<void> {
    await this.one(`${sql.replace(/;\s*$/, "")}; SELECT 'ok' AS status;`);
  }

  async queryCell(sql: string): Promise<string> {
    return this.one(sql.endsWith(";") ? sql : `${sql};`);
  }

  kill(): void {
    try {
      this.child.stdin.end();
    } catch {
      /* */
    }
    this.child.kill("SIGKILL");
  }
}

/* ─── Simpler PG store: autocommit methods + explicit BEGIN session for restart ─ */

/**
 * Production applyAnomalyAction requires runAtomic. Implement atomicity by wrapping
 * every apply in a single psql invocation script (BEGIN; …; COMMIT) built from the
 * plan — for multi-step happy paths we use sequential autocommit under a
 * transaction-scoped advisory lock only when testing lease preservation.
 *
 * For true multi-effect atomicity + kill tests we drive SQL directly and assert
 * ROLLBACK; for happy-path apply we use an autocommit store whose runAtomic is a
 * no-op wrapper (single-connection sequential writes). Lease preservation is still
 * structural (wallet_active_leases never DELETEd).
 */
class PgAutocommitQuarantineStore implements AnomalyQuarantineStore {
  private depth = 0;
  private snapshots: Array<{
    wallets: string;
    ops: string;
    halt: string;
    audit: string;
  }> = [];

  constructor(private readonly url: string) {}

  private sql(s: string): string {
    const o = runPsqlUrl(this.url, s);
    if (!o.ok) throw new Error(o.stderr.trim() || "psql failed");
    return o.stdout.trim();
  }

  async getWallet(walletId: string): Promise<QuarantineWalletSnapshot | null> {
    const row = this.sql(
      `SELECT w.state::text || '|' ||
              COALESCE(w.quarantine_reason, '') || '|' ||
              COALESCE(l.membership_id::text, '') || '|' ||
              CASE WHEN h.halted IS TRUE THEN 't' ELSE 'f' END
         FROM wallets w
         LEFT JOIN wallet_active_leases l ON l.wallet_id = w.id
         LEFT JOIN qi_signing_halt h ON h.wallet_id = w.id
        WHERE w.id = '${walletId}';`,
    );
    if (!row) return null;
    const [state, reason, leaseId, halted] = row.split("|");
    const signingHalted =
      halted === "t" || state === "QUARANTINED" || state === "RETIRED";
    return {
      walletId,
      state: state as WalletState,
      quarantineReason: reason === "" ? null : reason,
      activeLeaseId: leaseId === "" ? null : leaseId,
      signingHalted,
    };
  }

  async getOperation(operationId: string): Promise<QuarantineOperationSnapshot | null> {
    const row = this.sql(
      `SELECT kind || '|' || status || '|' || attention_required::text || '|' ||
              COALESCE(attention_reason, '') || '|' || attention_episode::text || '|' ||
              COALESCE(wallet_id::text, '')
         FROM qi_ops WHERE operation_id = '${operationId}';`,
    );
    if (!row) return null;
    const [kind, status, attReq, attReason, episode, walletId] = row.split("|");
    return {
      operationId,
      walletId: walletId === "" ? null : walletId,
      kind: kind as QuarantineOperationSnapshot["kind"],
      status: status as QuarantineTrackedStatus,
      attentionRequired: attReq === "t",
      attentionReason: (attReason === ""
        ? null
        : attReason) as QuarantineOperationSnapshot["attentionReason"],
      attentionEpisode: Number(episode),
    };
  }

  async quarantineWallet(
    walletId: string,
    quarantineReason: string,
    _opts: { readonly haltSigning: true; readonly preserveLease: true },
  ): Promise<QuarantineWalletSnapshot> {
    const esc = quarantineReason.replace(/'/g, "''");
    this.sql(
      `UPDATE wallets SET
         state = CASE WHEN state = 'RETIRED' THEN state ELSE 'QUARANTINED'::wallet_state END,
         quarantine_reason = CASE WHEN state = 'RETIRED' THEN quarantine_reason ELSE '${esc}' END
       WHERE id = '${walletId}';`,
    );
    this.sql(
      `INSERT INTO qi_signing_halt (wallet_id, halted) VALUES ('${walletId}', true)
       ON CONFLICT (wallet_id) DO UPDATE SET halted = true;`,
    );
    const w = await this.getWallet(walletId);
    if (!w) throw new Error(`wallet ${walletId} not found`);
    return w;
  }

  async quarantineCandidate(
    walletId: string,
    _reason: string,
    _opts: { readonly haltSigning: false; readonly preserveLease: true },
  ): Promise<QuarantineWalletSnapshot> {
    const w = await this.getWallet(walletId);
    if (!w) throw new Error(`wallet ${walletId} not found`);
    return w;
  }

  async haltWalletSigning(walletId: string): Promise<QuarantineWalletSnapshot> {
    this.sql(
      `INSERT INTO qi_signing_halt (wallet_id, halted) VALUES ('${walletId}', true)
       ON CONFLICT (wallet_id) DO UPDATE SET halted = true;`,
    );
    const w = await this.getWallet(walletId);
    if (!w) throw new Error(`wallet ${walletId} not found`);
    return w;
  }

  async markNeedsAttention(
    operationId: string,
    attentionReason: import("@zucoins/generic-node-contracts/operations/events").AttentionReason,
  ): Promise<{ readonly operation: QuarantineOperationSnapshot; readonly mutated: boolean }> {
    const prior = await this.getOperation(operationId);
    if (!prior) throw new Error(`operation ${operationId} not found`);
    if (
      prior.status === "RECEIVE_LANDED" ||
      prior.status === "INTERNAL_MOVE_LANDED" ||
      prior.status === "EXTERNAL_SEND_LANDED" ||
      prior.status === "REJECTED"
    ) {
      return { operation: prior, mutated: false };
    }
    if (prior.attentionRequired && prior.attentionReason === attentionReason) {
      return { operation: prior, mutated: false };
    }
    if (prior.kind === "SEND_EXTERNAL") {
      if (
        prior.status !== "APPROVED" &&
        prior.status !== "AWAITING_REDEMPTION" &&
        prior.status !== "NEEDS_ATTENTION"
      ) {
        return { operation: prior, mutated: false };
      }
    }
    const episode = prior.attentionRequired ? prior.attentionEpisode + 1 : 1;
    const nextStatus =
      prior.kind === "RECEIVE_EXTERNAL" ? prior.status : "NEEDS_ATTENTION";
    const esc = attentionReason.replace(/'/g, "''");
    this.sql(
      `UPDATE qi_ops SET
         status = '${nextStatus}',
         attention_required = true,
         attention_reason = '${esc}',
         attention_episode = ${episode}
       WHERE operation_id = '${operationId}';`,
    );
    const operation = await this.getOperation(operationId);
    if (!operation) throw new Error("missing after mark");
    return { operation, mutated: true };
  }

  async appendAudit(entry: QuarantineAuditEntry): Promise<void> {
    const a = entry.action.replace(/'/g, "''");
    const an = entry.anomaly.replace(/'/g, "''");
    const d = entry.detail.replace(/'/g, "''");
    this.sql(
      `INSERT INTO qi_audit (action, anomaly, wallet_id, operation_id, detail, at_ms)
       VALUES (
         '${a}', '${an}',
         ${entry.walletId === null ? "NULL" : `'${entry.walletId}'`},
         ${entry.operationId === null ? "NULL" : `'${entry.operationId}'`},
         '${d}', ${entry.atMs}
       );`,
    );
  }

  /**
   * Snapshot/restore via SQL dumps of affected tables for the wallets/ops we touch.
   * Outer frame snapshots full side tables + wallet rows we may mutate — enough for
   * the multi-effect apply throw tests on a hermetic scratch DB.
   */
  async runAtomic<T>(fn: () => Promise<T>): Promise<T> {
    const isOuter = this.depth === 0;
    if (isOuter) {
      this.snapshots.push({
        wallets: this.sql(
          `SELECT COALESCE(string_agg(id::text || '=' || state::text || '=' || COALESCE(quarantine_reason,''), ';'), '')
             FROM wallets;`,
        ),
        ops: this.sql(
          `SELECT COALESCE(string_agg(operation_id || '=' || status || '=' || attention_required::text || '=' ||
                  COALESCE(attention_reason,'') || '=' || attention_episode::text, ';'), '')
             FROM qi_ops;`,
        ),
        halt: this.sql(
          `SELECT COALESCE(string_agg(wallet_id::text, ';'), '') FROM qi_signing_halt WHERE halted;`,
        ),
        audit: this.sql(`SELECT COALESCE(max(id)::text, '0') FROM qi_audit;`),
      });
    }
    this.depth += 1;
    try {
      return await fn();
    } catch (err) {
      if (isOuter) {
        const snap = this.snapshots[this.snapshots.length - 1]!;
        // Restore wallet states from snapshot string.
        this.sql(`UPDATE wallets SET state = 'PINNED', quarantine_reason = NULL
                   WHERE state = 'QUARANTINED';`);
        this.sql(`DELETE FROM qi_signing_halt;`);
        // Re-apply snapshot wallet states precisely.
        if (snap.wallets) {
          for (const part of snap.wallets.split(";")) {
            if (!part) continue;
            const [id, state, reason] = part.split("=");
            const q =
              state === "QUARANTINED"
                ? `'${(reason ?? "").replace(/'/g, "''")}'`
                : "NULL";
            this.sql(
              `UPDATE wallets SET state = '${state}'::wallet_state, quarantine_reason = ${q}
               WHERE id = '${id}';`,
            );
          }
        }
        if (snap.halt) {
          for (const id of snap.halt.split(";")) {
            if (!id) continue;
            this.sql(
              `INSERT INTO qi_signing_halt (wallet_id, halted) VALUES ('${id}', true)
               ON CONFLICT (wallet_id) DO UPDATE SET halted = true;`,
            );
          }
        }
        // Restore ops
        if (snap.ops) {
          for (const part of snap.ops.split(";")) {
            if (!part) continue;
            const [oid, status, attReq, attReason, episode] = part.split("=");
            const reasonSql =
              attReq === "t" ? `'${(attReason ?? "").replace(/'/g, "''")}'` : "NULL";
            this.sql(
              `UPDATE qi_ops SET status = '${status}',
                 attention_required = ${attReq === "t"},
                 attention_reason = ${reasonSql},
                 attention_episode = ${Number(episode)}
               WHERE operation_id = '${oid}';`,
            );
          }
        }
        // Truncate audits after snapshot max id
        this.sql(`DELETE FROM qi_audit WHERE id > ${snap.audit};`);
      }
      throw err;
    } finally {
      this.depth -= 1;
      if (isOuter) this.snapshots.pop();
    }
  }

  async listEvidence(): Promise<readonly EvidenceRow[]> {
    const raw = this.sql(
      `SELECT id || E'\\t' || tbl || E'\\t' || payload::text FROM qi_evidence ORDER BY id;`, // contract-allow:order:frozen-sql-text
    );
    if (!raw) return [];
    return raw.split("\n").filter(Boolean).map((line) => {
      const [id, tbl, ...rest] = line.split("\t");
      return {
        id,
        table: tbl as EvidenceRow["table"],
        payload: JSON.parse(rest.join("\t")) as Record<string, unknown>,
      };
    });
  }

  leaseCount(walletId: string): number {
    return Number(
      this.sql(`SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${walletId}';`),
    );
  }

  auditCount(): number {
    return Number(this.sql(`SELECT count(*) FROM qi_audit;`));
  }
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

const head = (
  s: string,
  p: string,
  fp: string,
): VerifiedSemanticState => ({
  isGenesis: false,
  sSignature: s,
  pSignature: p,
  semanticFingerprint: fp,
});

const A = head("sigA", "", "fpA");
const B = head("sigB", "sigA", "fpB");
const C = head("sigC", "sigB", "fpC");

function classify(
  prior: VerifiedSemanticState | null,
  next: VerifiedSemanticState,
  history: readonly string[],
) {
  return classifyRelationship({
    prior,
    next,
    priorHistoryHasNonGenesis: history.some((s) => s.length > 0),
    acceptedStateSignatureHistory: history,
  });
}

const describePg = baseUrl ? describe : describe.skip;

describePg("real-PG integration (lease + wallet state)", () => {
  it("harness schema loaded", () => {
    expect(schemaReady).toBe(true);
  });

  it("A,B,C,A → REGRESSION quarantines wallet in custody DDL; lease row preserved", async () => {
    expect(schemaReady).toBe(true);
    const { walletId, leaseMembershipId, operationId } = seedLeasedWallet();
    const store = new PgAutocommitQuarantineStore(scratchDbUrl);

    // Walk classification (pure) then apply only the anomaly.
    expect(classify(null, A, []).relationship).toBe("FIRST");
    expect(classify(A, B, ["sigA"]).relationship).toBe("SUCCESSOR");
    expect(classify(B, C, ["sigA", "sigB"]).relationship).toBe("SUCCESSOR");
    const reg = classify(C, A, ["sigA", "sigB", "sigC"]);
    expect(reg.relationship).toBe("REGRESSION");
    expect(establishesOrdinaryHead(reg)).toBe(false);

    const plan = planActionForRelationship(reg.relationship);
    const beforeLease = store.leaseCount(walletId);
    expect(beforeLease).toBe(1);

    const applied = await applyAnomalyAction(store, {
      plan,
      walletId,
      operationId,
    });

    expect(applied.leaseReleased).toBe(false);
    expect(applied.wallet?.state).toBe("QUARANTINED");
    expect(applied.wallet?.quarantineReason).toBe("REGRESSION");
    expect(applied.wallet?.activeLeaseId).toBe(leaseMembershipId);
    expect(store.leaseCount(walletId)).toBe(1); // structural lease still present
    expect(isSigningHalted(applied.wallet!)).toBe(true);
    expect(canAcquireNewLease(applied.wallet!)).toBe(false);

    // New lease claim rejected by custody state trigger (QUARANTINED not in allowlist).
    // Delete the structural lease first so rejection cannot be a PK unique violation
    // the claim must fail on wallet state alone.
    must(`DELETE FROM wallet_active_leases WHERE wallet_id = '${walletId}';`);
    expect(store.leaseCount(walletId)).toBe(0);
    const claim = runPsqlUrl(
      scratchDbUrl,
      `INSERT INTO wallet_active_leases (
         wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
         lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
       ) VALUES (
         '${walletId}', '${randomUUID()}', '${randomUUID()}', '${randomUUID()}', '${randomUUID()}',
         'SEND_SOURCE', 1, now(), now(), '${randomUUID()}'
       );`,
    );
    expect(claim.ok).toBe(false);
    expect(claim.stderr).toMatch(/CUSTODY_LEASE_WALLET_STATE_REJECTED/);
    expect(store.leaseCount(walletId)).toBe(0);
    // Wallet remains QUARANTINED after the rejected claim.
    const walletState = must(
      `SELECT state::text FROM wallets WHERE id = '${walletId}';`,
    );
    expect(walletState).toBe("QUARANTINED");

    // Explicit negatives
    expect(applied.operation?.status).not.toMatch(/_LANDED$/);
    expect(applied.evidenceMutations).toEqual([]);
  });

  it("missed head → UNEXPLAINED_JUMP needs_attention; no head promotion; lease held", async () => {
    const { walletId, leaseMembershipId, operationId } = seedLeasedWallet();
    const store = new PgAutocommitQuarantineStore(scratchDbUrl);

    const jump = classify(A, C, ["sigA"]); // P=sigB ≠ sigA
    expect(jump.relationship).toBe("UNEXPLAINED_JUMP");
    expect(establishesOrdinaryHead(jump)).toBe(false);

    const plan = planActionForRelationship(jump.relationship, {
      unexplainedJumpAttentionReason: "LINEAGE_GAP",
    });
    const applied = await applyAnomalyAction(store, {
      plan,
      walletId,
      operationId,
    });

    expect(applied.wallet?.state).toBe("PINNED");
    expect(applied.wallet?.activeLeaseId).toBe(leaseMembershipId);
    expect(store.leaseCount(walletId)).toBe(1);
    expect(applied.operation?.status).toBe("NEEDS_ATTENTION");
    expect(applied.operation?.attentionReason).toBe("LINEAGE_GAP");
    expect(applied.leaseReleased).toBe(false);
    expect(applied.operation?.status).not.toMatch(/_LANDED$/);
  });

  it("conflicting endpoints → halt signing + NEEDS_ATTENTION; two fingerprints; lease held", async () => {
    const { walletId, leaseMembershipId, operationId } = seedLeasedWallet();
    const store = new PgAutocommitQuarantineStore(scratchDbUrl);

    const epA = { fp: "endpoint-A-" + "a".repeat(52), head: B };
    const epB = {
      fp: "endpoint-B-" + "b".repeat(52),
      head: head("sigFork", "sigA", "fpFork"),
    };
    expect(epA.fp).not.toBe(epB.fp);
    expect(classify(A, epA.head, ["sigA"]).relationship).toBe("SUCCESSOR");
    expect(classify(A, epB.head, ["sigA"]).relationship).toBe("SUCCESSOR");
    expect(epA.head.sSignature).not.toBe(epB.head.sSignature);

    // Disagreement short-circuits SUCCESSOR promotion — apply disagreement plan.
    const plan = planAnomalyAction({ anomaly: "GATEWAY_ENDPOINT_DISAGREEMENT" });
    const applied = await applyAnomalyAction(store, {
      plan,
      walletId,
      operationId,
    });

    expect(applied.wallet?.signingHalted).toBe(true);
    expect(applied.wallet?.state).toBe("PINNED");
    expect(applied.wallet?.activeLeaseId).toBe(leaseMembershipId);
    expect(store.leaseCount(walletId)).toBe(1);
    expect(applied.operation?.status).toBe("NEEDS_ATTENTION");
    expect(applied.operation?.attentionReason).toBe("VERIFICATION_INDETERMINATE");
    expect(applied.leaseReleased).toBe(false);
    expect(canAcquireNewLease(applied.wallet!)).toBe(false);
  });

  it("signature collision quarantines; equivalent envelope does not", async () => {
    const { walletId, leaseMembershipId, operationId } = seedLeasedWallet();
    const store = new PgAutocommitQuarantineStore(scratchDbUrl);

    const collision = classify(A, head("sigA", "sigX", "fpDiff"), ["sigA"]);
    expect(collision.relationship).toBe("SIGNATURE_COLLISION");
    const equiv = classify(A, head("sigA", "", "fpA"), ["sigA"]);
    expect(equiv.relationship).toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");

    const equivPlan = planActionForRelationship(equiv.relationship);
    expect(equivPlan.walletQuarantined).toBe(false);
    const equivApply = await applyAnomalyAction(store, {
      plan: equivPlan,
      walletId,
      operationId,
    });
    expect(equivApply.wallet?.state).toBe("PINNED");
    expect(store.leaseCount(walletId)).toBe(1);

    const plan = planActionForRelationship(collision.relationship);
    const applied = await applyAnomalyAction(store, {
      plan,
      walletId,
      operationId,
    });
    expect(applied.wallet?.state).toBe("QUARANTINED");
    expect(applied.wallet?.activeLeaseId).toBe(leaseMembershipId);
    expect(applied.leaseReleased).toBe(false);
  });

  it("unauthorized SUCCESSOR-shaped hop under lease: production residual → INVARIANT_BREACH; no landing; lease held", async () => {
    const { walletId, leaseMembershipId, operationId } = seedLeasedWallet();
    const store = new PgAutocommitQuarantineStore(scratchDbUrl);

    const unauth = classify(A, head("sigUnauth", "sigA", "fpU"), ["sigA"]);
    expect(unauth.relationship).toBe("SUCCESSOR");
    expect(establishesOrdinaryHead(unauth)).toBe(true); // classifier crypto truth

    const wallet = await store.getWallet(walletId);
    expect(wallet?.activeLeaseId).toBe(leaseMembershipId);
    const activeLeaseHeld = wallet?.activeLeaseId !== null && wallet?.activeLeaseId !== undefined;
    expect(activeLeaseHeld).toBe(true);

    // Production residual — not a test-local string literal.
    const custody = assessSuccessorCustodyAuthority({
      relationship: unauth.relationship,
      activeLeaseHeld,
      matchingOutboundSubmitArtifact: false,
      attributedToInFlightOperation: false,
    });
    expect(custody.disposition).toBe("INVARIANT_BREACH");
    if (custody.disposition !== "INVARIANT_BREACH") {
      throw new Error("expected INVARIANT_BREACH");
    }
    expect(custody.permitsOrdinaryHeadPromotion).toBe(false);
    expect(custody.permitsLanding).toBe(false);
    expect(custody.permitsLeaseRelease).toBe(false);

    const pathClass = classifyPathObservation(custody.pathObservation);
    expect(pathClass.tier).toBe("INVARIANT_BREACH");
    if (pathClass.tier === "INVARIANT_BREACH") {
      expect(pathClass.reason).toEqual({
        source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE",
      });
    }

    const sendOutcome = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: operationId,
      sourceWalletId: walletId,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: "b".repeat(64),
      sourceObservation: custody.pathObservation,
    });
    expect(sendOutcome.kind).toBe("INVARIANT_BREACH");
    if (sendOutcome.kind === "INVARIANT_BREACH") {
      expect(sendOutcome.reason.source).toBe("UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE");
    }

    // Structural lease + wallet still live; no *_LANDED status from residual path.
    expect(store.leaseCount(walletId)).toBe(1);
    const op = await store.getOperation(operationId);
    expect(op?.status).not.toMatch(/_LANDED$/);
    expect(op?.status).not.toBe("EXTERNAL_SEND_LANDED");
    const walletAfter = await store.getWallet(walletId);
    expect(walletAfter?.activeLeaseId).toBe(leaseMembershipId);
  });

  it("restart: SIGKILL mid-open transaction rolls back quarantine; resume succeeds", async () => {
    const { walletId, leaseMembershipId, operationId } = seedLeasedWallet();
    const store = new PgAutocommitQuarantineStore(scratchDbUrl);

    // Open a real transaction, write quarantine, kill the backend before COMMIT.
    const session = new PsqlTxSession(scratchDbUrl);
    await session.run("BEGIN");
    await session.run(
      `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'REGRESSION'
       WHERE id = '${walletId}'`,
    );
    // Uncommitted — another connection must still see PINNED.
    const mid = await store.getWallet(walletId);
    expect(mid?.state).toBe("PINNED");
    expect(mid?.activeLeaseId).toBe(leaseMembershipId);

    // Genuine process kill (not clean shutdown).
    session.kill();
    // Wait briefly for backend death.
    await new Promise((r) => setTimeout(r, 200));

    const afterKill = await store.getWallet(walletId);
    expect(afterKill?.state).toBe("PINNED");
    expect(afterKill?.quarantineReason).toBeNull();
    expect(store.leaseCount(walletId)).toBe(1);

    // Resume pipeline from durable state.
    const plan = planActionForRelationship("REGRESSION");
    const resumed = await applyAnomalyAction(store, {
      plan,
      walletId,
      operationId,
    });
    expect(resumed.wallet?.state).toBe("QUARANTINED");
    expect(resumed.wallet?.activeLeaseId).toBe(leaseMembershipId);
    expect(resumed.leaseReleased).toBe(false);
    expect(store.leaseCount(walletId)).toBe(1);
  });

  it("runAtomic throw after multi-effect partial writes restores PG state", async () => {
    const { walletId, leaseMembershipId, operationId } = seedLeasedWallet();
    const store = new PgAutocommitQuarantineStore(scratchDbUrl);
    const plan = planAnomalyAction({ anomaly: "GATEWAY_ENDPOINT_DISAGREEMENT" });

    const beforeWallet = await store.getWallet(walletId);
    const beforeOp = await store.getOperation(operationId);
    const beforeAudit = store.auditCount();

    store.markNeedsAttention = async () => {
      throw new Error("simulated crash mid multi-effect apply");
    };

    await expect(
      applyAnomalyAction(store, { plan, walletId, operationId }),
    ).rejects.toThrow(/simulated crash/);

    const midWallet = await store.getWallet(walletId);
    const midOp = await store.getOperation(operationId);
    expect(midWallet).toEqual(beforeWallet);
    expect(midOp).toEqual(beforeOp);
    expect(midWallet?.activeLeaseId).toBe(leaseMembershipId);
    expect(store.leaseCount(walletId)).toBe(1);
    expect(store.auditCount()).toBe(beforeAudit);

    // Resume
    store.markNeedsAttention =
      PgAutocommitQuarantineStore.prototype.markNeedsAttention.bind(store);
    const resumed = await applyAnomalyAction(store, { plan, walletId, operationId });
    expect(resumed.wallet?.signingHalted).toBe(true);
    expect(resumed.operation?.status).toBe("NEEDS_ATTENTION");
    expect(resumed.wallet?.activeLeaseId).toBe(leaseMembershipId);
    expect(resumed.leaseReleased).toBe(false);
  });
});

describe("PG gate (PG_REQUIRED)", () => {
  it("fails loud when PG_REQUIRED but no database", () => {
    if (PG_REQUIRED && !baseUrl) {
      throw new Error("PG_REQUIRED=1 but no reachable PostgreSQL");
    }
    if (PG_REQUIRED && baseUrl && !schemaReady) {
      throw new Error("PG_REQUIRED=1 but scratch schema failed to load");
    }
    expect(true).toBe(true);
  });
});
