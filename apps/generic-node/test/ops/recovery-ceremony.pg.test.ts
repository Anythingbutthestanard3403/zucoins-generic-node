// The recovery-verified ceremony pack, proven end to end against real Postgres.
//
// Covers the backup archive export + the restore and recovery-verification
// ceremony (workers refuse assign without recovery_verified_at).
//
// The gap this closes. Two suites already touch this ground and neither proves the pack:
//   - test/ops/recovery-ceremony.test.ts:172 `makeMemoryLiveSql` runs the ceremony against a
//     hand-written in-memory SQL fake — never a real live database, never a real live export.
//   - test/money-workers-fundable.pg.test.ts:354-394 uses real Postgres but calls
//     `stampRecoveryVerification` with the census/probe booleans supplied by hand, and says so
//     at its line 6-8: "NOT a full operator export/restore ceremony".
// So nothing ran the operator ceremony (live export → throwaway restore → per-wallet vault
// open, census, archived-proof verify, fresh probe → live stamp) over wallets the pool scaler
// actually minted, and nothing proved the recovery-verified assign gate opens afterwards.
//
// What this asserts, in order, on one disposable database:
//   1. Freshly minted pool wallets are born blocked — recovery_verified_at IS NULL
//      (start-money-workers.ts:300 and the mint header at :17 — workers never stamp).
//   2. A CREATED receive queued against that pool logs NO_ELIGIBLE_WALLET and is NOT assigned.
//   3. `runRecoveryCeremony` — the operator CLI entry point in src/ops/run-recovery-ceremony.ts,
//      no SQL written here — stamps ≥1 wallet. AC1.
//   4. The next `promoteQueuedReceives` tick assigns that receive and logs
//      "money-workers: promoted assigns=" (start-money-workers.ts:798). AC2.
//
// Never asserts on key material: the ceremony summary carries digests and counts only.

import { randomBytes, randomUUID, createHmac } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  deriveRootKey,
  ensureActiveNodeSigningKey,
  EncryptedWalletKeyStore,
  InMemoryVaultAccessAuditLog,
  migrateLeaseFoundation,
  toBase64UrlPadded,
  VaultSqlStore,
  DEFAULT_ADMIN_USERNAME,
  SqlAdminUserStore,
  createPoolAdminUserExecutor,
  generateTotpSecret,
  bootstrapInitialAdmin,
} from "@zucoins/node-core";

import {
  ensureNodeRow,
  generateEphemeralIdentityPublicKey,
} from "../../src/bootstrap/genesis.js";
import { startMoneyWorkers } from "../../src/money-workers/start-money-workers.js";
import { runRecoveryCeremony } from "../../src/ops/run-recovery-ceremony.js";

const PG_TEST_TIMEOUT_MS = 240_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
// ≥32 chars — the ceremony CLI refuses shorter (MIN_MASTER_KEY_CHARS).
const MASTER = "ceremony-pack-master-key-32b!!!!!!!!!!!!";

// the ceremony start consumes a FRESH single-use TOTP. These helpers
// mint a valid code from a base32 secret the test enrols on the default admin operator.
const TOTP_PERIOD = 30;
function generateTotpCode(secretBytes: Uint8Array, nowMs: number): string {
  const timestep = Math.floor(nowMs / 1000 / TOTP_PERIOD);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timestep));
  const hmac = createHmac("sha1", secretBytes).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    (hmac[offset + 1]! << 16) |
    (hmac[offset + 2]! << 8) |
    hmac[offset + 3]!;
  return (code % 1_000_000).toString().padStart(6, "0");
}
// RFC 4648 base32 decode (the TOTP secret store format).
function decodeBase32(b32: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = b32.replace(/=+$/, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

function hasClientTool(bin: string): boolean {
  try {
    execFileSync(bin, bin === "pg_isready" ? ["-q"] : ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const HAS_CREATEDB = hasClientTool("createdb");
const HAS_DROPDB = hasClientTool("dropdb");

const PG_AVAILABLE = (() => {
  try {
    if (hasClientTool("pg_isready")) {
      execFileSync("pg_isready", ["-q"], { stdio: "ignore" });
      return true;
    }
  } catch {
    /* fall through to a TCP probe */
  }
  try {
    execFileSync(
      "node",
      [
        "-e",
        `const {Client}=require('pg');const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:'postgres',password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ],
      { stdio: "ignore", env: process.env, cwd: fileURLToPath(new URL("../..", import.meta.url)) },
    );
    return true;
  } catch {
    return false;
  }
})();

function adminClientConfig(database = "postgres") {
  return {
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database,
    password: process.env.PGPASSWORD,
  };
}

function assertSafeDbName(dbName: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(dbName)) {
    throw new Error(`unsafe test db name: ${dbName}`);
  }
}

async function createTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_CREATEDB) {
    execFileSync("createdb", ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, dbName], {
      env: process.env,
    });
    return;
  }
  const admin = new Client(adminClientConfig("postgres"));
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${dbName}`);
  } finally {
    await admin.end();
  }
}

async function dropTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_DROPDB) {
    execFileSync(
      "dropdb",
      ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, "--if-exists", dbName],
      { env: process.env, stdio: "ignore" },
    );
    return;
  }
  const admin = new Client(adminClientConfig("postgres"));
  await admin.connect();
  try {
    await admin.query(
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [dbName],
    );
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
  } finally {
    await admin.end();
  }
}

function pgDatabaseUrl(dbName: string): string {
  const auth = process.env.PGPASSWORD
    ? `${encodeURIComponent(PG_USER)}:${encodeURIComponent(process.env.PGPASSWORD)}`
    : encodeURIComponent(PG_USER);
  const host = PG_HOST === "/tmp" ? "localhost" : PG_HOST;
  return `postgres://${auth}@${host}:${PG_PORT}/${dbName}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitFor(
  pred: () => Promise<boolean>,
  opts: { readonly timeoutMs: number; readonly intervalMs: number; readonly label: string },
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < opts.timeoutMs) {
    if (await pred()) return;
    await sleep(opts.intervalMs);
  }
  throw new Error(`timeout waiting for ${opts.label}`);
}

// A custody-gate proof that can silently skip is no proof. This suite
// FAILS CLOSED when real PostgreSQL is unavailable — it does not skip. `TEST_DATABASE_URL`
// overrides the local probe so CI/verify can target a managed Postgres. The ceremony's
// clean-PostgreSQL restore requirement is non-negotiable evidence; a green run
// that skips it is a false pass.
describe("recovery ceremony pack (real Postgres, fail-closed)", () => {
  beforeAll(() => {
    if (!PG_AVAILABLE) {
      throw new Error(
        "real-Postgres evidence is REQUIRED but PostgreSQL is unavailable. " +
          "Set PGHOST/PGPORT/PGUSER/PGPASSWORD or TEST_DATABASE_URL so the custody-gate proof runs. " +
          "A skip would be a false pass.",
      );
    }
  });
  const dbName = `run_recovery_ceremony_${process.pid}_${Date.now()}`;
  let pool: Pool;
  let databaseUrl: string;
  let prevDatabaseUrl: string | undefined;

  beforeAll(async () => {
    await createTestDatabase(dbName);
    databaseUrl = pgDatabaseUrl(dbName);
    pool = new Pool({ connectionString: databaseUrl });
    prevDatabaseUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = databaseUrl;
    const { runMigrationsOnPool } = await import("../../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl });
    await migrateLeaseFoundation({
      query: async <R>(text: string, params?: readonly unknown[]) => {
        const result = await pool.query(text, params as never);
        return { rows: result.rows as R[], rowCount: result.rowCount };
      },
    });
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = prevDatabaseUrl;
    await pool?.end().catch(() => {});
    await dropTestDatabase(dbName).catch(() => {});
  }, PG_TEST_TIMEOUT_MS);

  it(
    "operator ceremony stamps minted pool wallets, then promoteQueuedReceives assigns",
    async () => {
      const nodeId = randomUUID();
      const implementerId = randomUUID();
      const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);

      const withTx = async <T>(
        work: (sql: {
          query<R>(text: string, params?: readonly unknown[]): Promise<{ rows: R[] }>;
        }) => Promise<T>,
      ): Promise<T> => {
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const out = await work({
            query: async <R>(text: string, params?: readonly unknown[]) => {
              const result = await client.query(text, params as never);
              return { rows: result.rows as R[] };
            },
          });
          await client.query("COMMIT");
          return out;
        } catch (err) {
          try {
            await client.query("ROLLBACK");
          } catch {
            /* surface original */
          }
          throw err;
        } finally {
          client.release();
        }
      };

      // Boot order matters: node_signing_keys.node_id has an FK to nodes, and the sealed mint
      // is what fills in the real identity public key (ensureActiveNodeSigningKey ends with
      // syncIdentityPublicKey). Production main.ts does the same two steps in this order.
      await ensureNodeRow(pool, {
        nodeId,
        displayName: "fixture-ceremony-pack",
        identityPublicKey: generateEphemeralIdentityPublicKey(),
      });
      // Sealed NODE_IDENTITY is a hard precondition of the live export: it signs the archive
      // manifest, and exportLiveBackupArchive refuses a public-only registry row
      // ("refuse backup with placeholder identity"). Same call production main.ts:667 makes.
      const identity = await withTx((sql) =>
        ensureActiveNodeSigningKey({
          sql,
          rootKey,
          nodeId,
          purpose: "NODE_IDENTITY",
          seedOverride: randomBytes(32),
        }),
      );
      await pool.query(
        `INSERT INTO implementers (id, name, created_at)
         VALUES ($1::uuid, 'fixture-impl', now())
         ON CONFLICT DO NOTHING`,
        [implementerId],
      );

      const vault = new EncryptedWalletKeyStore({
        rootKey,
        store: new VaultSqlStore(pool),
        auditLog: new InMemoryVaultAccessAuditLog(),
      });

      const logs: string[] = [];
      const handle = startMoneyWorkers({
        pool,
        vault,
        config: {
          nodeId,
          ownerInstanceId: nodeId,
          poolCapTotal: 8,
          receiveQueueCap: 20,
          receiveQueueMaxWaitSecs: 900,
          receiveTtlDefaultSecs: 300,
          receiveTtlMinSecs: 60,
          receiveTtlMaxSecs: 3600,
          tickIntervalMs: 250,
          // Offline disposable-PG fixture — no gateway; the ceremony itself is fully offline
          // (no gateway interaction, no chain read).
          allowGenesisT0Stub: true,
          // Same offline posture for EVENT_SIGNING — no events are appended.
          allowMissingEventSigner: true,
        },
        logger: {
          info: (m) => logs.push(m),
          error: (m, err) =>
            logs.push(`err:${m}${err instanceof Error ? ` ${err.message}` : ""}`),
        },
        moneyPathGates: {
          assertMoneyAdmitted: () => {},
          assertCanOperate: () => {},
          assertWalletMaySign: async () => {},
          assertHaltAdmitsKind: () => {},
        },
        nodeIdentitySigner: () => ({
          signingKeyId: identity.signingKeyId,
          sign: (preimageBytes: Uint8Array) => toBase64UrlPadded(identity.sign(preimageBytes)),
        }),
      });

      try {
        // ---- 1. born blocked: the mint loop never stamps (:17, :300) ----
        await waitFor(
          async () => {
            const r = await pool.query<{ n: string }>(
              `SELECT count(*)::text AS n FROM wallets WHERE node_id = $1::uuid`,
              [nodeId],
            );
            return Number(r.rows[0]?.n ?? "0") >= 5;
          },
          { timeoutMs: 30_000, intervalMs: 200, label: "pool mint >= POOL_FLOOR" },
        );
        const minted = await pool.query<{ total: string; verified: string }>(
          `SELECT count(*)::text AS total,
                  count(recovery_verified_at)::text AS verified
             FROM wallets WHERE node_id = $1::uuid`,
          [nodeId],
        );
        expect(Number(minted.rows[0]!.total)).toBeGreaterThanOrEqual(5);
        expect(Number(minted.rows[0]!.verified)).toBe(0);

        // ---- 2. the recovery-verified assign gate refuses while every wallet is unstamped ----
        const operationId = randomUUID();
        await pool.query(
          `INSERT INTO receive_operations (
             operation_id, implementer_id, node_id, kind, status,
             http_method, route, idempotency_key, request_sha256,
             amount_zkz, anchor, ttl_ms, after_landing_kind
           ) VALUES (
             $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'CREATED',
             'POST', '/v1/receives', $4, repeat('0', 64),
             '0.01', 'run-recovery-ceremony', 300000, 'HOLD'
           )`,
          [operationId, implementerId, nodeId, `idem-${operationId}`],
        );
        await waitFor(async () => logs.some((l) => l.includes("NO_ELIGIBLE_WALLET")), {
          timeoutMs: 15_000,
          intervalMs: 100,
          label: "NO_ELIGIBLE_WALLET before the ceremony",
        });
        const blocked = await pool.query<{ attachments: string; status: string }>(
          `SELECT (SELECT count(*)::text FROM operation_wallets
                    WHERE operation_id = $1::uuid) AS attachments,
                  (SELECT status FROM receive_operations
                    WHERE operation_id = $1::uuid) AS status`,
          [operationId],
        );
        expect(blocked.rows[0]?.attachments).toBe("0");
        expect(blocked.rows[0]?.status).toBe("CREATED");
        expect(logs.some((l) => l.includes("promoted assigns="))).toBe(false);

        // ---- 3. The operator ceremony, not SQL, produces the stamp ----
        // Exactly what `node dist/ops/run-recovery-ceremony.js` runs: live archive export →
        // throwaway restored instance → per-wallet open/census/archived-proof/fresh probe →
        // stamp on the live database. ARCHIVE_OUT deliberately unset: no secret-class
        // archive touches the filesystem in a test run.
        // enrol an active TOTP factor on the default admin operator and pass a
        // FRESH single-use code. The CLI burns it via the durable SqlTotpBurnStore.
        const userStore = new SqlAdminUserStore(
          createPoolAdminUserExecutor(pool),
          deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT),
        );
        userStore.armVaultRoot();
        await userStore.ensureSchema();
        // Seed the default admin operator (production main.ts does this on first boot).
        await bootstrapInitialAdmin(userStore, { INITIAL_ADMIN_PASSWORD: "bootstrap-pw!!!!!!!!!!" });
        const admin = await userStore.findByUsername(DEFAULT_ADMIN_USERNAME);
        expect(admin).not.toBeNull();
        const totpSecretBase32 = generateTotpSecret();
        await userStore.setPendingTotpSecret(admin!.id, totpSecretBase32);
        expect(await userStore.setActiveTotpSecret(admin!.id, totpSecretBase32)).toBe("ok");
        const totpSecretBytes = decodeBase32(totpSecretBase32);
        const nowMs = Date.now();
        const summary = await runRecoveryCeremony({
          env: {
            DATABASE_URL: databaseUrl,
            VAULT_MASTER_KEY: MASTER,
            NODE_ID: nodeId,
            ADMIN_TOTP_CODE: generateTotpCode(totpSecretBytes, nowMs),
          },
          now: () => new Date(nowMs),
        });
        expect(summary.abortReasons, JSON.stringify(summary)).toEqual([]);
        expect(summary.accepted).toBe(true);
        expect(summary.ok).toBe(true);
        expect(summary.failedClosed).toBe(0);
        expect(summary.stamped).toBeGreaterThanOrEqual(1);
        expect(summary.verifiedOnLive).toBeGreaterThanOrEqual(1);
        // Phase 3 destroys the throwaway instance as a HARD step.
        expect(summary.instanceDestroyed).toBe(true);

        const stampEvidence = await pool.query<{ wallets: string; rows: string }>(
          `SELECT (SELECT count(*)::text FROM wallets
                    WHERE node_id = $1::uuid AND recovery_verified_at IS NOT NULL) AS wallets,
                  (SELECT count(*)::text FROM wallet_recovery_verifications
                    WHERE method = 'AUDITED_EXPORT') AS rows`,
          [nodeId],
        );
        expect(Number(stampEvidence.rows[0]!.wallets)).toBeGreaterThanOrEqual(1);
        // One evidence row per stamped wallet, never a whole-vault attestation.
        expect(Number(stampEvidence.rows[0]!.rows)).toBe(summary.stamped);

        // ---- 4. AC2 — the gate opens: the same queued receive is now assigned ----
        await waitFor(async () => logs.some((l) => l.includes("money-workers: promoted assigns=")), {
          timeoutMs: 30_000,
          intervalMs: 100,
          label: "promoted assigns after the stamp",
        });
        // operation_wallets is the early receive-time attachment — not operations.receiver_wallet_id,
        // which cannot be set until T0 (pool-allocator.ts:150-154).
        const assigned = await pool.query<{ wallet_id: string; verified: string | null }>(
          `SELECT ow.wallet_id::text AS wallet_id,
                  w.recovery_verified_at::text AS verified
             FROM operation_wallets ow
             JOIN wallets w ON w.id = ow.wallet_id
            WHERE ow.operation_id = $1::uuid AND ow.operation_role = 'RECEIVER'`,
          [operationId],
        );
        expect(assigned.rows).toHaveLength(1);
        // The assigned wallet is one the ceremony stamped — the gate opening, not luck.
        expect(assigned.rows[0]?.verified).toBeTruthy();

        // AC2 wants log evidence, so emit the two lines that bracket the stamp rather than
        // making a reader take the assertions on trust.
        for (const line of logs.filter(
          (l) => l.includes("NO_ELIGIBLE_WALLET") || l.includes("promoted assigns="),
        )) {
          console.log(`recovery-ceremony gate evidence | ${line}`);
        }
      } finally {
        handle.stop();
      }
    },
    PG_TEST_TIMEOUT_MS,
  );
});
