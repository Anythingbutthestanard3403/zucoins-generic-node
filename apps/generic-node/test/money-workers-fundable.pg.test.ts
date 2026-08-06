// Offline disposable-PG proof that custody money workers mint/assign/form
// a RECEIVE to fundable READY, and that MOVE_INTERNAL + SEND_EXTERNAL admit against
// real wallet/destination inventory on the same node DB.
//
// G1 path: runPoolScaleUp mint → sealed recovery-verification stamp seam only (createSqlRecoveryLiveDatabase
//   .stampRecoveryVerification — the sealed production stamp API; this suite is NOT
//   a full operator export/restore ceremony; see residual comment at stamp site) →
//   assignReceiveWallet → T0 + formReceiveCodeAndArtifact + commitReceiveReady.
// G2: startMoneyWorkers logs "money workers started" only after the interval is armed;
//   admission closed → tick skip, then open → READY.
// G3: createDestinationService + SqlDestinationStore register/list (not fail-closed 503).
// AC4: MOVE admit against recovery-verified + BLESSED dest; SEND admit to external pubkey.
//
// Residuals (documented, not faked):
//  - transfer_code stays null until ARM; AC1 is pubkey-fundable address only
//   - production main blessingAuthorizer is still null (device-key residual);
//     this suite plants BLESSED via destination_blessing_artifacts + destinations UPDATE
//     after real register so admission predicates can run offline
// - the operator recovery ceremony (export+restore+probe) remains ops/run-recovery-ceremony;
//     workers never invent recovery_verified_at
//   - SEND live signing-key custody park is a reserved-custody item; here NODE_IDENTITY is test-local seed

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  createDestinationService,
  createExternalSend,
  createInternalMove,
  createPgImplementerEventLog,
  createSqlDestinationStore,
  createSqlRecoveryLiveDatabase,
  deriveRootKey,
  ensureActiveNodeSigningKey,
  listEvents,
  type NodeEventSigner,
  EncryptedWalletKeyStore,
  InMemoryVaultAccessAuditLog,
  migrateLeaseFoundation,
  MOVE_ADMISSION_EVENTS_DDL,
  SqlMoveCreateStore,
  SqlSendCreateStore,
  toBase64UrlPadded,
  type Uuid,
  type WalletPublicKey,
  VaultSqlStore,
} from "@zucoins/node-core";

import { ensureNodeIdentitySigningKey, ensureNodeRow } from "../src/bootstrap/genesis.js";
import { startMoneyWorkers } from "../src/money-workers/start-money-workers.js";
import { publicKeyFromSeed, signPaddedBase64Url } from "../src/ops/ed25519-ops.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const MASTER = "fundable-master-key-32b!!!!!!!!!!!!!!!!";

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
    /* TCP */
  }
  try {
    execFileSync(
      "node",
      [
        "-e",
        `const {Client}=require('pg');const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:'postgres',password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ],
      { stdio: "ignore", env: process.env, cwd: fileURLToPath(new URL("..", import.meta.url)) },
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

function pgPool(dbName: string): Pool {
  return new Pool({
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database: dbName,
    password: process.env.PGPASSWORD,
  });
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

function externalWalletPubkey(): string {
  const { publicKey: pubObj } = generateKeyPairSync("ed25519");
  const spki = pubObj.export({ format: "der", type: "spki" });
  return toBase64UrlPadded(Buffer.from(spki).subarray(-32));
}

function dummyBlessSignature(): string {
  // 64 zero bytes → padded base64url signature domain (88 chars, trailing ==).
  return toBase64UrlPadded(Buffer.alloc(64, 1));
}

describe.skipIf(!PG_AVAILABLE)("money workers fundable path (disposable PG)", () => {
  const dbName = `money_workers_fundable_${process.pid}_${Date.now()}`;
  let pool: Pool;
  let prevDatabaseUrl: string | undefined;

  beforeAll(async () => {
    await createTestDatabase(dbName);
    pool = pgPool(dbName);
    prevDatabaseUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = pgDatabaseUrl(dbName);
    const { runMigrationsOnPool } = await import("../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl: process.env.DATABASE_URL });
    const leaseSql = {
      query: async <R>(text: string, params?: readonly unknown[]) => {
        const result = await pool.query(text, params as never);
        return { rows: result.rows as R[], rowCount: result.rowCount };
      },
    };
    await migrateLeaseFoundation(leaseSql);
    // Move admit event table is slice-local (not always in money pack migrate order).
    await pool.query(MOVE_ADMISSION_EVENTS_DDL);
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = prevDatabaseUrl;
    await pool?.end().catch(() => {});
    await dropTestDatabase(dbName).catch(() => {});
  }, PG_TEST_TIMEOUT_MS);

  it(
    "admission gate + sealed recovery-verification stamp seam → RECEIVE READY; MOVE+SEND admit on real inventory",
    async () => {
      const nodeId = randomUUID();
      const implementerId = randomUUID();
      const identitySeed = randomBytes(32);
      const identityPublicKey = publicKeyFromSeed(identitySeed);
      const signingKeyId = randomUUID();

      await ensureNodeRow(pool, {
        nodeId,
        displayName: "fixture-fundable",
        identityPublicKey,
      });
      await pool.query(
        `INSERT INTO implementers (id, name, created_at)
         VALUES ($1::uuid, 'fixture-impl', now())
         ON CONFLICT DO NOTHING`,
        [implementerId],
      );
      await ensureNodeIdentitySigningKey(pool, {
        keyId: signingKeyId,
        nodeId,
        publicKey: identityPublicKey,
      });
      const durableKey = await pool.query<{ id: string }>(
        `SELECT id::text AS id FROM node_signing_keys
          WHERE node_id = $1::uuid AND purpose = 'NODE_IDENTITY' AND public_key = $2
          LIMIT 1`,
        [nodeId, identityPublicKey],
      );
      const liveSigningKeyId = durableKey.rows[0]?.id ?? signingKeyId;

      const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
      const vault = new EncryptedWalletKeyStore({
        rootKey,
        store: new VaultSqlStore(pool),
        auditLog: new InMemoryVaultAccessAuditLog(),
      });

      // The same sealed EVENT_SIGNING ensure production boot runs, so the money
      // path can append the durable receive.ready event on both continuity chains.
      const eventKeyClient = await pool.connect();
      let eventSigner: NodeEventSigner;
      let eventPublicKey: string;
      try {
        await eventKeyClient.query("BEGIN");
        const eventKey = await ensureActiveNodeSigningKey({
          sql: {
            query: async <R>(text: string, params?: readonly unknown[]) => {
              const result = await eventKeyClient.query(text, params as never);
              return { rows: result.rows as R[] };
            },
          },
          rootKey,
          nodeId,
          purpose: "EVENT_SIGNING",
        });
        await eventKeyClient.query("COMMIT");
        eventPublicKey = eventKey.publicKey;
        eventSigner = {
          signingKeyId: eventKey.signingKeyId,
          sign: (bytes) => toBase64UrlPadded(Buffer.from(eventKey.sign(bytes))),
        };
      } finally {
        eventKeyClient.release();
      }

      // D4 — non-no-op gates: closed until opened; proves tick skip then READY.
      let moneyAdmitted = false;
      const moneyPathGates = {
        assertMoneyAdmitted: () => {
          if (!moneyAdmitted) throw new Error("money admission closed (test)");
        },
        assertCanOperate: () => {},
        assertWalletMaySign: async () => {},
        assertHaltAdmitsKind: () => {},
      };

      const logs: string[] = [];
      const handle = startMoneyWorkers({
        pool,
        vault,
        config: {
          nodeId,
          ownerInstanceId: nodeId,
          poolCapTotal: 10,
          receiveQueueCap: 20,
          receiveQueueMaxWaitSecs: 600,
          receiveTtlDefaultSecs: 300,
          receiveTtlMinSecs: 60,
          receiveTtlMaxSecs: 3600,
          tickIntervalMs: 250,
          // Offline disposable-PG fixture — no SPLITCHAIN_GATEWAY_URLS; D2 fail-closed.
          allowGenesisT0Stub: true,
        },
        logger: {
          info: (m) => logs.push(m),
          error: (m, err) =>
            logs.push(`err:${m}${err instanceof Error ? ` ${err.message}` : ""}`),
        },
        moneyPathGates,
        nodeIdentitySigner: () => ({
          signingKeyId: liveSigningKeyId,
          sign(preimageBytes: Uint8Array): string {
            return signPaddedBase64Url(identitySeed, preimageBytes);
          },
        }),
        // Sealed EVENT_SIGNING signer so RECEIVE READY appends the durable event.
        eventSigner: () => eventSigner,
      });

      try {
        expect(logs.some((l) => l.includes("money workers started"))).toBe(true);

        await waitFor(
          async () => logs.some((l) => l.includes("tick skipped — money not admitted")),
          { timeoutMs: 5_000, intervalMs: 50, label: "closed-admission tick skip" },
        );

        const preOpen = await pool.query<{ n: string }>(
          `SELECT count(*)::text AS n FROM wallets WHERE node_id = $1::uuid`,
          [nodeId],
        );
        expect(Number(preOpen.rows[0]?.n ?? "0")).toBe(0);

        moneyAdmitted = true;

        await waitFor(
          async () => {
            const r = await pool.query<{ n: string }>(
              `SELECT count(*)::text AS n FROM wallets WHERE node_id = $1::uuid`,
              [nodeId],
            );
            return Number(r.rows[0]?.n ?? "0") >= 5;
          },
          { timeoutMs: 20_000, intervalMs: 200, label: "pool mint >= POOL_FLOOR" },
        );

        const unverified = await pool.query<{ n: string }>(
          `SELECT count(*)::text AS n FROM wallets
            WHERE node_id = $1::uuid AND recovery_verified_at IS NULL`,
          [nodeId],
        );
        expect(Number(unverified.rows[0]?.n ?? "0")).toBeGreaterThan(0);

        // production recovery-verification stamp seam only — createSqlRecoveryLiveDatabase.stampRecoveryVerification.
        // Does NOT invent recovery_verified_at via raw SQL UPDATE. This is the sealed API the
        // operator ceremony (ops/run-recovery-ceremony → runRestoreRecoveryCeremony) calls after
        // export/restore/probe proofs; the offline suite supplies eligibility flags that those
        // proofs would have established. Workers still never stamp.
        const liveDb = createSqlRecoveryLiveDatabase({
          sql: {
            query: async <R>(text: string, params: readonly unknown[]) => {
              const result = await pool.query(text, params as never);
              return { rows: result.rows as R[] };
            },
          },
          nodeId,
          // Possession proof is consumed by the operator ceremony path, not by stamp SQL
          // itself (stamp verifies caller-supplied census/probe booleans). Ceremony E2E
          // is ops residual — see tasks note.
          proveCurrentKeyPossession: async () => {
            throw new Error(
              "fixture fundable suite: proveCurrentKeyPossession not used on stamp path; use runRestoreRecoveryCeremony for operator possession E2E",
            );
          },
        });

        const wallets = await liveDb.readWallets();
        let stamped = 0;
        for (const [walletId, row] of wallets) {
          if (row.recoveryVerifiedAt !== null) continue;
          const exportSha = createHash("sha256")
            .update(`fixture-export|${walletId}`, "utf8")
            .digest("hex");
          await liveDb.stampRecoveryVerification({
            ceremonyId: randomUUID(),
            walletId,
            method: "AUDITED_EXPORT",
            publicKey: row.publicKey,
            keyVersion: 1,
            exportId: randomUUID(),
            exportSha256: exportSha,
            censusMatchedRestored: true,
            censusMatchedLive: true,
            archivedProofVerified: true,
            probePreimageSha256: createHash("sha256").update("probe", "utf8").digest("hex"),
            probeSignature: signPaddedBase64Url(identitySeed, Buffer.from("probe")),
            probeVerified: true,
            verifierIdentity: "fixture-offline-stamp-seam",
          });
          stamped += 1;
        }
        expect(stamped).toBeGreaterThan(0);

        const operationId = randomUUID();
        const reqSha = createHash("sha256").update(`recv|${operationId}`, "utf8").digest("hex");
        await pool.query(
          `INSERT INTO receive_operations (
             operation_id, implementer_id, node_id, kind, status,
             http_method, route, idempotency_key, request_sha256,
             amount_zkz, anchor, ttl_ms, after_landing_kind
           ) VALUES (
             $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'CREATED',
             'POST', '/v1/receives', $4, $5,
             '0.01', 'money-workers-fundable', 300000, 'HOLD'
           )`,
          [operationId, implementerId, nodeId, `idem-${operationId}`, reqSha],
        );

        await waitFor(
          async () => {
            const r = await pool.query<{ status: string; body: string | null }>(
              `SELECT status, response_body AS body FROM receive_operations
                WHERE operation_id = $1::uuid`,
              [operationId],
            );
            const row = r.rows[0];
            return row?.status === "READY" && row.body !== null && row.body.length > 0;
          },
          { timeoutMs: 30_000, intervalMs: 250, label: "RECEIVE READY + response_body" },
        );

        const ready = await pool.query<{ status: string; body: string; wallet_id: string }>(
          `SELECT status, response_body AS body, wallet_id::text AS wallet_id
             FROM receive_operations WHERE operation_id = $1::uuid`,
          [operationId],
        );
        const body = JSON.parse(ready.rows[0]!.body) as {
          operation: { state: string };
          receiver_pubkey: string | null;
          code_status: string;
          transfer_code: string | null;
        };
        expect(ready.rows[0]!.status).toBe("READY");
        expect(body.operation.state).toBe("READY");
        expect(typeof body.receiver_pubkey).toBe("string");
        expect(body.receiver_pubkey?.length).toBeGreaterThan(20);
        // AC1 honest: wire transfer_code withheld until ARM. Fundable = pubkey.
        expect(body.code_status).toBe("AWAITING_ARM");
        expect(body.transfer_code).toBeNull();

        const code = await pool.query<{ code_status: string; has_text: boolean }>(
          `SELECT code_status, (transfer_code_text IS NOT NULL AND length(transfer_code_text) > 0) AS has_text
             FROM receive_codes WHERE operation_id = $1::uuid`,
          [operationId],
        );
        expect(code.rows[0]?.code_status).toBe("AWAITING_ARM");
        expect(code.rows[0]?.has_text).toBe(true);

        // RECEIVE READY appended the durable event on BOTH continuity chains and
        // GET /v1/events serves the signed zp-implementer-event-v1 proof.
        const nodeEvent = await pool.query<{
          event_type: string;
          preimage_text: string;
          signature: string;
          event_hash: string;
          data_text: string;
        }>(
          `SELECT event_type, preimage_text, signature, event_hash, data_text
             FROM node_events WHERE node_id = $1::uuid AND operation_id = $2::uuid`,
          [nodeId, operationId],
        );
        expect(nodeEvent.rows).toHaveLength(1);
        expect(nodeEvent.rows[0]!.event_type).toBe("receive.ready");
        // transfer_code secrecy survives into the event data.
        expect(nodeEvent.rows[0]!.data_text).not.toContain("transfer_code_text");

        const served = await listEvents(
          createPgImplementerEventLog({
            nodeId,
            query: async (text, values) => (await pool.query(text, values as unknown[])).rows,
            withTransaction: async (fn) =>
              fn(async (text, values) => (await pool.query(text, values as unknown[])).rows),
          }),
          { implementerId, afterImplementerSeq: null, limit: 10 },
        );
        expect(served.events.map((e) => e.eventType)).toContain("receive.ready");
        const proof = JSON.parse(
          served.events.find((e) => e.eventType === "receive.ready")!.proofRepresentation,
        ) as { preimage_text: string; signature: string };
        const proofPayload = JSON.parse(
          proof.preimage_text.slice(proof.preimage_text.indexOf("\n") + 1),
        ) as Record<string, unknown>;
        expect(proofPayload.purpose).toBe("zp-implementer-event-v1");
        expect(proofPayload.event_type).toBe("receive.ready");
        expect(proofPayload.operation_id).toBe(operationId);
        // Binds to its node-global row without disclosing the global seq (NC2).
        expect(proofPayload.node_event_hash).toBe(nodeEvent.rows[0]!.event_hash);
        expect(proofPayload.seq).toBeUndefined();
        const eventPubSpki = Buffer.concat([
          Buffer.from("302a300506032b6570032100", "hex"),
          Buffer.from(eventPublicKey, "base64url"),
        ]);
        expect(
          edVerify(
            null,
            Buffer.from(proof.preimage_text, "utf8"),
            createPublicKey({ key: eventPubSpki, format: "der", type: "spki" }),
            Buffer.from(proof.signature, "base64url"),
          ),
        ).toBe(true);

        // G3 — real DestinationService (not createFailClosedDestinationService)
        const destService = createDestinationService({
          store: createSqlDestinationStore(pool),
          keyGenerator: {
            async generate(nId) {
              const { privateKey, publicKey: pubObj } = generateKeyPairSync("ed25519");
              const spki = pubObj.export({ format: "der", type: "spki" });
              const publicKey = toBase64UrlPadded(
                Buffer.from(spki).subarray(-32),
              ) as WalletPublicKey;
              const jwk = privateKey.export({ format: "jwk" });
              const d = typeof jwk.d === "string" ? jwk.d : "";
              const seed = Buffer.from(d, "base64url");
              const secret64 = Buffer.concat([seed, Buffer.from(spki).subarray(-32)]);
              const walletId = randomUUID() as Uuid;
              try {
                await pool.query(
                  `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
                   VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
                  [walletId, nId, publicKey],
                );
                await vault.seal(
                  {
                    nodeId: nId,
                    walletId,
                    keyVersion: 1,
                    publicKey,
                    keyOrigin: "node_generated",
                  },
                  secret64,
                );
                return { walletId, publicKey };
              } finally {
                secret64.fill(0);
              }
            },
          },
          blessingAuthorizer: {
            async authorize() {
              // Mirrors production main.ts residual (device-key authorizer still null).
              return null;
            },
          },
          clock: { now: () => new Date().toISOString() },
          ids: { destinationId: () => randomUUID() as Uuid },
        });

        const registered = await destService.register({
          nodeId: nodeId as Uuid,
          label: "fixture-dest",
          idempotencyKey: `dest-${randomUUID()}`,
        });
        expect(registered.status).toBe("created");
        expect(registered.destination.state).toBe("PENDING");

        const page = await destService.list(nodeId as Uuid, { limit: 10 });
        expect(page.items.some((d) => d.destinationId === registered.destination.destinationId)).toBe(
          true,
        );

        // Production blessingAuthorizer residual — fail-closed, not silent 503.
        const bless = await destService.bless({
          nodeId: nodeId as Uuid,
          destinationId: registered.destination.destinationId,
          deviceSignature: "not-empty",
          nonce: randomUUID() as Uuid,
          issuedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        });
        expect(bless.status).toBe("authorization_rejected");

        // ---- AC4: MOVE admit against recovery-verified + BLESSED dest ----
        // Stamp dest wallet via the same sealed recovery-verification stamp seam (not raw recovery_verified UPDATE).
        const destWalletId = registered.destination.walletId;
        const destWallet = await pool.query<{ public_key: string }>(
          `SELECT public_key FROM wallets WHERE id = $1::uuid`,
          [destWalletId],
        );
        const destPub = destWallet.rows[0]!.public_key;
        await liveDb.stampRecoveryVerification({
          ceremonyId: randomUUID(),
          walletId: destWalletId,
          method: "AUDITED_EXPORT",
          publicKey: destPub,
          keyVersion: 1,
          exportId: randomUUID(),
          exportSha256: createHash("sha256").update(`export|${destWalletId}`, "utf8").digest("hex"),
          censusMatchedRestored: true,
          censusMatchedLive: true,
          archivedProofVerified: true,
          probePreimageSha256: createHash("sha256").update("probe-dest", "utf8").digest("hex"),
          probeSignature: signPaddedBase64Url(identitySeed, Buffer.from("probe-dest")),
          probeVerified: true,
          verifierIdentity: "fixture-offline-stamp-seam",
        });

        // Offline BLESSED plant on the registered destination (device-key ceremony residual in main).
        // Satisfies destinations_blessed_iff + FK to destination_blessing_artifacts.
        const blessingArtifactId = randomUUID();
        const deviceKeyId = randomUUID();
        const issuedAt = new Date();
        const expiresAt = new Date(issuedAt.getTime() + 60_000);
        await pool.query(
          `INSERT INTO destination_blessing_artifacts (
             id, purpose, canonical_version, node_id, destination_id, wallet_id,
             wallet_pubkey, nonce, issued_at, expires_at, device_signature,
             preimage_text, preimage_sha256, created_at
           ) VALUES (
             $1::uuid, 'zp-destination-bless-v1', 1, $2::uuid, $3::uuid, $4::uuid,
             $5, $6::uuid, $7::timestamptz, $8::timestamptz, $9,
             $10, $11, now()
           )`,
          [
            blessingArtifactId,
            nodeId,
            registered.destination.destinationId,
            destWalletId,
            destPub,
            randomUUID(),
            issuedAt.toISOString(),
            expiresAt.toISOString(),
            dummyBlessSignature(),
            `fixture-offline-bless|${registered.destination.destinationId}`,
            createHash("sha256")
              .update(`fixture-offline-bless|${registered.destination.destinationId}`, "utf8")
              .digest("hex"),
          ],
        );
        await pool.query(
          `UPDATE destinations
              SET state = 'BLESSED',
                  blessed_at = now(),
                  blessed_by_device_key_id = $2::uuid,
                  blessing_artifact_id = $3::uuid
            WHERE id = $1::uuid AND state = 'PENDING'`,
          [registered.destination.destinationId, deviceKeyId, blessingArtifactId],
        );

        const moveSource = await pool.query<{ id: string }>(
          `SELECT id::text AS id FROM wallets
            WHERE node_id = $1::uuid
              AND state = 'AVAILABLE'
              AND recovery_verified_at IS NOT NULL
              AND id <> $2::uuid
            LIMIT 1`,
          [nodeId, destWalletId],
        );
        expect(moveSource.rows[0]?.id).toBeTruthy();
        const moveSourceId = moveSource.rows[0]!.id;

        const sqlExec = {
          query: async <R>(text: string, params?: readonly unknown[]) => {
            const result = await pool.query(text, params as never);
            return { rows: result.rows as R[], rowCount: result.rowCount ?? 0 };
          },
        };
        const moveStore = new SqlMoveCreateStore({
          sql: sqlExec,
          withTransaction: async (body) => {
            const client = await pool.connect();
            try {
              await client.query("BEGIN");
              const tx = {
                query: async <R>(text: string, params?: readonly unknown[]) => {
                  const result = await client.query(text, params as never);
                  return { rows: result.rows as R[], rowCount: result.rowCount ?? 0 };
                },
              };
              const out = await body(tx);
              await client.query("COMMIT");
              return out;
            } catch (err) {
              try {
                await client.query("ROLLBACK");
              } catch {
                /* original */
              }
              throw err;
            } finally {
              client.release();
            }
          },
        });

        const moveOutcome = await createInternalMove(
          moveStore,
          {
            implementerId,
            nodeId,
            sourceWalletId: moveSourceId,
            destinationId: registered.destination.destinationId,
            amountZkz: "0.01",
            idempotencyKey: `move-admit-${randomUUID()}`,
          },
          { generateId: () => randomUUID(), now: () => Date.now() },
        );
        expect(moveOutcome.outcome, JSON.stringify(moveOutcome)).toBe("CREATED");
        if (moveOutcome.outcome === "CREATED") {
          expect(moveOutcome.operation.kind).toBe("MOVE_INTERNAL");
          expect(moveOutcome.operation.status).toBe("CREATED");
          expect(moveOutcome.operation.sourceWalletId).toBe(moveSourceId);
          expect(moveOutcome.operation.destinationId).toBe(
            registered.destination.destinationId,
          );
        }

        // ---- AC4: SEND admit against real AVAILABLE source + external destination ----
        const sendSource = await pool.query<{ id: string }>(
          `SELECT id::text AS id FROM wallets
            WHERE node_id = $1::uuid
              AND state = 'AVAILABLE'
              AND id <> $2::uuid
              AND id <> $3::uuid
            LIMIT 1`,
          [nodeId, destWalletId, moveSourceId],
        );
        // MOVE did not pin source (admit-only); reuse move source if pool tight.
        const sendSourceId = sendSource.rows[0]?.id ?? moveSourceId;
        const externalDest = externalWalletPubkey();
        const sendStore = new SqlSendCreateStore(sqlExec);
        const sendSigner = {
          signingKeyId: liveSigningKeyId,
          sign(preimageBytes: Uint8Array): Uint8Array {
            // Raw 64-byte Ed25519 sig (createExternalSend pads to wire form).
            const pkcs8 = Buffer.concat([
              Buffer.from("302e020100300506032b657004220420", "hex"),
              identitySeed,
            ]);
            const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
            return edSign(null, Buffer.from(preimageBytes), key);
          },
        };

        const sendOutcome = await createExternalSend(
          sendStore,
          sendSigner,
          {
            implementerId,
            nodeId,
            sourceWalletId: sendSourceId,
            destinationAddress: externalDest,
            amountZkz: "0.01",
            referencesOperationId: null,
            clientReference: "fixture-send-admit",
            description: null,
            idempotencyKey: `send-admit-${randomUUID()}`,
          },
          { generateId: () => randomUUID(), now: () => Date.now() },
        );
        expect(sendOutcome.outcome, JSON.stringify(sendOutcome)).toBe("CREATED");
        if (sendOutcome.outcome === "CREATED") {
          expect(sendOutcome.operation.kind).toBe("SEND_EXTERNAL");
          expect(sendOutcome.operation.status).toBe("CREATED");
          expect(sendOutcome.operation.sourceWalletId).toBe(sendSourceId);
          expect(sendOutcome.artifact.signature.length).toBe(88);
        }

        handle.stop();
        expect(logs.some((l) => l.includes("ENGINE_QUIESCE"))).toBe(true);
      } finally {
        handle.stop();
      }
    },
    PG_TEST_TIMEOUT_MS,
  );
});
