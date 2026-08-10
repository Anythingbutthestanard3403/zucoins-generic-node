// Operator CLI — full restore / recovery-verification ceremony composition.
//
// end-to-end:
//   1. Export live backup archive (vault-open + wallet export proofs) OR load ARCHIVE_PATH
//   2. Throwaway RestoredInstance + RestoredVaultAccess (master key open of restored envelopes)
//   3. createSqlRecoveryLiveDatabase on the LIVE pool (only stamp seam)
//   4. runRestoreRecoveryCeremony — stamps eligible wallets honestly on LIVE
//   5. Destroy throwaway instance; never print private keys
//
// Env (required): DATABASE_URL, VAULT_MASTER_KEY (≥32 chars), NODE_ID, ADMIN_TOTP_CODE
// Env (optional): NODE_IDENTITY_SEED (verify sealed public key on live export),
//                 ARCHIVE_PATH (skip live export; load file), ARCHIVE_OUT,
//                 ARCHIVE_EPOCH_MASTER_KEY (prior-epoch archive key)
//
//   node dist/ops/run-recovery-ceremony.js

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import { Pool } from "pg";

import {
  createSqlRecoveryLiveDatabase,
  deriveEd25519PublicKeyBase64Url,
  deriveRootKey,
  openWalletSecret,
  runRestoreRecoveryCeremony,
  verifyBackupArchive,
  type RestoreCeremonyResult,
  type SealedEnvelope,
  type WalletIdentity,
} from "@zucoins/node-core";

import {
  createSqlRestoredInstance,
} from "./sql-restored-instance.js";

// The ceremony start is a guarded mutation — fresh single-use TOTP
// against the enrolled admin operator's active secret, burned via the durable store. The
// verifier identity is derived from the authenticated operator, never caller-forged.
import {
  DEFAULT_ADMIN_USERNAME,
  SqlAdminUserStore,
  SqlTotpBurnStore,
  createPoolAdminUserExecutor,
  createPoolTotpBurnExecutor,
  verifyTotp,
  totpSecretBytes,
  type TotpConfig,
} from "@zucoins/node-core";

import { normalizeDatabaseUrl } from "../db/session-endpoint.js";
import {
  exportLiveBackupArchive,
  resolveIdentitySeedFromEnv,
} from "./export-live-backup-archive.js";
import {
  createRestoredVaultAccess,
  createThrowawayRestoredInstance,
} from "./restored-instance.js";
import {
  assertRootKeyOpensSealedEnvelope,
  resolveCeremonyRootKdfSalt,
} from "../vault/root-kdf-salt.js";

const MIN_MASTER_KEY_CHARS = 32;

export interface RunRecoveryCeremonyEnv {
  readonly DATABASE_URL?: string;
  readonly VAULT_MASTER_KEY?: string;
  readonly NODE_ID?: string;
  readonly NODE_IDENTITY_SEED?: string;
  readonly ARCHIVE_PATH?: string;
  readonly ARCHIVE_OUT?: string;
  readonly ARCHIVE_EPOCH_MASTER_KEY?: string;
  /**
   * A FRESH single-use TOTP code from the operator's authenticator. The
   * ceremony start is a guarded mutation: the code is verified against the enrolled admin
   * operator's active secret and atomically burned via the durable `SqlTotpBurnStore` (burned
   * on any downstream failure). The verifier identity is derived from the authenticated
   * operator, never caller-forged.
   */
  readonly ADMIN_TOTP_CODE?: string;
  /**
   * Base64 (standard or URL-safe) vault root-KDF salt. Read only as a cross-check: the
   * authoritative value is the one persisted beside the envelopes, and a disagreement refuses
   * the ceremony rather than deriving a key that opens nothing (ZTR-1159).
   */
  readonly VAULT_ROOT_SALT_B64?: string;
}

export interface RunRecoveryCeremonySummary {
  readonly ok: boolean;
  readonly ceremonyId: string;
  readonly accepted: boolean;
  readonly stamped: number;
  readonly failedClosed: number;
  readonly skipped: number;
  readonly bornBlocked: number;
  readonly abortReasons: readonly string[];
  readonly instanceDestroyed: boolean;
  readonly verifiedOnLive: number;
  readonly exportId: string | null;
}

function fail(message: string): never {
  console.error(`run-recovery-ceremony: ${message}`);
  process.exit(1);
}

// AggregateError (thrown by pg on a multi-address connect failure) carries its detail in
// `.errors`/`.code`, not `.message` — `.message` is the empty string, so printing it alone
// gives an operator a blank diagnostic line. Walk stack/cause/errors instead.
function describeError(err: unknown): string {
  if (!(err instanceof Error)) return String(err);
  const lines = [err.stack ?? err.message];
  const cause = (err as { cause?: unknown }).cause;
  if (cause !== undefined) lines.push(`cause: ${describeError(cause)}`);
  const errors = (err as { errors?: unknown[] }).errors;
  if (Array.isArray(errors)) {
    errors.forEach((sub, i) => lines.push(`errors[${i}]: ${describeError(sub)}`));
  }
  return lines.join("\n");
}

function requireEnv(env: RunRecoveryCeremonyEnv, name: keyof RunRecoveryCeremonyEnv): string {
  const value = env[name]?.trim();
  if (value === undefined || value === "") fail(`${name} is required`);
  return value;
}

function b64urlNonce(): string {
  const raw = randomBytes(16);
  const unpadded = raw.toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
}

function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function outcomeCounts(result: RestoreCeremonyResult): {
  stamped: number;
  failedClosed: number;
  skipped: number;
} {
  let stamped = 0;
  let failedClosed = 0;
  let skipped = 0;
  for (const outcome of result.outcomes.values()) {
    if (outcome === "stamped") stamped += 1;
    else if (outcome === "failed_closed") failedClosed += 1;
    else skipped += 1;
  }
  return { stamped, failedClosed, skipped };
}

async function proveCurrentKeyPossession(deps: {
  readonly sql: Pool;
  readonly rootKey: Uint8Array;
  readonly nodeId: string;
}): Promise<boolean> {
  const { rows } = await deps.sql.query<{
    id: string;
    node_id: string;
    public_key: string;
    key_origin: string;
    key_version: number | string;
    ciphertext: Buffer;
    nonce: Buffer;
    auth_tag: Buffer;
    ciphertext_sha256: string;
  }>(
    `SELECT w.id, w.node_id, w.public_key, w.key_origin,
            v.key_version, v.ciphertext, v.nonce, v.auth_tag, v.ciphertext_sha256
       FROM wallets w
       INNER JOIN vault v ON v.wallet_id = w.id
      WHERE w.node_id = $1::uuid
      LIMIT 1`,
    [deps.nodeId],
  );
  const row = rows[0];
  if (row === undefined) return false;

  const identity: WalletIdentity = {
    nodeId: row.node_id,
    walletId: row.id,
    keyVersion: Number(row.key_version),
    publicKey: row.public_key,
    keyOrigin: row.key_origin,
  };
  const envelope: SealedEnvelope = {
    walletId: row.id,
    keyVersion: Number(row.key_version),
    ciphertext: new Uint8Array(row.ciphertext),
    nonce: new Uint8Array(row.nonce),
    authTag: new Uint8Array(row.auth_tag),
    ciphertextSha256: row.ciphertext_sha256,
  };
  try {
    const secret = openWalletSecret(deps.rootKey, envelope, identity);
    try {
      return deriveEd25519PublicKeyBase64Url(secret.bytes) === row.public_key;
    } finally {
      secret.wipe();
    }
  } catch {
    return false;
  }
}

export async function composeRestoreRecoveryCeremony(deps: {
  readonly archiveText: string;
  readonly rootKey: Uint8Array;
  readonly nodeId: string;
  readonly liveSql: {
    query<R>(text: string, params?: readonly unknown[]): Promise<{ rows: R[] }>;
  };
  readonly verifierIdentity: string;
  readonly ceremonyId: string;
  readonly ceremonyNonce: string;
  readonly issuedAt: string;
  readonly now?: () => Date;
  readonly newId?: () => string;
  readonly proveCurrentKeyPossession?: () => Promise<boolean>;
  /**
   * the root key for the ARCHIVE's key epoch. When set, the
   * restored vault access opens the archive's envelopes with THIS key, while `rootKey` (the
   * current key) drives the current-key possession proof. When omitted, `rootKey` is used for
   * both (the single-epoch / live-export case).
   */
  readonly archiveRootKey?: Uint8Array;
  /**
   * the restored instance provider. When omitted, the Map-backed throwaway is used
   * (unit-test-only; never the production proof). Production and the
   * real-PG acceptance test pass `createSqlRestoredInstance` so the clean-PostgreSQL
   * restore requirement is met.
   */
  readonly restoredInstanceProvider?: () => Promise<{
    readonly instance: import("@zucoins/node-core").RestoredInstance;
    readonly restoredVault: import("@zucoins/node-core").RestoredVaultAccess;
    readonly destroy: () => Promise<void>;
  }>;
}): Promise<{
  result: RestoreCeremonyResult;
  destroyCalls: number;
}> {
  // production routes through a real PostgreSQL restored instance; the unit test
  // keeps the Map-backed throwaway (its header says it is NOT a full restore ceremony).
  const memoryBundle = deps.restoredInstanceProvider === undefined ? createThrowawayRestoredInstance() : null;
  let realDestroyed = false;
  const provided = deps.restoredInstanceProvider !== undefined ? await deps.restoredInstanceProvider() : null;
  // the restored vault opens the archive's envelopes under the ARCHIVE-epoch key
  // when supplied; the current rootKey drives the possession proof separately.
  const vaultOpenRootKey = deps.archiveRootKey ?? deps.rootKey;
  const restored =
    provided !== null
      ? (() => {
          // Wrap destroy so the real-PG path's destroy is observable for the summary.
          const origDestroy = provided.instance.destroy.bind(provided.instance);
          const wrappedInstance: import("@zucoins/node-core").RestoredInstance = {
            restore: provided.instance.restore.bind(provided.instance),
            readRestoredRowCounts: provided.instance.readRestoredRowCounts.bind(provided.instance),
            countActiveLeases: provided.instance.countActiveLeases.bind(provided.instance),
            readWallet: provided.instance.readWallet.bind(provided.instance),
            acquireReconciliationLease: provided.instance.acquireReconciliationLease.bind(provided.instance),
            releaseReconciliationLease: provided.instance.releaseReconciliationLease.bind(provided.instance),
            readActiveLease: provided.instance.readActiveLease.bind(provided.instance),
            async destroy() {
              await origDestroy();
              realDestroyed = true;
            },
          };
          return { instance: wrappedInstance, restoredVault: provided.restoredVault, destroy: wrappedInstance.destroy };
        })()
      : (() => {
          const restoredVault = createRestoredVaultAccess({
            rootKey: vaultOpenRootKey,
            nodeId: deps.nodeId,
            bundle: memoryBundle!,
          });
          return { instance: memoryBundle!.instance, restoredVault, destroy: () => memoryBundle!.instance.destroy() };
        })();

  const liveDatabase = createSqlRecoveryLiveDatabase({
    sql: deps.liveSql,
    nodeId: deps.nodeId,
    proveCurrentKeyPossession:
      deps.proveCurrentKeyPossession ??
      (async () =>
        proveCurrentKeyPossession({
          sql: deps.liveSql as Pool,
          rootKey: deps.rootKey,
          nodeId: deps.nodeId,
        })),
    now: deps.now,
    newId: deps.newId,
  });

  const result = await runRestoreRecoveryCeremony({
    ceremonyId: deps.ceremonyId,
    ceremonyNonce: deps.ceremonyNonce,
    issuedAt: deps.issuedAt,
    verifierIdentity: deps.verifierIdentity,
    liveNodeId: deps.nodeId,
    archiveText: deps.archiveText,
    restoredInstance: restored.instance,
    restoredVault: restored.restoredVault,
    liveDatabase,
  });

  const destroyCalls = memoryBundle !== null ? memoryBundle.destroyCalls() : (realDestroyed ? 1 : 0);
  return { result, destroyCalls };
}

/**
 * build a REAL PostgreSQL restored instance against a throwaway database on the
 * same server as the live pool (clean, freshly-initialized, frozen-schema, empty
 * of wallet/vault rows). Creates + migrates a fresh DB, returns the restored instance + a drop
 * closure. The instance never joins the network or runs money workers.
 */
// pg's Pool.options only reflects what was literally passed to its constructor. The live
// pool is built as `new Pool({ connectionString: databaseUrl })`, so pool.options.host/port/
// user/password are always undefined — reading them (as this function used to) silently
// falls back to pg's localhost:5432 defaults instead of the real DATABASE_URL target.
//
// This decomposed the URL into discrete host/port/user/password fields by hand, which
// silently dropped `sslmode`/query params (no ssl option ever reached the admin Client or
// throwaway Pool) and mishandled unix-socket DSNs (`?host=/var/run/postgresql` → host: "").
// Both are the same failure class this function exists to eliminate. Instead, reuse
// session-endpoint.ts's `normalizeDatabaseUrl` (already handles the WhatWG unix-socket edge
// case) to swap only the database segment, and hand pg the resulting connection string
// unchanged — pg's own bundled connection-string parser (already trusted for the live pool's
// `connectionString`) then applies ssl/sslmode and the `host=` socket form identically to how
// the real DATABASE_URL would connect.
export function deriveLiveConnectionParams(databaseUrl: string, targetDatabase: string): string {
  const { parsed } = normalizeDatabaseUrl(databaseUrl);
  const target = new URL(parsed.toString());
  target.pathname = `/${encodeURIComponent(targetDatabase)}`;
  return target.toString();
}

async function createThrowawayRestoredInstanceProvider(input: {
  readonly databaseUrl: string;
  readonly rootKey: Uint8Array;
  readonly archiveRootKey?: Uint8Array;
  readonly nodeId: string;
}): Promise<() => Promise<{
  readonly instance: import("@zucoins/node-core").RestoredInstance;
  readonly restoredVault: import("@zucoins/node-core").RestoredVaultAccess;
  readonly destroy: () => Promise<void>;
}>> {
  const adminConnectionString = deriveLiveConnectionParams(input.databaseUrl, "postgres");
  const adminClient = await import("pg").then(
    ({ Client }) => new Client({ connectionString: adminConnectionString }),
  );
  await adminClient.connect();
  const throwawayName = `run_recovery_ceremony_restore_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
  await adminClient.query(`CREATE DATABASE ${throwawayName}`);
  const throwawayPool = new Pool({
    connectionString: deriveLiveConnectionParams(input.databaseUrl, throwawayName),
  });
  const { runMigrationsOnPool } = await import("../db/migrate.js");
  await runMigrationsOnPool(throwawayPool);
  const { migrateLeaseFoundation } = await import("@zucoins/node-core");
  await migrateLeaseFoundation({
    query: async <R>(text: string, params?: readonly unknown[]) => {
      const r = await throwawayPool.query(text, params as never);
      return { rows: r.rows as R[], rowCount: r.rowCount };
    },
  });
  const drop = async () => {
    await throwawayPool.end().catch(() => {});
    await adminClient.query(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, [throwawayName]).catch(() => {});
    await adminClient.query(`DROP DATABASE IF EXISTS ${throwawayName}`).catch(() => {});
    await adminClient.end().catch(() => {});
  };
  return async () => {
    const r = await createSqlRestoredInstance({
      createThrowawayDatabase: async () => ({ pool: throwawayPool, databaseName: throwawayName, drop }),
      rootKey: input.rootKey,
      archiveRootKey: input.archiveRootKey,
      nodeId: input.nodeId,
    });
    return { instance: r.instance, restoredVault: r.vaultAccess, destroy: r.destroy };
  };
}

export async function runRecoveryCeremony(deps: {
  readonly env?: RunRecoveryCeremonyEnv;
  readonly now?: () => Date;
  readonly newId?: () => string;
  /**
   * provider for the real PostgreSQL restored instance. When
   * omitted, the CLI builds one against a throwaway database derived from DATABASE_URL's host.
   * The PG acceptance test injects its own to share the test's Postgres instance.
   */
  readonly restoredInstanceProvider?: () => Promise<{
    readonly instance: import("@zucoins/node-core").RestoredInstance;
    readonly restoredVault: import("@zucoins/node-core").RestoredVaultAccess;
    readonly destroy: () => Promise<void>;
  }>;
}): Promise<RunRecoveryCeremonySummary> {
  const env = deps.env ?? process.env;
  const databaseUrl = requireEnv(env, "DATABASE_URL");
  const masterKey = requireEnv(env, "VAULT_MASTER_KEY");
  if (masterKey.length < MIN_MASTER_KEY_CHARS) {
    fail(`VAULT_MASTER_KEY must be at least ${MIN_MASTER_KEY_CHARS} characters`);
  }
  const nodeId = requireEnv(env, "NODE_ID");
  const ceremonyId = deps.newId?.() ?? randomUUID();
  const ceremonyNonce = b64urlNonce();
  const issuedAt = (deps.now ?? (() => new Date()))().toISOString();
  const archiveEpochMaster = env.ARCHIVE_EPOCH_MASTER_KEY?.trim();
  if (archiveEpochMaster !== undefined && archiveEpochMaster.length < MIN_MASTER_KEY_CHARS) {
    fail(`ARCHIVE_EPOCH_MASTER_KEY must be at least ${MIN_MASTER_KEY_CHARS} characters`);
  }

  const pool = new Pool({ connectionString: databaseUrl });

  // ZTR-1159: the salt comes from the single resolver, read from the row persisted beside the
  // envelopes, and the derived root key is proven against a real envelope BEFORE the ceremony
  // takes a single further step. A ceremony that discovers a salt mismatch in its first second
  // is survivable; one that discovers it halfway through is not.
  const ceremonySql = {
    query: async <R>(text: string, params?: readonly unknown[]) => {
      const result = await pool.query(text, params as never);
      return { rows: result.rows as R[] };
    },
  };
  const rootSalt = await resolveCeremonyRootKdfSalt({ sql: ceremonySql, nodeId, env });
  const rootKey = deriveRootKey(masterKey, rootSalt.salt);
  await assertRootKeyOpensSealedEnvelope({
    sql: ceremonySql,
    nodeId,
    rootKey,
    saltSource: rootSalt.source,
  });
  // the archive-epoch key. Required when ARCHIVE_PATH names a
  // prior-epoch archive; the current VAULT_MASTER_KEY drives the possession proof, and this key
  // opens the archive's vault envelopes. Rotation re-seals under the SAME salt (only the master
  // key changes), so a prior epoch derives under the node's one salt too.
  const archiveRootKey =
    archiveEpochMaster !== undefined && archiveEpochMaster.length > 0
      ? deriveRootKey(archiveEpochMaster, rootSalt.salt)
      : undefined;
  let archiveText = "";
  let exportId: string | null = null;

  // The ceremony start is a guarded mutation. The operator presents a
  // FRESH single-use TOTP code (ADMIN_TOTP_CODE); it is verified against the enrolled default
  // admin operator's active secret and atomically burned via the durable `SqlTotpBurnStore`.
  // The burn is retained on any downstream failure — a failed ceremony consumes the
  // code, and a retry needs a fresh one. The verifier identity is derived from the authenticated
  // operator's id, never caller-forged.
  const totpCode = requireEnv(env, "ADMIN_TOTP_CODE");
  const userStore = new SqlAdminUserStore(createPoolAdminUserExecutor(pool), rootKey);
  await userStore.ensureSchema();
  const totpBurnStore = new SqlTotpBurnStore(createPoolTotpBurnExecutor(pool));
  await totpBurnStore.ensureSchema();
  const admin = await userStore.findByUsername(DEFAULT_ADMIN_USERNAME);
  if (admin === null) {
    fail(`default admin operator '${DEFAULT_ADMIN_USERNAME}' not found — bootstrap the node first`);
  }
  const totpFactor = await userStore.getTotpFactor(admin.id);
  if (totpFactor.status !== "active" || totpFactor.secretBase32 === undefined) {
    fail("default admin operator has no active TOTP factor — enrol+confirm TOTP first (admin/v1/enrol-totp)");
  }
  const secretBytes = totpSecretBytes(totpFactor.secretBase32);
  if (secretBytes === null) {
    fail("admin TOTP secret is not valid base32");
  }
  const totpConfig: TotpConfig = { secret: secretBytes, windowSteps: 1 };
  const totpOutcome = await verifyTotp(
    totpConfig,
    { nodeId, code: totpCode, nowMs: (deps.now ?? (() => new Date()))().getTime() },
    totpBurnStore,
  );
  if (!totpOutcome.ok) {
    fail(`ADMIN_TOTP_CODE rejected: ${totpOutcome.reason} (the code is consumed; a retry needs a fresh one)`);
  }
  // Provenance-derived identity: the authenticated admin operator's id, not an env string.
  const verifierIdentity = `admin:${admin.id}`;

  try {
    const archivePath = env.ARCHIVE_PATH?.trim();
    if (archivePath !== undefined && archivePath.length > 0) {
      archiveText = await readFile(archivePath, "utf8");
      const verification = verifyBackupArchive(archiveText);
      if (!verification.ok) {
        fail(`ARCHIVE_PATH rejected: ${verification.reasons.join(",")}`);
      }
      exportId = (JSON.parse(archiveText) as { manifest: { export_id: string } }).manifest
        .export_id;
    } else {
      // Prefer sealed-store identity; env seed is optional verify-only.
      let identitySeed: Buffer | undefined;
      const rawSeed = env.NODE_IDENTITY_SEED?.trim();
      if (rawSeed !== undefined && rawSeed.length > 0) {
        identitySeed = Buffer.from(resolveIdentitySeedFromEnv(env));
      }
      try {
        const exported = await exportLiveBackupArchive({
          sql: pool,
          rootKey,
          nodeId,
          identitySeed,
          exportId: ceremonyId,
          exportedAt: issuedAt,
        });
        archiveText = exported.archiveText;
        exportId = exported.exportId;
      } finally {
        identitySeed?.fill(0);
      }
    }

    const archiveOut = env.ARCHIVE_OUT?.trim();
    if (archiveOut !== undefined && archiveOut.length > 0) {
      await writeFile(archiveOut, archiveText, { mode: 0o600 });
    }

    const archiveSha = sha256HexUtf8(archiveText);

    const { result, destroyCalls } = await composeRestoreRecoveryCeremony({
      archiveText,
      rootKey,
      archiveRootKey,
      nodeId,
      liveSql: pool,
      verifierIdentity,
      ceremonyId,
      ceremonyNonce,
      issuedAt,
      now: deps.now,
      newId: deps.newId,
      restoredInstanceProvider: deps.restoredInstanceProvider ?? (await createThrowawayRestoredInstanceProvider({ databaseUrl, rootKey, archiveRootKey, nodeId })),
    });

    const counts = outcomeCounts(result);

    const verified = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM wallets
        WHERE node_id = $1::uuid AND recovery_verified_at IS NOT NULL`,
      [nodeId],
    );
    const verifiedOnLive = Number(verified.rows[0]?.n ?? "0");

    const summary: RunRecoveryCeremonySummary = {
      ok: result.accepted && counts.stamped + counts.skipped > 0 && verifiedOnLive > 0,
      ceremonyId,
      accepted: result.accepted,
      stamped: counts.stamped,
      failedClosed: counts.failedClosed,
      skipped: counts.skipped,
      bornBlocked: result.bornBlocked.length,
      abortReasons: result.abortReasons,
      instanceDestroyed: result.instanceDestroyed && destroyCalls >= 1,
      verifiedOnLive,
      exportId,
    };

    // Never keys — public digests and outcome counts only.
    console.log(
      JSON.stringify({
        ok: summary.ok,
        ceremony_id: summary.ceremonyId,
        export_id: summary.exportId,
        archive_sha256: archiveSha,
        accepted: summary.accepted,
        stamped: summary.stamped,
        failed_closed: summary.failedClosed,
        skipped: summary.skipped,
        born_blocked: summary.bornBlocked,
        abort_reasons: summary.abortReasons,
        instance_destroyed: summary.instanceDestroyed,
        recovery_verified_on_live: summary.verifiedOnLive,
      }),
    );

    return summary;
  } finally {
    await pool.end();
  }
}

async function main(): Promise<void> {
  const summary = await runRecoveryCeremony({});
  if (!summary.ok) process.exit(2);
}

const entry = process.argv[1];
if (
  entry !== undefined &&
  (entry.endsWith("run-recovery-ceremony.js") ||
    entry.endsWith("run-recovery-ceremony.ts") ||
    pathToFileURL(entry).href === import.meta.url)
) {
  void main().catch((err: unknown) => {
    fail(describeError(err));
  });
}
