// Offline disposable-PG proof of move-advanced-ports.ts's reconcileAndLand SQL
// paths. Prior to this test the module (production
// composition of the 5 advanced MOVE_INTERNAL money ports) had ZERO exercise against a
// real database — every existing test (move-internal-money-workers.test.ts) is static
// source-text analysis only.
//
// Covers, against a real disposable Postgres:
//  - "operation not found" (including the mandatory lease_group_operations JOIN in
//    LOAD_MOVE_DETAILS_SQL silently excluding an otherwise-valid row when that join is
//    missing) — protects against a future INNER JOIN -> LEFT JOIN slip.
//  - WAIT: "signed transaction not found" before STEP2_SIGNATURE_PERSISTED — exercises the
//    operation_transactions read for a MOVE attempt for the first time against real PG.
//  - SUBMIT-hold: a settled body is present but neither wallet holds an ACTIVE lease —
// classifyMoveReconcile's LEASE_NOT_ACTIVE_DURING_RECONCILE gate (the landing-proof rule) holds
//    reconcile rather than landing.
//  - LANDED_VERIFIED: both wallets carry ACTIVE MOVE_SOURCE/MOVE_DESTINATION leases and the
//    settled-transaction fixture from packages/node-core/test/fixtures/
//    splitchain-v2-byte-evidence.ts (real captured Ed25519 signatures — see
//    transaction-verify.ts) is reused for both legs' get_transaction__v1 read, driving the
// real the landing-proof rule depth-0 proveExactHeadLanding double-read oracle end to end and landing a
//    non-genesis internal_move.landed event through persistMoveOutcome.

import { createHash, createPrivateKey, createPublicKey, randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import { ATTENTION_REASONS } from "@zucoins/generic-node-contracts/api-schema";

import {
  advanceAttemptPhase,
  createSqlRecoveryLiveDatabase,
  deriveRootKey,
  EncryptedWalletKeyStore,
  fingerprintEndpoint,
  InMemoryVaultAccessAuditLog,
  insertTransactionAttempt,
  LEASE_STATEMENTS,
  migrateLeaseFoundation,
  sha256Hex,
  GENESIS_PROJECTION,
  MOVE_INTERNAL_ARTIFACT_PURPOSE,
  MOVE_INTERNAL_CANONICAL_VERSION,
  VaultSqlStore,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
  type GatewayRequest,
  type SqlQueryFn,
} from "@zucoins/node-core";

import { ensureNodeIdentitySigningKey, ensureNodeRow } from "../src/bootstrap/genesis.js";
import { publicKeyFromSeed } from "../src/ops/ed25519-ops.js";
import {
  createMoveAdvancedPorts,
  type MoveAdvancedPortsDeps,
} from "../src/money-workers/move-advanced-ports.js";
import { createSqlBootRecovery } from "../src/boot/sql-boot-recovery.js";
import {
  WALLET_RECEIVER_PUBLIC_KEY,
  WALLET_SENDER_PUBLIC_KEY,
  WALLET_SETTLED_TRANSACTION_SHA256,
  WALLET_SETTLED_TRANSACTION_TEXT,
} from "../../../packages/node-core/test/fixtures/splitchain-v2-byte-evidence.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const GATEWAY_A = "https://gateway-a.test.invalid/";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const VAULT_MASTER = "move-signer-audit-master-key!!!!!!!!!!!";
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

// A placeholder padded_base64url_signature (88 chars: 86x[A-Za-z0-9_-] + "=="). Never
// verified on this path — the WAIT test stops before STEP2_SIGNATURE_PERSISTED, so no
// signature or preimage here is ever passed to verifySettledTransaction.
const STUB_SIGNATURE = `${"A".repeat(86)}==`;

/** The 64-byte libsodium secret (seed || raw pubkey) createPoolVaultSigner reads back from
 * the vault — same derivation ed25519-ops.ts's publicKeyFromSeed uses, so the base64url
 * public key stamped on the wallets row matches what the sealed secret actually signs with. */
function sealedSecret64FromSeed(seed: Buffer): Buffer {
  const priv = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(priv).export({ type: "spki", format: "der" });
  return Buffer.concat([seed, Buffer.from(spki).subarray(-32)]);
}

function sha256HexOfText(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function hasClientTool(name: string): boolean {
  try {
    execFileSync(name, ["--version"], { stdio: "ignore" });
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
      execFileSync(
        "pg_isready",
        ["-q", "-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER],
        { stdio: "ignore" },
      );
      return true;
    }
  } catch {
    /* fall through */
  }
  try {
    execFileSync(
      "node",
      [
        "-e",
        `const {Client}=require("pg");const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:"postgres",password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ],
      { stdio: "ignore", env: process.env },
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
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
        WHERE datname = $1 AND pid <> pg_backend_pid()`,
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

/** Throws if ever called — neither the WAIT nor the not-found path may reach the gateway. */
function failingExchange(): GatewayExchangeTransport {
  return {
    async exchange(): Promise<GatewayExchangeCapture> {
      throw new Error("gateway unreachable (scripted): reconcileAndLand should not have read a fresh head here");
    },
  };
}

/**
 * Answers every get_transaction__v1 read with the same settled MOVE body regardless of
 * which wallet key was queried — sufficient to drive the real the landing-proof rule depth-0
 * proveExactHeadLanding double-read oracle for both the source and destination legs.
 */
function landedHeadExchange(): GatewayExchangeTransport {
  const responseText = `{"status":true,"code":"success","message":"","data":[${WALLET_SETTLED_TRANSACTION_TEXT}]}`;
  const responseBytes = new TextEncoder().encode(responseText);
  return {
    async exchange(endpoint: string, request: GatewayRequest): Promise<GatewayExchangeCapture> {
      expect(request.rpc).toBe("get_transaction__v1");
      return {
        endpoint,
        endpointFingerprint: fingerprintEndpoint(endpoint),
        requestBytes: request.bodyBytes,
        requestSha256: sha256Hex(request.bodyBytes),
        statusCode: 200,
        responseBytes,
        responseSha256: sha256Hex(responseBytes),
      };
    },
  };
}

/**
 * Answers the named wallet's read with the settled MOVE body and every OTHER wallet's with
 * the authoritative virgin-wallet genesis shape (`status:true`, exact empty history array —
 * gateway-envelope.ts's isAuthoritativeEmptyHistory).
 *
 * One leg then proves LANDED and the other anchors no path at all (a genesis head is a
 * legitimate observation the oracle turns into a MISSING_BODY fault), which is exactly the
 * reconcile row "one wallet appears landed and the other cannot connect to the same
 * transaction": INDETERMINATE / PATH_DISAGREEMENT, with both leases still ACTIVE.
 */
function pathDisagreementExchange(landedForPublicKey: string): GatewayExchangeTransport {
  const headText = `{"status":true,"code":"success","message":"","data":[${WALLET_SETTLED_TRANSACTION_TEXT}]}`;
  const genesisText = `{"status":true,"code":"success","message":"","data":[]}`;
  return {
    async exchange(endpoint: string, request: GatewayRequest): Promise<GatewayExchangeCapture> {
      expect(request.rpc).toBe("get_transaction__v1");
      // The read carries the wallet in its canonical key_public__base64urlsafe action-data
      // field, so which leg is asking is readable off the request bytes — through the frozen
      // form-body codec, which is `v=<encodeURIComponent(json)>`, so the key's base64 padding
      // arrives percent-escaped and a raw substring test would match neither leg.
      const asked = decodeURIComponent(
        new TextDecoder().decode(request.bodyBytes).replace(/^v=/, ""),
      );
      const responseBytes = new TextEncoder().encode(
        asked.includes(landedForPublicKey) ? headText : genesisText,
      );
      return {
        endpoint,
        endpointFingerprint: fingerprintEndpoint(endpoint),
        requestBytes: request.bodyBytes,
        requestSha256: sha256Hex(request.bodyBytes),
        statusCode: 200,
        responseBytes,
        responseSha256: sha256Hex(responseBytes),
      };
    },
  };
}

/** Node-identity signer stub: a 64-byte signature satisfies computeEventLogNodeEventHash's
 * length check (event-log/event-list.ts); the signature is never cryptographically verified
 * on this path. */
function stubNodeIdentitySigner(
  signingKeyId: string,
): () => { signingKeyId: string; sign: (bytes: Uint8Array) => string } {
  return () => ({
    signingKeyId,
    // padded_base64url_signature domain: 86 base64url chars + a literal "==" (see
    // STUB_SIGNATURE above) — randomBytes(64).toString("base64url") alone is 86 chars
    // with no padding and fails the DB check constraint.
    sign: () => `${randomBytes(64).toString("base64url")}==`,
  });
}

const logger = {
  lines: [] as string[],
  info(message: string) {
    this.lines.push(message);
  },
  error(message: string) {
    this.lines.push(`ERROR ${message}`);
  },
};

describe.skipIf(!PG_AVAILABLE)("move-advanced-ports reconcileAndLand SQL paths (disposable PG)", () => {
  const dbName = `move_advanced_ports_${process.pid}_${Date.now()}`;
  let pool: Pool;
  let prevDatabaseUrl: string | undefined;

  beforeAll(async () => {
    await createTestDatabase(dbName);
    pool = pgPool(dbName);
    prevDatabaseUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = pgDatabaseUrl(dbName);
    const { runMigrationsOnPool } = await import("../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl: process.env.DATABASE_URL });
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

  const query: SqlQueryFn = async (text, values) => {
    const result = await pool.query(text, values as never[]);
    return result.rows as readonly Record<string, unknown>[];
  };

  type DepsOverrides = Partial<
    Pick<MoveAdvancedPortsDeps, "gatewayExchange" | "nodeIdentitySigner" | "vault" | "leadership">
  >;

  function makeDeps(nodeId: string, overrides?: DepsOverrides): MoveAdvancedPortsDeps {
    return {
      pool,
      vault: overrides?.vault ?? ({} as unknown as EncryptedWalletKeyStore),
      nodeId,
      ownerInstanceId: randomUUID(),
      leadership: { held: true },
      moneyPathGates: {
        assertMoneyAdmitted() {},
        assertCanOperate() {},
        assertWalletMaySign() {},
        assertHaltAdmitsKind() {},
      },
      submitGateway: {
        endpoint: "https://submit.test.invalid/",
        limits: { readTimeoutMs: 10_000, maxRequestBytes: 1_048_576, maxResponseBytes: 4_194_304 },
      },
      gatewayUrls: [GATEWAY_A],
      gatewayExchange: overrides?.gatewayExchange ?? failingExchange(),
      nodeIdentitySigner: overrides?.nodeIdentitySigner ?? (() => null),
      logger,
    };
  }

  async function reconcile(nodeId: string, operationId: string, overrides?: DepsOverrides) {
    const ports = createMoveAdvancedPorts(makeDeps(nodeId, overrides));
    return ports.reconcileAndLand!(operationId, {} as Parameters<NonNullable<typeof ports.reconcileAndLand>>[1]);
  }

  interface SeededMove {
    readonly nodeId: string;
    readonly operationId: string;
    readonly sourceWalletId: string;
    readonly destinationWalletId: string;
    readonly leaseGroupId: string;
    readonly signingKeyId: string;
  }

  /**
   * a T0 gateway_observations row's verification classification, keyed the same
   * way loadBaselineBound now reads it (parse_result, not body truthiness). "GENESIS"
   * mirrors seedT0Observation's default placeholder row. "HEAD" seeds a real VERIFIED_HEAD
   * row carrying a re-verifiable settled-transaction body (observation-ledger.sql's
   * VERIFIED_HEAD CHECK). "CORRUPT" seeds a non-genesis/non-head parse_result (evidence
   * present but never reconstructable) to prove the fail-closed throw.
   */
  type T0SeedCase =
    | { readonly kind: "GENESIS" }
    | { readonly kind: "HEAD"; readonly walletRole: "sender" | "receiver"; readonly bodyText: string; readonly bodySha256: string }
    | { readonly kind: "CORRUPT" };

  /**
   * Seeds a MOVE_INTERNAL operation with its source/destination wallets and BLESSED
   * destination row. Lease state is out of scope here (reconcileAndLand's WAIT and
   * not-found returns both precede deriveLeaseState — see move-advanced-ports.ts lines
   * ~562-589), so no wallet_lease_memberships / wallet_active_leases rows are seeded — use
   * seedActiveLease for tests that need to reach the lease gate or beyond.
   *
   * @param joinLeaseGroupOperations When false, omits the lease_group_operations row that
   *   LOAD_MOVE_DETAILS_SQL mandatorily INNER JOINs on — proving that join really is
   *   mandatory (an otherwise fully-formed operation is invisible to reconcileAndLand
   *   without it).
   * @param walletKeys Overrides the source/destination wallets' public keys — the
   *   LANDED_VERIFIED walk needs the real fixture keypair embedded in the settled body.
   * @param t0Cases overrides each side's T0 observation parse_result away from
   *   the default VERIFIED_GENESIS placeholder, for loadBaselineBound reload coverage.
   */
  async function seedMoveOperation(
    joinLeaseGroupOperations: boolean,
    walletKeys?: { readonly sourcePublicKey: string; readonly destinationPublicKey: string },
    t0Cases?: { readonly source?: T0SeedCase; readonly destination?: T0SeedCase },
  ): Promise<SeededMove> {
    const nodeId = randomUUID();
    const implementerId = randomUUID();
    const operationId = randomUUID();
    const sourceWalletId = randomUUID();
    const destinationWalletId = randomUUID();
    const destinationId = randomUUID();
    const leaseGroupId = randomUUID();
    const signingKeyId = randomUUID();

    const identityPublicKey = publicKeyFromSeed(randomBytes(32));
    await ensureNodeRow(pool, {
      nodeId,
      displayName: "fixture-b-move-advanced-ports",
      identityPublicKey,
    });
    // persistMoveOutcome's internal_move.landed event stamps a real signing_key_id FK
    // (node_signing_keys) — the stub signer below never verifies the signature bytes, but
    // the key row must exist (ensureNodeIdentitySigningKey, deprecated-but-test-fixture path).
    await ensureNodeIdentitySigningKey(pool, { keyId: signingKeyId, nodeId, publicKey: identityPublicKey });
    await pool.query(
      `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-b-impl', now())`,
      [implementerId],
    );
    const sourcePublicKey = walletKeys?.sourcePublicKey ?? publicKeyFromSeed(randomBytes(32));
    const destinationPublicKey = walletKeys?.destinationPublicKey ?? publicKeyFromSeed(randomBytes(32));
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ($1::uuid, $3::uuid, $2, 'node_generated', 'AVAILABLE')`,
      [sourceWalletId, sourcePublicKey, nodeId],
    );
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ($1::uuid, $3::uuid, $2, 'node_generated', 'AVAILABLE')`,
      [destinationWalletId, destinationPublicKey, nodeId],
    );
    // MOVE_DESTINATION leases require recovery_verified_at (custody_reject_ineligible_lease,
    // custody-eligibility.sql) — stamp via the sealed recovery-verification production API (never a raw
    // recovery_verified_at UPDATE), mirroring money-workers-fundable.pg.test.ts.
    const destRecoveryLiveDb = createSqlRecoveryLiveDatabase({
      sql: {
        query: async <R>(text: string, params: readonly unknown[]) => {
          const result = await pool.query(text, params as never);
          return { rows: result.rows as R[] };
        },
      },
      nodeId,
      proveCurrentKeyPossession: async () => true,
    });
    const destRecoveryPreimage = `fixture-b-move-advanced-ports-recovery|${destinationWalletId}`;
    await destRecoveryLiveDb.stampRecoveryVerification({
      ceremonyId: randomUUID(),
      walletId: destinationWalletId,
      method: "AUDITED_EXPORT",
      publicKey: destinationPublicKey,
      keyVersion: 1,
      exportId: randomUUID(),
      exportSha256: sha256HexOfText(destRecoveryPreimage),
      censusMatchedRestored: true,
      censusMatchedLive: true,
      archivedProofVerified: true,
      probePreimageSha256: sha256HexOfText(`${destRecoveryPreimage}-probe`),
      probeSignature: STUB_SIGNATURE,
      probeVerified: true,
      verifierIdentity: "fixture-b-offline-stamp-seam",
    });
    // BLESSED requires a real destination_blessing_artifacts row first — destinations_
    // blessing_artifact_fk (signer-support.sql) references it; destinations_blessing_
    // requires_device_artifact then lets the UPDATE set state='BLESSED' (custody-
    // eligibility.sql). Mirrors apps/generic-node/test/money-workers-fundable.pg.test.ts.
    await pool.query(
      `INSERT INTO destinations (id, node_id, wallet_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
      [destinationId, nodeId, destinationWalletId],
    );
    const blessingArtifactId = randomUUID();
    const blessingPreimageText = `fixture-b-move-advanced-ports-bless|${destinationId}`;
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
        destinationId,
        destinationWalletId,
        destinationPublicKey,
        randomUUID(),
        issuedAt.toISOString(),
        expiresAt.toISOString(),
        STUB_SIGNATURE,
        blessingPreimageText,
        sha256HexOfText(blessingPreimageText),
      ],
    );
    await pool.query(
      `UPDATE destinations
          SET state = 'BLESSED', blessed_at = now(),
              blessed_by_device_key_id = $2::uuid, blessing_artifact_id = $3::uuid
        WHERE id = $1::uuid`,
      [destinationId, randomUUID(), blessingArtifactId],
    );
    await pool.query(
      `INSERT INTO operations (
         id, node_id, implementer_id, kind, status, amount_zkz,
         source_wallet_id, destination_id, idempotency_key, request_sha256)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'MOVE_INTERNAL', 'CREATED', $4,
               $5::uuid, $6::uuid, $7, $8)`,
      [
        operationId,
        nodeId,
        implementerId,
        "1.5",
        sourceWalletId,
        destinationId,
        `idem-${operationId}`,
        sha256HexOfText(operationId),
      ],
    );

    if (joinLeaseGroupOperations) {
      await pool.query(
        `INSERT INTO lease_groups (id, root_operation_id, created_at)
         VALUES ($1::uuid, $2::uuid, now())`,
        [leaseGroupId, operationId],
      );
      await pool.query(
        `INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at)
         VALUES ($1::uuid, $2::uuid, now())`,
        [leaseGroupId, operationId],
      );
    }

    // persistMoveOutcome's CAS UPDATE (PERSIST_MOVE_OUTCOME, move-internal-landing-store.ts)
    // requires a pre-existing move_observation_evidence row whenever the outcome carries a
    // non-null terminal observation id (true for LANDED_VERIFIED) — production forms this row
    // during MOVE formation (move-baseline-binding.ts's INSERT_EVIDENCE), which is out of
    // scope here (file header). Seed it directly: two placeholder T0 gateway_observations rows
    // under one observers row, then the evidence row linking them. VERIFIED_GENESIS / FIRST is
    // the branch used (not TRANSPORT_ERROR / NOT_APPLICABLE) because an anomalous parse_result
    // or relationship trips observation-anomaly-indexes.sql's No-blind-retry anomaly-ledger deferred
    // constraint trigger, which demands a matching observation_anomalies row this seed doesn't
    // (and shouldn't) create.
    // owner_id is deliberately NOT nodeId: production's own real observer for this node
    // is also keyed (domain='NODE', owner_id=nodeId), and reusing that identity here would
    // collide the wallet_seq this stub picks with the wallet_seq reconcileAndLand's own
    // gateway read later assigns to the same (observer_id, wallet_public_key) stream.
    const observerId = randomUUID();
    await pool.query(
      `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
       VALUES ($1::uuid, 'NODE', $2::uuid, $3, now())`,
      [observerId, randomUUID(), fingerprintEndpoint(GATEWAY_A)],
    );
    async function seedT0Observation(
      walletId: string,
      publicKey: string,
      t0Case: T0SeedCase = { kind: "GENESIS" },
    ): Promise<string> {
      const observationId = randomUUID();
      if (t0Case.kind === "GENESIS") {
        const responseBytes = new TextEncoder().encode(`fixture-b-t0-placeholder|${observationId}`);
        await pool.query(
          `INSERT INTO gateway_observations (
             id, observer_id, endpoint_fingerprint, wallet_id, wallet_public_key, wallet_seq,
             observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship,
             semantic_fingerprint, state_changed, wallet_role, s_signature, p_signature, b_amount
           ) VALUES (
             $1::uuid, $2::uuid, $3, $4::uuid, $5, 1, now(), $6, $7, 'VERIFIED_GENESIS', 'FIRST',
             $8, true, 'genesis', '', '', '0'
           )`,
          [
            observationId,
            observerId,
            fingerprintEndpoint(GATEWAY_A),
            walletId,
            publicKey,
            responseBytes,
            sha256Hex(responseBytes),
            sha256HexOfText(`fixture-b-semantic|${observationId}`),
          ],
        );
        return observationId;
      }
      if (t0Case.kind === "HEAD") {
        // a real VERIFIED_HEAD T0 row: observation-ledger.sql mandates
        // wallet_role/s_signature/step_1/step_2/completed_transaction_* all present and
        // pattern-matched. completed_transaction_text is the raw settled-transaction JSON
        // (no envelope wrapper) — the same shape STEP2_SIGNATURE_PERSISTED persists in
        // operation_transactions (seedSettledAttempt below) and the same shape
        // projectionFromBodyText wraps back into an envelope to re-verify.
        const responseBytes = new TextEncoder().encode(`fixture-c-t0-head-placeholder|${observationId}`);
        await pool.query(
          `INSERT INTO gateway_observations (
             id, observer_id, endpoint_fingerprint, wallet_id, wallet_public_key, wallet_seq,
             observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship,
             semantic_fingerprint, state_changed, wallet_role, s_signature, p_signature, b_amount,
             inner_preimage_text, step_1_signature, step_2_signature,
             completed_transaction_text, completed_transaction_sha256
           ) VALUES (
             $1::uuid, $2::uuid, $3, $4::uuid, $5, 1, now(), $6, $7, 'VERIFIED_HEAD', 'FIRST',
             $8, true, $9, $10, '', '1.5',
             $11, $10, $10,
             $12, $13
           )`,
          [
            observationId,
            observerId,
            fingerprintEndpoint(GATEWAY_A),
            walletId,
            publicKey,
            responseBytes,
            sha256Hex(responseBytes),
            sha256HexOfText(`fixture-c-semantic|${observationId}`),
            t0Case.walletRole,
            STUB_SIGNATURE,
            `fixture-c-inner-preimage|${observationId}`,
            t0Case.bodyText,
            t0Case.bodySha256,
          ],
        );
        return observationId;
      }
      // "CORRUPT" — evidence is present but its parse_result is neither VERIFIED_GENESIS nor
      // VERIFIED_HEAD (observation-ledger.sql's final CHECK requires relationship
      // NOT_APPLICABLE and every downstream column NULL for this branch): reload must throw,
      // never silently treat this as absent (undefined) and WAIT forever.
      //
      // A TRANSPORT_ERROR-classified row also trips the No-blind-retry anomaly-ledger deferred
      // constraint (observation_anomaly_guard() in observation-anomaly-indexes.sql), which
      // requires a matching observation_anomalies row committed in the SAME transaction —
      // so both inserts run on one client wrapped in BEGIN/COMMIT (mirrors the pattern in
      // packages/node-core/test/observation-anomaly-indexes.pg.test.ts).
      const responseBytes = new TextEncoder().encode(`fixture-c-t0-corrupt-placeholder|${observationId}`);
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          `INSERT INTO gateway_observations (
             id, observer_id, endpoint_fingerprint, wallet_id, wallet_public_key, wallet_seq,
             observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship
           ) VALUES (
             $1::uuid, $2::uuid, $3, $4::uuid, $5, 1, now(), $6, $7, 'TRANSPORT_ERROR', 'NOT_APPLICABLE'
           )`,
          [
            observationId,
            observerId,
            fingerprintEndpoint(GATEWAY_A),
            walletId,
            publicKey,
            responseBytes,
            sha256Hex(responseBytes),
          ],
        );
        await client.query(
          `INSERT INTO observation_anomalies (
             id, observation_id, observer_id, wallet_id, wallet_public_key, kind, details, detected_at
           ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, 'TRANSPORT_ERROR', $6, now())`,
          [randomUUID(), observationId, observerId, walletId, publicKey, "fixture-c corrupt T0 fixture"],
        );
        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK");
        throw err;
      } finally {
        client.release();
      }
      return observationId;
    }
    const sourceT0ObservationId = await seedT0Observation(sourceWalletId, sourcePublicKey, t0Cases?.source);
    const destinationT0ObservationId = await seedT0Observation(
      destinationWalletId,
      destinationPublicKey,
      t0Cases?.destination,
    );
    await pool.query(
      `INSERT INTO move_observation_evidence
         (operation_id, source_t0_observation_id, destination_t0_observation_id)
       VALUES ($1::uuid, $2::uuid, $3::uuid)`,
      [operationId, sourceT0ObservationId, destinationT0ObservationId],
    );

    return { nodeId, operationId, sourceWalletId, destinationWalletId, leaseGroupId, signingKeyId };
  }

  /** Seeds one ACTIVE wallet_lease_memberships + wallet_active_leases row pair. */
  async function seedActiveLease(params: {
    readonly leaseGroupId: string;
    readonly operationId: string;
    readonly walletId: string;
    readonly leaseRole: "MOVE_SOURCE" | "MOVE_DESTINATION";
  }): Promise<void> {
    const membershipId = randomUUID();
    const acquiredAt = new Date().toISOString();
    await pool.query(LEASE_STATEMENTS.INSERT_MEMBERSHIP, [
      membershipId,
      params.leaseGroupId,
      params.walletId,
      params.operationId,
      params.leaseRole,
      1,
      acquiredAt,
    ]);
    await pool.query(LEASE_STATEMENTS.INSERT_ACTIVE, [
      params.walletId,
      membershipId,
      params.leaseGroupId,
      params.operationId,
      params.operationId,
      params.leaseRole,
      1,
      acquiredAt,
      acquiredAt,
      randomUUID(),
    ]);
  }

  /**
   * Seeds the operation_expected_artifacts row loadBaselineBound unconditionally
   * requires (move-advanced-ports.ts lines ~447-458), independent of the T0 genesis/head
   * fix under test. Column set mirrors core/move-baseline-binding.ts's INSERT_ARTIFACT.
   */
  async function seedExpectedArtifact(operationId: string, signingKeyId: string): Promise<void> {
    const preimageText = `fixture-c-expected-artifact|${operationId}`;
    await pool.query(
      `INSERT INTO operation_expected_artifacts (
         id, operation_id, purpose, canonical_version, signing_key_id,
         preimage_text, preimage_sha256, signature, created_at
       ) VALUES ($1::uuid, $2::uuid, $3, $4, $5::uuid, $6, $7, $8, now())`,
      [
        randomUUID(),
        operationId,
        MOVE_INTERNAL_ARTIFACT_PURPOSE,
        MOVE_INTERNAL_CANONICAL_VERSION,
        signingKeyId,
        preimageText,
        sha256HexOfText(preimageText),
        STUB_SIGNATURE,
      ],
    );
  }

  /** Advances a MOVE attempt through STEP2_SIGNATURE_PERSISTED using the settled-body fixture. */
  async function seedSettledAttempt(operationId: string): Promise<void> {
    const innerPreimageText = JSON.stringify({ stub: "move-inner", operationId });
    const step2PreimageText = JSON.stringify({ stub: "move-step2", operationId });

    await insertTransactionAttempt(query, {
      operationId,
      innerPreimageText,
      innerSha256: sha256HexOfText(innerPreimageText),
      formedAt: new Date().toISOString(),
    });
    await advanceAttemptPhase(query, operationId, "STEP1_SIGNATURE_PERSISTED", {
      step_1_signature: STUB_SIGNATURE,
    });
    await advanceAttemptPhase(query, operationId, "STEP2_PREIMAGE_PERSISTED", {
      step_2_preimage_text: step2PreimageText,
      step_2_preimage_sha256: sha256HexOfText(step2PreimageText),
    });
    await advanceAttemptPhase(query, operationId, "STEP2_SIGNATURE_PERSISTED", {
      step_2_signature: STUB_SIGNATURE,
      completed_transaction_text: WALLET_SETTLED_TRANSACTION_TEXT,
      completed_transaction_sha256: WALLET_SETTLED_TRANSACTION_SHA256,
    });
  }

  it("operation not found: an unknown operation id returns 'operation not found'", async () => {
    const nodeId = randomUUID();
    await ensureNodeRow(pool, {
      nodeId,
      displayName: "fixture-b-not-found",
      identityPublicKey: publicKeyFromSeed(randomBytes(32)),
    });
    const result = await reconcile(nodeId, randomUUID());
    expect(result).toEqual({ ok: false, reason: "operation not found" });
  });

  it(
    "mandatory lease_group_operations JOIN: a fully-formed operation with no lease_group_operations row is invisible (operation not found)",
    async () => {
      const seeded = await seedMoveOperation(false);
      const result = await reconcile(seeded.nodeId, seeded.operationId);
      expect(result).toEqual({ ok: false, reason: "operation not found" });
    },
  );

  it(
    "WAIT: an attempt parked before STEP2_SIGNATURE_PERSISTED returns 'signed transaction not found' and holds reconcile",
    async () => {
      const seeded = await seedMoveOperation(true);
      const innerPreimageText = JSON.stringify({ stub: "move-inner", operationId: seeded.operationId });
      const step2PreimageText = JSON.stringify({ stub: "move-step2", operationId: seeded.operationId });

      await insertTransactionAttempt(query, {
        operationId: seeded.operationId,
        innerPreimageText,
        innerSha256: sha256HexOfText(innerPreimageText),
        formedAt: new Date().toISOString(),
      });
      await advanceAttemptPhase(query, seeded.operationId, "STEP1_SIGNATURE_PERSISTED", {
        step_1_signature: STUB_SIGNATURE,
      });
      await advanceAttemptPhase(query, seeded.operationId, "STEP2_PREIMAGE_PERSISTED", {
        step_2_preimage_text: step2PreimageText,
        step_2_preimage_sha256: sha256HexOfText(step2PreimageText),
      });

      const result = await reconcile(seeded.nodeId, seeded.operationId);
      expect(result).toEqual({ ok: false, reason: "signed transaction not found", holdReconcile: true });
    },
  );

  it(
    "SUBMIT-hold: a settled body with no ACTIVE lease on either wallet holds reconcile (LEASE_NOT_ACTIVE_DURING_RECONCILE)",
    async () => {
      const seeded = await seedMoveOperation(true, {
        sourcePublicKey: WALLET_SENDER_PUBLIC_KEY,
        destinationPublicKey: WALLET_RECEIVER_PUBLIC_KEY,
      });
      await seedSettledAttempt(seeded.operationId);
      // Deliberately no seedActiveLease calls — both wallets read back RELEASED.

      const result = await reconcile(seeded.nodeId, seeded.operationId, {
        gatewayExchange: landedHeadExchange(),
        nodeIdentitySigner: stubNodeIdentitySigner(seeded.signingKeyId),
      });
      expect(result).toEqual({ ok: false, reason: "reconcile: INVARIANT_BREACH", holdReconcile: true });
    },
  );

  // ZTR-1130. MOVE_INTERNAL declares NEEDS_ATTENTION as a reachable state and
  // move-internal-landing-store.ts projects both non-landing verdicts onto it, but the
  // production caller used to return before persistMoveOutcome on every kind except
  // LANDED_VERIFIED. An ambiguous move therefore sat at CREATED forever holding BOTH wallet
  // leases with no flag and no event — against a hard wallet cap that never restores capacity,
  // so the only symptom was a slow drift toward pool exhaustion. These tests drive the real
  // reconcile to each non-landing verdict and prove the durable escalation now happens.

  /** The operation row's attention columns plus the owner the tenant stream is keyed on. */
  async function readAttention(operationId: string): Promise<{
    readonly status: string;
    readonly attention_required: boolean;
    readonly attention_reason: string | null;
    readonly attention_detail: string | null;
    readonly no_terminal: boolean;
    readonly implementer_id: string;
  }> {
    const rows = await pool.query(
      `SELECT status::text AS status, attention_required, attention_reason, attention_detail,
              (terminal_at IS NULL) AS no_terminal, implementer_id::text AS implementer_id
         FROM operations WHERE id = $1::uuid`,
      [operationId],
    );
    return rows.rows[0] as never;
  }

  const nodeEventTypes = async (operationId: string): Promise<readonly string[]> =>
    (
      await pool.query(
        `SELECT event_type FROM node_events WHERE operation_id = $1::uuid ORDER BY seq`,
        [operationId],
      )
    ).rows.map((r) => (r as { event_type: string }).event_type);

  /** What GET /v1/events would serve this tenant: the zp-implementer-event-v1 chain. */
  const implementerEventTypes = async (implementerId: string): Promise<readonly string[]> =>
    (
      await pool.query(
        `SELECT event_type FROM implementer_events WHERE implementer_id = $1::uuid
          ORDER BY implementer_seq`,
        [implementerId],
      )
    ).rows.map((r) => (r as { event_type: string }).event_type);

  /** Wallet ids that still hold an ACTIVE lease, sorted for a stable comparison. */
  const heldLeases = async (walletIds: readonly string[]): Promise<readonly string[]> =>
    (
      await pool.query(
        `SELECT wallet_id::text AS wallet_id FROM wallet_active_leases
          WHERE wallet_id = ANY($1::uuid[]) ORDER BY wallet_id`,
        [walletIds],
      )
    ).rows.map((r) => (r as { wallet_id: string }).wallet_id);

  it(
    "INDETERMINATE: an ambiguous move parks at NEEDS_ATTENTION with a frozen attention reason, an operation.needs_attention event on both chains, and BOTH leases still held",
    async () => {
      const seeded = await seedMoveOperation(true, {
        sourcePublicKey: WALLET_SENDER_PUBLIC_KEY,
        destinationPublicKey: WALLET_RECEIVER_PUBLIC_KEY,
      });
      await seedSettledAttempt(seeded.operationId);
      await seedActiveLease({
        leaseGroupId: seeded.leaseGroupId,
        operationId: seeded.operationId,
        walletId: seeded.sourceWalletId,
        leaseRole: "MOVE_SOURCE",
      });
      await seedActiveLease({
        leaseGroupId: seeded.leaseGroupId,
        operationId: seeded.operationId,
        walletId: seeded.destinationWalletId,
        leaseRole: "MOVE_DESTINATION",
      });
      const wallets = [seeded.sourceWalletId, seeded.destinationWalletId];
      const leasesBefore = await heldLeases(wallets);
      expect(leasesBefore).toHaveLength(2);

      const result = await reconcile(seeded.nodeId, seeded.operationId, {
        // Source lands, destination reads genesis — neither wallet can be released and
        // neither a landing nor a non-landing can be concluded.
        gatewayExchange: pathDisagreementExchange(WALLET_SENDER_PUBLIC_KEY),
        nodeIdentitySigner: stubNodeIdentitySigner(seeded.signingKeyId),
      });

      // Still holds and still licenses no retry — that part was always right.
      expect(result).toEqual({ ok: false, reason: "reconcile: INDETERMINATE", holdReconcile: true });

      const attention = await readAttention(seeded.operationId);
      expect(attention.status).toBe("NEEDS_ATTENTION");
      expect(attention.attention_required).toBe(true);
      // PATH_DISAGREEMENT maps onto exactly one closed-vocabulary member; the free-text
      // specifics live in attention_detail, never in a new reason.
      expect(attention.attention_reason).toBe("VERIFICATION_INDETERMINATE");
      expect(ATTENTION_REASONS).toContain(attention.attention_reason);
      expect(attention.attention_detail).toContain("PATH_DISAGREEMENT");
      // No landing was proven, so no terminal instant was stamped.
      expect(attention.no_terminal).toBe(true);

      expect(await nodeEventTypes(seeded.operationId)).toEqual(["operation.needs_attention"]);
      expect(await implementerEventTypes(attention.implementer_id)).toEqual([
        "operation.needs_attention",
      ]);

      // Doc 01 §12: possible landing retains the leases and escalates. Both, not either.
      expect(await heldLeases(wallets)).toEqual(leasesBefore);

      // A later tick reaching the same verdict must not re-append: the frozen transition table
      // has no NEEDS_ATTENTION → NEEDS_ATTENTION edge, so the park is a one-shot escalation.
      const second = await reconcile(seeded.nodeId, seeded.operationId, {
        gatewayExchange: pathDisagreementExchange(WALLET_SENDER_PUBLIC_KEY),
        nodeIdentitySigner: stubNodeIdentitySigner(seeded.signingKeyId),
      });
      expect(second).toEqual({ ok: false, reason: "reconcile: INDETERMINATE", holdReconcile: true });
      expect(await nodeEventTypes(seeded.operationId)).toEqual(["operation.needs_attention"]);

      // NEEDS_ATTENTION → INTERNAL_MOVE_LANDED: a later reconciliation that CAN see both legs
      // recovers through the very same production path, out of the state this fix introduced.
      const recovered = await reconcile(seeded.nodeId, seeded.operationId, {
        gatewayExchange: landedHeadExchange(),
        nodeIdentitySigner: stubNodeIdentitySigner(seeded.signingKeyId),
      });
      expect(recovered.ok).toBe(true);
      if (!recovered.ok) return;
      expect(recovered.land.persist.kind).toBe("PERSISTED");
      const landed = await readAttention(seeded.operationId);
      expect(landed.status).toBe("INTERNAL_MOVE_LANDED");
      expect(landed.attention_required).toBe(false);
      expect(landed.attention_reason).toBeNull();
      expect(await nodeEventTypes(seeded.operationId)).toEqual([
        "operation.needs_attention",
        "internal_move.landed",
      ]);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "INVARIANT_BREACH: a lease that is no longer ACTIVE parks at NEEDS_ATTENTION with LEASE_INVARIANT_VIOLATION and releases nothing",
    async () => {
      const seeded = await seedMoveOperation(true, {
        sourcePublicKey: WALLET_SENDER_PUBLIC_KEY,
        destinationPublicKey: WALLET_RECEIVER_PUBLIC_KEY,
      });
      await seedSettledAttempt(seeded.operationId);
      // Only the source is leased: reconciling while the destination lease has already been
      // released contradicts the release precondition outright.
      await seedActiveLease({
        leaseGroupId: seeded.leaseGroupId,
        operationId: seeded.operationId,
        walletId: seeded.sourceWalletId,
        leaseRole: "MOVE_SOURCE",
      });

      const result = await reconcile(seeded.nodeId, seeded.operationId, {
        gatewayExchange: landedHeadExchange(),
        nodeIdentitySigner: stubNodeIdentitySigner(seeded.signingKeyId),
      });
      expect(result).toEqual({ ok: false, reason: "reconcile: INVARIANT_BREACH", holdReconcile: true });

      const attention = await readAttention(seeded.operationId);
      expect(attention.status).toBe("NEEDS_ATTENTION");
      expect(attention.attention_reason).toBe("LEASE_INVARIANT_VIOLATION");
      expect(ATTENTION_REASONS).toContain(attention.attention_reason);
      expect(attention.attention_detail).toContain("LEASE_NOT_ACTIVE_DURING_RECONCILE");
      expect(attention.no_terminal).toBe(true);

      expect(await nodeEventTypes(seeded.operationId)).toEqual(["operation.needs_attention"]);
      expect(await implementerEventTypes(attention.implementer_id)).toEqual([
        "operation.needs_attention",
      ]);
      // The park is not a release: the lease that WAS held is still held.
      expect(await heldLeases([seeded.sourceWalletId])).toEqual([seeded.sourceWalletId]);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "LANDED_VERIFIED: ACTIVE leases on both wallets + a matching settled body lands a non-genesis internal_move.landed event",
    async () => {
      const seeded = await seedMoveOperation(true, {
        sourcePublicKey: WALLET_SENDER_PUBLIC_KEY,
        destinationPublicKey: WALLET_RECEIVER_PUBLIC_KEY,
      });
      await seedSettledAttempt(seeded.operationId);
      await seedActiveLease({
        leaseGroupId: seeded.leaseGroupId,
        operationId: seeded.operationId,
        walletId: seeded.sourceWalletId,
        leaseRole: "MOVE_SOURCE",
      });
      await seedActiveLease({
        leaseGroupId: seeded.leaseGroupId,
        operationId: seeded.operationId,
        walletId: seeded.destinationWalletId,
        leaseRole: "MOVE_DESTINATION",
      });

      const result = await reconcile(seeded.nodeId, seeded.operationId, {
        gatewayExchange: landedHeadExchange(),
        nodeIdentitySigner: stubNodeIdentitySigner(seeded.signingKeyId),
      });

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.land.outcome).toMatchObject({
        kind: "LANDED_VERIFIED",
        moveAttemptId: seeded.operationId,
      });
      expect(result.land.persist.kind).toBe("PERSISTED");
    },
  );

  // MOVE crash recovery cannot reload genesis T0 baseline
  // loadBaselineBound must key its T0 reload on
  // each observation's parse_result classification, not completed_transaction_text
  // truthiness: a VERIFIED_GENESIS row is durably NULL-bodied by construction, and that
  // NULL is the genesis baseline itself, not missing evidence. These tests exercise the
  // fixed loadBaselineBound directly against a real disposable Postgres, seeding every
  // genesis/non-genesis source/destination combination plus the fail-closed corrupt case.

  async function seedT0ObservationIds(operationId: string): Promise<{ readonly s: string; readonly d: string }> {
    const rows = await pool.query(
      `SELECT source_t0_observation_id::text AS s, destination_t0_observation_id::text AS d
         FROM move_observation_evidence WHERE operation_id = $1::uuid`,
      [operationId],
    );
    return rows.rows[0] as { s: string; d: string };
  }

  it(
    "loadBaselineBound: VERIFIED_GENESIS/VERIFIED_GENESIS reloads GENESIS_PROJECTION for both wallets and resumes the same T0 attempt",
    async () => {
      const seeded = await seedMoveOperation(true);
      await seedExpectedArtifact(seeded.operationId, seeded.signingKeyId);
      const evidence = await seedT0ObservationIds(seeded.operationId);

      const ports = createMoveAdvancedPorts(makeDeps(seeded.nodeId));
      const bound = await ports.loadBaselineBound!(seeded.operationId);

      expect(bound).not.toBeNull();
      if (bound === null) return;
      expect(bound.capture.sourceBaseline).toEqual(GENESIS_PROJECTION);
      expect(bound.capture.destinationBaseline).toEqual(GENESIS_PROJECTION);
      expect(bound.capture.operationId).toBe(seeded.operationId);
      expect(bound.sourceT0ObservationId).toBe(evidence.s);
      expect(bound.destinationT0ObservationId).toBe(evidence.d);
    },
  );

  it(
    "loadBaselineBound: VERIFIED_HEAD source / VERIFIED_GENESIS destination reloads the source's re-verified projection and resumes the same T0 attempt",
    async () => {
      const seeded = await seedMoveOperation(
        true,
        { sourcePublicKey: WALLET_SENDER_PUBLIC_KEY, destinationPublicKey: WALLET_RECEIVER_PUBLIC_KEY },
        {
          source: {
            kind: "HEAD",
            walletRole: "sender",
            bodyText: WALLET_SETTLED_TRANSACTION_TEXT,
            bodySha256: WALLET_SETTLED_TRANSACTION_SHA256,
          },
        },
      );
      await seedExpectedArtifact(seeded.operationId, seeded.signingKeyId);
      const evidence = await seedT0ObservationIds(seeded.operationId);

      const ports = createMoveAdvancedPorts(makeDeps(seeded.nodeId));
      const bound = await ports.loadBaselineBound!(seeded.operationId);

      expect(bound).not.toBeNull();
      if (bound === null) return;
      expect(bound.capture.sourceBaseline).not.toEqual(GENESIS_PROJECTION);
      expect(bound.capture.destinationBaseline).toEqual(GENESIS_PROJECTION);
      expect(bound.sourceT0ObservationId).toBe(evidence.s);
      expect(bound.destinationT0ObservationId).toBe(evidence.d);
    },
  );

  it(
    "loadBaselineBound: VERIFIED_GENESIS source / VERIFIED_HEAD destination reloads the destination's re-verified projection and resumes the same T0 attempt",
    async () => {
      const seeded = await seedMoveOperation(
        true,
        { sourcePublicKey: WALLET_SENDER_PUBLIC_KEY, destinationPublicKey: WALLET_RECEIVER_PUBLIC_KEY },
        {
          destination: {
            kind: "HEAD",
            walletRole: "receiver",
            bodyText: WALLET_SETTLED_TRANSACTION_TEXT,
            bodySha256: WALLET_SETTLED_TRANSACTION_SHA256,
          },
        },
      );
      await seedExpectedArtifact(seeded.operationId, seeded.signingKeyId);
      const evidence = await seedT0ObservationIds(seeded.operationId);

      const ports = createMoveAdvancedPorts(makeDeps(seeded.nodeId));
      const bound = await ports.loadBaselineBound!(seeded.operationId);

      expect(bound).not.toBeNull();
      if (bound === null) return;
      expect(bound.capture.sourceBaseline).toEqual(GENESIS_PROJECTION);
      expect(bound.capture.destinationBaseline).not.toEqual(GENESIS_PROJECTION);
      expect(bound.sourceT0ObservationId).toBe(evidence.s);
      expect(bound.destinationT0ObservationId).toBe(evidence.d);
    },
  );

  it(
    "loadBaselineBound: VERIFIED_HEAD source / VERIFIED_HEAD destination reloads both wallets' re-verified projections and resumes the same T0 attempt",
    async () => {
      const seeded = await seedMoveOperation(
        true,
        { sourcePublicKey: WALLET_SENDER_PUBLIC_KEY, destinationPublicKey: WALLET_RECEIVER_PUBLIC_KEY },
        {
          source: {
            kind: "HEAD",
            walletRole: "sender",
            bodyText: WALLET_SETTLED_TRANSACTION_TEXT,
            bodySha256: WALLET_SETTLED_TRANSACTION_SHA256,
          },
          destination: {
            kind: "HEAD",
            walletRole: "receiver",
            bodyText: WALLET_SETTLED_TRANSACTION_TEXT,
            bodySha256: WALLET_SETTLED_TRANSACTION_SHA256,
          },
        },
      );
      await seedExpectedArtifact(seeded.operationId, seeded.signingKeyId);
      const evidence = await seedT0ObservationIds(seeded.operationId);

      const ports = createMoveAdvancedPorts(makeDeps(seeded.nodeId));
      const bound = await ports.loadBaselineBound!(seeded.operationId);

      expect(bound).not.toBeNull();
      if (bound === null) return;
      expect(bound.capture.sourceBaseline).not.toEqual(GENESIS_PROJECTION);
      expect(bound.capture.destinationBaseline).not.toEqual(GENESIS_PROJECTION);
      expect(bound.sourceT0ObservationId).toBe(evidence.s);
      expect(bound.destinationT0ObservationId).toBe(evidence.d);
    },
  );

  it(
    "loadBaselineBound: a CORRUPT (non-genesis/non-head) T0 parse_result throws a typed 'unreconstructable' error instead of returning null — never collapses to unbounded WAIT",
    async () => {
      const seeded = await seedMoveOperation(true, undefined, { source: { kind: "CORRUPT" } });
      await seedExpectedArtifact(seeded.operationId, seeded.signingKeyId);

      const ports = createMoveAdvancedPorts(makeDeps(seeded.nodeId));
      await expect(ports.loadBaselineBound!(seeded.operationId)).rejects.toThrow(/unreconstructable/);
    },
  );
  // Prior to this ticket, createMoveAdvancedPorts wired createNoopSignerAuditLog for
  // auditLog (see history at apps/generic-node/src/money-workers/send-signer-deps.ts), so
  // every MOVE signUnderLeases call — success or rejection — left zero rows in signer_audit
  // regardless of whether the vault was actually invoked. Boot recovery's signer_audit_present
  // check (createSqlBootRecovery, SQL_LIST_NONTERMINAL_OPS) was therefore always false for
  // MOVE_INTERNAL operations, which made "signer never called" and "call occurred before
  // signature persistence" indistinguishable for this operation kind. This
  // suite drives createMoveAdvancedPorts's real signUnderLeases against a real vault + real
  // Postgres and proves the durable row now lands and boot recovery observes it.
  describe("signer_audit — MOVE production wiring (real PG)", () => {
    async function seedMoveForSigning(): Promise<{
      readonly nodeId: string;
      readonly operationId: string;
      readonly sourceWalletId: string;
      readonly destinationWalletId: string;
      readonly leaseGroupId: string;
      readonly vault: EncryptedWalletKeyStore;
    }> {
      const nodeId = randomUUID();
      const implementerId = randomUUID();
      const operationId = randomUUID();
      const sourceWalletId = randomUUID();
      const destinationWalletId = randomUUID();
      const destinationId = randomUUID();
      const leaseGroupId = randomUUID();
      const sourceSeed = randomBytes(32);
      const destinationSeed = randomBytes(32);
      const sourcePublicKey = publicKeyFromSeed(sourceSeed);
      const destinationPublicKey = publicKeyFromSeed(destinationSeed);

      await ensureNodeRow(pool, {
        nodeId,
        displayName: "fixture-move-signer-audit",
        identityPublicKey: publicKeyFromSeed(randomBytes(32)),
      });
      await pool.query(
        `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-impl', now())`,
        [implementerId],
      );
      await pool.query(
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
         VALUES ($1::uuid, $3::uuid, $2, 'node_generated', 'AVAILABLE')`,
        [sourceWalletId, sourcePublicKey, nodeId],
      );
      await pool.query(
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
         VALUES ($1::uuid, $3::uuid, $2, 'node_generated', 'AVAILABLE')`,
        [destinationWalletId, destinationPublicKey, nodeId],
      );
      // lease_foundation_reject_ineligible_lease (lease-foundation.sql) refuses the
      // wallet_active_leases INSERT itself for MOVE_DESTINATION unless the destination is
      // recovery-verified and BLESSED — this is a DB-level gate seedActiveLease cannot bypass,
      // not a reconcileAndLand admission check. Same seeding as seedMoveOperation above.
      const destRecoveryLiveDb = createSqlRecoveryLiveDatabase({
        sql: {
          query: async <R>(text: string, params: readonly unknown[]) => {
            const result = await pool.query(text, params as never);
            return { rows: result.rows as R[] };
          },
        },
        nodeId,
        proveCurrentKeyPossession: async () => true,
      });
      const destRecoveryPreimage = `fixture-move-signer-audit-recovery|${destinationWalletId}`;
      await destRecoveryLiveDb.stampRecoveryVerification({
        ceremonyId: randomUUID(),
        walletId: destinationWalletId,
        method: "AUDITED_EXPORT",
        publicKey: destinationPublicKey,
        keyVersion: 1,
        exportId: randomUUID(),
        exportSha256: sha256HexOfText(destRecoveryPreimage),
        censusMatchedRestored: true,
        censusMatchedLive: true,
        archivedProofVerified: true,
        probePreimageSha256: sha256HexOfText(`${destRecoveryPreimage}-probe`),
        probeSignature: STUB_SIGNATURE,
        probeVerified: true,
        verifierIdentity: "fixture-offline-stamp-seam",
      });
      await pool.query(
        `INSERT INTO destinations (id, node_id, wallet_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
        [destinationId, nodeId, destinationWalletId],
      );
      const blessingArtifactId = randomUUID();
      const blessingPreimageText = `fixture-move-signer-audit-bless|${destinationId}`;
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
          destinationId,
          destinationWalletId,
          destinationPublicKey,
          randomUUID(),
          issuedAt.toISOString(),
          expiresAt.toISOString(),
          STUB_SIGNATURE,
          blessingPreimageText,
          sha256HexOfText(blessingPreimageText),
        ],
      );
      await pool.query(
        `UPDATE destinations
            SET state = 'BLESSED', blessed_at = now(),
                blessed_by_device_key_id = $2::uuid, blessing_artifact_id = $3::uuid
          WHERE id = $1::uuid`,
        [destinationId, randomUUID(), blessingArtifactId],
      );
      await pool.query(
        `INSERT INTO operations (
           id, node_id, implementer_id, kind, status, amount_zkz,
           source_wallet_id, destination_id, idempotency_key, request_sha256)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'MOVE_INTERNAL', 'CREATED', $4,
                 $5::uuid, $6::uuid, $7, $8)`,
        [
          operationId, nodeId, implementerId, "1.0", sourceWalletId, destinationId,
          `idem-${operationId}`, sha256HexOfText(operationId),
        ],
      );
      await pool.query(
        `INSERT INTO lease_groups (id, root_operation_id, created_at) VALUES ($1::uuid, $2::uuid, now())`,
        [leaseGroupId, operationId],
      );
      const innerPreimageText = JSON.stringify({ stub: "fixture-move-inner", operationId });
      await insertTransactionAttempt(query, {
        operationId,
        innerPreimageText,
        innerSha256: sha256HexOfText(innerPreimageText),
        formedAt: new Date().toISOString(),
      });

      const vault = new EncryptedWalletKeyStore({
        rootKey: deriveRootKey(VAULT_MASTER, VAULT_ROOT_KDF_SALT),
        store: new VaultSqlStore(pool),
        auditLog: new InMemoryVaultAccessAuditLog(),
      });
      await vault.seal(
        { nodeId, walletId: sourceWalletId, keyVersion: 1, publicKey: sourcePublicKey, keyOrigin: "node_generated" },
        sealedSecret64FromSeed(sourceSeed),
      );
      await vault.seal(
        {
          nodeId, walletId: destinationWalletId, keyVersion: 1,
          publicKey: destinationPublicKey, keyOrigin: "node_generated",
        },
        sealedSecret64FromSeed(destinationSeed),
      );

      return { nodeId, operationId, sourceWalletId, destinationWalletId, leaseGroupId, vault };
    }

    const readAudit = async (operationId: string): Promise<readonly Record<string, unknown>[]> =>
      query(
        `SELECT node_id::text AS node_id, outcome, purpose, lease_epoch::text AS lease_epoch,
                preimage_sha256
           FROM signer_audit WHERE operation_id = $1 ORDER BY called_at`,
        [operationId],
      );

    it(
      "SIGNED: signUnderLeases writes a SUCCEEDED row per leg, and boot recovery observes the call",
      async () => {
        const seeded = await seedMoveForSigning();
        const { vault } = seeded;

        // Never called yet: boot recovery must not report a call that has not happened.
        const before = await createSqlBootRecovery(pool, logger).store.listNonterminalOperations();
        expect(before.find((o) => o.operationId === seeded.operationId)?.signerAuditIndicatesCall).toBe(false);

        await seedActiveLease({
          leaseGroupId: seeded.leaseGroupId, operationId: seeded.operationId,
          walletId: seeded.sourceWalletId, leaseRole: "MOVE_SOURCE",
        });
        await seedActiveLease({
          leaseGroupId: seeded.leaseGroupId, operationId: seeded.operationId,
          walletId: seeded.destinationWalletId, leaseRole: "MOVE_DESTINATION",
        });

        const ports = createMoveAdvancedPorts(makeDeps(seeded.nodeId, { vault }));
        const result = await ports.signUnderLeases!(seeded.operationId, {
          sourceWalletId: seeded.sourceWalletId,
          sourceLeaseEpoch: 1n,
          destinationWalletId: seeded.destinationWalletId,
          destinationLeaseEpoch: 1n,
        });
        expect(result.ok, JSON.stringify(result)).toBe(true);

        const audit = await readAudit(seeded.operationId);
        expect(audit).toHaveLength(2);
        expect(audit[0]).toMatchObject({ node_id: seeded.nodeId, outcome: "SUCCEEDED", purpose: "STEP_1", lease_epoch: "1" });
        expect(audit[1]).toMatchObject({ node_id: seeded.nodeId, outcome: "SUCCEEDED", purpose: "STEP_2", lease_epoch: "1" });

        // Called-before-persist is now provable through the same signer_audit_present check
        // recovery already trusted for RECEIVE — no boot-recovery code changed, only the
        // production wiring that used to leave this row unwritten for MOVE.
        const after = await createSqlBootRecovery(pool, logger).store.listNonterminalOperations();
        expect(after.find((o) => o.operationId === seeded.operationId)?.signerAuditIndicatesCall).toBe(true);
      },
    );

    it(
      "REJECTED: signing with no active lease writes a FAILED row instead of silently dropping the attempt",
      async () => {
        const seeded = await seedMoveForSigning();
        const { vault } = seeded;
        // Deliberately no seedActiveLease calls — validateLease reads back "no active lease".

        const ports = createMoveAdvancedPorts(makeDeps(seeded.nodeId, { vault }));
        const result = await ports.signUnderLeases!(seeded.operationId, {
          sourceWalletId: seeded.sourceWalletId,
          sourceLeaseEpoch: 1n,
          destinationWalletId: seeded.destinationWalletId,
          destinationLeaseEpoch: 1n,
        });
        expect(result.ok).toBe(false);

        const audit = await readAudit(seeded.operationId);
        expect(audit).toHaveLength(1);
        expect(audit[0]).toMatchObject({ node_id: seeded.nodeId, outcome: "FAILED", purpose: "STEP_1" });

        // A rejected signer call is still a call: recovery must see it, not just successes.
        const after = await createSqlBootRecovery(pool, logger).store.listNonterminalOperations();
        expect(after.find((o) => o.operationId === seeded.operationId)?.signerAuditIndicatesCall).toBe(true);
      },
    );
  });
});
