// ZTR-1160 — lease FOR UPDATE held across vault sign + SIGNED audit.
//
// Proves the production wiring (createSqlSignUnderLeaseTransaction + signUnderLease)
// closes the TOCTOU window where autocommit FOR SHARE released before the signature
// existed. A concurrent release that takes the same row FOR UPDATE blocks until the
// sign transaction commits with a durable signer_audit row — or the sign is refused.
//
// Connectivity: TEST_DATABASE_URL from vitest.global-setup (root / package project).
// registerPgRequiredGuard fails PG_REQUIRED=1 runs that would otherwise silently skip.

import { createHash, createPrivateKey, createPublicKey, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import {
  createMoneySignerBoundaryDeps,
  createSqlSignerAuditLog,
  deriveRootKey,
  EncryptedWalletKeyStore,
  InMemoryVaultAccessAuditLog,
  LEASE_STATEMENTS,
  migrateLeaseFoundation,
  signUnderLease,
  VaultSqlStore,
  type SignerBoundaryDeps,
  type SqlQueryFn,
  type VaultSigner,
} from "@zucoins/node-core";

import { registerPgRequiredGuard } from "../../../packages/node-core/test/pg-required-guard.ts";
import { ensureNodeRow } from "../src/bootstrap/genesis.js";
import { publicKeyFromSeed } from "../src/ops/ed25519-ops.js";
import {
  createSqlLeaseReader,
  createSqlSignUnderLeaseTransaction,
} from "../src/money-workers/send-signer-deps.js";
import { createPoolVaultSigner } from "../src/money-workers/send-vault-signer.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const databaseUrl = process.env.TEST_DATABASE_URL;
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const VAULT_MASTER = "sign-toctou-master-key!!!!!!!!!!!!!!!!";
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Set only at the END of a successful beforeAll — registerPgRequiredGuard reads it. */
let suiteReady = false;

function sha256HexOfText(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function sealedSecret64FromSeed(seed: Buffer): Buffer {
  const priv = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(priv).export({ type: "spki", format: "der" });
  return Buffer.concat([seed, Buffer.from(spki).subarray(-32)]);
}

const describeLive = databaseUrl ? describe : describe.skip;

describeLive("signUnderLease TOCTOU — lease FOR UPDATE across vault + audit (ZTR-1160)", () => {
  let pool: Pool;
  let prevDatabaseUrl: string | undefined;

  beforeAll(async () => {
    if (!databaseUrl) return;
    pool = new Pool({ connectionString: databaseUrl, max: 8 });
    prevDatabaseUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = databaseUrl;
    const { runMigrationsOnPool } = await import("../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl });
    await migrateLeaseFoundation({
      query: async <R>(text: string, params?: readonly unknown[]) => {
        const result = await pool.query(text, params as never);
        return { rows: result.rows as R[], rowCount: result.rowCount };
      },
    });
    suiteReady = true;
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    await pool?.end().catch(() => {});
    if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = prevDatabaseUrl;
  }, PG_TEST_TIMEOUT_MS);

  const query: SqlQueryFn = async (text, values) => {
    const result = await pool.query(text, values as never[]);
    return result.rows as readonly Record<string, unknown>[];
  };

  function productionDeps(
    nodeId: string,
    vault: EncryptedWalletKeyStore,
    vaultSigner?: VaultSigner,
  ): SignerBoundaryDeps {
    return createMoneySignerBoundaryDeps(
      {
        leadership: { held: true },
        leaseReader: createSqlLeaseReader(pool),
        vaultSigner:
          vaultSigner ?? createPoolVaultSigner({ pool, vault, nodeId }),
        auditLog: createSqlSignerAuditLog(query),
        withSignTransaction: createSqlSignUnderLeaseTransaction(pool),
      },
      {
        assertMoneyAdmitted: () => {},
        assertCanOperate: () => {},
        assertWalletMaySign: () => {},
      },
    );
  }

  async function seedSendForSigning(): Promise<{
    readonly nodeId: string;
    readonly operationId: string;
    readonly walletId: string;
    readonly leaseGroupId: string;
    readonly vault: EncryptedWalletKeyStore;
  }> {
    const nodeId = randomUUID();
    const implementerId = randomUUID();
    const operationId = randomUUID();
    const walletId = randomUUID();
    const leaseGroupId = randomUUID();
    const seed = randomBytes(32);
    const publicKey = publicKeyFromSeed(seed);

    await ensureNodeRow(pool, {
      nodeId,
      displayName: "fixture-sign-toctou",
      identityPublicKey: publicKeyFromSeed(randomBytes(32)),
    });
    await pool.query(
      `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-toctou-impl', now())`,
      [implementerId],
    );
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ($1::uuid, $3::uuid, $2, 'node_generated', 'PINNED')`,
      [walletId, publicKey, nodeId],
    );
    const destinationAddress = publicKeyFromSeed(randomBytes(32));
    await pool.query(
      `INSERT INTO operations (
         id, node_id, implementer_id, kind, status, amount_zkz,
         source_wallet_id, destination_address, idempotency_key, request_sha256, formation_state)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'SEND_EXTERNAL', 'APPROVED', '1.0',
               $4::uuid, $5, $6, $7, 'SIGNING_CLAIMED')`,
      [
        operationId,
        nodeId,
        implementerId,
        walletId,
        destinationAddress,
        `idem-${operationId}`,
        sha256HexOfText(operationId),
      ],
    );
    await pool.query(
      `INSERT INTO lease_groups (id, root_operation_id, created_at) VALUES ($1::uuid, $2::uuid, now())`,
      [leaseGroupId, operationId],
    );

    const vault = new EncryptedWalletKeyStore({
      rootKey: deriveRootKey(VAULT_MASTER, VAULT_ROOT_KDF_SALT),
      store: new VaultSqlStore(pool),
      auditLog: new InMemoryVaultAccessAuditLog(),
    });
    await vault.seal(
      { nodeId, walletId, keyVersion: 1, publicKey, keyOrigin: "node_generated" },
      sealedSecret64FromSeed(seed),
    );

    return { nodeId, operationId, walletId, leaseGroupId, vault };
  }

  async function seedActiveSendSourceLease(params: {
    readonly leaseGroupId: string;
    readonly operationId: string;
    readonly walletId: string;
  }): Promise<void> {
    const membershipId = randomUUID();
    const acquiredAt = new Date().toISOString();
    await pool.query(LEASE_STATEMENTS.INSERT_MEMBERSHIP, [
      membershipId,
      params.leaseGroupId,
      params.walletId,
      params.operationId,
      "SEND_SOURCE",
      1,
      acquiredAt,
    ]);
    await pool.query(LEASE_STATEMENTS.INSERT_ACTIVE, [
      params.walletId,
      membershipId,
      params.leaseGroupId,
      params.operationId,
      params.operationId,
      "SEND_SOURCE",
      1,
      acquiredAt,
      acquiredAt,
      randomUUID(),
    ]);
  }

  it(
    "concurrent release blocks on FOR UPDATE until SIGNED audit is committed",
    async () => {
      const seeded = await seedSendForSigning();
      await seedActiveSendSourceLease(seeded);

      let resolveVault!: (sig: string) => void;
      const vaultHeld = new Promise<string>((resolve) => {
        resolveVault = resolve;
      });
      let vaultEntered = false;
      const slowVault: VaultSigner = {
        async sign() {
          vaultEntered = true;
          return vaultHeld;
        },
      };
      const deps = productionDeps(seeded.nodeId, seeded.vault, slowVault);

      const preimageText = JSON.stringify({ stub: "toctou", operationId: seeded.operationId });
      const signPromise = signUnderLease(deps, {
        walletId: seeded.walletId,
        operationId: seeded.operationId,
        leaseEpoch: 1n,
        purpose: "SPLITCHAIN_STEP_1",
        preimageText,
        expectedPreimageSha256: sha256HexOfText(preimageText),
      });

      // Wait until the sign path has taken FOR UPDATE and reached the vault.
      for (let i = 0; i < 200 && !vaultEntered; i += 1) {
        await new Promise((r) => setTimeout(r, 10));
      }
      expect(vaultEntered).toBe(true);

      // Release path: same FOR UPDATE the production release repository uses.
      // With the sign transaction holding the row, this must block until we finish signing.
      const releaseClient = await pool.connect();
      let releaseDone = false;
      let releaseError: unknown;
      const releasePromise = (async () => {
        try {
          await releaseClient.query("BEGIN");
          await releaseClient.query(
            `SELECT wallet_id FROM wallet_active_leases WHERE wallet_id = $1::uuid FOR UPDATE`,
            [seeded.walletId],
          );
          await releaseClient.query(
            `DELETE FROM wallet_active_leases WHERE wallet_id = $1::uuid`,
            [seeded.walletId],
          );
          await releaseClient.query("COMMIT");
          releaseDone = true;
        } catch (err) {
          releaseError = err;
          try {
            await releaseClient.query("ROLLBACK");
          } catch {
            /* ignore */
          }
        } finally {
          releaseClient.release();
        }
      })();

      // Give the release a moment to block on the row lock — it must NOT have finished.
      await new Promise((r) => setTimeout(r, 150));
      expect(releaseDone).toBe(false);
      expect(releaseError).toBeUndefined();

      // While the lock is held, no SIGNED audit yet (audit lands before COMMIT).
      const midAudit = await pool.query(
        `SELECT outcome FROM signer_audit WHERE operation_id = $1::uuid`,
        [seeded.operationId],
      );
      expect(midAudit.rows).toHaveLength(0);

      // Complete the vault; sign tx commits audit + releases FOR UPDATE.
      resolveVault("c2lnbmF0dXJlLWJ5dGVz");
      const signed = await signPromise;
      expect(signed.signature).toBe("c2lnbmF0dXJlLWJ5dGVz");

      await releasePromise;
      expect(releaseError).toBeUndefined();
      expect(releaseDone).toBe(true);

      // SIGNED audit is durable; lease is gone only after the sign committed.
      const audit = await pool.query(
        `SELECT outcome FROM signer_audit WHERE operation_id = $1::uuid ORDER BY called_at`,
        [seeded.operationId],
      );
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0]?.outcome).toBe("SUCCEEDED");

      const leases = await pool.query(
        `SELECT 1 FROM wallet_active_leases WHERE wallet_id = $1::uuid`,
        [seeded.walletId],
      );
      expect(leases.rows).toHaveLength(0);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "REJECTED path commits FAILED audit and does not deadlock against a concurrent release",
    async () => {
      const seeded = await seedSendForSigning();
      // No active lease — validateLease rejects immediately under FOR UPDATE (empty).
      const deps = productionDeps(seeded.nodeId, seeded.vault);
      const preimageText = JSON.stringify({ stub: "reject", operationId: seeded.operationId });

      await expect(
        signUnderLease(deps, {
          walletId: seeded.walletId,
          operationId: seeded.operationId,
          leaseEpoch: 1n,
          purpose: "SPLITCHAIN_STEP_1",
          preimageText,
          expectedPreimageSha256: sha256HexOfText(preimageText),
        }),
      ).rejects.toThrow(/no active lease/);

      const audit = await pool.query(
        `SELECT outcome FROM signer_audit WHERE operation_id = $1::uuid`,
        [seeded.operationId],
      );
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0]?.outcome).toBe("FAILED");
    },
    PG_TEST_TIMEOUT_MS,
  );

  it("SELECT uses FOR UPDATE (not FOR SHARE) in the production lease reader SQL", () => {
    // Static proof the wiring cannot silently regress to FOR SHARE on the SELECT.
    // Comments may still name FOR SHARE when describing the pre-fix defect.
    const source = readFileSync(
      fileURLToPath(new URL("../src/money-workers/send-signer-deps.ts", import.meta.url)),
      "utf8",
    );
    expect(source).toMatch(/SELECT_ACTIVE_LEASE_FOR_UPDATE[\s\S]*FOR UPDATE`/);
    // No SQL lock mode other than FOR UPDATE on the active-lease SELECT.
    const sqlBlocks = source.match(/`[^`]*wallet_active_leases[^`]*`/g) ?? [];
    expect(sqlBlocks.length).toBeGreaterThan(0);
    for (const block of sqlBlocks) {
      expect(block).toMatch(/FOR UPDATE/);
      expect(block).not.toMatch(/FOR SHARE/);
    }
  });
});

registerPgRequiredGuard({
  name: "sign-under-lease-toctou.pg",
  databaseUrl,
  isReady: () => suiteReady,
});
