// MOVE_INTERNAL dual signing against a real PostgreSQL server.
//
// The unit suite proves the ceremony's ordering against a modelled ladder. This one proves the
// two properties a model cannot: that the frozen CHECK constraints — not application code —
// refuse an out-of-order write, and that the exact preimage bytes survive a round trip through
// `text` columns and come back byte-identical (a `jsonb` column, or any re-serializing driver
// path, would fail this and pass a shape assertion).
//
// The DDL applied is the frozen contract text of src/schema/transaction-material.sql, verbatim,
// plus a wallet_active_leases projection matching custody-eligibility columns so the
// AttemptLeaseGuard CTE has a real relation to lock (the full lease-foundation pack
// pulls wallets/destinations eligibility triggers this suite does not need).
// psql runs as a child process, keeping the in-process network-containment guard intact,
// exactly as transaction-material-store.pg.test.ts does.

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  resumeMoveStep2FromPersistedStep1,
  signMoveStepsUnderLeases,
  type MoveHeldLease,
} from "../src/core/move-form-and-sign.ts";
import { advanceAttemptPhase } from "../src/core/transaction-material-store.ts";
import { hashMovePreimageText } from "../src/core/move-step2.ts";
import {
  type ActiveLeaseRecord,
  type SignerBoundaryDeps,
} from "../src/core/signer-boundary.ts";
import type { SqlQueryFn } from "../src/core/sql-query-fn.ts";
import { TRANSACTION_MATERIAL_SCHEMA_FILE } from "../src/schema/transaction-material.contract.ts";
import {
  NON_ASCII_INNER_PREIMAGE_SHA256,
  NON_ASCII_INNER_PREIMAGE_TEXT,
  WALLET_INNER_PREIMAGE_SHA256,
  WALLET_INNER_PREIMAGE_TEXT,
  WALLET_SETTLED_TRANSACTION_TEXT,
  WALLET_STEP_1_SIGNATURE,
  WALLET_STEP_2_PREIMAGE_TEXT,
  WALLET_STEP_2_SIGNATURE,
} from "./fixtures/splitchain-v2-byte-evidence.ts";

const here = dirname(fileURLToPath(import.meta.url));
const contractSql = readFileSync(
  resolve(here, "../src/schema", TRANSACTION_MATERIAL_SCHEMA_FILE),
  "utf8",
);

const SCHEMA = "move_form_and_sign_move_dual_signing";
const CHECK_VIOLATION = "23514";
const databaseUrl = process.env.TEST_DATABASE_URL;

const SOURCE_WALLET = "22222222-2222-4222-8222-222222222222";
const DESTINATION_WALLET = "33333333-3333-4333-8333-333333333333";
const SOURCE_LEASE: MoveHeldLease = { walletId: SOURCE_WALLET, leaseEpoch: 7n };
const DESTINATION_LEASE: MoveHeldLease = { walletId: DESTINATION_WALLET, leaseEpoch: 9n };
const OWNER_INSTANCE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

/** Minimal active-lease projection — columns the AttemptLeaseGuard CTE reads + locks. */
const WALLET_ACTIVE_LEASES_DDL = `
CREATE TABLE wallet_active_leases (
  wallet_id uuid PRIMARY KEY,
  membership_id uuid NOT NULL UNIQUE,
  lease_group_id uuid NOT NULL,
  root_operation_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  lease_role text NOT NULL
    CHECK (lease_role IN (
      'RECEIVE_WINDOW',
      'MOVE_SOURCE',
      'MOVE_DESTINATION',
      'SEND_SOURCE',
      'RECONCILIATION'
    )),
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  acquired_at timestamptz NOT NULL,
  heartbeat_at timestamptz NOT NULL,
  owner_instance_id uuid NOT NULL,
  release_not_before timestamptz,
  UNIQUE (operation_id, wallet_id),
  UNIQUE (lease_group_id, wallet_id)
);
`;

const pgEnv = (): NodeJS.ProcessEnv => {
  const url = new URL(databaseUrl as string);
  return {
    ...process.env,
    PGHOST: url.hostname,
    PGPORT: url.port || "5432",
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
    PGDATABASE: url.pathname.replace(/^\//, ""),
  };
};

interface PsqlResult {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}

// Test-only stand-in for a driver's parameter binding: psql has no wire parameters, so each $n
// becomes a psql variable reference, which psql quotes and escapes. Byte values therefore reach
// the server through psql's own quoting, never through string concatenation in this file.
function psql(sql: string, values: readonly unknown[] = []): Promise<PsqlResult> {
  const args = ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose"];
  values.forEach((value, index) => {
    if (value !== null && value !== undefined) {
      args.push("-v", `p${index + 1}=${String(value)}`);
    }
  });
  args.push("-f", "-");
  const bound = sql.replace(/\$(\d+)/g, (_match, position: string) => {
    const value = values[Number(position) - 1];
    return value === null || value === undefined ? "NULL" : `:'p${position}'`;
  });
  return new Promise((settle, fail) => {
    const child = spawn("psql", args, { env: pgEnv(), stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", fail);
    child.on("close", (code) => settle({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(`${sql.trimEnd().endsWith(";") ? bound : `${bound};`}\n`);
  });
}

async function psqlOk(sql: string, values: readonly unknown[] = []): Promise<string> {
  const result = await psql(sql, values);
  if (result.code !== 0) throw new Error(result.stderr.trim());
  return result.stdout;
}

const inSchema = (sql: string): string => `SET search_path TO ${SCHEMA};\n${sql}`;

const query: SqlQueryFn = async (text, values) => {
  const wrapped = `WITH q AS (${text}) SELECT coalesce(json_agg(row_to_json(q)), '[]'::json) FROM q`;
  const stdout = await psqlOk(inSchema(wrapped), values);
  const line = stdout.trim().split("\n").filter(Boolean).at(-1) ?? "[]";
  return JSON.parse(line) as Record<string, unknown>[];
};

/** Runs a statement expected to be REJECTED, returning its SQLSTATE. */
async function rejected(sql: string, values: readonly unknown[] = []): Promise<string> {
  const result = await psql(inSchema(sql), values);
  expect(result.code, `statement should have been rejected: ${sql}`).not.toBe(0);
  return /ERROR:\s+(\d{5}):/.exec(result.stderr)?.[1] ?? "";
}

// ── signer fake (no key material; the vault seam returns captured signature bytes) ───────────

const lease = (
  walletId: string,
  operationId: string,
  role: ActiveLeaseRecord["role"],
  epoch: bigint,
  overrides: Partial<ActiveLeaseRecord> = {},
): ActiveLeaseRecord => ({ walletId, operationId, epoch, role, lifecycle: "ACTIVE", ...overrides });

function makeSigner(
  operationId: string,
  options: {
    readonly destinationLease?: ActiveLeaseRecord | null;
    /** Signatures returned in call order; a resume signs step 2 on its FIRST call. */
    readonly signatures?: readonly string[];
  } = {},
) {
  const signed: Array<{ walletId: string; preimage: string }> = [];
  const signatures = options.signatures ?? [WALLET_STEP_1_SIGNATURE, WALLET_STEP_2_SIGNATURE];
  const leases: Record<string, ActiveLeaseRecord | null> = {
    [SOURCE_WALLET]: lease(SOURCE_WALLET, operationId, "MOVE_SOURCE", 7n),
    [DESTINATION_WALLET]:
      options.destinationLease === undefined
        ? lease(DESTINATION_WALLET, operationId, "MOVE_DESTINATION", 9n)
        : options.destinationLease,
  };
  const deps: SignerBoundaryDeps & {
    assertHaltAdmitsKind: (kind: string) => void;
  } = {
    leadership: { held: true },
    leaseReader: { readActiveLease: async (walletId: string) => leases[walletId] ?? null },
    vaultSigner: {
      sign: async (walletId: string, bytes: Uint8Array) => {
        signed.push({ walletId, preimage: new TextDecoder().decode(bytes) });
        const next = signatures[signed.length - 1];
        if (next === undefined) throw new Error("signer fake ran out of scripted signatures");
        return next;
      },
    },
    auditLog: { append: async () => undefined },
    now: () => "2026-07-27T00:00:00.000Z",
    assertMoneyAdmitted: () => {},
    assertCanOperate: () => {},
    assertWalletMaySign: async () => {},
    assertHaltAdmitsKind: () => {},
  };
  return { deps, signed };
}

let reachable = false;

/** Seeds one operation and its attempt row at INNER_PREIMAGE_PERSISTED (output). */
async function seedAttempt(
  innerText = WALLET_INNER_PREIMAGE_TEXT,
  innerSha = WALLET_INNER_PREIMAGE_SHA256,
): Promise<string> {
  const operationId = randomUUID();
  await psqlOk(inSchema(`INSERT INTO operations (id) VALUES ('${operationId}')`));
  await psqlOk(
    inSchema(
      `INSERT INTO operation_transactions
         (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256, formed_at)
       VALUES ($1, 1, 'INNER_PREIMAGE_PERSISTED', $2, $3, now())`,
    ),
    [operationId, innerText, innerSha],
  );
  // Signature advances re-check the held lease under FOR SHARE. Plant both legs.
  await seedHeldLeases(operationId);
  return operationId;
}

async function seedHeldLeases(operationId: string): Promise<void> {
  // wallet_active_leases is PK'd on wallet_id alone (One-in-flight). A second seedAttempt in the
  // same test (e.g. the resume byte-drift pair) must replace, not collide.
  await psqlOk(
    inSchema(
      `DELETE FROM wallet_active_leases
        WHERE wallet_id IN ($1::uuid, $2::uuid)`,
    ),
    [SOURCE_WALLET, DESTINATION_WALLET],
  );
  const groupId = randomUUID();
  const sourceMembership = randomUUID();
  const destMembership = randomUUID();
  await psqlOk(
    inSchema(
      `INSERT INTO wallet_active_leases
         (wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
          lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
       VALUES
         ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $4::uuid,
          'MOVE_SOURCE', 7, now(), now(), $5::uuid),
         ($6::uuid, $7::uuid, $3::uuid, $4::uuid, $4::uuid,
          'MOVE_DESTINATION', 9, now(), now(), $5::uuid)`,
    ),
    [
      SOURCE_WALLET,
      sourceMembership,
      groupId,
      operationId,
      OWNER_INSTANCE,
      DESTINATION_WALLET,
      destMembership,
    ],
  );
}

async function releaseWalletLease(walletId: string): Promise<void> {
  await psqlOk(inSchema(`DELETE FROM wallet_active_leases WHERE wallet_id = $1::uuid`), [
    walletId,
  ]);
}

async function countLeases(walletId: string): Promise<number> {
  const rows = await query(
    `SELECT count(*)::int AS n FROM wallet_active_leases WHERE wallet_id = $1`,
    [walletId],
  );
  return Number(rows[0]?.n ?? 0);
}

const readAttempt = async (operationId: string): Promise<Record<string, unknown>> => {
  const rows = await query(
    `SELECT attempt_phase, inner_preimage_text, step_1_signature, step_2_preimage_text,
            step_2_preimage_sha256, step_2_signature, completed_transaction_text,
            completed_transaction_sha256
       FROM operation_transactions WHERE operation_id = $1 AND attempt_no = 1`,
    [operationId],
  );
  const row = rows[0];
  if (row === undefined) throw new Error(`no attempt row for ${operationId}`);
  return row;
};

describe.skipIf(databaseUrl === undefined)(
  "operation-flow MOVE_INTERNAL dual signing against a live PostgreSQL",
  () => {
    beforeAll(async () => {
      await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
      await psqlOk(
        inSchema(
          // Exactly the columns's FKs reference; the frozen contract text supplies the rest.
          `CREATE TABLE operations (id uuid PRIMARY KEY);
           CREATE TABLE operation_approvals (id uuid PRIMARY KEY);
           CREATE TABLE wallets (id uuid PRIMARY KEY);
           INSERT INTO wallets (id) VALUES ('${SOURCE_WALLET}'), ('${DESTINATION_WALLET}');
           ${contractSql}
           ${WALLET_ACTIVE_LEASES_DDL}`,
        ),
      );
      reachable = true;
    });

    afterAll(async () => {
      if (reachable) await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE;`);
    });

    afterEach(async () => {
      if (!reachable) return;
      await psqlOk(inSchema(`DELETE FROM wallet_active_leases`));
      await psqlOk(inSchema(`DELETE FROM operation_transactions`));
      await psqlOk(inSchema(`DELETE FROM operations`));
    });

    it("walks the frozen phase ladder and leaves both signatures durable", async () => {
      const operationId = await seedAttempt();
      const signer = makeSigner(operationId);

      await signMoveStepsUnderLeases({
        operationId,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query,
        signerDeps: signer.deps,
      });

      const row = await readAttempt(operationId);
      expect(row.attempt_phase).toBe("STEP2_SIGNATURE_PERSISTED");
      expect(row.step_1_signature).toBe(WALLET_STEP_1_SIGNATURE);
      expect(row.step_2_signature).toBe(WALLET_STEP_2_SIGNATURE);
      expect(signer.signed.map((call) => call.walletId)).toEqual([
        SOURCE_WALLET,
        DESTINATION_WALLET,
      ]);
    });

    it("returns the exact preimage bytes out of the database, byte-for-byte", async () => {
      const operationId = await seedAttempt();
      await signMoveStepsUnderLeases({
        operationId,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query,
        signerDeps: makeSigner(operationId).deps,
      });

      const row = await readAttempt(operationId);
      // Round trip through the server: what came back is the wallet's own captured bytes.
      expect(row.inner_preimage_text).toBe(WALLET_INNER_PREIMAGE_TEXT);
      expect(row.step_2_preimage_text).toBe(WALLET_STEP_2_PREIMAGE_TEXT);
      expect(row.completed_transaction_text).toBe(WALLET_SETTLED_TRANSACTION_TEXT);
      // Digests recomputed from what the SERVER returned, not from what we sent.
      expect(row.step_2_preimage_sha256).toBe(
        hashMovePreimageText(row.step_2_preimage_text as string),
      );
      expect(row.completed_transaction_sha256).toBe(
        hashMovePreimageText(row.completed_transaction_text as string),
      );
      // Byte length as well as string equality: a normalizing column fails this.
      expect(Buffer.byteLength(row.step_2_preimage_text as string, "utf8")).toBe(
        Buffer.byteLength(WALLET_STEP_2_PREIMAGE_TEXT, "utf8"),
      );
    });

    it("preserves multi-byte UTF-8 in the signed preimage across the column", async () => {
      const operationId = await seedAttempt(
        NON_ASCII_INNER_PREIMAGE_TEXT,
        NON_ASCII_INNER_PREIMAGE_SHA256,
      );
      const signer = makeSigner(operationId);
      await signMoveStepsUnderLeases({
        operationId,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query,
        signerDeps: signer.deps,
      });

      const row = await readAttempt(operationId);
      // The bytes the destination signer saw are exactly the bytes the column now holds.
      expect(row.step_2_preimage_text).toBe(signer.signed[1]!.preimage);
      expect(row.inner_preimage_text).toBe(NON_ASCII_INNER_PREIMAGE_TEXT);
      expect(hashMovePreimageText(row.inner_preimage_text as string)).toBe(
        NON_ASCII_INNER_PREIMAGE_SHA256,
      );
    });

    it("the DATABASE, not the application, refuses an out-of-order step-2 signature", async () => {
      const operationId = await seedAttempt();
      await psqlOk(
        inSchema(
          `UPDATE operation_transactions SET attempt_phase = 'STEP1_SIGNATURE_PERSISTED',
             step_1_signature = $2
           WHERE operation_id = $1 AND attempt_no = 1`,
        ),
        [operationId, WALLET_STEP_1_SIGNATURE],
      );

      // Writing step_2_signature while the row is at STEP1_SIGNATURE_PERSISTED violates the
      // frozen phase CHECK — a raw UPDATE that bypasses advanceAttemptPhase entirely.
      const sqlstate = await rejected(
        `UPDATE operation_transactions SET step_2_signature = $2
           WHERE operation_id = $1 AND attempt_no = 1`,
        [operationId, WALLET_STEP_2_SIGNATURE],
      );
      expect(sqlstate).toBe(CHECK_VIOLATION);

      const row = await readAttempt(operationId);
      expect(row.attempt_phase).toBe("STEP1_SIGNATURE_PERSISTED");
      expect(row.step_2_signature).toBeNull();
    });

    it("the DATABASE refuses a second attempt row for the same operation", async () => {
      const operationId = await seedAttempt();
      const duplicate = await rejected(
        `INSERT INTO operation_transactions
           (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256, formed_at)
         VALUES ($1, 1, 'INNER_PREIMAGE_PERSISTED', $2, $3, now())`,
        [operationId, WALLET_INNER_PREIMAGE_TEXT, WALLET_INNER_PREIMAGE_SHA256],
      );
      expect(duplicate).toBe("23505"); // unique_violation on the composite primary key
      const secondAttempt = await rejected(
        `INSERT INTO operation_transactions
           (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256, formed_at)
         VALUES ($1, 2, 'INNER_PREIMAGE_PERSISTED', $2, $3, now())`,
        [operationId, WALLET_INNER_PREIMAGE_TEXT, WALLET_INNER_PREIMAGE_SHA256],
      );
      expect(secondAttempt).toBe(CHECK_VIOLATION); // attempt_no CHECK (attempt_no = 1)
    });

    it("leaves the step-2 preimage durable and unsigned when the destination lease is gone", async () => {
      const operationId = await seedAttempt();
      const signer = makeSigner(operationId, { destinationLease: null });

      await expect(
        signMoveStepsUnderLeases({
          operationId,
          leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
          query,
          signerDeps: signer.deps,
        }),
      ).rejects.toMatchObject({ name: "SignerBoundaryError", code: "NO_LEASE" });

      const row = await readAttempt(operationId);
      expect(row.attempt_phase).toBe("STEP2_PREIMAGE_PERSISTED");
      expect(row.step_2_preimage_text).toBe(WALLET_STEP_2_PREIMAGE_TEXT);
      expect(row.step_2_signature).toBeNull();
      expect(row.completed_transaction_text).toBeNull();
    });

    it("resumes from a crashed STEP1_SIGNATURE_PERSISTED row without byte drift", async () => {
      // Reference: an uninterrupted ceremony over the same inner.
      const straightId = await seedAttempt();
      const reference = await signMoveStepsUnderLeases({
        operationId: straightId,
        leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
        query,
        signerDeps: makeSigner(straightId).deps,
      });

      // Crashed: step-1 signature durable, nothing after it.
      const crashedId = await seedAttempt();
      await psqlOk(
        inSchema(
          `UPDATE operation_transactions SET attempt_phase = 'STEP1_SIGNATURE_PERSISTED',
             step_1_signature = $2
           WHERE operation_id = $1 AND attempt_no = 1`,
        ),
        [crashedId, WALLET_STEP_1_SIGNATURE],
      );

      const resumeSigner = makeSigner(crashedId, { signatures: [WALLET_STEP_2_SIGNATURE] });
      const resumed = await resumeMoveStep2FromPersistedStep1({
        operationId: crashedId,
        destinationLease: DESTINATION_LEASE,
        query,
        signerDeps: resumeSigner.deps,
      });

      // Re-derived from the persisted inner + persisted step-1 signature: identical bytes.
      expect(resumed.step2PreimageText).toBe(reference.step2PreimageText);
      expect(resumed.step2PreimageSha256).toBe(reference.step2PreimageSha256);
      const row = await readAttempt(crashedId);
      expect(row.step_2_preimage_text).toBe(reference.step2PreimageText);
      expect(row.attempt_phase).toBe("STEP2_SIGNATURE_PERSISTED");
      // The resume signed exactly once, and only the destination wallet.
      expect(resumeSigner.signed.map((call) => call.walletId)).toEqual([DESTINATION_WALLET]);
    });

    // ── MOVE signature advances vs lease release ─────────────────────────────────
    //
    // signUnderLease and advanceAttemptPhase are separate autocommit statements. A release
    // that commits between them must leave no durable signature. Mirrors receive-settle-step
    // coverage for the SEND/MOVE write side.

    it("a release that commits mid step-2 sign leaves no durable step-2 signature", async () => {
      const operationId = await seedAttempt();
      const signer = makeSigner(operationId);
      const baseSign = signer.deps.vaultSigner.sign.bind(signer.deps.vaultSigner);
      // Release the destination lease while the vault is open for step 2 — the one window the
      // lease READ inside signUnderLease cannot cover. Only the advance guard stands between
      // that and a durable step-2 signature.
      let signCalls = 0;
      signer.deps.vaultSigner.sign = async (walletId, bytes) => {
        signCalls += 1;
        const signature = await baseSign(walletId, bytes);
        if (signCalls === 2) {
          await releaseWalletLease(DESTINATION_WALLET);
        }
        return signature;
      };

      await expect(
        signMoveStepsUnderLeases({
          operationId,
          leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
          query,
          signerDeps: signer.deps,
        }),
      ).rejects.toThrow(/did not advance to STEP2_SIGNATURE_PERSISTED/);

      const row = await readAttempt(operationId);
      expect(row.attempt_phase).toBe("STEP2_PREIMAGE_PERSISTED");
      expect(row.step_1_signature).toBe(WALLET_STEP_1_SIGNATURE);
      expect(row.step_2_signature).toBeNull();
      expect(row.completed_transaction_text).toBeNull();
      expect(await countLeases(DESTINATION_WALLET)).toBe(0);
      // Step-1 source lease remains held — only destination was released mid step-2.
      expect(await countLeases(SOURCE_WALLET)).toBe(1);
    });

    it("a release that commits mid step-1 sign leaves no durable step-1 signature", async () => {
      const operationId = await seedAttempt();
      const signer = makeSigner(operationId);
      const baseSign = signer.deps.vaultSigner.sign.bind(signer.deps.vaultSigner);
      signer.deps.vaultSigner.sign = async (walletId, bytes) => {
        const signature = await baseSign(walletId, bytes);
        await releaseWalletLease(SOURCE_WALLET);
        return signature;
      };

      await expect(
        signMoveStepsUnderLeases({
          operationId,
          leases: { source: SOURCE_LEASE, destination: DESTINATION_LEASE },
          query,
          signerDeps: signer.deps,
        }),
      ).rejects.toThrow(/did not advance to STEP1_SIGNATURE_PERSISTED/);

      const row = await readAttempt(operationId);
      expect(row.attempt_phase).toBe("INNER_PREIMAGE_PERSISTED");
      expect(row.step_1_signature).toBeNull();
      expect(await countLeases(SOURCE_WALLET)).toBe(0);
    });

    it("concurrent FOR UPDATE release vs step-2 advance — exactly one wins", async () => {
      // Crashed after step 1: resume walks step-2 preimage → sign → guarded step-2 signature.
      // Hold the destination lease FOR UPDATE on a second session BEFORE resume starts, so the
      // race cannot lose to a slow releaser spawn (the flaky interleaving where resume commits
      // first and the release is just a post-hoc cleanup).
      const operationId = await seedAttempt();
      await psqlOk(
        inSchema(
          `UPDATE operation_transactions SET attempt_phase = 'STEP1_SIGNATURE_PERSISTED',
             step_1_signature = $2
           WHERE operation_id = $1 AND attempt_no = 1`,
        ),
        [operationId, WALLET_STEP_1_SIGNATURE],
      );

      const hold = spawn(
        "psql",
        ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-f", "-"],
        { env: pgEnv(), stdio: ["pipe", "pipe", "pipe"] },
      );
      let holdOut = "";
      let holdErr = "";
      hold.stdout.setEncoding("utf8");
      hold.stderr.setEncoding("utf8");
      hold.stdout.on("data", (c: string) => {
        holdOut += c;
      });
      hold.stderr.on("data", (c: string) => {
        holdErr += c;
      });
      hold.stdin.write(
        `SET search_path TO ${SCHEMA};
` +
          `BEGIN ISOLATION LEVEL SERIALIZABLE;
` +
          `SELECT 1 FROM wallet_active_leases WHERE wallet_id = '${DESTINATION_WALLET}' FOR UPDATE;
`,
      );
      await new Promise<void>((resolve, reject) => {
        const start = Date.now();
        const tick = () => {
          if (holdOut.includes("1")) {
            resolve();
            return;
          }
          if (Date.now() - start > 5_000) {
            reject(new Error(`lock not acquired: out=${holdOut} err=${holdErr}`));
            return;
          }
          setTimeout(tick, 50);
        };
        tick();
      });

      const resumeSigner = makeSigner(operationId, { signatures: [WALLET_STEP_2_SIGNATURE] });
      // Resume blocks on the lease FOR SHARE at step-2 sign and/or the guarded advance.
      const resumePromise = resumeMoveStep2FromPersistedStep1({
        operationId,
        destinationLease: DESTINATION_LEASE,
        query,
        signerDeps: resumeSigner.deps,
      }).then(
        () => "ok" as const,
        (err: unknown) => err,
      );

      // Keep the lock held long enough that resume must be waiting, then release.
      await new Promise((r) => setTimeout(r, 500));
      hold.stdin.write(
        `DELETE FROM wallet_active_leases WHERE wallet_id = '${DESTINATION_WALLET}';
COMMIT;
`,
      );
      hold.stdin.end();
      await new Promise<void>((resolve) => hold.on("close", () => resolve()));

      const outcome = await resumePromise;
      expect(outcome).not.toBe("ok");

      const row = await readAttempt(operationId);
      expect(row.step_2_signature).toBeNull();
      expect(row.completed_transaction_text).toBeNull();
      // Preimage advance is unguarded, so the row may already be at STEP2_PREIMAGE when the
      // signature advance loses; either way the signature never landed.
      expect(["STEP1_SIGNATURE_PERSISTED", "STEP2_PREIMAGE_PERSISTED"]).toContain(
        row.attempt_phase,
      );
      expect(await countLeases(DESTINATION_WALLET)).toBe(0);
    }, 20_000);

    it("behavioral: advance blocks on FOR SHARE while releaser holds FOR UPDATE, then matches 0", async () => {
      // Direct store-level proof that the guard CTE's FOR SHARE participates in the lock, not
      // a plain EXISTS snapshot read (Review B). A release transaction holds the row
      // FOR UPDATE; the advance is started and must not finish until the release commits; then
      // it matches zero rows.
      const operationId = await seedAttempt();
      await psqlOk(
        inSchema(
          `UPDATE operation_transactions SET
             attempt_phase = 'STEP2_PREIMAGE_PERSISTED',
             step_1_signature = $2,
             step_2_preimage_text = $3,
             step_2_preimage_sha256 = $4
           WHERE operation_id = $1 AND attempt_no = 1`,
        ),
        [
          operationId,
          WALLET_STEP_1_SIGNATURE,
          WALLET_STEP_2_PREIMAGE_TEXT,
          hashMovePreimageText(WALLET_STEP_2_PREIMAGE_TEXT),
        ],
      );

      // Hold FOR UPDATE on a second session without committing yet.
      const hold = spawn(
        "psql",
        ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-f", "-"],
        { env: pgEnv(), stdio: ["pipe", "pipe", "pipe"] },
      );
      let holdOut = "";
      let holdErr = "";
      hold.stdout.setEncoding("utf8");
      hold.stderr.setEncoding("utf8");
      hold.stdout.on("data", (c: string) => {
        holdOut += c;
      });
      hold.stderr.on("data", (c: string) => {
        holdErr += c;
      });
      // Begin + lock; leave the transaction open.
      hold.stdin.write(
        `SET search_path TO ${SCHEMA};\n` +
          `BEGIN ISOLATION LEVEL SERIALIZABLE;\n` +
          `SELECT 1 FROM wallet_active_leases WHERE wallet_id = '${DESTINATION_WALLET}' FOR UPDATE;\n`,
      );

      // Wait until the lock is held (SELECT returns).
      await new Promise<void>((resolve, reject) => {
        const start = Date.now();
        const tick = () => {
          if (holdOut.includes("1")) {
            resolve();
            return;
          }
          if (Date.now() - start > 5_000) {
            reject(new Error(`lock not acquired: out=${holdOut} err=${holdErr}`));
            return;
          }
          setTimeout(tick, 50);
        };
        tick();
      });

      const advanceStarted = Date.now();
      let advanceSettledAt = 0;
      const advancePromise = advanceAttemptPhase(
        query,
        operationId,
        "STEP2_SIGNATURE_PERSISTED",
        {
          step_2_signature: WALLET_STEP_2_SIGNATURE,
          completed_transaction_text: WALLET_SETTLED_TRANSACTION_TEXT,
          completed_transaction_sha256: hashMovePreimageText(WALLET_SETTLED_TRANSACTION_TEXT),
        },
        {
          walletId: DESTINATION_WALLET,
          operationId,
          leaseEpoch: 9n,
        },
      ).then(
        () => {
          advanceSettledAt = Date.now();
          return "ok" as const;
        },
        (err: unknown) => {
          advanceSettledAt = Date.now();
          return err;
        },
      );

      // Give the advance time to block on FOR SHARE rather than finish against a snapshot.
      await new Promise((r) => setTimeout(r, 400));
      expect(advanceSettledAt).toBe(0); // still blocked while releaser holds FOR UPDATE

      // Release the row and commit — advance must then observe zero leases and throw.
      hold.stdin.write(
        `DELETE FROM wallet_active_leases WHERE wallet_id = '${DESTINATION_WALLET}';\nCOMMIT;\n`,
      );
      hold.stdin.end();
      await new Promise<void>((resolve) => hold.on("close", () => resolve()));

      const outcome = await advancePromise;
      expect(outcome).not.toBe("ok");
      expect(String(outcome)).toMatch(/did not advance to STEP2_SIGNATURE_PERSISTED/);
      // Blocked for a meaningful window, not a free EXISTS snapshot read.
      expect(advanceSettledAt - advanceStarted).toBeGreaterThanOrEqual(350);

      const row = await readAttempt(operationId);
      expect(row.attempt_phase).toBe("STEP2_PREIMAGE_PERSISTED");
      expect(row.step_2_signature).toBeNull();
      expect(await countLeases(DESTINATION_WALLET)).toBe(0);
    }, 20_000);
  },
);
