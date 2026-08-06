// The receive settle worker step against a real PostgreSQL server.
// The one-in-flight-per-wallet and byte-exact signing rules, 4.
//
// The unit suite (packages/node-core/src/core/receive-settle.test.ts) drives
// settleReceiveAttempt through a fake SqlQueryFn, so it proves the ceremony and proves nothing
// about the three statements this app-tree step actually sends. Those went to review once
// having never been executed against a schema, and the signer_audit INSERT was wrong in eight
// ways against a DDL that a correct adapter for the same table sat four files away from. This
// suite exists so that class of defect fails a test rather than a production settle.
//
// The DDL applied is the frozen contract text of the money-pack slices this step touches,
// verbatim, composed in dependency sequence. Only the FK targets outside those slices are
// stubbed, exactly as move-form-and-sign.pg.test.ts does.
//
// psql runs as a child process, which keeps the in-process network containment intact.

import { spawn } from "node:child_process";
import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, createPublicKey, randomUUID, sign as edSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  GetTransactionActionDataShapeError,
  assertCanonicalGetTransactionActionData,
  buildGatewayActionRequest,
  type GatewayExchangeTransport,
  type GatewayRequest,
  type SqlQueryFn,
} from "@zucoins/node-core";

import { registerPgRequiredGuard } from "../../../packages/node-core/test/pg-required-guard.ts";
import {
  runReceiveSettleStep,
  type ReceiveSettleStepDeps,
} from "../src/money-workers/receive-settle-step.js";

// Decodes request bytes exactly as the real gateway would: one urlencoded form field
// whose value is encodeURIComponent(JSON.stringify({action_name, action_data})).
function decodeGatewayFormBody(bodyBytes: Uint8Array): { actionName: string; actionData: unknown } {
  const text = new TextDecoder().decode(bodyBytes);
  const encoded = new URLSearchParams(text).get("v");
  if (encoded === null) throw new Error("gateway request body carries no v= form field");
  const parsed = JSON.parse(encoded) as { action_name: string; action_data: unknown };
  return { actionName: parsed.action_name, actionData: parsed.action_data };
}

const SCHEMA = "receive_settle_step_receive_settle_step";
const databaseUrl = process.env.TEST_DATABASE_URL;

const NODE_ID = "00000000-0000-4000-8000-00000000000a";
const IMPLEMENTER_ID = "00000000-0000-4000-8000-00000000000b";
const NOW_ISO = "2026-01-01T00:00:00.000Z";

// ── keys and the one candidate's exact bytes ───────────────────────────────────────────────

const RECEIVER_SEED = Buffer.alloc(32, 0x03);
const PAYER_SEED = Buffer.alloc(32, 0x02);
const keyFromSeed = (seed: Buffer) =>
  createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    type: "pkcs8",
    format: "der",
  });
const publicKeyOf = (seed: Buffer): Buffer =>
  createPublicKey(keyFromSeed(seed)).export({ type: "spki", format: "der" }).subarray(-32);
/** The padded base64url spelling — the only form the frozen scalar domains accept. */
const base64urlPadded = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");

const sha256 = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");
const sha256Bytes = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

const RECEIVER_PUBLIC = base64urlPadded(publicKeyOf(RECEIVER_SEED));
const PAYER_PUBLIC = base64urlPadded(publicKeyOf(PAYER_SEED));

/** A well-formed v2 inner in canonical insertion sequence, serialized once. */
const INNER_PREIMAGE_TEXT = JSON.stringify({
  type: "unique_combinable",
  version: "2",
  unix_time_secs: "1767225600",
  signer_steps: 2,
  step_1_signer: "sender",
  step_2_signer: "receiver",
  step_1_key_public__base64urlsafe: PAYER_PUBLIC,
  step_2_key_public__base64urlsafe: RECEIVER_PUBLIC,
  step_1_state: { amount: "9.99", nonce: "n1" },
  step_2_state: { amount: "0.01", nonce: "n2" },
  previous_step_1_state_signature: "prev-s1",
  previous_step_2_state_signature: "",
  expiry__unix_time_secs: "1767229200",
});
const PAYER_STEP1_SIGNATURE = base64urlPadded(
  Buffer.from(edSign(null, Buffer.from(INNER_PREIMAGE_TEXT, "utf8"), keyFromSeed(PAYER_SEED))),
);

/** Exactly what the settle sign steps produce, computed here so the assertions below are not
 * comparing the step against itself. */
const STEP2_PREIMAGE_TEXT = `{"inner":${INNER_PREIMAGE_TEXT},"step_1_signature":${JSON.stringify(PAYER_STEP1_SIGNATURE)}}`;
const STEP2_SIGNATURE = base64urlPadded(
  Buffer.from(edSign(null, Buffer.from(STEP2_PREIMAGE_TEXT, "utf8"), keyFromSeed(RECEIVER_SEED))),
);
const COMPLETED_TEXT = `${STEP2_PREIMAGE_TEXT.slice(0, -1)},"step_2_signature":${JSON.stringify(STEP2_SIGNATURE)}}`;

// ── psql transport ─────────────────────────────────────────────────────────────────────────

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

// Test-only stand-in for a driver's parameter binding: psql has no wire parameters, so each $n
// becomes a psql variable reference, which psql quotes and escapes. Byte values therefore reach
// the server through psql's own quoting, never through string concatenation in this file.
function psql(sql: string, values: readonly unknown[] = []): Promise<{ code: number; stdout: string; stderr: string }> {
  const args = ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose"];
  const literal = (value: unknown): string =>
    Array.isArray(value) ? `{${(value as unknown[]).join(",")}}` : String(value);
  values.forEach((value, index) => {
    if (value !== null && value !== undefined) args.push("-v", `p${index + 1}=${literal(value)}`);
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
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
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

/** The production SqlQueryFn shape over psql — the seam the step itself consumes. A statement
 * that returns no rows (the signer audit INSERT) cannot be wrapped in a CTE, so it runs bare. */
const query: SqlQueryFn = async (text, values) => {
  const returnsRows = /^\s*(SELECT|WITH)\b/i.test(text) || /\bRETURNING\b/i.test(text);
  if (!returnsRows) {
    await psqlOk(inSchema(text), values);
    return [];
  }
  const wrapped = `WITH q AS (${text}) SELECT coalesce(json_agg(row_to_json(q)), '[]'::json) FROM q`;
  const stdout = await psqlOk(inSchema(wrapped), values);
  const line = stdout.trim().split("\n").filter(Boolean).at(-1) ?? "[]";
  return JSON.parse(line) as Record<string, unknown>[];
};

// ── schema composition ─────────────────────────────────────────────────────────────────────

const schemaDir = fileURLToPath(
  new URL("../../../packages/node-core/src/schema/", import.meta.url),
);
/** Dependency sequence: every FK target precedes its user. */
const PACK_SLICES = [
  "base-enums-domains",
  "custody-eligibility",
  "signer-support",
  "operations",
  "transaction-material",
  "submit-attempts",
] as const;

/** FK targets owned by slices this step never touches. Only the referenced column is needed. */
const FK_TARGET_STUBS = ["nodes", "implementers", "operation_approvals"]
  .map((table) => `CREATE TABLE ${table} (id uuid PRIMARY KEY);`)
  .join("\n");

/**
 * Several slices repeat the shared scalar-domain declarations, because each is applied against a
 * schema the reporting prefix already seeded. This scratch schema has no reporting prefix, so
 * every domain and enum declaration is hoisted ahead of the table DDL and declared once. Table
 * DDL is never touched: every CREATE TABLE applied below is the frozen contract text, verbatim.
 */
function packSql(): string {
  const declared = new Set<string>();
  const declarations: string[] = [];
  const tables = PACK_SLICES.map((slice) =>
    readFileSync(`${schemaDir}${slice}.sql`, "utf8"),
  )
    .join("\n")
    .replace(
      /^CREATE (DOMAIN|TYPE) ([a-z0-9_]+)[\s\S]*?;\n/gm,
      (statement, _kind: string, name: string) => {
        if (!declared.has(name)) {
          declared.add(name);
          declarations.push(statement);
        }
        return "";
      },
    );
  return `${declarations.join("\n")}\n${tables}`;
}

// ── fakes ──────────────────────────────────────────────────────────────────────────────────

/** The vault seam: returns the 64-byte libsodium secret key the step halves into a seed. */
const vault: ReceiveSettleStepDeps["vault"] = {
  open: async () => {
    const bytes = Buffer.concat([RECEIVER_SEED, publicKeyOf(RECEIVER_SEED)]);
    return { bytes, wipe: () => bytes.fill(0) } as Awaited<
      ReturnType<ReceiveSettleStepDeps["vault"]["open"]>
    >;
  },
};

/** One gateway transport for both the submit and the landing confirm-read, so the assertions can
 * tell which action crossed the wire. `headBody` is what the confirm-read observes. */
function makeExchange(headStep2Signature: string | null) {
  const calls: GatewayRequest[] = [];
  // A head is `data` as a one-entry array of a complete settled transaction; the
  // no-head case is the authoritative account-not-found genesis result, not an empty object.
  const headBody =
    headStep2Signature === null
      ? JSON.stringify({ status: false, code: "account_not_found", message: "no account", data: null })
      : JSON.stringify({
          status: true,
          code: "ok",
          message: "OK",
          data: [
            {
              inner: { version: "2" },
              step_1_signature: PAYER_STEP1_SIGNATURE,
              step_2_signature: headStep2Signature,
            },
          ],
        });
  const transport: GatewayExchangeTransport = {
    exchange: async (endpoint: string, request: GatewayRequest) => {
      calls.push(request);
      // exact-form fake — a get_transaction__v1 exchange is decoded off the real wire
      // bytes and run through the canonical shape assertion before a response is served, so a
      // regression back to the legacy `public_key_base64urlsafe` field (or any other
      // noncanonical shape) fails this test instead of silently getting a scripted answer.
      if (request.rpc === "get_transaction__v1") {
        const { actionData } = decodeGatewayFormBody(request.bodyBytes);
        assertCanonicalGetTransactionActionData(actionData);
      }
      const body =
        request.rpc === "get_transaction__v1"
          ? headBody
          : '{"status":true,"code":"ok","message":"OK","data":{}}';
      const responseBytes = new TextEncoder().encode(body);
      // Real digests: gateway_submit_attempts stores both under the sha256_hex domain, so a
      // placeholder string here would be refused by the schema rather than by the code.
      return {
        endpoint,
        endpointFingerprint: "offline-fp",
        requestBytes: request.bodyBytes,
        requestSha256: sha256Bytes(request.bodyBytes),
        responseBytes,
        responseSha256: sha256Bytes(responseBytes),
        statusCode: 200,
      };
    },
  };
  return { transport, calls, submits: () => calls.filter((c) => c.rpc === "submit_transaction__v1") };
}

let logs: string[] = [];
const logger = {
  info: (message: string) => void logs.push(message),
  error: (message: string, err?: unknown) =>
    void logs.push(`ERROR ${message} :: ${err instanceof Error ? err.message : String(err)}`),
};

function makeDeps(exchange: ReturnType<typeof makeExchange>): ReceiveSettleStepDeps {
  return {
    query,
    vault,
    nodeId: NODE_ID,
    leadership: { held: true },
    moneyPathGates: {
      assertMoneyAdmitted: () => {},
      assertCanOperate: () => {},
      assertWalletMaySign: async () => {},
    },
    gateway: {
      endpoint: "https://gateway.offline.test",
      limits: { readTimeoutMs: 1000, maxRequestBytes: 65536, maxResponseBytes: 65536 },
      exchange: exchange.transport,
    },
    logger,
  };
}

// ── seeding ────────────────────────────────────────────────────────────────────────────────

interface Seeded {
  readonly operationId: string;
  readonly nodeId: string;
  readonly walletId: string;
}

interface SeedOptions {
  readonly attemptPhase: "STEP1_SIGNATURE_PERSISTED" | "STEP2_PREIMAGE_PERSISTED" | "STEP2_SIGNATURE_PERSISTED";
  /** Mint the durable submit claim a crash after the single submit would have left behind. */
  readonly withSubmitClaim?: boolean;
}



/**
 * One RECEIVE_EXTERNAL operation with its own node, recovery-verified receiver wallet, held
 * RECEIVE_WINDOW lease, and attempt row. Each candidate gets its own node and wallet because
 * wallet_active_leases is keyed on wallet_id alone (the one-in-flight-per-wallet carrier) and wallets are
 * UNIQUE per (node_id, public_key) — two candidates sharing either would collide in the seed
 * rather than in the code under test.
 */
async function seedCandidate(options: SeedOptions): Promise<Seeded> {
  const operationId = randomUUID();
  const nodeId = randomUUID();
  const walletId = randomUUID();
  const verificationId = randomUUID();
  await psqlOk(
    inSchema(
      `INSERT INTO nodes (id) VALUES ($1::uuid);
       INSERT INTO wallets (id, node_id, public_key, key_origin)
         VALUES ($2::uuid, $1::uuid, $3, 'node_generated');
       INSERT INTO wallet_recovery_verifications
         (id, wallet_id, method, public_key, export_sha256, audit_event_id, verified_at,
          verifier_identity)
         VALUES ($4::uuid, $2::uuid, 'AUDITED_EXPORT', $3, $5, $6::uuid, now(), 'receive-settle-step-seed');
       UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = $4::uuid
         WHERE id = $2::uuid`,
    ),
    [nodeId, walletId, RECEIVER_PUBLIC, verificationId, sha256(walletId), randomUUID()],
  );
  await psqlOk(
    inSchema(
      // A READY RECEIVE_EXTERNAL with a receiver wallet, as the operations CHECKs require it: the
      // discriminator is the operation id, the anchor and expiry are set, and T0 is observed.
      `INSERT INTO operations
         (id, node_id, implementer_id, kind, status, amount_zkz, receiver_wallet_id,
          discriminator, anchor, after_landing, expiry_unix_time_secs, t0_observation_id,
          idempotency_key, request_sha256)
       VALUES ($1::uuid, $5::uuid, '${IMPLEMENTER_ID}', 'RECEIVE_EXTERNAL', 'READY',
               '0.01', $6::uuid, $1::uuid, 'anchor-1', 'HOLD', '1767229200', $2::uuid,
               $3, $4)`,
    ),
    [operationId, randomUUID(), `idem-${operationId}`, sha256(operationId), nodeId, walletId],
  );
  await psqlOk(
    inSchema(
      `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role)
       VALUES ($1::uuid, $2::uuid, 'RECEIVER')`,
    ),
    [operationId, walletId],
  );
  await psqlOk(
    inSchema(
      `INSERT INTO wallet_active_leases
         (wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
          lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
       VALUES ($4::uuid, $2::uuid, $3::uuid, $1::uuid, $1::uuid,
               'RECEIVE_WINDOW', 7, now(), now(), $5::uuid)`,
    ),
    [operationId, randomUUID(), randomUUID(), walletId, randomUUID()],
  );
  await psqlOk(
    inSchema(
      `INSERT INTO operation_transactions
         (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256,
          step_1_signature, formed_at)
       VALUES ($1::uuid, 1, 'STEP1_SIGNATURE_PERSISTED', $2, $3, $4, now())`,
    ),
    [operationId, INNER_PREIMAGE_TEXT, sha256(INNER_PREIMAGE_TEXT), PAYER_STEP1_SIGNATURE],
  );

  // Walk the durable row up the frozen one-way ladder to the rung the crash would have left.
  if (options.attemptPhase !== "STEP1_SIGNATURE_PERSISTED") {
    await psqlOk(
      inSchema(
        `UPDATE operation_transactions
            SET attempt_phase = 'STEP2_PREIMAGE_PERSISTED',
                step_2_preimage_text = $2, step_2_preimage_sha256 = $3
          WHERE operation_id = $1::uuid AND attempt_no = 1`,
      ),
      [operationId, STEP2_PREIMAGE_TEXT, sha256(STEP2_PREIMAGE_TEXT)],
    );
  }
  if (options.attemptPhase === "STEP2_SIGNATURE_PERSISTED") {
    await psqlOk(
      inSchema(
        `UPDATE operation_transactions
            SET attempt_phase = 'STEP2_SIGNATURE_PERSISTED', step_2_signature = $2,
                completed_transaction_text = $3, completed_transaction_sha256 = $4
          WHERE operation_id = $1::uuid AND attempt_no = 1`,
      ),
      [operationId, STEP2_SIGNATURE, COMPLETED_TEXT, sha256(COMPLETED_TEXT)],
    );
  }
  if (options.withSubmitClaim === true) {
    await psqlOk(
      inSchema(
        `INSERT INTO submit_decisions
           (id, operation_id, transaction_attempt_no, decision, decided_at, details)
         VALUES ($1::uuid, $1::uuid, 1, 'INITIAL_SINGLE_SHOT', '${NOW_ISO}', 'seeded')`,
      ),
      [operationId],
    );
  }
  seededWallets.push(walletId);
  return { operationId, nodeId, walletId };
}

const readAttempt = async (operationId: string): Promise<Record<string, unknown>> => {
  const rows = await query(
    `SELECT attempt_phase, step_2_preimage_text, step_2_signature, completed_transaction_text
       FROM operation_transactions WHERE operation_id = $1 AND attempt_no = 1`,
    [operationId],
  );
  const row = rows[0];
  if (row === undefined) throw new Error(`no attempt row for ${operationId}`);
  return row;
};

/** Wallets seeded by the current test, released in afterEach. Releasing the receiver lease is
 * what takes a finished candidate out of the selector; without it every test would also re-drive
 * every earlier test's row, so the per-tick counts below would not mean anything. */
const seededWallets: string[] = [];

const releaseLeases = async (): Promise<void> => {
  for (const walletId of seededWallets.splice(0)) {
    await psqlOk(inSchema(`DELETE FROM wallet_active_leases WHERE wallet_id = $1::uuid`), [
      walletId,
    ]);
  }
};

const readAudit = async (operationId: string): Promise<readonly Record<string, unknown>[]> =>
  query(
    `SELECT node_id::text AS node_id, outcome, purpose, lease_epoch::text AS lease_epoch,
            preimage_sha256
       FROM signer_audit WHERE operation_id = $1 ORDER BY called_at`,
    [operationId],
  );

let reachable = false;

describe.skipIf(databaseUrl === undefined)(
  "receive settle step against a live PostgreSQL",
  () => {
    beforeAll(async () => {
      await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
      await psqlOk(inSchema(`${FK_TARGET_STUBS}\n${packSql()}`));
      await psqlOk(
        inSchema(
          `INSERT INTO implementers (id) VALUES ('${IMPLEMENTER_ID}');`,
        ),
      );
      reachable = true;
    });

    afterAll(async () => {
      if (reachable) await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE;`);
    });

    beforeEach(() => {
      logs = [];
    });

    afterEach(releaseLeases);

    it("settles a first-rung candidate and writes every row the frozen DDL demands", async () => {
      const { operationId, nodeId } = await seedCandidate({
        attemptPhase: "STEP1_SIGNATURE_PERSISTED",
      });
      const exchange = makeExchange(null);

      const decided = await runReceiveSettleStep(makeDeps(exchange));
      expect(decided).toBe(1);

      // The step-2 material the server holds is the exact bytes, not a re-serialization.
      const attempt = await readAttempt(operationId);
      expect(attempt.attempt_phase).toBe("STEP2_SIGNATURE_PERSISTED");
      expect(attempt.step_2_preimage_text).toBe(STEP2_PREIMAGE_TEXT);
      expect(attempt.step_2_signature).toBe(STEP2_SIGNATURE);
      expect(attempt.completed_transaction_text).toBe(COMPLETED_TEXT);

      // The regression this suite exists for: the signer audit INSERT must satisfy the
      // signer_audit CHECK vocabulary and every NOT NULL column, with node_id taken from the
      // operation rather than invented.
      const audit = await readAudit(operationId);
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({
        node_id: nodeId,
        outcome: "SUCCEEDED",
        purpose: "STEP_2",
        lease_epoch: "7",
      });
      expect(audit[0]!.preimage_sha256).toBe(sha256(STEP2_PREIMAGE_TEXT));

      // Single submit: exactly one claim and one recorded gateway attempt, and one submit.
      const decisions = await query(
        `SELECT count(*)::int AS n FROM submit_decisions WHERE operation_id = $1`,
        [operationId],
      );
      expect(decisions[0]?.n).toBe(1);
      const attempts = await query(
        `SELECT transport_outcome FROM gateway_submit_attempts WHERE operation_id = $1`,
        [operationId],
      );
      expect(attempts, logs.join("\n")).toHaveLength(1);
      expect(attempts[0]?.transport_outcome).toBe("ACK");
      expect(exchange.submits()).toHaveLength(1);

      // The byte-exact signing rule at the wire: the bytes that left carry the settled body verbatim.
      const wire = new TextDecoder().decode(exchange.submits()[0]!.bodyBytes);
      expect(decodeURIComponent(wire.slice(wire.indexOf("=") + 1))).toContain(COMPLETED_TEXT);
    });

    it("resumes a row crashed between the cosign-persist and the submit", async () => {
      const { operationId } = await seedCandidate({ attemptPhase: "STEP2_PREIMAGE_PERSISTED" });
      const exchange = makeExchange(null);

      // The selector must admit this rung at all — before rework it did not, and the
      // row sat at STEP2_PREIMAGE_PERSISTED with its receiver lease held forever.
      expect(await runReceiveSettleStep(makeDeps(exchange))).toBe(1);

      const attempt = await readAttempt(operationId);
      expect(attempt.attempt_phase).toBe("STEP2_SIGNATURE_PERSISTED");
      // Signed from the PERSISTED preimage, so the bytes match the uninterrupted ceremony.
      expect(attempt.step_2_signature).toBe(STEP2_SIGNATURE);
      expect(attempt.completed_transaction_text).toBe(COMPLETED_TEXT);
      expect(exchange.submits()).toHaveLength(1);
      // No confirm-read: no submit had started, so there was no outcome to reconcile.
      expect(exchange.calls.filter((c) => c.rpc === "get_transaction__v1")).toHaveLength(0);
    });

    it("a row crashed between submit and the landing write reconciles and never resubmits", async () => {
      const { operationId } = await seedCandidate({
        attemptPhase: "STEP2_SIGNATURE_PERSISTED",
        withSubmitClaim: true,
      });
      // The receiver head IS this attempt's body: the one submit reached the chain.
      const exchange = makeExchange(STEP2_SIGNATURE);

      expect(await runReceiveSettleStep(makeDeps(exchange))).toBe(1);

      // The never-blind-retry rule, load-bearing: a confirm-read happened and no submit did.
      expect(exchange.calls.filter((c) => c.rpc === "get_transaction__v1")).toHaveLength(1);
      expect(exchange.submits()).toHaveLength(0);
      const attempts = await query(
        `SELECT count(*)::int AS n FROM gateway_submit_attempts WHERE operation_id = $1`,
        [operationId],
      );
      expect(attempts[0]?.n).toBe(0);
      // Nothing was signed a second time, and the durable body is untouched.
      expect(await readAudit(operationId)).toHaveLength(0);
      expect((await readAttempt(operationId)).completed_transaction_text).toBe(COMPLETED_TEXT);
      expect(logs.join("\n")).toContain(`OBSERVED_AT_HEAD op=${operationId}`);
    });

    // ── settle vs lease release ──────────────────────────────────────────────────
    //
    // The settle path reads the lease and persists the step-2 signature in two separate
    // autocommit statements, so a proof-backed release can commit between them. Both tests
    // below drive a real concurrent release against a real settle and require the same
    // outcome: the release and the signature never both succeed, and the loser writes nothing.

    it("a release that commits mid-sign leaves no durable signature and no submit", async () => {
      const { operationId, walletId } = await seedCandidate({
        attemptPhase: "STEP1_SIGNATURE_PERSISTED",
      });
      const exchange = makeExchange(null);

      // The release lands at the one instant the row lock on the settle's lease READ cannot
      // cover: after the signer validated the lease, while the vault secret is open. Only the
      // guard on the step-2 advance itself stands between that and a submittable body.
      const releasingVault: ReceiveSettleStepDeps["vault"] = {
        open: async (descriptor, purpose) => {
          await psqlOk(inSchema(`DELETE FROM wallet_active_leases WHERE wallet_id = $1::uuid`), [
            walletId,
          ]);
          return vault.open(descriptor, purpose);
        },
      };

      const decided = await runReceiveSettleStep({ ...makeDeps(exchange), vault: releasingVault });

      // Nothing reached a settled decision, and the refusal is logged rather than retried.
      expect(decided).toBe(0);
      expect(logs.join("\n")).toContain(`receive settle failed op=${operationId}`);

      // The durable row is untouched past the preimage rung: no signature, no body.
      const attempt = await readAttempt(operationId);
      expect(attempt.attempt_phase).toBe("STEP2_PREIMAGE_PERSISTED");
      expect(attempt.step_2_signature).toBeNull();
      expect(attempt.completed_transaction_text).toBeNull();

      // The one-in-flight-per-wallet rule at the wire: nothing was submitted for a wallet this node no longer holds,
      // and no submit claim was minted for a later pass to find.
      expect(exchange.submits()).toHaveLength(0);
      const decisions = await query(
        `SELECT count(*)::int AS n FROM submit_decisions WHERE operation_id = $1`,
        [operationId],
      );
      expect(decisions[0]?.n).toBe(0);

      // The release itself completed exactly once — the settle never resurrected the lease.
      const leases = await query(
        `SELECT count(*)::int AS n FROM wallet_active_leases WHERE wallet_id = $1`,
        [walletId],
      );
      expect(leases[0]?.n).toBe(0);

      // Stated plainly rather than left for review to find: the vault WAS opened, so a signature
      // was produced. What this fix guarantees is narrower and is the part that moves money —
      // that signature never becomes durable and never crosses the wire.
      expect(await readAudit(operationId)).toHaveLength(1);
    });

    it("settle and a concurrent releasing transaction — exactly one wins", async () => {
      const { operationId, walletId } = await seedCandidate({
        attemptPhase: "STEP2_PREIMAGE_PERSISTED",
      });
      const exchange = makeExchange(null);

      // A second database transaction doing what the sanctioned release paths do: hold the lease
      // row FOR UPDATE under SERIALIZABLE, then delete it. Started but deliberately not awaited,
      // so the settle below runs against a release that is genuinely in flight.
      const releaser = psql(
        inSchema(
          `BEGIN ISOLATION LEVEL SERIALIZABLE;
           SELECT 1 FROM wallet_active_leases WHERE wallet_id = $1::uuid FOR UPDATE;
           SELECT pg_sleep(1);
           DELETE FROM wallet_active_leases WHERE wallet_id = $1::uuid;
           COMMIT;`,
        ),
        [walletId],
      );

      const decided = await runReceiveSettleStep(makeDeps(exchange));
      const released = await releaser;
      expect(released.code, released.stderr).toBe(0);

      // However the server interleaved the two, the settle lost: it either never selected the
      // candidate, or its FOR SHARE read blocked until the release committed and then found no
      // lease. Both are clean refusals — the assertion is on the durable outcome, not on timing.
      expect(decided).toBe(0);
      const attempt = await readAttempt(operationId);
      expect(attempt.attempt_phase).toBe("STEP2_PREIMAGE_PERSISTED");
      expect(attempt.step_2_signature).toBeNull();
      expect(exchange.submits()).toHaveLength(0);

      // Released once, by the releaser, and not double-released by the settle path.
      const leases = await query(
        `SELECT count(*)::int AS n FROM wallet_active_leases WHERE wallet_id = $1`,
        [walletId],
      );
      expect(leases[0]?.n).toBe(0);
    }, 20_000);

    it("regression guard: the exact-form fake rejects the legacy public_key_base64urlsafe form", () => {
      // The exact defect that shipped at this step's confirm-read before a request
      // built with the noncanonical field name. buildGatewayActionRequest never reorders or
      // renames action-data keys (the byte-exact signing rule), so this reproduces the literal bytes the
      // pre-fix confirm-read sent — and proves makeExchange's assertion above would have
      // caught it.
      const legacyRequest = buildGatewayActionRequest("get_transaction__v1", {
        public_key_base64urlsafe: RECEIVER_PUBLIC,
      });
      const { actionData } = decodeGatewayFormBody(legacyRequest.bodyBytes);
      expect(() => assertCanonicalGetTransactionActionData(actionData)).toThrow(
        GetTransactionActionDataShapeError,
      );
    });
  },
);

// A vitest suite whose beforeAll throws reports its tests SKIPPED, not failed. Under
// PG_REQUIRED=1 that is a broken harness, never "no Postgres here" — a money-path suite must
// not report green having proven nothing.
//
// Registered AFTER the describe, as every other caller of this helper does: the helper registers
// a top-level `it`, vitest runs a file's tasks in declaration order, and `isReady()` only becomes
// true in the describe's beforeAll. Registered above, the guard fires before the suite it is
// guarding has had a chance to run and fails unconditionally.
registerPgRequiredGuard({
  name: "receive-settle-step.pg",
  databaseUrl,
  isReady: () => reachable,
});
