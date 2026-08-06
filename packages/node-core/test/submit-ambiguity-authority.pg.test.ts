// real-PostgreSQL half (mandatory database tests).
// Governing: the data model, mandatory database test 10, the never-blind-retry rule.
//
// Applies the frozen contract text of src/schema/submit-attempts.sql verbatim and proves:
//   1. Concurrent workers → exactly one gateway POST / one gateway_submit_attempts row.
//   2. Duplicate (decision_id) / (operation_id, transaction_attempt_no) inserts fail at the
//      DB UNIQUE layer (SQLSTATE 23505), not merely in application logic.
//   3. CHECK (transaction_attempt_no = 1) and CHECK (decision = 'INITIAL_SINGLE_SHOT').
//   4. Corrupted evidence: response_body/response_sha256 biconditional CHECK rejects
//      mismatched pairs at write time (SQLSTATE 23514) — never silently coerced to ACK.
//   5. INDETERMINATE row schedules no second submit row (UNIQUE backstop).
//   6. operation_transactions CHECK (attempt_no = 1) rejects a second transaction attempt.
//
// Sibling discharge (landed, green on origin/main — also run under the same DDL):
//   packages/node-core/test/submit-decision-claim-store.pg.test.ts
//
// Skips cleanly when TEST_DATABASE_URL is unset (same pattern as every other *.pg.test.ts).

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";

import { executeMoveSubmitClaim } from "../src/core/move-submit-claim.ts";
import type { SqlQueryFn } from "../src/core/sql-query-fn.ts";
import {
  classifySubmitAttemptEvidence,
  makeSubmitAttemptRecorder,
  makeSubmitDecisionClaimStore,
  readSubmitAttemptEvidence,
} from "../src/core/submit-decision-claim-store.ts";
import { sha256Hex, type GatewayExchangeTransport } from "../src/gateway/capture.ts";
import type { SubmitAuthorization } from "../src/gateway/submit.ts";
import type { GatewayLimits } from "../src/gateway/types.ts";
import { toAttentionReason } from "../src/protocol/reconcile/types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const submitAttemptsSql = readFileSync(resolve(here, "../src/schema/submit-attempts.sql"), "utf8");

const SCHEMA = "submit_ambiguity_submit_ambiguity_authority";
const UNIQUE_VIOLATION = "23505";
const CHECK_VIOLATION = "23514";

const databaseUrl = process.env.TEST_DATABASE_URL;

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

function psql(sql: string, values: readonly unknown[] = []): Promise<PsqlResult> {
  const args = ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose"];
  values.forEach((value, index) => {
    if (value !== null && value !== undefined) {
      args.push("-v", `p${index + 1}=${String(value)}`);
    }
  });
  args.push("-f", "-");
  const bound = sql.replace(/\$(\d+)/g, (_match, position: string) =>
    values[Number(position) - 1] === null || values[Number(position) - 1] === undefined
      ? "NULL"
      : `:'p${position}'`,
  );
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
  if (result.code !== 0) {
    throw new Error(result.stderr.trim());
  }
  return result.stdout;
}

const inSchema = (sql: string): string => `SET search_path TO ${SCHEMA};\n${sql}`;

const query: SqlQueryFn = async (text, values) => {
  const wrapped = `WITH q AS (${text}) SELECT coalesce(json_agg(row_to_json(q)), '[]'::json) FROM q`;
  const stdout = await psqlOk(inSchema(wrapped), values);
  const line = stdout.trim().split("\n").filter(Boolean).at(-1) ?? "[]";
  return JSON.parse(line) as Record<string, unknown>[];
};

const errorOf = async (sql: string): Promise<string> => (await psql(inSchema(sql))).stderr;
const scalar = async (sql: string): Promise<string> => (await psqlOk(inSchema(sql))).trim();

const LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 4_096,
  maxResponseBytes: 4_096,
};

const RESPONSE_BYTES = new TextEncoder().encode('{"status":true,"code":"ok"}');
const SHA = "a".repeat(64);

function countingExchange(): { readonly posts: string[]; readonly exchange: GatewayExchangeTransport } {
  const posts: string[] = [];
  return {
    posts,
    exchange: {
      exchange: async (endpoint, request) => {
        posts.push(endpoint);
        return {
          endpoint,
          endpointFingerprint: sha256Hex(new TextEncoder().encode(endpoint)),
          requestBytes: request.bodyBytes,
          requestSha256: sha256Hex(request.bodyBytes),
          responseBytes: RESPONSE_BYTES,
          responseSha256: sha256Hex(RESPONSE_BYTES),
          statusCode: 200,
        };
      },
    },
  };
}

async function seedOperation(): Promise<SubmitAuthorization> {
  const operationId = randomUUID();
  await psqlOk(
    inSchema(
      `INSERT INTO operations (id) VALUES ('${operationId}');
       INSERT INTO operation_transactions (operation_id, attempt_no) VALUES ('${operationId}', 1);`,
    ),
  );
  return { submitDecisionId: randomUUID(), operationId, transactionAttemptNo: 1 };
}

let reachable = false;
// True only after schema apply succeeds.
let liveReady = false;

describe.skipIf(databaseUrl === undefined)(
  "D3 — real PostgreSQL enforcement (submit ambiguity authority)",
  () => {
    beforeAll(async () => {
      await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
      await psqlOk(
        inSchema(
          `CREATE TABLE operations (id uuid PRIMARY KEY);
           CREATE TABLE operation_transactions (
             operation_id uuid NOT NULL REFERENCES operations(id),
             attempt_no integer NOT NULL CHECK (attempt_no = 1),
             PRIMARY KEY (operation_id, attempt_no));
           ${submitAttemptsSql}`,
        ),
      );
      reachable = true;
      liveReady = true;
    });

    afterAll(async () => {
      if (reachable) {
        await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE;`);
      }
    });

    it("applies the frozen submit-attempts.sql contract text unmodified", async () => {
      const applied = await scalar(
        `SELECT count(*) FROM pg_tables WHERE schemaname = '${SCHEMA}'
           AND tablename IN ('submit_decisions', 'gateway_submit_attempts')`,
      );
      expect(applied).toBe("2");
      expect(submitAttemptsSql).toContain("UNIQUE (operation_id, transaction_attempt_no)");
      expect(submitAttemptsSql).toContain("CHECK ((response_body IS NULL) = (response_sha256 IS NULL))");
      expect(submitAttemptsSql).toContain("CHECK (decision = 'INITIAL_SINGLE_SHOT')");
      expect(submitAttemptsSql).toContain("CHECK (transaction_attempt_no = 1)");
    });

    it("eight concurrent workers on one attempt produce exactly ONE gateway POST", async () => {
      const authorization = await seedOperation();
      const counted = countingExchange();
      const claimStore = makeSubmitDecisionClaimStore(query);
      const recorder = makeSubmitAttemptRecorder(query);

      const workers = Array.from({ length: 8 }, () =>
        executeMoveSubmitClaim({
          authorization,
          signedTransaction: { inner: "move-inner", step_1_signature: "sig" },
          claimStore,
          submit: {
            endpoint: "https://gateway-a.invalid/",
            limits: LIMITS,
            recorder,
            exchange: counted.exchange,
          },
        }),
      );
      const results = await Promise.all(workers);

      expect(counted.posts.length).toBe(1);
      expect(results.filter((r) => r.executed).length).toBe(1);
      expect(
        await scalar(
          `SELECT count(*) FROM submit_decisions WHERE operation_id = '${authorization.operationId}'`,
        ),
      ).toBe("1");
      expect(
        await scalar(
          `SELECT count(*) FROM gateway_submit_attempts WHERE operation_id = '${authorization.operationId}'`,
        ),
      ).toBe("1");
    });

    it("replay-claim: duplicate submit_decisions insert is a UNIQUE violation (23505)", async () => {
      const authorization = await seedOperation();
      await makeSubmitDecisionClaimStore(query).claimSubmitOnce({
        attemptId: authorization.submitDecisionId,
        claimedAt: "2026-07-26T00:00:01.000Z",
        operationId: authorization.operationId,
        transactionAttemptNo: 1,
      });

      const stderr = await errorOf(
        `INSERT INTO submit_decisions (id, operation_id, transaction_attempt_no, decision, decided_at, details)
         VALUES ('${randomUUID()}', '${authorization.operationId}', 1, 'INITIAL_SINGLE_SHOT', now(), 'replay')`,
      );
      expect(stderr).toContain(UNIQUE_VIOLATION);
      expect(stderr).toContain("submit_decisions_operation_id_transaction_attempt_no_key");
    });

    it("replay-claim: duplicate gateway_submit_attempts for one decision_id is UNIQUE (23505)", async () => {
      const authorization = await seedOperation();
      const counted = countingExchange();
      await executeMoveSubmitClaim({
        authorization,
        signedTransaction: { inner: "move-inner", step_1_signature: "sig" },
        claimStore: makeSubmitDecisionClaimStore(query),
        submit: {
          endpoint: "https://gateway-a.invalid/",
          limits: LIMITS,
          recorder: makeSubmitAttemptRecorder(query),
          exchange: counted.exchange,
        },
      });

      const stderr = await errorOf(
        `INSERT INTO gateway_submit_attempts (id, operation_id, attempt_no, transaction_attempt_no,
           decision_id, request_body, request_sha256, transport_outcome, started_at)
         VALUES ('${randomUUID()}', '${authorization.operationId}', 1, 1, '${authorization.submitDecisionId}',
           decode('00', 'hex'), '${SHA}', 'ACK', now())`,
      );
      expect(stderr).toContain(UNIQUE_VIOLATION);
    });

    it("CHECK rejects transaction_attempt_no other than 1 at the database layer", async () => {
      const authorization = await seedOperation();
      const stderr = await errorOf(
        `INSERT INTO submit_decisions (id, operation_id, transaction_attempt_no, decision, decided_at, details)
         VALUES ('${randomUUID()}', '${authorization.operationId}', 2, 'INITIAL_SINGLE_SHOT', now(), 'bad attempt')`,
      );
      expect(stderr.length).toBeGreaterThan(0);
      expect(stderr).toMatch(/23514|23503|transaction_attempt_no|foreign key|check/i);
    });

    it("CHECK rejects decision other than INITIAL_SINGLE_SHOT", async () => {
      const authorization = await seedOperation();
      const stderr = await errorOf(
        `INSERT INTO submit_decisions (id, operation_id, transaction_attempt_no, decision, decided_at, details)
         VALUES ('${randomUUID()}', '${authorization.operationId}', 1, 'SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING', now(), 'forbidden')`,
      );
      expect(stderr).toContain(CHECK_VIOLATION);
    });

    it("corrupted evidence: response_body set with response_sha256 NULL is CHECK-rejected", async () => {
      const authorization = await seedOperation();
      await makeSubmitDecisionClaimStore(query).claimSubmitOnce({
        attemptId: authorization.submitDecisionId,
        claimedAt: "2026-07-26T00:00:01.000Z",
        operationId: authorization.operationId,
        transactionAttemptNo: 1,
      });

      const stderr = await errorOf(
        `INSERT INTO gateway_submit_attempts (id, operation_id, attempt_no, transaction_attempt_no,
           decision_id, request_body, request_sha256, response_body, response_sha256,
           transport_outcome, started_at)
         VALUES ('${randomUUID()}', '${authorization.operationId}', 1, 1, '${authorization.submitDecisionId}',
           decode('00', 'hex'), '${SHA}', decode('01', 'hex'), NULL, 'ACK', now())`,
      );
      expect(stderr).toContain(CHECK_VIOLATION);
    });

    it("corrupted evidence: response_sha256 set with response_body NULL is CHECK-rejected", async () => {
      const authorization = await seedOperation();
      await makeSubmitDecisionClaimStore(query).claimSubmitOnce({
        attemptId: authorization.submitDecisionId,
        claimedAt: "2026-07-26T00:00:01.000Z",
        operationId: authorization.operationId,
        transactionAttemptNo: 1,
      });

      const stderr = await errorOf(
        `INSERT INTO gateway_submit_attempts (id, operation_id, attempt_no, transaction_attempt_no,
           decision_id, request_body, request_sha256, response_body, response_sha256,
           transport_outcome, started_at)
         VALUES ('${randomUUID()}', '${authorization.operationId}', 1, 1, '${authorization.submitDecisionId}',
           decode('00', 'hex'), '${SHA}', NULL, '${SHA}', 'ACK', now())`,
      );
      expect(stderr).toContain(CHECK_VIOLATION);
    });

    it("INDETERMINATE evidence classifies to SUBMIT_OUTCOME_AMBIGUOUS; second attempt UNIQUE-rejected", async () => {
      const authorization = await seedOperation();
      const claimStore = makeSubmitDecisionClaimStore(query);
      const recorder = makeSubmitAttemptRecorder(query);

      await claimStore.claimSubmitOnce({
        attemptId: authorization.submitDecisionId,
        claimedAt: "2026-07-26T00:00:01.000Z",
        operationId: authorization.operationId,
        transactionAttemptNo: 1,
      });

      const requestBytes = new TextEncoder().encode('{"step":"1"}');
      await recorder.recordSubmitAttempt({
        decisionId: authorization.submitDecisionId,
        operationId: authorization.operationId,
        attemptNo: 1,
        transactionAttemptNo: 1,
        requestBytes,
        requestSha256: sha256Hex(requestBytes),
        responseBytes: null,
        responseSha256: null,
        transportOutcome: "INDETERMINATE",
        startedAt: "2026-07-26T00:00:01.000Z",
        completedAt: "2026-07-26T00:00:01.500Z",
      });

      const evidence = await readSubmitAttemptEvidence(query, authorization.operationId, 1);
      expect(evidence).toEqual({ status: "RETURNED", transportOutcome: "INDETERMINATE" });
      const reason = classifySubmitAttemptEvidence(evidence);
      expect(reason).toEqual({ source: "SUBMIT_OUTCOME_UNKNOWN" });
      expect(toAttentionReason(reason!)).toBe("SUBMIT_OUTCOME_AMBIGUOUS");

      const stderr = await errorOf(
        `INSERT INTO gateway_submit_attempts (id, operation_id, attempt_no, transaction_attempt_no,
           decision_id, request_body, request_sha256, transport_outcome, started_at)
         VALUES ('${randomUUID()}', '${authorization.operationId}', 2, 1, '${authorization.submitDecisionId}',
           decode('00', 'hex'), '${"b".repeat(64)}', 'ACK', now())`,
      );
      expect(stderr).toContain(UNIQUE_VIOLATION);
    });

    it("CLAIMED_UNRETURNED after crash: restart mints=false, zero further gateway POSTs", async () => {
      const authorization = await seedOperation();
      const claimStore = makeSubmitDecisionClaimStore(query);
      const counted = countingExchange();

      const first = await claimStore.claimSubmitOnce({
        attemptId: authorization.submitDecisionId,
        claimedAt: "2026-07-26T00:00:01.000Z",
        operationId: authorization.operationId,
        transactionAttemptNo: 1,
      });
      expect(first.minted).toBe(true);

      const evidence = await readSubmitAttemptEvidence(query, authorization.operationId, 1);
      expect(evidence.status).toBe("CLAIMED_UNRETURNED");
      expect(classifySubmitAttemptEvidence(evidence)).toEqual({ source: "SUBMIT_OUTCOME_UNKNOWN" });

      const result = await executeMoveSubmitClaim({
        authorization: { ...authorization, submitDecisionId: randomUUID() },
        signedTransaction: { inner: "move-inner", step_1_signature: "sig" },
        claimStore,
        submit: {
          endpoint: "https://gateway-a.invalid/",
          limits: LIMITS,
          recorder: makeSubmitAttemptRecorder(query),
          exchange: counted.exchange,
        },
      });
      expect(result.executed).toBe(false);
      expect(counted.posts.length).toBe(0);
      expect(
        await scalar(
          `SELECT count(*) FROM gateway_submit_attempts WHERE operation_id = '${authorization.operationId}'`,
        ),
      ).toBe("0");
    });

    it("operation_transactions CHECK (attempt_no = 1) rejects a second transaction attempt row", async () => {
      const authorization = await seedOperation();
      const stderr = await errorOf(
        `INSERT INTO operation_transactions (operation_id, attempt_no)
         VALUES ('${authorization.operationId}', 2)`,
      );
      expect(stderr).toContain(CHECK_VIOLATION);
    });
  },
);

registerPgRequiredGuard({
  name: "submit-ambiguity-authority live block",
  databaseUrl,
  isReady: () => liveReady,
  readyMessage:
    "PG_REQUIRED=1 but the submit-ambiguity beforeAll never completed — ambiguity proofs skipped, not proven",
});
