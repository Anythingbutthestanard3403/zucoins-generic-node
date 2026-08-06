// Real-PostgreSQL proof that the single-shot submit claim is arbitrated by the database.
// Governing: the data model (submit_decisions /
// gateway_submit_attempts uniqueness) and mandatory database test 10 ("a second transaction attempt, submit
// decision, or submit call for one operation fails"); operation flows step 9;
// the never-blind-retry rule (never blind-retry a submit).
//
// The blocking defect this suite exists to catch: two workers racing one attempt each POSTing
// the same signed transaction. An in-process fake cannot prove the cure, because the arbiter
// under test IS the UNIQUE constraint. So the DDL applied here is the frozen contract text of
// src/schema/submit-attempts.sql, verbatim, and the concurrent workers run through the real
// makeSubmitDecisionClaimStore against it.
//
// operations / operation_transactions are the FK targets no slice in this package creates
// (the documented schema-apply / reconciliation gap, test/migration-integrity.test.ts).
// They are stubbed here to exactly the columns the FKs reference — the tables under test are
// applied from the frozen file, never retyped.
//
// psql runs as a child process (node:child_process), which keeps the in-process
// network-containment guard intact — as migration-integrity.test.ts and
// node-implementer-registry.pg.test.ts already do.

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
import { toAttentionReason } from "../src/protocol/reconcile/types.ts";
import { sha256Hex, type GatewayExchangeTransport } from "../src/gateway/capture.ts";
import type { SubmitAuthorization } from "../src/gateway/submit.ts";
import type { GatewayLimits } from "../src/gateway/types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const submitAttemptsSql = readFileSync(resolve(here, "../src/schema/submit-attempts.sql"), "utf8");

const SCHEMA = "submit_decision_claim_submit_decision_claims";
const UNIQUE_VIOLATION = "23505";

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

// Test-only stand-in for a driver's parameter binding: psql has no wire-protocol parameters,
// so each $n is spliced as a psql variable reference, which psql quotes and escapes. SQL is
// fed on stdin rather than -c because psql expands variables only in lexed input.
// VERBOSITY=verbose makes it print the SQLSTATE, which the negative tests assert on.
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

// Wrapping every statement in a data-modifying CTE that aggregates to JSON makes the result
// shape uniform regardless of whether the statement is a SELECT or an INSERT ... RETURNING,
// so the adapter never has to parse psql's textual table output.
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

// Each test owns a fresh operation so the UNIQUE (operation_id, transaction_attempt_no) key is
// never shared between tests.
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
  "submit claim arbitration against a live PostgreSQL",
  () => {
    beforeAll(async () => {
      await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
      await psqlOk(
        inSchema(
          `CREATE TABLE operations (id uuid PRIMARY KEY);
           CREATE TABLE operation_transactions (
             operation_id uuid NOT NULL REFERENCES operations(id),
             attempt_no integer NOT NULL,
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
    });

    // The blocking defect, reproduced as a race and proven cured: eight workers, one attempt.
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
          submit: { endpoint: "https://gateway-a.invalid/", limits: LIMITS, recorder, exchange: counted.exchange },
        }),
      );
      const results = await Promise.all(workers);

      expect(counted.posts.length).toBe(1);
      expect(results.filter((result) => result.executed).length).toBe(1);
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
      // Every worker holds the same durable claim; only the winner carries an outcome.
      const attemptIds = new Set(results.map((result) => result.claim.attemptId));
      expect(attemptIds.size).toBe(1);
      expect(results.filter((result) => result.recordedOutcome !== null).length).toBe(1);
    });

    it("the database, not a prior read, decides the mint: a repeat call reports minted=false", async () => {
      const authorization = await seedOperation();
      const claimStore = makeSubmitDecisionClaimStore(query);
      const attempt = {
        attemptId: authorization.submitDecisionId,
        claimedAt: "2026-07-21T00:00:01.000Z",
        operationId: authorization.operationId,
        transactionAttemptNo: 1,
      };

      const first = await claimStore.claimSubmitOnce(attempt);
      expect(first.minted).toBe(true);
      expect(first.claim.attemptId).toBe(authorization.submitDecisionId);
      expect(first.claim.claimedAt).toBe("2026-07-21T00:00:01.000Z");

      // A different worker minting a different decision id for the SAME attempt loses, and is
      // handed the winner's claim — not its own.
      const second = await claimStore.claimSubmitOnce({ ...attempt, attemptId: randomUUID() });
      expect(second.minted).toBe(false);
      expect(second.claim.attemptId).toBe(authorization.submitDecisionId);
    });

    it("a second submit_decisions row for one attempt is a UNIQUE violation, not an app check", async () => {
      const authorization = await seedOperation();
      await makeSubmitDecisionClaimStore(query).claimSubmitOnce({
        attemptId: authorization.submitDecisionId,
        claimedAt: "2026-07-21T00:00:01.000Z",
        operationId: authorization.operationId,
        transactionAttemptNo: 1,
      });

      const stderr = await errorOf(
        `INSERT INTO submit_decisions (id, operation_id, transaction_attempt_no, decision, decided_at, details)
         VALUES ('${randomUUID()}', '${authorization.operationId}', 1, 'INITIAL_SINGLE_SHOT', now(), 'second decision')`,
      );
      expect(stderr).toContain(UNIQUE_VIOLATION);
      expect(stderr).toContain("submit_decisions_operation_id_transaction_attempt_no_key");
    });

    it("a second gateway_submit_attempts row for one attempt is a UNIQUE violation", async () => {
      const authorization = await seedOperation();
      const counted = countingExchange();
      await executeMoveSubmitClaim({
        authorization,
        signedTransaction: { inner: "move-inner", step_1_signature: "sig" },
        claimStore: makeSubmitDecisionClaimStore(query),
        submit: { endpoint: "https://gateway-a.invalid/", limits: LIMITS, recorder: makeSubmitAttemptRecorder(query), exchange: counted.exchange },
      });

      const stderr = await errorOf(
        `INSERT INTO gateway_submit_attempts (id, operation_id, attempt_no, transaction_attempt_no,
           decision_id, request_body, request_sha256, transport_outcome, started_at)
         VALUES ('${randomUUID()}', '${authorization.operationId}', 1, 1, '${authorization.submitDecisionId}',
           decode('00', 'hex'), '${"a".repeat(64)}', 'ACK', now())`,
      );
      expect(stderr).toContain(UNIQUE_VIOLATION);
    });

    it("persists the exact request and response bytes and their digests verbatim", async () => {
      const authorization = await seedOperation();
      const counted = countingExchange();
      const result = await executeMoveSubmitClaim({
        authorization,
        signedTransaction: { inner: "move-inner", step_1_signature: "sig" },
        claimStore: makeSubmitDecisionClaimStore(query),
        submit: { endpoint: "https://gateway-a.invalid/", limits: LIMITS, recorder: makeSubmitAttemptRecorder(query), exchange: counted.exchange },
      });
      expect(result.executed).toBe(true);

      const stored = await scalar(
        `SELECT encode(request_body, 'hex') || ' ' || request_sha256 || ' ' ||
                encode(response_body, 'hex') || ' ' || response_sha256 || ' ' || transport_outcome
         FROM gateway_submit_attempts WHERE operation_id = '${authorization.operationId}'`,
      );
      const recorded = result.recordedOutcome?.recordedAttempt;
      const hex = (bytes: Uint8Array | null | undefined): string =>
        Buffer.from(bytes ?? new Uint8Array()).toString("hex");
      expect(stored).toBe(
        `${hex(recorded?.requestBytes)} ${recorded?.requestSha256} ${hex(recorded?.responseBytes)} ${recorded?.responseSha256} ACK`,
      );
      expect(recorded?.responseSha256).toBe(sha256Hex(RESPONSE_BYTES));
    });

    it("rejects a transaction_attempt_no other than 1 at the CHECK constraint", async () => {
      const authorization = await seedOperation();
      await psqlOk(
        inSchema(
          `INSERT INTO operation_transactions (operation_id, attempt_no) VALUES ('${authorization.operationId}', 2);`,
        ),
      );
      await expect(
        makeSubmitDecisionClaimStore(query).claimSubmitOnce({
          attemptId: randomUUID(),
          claimedAt: "2026-07-21T00:00:01.000Z",
          operationId: authorization.operationId,
          transactionAttemptNo: 2,
        }),
      ).rejects.toThrow(/transaction_attempt_no/);
    });

    // review indicator: crash after the claim is durable (submit_decisions row)
    // but before any gateway_submit_attempts row is written — the STARTED-equivalent under
    // the insert-only regime (transport_outcome is NOT NULL, so "in flight" is the ABSENCE
    // of an attempt row, not a partial one). On restart the evidence must classify as
    // SUBMIT_OUTCOME_AMBIGUOUS, authorize zero further gateway calls, and leave exactly
    // one claim row / zero attempt rows.
    it("crash after claim, before attempt return: one STARTED claim, zero gateway calls on restart", async () => {
      const authorization = await seedOperation();
      const claimStore = makeSubmitDecisionClaimStore(query);
      const counted = countingExchange();

      const first = await claimStore.claimSubmitOnce({
        attemptId: authorization.submitDecisionId,
        claimedAt: "2026-07-21T00:00:01.000Z",
        operationId: authorization.operationId,
        transactionAttemptNo: 1,
      });
      expect(first.minted).toBe(true);

      // Crash window: claim durable, no gateway_submit_attempts row, zero POSTs yet.
      expect(
        await scalar(
          `SELECT count(*) FROM submit_decisions WHERE operation_id = '${authorization.operationId}'`,
        ),
      ).toBe("1");
      expect(
        await scalar(
          `SELECT count(*) FROM gateway_submit_attempts WHERE operation_id = '${authorization.operationId}'`,
        ),
      ).toBe("0");
      expect(counted.posts.length).toBe(0);

      const evidence = await readSubmitAttemptEvidence(
        query,
        authorization.operationId,
        authorization.transactionAttemptNo,
      );
      expect(evidence).toEqual({ status: "CLAIMED_UNRETURNED", transportOutcome: null });

      const reason = classifySubmitAttemptEvidence(evidence);
      expect(reason).toEqual({ source: "SUBMIT_OUTCOME_UNKNOWN" });
      expect(toAttentionReason(reason!)).toBe("SUBMIT_OUTCOME_AMBIGUOUS");

      // Restart-equivalent: re-claim. Database hands back the existing claim; mint is false,
      // so the MOVE_INTERNAL path refuses a second POST (executeMoveSubmitClaim only posts
      // when minted=true). Zero further gateway calls.
      const restart = await claimStore.claimSubmitOnce({
        attemptId: randomUUID(),
        claimedAt: "2026-07-21T00:00:02.000Z",
        operationId: authorization.operationId,
        transactionAttemptNo: 1,
      });
      expect(restart.minted).toBe(false);
      expect(restart.claim.attemptId).toBe(authorization.submitDecisionId);

      // Classifier output is never a submit-authority token — a second attempt INSERT for
      // this claim is unrepresentable at the UNIQUE constraint even if a caller ignored
      // minted=false and tried to record one (no decision_id may own two attempt rows).
      expect(counted.posts.length).toBe(0);
      expect(
        await scalar(
          `SELECT count(*) FROM submit_decisions WHERE operation_id = '${authorization.operationId}'`,
        ),
      ).toBe("1");
      expect(
        await scalar(
          `SELECT count(*) FROM gateway_submit_attempts WHERE operation_id = '${authorization.operationId}'`,
        ),
      ).toBe("0");
    });

    it("read path classifies RETURNED INDETERMINATE as SUBMIT_OUTCOME_AMBIGUOUS and ACK as not ambiguous", async () => {
      const authorization = await seedOperation();
      const claimStore = makeSubmitDecisionClaimStore(query);
      const recorder = makeSubmitAttemptRecorder(query);

      const claim = await claimStore.claimSubmitOnce({
        attemptId: authorization.submitDecisionId,
        claimedAt: "2026-07-21T00:00:01.000Z",
        operationId: authorization.operationId,
        transactionAttemptNo: 1,
      });
      expect(claim.minted).toBe(true);

      // Before any attempt row: NOT yet returned.
      expect(
        await readSubmitAttemptEvidence(query, authorization.operationId, 1),
      ).toEqual({ status: "CLAIMED_UNRETURNED", transportOutcome: null });

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
        startedAt: "2026-07-21T00:00:01.000Z",
        completedAt: "2026-07-21T00:00:01.500Z",
      });

      const indeterminate = await readSubmitAttemptEvidence(query, authorization.operationId, 1);
      expect(indeterminate).toEqual({ status: "RETURNED", transportOutcome: "INDETERMINATE" });
      const reason = classifySubmitAttemptEvidence(indeterminate);
      expect(reason).toEqual({ source: "SUBMIT_OUTCOME_UNKNOWN" });
      expect(toAttentionReason(reason!)).toBe("SUBMIT_OUTCOME_AMBIGUOUS");

      // A second attempt INSERT for the same (operation_id, transaction_attempt_no) is
      // rejected by UNIQUE — INDETERMINATE evidence cannot authorize another submit row.
      const stderr = await errorOf(
        `INSERT INTO gateway_submit_attempts (id, operation_id, attempt_no, transaction_attempt_no,
           decision_id, request_body, request_sha256, transport_outcome, started_at)
         VALUES ('${randomUUID()}', '${authorization.operationId}', 2, 1, '${authorization.submitDecisionId}',
           decode('00', 'hex'), '${"b".repeat(64)}', 'ACK', now())`,
      );
      expect(stderr).toContain(UNIQUE_VIOLATION);

      // Separate operation with a definite ACK is not ambiguous.
      const ackAuth = await seedOperation();
      await claimStore.claimSubmitOnce({
        attemptId: ackAuth.submitDecisionId,
        claimedAt: "2026-07-21T00:00:03.000Z",
        operationId: ackAuth.operationId,
        transactionAttemptNo: 1,
      });
      await recorder.recordSubmitAttempt({
        decisionId: ackAuth.submitDecisionId,
        operationId: ackAuth.operationId,
        attemptNo: 1,
        transactionAttemptNo: 1,
        requestBytes,
        requestSha256: sha256Hex(requestBytes),
        responseBytes: RESPONSE_BYTES,
        responseSha256: sha256Hex(RESPONSE_BYTES),
        transportOutcome: "ACK",
        startedAt: "2026-07-21T00:00:03.000Z",
        completedAt: "2026-07-21T00:00:03.100Z",
      });
      const ackEvidence = await readSubmitAttemptEvidence(query, ackAuth.operationId, 1);
      expect(ackEvidence).toEqual({ status: "RETURNED", transportOutcome: "ACK" });
      expect(classifySubmitAttemptEvidence(ackEvidence)).toBeNull();
      expect(
        classifySubmitAttemptEvidence({ status: "NOT_CLAIMED", transportOutcome: null }),
      ).toBeNull();
    });
  },
);

registerPgRequiredGuard({
  name: "submit-decision-claim-store live block",
  databaseUrl,
  isReady: () => liveReady,
  readyMessage:
    "PG_REQUIRED=1 but the submit-decision-claim beforeAll never completed — claim proofs skipped, not proven",
});
