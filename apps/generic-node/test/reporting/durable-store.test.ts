// money-path tests for DurableReportingRequestStore. They run against a FAKE injected
// ReportingQueryClient (no socket — the package network guard is active), scripting the exact
// Postgres responses the frozen reporting_lock_and_assert_admission function and the frozen
// UNIQUE constraints produce, and asserting the store maps each to the right outcome. The burn
// must call the admission function as the AUTHORITY and never replicate its lock/recheck logic.

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import { computeReportingLogicalFingerprint } from "@zucoins/node-core";
import type {
  BurnNonceEvidence,
  BurnNonceRequest,
  CompletedIdempotencyRecord,
} from "@zucoins/node-core";

import {
  createPoolReportingClient,
  DurableReportingRequestStore,
} from "../../src/reporting/durable-store.js";
import type {
  ReportingQueryClient,
  ReportingQueryFn,
  ReportingTransactionFn,
} from "../../src/reporting/pg-client.js";
import { NONCE_EVIDENCE_COLUMNS, nonceEvidenceParams } from "../../src/reporting/row-mappers.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const KEY_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const NONCE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const EPOCH = 7n;
const RECEIVED_AT_MS = Date.parse("2026-07-18T00:00:30.000Z");
const CONSUMED_AT_MS = Date.parse("2026-07-18T00:00:30.050Z");
const ISSUED_AT = "2026-07-18T00:00:00.000Z";
const EXPIRES_AT = "2026-07-18T00:00:45.000Z";
const METHOD = "POST";
const RAW_TARGET = "/v1/operations/33333333-3333-4333-8333-333333333333/verification-complete";
const BODY_SHA256 = "ab".repeat(32);

// node-postgres attaches `constraint` (the violated constraint's name) as a structured field on
// integrity errors, alongside `code`. The store discriminates a 23505 by this field, NOT by the
// message text, so the fake must set it exactly as the driver would.
function pgError(code: string, message: string, constraint?: string): Error {
  const err = new Error(message);
  (err as Error & { code: string; constraint?: string }).code = code;
  if (constraint !== undefined) {
    (err as Error & { constraint?: string }).constraint = constraint;
  }
  return err;
}

// The real, DB-verified Postgres constraint names (see the real-PG suite below). Postgres
// truncates generated names to 63 bytes — note the idempotency-key guard's missing trailing "y".
const NONCE_REPLAY_GUARD = "reporting_request_nonces_node_id_implementer_id_nonce_key";
const NONCE_SEQUENCE_GUARD = "reporting_request_nonces_node_id_nonce_burn_sequence_key";
const IDEMPOTENCY_KEY_GUARD = "reporting_mutation_idempotenc_node_id_implementer_id_route__key";
const IDEMPOTENCY_NONCE_GUARD = "reporting_mutation_idempotency_reporting_nonce_id_key";
const IDEMPOTENCY_PK_GUARD = "reporting_mutation_idempotency_pkey";

function burnEvidence(): BurnNonceEvidence {
  return {
    nodeId: NODE_ID,
    implementerId: IMPLEMENTER_ID,
    nonce: NONCE,
    purpose: "zp-report-request-v1",
    routeId: "verification_complete",
    requestClass: "MUTATION",
    reportingKeyId: KEY_ID,
    lifecycleEpoch: EPOCH,
    requestPreimageText: "preimage",
    requestPreimageSha256: "cd".repeat(32),
    requestSignature: `${"A".repeat(86)}==`,
    method: METHOD,
    rawTarget: RAW_TARGET,
    bodySha256: BODY_SHA256,
    logicalFingerprint: computeReportingLogicalFingerprint(METHOD, RAW_TARGET, BODY_SHA256),
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    receivedAtMs: RECEIVED_AT_MS,
    consumedAtMs: CONSUMED_AT_MS,
    retentionClass: "PERMANENT_MUTATION",
  };
}

function burnRequest(): BurnNonceRequest {
  return { expectedEpoch: EPOCH, evidence: burnEvidence() };
}

function idempotencyRecord(overrides: Partial<CompletedIdempotencyRecord> = {}): CompletedIdempotencyRecord {
  return {
    id: "99999999-9999-4999-8999-999999999999",
    nodeId: NODE_ID,
    implementerId: IMPLEMENTER_ID,
    routeId: "verification_complete",
    idempotencyKey: "key-0123456789ab",
    reportingNonceId: "88888888-8888-4888-8888-888888888888",
    childRecordId: "77777777-7777-4777-8777-777777777777",
    method: METHOD,
    rawTarget: RAW_TARGET,
    bodySha256: BODY_SHA256,
    logicalFingerprint: computeReportingLogicalFingerprint(METHOD, RAW_TARGET, BODY_SHA256),
    responseStatus: 200,
    responseBytes: new Uint8Array([1, 2, 3]),
    completedAtMs: CONSUMED_AT_MS,
    ...overrides,
  };
}

// ---- the fake injected client ----

interface FakeClient extends ReportingQueryClient {
  readonly calls: { text: string; params: readonly unknown[] }[];
  /** Every BEGIN/COMMIT/ROLLBACK boundary observed by `transact` (atomicity oracle). */
  readonly txnLog: string[];
  /** Count of `transact` invocations (must be exactly 1 per UoW call). */
  readonly transactCalls: { count: number };
}

interface HandlerResult {
  rows?: readonly Record<string, unknown>[];
  throw?: Error;
}

type Handler = (
  text: string,
  params: readonly unknown[],
) => HandlerResult | undefined;

// Routes by SQL substring. Handlers return undefined to fall through to the default. The default
// models the happy admission path: both existence probes find their row, the admission function
// returns void, the counter allocates sequence 1, and the nonce insert returns its row.
//
// `transact` mirrors createPoolReportingClient: BEGIN → body(txQuery) → COMMIT, or ROLLBACK on
// throw. Autocommit `query` and in-txn `txQuery` push to distinct call journals so tests can
// prove child + parent writes rode the transaction query fn, not autocommit.
function makeFake(handlers: Handler[] = [], nonceBurnSequence = "1"): FakeClient {
  const calls: { text: string; params: readonly unknown[] }[] = [];
  const txnLog: string[] = [];
  const transactCalls = { count: 0 };
  const exec = (text: string, params: readonly unknown[]): HandlerResult => {
    for (const handler of handlers) {
      const result = handler(text, params);
      if (result !== undefined) return result;
    }
    if (text.includes("FROM reporting_restore_state")) return { rows: [{ "?column?": 1 }] };
    if (text.includes("FROM reporting_key_lifecycle_heads")) return { rows: [{ "?column?": 1 }] };
    if (text.includes("reporting_lock_and_assert_admission")) return { rows: [] };
    if (text.includes("UPDATE reporting_nonce_burn_counters")) {
      return { rows: [{ nonce_burn_sequence: nonceBurnSequence }] };
    }
    if (text.includes("INSERT INTO reporting_request_nonces")) {
      return {
        rows: [
          {
            id: params[0],
            nonce_burn_sequence: nonceBurnSequence,
            logical_fingerprint: computeReportingLogicalFingerprint(
              String(params[13]),
              String(params[14]),
              String(params[15]),
            ),
          },
        ],
      };
    }
    return { rows: [] };
  };
  const run = (text: string, params: readonly unknown[]): HandlerResult => {
    calls.push({ text, params });
    return exec(text, params);
  };
  const query: ReportingQueryFn = async (text, params = []) => {
    const result = run(text, params);
    if (result.throw) throw result.throw;
    return result.rows ?? [];
  };
  const transact: ReportingTransactionFn = async (body) => {
    transactCalls.count += 1;
    txnLog.push("BEGIN");
    // In-txn query journal — separate from autocommit `calls` so UoW tests can prove writes
    // did not leak onto the autocommit path.
    const txCalls: { text: string; params: readonly unknown[] }[] = [];
    const txQuery: ReportingQueryFn = async (text, params = []) => {
      txCalls.push({ text, params });
      calls.push({ text, params }); // keep existing burn assertions that scan calls[]
      const result = exec(text, params);
      if (result.throw) throw result.throw;
      return result.rows ?? [];
    };
    try {
      const result = await body(txQuery);
      txnLog.push("COMMIT");
      // Expose the last txn's in-txn call list on the fake for UoW assertions.
      (transact as { lastTxCalls?: typeof txCalls }).lastTxCalls = txCalls;
      return result;
    } catch (err) {
      txnLog.push("ROLLBACK");
      (transact as { lastTxCalls?: typeof txCalls }).lastTxCalls = txCalls;
      throw err;
    }
  };
  return { query, transact, calls, txnLog, transactCalls };
}

const admissionCalls = (fake: FakeClient) =>
  fake.calls.filter((call) => call.text.includes("reporting_lock_and_assert_admission"));

describe("DurableReportingRequestStore.burnNonceAtomically", () => {
  it("happy path burns, allocating the sequence and reading logical_fingerprint via RETURNING", async () => {
    const fake = makeFake([], "42");
    const store = new DurableReportingRequestStore(fake);

    const outcome = await store.burnNonceAtomically(burnRequest());

    expect(outcome.kind).toBe("BURNED");
    if (outcome.kind !== "BURNED") return;
    expect(outcome.evidence.nonceBurnSequence).toBe(42n);
    expect(outcome.evidence.logicalFingerprint).toBe(
      computeReportingLogicalFingerprint(METHOD, RAW_TARGET, BODY_SHA256),
    );
    expect(outcome.evidence.nonce).toBe(NONCE);
    // The logical fingerprint is GENERATED: it is read back via RETURNING, never supplied on
    // INSERT. The insert column list (before VALUES) must omit it; the returned id/sequence come
    // straight back from the RETURNING projection.
    const insert = fake.calls.find((call) => call.text.includes("INSERT INTO reporting_request_nonces"));
    expect(insert).toBeDefined();
    const columnList = insert?.text.split("VALUES")[0] ?? "";
    expect(columnList).not.toContain("logical_fingerprint");
    expect(insert?.text).toContain("RETURNING id, nonce_burn_sequence, logical_fingerprint");
    expect(outcome.evidence.id).toBe(insert?.params[0]);
  });

  it("calls the frozen admission function as the authority, passing epoch/key/received_at", async () => {
    const fake = makeFake();
    const store = new DurableReportingRequestStore(fake);

    await store.burnNonceAtomically(burnRequest());

    const admissions = admissionCalls(fake);
    expect(admissions).toHaveLength(1);
    expect(admissions[0].params).toEqual([
      NODE_ID,
      IMPLEMENTER_ID,
      EPOCH.toString(),
      KEY_ID,
      new Date(RECEIVED_AT_MS).toISOString(),
    ]);
    // The store does not replicate the admission logic: it issues no FOR UPDATE lock of its own
    // and rechecks nothing — the function call is the single admission gate inside the burn.
    expect(
      fake.calls.some((call) => /FOR UPDATE/i.test(call.text) && !call.text.includes("assert_admission")),
    ).toBe(false);
  });

  it("maps a UNIQUE(node_id, implementer_id, nonce) violation on the second burn to REPLAY", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("INSERT INTO reporting_request_nonces")
          ? {
              throw: pgError(
                "23505",
                'duplicate key value violates unique constraint "reporting_request_nonces_node_id_implementer_id_nonce_key"',
                NONCE_REPLAY_GUARD,
              ),
            }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    const outcome = await store.burnNonceAtomically(burnRequest());

    expect(outcome).toEqual({ kind: "REPLAY" });
    // Admission still ran first (the replay is decided by the unique insert, after admission).
    expect(admissionCalls(fake)).toHaveLength(1);
    // Gapless: the replay MUST roll the burn-sequence allocation
    // back to the savepoint so no sequence value is consumed. The counter UPDATE ran (it is inside
    // the savepoint) but is undone by the ROLLBACK TO SAVEPOINT — matching the reference adapter,
    // which never allocates on replay.
    const seqIdx = fake.calls.findIndex((c) => c.text.includes("UPDATE reporting_nonce_burn_counters"));
    const rollbackIdx = fake.calls.findIndex((c) => c.text.includes("ROLLBACK TO SAVEPOINT"));
    expect(seqIdx).toBeGreaterThanOrEqual(0);
    expect(rollbackIdx).toBeGreaterThan(seqIdx);
  });

  it("THROWS (does not REPLAY) on a 23505 against the burn-sequence guard, without rolling back to the savepoint", async () => {
    // A 23505 on UNIQUE(node_id, nonce_burn_sequence) — reachable on PITR / logical restore /
    // counter rewind — is a real money-path integrity failure, NOT a benign replay. The store must
    // rethrow so transact ROLLBACKs the whole burn and the error surfaces/alarms, and must NOT
    // fold it into REPLAY (which would silently swallow a corrupt counter and lose the request).
    const fake = makeFake([
      (text) =>
        text.includes("INSERT INTO reporting_request_nonces")
          ? {
              throw: pgError(
                "23505",
                'duplicate key value violates unique constraint "reporting_request_nonces_node_id_nonce_burn_sequence_key"',
                NONCE_SEQUENCE_GUARD,
              ),
            }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    await expect(store.burnNonceAtomically(burnRequest())).rejects.toThrow(/nonce_burn_sequence/);
    // It rethrows for the outer ROLLBACK — it does NOT swallow the error via a savepoint rollback.
    expect(fake.calls.some((c) => c.text.includes("ROLLBACK TO SAVEPOINT"))).toBe(false);
  });

  it("THROWS on a nameless 23505 (fail-closed: an unattributed unique violation is never a benign REPLAY)", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("INSERT INTO reporting_request_nonces")
          ? { throw: pgError("23505", "duplicate key value violates unique constraint") }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    await expect(store.burnNonceAtomically(burnRequest())).rejects.toThrow();
  });

  it("maps 55000 'reporting restore hold is active' to HOLD", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("reporting_lock_and_assert_admission")
          ? { throw: pgError("55000", "reporting restore hold is active") }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    expect(await store.burnNonceAtomically(burnRequest())).toEqual({ kind: "HOLD" });
  });

  it("maps 55000 'reporting lifecycle admission is closed' to LIFECYCLE_RECHECK_FAILED", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("reporting_lock_and_assert_admission")
          ? { throw: pgError("55000", "reporting lifecycle admission is closed") }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    expect(await store.burnNonceAtomically(burnRequest())).toEqual({
      kind: "LIFECYCLE_RECHECK_FAILED",
    });
  });

  it("maps P0002 with a missing restore_state row to HOLD", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("FROM reporting_restore_state") ? { rows: [] } : undefined,
      (text) =>
        text.includes("reporting_lock_and_assert_admission")
          ? { throw: pgError("P0002", "query returned no rows") }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    expect(await store.burnNonceAtomically(burnRequest())).toEqual({ kind: "HOLD" });
  });

  it("maps P0002 with a missing lifecycle head row to LIFECYCLE_RECHECK_FAILED", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("FROM reporting_key_lifecycle_heads") ? { rows: [] } : undefined,
      (text) =>
        text.includes("reporting_lock_and_assert_admission")
          ? { throw: pgError("P0002", "query returned no rows") }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    expect(await store.burnNonceAtomically(burnRequest())).toEqual({
      kind: "LIFECYCLE_RECHECK_FAILED",
    });
  });

  it("seeds the burn counter idempotently before the burn transaction", async () => {
    const fake = makeFake();
    const store = new DurableReportingRequestStore(fake);

    await store.burnNonceAtomically(burnRequest());

    const seed = fake.calls.find((call) =>
      call.text.includes("INSERT INTO reporting_nonce_burn_counters"),
    );
    expect(seed).toBeDefined();
    expect(seed?.text).toContain("ON CONFLICT (node_id) DO NOTHING");
    const seedIndex = fake.calls.indexOf(seed as { text: string; params: readonly unknown[] });
    const admissionIndex = fake.calls.findIndex((call) =>
      call.text.includes("reporting_lock_and_assert_admission"),
    );
    expect(seedIndex).toBeLessThan(admissionIndex);
  });
});

describe("DurableReportingRequestStore.insertCompletedIdempotency", () => {
  it("returns INSERTED then CONFLICT on a duplicate idempotency key", async () => {
    let inserted = false;
    const fake = makeFake([
      (text) => {
        if (!text.includes("INSERT INTO reporting_mutation_idempotency")) return undefined;
        if (inserted) {
          return {
            throw: pgError(
              "23505",
              'duplicate key value violates unique constraint "reporting_mutation_idempotenc_node_id_implementer_id_route__key"',
              IDEMPOTENCY_KEY_GUARD,
            ),
          };
        }
        inserted = true;
        return { rows: [] };
      },
    ]);
    const store = new DurableReportingRequestStore(fake);

    expect(await store.insertCompletedIdempotency(idempotencyRecord())).toEqual({
      kind: "INSERTED",
    });
    expect(await store.insertCompletedIdempotency(idempotencyRecord())).toEqual({
      kind: "CONFLICT",
    });
  });

  it("THROWS (does not CONFLICT) on a 23505 against a non-idempotency guard (e.g. reporting_nonce_id)", async () => {
    // The completed-idempotency row also carries UNIQUE(reporting_nonce_id) and
    // UNIQUE(child_record_id). A 23505 on either means the same nonce/child is being bound to a
    // DIFFERENT completion — an integrity failure, not an idempotent replay. It must surface, not
    // be folded into CONFLICT (which would drop a mutation completion and swallow the corruption).
    const fake = makeFake([
      (text) =>
        text.includes("INSERT INTO reporting_mutation_idempotency")
          ? {
              throw: pgError(
                "23505",
                'duplicate key value violates unique constraint "reporting_mutation_idempotency_reporting_nonce_id_key"',
                IDEMPOTENCY_NONCE_GUARD,
              ),
            }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    await expect(store.insertCompletedIdempotency(idempotencyRecord())).rejects.toThrow(
      /reporting_nonce_id/,
    );
  });

  it("rejects a record missing a mandatory completion field (never a request outcome)", async () => {
    const fake = makeFake();
    const store = new DurableReportingRequestStore(fake);

    await expect(
      store.insertCompletedIdempotency(idempotencyRecord({ responseStatus: 99 })),
    ).rejects.toThrow(/mandatory completion field/);
    // The mandate gate fires before any database write.
    expect(
      fake.calls.some((call) => call.text.includes("INSERT INTO reporting_mutation_idempotency")),
    ).toBe(false);
  });
});


describe("DurableReportingRequestStore.commitMutationWithCompletedIdempotency", () => {
  it("runs persistChild and the completed parent INSERT inside ONE client.transact (BEGIN…COMMIT)", async () => {
    const fake = makeFake();
    const store = new DurableReportingRequestStore(fake);
    const childId = "77777777-7777-4777-8777-777777777777";
    const full = idempotencyRecord({ childRecordId: "ignored" });
    const { childRecordId: _c, ...draft } = full;
    // Autocommit probe: if the store ever wrote outside transact, this would capture it.
    const autocommitBefore = fake.calls.length;
    const outcome = await store.commitMutationWithCompletedIdempotency({
      persistChild: async (tx) => {
        expect(typeof tx.query).toBe("function");
        // Must be the in-txn query — not client.query (autocommit).
        expect(tx.query).not.toBe(fake.query);
        await tx.query!("SELECT 1 /* child-write */", []);
        return childId;
      },
      record: draft,
    });
    expect(outcome).toEqual({ kind: "INSERTED", childRecordId: childId });
    // D1: exactly one transact, BEGIN before both writes, single COMMIT after both.
    expect(fake.transactCalls.count).toBe(1);
    expect(fake.txnLog).toEqual(["BEGIN", "COMMIT"]);
    const lastTxCalls =
      (fake.transact as { lastTxCalls?: { text: string }[] }).lastTxCalls ?? [];
    expect(lastTxCalls.some((c) => c.text.includes("child-write"))).toBe(true);
    expect(
      lastTxCalls.some((c) => c.text.includes("INSERT INTO reporting_mutation_idempotency")),
    ).toBe(true);
    // No autocommit writes for the UoW — only in-txn calls advanced the journal.
    // (calls[] still records in-txn SQL for burn-test compatibility; the oracle is txnLog +
    // lastTxCalls + transactCalls, which a two-autocommit broken store cannot satisfy.)
    expect(fake.calls.length).toBeGreaterThan(autocommitBefore);
  });

  it("ROLLbacks the txn (child write dropped) when the parent uniqueness race fires", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("INSERT INTO reporting_mutation_idempotency")
          ? {
              throw: pgError(
                "23505",
                'duplicate key value violates unique constraint "reporting_mutation_idempotenc_node_id_implementer_id_route__key"',
                IDEMPOTENCY_KEY_GUARD,
              ),
            }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);
    const full = idempotencyRecord();
    const { childRecordId: _c, ...draft } = full;
    let childWrote = false;
    const outcome = await store.commitMutationWithCompletedIdempotency({
      persistChild: async (tx) => {
        await tx.query!("INSERT INTO child_table /* child-write */ VALUES (1)", []);
        childWrote = true;
        return full.childRecordId;
      },
      record: draft,
    });
    expect(childWrote).toBe(true);
    expect(outcome).toEqual({ kind: "CONFLICT" });
    // D1: conflict sentinel forces outer ROLLBACK (child not durable).
    expect(fake.transactCalls.count).toBe(1);
    expect(fake.txnLog).toEqual(["BEGIN", "ROLLBACK"]);
    const lastTxCalls =
      (fake.transact as { lastTxCalls?: { text: string }[] }).lastTxCalls ?? [];
    expect(lastTxCalls.some((c) => c.text.includes("child-write"))).toBe(true);
    expect(
      lastTxCalls.some((c) => c.text.includes("INSERT INTO reporting_mutation_idempotency")),
    ).toBe(true);
  });

  it("aborts the unit of work (ROLLBACK, no parent insert) when persistChild throws", async () => {
    const fake = makeFake();
    const store = new DurableReportingRequestStore(fake);
    const full = idempotencyRecord();
    const { childRecordId: _c, ...draft } = full;
    await expect(
      store.commitMutationWithCompletedIdempotency({
        persistChild: async () => {
          throw new Error("child failed");
        },
        record: draft,
      }),
    ).rejects.toThrow(/child failed/);
    expect(fake.transactCalls.count).toBe(1);
    expect(fake.txnLog).toEqual(["BEGIN", "ROLLBACK"]);
    expect(
      fake.calls.some((c) => c.text.includes("INSERT INTO reporting_mutation_idempotency")),
    ).toBe(false);
  });

  it("rejects a two-autocommit store that never calls transact (D1 tautology guard)", async () => {
    // Oracle: the broken pre-fix shape (two autocommit writes, zero transact) must NOT
    // satisfy the UoW assertions above. This probe pins that the oracle is non-vacuous.
    const calls: { text: string }[] = [];
    const broken = {
      query: async (text: string, _params?: readonly unknown[]) => {
        calls.push({ text });
        return [] as const;
      },
      transact: async <T>(body: (q: ReportingQueryFn) => Promise<T>) => {
        // Deliberately NOT used by broken commitMutation below.
        return body(async (text) => {
          calls.push({ text });
          return [];
        });
      },
      async commitMutationWithCompletedIdempotency(input: {
        persistChild: (
          tx: { query?: ReportingQueryFn },
          completedIdempotencyId: string,
        ) => Promise<string>;
        record: Omit<CompletedIdempotencyRecord, "childRecordId">;
      }) {
        // Broken: two autocommit writes, never opens a transaction.
        const childId = await input.persistChild({ query: this.query }, input.record.id);
        await this.query(
          `INSERT INTO reporting_mutation_idempotency /* broken-autocommit */ VALUES ($1)`,
          [childId],
        );
        return { kind: "INSERTED" as const, childRecordId: childId };
      },
    };
    const full = idempotencyRecord();
    const { childRecordId: _c, ...draft } = full;
    await broken.commitMutationWithCompletedIdempotency({
      persistChild: async (tx) => {
        await tx.query!("SELECT 1 /* child-write */", []);
        return full.childRecordId;
      },
      record: draft,
    });
    // Broken path wrote both SQLs on autocommit and never ran BEGIN/COMMIT.
    expect(calls.some((c) => c.text.includes("child-write"))).toBe(true);
    expect(calls.some((c) => c.text.includes("reporting_mutation_idempotency"))).toBe(true);
    // Contrast: a real DurableReportingRequestStore against makeFake would have
    // transactCalls=1 and txnLog=["BEGIN","COMMIT"]. The broken path has neither.
    const honest = makeFake();
    const store = new DurableReportingRequestStore(honest);
    await store.commitMutationWithCompletedIdempotency({
      persistChild: async (tx) => {
        await tx.query!("SELECT 1 /* child-write */", []);
        return full.childRecordId;
      },
      record: draft,
    });
    expect(honest.transactCalls.count).toBe(1);
    expect(honest.txnLog).toEqual(["BEGIN", "COMMIT"]);
  });

  it("maps bare parent-PK 23505 to CONFLICT (not a rethrow)", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("INSERT INTO reporting_mutation_idempotency")
          ? {
              throw: pgError(
                "23505",
                'duplicate key value violates unique constraint "reporting_mutation_idempotency_pkey"',
                IDEMPOTENCY_PK_GUARD,
              ),
            }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);
    const full = idempotencyRecord();
    const { childRecordId: _c, ...draft } = full;
    const outcome = await store.commitMutationWithCompletedIdempotency({
      persistChild: async (_tx, completedIdempotencyId) => {
        expect(completedIdempotencyId).toBe(draft.id);
        return full.childRecordId;
      },
      record: draft,
    });
    expect(outcome).toEqual({ kind: "CONFLICT" });
    expect(fake.txnLog).toEqual(["BEGIN", "ROLLBACK"]);
  });

  it("passes record.id to persistChild so child.mutation_idempotency_id can correlate", async () => {
    const fake = makeFake();
    const store = new DurableReportingRequestStore(fake);
    const full = idempotencyRecord({ id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" });
    const { childRecordId: _c, ...draft } = full;
    let received: string | undefined;
    const outcome = await store.commitMutationWithCompletedIdempotency({
      persistChild: async (_tx, completedIdempotencyId) => {
        received = completedIdempotencyId;
        return full.childRecordId;
      },
      record: draft,
    });
    expect(outcome).toEqual({ kind: "INSERTED", childRecordId: full.childRecordId });
    expect(received).toBe(draft.id);
  });
});

describe("DurableReportingRequestStore read paths", () => {
  it("findCompletedIdempotency maps bytea and timestamptz back to the domain record", async () => {
    const bytes = new Uint8Array([9, 8, 7]);
    const fake = makeFake([
      (text) =>
        text.includes("FROM reporting_mutation_idempotency")
          ? {
              rows: [
                {
                  id: "99999999-9999-4999-8999-999999999999",
                  node_id: NODE_ID,
                  implementer_id: IMPLEMENTER_ID,
                  route_id: "verification_complete",
                  idempotency_key: "key-0123456789ab",
                  reporting_nonce_id: "88888888-8888-4888-8888-888888888888",
                  child_record_id: "77777777-7777-4777-8777-777777777777",
                  method: METHOD,
                  raw_target: RAW_TARGET,
                  body_sha256: BODY_SHA256,
                  logical_fingerprint: computeReportingLogicalFingerprint(
                    METHOD,
                    RAW_TARGET,
                    BODY_SHA256,
                  ),
                  response_status: 200,
                  response_bytes: bytes,
                  completed_at: new Date(CONSUMED_AT_MS).toISOString(),
                },
              ],
            }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    const found = await store.findCompletedIdempotency(
      NODE_ID,
      IMPLEMENTER_ID,
      "verification_complete",
      "key-0123456789ab",
    );

    expect(found).not.toBeNull();
    expect(found?.responseBytes).toEqual(bytes);
    expect(found?.completedAtMs).toBe(CONSUMED_AT_MS);
    expect(found?.responseStatus).toBe(200);
  });

  it("findCompletedIdempotency returns null when no row matches", async () => {
    const fake = makeFake([
      (text) => (text.includes("FROM reporting_mutation_idempotency") ? { rows: [] } : undefined),
    ]);
    const store = new DurableReportingRequestStore(fake);

    expect(
      await store.findCompletedIdempotency(NODE_ID, IMPLEMENTER_ID, "verification_complete", "absent"),
    ).toBeNull();
  });

  it("findRegistration maps the reporting-registration binding row", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("FROM implementer_reporting_keys")
          ? {
              rows: [
                {
                  id: KEY_ID,
                  node_id: NODE_ID,
                  implementer_id: IMPLEMENTER_ID,
                  public_key: `${"B".repeat(43)}=`,
                },
              ],
            }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    expect(await store.findRegistration(NODE_ID, KEY_ID)).toEqual({
      reportingKeyId: KEY_ID,
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_ID,
      publicKeyEncoded: `${"B".repeat(43)}=`,
    });
  });

  it("readAdmissionSnapshot maps the epoch as bigint and defaults restore_hold fail-closed", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("FROM reporting_key_lifecycle_heads h")
          ? {
              rows: [
                {
                  restore_hold: true, // COALESCE(rs.restore_hold, true): no restore-state row → fail-closed
                  epoch: "7",
                  auth_hold: false,
                  current_key_id: KEY_ID,
                  prior_key_id: null,
                  overlap_expires_at: null,
                  successor_committed_at: null,
                  presented_key_state: "ACTIVE",
                  presented_key_state_changed_at: null,
                },
              ],
            }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    const snapshot = await store.readAdmissionSnapshot(NODE_ID, IMPLEMENTER_ID, KEY_ID);

    expect(snapshot?.restoreHold).toBe(true);
    expect(snapshot?.epoch).toBe(7n);
    expect(snapshot?.authHold).toBe(false);
    expect(snapshot?.currentKeyId).toBe(KEY_ID);
    expect(snapshot?.presentedKeyState).toBe("ACTIVE");
    expect(snapshot?.presentedKeyRevokedAtMs).toBeNull();
  });

  it("readAdmissionSnapshot returns null when there is no lifecycle head", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("FROM reporting_key_lifecycle_heads h") ? { rows: [] } : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    expect(await store.readAdmissionSnapshot(NODE_ID, IMPLEMENTER_ID, KEY_ID)).toBeNull();
  });

  it("peekNonceBurned reflects the advisory existence check", async () => {
    const fake = makeFake([
      (text) =>
        text.includes("FROM reporting_request_nonces")
          ? { rows: [{ "?column?": 1 }] }
          : undefined,
    ]);
    const store = new DurableReportingRequestStore(fake);

    expect(await store.peekNonceBurned(NODE_ID, IMPLEMENTER_ID, NONCE)).toBe(true);
  });
});

// ---- real-Postgres suite ----
//
// Proves what the FakeClient cannot: (A) migration 0000 provisions pgcrypto, so the GENERATED
// logical_fingerprint column (which calls pgcrypto digest()) can be produced — at head (no
// CREATE EXTENSION in runMigrationsOnPool) this whole suite is RED because runMigrationsOnPool
// rejects in beforeAll with 42883 (`function digest(bytea, unknown) does not exist`); after the
// fix it is GREEN. And (B) the exact constraint names the store discriminates a 23505 on match a
// real migrated DB — Postgres truncates generated names to 63 bytes, so a hard-coded guess (like
// the old idempotency-key literal) would silently misroute; here they are asserted against pg.
//
// This package is network-contained: pg reaches Postgres via `new net.Socket.connect`
// (NOT the guard-patched net.connect), and createdb/dropdb run in a child process the guard cannot
// touch. The database is a THROWAWAY, created and dropped per suite — NEVER a shared/live/reference
// DB. If no local Postgres is reachable the suite skips (it does not fall back to any shared DB).

const PG_AVAILABLE = (() => {
  try {
    execFileSync("pg_isready", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

describe.skipIf(!PG_AVAILABLE)(
  "DurableReportingRequestStore against real Postgres (migration provisions pgcrypto + constraint names)",
  () => {
    const scratchDb = `zt562_test_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    let pool: Pool;

    beforeAll(async () => {
      execFileSync("createdb", [scratchDb]);
      pool = new Pool({ host: process.env.PGHOST ?? "/tmp", database: scratchDb });
      // runMigrationsOnPool(pool) below passes no explicit options.databaseUrl, so it falls back to
      // process.env.DATABASE_URL for the direct/session-endpoint check; the scratch pool passed in
      // (not a value read from db/client.ts) is what actually connects. Import dynamically so this
      // module load stays confined to the PG-available path (never loaded when this suite is
      // skipped or by the FakeClient unit tests above).
      process.env.DATABASE_URL ??= `postgres://localhost:5432/${scratchDb}`;
      const { runMigrationsOnPool } = await import("../../src/db/migrate.js");
      // Defect A: at head this rejects with 42883; after the fix it provisions pgcrypto and applies.
      await runMigrationsOnPool(pool);
    });

    afterAll(async () => {
      await pool?.end();
      try {
        execFileSync("dropdb", ["--if-exists", scratchDb]);
      } catch {
        /* best-effort cleanup of the throwaway DB */
      }
    });

    // A valid, GLOBALLY-UNIQUE padded_base64url_pubkey (44 chars: 43 [A-Za-z0-9_-] + "="): a
    // random 32-hex prefix keeps nodes.identity_public_key unique across tests (it is UNIQUE).
    const uniquePubkey = (): string => `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;

    // Minimal FK closure for a zp-report-request-v1 mutation nonce burn row.
    async function seedParents(nodeId: string, implementerId: string, keyId: string): Promise<void> {
      await pool.query(
        `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1, $2, $3)`,
        [nodeId, "test-node", uniquePubkey()],
      );
      await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
        implementerId,
        "test-impl",
      ]);
      await pool.query(
        `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
         VALUES ($1, $2, $3, $4, now())`,
        [keyId, nodeId, implementerId, uniquePubkey()],
      );
      await pool.query(`INSERT INTO reporting_nonce_burn_counters (node_id) VALUES ($1)`, [nodeId]);
    }

    // Insert one valid nonce row exactly as the burn does (NONCE_EVIDENCE_COLUMNS +
    // nonceEvidenceParams) and read back the GENERATED logical_fingerprint via RETURNING.
    async function insertNonce(
      nodeId: string,
      implementerId: string,
      keyId: string,
      nonce: string,
      seq: bigint,
    ): Promise<string> {
      const evidence: BurnNonceEvidence = {
        ...burnEvidence(),
        nodeId,
        implementerId,
        reportingKeyId: keyId,
        nonce,
      };
      const columns = [...NONCE_EVIDENCE_COLUMNS];
      const placeholders = columns.map((_, i) => `$${i + 1}`);
      const text = `INSERT INTO reporting_request_nonces (${columns.join(", ")})
                    VALUES (${placeholders.join(", ")})
                    RETURNING logical_fingerprint`;
      const res = await pool.query(text, nonceEvidenceParams(randomUUID(), evidence, seq) as unknown[]);
      return String(res.rows[0].logical_fingerprint);
    }

    it("migration applied (pgcrypto present) and a burned nonce's GENERATED logical_fingerprint matches the reference", async () => {
      const nodeId = randomUUID();
      const implementerId = randomUUID();
      const keyId = randomUUID();
      await seedParents(nodeId, implementerId, keyId);

      const fingerprint = await insertNonce(nodeId, implementerId, keyId, randomUUID(), 1n);

      // The digest fired at INSERT (pgcrypto is installed) and equals the TS reference derivation.
      expect(fingerprint).toBe(computeReportingLogicalFingerprint(METHOD, RAW_TARGET, BODY_SHA256));
    });

    it("the replay guard and the burn-sequence guard are DISTINCT 23505 constraints with the names the store discriminates on", async () => {
      const nodeId = randomUUID();
      const implementerId = randomUUID();
      const keyId = randomUUID();
      const nonce = randomUUID();
      await seedParents(nodeId, implementerId, keyId);

      await insertNonce(nodeId, implementerId, keyId, nonce, 1n);

      // Same (node_id, implementer_id, nonce), different burn sequence → the REPLAY guard fires.
      let replayConstraint: string | undefined;
      try {
        await insertNonce(nodeId, implementerId, keyId, nonce, 2n);
      } catch (err) {
        replayConstraint = (err as { constraint?: string }).constraint;
      }
      expect(replayConstraint).toBe(NONCE_REPLAY_GUARD);

      // Different nonce, SAME (node_id, nonce_burn_sequence) → the SEQUENCE guard fires (a distinct
      // constraint the store must NOT treat as a replay).
      let sequenceConstraint: string | undefined;
      try {
        await insertNonce(nodeId, implementerId, keyId, randomUUID(), 1n);
      } catch (err) {
        sequenceConstraint = (err as { constraint?: string }).constraint;
      }
      expect(sequenceConstraint).toBe(NONCE_SEQUENCE_GUARD);
      expect(sequenceConstraint).not.toBe(replayConstraint);
    });

    // ---- Real-PG unit-of-work: child + parent one txn; crash/CONFLICT drops both ----

    // Scratch child table used only by these UoW tests to observe durable child side effects.
    // Production children (receive_arms / verification_acknowledgements) carry
    // mutation_idempotency_id = parent.id; the scratch table mirrors that correlation column
    // so the harness can prove the store passes draft.id into persistChild on real PG.
    async function ensureChildScratch(): Promise<void> {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS durable_store_uow_child (
          id uuid PRIMARY KEY,
          note text NOT NULL,
          mutation_idempotency_id uuid
        )
      `);
      await pool.query(`
        ALTER TABLE durable_store_uow_child
          ADD COLUMN IF NOT EXISTS mutation_idempotency_id uuid
      `);
      // The shipped correlation guard (mutation-correlation.sql) resolves child_record_id in
      // receive_arms / verification_acknowledgements, selected by route_id — a stand-in child
      // table can never satisfy it, and every parent here names one. These tests are about the
      // store's transaction envelope, not correlation; the guard is proven against a
      // production-built database in apps/generic-node/test/mutation-correlation.pg.test.ts.
      // Scoped to this suite's throwaway database, which afterAll drops.
      await pool.query(
        `ALTER TABLE reporting_mutation_idempotency
           DISABLE TRIGGER reporting_completed_parent_has_child`,
      );
    }

    async function insertNonceReturningId(
      nodeId: string,
      implementerId: string,
      keyId: string,
      nonce: string,
      seq: bigint,
      method = METHOD,
      rawTarget = RAW_TARGET,
      bodySha256 = BODY_SHA256,
    ): Promise<string> {
      const evidence: BurnNonceEvidence = {
        ...burnEvidence(),
        nodeId,
        implementerId,
        reportingKeyId: keyId,
        nonce,
        method,
        rawTarget,
        bodySha256,
      };
      const columns = [...NONCE_EVIDENCE_COLUMNS];
      const placeholders = columns.map((_, i) => `$${i + 1}`);
      const text = `INSERT INTO reporting_request_nonces (${columns.join(", ")})
                    VALUES (${placeholders.join(", ")})
                    RETURNING id`;
      const res = await pool.query(
        text,
        nonceEvidenceParams(randomUUID(), evidence, seq) as unknown[],
      );
      return String(res.rows[0].id);
    }

    it("commitMutationWithCompletedIdempotency COMMITs child + parent together (real PG)", async () => {
      await ensureChildScratch();
      const nodeId = randomUUID();
      const implementerId = randomUUID();
      const keyId = randomUUID();
      await seedParents(nodeId, implementerId, keyId);
      const nonceId = await insertNonceReturningId(nodeId, implementerId, keyId, randomUUID(), 1n);
      const client = createPoolReportingClient(pool);
      const store = new DurableReportingRequestStore(client);
      const childId = randomUUID();
      const idemKey = `key-${randomUUID().slice(0, 12)}`;
      const full = idempotencyRecord({
        id: randomUUID(),
        nodeId,
        implementerId,
        reportingNonceId: nonceId,
        childRecordId: childId,
        idempotencyKey: idemKey,
      });
      const { childRecordId: _c, ...draft } = full;
      const outcome = await store.commitMutationWithCompletedIdempotency({
        persistChild: async (tx) => {
          await tx.query!(
            `INSERT INTO durable_store_uow_child (id, note) VALUES ($1, $2)`,
            [childId, "committed"],
          );
          return childId;
        },
        record: draft,
      });
      expect(outcome).toEqual({ kind: "INSERTED", childRecordId: childId });
      const child = await pool.query(`SELECT note FROM durable_store_uow_child WHERE id = $1`, [childId]);
      expect(child.rows).toHaveLength(1);
      expect(child.rows[0].note).toBe("committed");
      const parent = await store.findCompletedIdempotency(
        nodeId,
        implementerId,
        "verification_complete",
        idemKey,
      );
      expect(parent?.childRecordId).toBe(childId);
      expect(parent?.reportingNonceId).toBe(nonceId);
    });

    // Parent PK shared with child.mutation_idempotency_id via persistChild 2nd arg.
    it("persistChild receives draft.id and child.mutation_idempotency_id correlates (real PG)", async () => {
      await ensureChildScratch();
      const nodeId = randomUUID();
      const implementerId = randomUUID();
      const keyId = randomUUID();
      await seedParents(nodeId, implementerId, keyId);
      const nonceId = await insertNonceReturningId(nodeId, implementerId, keyId, randomUUID(), 1n);
      const client = createPoolReportingClient(pool);
      const store = new DurableReportingRequestStore(client);
      const parentId = randomUUID();
      const childId = randomUUID();
      const idemKey = `key-${randomUUID().slice(0, 12)}`;
      let seenCompletedId: string | undefined;
      const full = idempotencyRecord({
        id: parentId,
        nodeId,
        implementerId,
        reportingNonceId: nonceId,
        childRecordId: childId,
        idempotencyKey: idemKey,
      });
      const { childRecordId: _c, ...draft } = full;
      const outcome = await store.commitMutationWithCompletedIdempotency({
        persistChild: async (tx, completedIdempotencyId) => {
          seenCompletedId = completedIdempotencyId;
          await tx.query!(
            `INSERT INTO durable_store_uow_child (id, note, mutation_idempotency_id) VALUES ($1, $2, $3)`,
            [childId, "correlated", completedIdempotencyId],
          );
          return childId;
        },
        record: draft,
      });
      expect(outcome).toEqual({ kind: "INSERTED", childRecordId: childId });
      expect(seenCompletedId).toBe(parentId);
      const joined = await pool.query(
        `SELECT c.mutation_idempotency_id AS child_parent, p.id AS parent_pk
           FROM durable_store_uow_child c
           JOIN reporting_mutation_idempotency p ON p.id = c.mutation_idempotency_id
          WHERE c.id = $1`,
        [childId],
      );
      expect(joined.rows).toHaveLength(1);
      expect(joined.rows[0].child_parent).toBe(parentId);
      expect(joined.rows[0].parent_pk).toBe(parentId);
      expect(joined.rows[0].parent_pk).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    });

    it("parent CONFLICT after child INSERT ROLLBACKs — child not durable (real PG)", async () => {
      await ensureChildScratch();
      const nodeId = randomUUID();
      const implementerId = randomUUID();
      const keyId = randomUUID();
      await seedParents(nodeId, implementerId, keyId);
      // Two distinct nonces so FK + UNIQUE(reporting_nonce_id) are satisfied independently.
      const winnerNonceId = await insertNonceReturningId(
        nodeId,
        implementerId,
        keyId,
        randomUUID(),
        1n,
      );
      const loserNonceId = await insertNonceReturningId(
        nodeId,
        implementerId,
        keyId,
        randomUUID(),
        2n,
        METHOD,
        RAW_TARGET,
        "cd".repeat(32), // different body so fingerprint partial unique does not collide first
      );
      const client = createPoolReportingClient(pool);
      const store = new DurableReportingRequestStore(client);
      const idemKey = `key-${randomUUID().slice(0, 12)}`;
      const winnerChild = randomUUID();
      const winner = idempotencyRecord({
        id: randomUUID(),
        nodeId,
        implementerId,
        reportingNonceId: winnerNonceId,
        childRecordId: winnerChild,
        idempotencyKey: idemKey,
        bodySha256: BODY_SHA256,
      });
      const { childRecordId: _w, ...winnerDraft } = winner;
      expect(
        await store.commitMutationWithCompletedIdempotency({
          persistChild: async (tx) => {
            await tx.query!(
              `INSERT INTO durable_store_uow_child (id, note) VALUES ($1, $2)`,
              [winnerChild, "winner"],
            );
            return winnerChild;
          },
          record: winnerDraft,
        }),
      ).toEqual({ kind: "INSERTED", childRecordId: winnerChild });

      const loserChild = randomUUID();
      const loser = idempotencyRecord({
        id: randomUUID(),
        nodeId,
        implementerId,
        reportingNonceId: loserNonceId,
        childRecordId: loserChild,
        idempotencyKey: idemKey, // same key → primary UNIQUE fires
        bodySha256: "cd".repeat(32),
        rawTarget: RAW_TARGET,
      });
      const { childRecordId: _l, ...loserDraft } = loser;
      const conflict = await store.commitMutationWithCompletedIdempotency({
        persistChild: async (tx) => {
          await tx.query!(
            `INSERT INTO durable_store_uow_child (id, note) VALUES ($1, $2)`,
            [loserChild, "loser-should-rollback"],
          );
          return loserChild;
        },
        record: loserDraft,
      });
      expect(conflict).toEqual({ kind: "CONFLICT" });
      // Child from the losing UoW must NOT be durable (ROLLBACK).
      const loserRows = await pool.query(`SELECT 1 FROM durable_store_uow_child WHERE id = $1`, [
        loserChild,
      ]);
      expect(loserRows.rows).toHaveLength(0);
      // Winner remains.
      const winnerRows = await pool.query(`SELECT note FROM durable_store_uow_child WHERE id = $1`, [
        winnerChild,
      ]);
      expect(winnerRows.rows).toHaveLength(1);
      const parent = await store.findCompletedIdempotency(
        nodeId,
        implementerId,
        "verification_complete",
        idemKey,
      );
      expect(parent?.childRecordId).toBe(winnerChild);
    });

    it("throw after child INSERT before parent COMMIT leaves neither durable (real PG crash AC)", async () => {
      await ensureChildScratch();
      const nodeId = randomUUID();
      const implementerId = randomUUID();
      const keyId = randomUUID();
      await seedParents(nodeId, implementerId, keyId);
      const nonceId = await insertNonceReturningId(nodeId, implementerId, keyId, randomUUID(), 1n);
      const client = createPoolReportingClient(pool);
      const store = new DurableReportingRequestStore(client);
      const childId = randomUUID();
      const idemKey = `key-${randomUUID().slice(0, 12)}`;
      const full = idempotencyRecord({
        id: randomUUID(),
        nodeId,
        implementerId,
        reportingNonceId: nonceId,
        childRecordId: childId,
        idempotencyKey: idemKey,
      });
      const { childRecordId: _c, ...draft } = full;
      await expect(
        store.commitMutationWithCompletedIdempotency({
          persistChild: async (tx) => {
            await tx.query!(
              `INSERT INTO durable_store_uow_child (id, note) VALUES ($1, $2)`,
              [childId, "should-vanish"],
            );
            // Simulate crash / handler failure after the child write, before parent insert
            // completes — the outer ROLLBACK must drop the child.
            throw new Error("simulated-crash-mid-uow");
          },
          record: draft,
        }),
      ).rejects.toThrow(/simulated-crash-mid-uow/);
      const childRows = await pool.query(`SELECT 1 FROM durable_store_uow_child WHERE id = $1`, [childId]);
      expect(childRows.rows).toHaveLength(0);
      const parent = await store.findCompletedIdempotency(
        nodeId,
        implementerId,
        "verification_complete",
        idemKey,
      );
      expect(parent).toBeNull();
    });
  },
);
