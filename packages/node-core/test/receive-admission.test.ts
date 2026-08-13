// Admission logic driven through the REAL store
// (SqlReceiveAdmissionStore) and its REAL parameterized statements.
//
// Verification posture, stated honestly: node-core is network-contained and depends
// on no database driver, so this suite supplies an in-process SqlExecutor that models the
// receive_operations constraints — the idempotency UNIQUE emitting 23505, and the two partial
// unique indexes emitting 23505 with their index names. That drives the store's REAL SQL,
// REAL constraint-name mapping, and REAL error propagation. What it does NOT prove — that a
// live PostgreSQL parses and enforces the DDL as modeled — is proven separately, and is not
// deferred: test/receive-admission-pg.test.ts provisions a hermetic scratch database, applies
// the real frozen DDL, and drills the actual 23505 / 23514 emissions. Neither file alone is
// the evidence; the pair is.
import { describe, expect, it } from "vitest";

import {
  IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS,
  RECEIVE_CANONICAL_ROUTE,
  RECEIVE_HTTP_METHOD,
  RECEIVE_QUEUE_FULL_RETRY_AFTER_SECONDS,
  admitReceiveExternal,
  canonicalRequestSha256,
  isMoveDestinationEligible,
  isReceiveEligible,
  validateAfterLanding,
  validateReceiveRequest,
  type ReceiveDestinationRecord,
  type ReceiveRequest,
  type ReceiveWalletRecord,
} from "../src/receive/admission.js";
import {
  DESTINATION_IN_FLIGHT_INDEX,
  OPERATION_COLUMNS,
  RECEIVER_IN_FLIGHT_INDEX,
  SQLSTATE_UNIQUE_VIOLATION,
  STATEMENTS,
  SqlReceiveAdmissionStore,
  type SqlExecutor,
  type SqlQueryResult,
} from "../src/receive/sql-store.js";
import { hashSubscriptionHandle } from "../src/api/subscription-handle.js";

const DEST_ID = "11111111-1111-4111-8111-111111111111";
const DEST_WALLET = "22222222-2222-4222-8222-222222222222";
const RECEIVER_WALLET = "33333333-3333-4333-8333-333333333333";

/* ─── in-process SqlExecutor modelling the receive_operations constraints ─── */

function uniqueViolation(constraint: string): Error {
  return Object.assign(
    new Error(`duplicate key value violates unique constraint "${constraint}"`),
    { code: SQLSTATE_UNIQUE_VIOLATION, constraint },
  );
}

const NON_TERMINAL = new Set(["CREATED", "READY"]);

class InProcessSqlExecutor implements SqlExecutor {
  readonly rows: Record<string, unknown>[] = [];
  readonly subscriptionHandles: Record<string, unknown>[] = [];
  readonly destinations = new Map<string, Record<string, unknown>>();

  addDestination(record: Record<string, unknown>): void {
    this.destinations.set(record.destination_id as string, record);
  }

  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> {
    return Promise.resolve({ rows: this.run(text, params) as R[] });
  }

  private run(text: string, params: readonly unknown[]): Record<string, unknown>[] {
    if (text === STATEMENTS.SELECT_DESTINATION) {
      const found = this.destinations.get(params[0] as string);
      return found === undefined ? [] : [found];
    }
    if (text === STATEMENTS.INSERT_IN_PROGRESS) return this.insert(params);
    if (text === STATEMENTS.INSERT_SUBSCRIPTION_HANDLE) {
      const handleHash = params[3] as string;
      if (this.subscriptionHandles.some((h) => h.handle_hash === handleHash)) {
        throw uniqueViolation("subscription_handles_handle_hash_key");
      }
      if (this.subscriptionHandles.some((h) => h.operation_id === params[2])) {
        throw uniqueViolation("subscription_handles_operation_id_key");
      }
      // Only the hash is durable — plaintext is never a bind parameter.
      this.subscriptionHandles.push({
        id: params[0],
        node_id: params[1],
        operation_id: params[2],
        handle_hash: handleHash,
        expires_at: params[4],
      });
      return [{ id: params[0] }];
    }
    if (text === STATEMENTS.LOCK_ADMISSION_QUEUE) {
      // Advisory lock is a no-op in-process; real serialisation is proven on live PG.
      return [{ locked: true }];
    }
    if (text === STATEMENTS.SELECT_BY_IDEMPOTENCY) {
      return this.rows.filter(
        (row) =>
          row.implementer_id === params[0] &&
          row.http_method === params[1] &&
          row.route === params[2] &&
          row.idempotency_key === params[3],
      );
    }
    if (text === STATEMENTS.COMPLETE_OPERATION) {
      const row = this.rows.find(
        (candidate) => candidate.operation_id === params[0] && candidate.completed_at === null,
      );
      if (row === undefined) return [];
      row.completed_at = "2023-11-14T22:13:20.000Z";
      row.response_status = params[1];
      row.response_body = params[2];
      return [{ operation_id: row.operation_id }];
    }
    if (text === STATEMENTS.COUNT_QUEUED) {
      // node-core: unassigned CREATED receives for this node only.
      const depth = this.rows.filter(
        (row) =>
          row.node_id === params[0] && row.status === "CREATED" && row.wallet_id === null,
      ).length;
      return [{ depth }];
    }
    throw new Error(`unmodelled statement: ${text}`);
  }

  private insert(params: readonly unknown[]): Record<string, unknown>[] {
    const row: Record<string, unknown> = {
      completed_at: null,
      response_status: null,
      response_body: null,
    };
    OPERATION_COLUMNS.forEach((column, i) => {
      row[column] = params[i];
    });
    row.created_at = new Date(params[16] as number).toISOString();

    // ON CONFLICT ON CONSTRAINT receive_operations_idempotency_scope DO NOTHING.
    const conflicting = this.rows.some(
      (existing) =>
        existing.implementer_id === row.implementer_id &&
        existing.http_method === row.http_method &&
        existing.route === row.route &&
        existing.idempotency_key === row.idempotency_key,
    );
    if (conflicting) return [];

    // The two partial unique indexes are NOT absorbed by that clause: they raise.
    if (
      row.destination_wallet_id !== null &&
      this.rows.some(
        (existing) =>
          existing.destination_wallet_id === row.destination_wallet_id &&
          NON_TERMINAL.has(existing.status as string),
      )
    ) {
      throw uniqueViolation(DESTINATION_IN_FLIGHT_INDEX);
    }
    if (
      row.wallet_id !== null &&
      this.rows.some(
        (existing) =>
          existing.wallet_id === row.wallet_id && NON_TERMINAL.has(existing.status as string),
      )
    ) {
      throw uniqueViolation(RECEIVER_IN_FLIGHT_INDEX);
    }

    this.rows.push(row);
    return [{ operation_id: row.operation_id }];
  }
}

function newStore(): { sql: InProcessSqlExecutor; store: SqlReceiveAdmissionStore } {
  const sql = new InProcessSqlExecutor();
  // Identity TX factory: single-threaded in-process fake cannot race; live PG stress uses
  // a real BEGIN/COMMIT factory (receive-admission-pg.test.ts).
  return { sql, store: new SqlReceiveAdmissionStore(sql, { withTransaction: (fn) => fn(sql) }) };
}

/**
 * Models withPgTransaction (main.ts): BEGIN → fn(tx) → COMMIT on normal return;
 * ROLLBACK only when fn throws. A unique_violation aborts the session — subsequent
 * queries and COMMIT fail with "current transaction is aborted" unless ROLLBACK runs.
 * Proves insertOn must not swallow 23505 inside the open TX (ZTR-1142 Review B D1).
 */
function newStoreWithBeginCommitTx(): {
  sql: InProcessSqlExecutor;
  store: SqlReceiveAdmissionStore;
  commits: number;
  rollbacks: number;
  commitErrors: number;
} {
  const sql = new InProcessSqlExecutor();
  let commits = 0;
  let rollbacks = 0;
  let commitErrors = 0;
  const store = new SqlReceiveAdmissionStore(sql, {
    withTransaction: async <T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T> => {
      let aborted = false;
      const tx: SqlExecutor = {
        query: async <R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> => {
          if (aborted) {
            throw Object.assign(new Error("current transaction is aborted, commands ignored until end of transaction block"), {
              code: "25P02",
            });
          }
          try {
            return await sql.query<R>(text, params);
          } catch (error) {
            // PG marks the TX aborted on any error (including 23505).
            aborted = true;
            throw error;
          }
        },
      };
      try {
        const out = await fn(tx);
        if (aborted) {
          commitErrors += 1;
          throw Object.assign(
            new Error("current transaction is aborted, commands ignored until end of transaction block"),
            { code: "25P02" },
          );
        }
        commits += 1;
        return out;
      } catch (error) {
        rollbacks += 1;
        throw error;
      }
    },
  });
  return {
    sql,
    store,
    get commits() {
      return commits;
    },
    get rollbacks() {
      return rollbacks;
    },
    get commitErrors() {
      return commitErrors;
    },
  };
}

const blessedDestinationRow = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  destination_id: DEST_ID,
  destination_state: "BLESSED",
  wallet_id: DEST_WALLET,
  node_id: "node-1",
  public_key: "pk-dest",
  key_origin: "node_generated",
  wallet_state: "AVAILABLE",
  allow_external_receive: true,
  allow_internal_move: true,
  recovery_verified_at: "2023-11-14T22:13:20.000Z",
  ...overrides,
});

function eligibleWallet(overrides: Partial<ReceiveWalletRecord> = {}): ReceiveWalletRecord {
  return {
    walletId: DEST_WALLET,
    nodeId: "node-1",
    keyOrigin: "node_generated",
    state: "AVAILABLE",
    recoveryVerifiedAt: 1700000000000,
    allowExternalReceive: true,
    allowInternalMove: true,
    ...overrides,
  };
}

function destination(overrides: Partial<ReceiveDestinationRecord> = {}): ReceiveDestinationRecord {
  return {
    destinationId: DEST_ID,
    destinationState: "BLESSED",
    wallet: eligibleWallet(),
    ...overrides,
  };
}

function validRequest(overrides: Partial<ReceiveRequest> = {}): ReceiveRequest {
  return {
    implementerId: "impl-1",
    nodeId: "node-1",
    amountZkz: "1.5",
    anchor: "anchor_abc-123",
    ttlMs: 60_000,
    afterLanding: { kind: "HOLD" },
    idempotencyKey: "abcdef1234567890",
    ...overrides,
  };
}

// queueCap is required (no default): a silent unbounded queue is the failure mode prevents.
const config = { queueCap: 100, generateId: () => "op-001", now: () => 1700000000000 };

/* ─── validators ──────────────────────────────────────────────────── */

describe("validateReceiveRequest", () => {
  it("accepts a valid request", () => {
    expect(validateReceiveRequest(validRequest())).toEqual({ ok: true });
  });

  it("rejects missing idempotency key (too short)", () => {
    expect(validateReceiveRequest(validRequest({ idempotencyKey: "short" }))).toEqual({
      ok: false,
      code: "missing_idempotency_key",
    });
  });

  it("rejects idempotency key with non-visible-ASCII", () => {
    expect(
      validateReceiveRequest(validRequest({ idempotencyKey: "abcdef1234567890\x01" })),
    ).toEqual({ ok: false, code: "missing_idempotency_key" });
  });

  it.each(["0", "0.0", "0.00", `0.${"0".repeat(32)}`, "-1.5", "abc", "1e3", "01.5"])(
    "rejects non-positive or non-canonical amount %s",
    (amountZkz) => {
      const result = validateReceiveRequest(validRequest({ amountZkz }));
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe("invalid_amount");
    },
  );

  it("rejects invalid anchor (special chars)", () => {
    expect(validateReceiveRequest(validRequest({ anchor: "bad!anchor" }))).toEqual({
      ok: false,
      code: "invalid_anchor",
    });
  });

  it("rejects anchor exceeding 96 chars", () => {
    expect(validateReceiveRequest(validRequest({ anchor: "a".repeat(97) }))).toEqual({
      ok: false,
      code: "invalid_anchor",
    });
  });

  it.each([999, 86_400_001, 1000.5])("rejects out-of-range ttl %s", (ttlMs) => {
    const result = validateReceiveRequest(validRequest({ ttlMs }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("invalid_ttl");
  });

  it("rejects an unknown after_landing discriminant", () => {
    const result = validateReceiveRequest(
      validRequest({ afterLanding: { kind: "BURN" } as never }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("invalid_after_landing");
  });
});

describe("validateAfterLanding — canonical fields admits exactly two shapes", () => {
  it("accepts HOLD with and without an explicit null destination", () => {
    expect(validateAfterLanding({ kind: "HOLD" })).toBe(true);
    expect(validateAfterLanding({ kind: "HOLD", destinationId: null })).toBe(true);
  });

  it("accepts INTERNAL_MOVE with a UUID destination", () => {
    expect(validateAfterLanding({ kind: "INTERNAL_MOVE", destinationId: DEST_ID })).toBe(true);
  });

  it.each([
    ["unknown discriminant", { kind: "BURN", destinationId: DEST_ID }],
    ["HOLD carrying a destination", { kind: "HOLD", destinationId: DEST_ID }],
    ["INTERNAL_MOVE without a destination", { kind: "INTERNAL_MOVE" }],
    ["INTERNAL_MOVE with a null destination", { kind: "INTERNAL_MOVE", destinationId: null }],
    ["INTERNAL_MOVE with a traversal string", { kind: "INTERNAL_MOVE", destinationId: "../../etc" }],
    ["extra keys", { kind: "HOLD", destinationId: null, extra: 1 }],
    ["a bare string", "HOLD"],
    ["null", null],
  ])("rejects %s", (_label, value) => {
    expect(validateAfterLanding(value)).toBe(false);
  });
});

describe("isReceiveEligible — receive-pool predicate (blessing-free)", () => {
  it("accepts node_generated + AVAILABLE + recovery verified", () => {
    expect(isReceiveEligible(eligibleWallet())).toBe(true);
  });

  it.each([
    ["imported wallet", { keyOrigin: "imported" as const }],
    ["PINNED wallet", { state: "PINNED" as const }],
    ["QUARANTINED wallet", { state: "QUARANTINED" as const }],
    ["RETIRED wallet", { state: "RETIRED" as const }],
    ["wallet without recovery verification", { recoveryVerifiedAt: null }],
    ["wallet with allow_external_receive false", { allowExternalReceive: false }],
  ])("rejects %s", (_label, overrides) => {
    expect(isReceiveEligible(eligibleWallet(overrides))).toBe(false);
  });
});

describe("isMoveDestinationEligible — step 3 four-conjunct predicate", () => {
  it("accepts a blessed, node-generated, recovery-verified, AVAILABLE destination", () => {
    expect(isMoveDestinationEligible(destination())).toBe(true);
  });

  it("rejects an UNBLESSED but otherwise eligible destination", () => {
    // The receive-pool predicate would admit this. A move destination must also be blessed
    // (B-08) — the exact gate this admission step anchors.
    expect(isMoveDestinationEligible(destination({ destinationState: "PENDING" }))).toBe(false);
    expect(isMoveDestinationEligible(destination({ destinationState: "RETIRED" }))).toBe(false);
  });

  it("rejects a blessed destination whose wallet fails the recovery gate", () => {
    expect(
      isMoveDestinationEligible(
        destination({ wallet: eligibleWallet({ recoveryVerifiedAt: null }) }),
      ),
    ).toBe(false);
  });

  it("rejects when allow_internal_move is false even if external receive is allowed (ZTR-1268)", () => {
    expect(
      isMoveDestinationEligible(
        destination({
          wallet: eligibleWallet({
            allowExternalReceive: true,
            allowInternalMove: false,
          }),
        }),
      ),
    ).toBe(false);
  });
});

describe("canonicalRequestSha256", () => {
  it("is stable for the same request", () => {
    expect(canonicalRequestSha256(validRequest())).toBe(canonicalRequestSha256(validRequest()));
  });

  it("changes when any canonical field changes", () => {
    const base = canonicalRequestSha256(validRequest());
    expect(canonicalRequestSha256(validRequest({ amountZkz: "5.5" }))).not.toBe(base);
    expect(canonicalRequestSha256(validRequest({ anchor: "other" }))).not.toBe(base);
    expect(canonicalRequestSha256(validRequest({ ttlMs: 61_000 }))).not.toBe(base);
  });

  it("does not depend on the idempotency key", () => {
    expect(canonicalRequestSha256(validRequest({ idempotencyKey: "zzzzzzzzzzzzzzzz" }))).toBe(
      canonicalRequestSha256(validRequest()),
    );
  });
});

/* ─── admission ───────────────────────────────────────────────────── */

describe("admitReceiveExternal", () => {
  it("admits a valid HOLD request and records the idempotency scope tuple", async () => {
    const { sql, store } = newStore();
    const result = await admitReceiveExternal(store, validRequest(), config);

    expect(result.outcome).toBe("ADMITTED");
    if (result.outcome !== "ADMITTED") return;
    expect(result.operation.operationId).toBe("op-001");
    expect(result.operation.kind).toBe("RECEIVE_EXTERNAL");
    expect(result.operation.status).toBe("CREATED");
    expect(result.operation.walletId).toBeNull();
    expect(result.operation.amountZkz).toBe("1.5");
    expect(result.operation.httpMethod).toBe(RECEIVE_HTTP_METHOD);
    expect(result.operation.route).toBe(RECEIVE_CANONICAL_ROUTE);
    expect(sql.rows).toHaveLength(1);
    expect(sql.rows[0].request_sha256).toBe(canonicalRequestSha256(validRequest()));
    // ZTR-1142: mint in the same TX; only the hash is durable.
    expect(result.subscriptionHandlePlaintext.startsWith("sh_")).toBe(true);
    expect(sql.subscriptionHandles).toHaveLength(1);
    expect(sql.subscriptionHandles[0].handle_hash).toBe(
      hashSubscriptionHandle(result.subscriptionHandlePlaintext),
    );
    expect(sql.subscriptionHandles[0].operation_id).toBe("op-001");
    // Plaintext must never appear as a bind / durable field.
    expect(JSON.stringify(sql.subscriptionHandles)).not.toContain(
      result.subscriptionHandlePlaintext,
    );
  });

  it("replays the first completed execution byte-identically for same key + same hash", async () => {
    const { store } = newStore();
    const first = await admitReceiveExternal(store, validRequest(), config);
    expect(first.outcome).toBe("ADMITTED");
    if (first.outcome !== "ADMITTED") return;
    await store.completeOperation(first.operation.operationId, 202, '{"operation_id":"op-001"}');

    const second = await admitReceiveExternal(store, validRequest(), {
      ...config,
      generateId: () => "op-002",
    });
    expect(second.outcome).toBe("IDEMPOTENT_REPLAY");
    if (second.outcome !== "IDEMPOTENT_REPLAY") return;
    expect(second.operation.operationId).toBe("op-001");
    expect(second.responseStatus).toBe(202);
    expect(second.responseBody).toBe('{"operation_id":"op-001"}');
  });

  it("returns idempotency_key_reused for same key + DIFFERENT request hash, creating nothing", async () => {
    const { sql, store } = newStore();
    const first = await admitReceiveExternal(store, validRequest({ amountZkz: "1.5" }), config);
    expect(first.outcome).toBe("ADMITTED");
    if (first.outcome !== "ADMITTED") return;
    await store.completeOperation(first.operation.operationId, 202, "{}");

    // Same key, 5 ZKZ instead of 1.5. Returning the 1.5 operation would tell the caller its
    // 5 ZKZ receive exists when it does not.
    const reused = await admitReceiveExternal(store, validRequest({ amountZkz: "5.5" }), {
      ...config,
      generateId: () => "op-002",
    });
    expect(reused.outcome).toBe("REJECTED");
    if (reused.outcome !== "REJECTED") return;
    expect(reused.code).toBe("idempotency_key_reused");
    expect(sql.rows).toHaveLength(1);
    expect(sql.rows[0].amount_zkz).toBe("1.5");
  });

  it("returns idempotency_in_progress with Retry-After while the creator has stored no result", async () => {
    const { sql, store } = newStore();
    expect((await admitReceiveExternal(store, validRequest(), config)).outcome).toBe("ADMITTED");

    const follower = await admitReceiveExternal(store, validRequest(), {
      ...config,
      generateId: () => "op-002",
    });
    expect(follower.outcome).toBe("REJECTED");
    if (follower.outcome !== "REJECTED") return;
    expect(follower.code).toBe("idempotency_in_progress");
    expect(follower.retryAfterSeconds).toBe(IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS);
    // The follower created nothing: the in-progress marker is the arbiter.
    expect(sql.rows).toHaveLength(1);
  });

  it("scopes idempotency by implementerId", async () => {
    const { store } = newStore();
    await admitReceiveExternal(store, validRequest(), config);

    const otherImpl = await admitReceiveExternal(store, validRequest({ implementerId: "impl-2" }), {
      ...config,
      generateId: () => "op-002",
    });
    expect(otherImpl.outcome).toBe("ADMITTED");
  });

  it("rejects when the INTERNAL_MOVE destination is not found", async () => {
    const { sql, store } = newStore();
    const result = await admitReceiveExternal(
      store,
      validRequest({ afterLanding: { kind: "INTERNAL_MOVE", destinationId: DEST_ID } }),
      config,
    );
    expect(result.outcome).toBe("REJECTED");
    if (result.outcome !== "REJECTED") return;
    expect(result.code).toBe("destination_not_found");
    expect(sql.rows).toHaveLength(0);
  });

  it("rejects an UNBLESSED INTERNAL_MOVE destination before any row is created", async () => {
    const { sql, store } = newStore();
    sql.addDestination(blessedDestinationRow({ destination_state: "PENDING" }));

    const result = await admitReceiveExternal(
      store,
      validRequest({ afterLanding: { kind: "INTERNAL_MOVE", destinationId: DEST_ID } }),
      config,
    );
    expect(result.outcome).toBe("REJECTED");
    if (result.outcome !== "REJECTED") return;
    expect(result.code).toBe("destination_not_eligible");
    expect(sql.rows).toHaveLength(0);
  });

  it("rejects a non-recovery-verified INTERNAL_MOVE destination", async () => {
    const { sql, store } = newStore();
    sql.addDestination(blessedDestinationRow({ recovery_verified_at: null }));

    const result = await admitReceiveExternal(
      store,
      validRequest({ afterLanding: { kind: "INTERNAL_MOVE", destinationId: DEST_ID } }),
      config,
    );
    expect(result.outcome).toBe("REJECTED");
    if (result.outcome !== "REJECTED") return;
    expect(result.code).toBe("destination_not_eligible");
    expect(sql.rows).toHaveLength(0);
  });

  it("admits INTERNAL_MOVE for a blessed destination and stamps its wallet on the row", async () => {
    const { sql, store } = newStore();
    sql.addDestination(blessedDestinationRow());

    const result = await admitReceiveExternal(
      store,
      validRequest({ afterLanding: { kind: "INTERNAL_MOVE", destinationId: DEST_ID } }),
      config,
    );
    expect(result.outcome).toBe("ADMITTED");
    if (result.outcome !== "ADMITTED") return;
    expect(result.operation.destinationWalletId).toBe(DEST_WALLET);
    expect(sql.rows[0].destination_wallet_id).toBe(DEST_WALLET);
  });

  it("The one-in-flight-per-wallet rule: the constraint — not a prior read — rejects a second in-flight receive for one wallet", async () => {
    const { sql, store } = internalMoveFixture();
    const first = await admitReceiveExternal(
      store,
      validRequest({ afterLanding: { kind: "INTERNAL_MOVE", destinationId: DEST_ID } }),
      config,
    );
    expect(first.outcome).toBe("ADMITTED");

    // Different idempotency key, so the idempotency constraint cannot be what rejects it.
    const second = await admitReceiveExternal(
      store,
      validRequest({
        afterLanding: { kind: "INTERNAL_MOVE", destinationId: DEST_ID },
        idempotencyKey: "zzzzzzzzzzzzzzzz",
      }),
      { ...config, generateId: () => "op-002" },
    );
    expect(second.outcome).toBe("REJECTED");
    if (second.outcome !== "REJECTED") return;
    expect(second.code).toBe("wallet_in_flight");
    // — implementers never see the internal wallet UUID in the rejection.
    expect(second.detail).toBeUndefined();
    expect(sql.rows).toHaveLength(1);
  });

  it("BEGIN/COMMIT factory: second INTERNAL_MOVE admit returns WALLET_IN_FLIGHT without COMMIT error", async () => {
    // Review B D1: insertOn must not catch unique_violation inside an open PG TX and return
    // WALLET_IN_FLIGHT — that leaves the session aborted and COMMIT fails (500). With a real
    // BEGIN/COMMIT factory, 23505 must throw out for ROLLBACK; outer catch maps the constraint.
    const fixture = newStoreWithBeginCommitTx();
    fixture.sql.addDestination(blessedDestinationRow());
    const { sql, store } = fixture;

    const first = await store.insertInProgress({
      operationId: "op-001",
      implementerId: "impl-1",
      nodeId: "node-1",
      kind: "RECEIVE_EXTERNAL",
      status: "CREATED",
      httpMethod: RECEIVE_HTTP_METHOD,
      route: RECEIVE_CANONICAL_ROUTE,
      amountZkz: "1.5",
      anchor: "anchor_abc-123",
      ttlMs: 60_000,
      afterLanding: { kind: "INTERNAL_MOVE", destinationId: DEST_ID },
      idempotencyKey: "abcdef1234567890",
      requestSha256: "a".repeat(64),
      destinationWalletId: DEST_WALLET,
      walletId: null,
      createdAt: 1700000000000,
    });
    expect(first.kind).toBe("INSERTED");
    expect(fixture.commits).toBe(1);
    expect(fixture.commitErrors).toBe(0);

    const second = await store.insertInProgress({
      operationId: "op-002",
      implementerId: "impl-1",
      nodeId: "node-1",
      kind: "RECEIVE_EXTERNAL",
      status: "CREATED",
      httpMethod: RECEIVE_HTTP_METHOD,
      route: RECEIVE_CANONICAL_ROUTE,
      amountZkz: "2.5",
      anchor: "anchor_def-456",
      ttlMs: 60_000,
      afterLanding: { kind: "INTERNAL_MOVE", destinationId: DEST_ID },
      idempotencyKey: "zzzzzzzzzzzzzzzz",
      requestSha256: "b".repeat(64),
      destinationWalletId: DEST_WALLET,
      walletId: null,
      createdAt: 1700000000001,
    });
    expect(second).toEqual({ kind: "WALLET_IN_FLIGHT", walletId: DEST_WALLET });
    expect(fixture.commitErrors).toBe(0);
    expect(fixture.rollbacks).toBe(1);
    expect(fixture.commits).toBe(1);
    expect(sql.rows).toHaveLength(1);
    expect(sql.subscriptionHandles).toHaveLength(1);
  });

  it("The one-in-flight-per-wallet rule: a TERMINAL predecessor does not block a fresh receive for the same wallet", async () => {
    const { sql, store } = internalMoveFixture();
    await admitReceiveExternal(
      store,
      validRequest({ afterLanding: { kind: "INTERNAL_MOVE", destinationId: DEST_ID } }),
      config,
    );
    sql.rows[0].status = "EXPIRED";

    const fresh = await admitReceiveExternal(
      store,
      validRequest({
        afterLanding: { kind: "INTERNAL_MOVE", destinationId: DEST_ID },
        idempotencyKey: "zzzzzzzzzzzzzzzz",
      }),
      { ...config, generateId: () => "op-002" },
    );
    expect(fresh.outcome).toBe("ADMITTED");
  });

  it("maps the receiver-wallet index to wallet_in_flight too", async () => {
    // The assignment slice stamps wallet_id; both wallet references the row can hold are
    // covered by the same rejection.
    const { sql, store } = newStore();
    sql.rows.push({ status: "READY", wallet_id: RECEIVER_WALLET, destination_wallet_id: null });

    const outcome = await store.insertInProgress({
      operationId: "op-002",
      implementerId: "impl-1",
      nodeId: "node-1",
      kind: "RECEIVE_EXTERNAL",
      status: "CREATED",
      httpMethod: RECEIVE_HTTP_METHOD,
      route: RECEIVE_CANONICAL_ROUTE,
      amountZkz: "1.5",
      anchor: "anchor_abc-123",
      ttlMs: 60_000,
      afterLanding: { kind: "HOLD" },
      idempotencyKey: "abcdef1234567890",
      requestSha256: "a".repeat(64),
      destinationWalletId: null,
      walletId: RECEIVER_WALLET,
      createdAt: 1700000000000,
    });
    expect(outcome).toEqual({ kind: "WALLET_IN_FLIGHT", walletId: RECEIVER_WALLET });
  });

  it("rejects an invalid request before touching the store", async () => {
    const { sql, store } = newStore();
    const result = await admitReceiveExternal(store, validRequest({ amountZkz: "bad" }), config);
    expect(result.outcome).toBe("REJECTED");
    if (result.outcome !== "REJECTED") return;
    expect(result.code).toBe("invalid_amount");
    expect(sql.rows).toHaveLength(0);
  });

  it("never assigns a wallet at admission (walletId is null)", async () => {
    const { sql, store } = newStore();
    const result = await admitReceiveExternal(store, validRequest(), config);
    expect(result.outcome).toBe("ADMITTED");
    if (result.outcome !== "ADMITTED") return;
    expect(result.operation.walletId).toBeNull();
    expect(sql.rows[0].wallet_id).toBeNull();
  });

  it("at RECEIVE_QUEUE_CAP returns receive_queue_full with Retry-After and creates nothing", async () => {
    const { sql, store } = newStore();
    // Fill the queue to the cap with distinct keys.
    for (let i = 0; i < 2; i++) {
      const admitted = await admitReceiveExternal(
        store,
        validRequest({ idempotencyKey: `queued-key-${i.toString().padStart(10, "0")}` }),
        { ...config, queueCap: 2, generateId: () => `op-q-${i}` },
      );
      expect(admitted.outcome).toBe("ADMITTED");
    }
    expect(sql.rows).toHaveLength(2);

    const rejected = await admitReceiveExternal(
      store,
      validRequest({ idempotencyKey: "zzzzzzzzzzzzzzzz" }),
      { ...config, queueCap: 2, generateId: () => "op-overflow" },
    );
    expect(rejected.outcome).toBe("REJECTED");
    if (rejected.outcome !== "REJECTED") return;
    expect(rejected.code).toBe("receive_queue_full");
    expect(rejected.retryAfterSeconds).toBe(RECEIVE_QUEUE_FULL_RETRY_AFTER_SECONDS);
    // No operation row created at all — not created-then-rolled-back.
    expect(sql.rows).toHaveLength(2);
    expect(sql.rows.every((row) => row.operation_id !== "op-overflow")).toBe(true);
  });

  it("a retry of an already-accepted key at queue cap still replays, never 503s", async () => {
    const { store } = newStore();
    const first = await admitReceiveExternal(store, validRequest(), { ...config, queueCap: 1 });
    expect(first.outcome).toBe("ADMITTED");
    if (first.outcome !== "ADMITTED") return;
    await store.completeOperation(first.operation.operationId, 202, '{"operation_id":"op-001"}');

    // Queue is full (depth=1, cap=1), but this key already has a completed row.
    const replay = await admitReceiveExternal(store, validRequest(), {
      ...config,
      queueCap: 1,
      generateId: () => "op-002",
    });
    expect(replay.outcome).toBe("IDEMPOTENT_REPLAY");
    if (replay.outcome !== "IDEMPOTENT_REPLAY") return;
    expect(replay.responseBody).toBe('{"operation_id":"op-001"}');
  });
});

function internalMoveFixture(): { sql: InProcessSqlExecutor; store: SqlReceiveAdmissionStore } {
  const created = newStore();
  created.sql.addDestination(blessedDestinationRow());
  return created;
}
