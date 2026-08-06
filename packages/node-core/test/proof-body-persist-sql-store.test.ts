import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  MAX_BODIES_PER_OPERATION,
  MAX_BODIES_PER_ROLE,
  MAX_BODIES_PER_TENANT,
  MAX_PATH_DEPTH,
  MAX_SIGHTINGS_PER_BODY,
  MAX_SIGHTINGS_PER_TENANT,
  MAX_TOTAL_BYTES_PER_TENANT,
  persistProofBody,
  type AuthenticatedRequestIdentity,
  type PersistProofBodyRequest,
  type ProofBodyAccepted,
  type StoredProofBody,
  type ValidatedProofBody,
} from "../src/proof-body/index.js";
import {
  CANDIDATE_COLUMNS,
  SqlProofBodyStore,
  STATEMENTS,
  type SqlExecutor,
  type SqlQueryResult,
} from "../src/proof-body/sql-store.js";

// Persistence logic suite RE-RUN against the durable
// SqlProofBodyStore (the real Postgres-backed store) rather than the in-memory double.
//
// Verification posture (honest, per node-core convention): node-core is network-contained
// (forbids a live PG socket in-package) and depends on no database driver, so the
// store is exercised through a faithful in-process SqlExecutor that models the three tables'
// constraints -- PK / full-tuple UNIQUE emitting SQLSTATE 23505, and the counter UPSERT
// increment. This drives the store's REAL parameterized SQL (STATEMENTS), REAL result
// mapping, and REAL error propagation. What it does NOT prove -- that a live Postgres parses
// and enforces the DDL as modeled (domain regexes, octet CHECKs, actual 23505 emission,
// atomic concurrent UPSERTs) -- is inventoried as schema-apply obligations in
// src/schema/proof-body-store.contract.ts. Those, not the store's logic, are the only legs
// that need a live database. Governing spec: the data model, the API contract, observation verification.

// --- Faithful in-process SqlExecutor over the three tables ---

function uniqueViolation(constraint: string): Error {
  return Object.assign(
    new Error(`duplicate key value violates unique constraint "${constraint}"`),
    { code: "23505", constraint },
  );
}

const slotKey = (pathProofId: unknown, pathIndex: unknown): string =>
  `${String(pathProofId)} ${String(pathIndex)}`;

class InProcessSqlExecutor implements SqlExecutor {
  // Column values stored as strings, mirroring node-postgres text/bigint-as-string returns.
  private readonly bodies = new Map<string, Record<string, string>>();
  private readonly slotCounters = new Map<string, number>();
  private readonly tenantCounters = new Map<string, number>();
  private pendingInsertError: unknown = undefined;

  // --- test seams (model direct-fixture setup the in-memory suite did via array pushes) ---

  failNextInsertWith(err: unknown): void {
    this.pendingInsertError = err;
  }

  seedCandidate(row: StoredProofBody): void {
    const record: Record<string, string> = {};
    for (const col of CANDIDATE_COLUMNS) {
      record[col] = String((row as Record<string, unknown>)[col]);
    }
    this.bodies.set(slotKey(row.path_proof_id, row.path_index), record);
  }

  seedTenantSightingCounter(tenantId: string, count: number): void {
    this.tenantCounters.set(tenantId, count);
  }

  bodyCount(): number {
    return this.bodies.size;
  }

  async query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> {
    const rows = this.run(text, params) as R[];
    return { rows };
  }

  private run(text: string, params: readonly unknown[]): unknown[] {
    switch (text) {
      case STATEMENTS.INSERT_CANDIDATE: {
        if (this.pendingInsertError !== undefined) {
          const err = this.pendingInsertError;
          this.pendingInsertError = undefined;
          throw err;
        }
        const record: Record<string, string> = {};
        CANDIDATE_COLUMNS.forEach((col, i) => {
          record[col] = String(params[i]);
        });
        const pk = slotKey(record.path_proof_id, record.path_index);
        if (this.bodies.has(pk)) {
          throw uniqueViolation("proof_channel_candidate_bodies_pkey");
        }
        for (const existing of this.bodies.values()) {
          if (
            existing.tenant_id === record.tenant_id &&
            existing.operation_id === record.operation_id &&
            existing.idempotency_key === record.idempotency_key
          ) {
            throw uniqueViolation("proof_channel_candidate_bodies_tenant_op_idem_key");
          }
        }
        this.bodies.set(pk, record);
        return [];
      }
      case STATEMENTS.SELECT_BY_SLOT: {
        const record = this.bodies.get(slotKey(params[0], params[1]));
        return record ? [record] : [];
      }
      case STATEMENTS.SELECT_BY_OPERATION_PATH: {
        const pathIndex = String(params[1]);
        return [...this.bodies.values()].filter(
          (r) => r.operation_id === params[0] && r.path_index === pathIndex,
        );
      }
      case STATEMENTS.SELECT_BY_DIGEST:
        return [...this.bodies.values()].filter((r) => r.raw_bytes_sha256 === params[0]);
      case STATEMENTS.SELECT_BY_IDEMPOTENCY: {
        const found = [...this.bodies.values()].find(
          (r) =>
            r.tenant_id === params[0] &&
            r.operation_id === params[1] &&
            r.idempotency_key === params[2],
        );
        return found ? [found] : [];
      }
      case STATEMENTS.COUNT_BY_TENANT:
        return [{ n: String([...this.bodies.values()].filter((r) => r.tenant_id === params[0]).length) }];
      case STATEMENTS.COUNT_BY_OPERATION:
        return [{ n: String([...this.bodies.values()].filter((r) => r.operation_id === params[0]).length) }];
      case STATEMENTS.COUNT_BY_ROLE:
        return [
          {
            n: String(
              [...this.bodies.values()].filter(
                (r) => r.tenant_id === params[0] && r.wallet_role === params[1],
              ).length,
            ),
          },
        ];
      case STATEMENTS.SUM_BYTES_BY_TENANT: {
        const sum = [...this.bodies.values()]
          .filter((r) => r.tenant_id === params[0])
          .reduce((acc, r) => acc + Number(r.completed_transaction_octets), 0);
        return [{ n: String(sum) }];
      }
      case STATEMENTS.UPSERT_SLOT_COUNTER: {
        const key = slotKey(params[0], params[1]);
        this.slotCounters.set(key, (this.slotCounters.get(key) ?? 0) + 1);
        return [];
      }
      case STATEMENTS.UPSERT_TENANT_COUNTER: {
        const key = String(params[0]);
        this.tenantCounters.set(key, (this.tenantCounters.get(key) ?? 0) + 1);
        return [];
      }
      case STATEMENTS.SELECT_SLOT_COUNTER: {
        const n = this.slotCounters.get(slotKey(params[0], params[1]));
        return n === undefined ? [] : [{ sighting_count: String(n) }];
      }
      case STATEMENTS.SELECT_TENANT_COUNTER: {
        const n = this.tenantCounters.get(String(params[0]));
        return n === undefined ? [] : [{ sighting_count: String(n) }];
      }
      default:
        throw new Error(`InProcessSqlExecutor: unmodelled statement:\n${text}`);
    }
  }
}

// --- Test fixtures (identical to proof-body-persist.test.ts, so the assertions are the
// same logic re-run against the durable store) ---

const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const PATH_PROOF_ID = "44444444-4444-4444-8444-444444444444";

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function makeBody(overrides: Partial<ValidatedProofBody> = {}): ValidatedProofBody {
  const txText = '{"inner":{"type":"unique_combinable","version":"2"}}';
  return {
    path_index: 0,
    source_kind: "PROOF_CHANNEL",
    completed_transaction_text: txText,
    completed_transaction_sha256: sha256Hex(txText),
    completed_transaction_octets: Buffer.byteLength(txText, "utf8"),
    wallet_role: "sender",
    s_signature: "sig-s-base64",
    p_signature: "sig-p-base64",
    b_amount: "10.00",
    inner_preimage_text: '{"type":"unique_combinable"}',
    inner_sha256: sha256Hex('{"type":"unique_combinable"}'),
    step_1_signature: "step1-sig-base64",
    step_2_signature: "step2-sig-base64",
    verification_manifest_text: '{"verifier":"fixture"}',
    verification_manifest_sha256: sha256Hex('{"verifier":"fixture"}'),
    ...overrides,
  };
}

function makeAccepted(body?: ValidatedProofBody): ProofBodyAccepted {
  const b = body ?? makeBody();
  const raw = JSON.stringify(b);
  return {
    accepted: true,
    body: b,
    rawBytes: new TextEncoder().encode(raw),
    rawSha256: sha256Hex(raw),
  };
}

function makeIdentity(overrides: Partial<AuthenticatedRequestIdentity> = {}): AuthenticatedRequestIdentity {
  return { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "sender", ...overrides };
}

function makeRequest(overrides: Partial<PersistProofBodyRequest> = {}): PersistProofBodyRequest {
  return {
    accepted: makeAccepted(),
    identity: makeIdentity(),
    path_proof_id: PATH_PROOF_ID,
    idempotency_key: "idem-key-001",
    ...overrides,
  };
}

// A minimal quota-prefill body row (matches the in-memory suite's direct row pushes).
function fillerRow(overrides: Partial<StoredProofBody>): StoredProofBody {
  return {
    path_proof_id: "pp-x",
    path_index: 0,
    source_kind: "PROOF_CHANNEL",
    completed_transaction_text: "tx",
    completed_transaction_sha256: "sha",
    completed_transaction_octets: 2,
    wallet_role: "sender",
    s_signature: "s",
    p_signature: "p",
    b_amount: "1",
    inner_preimage_text: "inner",
    inner_sha256: "isha",
    step_1_signature: "s1",
    step_2_signature: "s2",
    verification_manifest_text: "m",
    verification_manifest_sha256: "msha",
    raw_bytes_sha256: "digest-x",
    tenant_id: TENANT_ID,
    operation_id: "op-x",
    idempotency_key: "key-x",
    persisted_at: "2025-01-01T00:00:00.000Z",
    ...overrides,
  };
}

function newStore(): { store: SqlProofBodyStore; exec: InProcessSqlExecutor } {
  const exec = new InProcessSqlExecutor();
  return { store: new SqlProofBodyStore(exec), exec };
}

// --- Tests ---

describe("persistProofBody against the durable SqlProofBodyStore", () => {
  it("happy path: persists a valid accepted body", async () => {
    const { store, exec } = newStore();
    const request = makeRequest();

    const result = await persistProofBody(store, request);

    expect(result).toEqual({ persisted: true, sighting_count: 1 });
    expect(exec.bodyCount()).toBe(1);
    const stored = await store.findByPathProofAndIndex(PATH_PROOF_ID, 0);
    expect(stored?.path_proof_id).toBe(PATH_PROOF_ID);
    expect(stored?.tenant_id).toBe(TENANT_ID);
    expect(stored?.operation_id).toBe(OPERATION_ID);
    expect(stored?.wallet_role).toBe("sender");
    expect(stored?.source_kind).toBe("PROOF_CHANNEL");
    expect(stored?.path_index).toBe(0);
    expect(stored?.completed_transaction_octets).toBe(request.accepted.body.completed_transaction_octets);
    expect(stored?.raw_bytes_sha256).toBe(request.accepted.rawSha256);
    expect(await store.countSightingsBySlot(PATH_PROOF_ID, 0)).toBe(1);
  });

  it("idempotent retry: same key + same content returns success, no duplicate row", async () => {
    const { store, exec } = newStore();
    const request = makeRequest();

    expect(await persistProofBody(store, request)).toEqual({ persisted: true, sighting_count: 1 });
    const second = await persistProofBody(store, request);
    expect(second.persisted).toBe(true);
    if (second.persisted) expect(second.sighting_count).toBe(1);
    expect(exec.bodyCount()).toBe(1);
    // No sighting appended on the idempotent no-op.
    expect(await store.countSightingsBySlot(PATH_PROOF_ID, 0)).toBe(1);
  });

  it("idempotency conflict: same key + different content returns IDEMPOTENCY_CONFLICT", async () => {
    const { store, exec } = newStore();
    await persistProofBody(store, makeRequest());

    const request2 = makeRequest({
      accepted: makeAccepted(makeBody({ b_amount: "99.99" })),
      idempotency_key: "idem-key-001",
    });
    const result = await persistProofBody(store, request2);

    expect(result.persisted).toBe(false);
    if (!result.persisted) expect(result.reason).toBe("IDEMPOTENCY_CONFLICT");
    expect(exec.bodyCount()).toBe(1);
    expect((await store.findByPathProofAndIndex(PATH_PROOF_ID, 0))?.b_amount).toBe("10.00");
  });

  it("deduplication: same content same slot increments the counter, no duplicate row", async () => {
    const { store, exec } = newStore();
    await persistProofBody(store, makeRequest({ idempotency_key: "key-a" }));

    const result = await persistProofBody(store, makeRequest({ idempotency_key: "key-b" }));
    expect(result.persisted).toBe(true);
    if (result.persisted) expect(result.sighting_count).toBe(2);
    expect(exec.bodyCount()).toBe(1);
    expect(await store.countSightingsBySlot(PATH_PROOF_ID, 0)).toBe(2);
  });

  it("digest collision: different content same slot returns DIGEST_COLLISION, original preserved", async () => {
    const { store, exec } = newStore();
    await persistProofBody(store, makeRequest({ idempotency_key: "key-a" }));

    const result = await persistProofBody(
      store,
      makeRequest({ accepted: makeAccepted(makeBody({ b_amount: "55.55" })), idempotency_key: "key-b" }),
    );
    expect(result.persisted).toBe(false);
    if (!result.persisted) expect(result.reason).toBe("DIGEST_COLLISION");
    expect(exec.bodyCount()).toBe(1);
    expect((await store.findByPathProofAndIndex(PATH_PROOF_ID, 0))?.b_amount).toBe("10.00");
    // Collision sighting counted.
    expect(await store.countSightingsBySlot(PATH_PROOF_ID, 0)).toBe(2);
  });

  it("role conflict: same operation+path_index different role returns ROLE_CONFLICT", async () => {
    const { store, exec } = newStore();
    await persistProofBody(
      store,
      makeRequest({
        accepted: makeAccepted(makeBody({ wallet_role: "sender" })),
        identity: makeIdentity({ wallet_role: "sender" }),
        idempotency_key: "key-sender",
      }),
    );

    const result = await persistProofBody(
      store,
      makeRequest({
        accepted: makeAccepted(makeBody({ wallet_role: "receiver" })),
        identity: makeIdentity({ wallet_role: "receiver" }),
        path_proof_id: "55555555-5555-4555-8555-555555555555",
        idempotency_key: "key-receiver",
      }),
    );
    expect(result.persisted).toBe(false);
    if (!result.persisted) expect(result.reason).toBe("ROLE_CONFLICT");
    expect(exec.bodyCount()).toBe(1);
    expect((await store.findByPathProofAndIndex(PATH_PROOF_ID, 0))?.wallet_role).toBe("sender");
  });

  describe("quota enforcement", () => {
    it("fails closed on MAX_BODIES_PER_TENANT", async () => {
      const { store, exec } = newStore();
      for (let i = 0; i < MAX_BODIES_PER_TENANT; i++) {
        exec.seedCandidate(
          fillerRow({ path_proof_id: `pp-${i}`, path_index: i, operation_id: `op-${i}`, idempotency_key: `key-${i}`, raw_bytes_sha256: `digest-${i}` }),
        );
      }
      const result = await persistProofBody(store, makeRequest());
      expect(result.persisted).toBe(false);
      if (!result.persisted) {
        expect(result.reason).toBe("QUOTA_EXCEEDED");
        expect(result.detail).toContain("MAX_BODIES_PER_TENANT");
      }
    });

    it("fails closed on MAX_BODIES_PER_OPERATION", async () => {
      const { store, exec } = newStore();
      for (let i = 0; i < MAX_BODIES_PER_OPERATION; i++) {
        exec.seedCandidate(
          fillerRow({ path_proof_id: `pp-${i}`, path_index: i, operation_id: OPERATION_ID, idempotency_key: `key-${i}`, raw_bytes_sha256: `digest-${i}` }),
        );
      }
      const result = await persistProofBody(store, makeRequest());
      expect(result.persisted).toBe(false);
      if (!result.persisted) {
        expect(result.reason).toBe("QUOTA_EXCEEDED");
        expect(result.detail).toContain("MAX_BODIES_PER_OPERATION");
      }
    });

    it("fails closed on MAX_BODIES_PER_ROLE", async () => {
      const { store, exec } = newStore();
      for (let i = 0; i < MAX_BODIES_PER_ROLE; i++) {
        exec.seedCandidate(
          fillerRow({ path_proof_id: `pp-${i}`, path_index: i, operation_id: `op-${i}`, idempotency_key: `key-${i}`, raw_bytes_sha256: `digest-${i}` }),
        );
      }
      const result = await persistProofBody(store, makeRequest());
      expect(result.persisted).toBe(false);
      if (!result.persisted) {
        expect(result.reason).toBe("QUOTA_EXCEEDED");
        expect(result.detail).toContain("MAX_BODIES_PER_ROLE");
      }
    });

    it("fails closed on MAX_TOTAL_BYTES_PER_TENANT", async () => {
      const { store, exec } = newStore();
      exec.seedCandidate(
        fillerRow({ path_proof_id: "pp-fill", completed_transaction_octets: MAX_TOTAL_BYTES_PER_TENANT, operation_id: "op-other", idempotency_key: "key-fill", raw_bytes_sha256: "digest-fill" }),
      );
      const result = await persistProofBody(store, makeRequest());
      expect(result.persisted).toBe(false);
      if (!result.persisted) {
        expect(result.reason).toBe("QUOTA_EXCEEDED");
        expect(result.detail).toContain("MAX_TOTAL_BYTES_PER_TENANT");
      }
    });

    it("fails closed on MAX_PATH_DEPTH", async () => {
      const { store } = newStore();
      const request = makeRequest({ accepted: makeAccepted(makeBody({ path_index: MAX_PATH_DEPTH })) });
      const result = await persistProofBody(store, request);
      expect(result.persisted).toBe(false);
      if (!result.persisted) {
        expect(result.reason).toBe("QUOTA_EXCEEDED");
        expect(result.detail).toContain("MAX_PATH_DEPTH");
      }
    });
  });

  it("non-authority: SqlProofBodyStore exposes no verdict/lease/retry/promote/release method", () => {
    const keys = Object.getOwnPropertyNames(SqlProofBodyStore.prototype);
    const forbidden = ["verdict", "lease", "retry", "authorize", "promote", "release"];
    for (const key of keys) {
      for (const word of forbidden) {
        expect(key.toLowerCase()).not.toContain(word);
      }
    }
  });

  // --- regressions, re-run against the durable store ---

  it("cross-tenant idempotency: same key different tenant does NOT conflict", async () => {
    const { store, exec } = newStore();
    await persistProofBody(
      store,
      makeRequest({
        accepted: makeAccepted(makeBody({ b_amount: "10.00" })),
        identity: makeIdentity({ tenant_id: "tenant-aaaa", operation_id: "op-aaaa" }),
        idempotency_key: "K",
      }),
    );
    const second = await persistProofBody(
      store,
      makeRequest({
        accepted: makeAccepted(makeBody({ b_amount: "20.00" })),
        identity: makeIdentity({ tenant_id: "tenant-bbbb", operation_id: "op-bbbb" }),
        path_proof_id: "66666666-6666-4666-8666-666666666666",
        idempotency_key: "K",
      }),
    );
    expect(second.persisted).toBe(true);
    expect(exec.bodyCount()).toBe(2);
  });

  it("wallet_role: stored row uses identity.wallet_role, not body.wallet_role", async () => {
    const { store } = newStore();
    const result = await persistProofBody(
      store,
      makeRequest({ accepted: makeAccepted(makeBody({ wallet_role: "sender" })), identity: makeIdentity({ wallet_role: "receiver" }) }),
    );
    expect(result.persisted).toBe(true);
    expect((await store.findByPathProofAndIndex(PATH_PROOF_ID, 0))?.wallet_role).toBe("receiver");
  });

  it("wallet_role: conflict check uses identity.wallet_role against siblings", async () => {
    const { store } = newStore();
    await persistProofBody(
      store,
      makeRequest({ accepted: makeAccepted(makeBody({ wallet_role: "sender" })), identity: makeIdentity({ wallet_role: "sender" }), idempotency_key: "key-s1" }),
    );
    const result = await persistProofBody(
      store,
      makeRequest({
        accepted: makeAccepted(makeBody({ wallet_role: "sender" })),
        identity: makeIdentity({ wallet_role: "receiver" }),
        path_proof_id: "77777777-7777-4777-8777-777777777777",
        idempotency_key: "key-s2",
      }),
    );
    expect(result.persisted).toBe(false);
    if (!result.persisted) expect(result.reason).toBe("ROLE_CONFLICT");
  });

  it("TOCTOU race: unique-constraint violation on insert returns DIGEST_COLLISION", async () => {
    const { store, exec } = newStore();
    exec.failNextInsertWith(
      new Error("UNIQUE constraint failed: proof_channel_candidate_bodies.path_proof_id, path_index"),
    );
    const result = await persistProofBody(store, makeRequest());
    expect(result.persisted).toBe(false);
    if (!result.persisted) {
      expect(result.reason).toBe("DIGEST_COLLISION");
      expect(result.detail).toContain("concurrent insert at same slot");
    }
  });

  it("TOCTOU race: postgres 23505 code also returns DIGEST_COLLISION", async () => {
    const { store, exec } = newStore();
    const pgError = Object.assign(new Error("duplicate key value violates unique constraint"), { code: "23505" });
    exec.failNextInsertWith(pgError);
    const result = await persistProofBody(store, makeRequest());
    expect(result.persisted).toBe(false);
    if (!result.persisted) expect(result.reason).toBe("DIGEST_COLLISION");
  });

  it("TOCTOU race: non-unique errors are re-thrown", async () => {
    const { store, exec } = newStore();
    exec.failNextInsertWith(new Error("connection reset by peer"));
    await expect(persistProofBody(store, makeRequest())).rejects.toThrow("connection reset by peer");
  });

  // --- Sighting-cap enforcement against the bounded COUNTER ---

  describe("sighting caps fail closed on the counter", () => {
    it("per-slot: dedup sightings fail closed AT MAX_SIGHTINGS_PER_BODY (not cap+1)", async () => {
      const { store, exec } = newStore();
      expect((await persistProofBody(store, makeRequest({ idempotency_key: "k-1" }))).persisted).toBe(true);

      for (let i = 2; i <= MAX_SIGHTINGS_PER_BODY; i++) {
        const r = await persistProofBody(store, makeRequest({ idempotency_key: `k-${i}` }));
        expect(r.persisted).toBe(true);
      }
      expect(await store.countSightingsBySlot(PATH_PROOF_ID, 0)).toBe(MAX_SIGHTINGS_PER_BODY);

      const overflow = await persistProofBody(store, makeRequest({ idempotency_key: "k-overflow" }));
      expect(overflow.persisted).toBe(false);
      if (!overflow.persisted) {
        expect(overflow.reason).toBe("QUOTA_EXCEEDED");
        expect(overflow.detail).toContain("MAX_SIGHTINGS_PER_BODY");
      }
      // Not cap+1: counter unchanged, no duplicate row.
      expect(await store.countSightingsBySlot(PATH_PROOF_ID, 0)).toBe(MAX_SIGHTINGS_PER_BODY);
      expect(exec.bodyCount()).toBe(1);
    });

    it("per-tenant: sightings fail closed AT MAX_SIGHTINGS_PER_TENANT (not cap+1)", async () => {
      const { store, exec } = newStore();
      // Seed the bounded tenant counter to one below the cap (the whole point of a counter:
      // no 50k rows needed). No body rows, so body quotas stay clear.
      exec.seedTenantSightingCounter(TENANT_ID, MAX_SIGHTINGS_PER_TENANT - 1);

      const atCap = await persistProofBody(
        store,
        makeRequest({ path_proof_id: "88888888-8888-4888-8888-888888888888", identity: makeIdentity({ operation_id: "op-atcap" }), idempotency_key: "k-atcap" }),
      );
      expect(atCap.persisted).toBe(true);
      expect(await store.countSightingsByTenant(TENANT_ID)).toBe(MAX_SIGHTINGS_PER_TENANT);
      const rowsAtCap = exec.bodyCount();

      const overflow = await persistProofBody(
        store,
        makeRequest({ path_proof_id: "99999999-9999-4999-8999-999999999999", identity: makeIdentity({ operation_id: "op-overflow" }), idempotency_key: "k-tenant-overflow" }),
      );
      expect(overflow.persisted).toBe(false);
      if (!overflow.persisted) {
        expect(overflow.reason).toBe("QUOTA_EXCEEDED");
        expect(overflow.detail).toContain("MAX_SIGHTINGS_PER_TENANT");
      }
      expect(await store.countSightingsByTenant(TENANT_ID)).toBe(MAX_SIGHTINGS_PER_TENANT);
      expect(exec.bodyCount()).toBe(rowsAtCap);
    });

    it("per-tenant cap closes the role-conflict fresh-slot spray the per-slot cap misses", async () => {
      const { store, exec } = newStore();
      // A legitimate sender sibling at (operation, path_index 0).
      exec.seedCandidate(
        fillerRow({ path_proof_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", operation_id: OPERATION_ID, idempotency_key: "sibling-key", raw_bytes_sha256: "sibling-digest" }),
      );
      // Tenant sighting counter already at the cap; the per-slot cap gives no help (fresh slots).
      exec.seedTenantSightingCounter(TENANT_ID, MAX_SIGHTINGS_PER_TENANT);

      const attack = await persistProofBody(
        store,
        makeRequest({
          accepted: makeAccepted(makeBody({ wallet_role: "receiver" })),
          identity: makeIdentity({ wallet_role: "receiver" }),
          path_proof_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
          idempotency_key: "attack-1",
        }),
      );
      expect(attack.persisted).toBe(false);
      if (!attack.persisted) {
        expect(attack.reason).toBe("QUOTA_EXCEEDED");
        expect(attack.detail).toContain("MAX_SIGHTINGS_PER_TENANT");
      }
      // Fail closed: counter not incremented past the cap.
      expect(await store.countSightingsByTenant(TENANT_ID)).toBe(MAX_SIGHTINGS_PER_TENANT);
    });
  });
});
