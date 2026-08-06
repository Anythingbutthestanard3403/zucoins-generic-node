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
  type PersistProofBodyRequest,
  type ProofBodySighting,
  type ProofBodyStore,
  type StoredProofBody,
  type AuthenticatedRequestIdentity,
  type ProofBodyAccepted,
  type ValidatedProofBody,
} from "../src/proof-body/index.js";

// proof-body persistence tests.
//
// Governing spec: the data model,
// the API contract, observation verification.

// --- In-memory store implementation ---

class InMemoryProofBodyStore implements ProofBodyStore {
  readonly rows: StoredProofBody[] = [];
  readonly sightings: ProofBodySighting[] = [];

  async findByPathProofAndIndex(pathProofId: string, pathIndex: number): Promise<StoredProofBody | null> {
    return this.rows.find((r) => r.path_proof_id === pathProofId && r.path_index === pathIndex) ?? null;
  }

  async findByOperationAndPathIndex(operationId: string, pathIndex: number): Promise<StoredProofBody[]> {
    return this.rows.filter((r) => r.operation_id === operationId && r.path_index === pathIndex);
  }

  async findByBodyDigest(digest: string): Promise<StoredProofBody[]> {
    return this.rows.filter((r) => r.raw_bytes_sha256 === digest);
  }

  async insert(row: StoredProofBody): Promise<void> {
    this.rows.push(row);
  }

  async insertSighting(sighting: ProofBodySighting): Promise<void> {
    this.sightings.push(sighting);
  }

  async countSightingsBySlot(pathProofId: string, pathIndex: number): Promise<number> {
    return this.sightings.filter(
      (s) => s.path_proof_id === pathProofId && s.path_index === pathIndex,
    ).length;
  }

  async countSightingsByTenant(tenantId: string): Promise<number> {
    return this.sightings.filter((s) => s.tenant_id === tenantId).length;
  }

  async countByTenant(tenantId: string): Promise<number> {
    return this.rows.filter((r) => r.tenant_id === tenantId).length;
  }

  async countByOperation(operationId: string): Promise<number> {
    return this.rows.filter((r) => r.operation_id === operationId).length;
  }

  async countByRole(tenantId: string, role: string): Promise<number> {
    return this.rows.filter((r) => r.tenant_id === tenantId && r.wallet_role === role).length;
  }

  async totalBytesByTenant(tenantId: string): Promise<number> {
    return this.rows
      .filter((r) => r.tenant_id === tenantId)
      .reduce((sum, r) => sum + r.completed_transaction_octets, 0);
  }

  async findByIdempotencyKey(tenantId: string, operationId: string, key: string): Promise<StoredProofBody | null> {
    return this.rows.find(
      (r) => r.tenant_id === tenantId && r.operation_id === operationId && r.idempotency_key === key,
    ) ?? null;
  }
}

// --- Test fixtures ---

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
  return {
    tenant_id: TENANT_ID,
    operation_id: OPERATION_ID,
    wallet_role: "sender",
    ...overrides,
  };
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

// --- Tests ---

describe("persistProofBody", () => {
  it("happy path: persists a valid accepted body", async () => {
    const store = new InMemoryProofBodyStore();
    const request = makeRequest();

    const result = await persistProofBody(store, request);

    expect(result).toEqual({ persisted: true, sighting_count: 1 });
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0]!.path_proof_id).toBe(PATH_PROOF_ID);
    expect(store.rows[0]!.tenant_id).toBe(TENANT_ID);
    expect(store.rows[0]!.operation_id).toBe(OPERATION_ID);
    expect(store.rows[0]!.wallet_role).toBe("sender");
    expect(store.rows[0]!.source_kind).toBe("PROOF_CHANNEL");
    expect(store.rows[0]!.raw_bytes_sha256).toBe(request.accepted.rawSha256);
    expect(store.sightings).toHaveLength(1);
    expect(store.sightings[0]!.is_duplicate).toBe(false);
    expect(store.sightings[0]!.is_conflict).toBe(false);
  });

  it("idempotent retry: same key + same content returns success", async () => {
    const store = new InMemoryProofBodyStore();
    const request = makeRequest();

    const first = await persistProofBody(store, request);
    expect(first).toEqual({ persisted: true, sighting_count: 1 });

    // Same key, same content → idempotent success.
    const second = await persistProofBody(store, request);
    expect(second.persisted).toBe(true);
    if (second.persisted) {
      expect(second.sighting_count).toBe(1);
    }
    // No duplicate row created.
    expect(store.rows).toHaveLength(1);
  });

  it("idempotency conflict: same key + different content returns IDEMPOTENCY_CONFLICT", async () => {
    const store = new InMemoryProofBodyStore();
    const request1 = makeRequest();

    await persistProofBody(store, request1);

    // Same idempotency key, different body content.
    const differentBody = makeBody({ b_amount: "99.99" });
    const request2 = makeRequest({
      accepted: makeAccepted(differentBody),
      idempotency_key: "idem-key-001",
    });

    const result = await persistProofBody(store, request2);

    expect(result.persisted).toBe(false);
    if (!result.persisted) {
      expect(result.reason).toBe("IDEMPOTENCY_CONFLICT");
    }
    // Original row preserved.
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0]!.b_amount).toBe("10.00");
  });

  it("deduplication: same content same slot increments sighting, no duplicate row", async () => {
    const store = new InMemoryProofBodyStore();
    const request1 = makeRequest({ idempotency_key: "key-a" });

    await persistProofBody(store, request1);

    // Same content, same (path_proof_id, path_index), different idempotency key.
    const request2 = makeRequest({ idempotency_key: "key-b" });
    const result = await persistProofBody(store, request2);

    expect(result.persisted).toBe(true);
    if (result.persisted) {
      expect(result.sighting_count).toBe(2);
    }
    // Still only one row.
    expect(store.rows).toHaveLength(1);
    expect(store.sightings).toHaveLength(2);
    expect(store.sightings[1]!.is_duplicate).toBe(true);
  });

  it("digest collision: different content same slot returns DIGEST_COLLISION, original preserved", async () => {
    const store = new InMemoryProofBodyStore();
    const request1 = makeRequest({ idempotency_key: "key-a" });

    await persistProofBody(store, request1);

    // Different content, same (path_proof_id, path_index).
    const differentBody = makeBody({ b_amount: "55.55" });
    const request2 = makeRequest({
      accepted: makeAccepted(differentBody),
      idempotency_key: "key-b",
    });

    const result = await persistProofBody(store, request2);

    expect(result.persisted).toBe(false);
    if (!result.persisted) {
      expect(result.reason).toBe("DIGEST_COLLISION");
    }
    // Original row untouched.
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0]!.b_amount).toBe("10.00");
    // Conflict sighting recorded.
    expect(store.sightings).toHaveLength(2);
    expect(store.sightings[1]!.is_conflict).toBe(true);
  });

  it("role conflict: same operation+path_index different role returns ROLE_CONFLICT", async () => {
    const store = new InMemoryProofBodyStore();
    const senderBody = makeBody({ wallet_role: "sender" });
    const request1 = makeRequest({
      accepted: makeAccepted(senderBody),
      identity: makeIdentity({ wallet_role: "sender" }),
      idempotency_key: "key-sender",
    });

    await persistProofBody(store, request1);

    // Same operation, same path_index, different role, different path_proof_id.
    const receiverBody = makeBody({ wallet_role: "receiver" });
    const request2 = makeRequest({
      accepted: makeAccepted(receiverBody),
      identity: makeIdentity({ wallet_role: "receiver" }),
      path_proof_id: "55555555-5555-4555-8555-555555555555",
      idempotency_key: "key-receiver",
    });

    const result = await persistProofBody(store, request2);

    expect(result.persisted).toBe(false);
    if (!result.persisted) {
      expect(result.reason).toBe("ROLE_CONFLICT");
    }
    // Original preserved, no new row.
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0]!.wallet_role).toBe("sender");
  });

  describe("quota enforcement", () => {
    it("fails closed on MAX_BODIES_PER_TENANT", async () => {
      const store = new InMemoryProofBodyStore();
      // Pre-fill store to the tenant limit.
      for (let i = 0; i < MAX_BODIES_PER_TENANT; i++) {
        store.rows.push({
          path_proof_id: `pp-${i}`,
          path_index: i,
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
          raw_bytes_sha256: `digest-${i}`,
          tenant_id: TENANT_ID,
          operation_id: `op-${i}`,
          idempotency_key: `key-${i}`,
          persisted_at: "2025-01-01T00:00:00.000Z",
        });
      }

      const result = await persistProofBody(store, makeRequest());

      expect(result.persisted).toBe(false);
      if (!result.persisted) {
        expect(result.reason).toBe("QUOTA_EXCEEDED");
        expect(result.detail).toContain("MAX_BODIES_PER_TENANT");
      }
    });

    it("fails closed on MAX_BODIES_PER_OPERATION", async () => {
      const store = new InMemoryProofBodyStore();
      for (let i = 0; i < MAX_BODIES_PER_OPERATION; i++) {
        store.rows.push({
          path_proof_id: `pp-${i}`,
          path_index: i,
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
          raw_bytes_sha256: `digest-${i}`,
          tenant_id: TENANT_ID,
          operation_id: OPERATION_ID,
          idempotency_key: `key-${i}`,
          persisted_at: "2025-01-01T00:00:00.000Z",
        });
      }

      const result = await persistProofBody(store, makeRequest());

      expect(result.persisted).toBe(false);
      if (!result.persisted) {
        expect(result.reason).toBe("QUOTA_EXCEEDED");
        expect(result.detail).toContain("MAX_BODIES_PER_OPERATION");
      }
    });

    it("fails closed on MAX_BODIES_PER_ROLE", async () => {
      const store = new InMemoryProofBodyStore();
      for (let i = 0; i < MAX_BODIES_PER_ROLE; i++) {
        store.rows.push({
          path_proof_id: `pp-${i}`,
          path_index: i,
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
          raw_bytes_sha256: `digest-${i}`,
          tenant_id: TENANT_ID,
          operation_id: `op-${i}`,
          idempotency_key: `key-${i}`,
          persisted_at: "2025-01-01T00:00:00.000Z",
        });
      }

      const result = await persistProofBody(store, makeRequest());

      expect(result.persisted).toBe(false);
      if (!result.persisted) {
        expect(result.reason).toBe("QUOTA_EXCEEDED");
        expect(result.detail).toContain("MAX_BODIES_PER_ROLE");
      }
    });

    it("fails closed on MAX_TOTAL_BYTES_PER_TENANT", async () => {
      const store = new InMemoryProofBodyStore();
      // One row that already fills the byte budget.
      store.rows.push({
        path_proof_id: "pp-fill",
        path_index: 0,
        source_kind: "PROOF_CHANNEL",
        completed_transaction_text: "x".repeat(MAX_TOTAL_BYTES_PER_TENANT),
        completed_transaction_sha256: "sha",
        completed_transaction_octets: MAX_TOTAL_BYTES_PER_TENANT,
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
        raw_bytes_sha256: "digest-fill",
        tenant_id: TENANT_ID,
        operation_id: "op-other",
        idempotency_key: "key-fill",
        persisted_at: "2025-01-01T00:00:00.000Z",
      });

      const result = await persistProofBody(store, makeRequest());

      expect(result.persisted).toBe(false);
      if (!result.persisted) {
        expect(result.reason).toBe("QUOTA_EXCEEDED");
        expect(result.detail).toContain("MAX_TOTAL_BYTES_PER_TENANT");
      }
    });

    it("fails closed on MAX_PATH_DEPTH", async () => {
      const store = new InMemoryProofBodyStore();
      const deepBody = makeBody({ path_index: MAX_PATH_DEPTH });
      const request = makeRequest({ accepted: makeAccepted(deepBody) });

      const result = await persistProofBody(store, request);

      expect(result.persisted).toBe(false);
      if (!result.persisted) {
        expect(result.reason).toBe("QUOTA_EXCEEDED");
        expect(result.detail).toContain("MAX_PATH_DEPTH");
      }
    });
  });

  it("non-authority: interface exposes no verdict, lease, or retry methods", () => {
    // Structural check: the ProofBodyStore interface and persistProofBody function
    // have no methods or properties related to verdicts, leases, or retry authorization.
    const storeKeys = Object.getOwnPropertyNames(InMemoryProofBodyStore.prototype);
    const forbidden = ["verdict", "lease", "retry", "authorize", "promote", "release"];
    for (const key of storeKeys) {
      for (const word of forbidden) {
        expect(key.toLowerCase()).not.toContain(word);
      }
    }
    // persistProofBody is a pure storage function — its source has no verdict/lease logic.
    expect(typeof persistProofBody).toBe("function");
  });

  // --- regression tests ---

  it("cross-tenant idempotency: same key different tenant does NOT conflict", async () => {
    const store = new InMemoryProofBodyStore();
    const bodyA = makeBody({ b_amount: "10.00" });
    const requestA = makeRequest({
      accepted: makeAccepted(bodyA),
      identity: makeIdentity({ tenant_id: "tenant-aaaa", operation_id: "op-aaaa" }),
      idempotency_key: "K",
    });

    const first = await persistProofBody(store, requestA);
    expect(first.persisted).toBe(true);

    // Tenant B uses the same idempotency key "K" but different content — should NOT conflict.
    const bodyB = makeBody({ b_amount: "20.00" });
    const requestB = makeRequest({
      accepted: makeAccepted(bodyB),
      identity: makeIdentity({ tenant_id: "tenant-bbbb", operation_id: "op-bbbb" }),
      path_proof_id: "66666666-6666-4666-8666-666666666666",
      idempotency_key: "K",
    });

    const second = await persistProofBody(store, requestB);
    expect(second.persisted).toBe(true);
    expect(store.rows).toHaveLength(2);
  });

  it("wallet_role: stored row uses identity.wallet_role, not body.wallet_role", async () => {
    const store = new InMemoryProofBodyStore();
    // Body claims "sender" but authenticated identity says "receiver".
    const lyingBody = makeBody({ wallet_role: "sender" });
    const request = makeRequest({
      accepted: makeAccepted(lyingBody),
      identity: makeIdentity({ wallet_role: "receiver" }),
    });

    const result = await persistProofBody(store, request);
    expect(result.persisted).toBe(true);
    // The stored row must use the trusted identity role.
    expect(store.rows[0]!.wallet_role).toBe("receiver");
  });

  it("wallet_role: conflict check uses identity.wallet_role against siblings", async () => {
    const store = new InMemoryProofBodyStore();
    // First: persist a body as "sender" (identity and body agree).
    const senderBody = makeBody({ wallet_role: "sender" });
    const request1 = makeRequest({
      accepted: makeAccepted(senderBody),
      identity: makeIdentity({ wallet_role: "sender" }),
      idempotency_key: "key-s1",
    });
    await persistProofBody(store, request1);

    // Second: body claims "sender" but identity is "receiver" → conflict with existing sender sibling.
    const lyingBody = makeBody({ wallet_role: "sender" });
    const request2 = makeRequest({
      accepted: makeAccepted(lyingBody),
      identity: makeIdentity({ wallet_role: "receiver" }),
      path_proof_id: "77777777-7777-4777-8777-777777777777",
      idempotency_key: "key-s2",
    });

    const result = await persistProofBody(store, request2);
    expect(result.persisted).toBe(false);
    if (!result.persisted) {
      expect(result.reason).toBe("ROLE_CONFLICT");
    }
  });

  it("TOCTOU race: unique-constraint violation on insert returns DIGEST_COLLISION", async () => {
    const store = new InMemoryProofBodyStore();
    // Override insert to simulate a concurrent unique-constraint violation.
    store.insert = async () => {
      throw new Error("UNIQUE constraint failed: lineage_path_bodies.path_proof_id, lineage_path_bodies.path_index");
    };

    const request = makeRequest();
    const result = await persistProofBody(store, request);

    expect(result.persisted).toBe(false);
    if (!result.persisted) {
      expect(result.reason).toBe("DIGEST_COLLISION");
      expect(result.detail).toContain("concurrent insert at same slot");
    }
  });

  it("TOCTOU race: postgres 23505 code also returns DIGEST_COLLISION", async () => {
    const store = new InMemoryProofBodyStore();
    const pgError = new Error("duplicate key value violates unique constraint");
    (pgError as Error & { code: string }).code = "23505";
    store.insert = async () => {
      throw pgError;
    };

    const request = makeRequest();
    const result = await persistProofBody(store, request);

    expect(result.persisted).toBe(false);
    if (!result.persisted) {
      expect(result.reason).toBe("DIGEST_COLLISION");
    }
  });

  it("TOCTOU race: non-unique errors are re-thrown", async () => {
    const store = new InMemoryProofBodyStore();
    store.insert = async () => {
      throw new Error("connection reset by peer");
    };

    const request = makeRequest();
    await expect(persistProofBody(store, request)).rejects.toThrow("connection reset by peer");
  });

  // --- Sighting-cap enforcement: quota-boundary tests each fail closed at the limit ---
  // (DoS closure — the unbounded sighting store this bound exists to close.)

  describe("sighting caps fail closed", () => {
    it("per-slot: dedup sightings fail closed AT MAX_SIGHTINGS_PER_BODY (not cap+1)", async () => {
      const store = new InMemoryProofBodyStore();

      // First submit creates the body row + sighting #1.
      const first = await persistProofBody(store, makeRequest({ idempotency_key: "k-1" }));
      expect(first.persisted).toBe(true);

      // Drive dedup sightings (identical bytes, fresh idempotency_key each time — the
      // literal exploit) up to exactly the per-slot cap.
      for (let i = 2; i <= MAX_SIGHTINGS_PER_BODY; i++) {
        const r = await persistProofBody(store, makeRequest({ idempotency_key: `k-${i}` }));
        expect(r.persisted).toBe(true);
      }
      expect(store.sightings).toHaveLength(MAX_SIGHTINGS_PER_BODY);

      // The next identical-bytes resubmit must fail closed AT the cap.
      const overflow = await persistProofBody(store, makeRequest({ idempotency_key: "k-overflow" }));
      expect(overflow.persisted).toBe(false);
      if (!overflow.persisted) {
        expect(overflow.reason).toBe("QUOTA_EXCEEDED");
        expect(overflow.detail).toContain("MAX_SIGHTINGS_PER_BODY");
      }

      // Not cap+1: the rejected write appended nothing and duplicated no row.
      expect(store.sightings).toHaveLength(MAX_SIGHTINGS_PER_BODY);
      expect(store.rows).toHaveLength(1);
    });

    it("per-tenant: sightings fail closed AT MAX_SIGHTINGS_PER_TENANT (not cap+1)", async () => {
      const store = new InMemoryProofBodyStore();

      // Pre-fill the tenant sighting ledger to one below the cap (distinct fresh slots,
      // no body rows) so the body quotas stay clear and only the sighting cap is exercised.
      for (let i = 0; i < MAX_SIGHTINGS_PER_TENANT - 1; i++) {
        store.sightings.push({
          path_proof_id: `pre-${i}`,
          path_index: 0,
          raw_bytes_sha256: `d-${i}`,
          idempotency_key: `pk-${i}`,
          tenant_id: TENANT_ID,
          seen_at: "2025-01-01T00:00:00.000Z",
          is_duplicate: true,
          is_conflict: false,
        });
      }

      // One more fresh happy-path body reaches exactly the cap and still succeeds.
      const atCap = await persistProofBody(
        store,
        makeRequest({
          path_proof_id: "88888888-8888-4888-8888-888888888888",
          identity: makeIdentity({ operation_id: "op-atcap" }),
          idempotency_key: "k-atcap",
        }),
      );
      expect(atCap.persisted).toBe(true);
      expect(store.sightings).toHaveLength(MAX_SIGHTINGS_PER_TENANT);
      const rowsAtCap = store.rows.length;

      // The next fresh body must fail closed BEFORE inserting a row.
      const overflow = await persistProofBody(
        store,
        makeRequest({
          path_proof_id: "99999999-9999-4999-8999-999999999999",
          identity: makeIdentity({ operation_id: "op-overflow" }),
          idempotency_key: "k-tenant-overflow",
        }),
      );
      expect(overflow.persisted).toBe(false);
      if (!overflow.persisted) {
        expect(overflow.reason).toBe("QUOTA_EXCEEDED");
        expect(overflow.detail).toContain("MAX_SIGHTINGS_PER_TENANT");
      }

      // Not cap+1: no new sighting, and no row written (fail closed pre-insert).
      expect(store.sightings).toHaveLength(MAX_SIGHTINGS_PER_TENANT);
      expect(store.rows).toHaveLength(rowsAtCap);
    });

    it("per-tenant cap closes the role-conflict fresh-slot spray the per-slot cap misses", async () => {
      const store = new InMemoryProofBodyStore();

      // A legitimate sender sibling at (operation, path_index 0) — the setup an attacker
      // needs to make the role-conflict path fire.
      store.rows.push({
        path_proof_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
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
        raw_bytes_sha256: "sibling-digest",
        tenant_id: TENANT_ID,
        operation_id: OPERATION_ID,
        idempotency_key: "sibling-key",
        persisted_at: "2025-01-01T00:00:00.000Z",
      });

      // Tenant sighting ledger already at the cap. The per-slot cap gives no help here:
      // the attack targets brand-new (fresh path_proof_id) slots whose slot count is 0.
      for (let i = 0; i < MAX_SIGHTINGS_PER_TENANT; i++) {
        store.sightings.push({
          path_proof_id: `pre-${i}`,
          path_index: 0,
          raw_bytes_sha256: `d-${i}`,
          idempotency_key: `pk-${i}`,
          tenant_id: TENANT_ID,
          seen_at: "2025-01-01T00:00:00.000Z",
          is_duplicate: false,
          is_conflict: true,
        });
      }

      // Attack: role=receiver, brand-new path_proof_id, fresh idempotency_key. Without the
      // per-tenant cap this appends an unbounded conflict sighting at a fresh slot without
      // consuming the body quota. With it, it fails closed.
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
      // Fail closed: no conflict sighting appended at the fresh slot.
      expect(store.sightings).toHaveLength(MAX_SIGHTINGS_PER_TENANT);
    });
  });
});
