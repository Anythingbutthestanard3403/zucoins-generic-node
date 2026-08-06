import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  intakeProofBody,
  MAX_PROOF_BODY_BYTES,
  persistProofBody,
  type PersistProofBodyRequest,
  type ProofBodyIntakeRequest,
  type ProofBodySighting,
  type ProofBodyStore,
  type StoredProofBody,
} from "../src/proof-body/index.js";

// Adversarial non-authority proof suite.
//
// Proves the invariant: supplied bodies are untrusted evidence until verified and
// fresh-head-anchored. The persistence layer has NO authority-granting methods; stored
// rows carry NO verdict/authority fields; intake rejection leaks NO projection fields.

// --- In-memory store (same pattern as proof-body-persist.test.ts) ---

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

// --- Fixtures ---

const TENANT_ID = "tenant-1";
const OPERATION_ID = "op-1";
const PATH_PROOF_ID = "pp-1";

function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function makeValidBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    path_index: 0,
    source_kind: "PROOF_CHANNEL",
    completed_transaction_text: '{"purpose":"zp-receive-expected-artifact-v1"}',
    completed_transaction_sha256: "a".repeat(64),
    completed_transaction_octets: 45,
    wallet_role: "receiver",
    s_signature: "A".repeat(86) + "==",
    p_signature: "",
    b_amount: "1.5",
    inner_preimage_text: "zp-receive-expected-artifact-v1\n{}",
    inner_sha256: "b".repeat(64),
    step_1_signature: "C".repeat(86) + "==",
    step_2_signature: "D".repeat(86) + "==",
    verification_manifest_text: '{"manifest":true}',
    verification_manifest_sha256: "c".repeat(64),
    ...overrides,
  };
}

function makeIntakeRequest(
  body: Record<string, unknown>,
  overrides: Partial<ProofBodyIntakeRequest> = {},
): ProofBodyIntakeRequest {
  const text = JSON.stringify(body);
  const rawBytes = new TextEncoder().encode(text);
  return {
    authenticated: { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "receiver" },
    expected: { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "receiver" },
    transport: {
      claimed_signature: "x".repeat(86) + "==",
      content_length: rawBytes.byteLength,
      media_type: "application/json",
      request_id: "req-1",
      provenance: "test",
    },
    rawBytes,
    ...overrides,
  };
}

function makePersistRequest(
  accepted: Parameters<typeof persistProofBody>[1]["accepted"],
  overrides: Partial<PersistProofBodyRequest> = {},
): PersistProofBodyRequest {
  return {
    accepted,
    identity: { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "receiver" },
    path_proof_id: PATH_PROOF_ID,
    idempotency_key: `idem-${Math.random().toString(36).slice(2)}`,
    ...overrides,
  };
}

// Authority-related field names that must NEVER appear on a stored row.
const AUTHORITY_FIELDS = ["verdict", "landed", "authorized", "released", "promoted"] as const;

// Authority-related method name fragments that must NEVER appear on the store interface.
const AUTHORITY_METHOD_FRAGMENTS = [
  "verify", "land", "release", "promote", "authorize", "retry", "resubmit", "close", "verdict",
] as const;

function assertNoAuthorityFields(row: StoredProofBody): void {
  const keys = Object.keys(row);
  for (const field of AUTHORITY_FIELDS) {
    expect(keys).not.toContain(field);
  }
}

// --- Group 1: Intake rejection produces no authority ---

describe("Group 1: intake rejection produces no authority", () => {
  const fixtures: Array<{ name: string; request: ProofBodyIntakeRequest }> = [
    {
      name: "forged signature (not valid base64url-86-chars)",
      request: makeIntakeRequest(makeValidBody({ s_signature: "FORGED_SIG_SHORT" })),
    },
    {
      name: "invalid JSON (not parseable)",
      request: (() => {
        const rawBytes = new TextEncoder().encode("{not valid json at all!!!");
        return {
          authenticated: { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "receiver" as const },
          expected: { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "receiver" as const },
          transport: {
            claimed_signature: "x".repeat(86) + "==",
            content_length: rawBytes.byteLength,
            media_type: "application/json",
            request_id: "req-invalid-json",
            provenance: "test",
          },
          rawBytes,
        };
      })(),
    },
    {
      name: "wrong source_kind (CANONICAL_LEDGER)",
      request: makeIntakeRequest(makeValidBody({ source_kind: "CANONICAL_LEDGER" })),
    },
    {
      name: "missing required field (inner_sha256 omitted)",
      request: (() => {
        const body = makeValidBody();
        delete body.inner_sha256;
        return makeIntakeRequest(body);
      })(),
    },
    {
      name: "unknown extra field (verdict smuggled in)",
      request: makeIntakeRequest(makeValidBody({ verdict: "LANDED_VERIFIED" })),
    },
    {
      name: "oversize body (exceeds MAX_PROOF_BODY_BYTES)",
      request: (() => {
        const padding = "x".repeat(MAX_PROOF_BODY_BYTES + 1);
        const rawBytes = new TextEncoder().encode(padding);
        return {
          authenticated: { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "receiver" as const },
          expected: { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "receiver" as const },
          transport: {
            claimed_signature: "x".repeat(86) + "==",
            content_length: rawBytes.byteLength,
            media_type: "application/json",
            request_id: "req-oversize",
            provenance: "test",
          },
          rawBytes,
        };
      })(),
    },
  ];

  for (const { name, request } of fixtures) {
    it(`rejects: ${name}`, () => {
      const result = intakeProofBody(request);

      expect(result.accepted).toBe(false);
      if (!result.accepted) {
        // No projection/body field leaks on rejection.
        expect("body" in result).toBe(false);
        // Evidence is still captured.
        expect(result.rawBytes).toBeInstanceOf(Uint8Array);
        expect(result.rawBytes.byteLength).toBeGreaterThan(0);
        expect(result.rawSha256).toMatch(/^[0-9a-f]{64}$/);
        expect(result.rawSha256).toBe(sha256Hex(request.rawBytes));
      }
    });
  }
});

// --- Group 2: Accepted bodies persist as candidate-only evidence ---

describe("Group 2: accepted bodies persist as candidate-only evidence", () => {
  it("happy path: persists with PROOF_CHANNEL source_kind and no authority field", async () => {
    const store = new InMemoryProofBodyStore();
    const intakeResult = intakeProofBody(makeIntakeRequest(makeValidBody()));
    expect(intakeResult.accepted).toBe(true);
    if (!intakeResult.accepted) return;

    const result = await persistProofBody(store, makePersistRequest(intakeResult, { idempotency_key: "key-happy" }));

    expect(result.persisted).toBe(true);
    expect(store.rows).toHaveLength(1);
    const row = store.rows[0]!;
    expect(row.source_kind).toBe("PROOF_CHANNEL");
    assertNoAuthorityFields(row);
  });

  it("dedup: same body resubmitted increments sighting, still no authority field", async () => {
    const store = new InMemoryProofBodyStore();
    const intakeResult = intakeProofBody(makeIntakeRequest(makeValidBody()));
    expect(intakeResult.accepted).toBe(true);
    if (!intakeResult.accepted) return;

    await persistProofBody(store, makePersistRequest(intakeResult, { idempotency_key: "key-dedup-a" }));
    const second = await persistProofBody(store, makePersistRequest(intakeResult, { idempotency_key: "key-dedup-b" }));

    expect(second.persisted).toBe(true);
    if (second.persisted) {
      expect(second.sighting_count).toBe(2);
    }
    expect(store.rows).toHaveLength(1);
    assertNoAuthorityFields(store.rows[0]!);
  });

  it("collision: different body at same slot returns DIGEST_COLLISION, original unchanged", async () => {
    const store = new InMemoryProofBodyStore();
    const intake1 = intakeProofBody(makeIntakeRequest(makeValidBody()));
    expect(intake1.accepted).toBe(true);
    if (!intake1.accepted) return;

    await persistProofBody(store, makePersistRequest(intake1, { idempotency_key: "key-coll-a" }));

    // Different body content, same slot (path_proof_id, path_index).
    const intake2 = intakeProofBody(makeIntakeRequest(makeValidBody({ b_amount: "99.9" })));
    expect(intake2.accepted).toBe(true);
    if (!intake2.accepted) return;

    const result = await persistProofBody(store, makePersistRequest(intake2, { idempotency_key: "key-coll-b" }));

    expect(result.persisted).toBe(false);
    if (!result.persisted) {
      expect(result.reason).toBe("DIGEST_COLLISION");
    }
    // Original row unchanged, no authority granted.
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0]!.b_amount).toBe("1.5");
    assertNoAuthorityFields(store.rows[0]!);
  });

  it("quota-exhausted: at limit returns QUOTA_EXCEEDED, no partial write, no authority", async () => {
    const store = new InMemoryProofBodyStore();
    // Pre-fill to MAX_BODIES_PER_OPERATION (100) for this operation.
    for (let i = 0; i < 100; i++) {
      store.rows.push({
        path_proof_id: `pp-fill-${i}`,
        path_index: i,
        source_kind: "PROOF_CHANNEL",
        completed_transaction_text: "tx",
        completed_transaction_sha256: "a".repeat(64),
        completed_transaction_octets: 2,
        wallet_role: "receiver",
        s_signature: "s",
        p_signature: "",
        b_amount: "1",
        inner_preimage_text: "inner",
        inner_sha256: "b".repeat(64),
        step_1_signature: "s1",
        step_2_signature: "s2",
        verification_manifest_text: "m",
        verification_manifest_sha256: "c".repeat(64),
        raw_bytes_sha256: `digest-${i}`,
        tenant_id: TENANT_ID,
        operation_id: OPERATION_ID,
        idempotency_key: `key-fill-${i}`,
        persisted_at: "2025-01-01T00:00:00.000Z",
      });
    }

    const intakeResult = intakeProofBody(makeIntakeRequest(makeValidBody()));
    expect(intakeResult.accepted).toBe(true);
    if (!intakeResult.accepted) return;

    const result = await persistProofBody(store, makePersistRequest(intakeResult, { idempotency_key: "key-quota" }));

    expect(result.persisted).toBe(false);
    if (!result.persisted) {
      expect(result.reason).toBe("QUOTA_EXCEEDED");
    }
    // No partial write occurred.
    expect(store.rows).toHaveLength(100);
  });
});

// --- Group 3: Identity mismatch never produces stored evidence ---

describe("Group 3: identity mismatch never produces stored evidence", () => {
  it("wrong tenant: rejected at intake, nothing persisted", () => {
    const store = new InMemoryProofBodyStore();
    const request = makeIntakeRequest(makeValidBody(), {
      authenticated: { tenant_id: "evil-tenant", operation_id: OPERATION_ID, wallet_role: "receiver" },
    });

    const result = intakeProofBody(request);

    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.code).toBe("TENANT_MISMATCH");
    }
    expect(store.rows).toHaveLength(0);
  });

  it("wrong operation: rejected at intake, nothing persisted", () => {
    const store = new InMemoryProofBodyStore();
    const request = makeIntakeRequest(makeValidBody(), {
      authenticated: { tenant_id: TENANT_ID, operation_id: "evil-op", wallet_role: "receiver" },
    });

    const result = intakeProofBody(request);

    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.code).toBe("OPERATION_MISMATCH");
    }
    expect(store.rows).toHaveLength(0);
  });

  it("wrong role: rejected at intake, nothing persisted", () => {
    const store = new InMemoryProofBodyStore();
    const request = makeIntakeRequest(makeValidBody(), {
      authenticated: { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "sender" },
    });

    const result = intakeProofBody(request);

    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.code).toBe("ROLE_MISMATCH");
    }
    expect(store.rows).toHaveLength(0);
  });
});

// --- Group 4: Structural non-authority proof (meta-test) ---

describe("Group 4: structural non-authority proof", () => {
  it("ProofBodyStore interface has no authority-granting methods", () => {
    const storeKeys = Object.getOwnPropertyNames(InMemoryProofBodyStore.prototype);
    for (const key of storeKeys) {
      for (const fragment of AUTHORITY_METHOD_FRAGMENTS) {
        expect(key.toLowerCase()).not.toContain(fragment);
      }
    }
  });

  it("PersistProofBodyResult success branch has only persisted and sighting_count", async () => {
    const store = new InMemoryProofBodyStore();
    const intakeResult = intakeProofBody(makeIntakeRequest(makeValidBody()));
    expect(intakeResult.accepted).toBe(true);
    if (!intakeResult.accepted) return;

    const result = await persistProofBody(store, makePersistRequest(intakeResult, { idempotency_key: "key-meta" }));

    expect(result.persisted).toBe(true);
    if (result.persisted) {
      const keys = Object.keys(result);
      expect(keys.sort()).toEqual(["persisted", "sighting_count"]);
    }
  });

  it("StoredProofBody has no verdict/authority field", async () => {
    const store = new InMemoryProofBodyStore();
    const intakeResult = intakeProofBody(makeIntakeRequest(makeValidBody()));
    expect(intakeResult.accepted).toBe(true);
    if (!intakeResult.accepted) return;

    await persistProofBody(store, makePersistRequest(intakeResult, { idempotency_key: "key-fields" }));

    const row = store.rows[0]!;
    const rowKeys = Object.keys(row);
    for (const field of AUTHORITY_FIELDS) {
      expect(rowKeys).not.toContain(field);
    }
    // source_kind is always PROOF_CHANNEL, never CANONICAL_LEDGER or FRESH_GATEWAY_HEAD.
    expect(row.source_kind).toBe("PROOF_CHANNEL");
  });
});

// --- Group 5: Positive control — read-only completeness check ---

describe("Group 5: positive control (verifier can consume evidence without authority)", () => {
  // Simulates what would do: read candidates, verify contiguity. Read-only.
  function simulateCompletePathVerification(
    store: InMemoryProofBodyStore,
    pathProofId: string,
  ): { complete: true; bodyCount: number } | { complete: false } {
    const bodies = store.rows
      .filter((r) => r.path_proof_id === pathProofId)
      .sort((a, b) => a.path_index - b.path_index);

    if (bodies.length === 0) return { complete: false };

    for (let i = 0; i < bodies.length; i++) {
      if (bodies[i]!.path_index !== i) return { complete: false };
    }

    return { complete: true, bodyCount: bodies.length };
  }

  it("verifier reads stored candidates and confirms completeness without granting authority", async () => {
    const store = new InMemoryProofBodyStore();

    // Persist a contiguous 3-body path (indices 0, 1, 2).
    for (let i = 0; i < 3; i++) {
      const body = makeValidBody({ path_index: i });
      const intakeResult = intakeProofBody(makeIntakeRequest(body));
      expect(intakeResult.accepted).toBe(true);
      if (!intakeResult.accepted) return;

      const result = await persistProofBody(store, makePersistRequest(intakeResult, { idempotency_key: `key-path-${i}` }));
      expect(result.persisted).toBe(true);
    }

    // The verifier CAN read and confirm completeness...
    const verification = simulateCompletePathVerification(store, PATH_PROOF_ID);
    expect(verification).toEqual({ complete: true, bodyCount: 3 });

    // ...but the stored rows still carry no authority — the persistence layer did not
    // grant any verdict. Authority comes only from fresh-head-anchoring.
    for (const row of store.rows) {
      expect(row.source_kind).toBe("PROOF_CHANNEL");
      assertNoAuthorityFields(row);
    }
  });

  it("incomplete path returns complete: false (gap detection)", async () => {
    const store = new InMemoryProofBodyStore();

    // Persist indices 0 and 2 (gap at 1).
    for (const idx of [0, 2]) {
      const body = makeValidBody({ path_index: idx });
      const intakeResult = intakeProofBody(makeIntakeRequest(body));
      expect(intakeResult.accepted).toBe(true);
      if (!intakeResult.accepted) return;

      await persistProofBody(store, makePersistRequest(intakeResult, { idempotency_key: `key-gap-${idx}` }));
    }

    const verification = simulateCompletePathVerification(store, PATH_PROOF_ID);
    expect(verification).toEqual({ complete: false });
  });
});

// --- Group 6: remediation regression guards ---
//
// Two MEDIUM defects were identified in an earlier persist.ts
// and required regression tests that fail against the pre-fix code and pass against the
// corrected code (head ef886b13). These two cases feed exactly the inputs that exercised
// those defects. Governing: the API contract (operator non-authority)
// (candidate bodies are never authoritative).

describe("Group 6: remediation regression guards", () => {
  // (a) Untrusted body.wallet_role must never be silently stored, nor drive the integrity
  // gate. Pre-fix defect: persist stored `wallet_role: body.wallet_role` and ran the
  // role-mapping-conflict gate on `body.wallet_role` — both trusting an attacker-controlled
  // field over the authenticated identity. Corrected persist normalizes to
  // identity.wallet_role for BOTH storage and the gate.
  it("wallet_role mismatch: body role is normalized to identity, never stored nor used for the gate", async () => {
    // Facet 1 — storage normalization. Intake accepts a schema-valid body whose wallet_role
    // ("sender") differs from the authenticated identity ("receiver"): intake binds
    // authenticated<->expected only and deliberately does NOT cross-check the body field, so
    // the mismatch reaches persist exactly as the pre-fix defect required. The stored role
    // MUST be the authenticated identity, never the untrusted body value. Pre-fix stored
    // "sender" (body) and FAILS this assertion; corrected stores "receiver" (identity).
    const storageStore = new InMemoryProofBodyStore();
    const mismatchIntake = intakeProofBody(makeIntakeRequest(makeValidBody({ wallet_role: "sender" })));
    expect(mismatchIntake.accepted).toBe(true);
    if (!mismatchIntake.accepted) return;
    // The untrusted value is genuinely present on the accepted candidate.
    expect(mismatchIntake.body.wallet_role).toBe("sender");

    const stored = await persistProofBody(
      storageStore,
      makePersistRequest(mismatchIntake, {
        identity: { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "receiver" },
        idempotency_key: "key-role-normalize",
      }),
    );

    expect(stored.persisted).toBe(true);
    expect(storageStore.rows).toHaveLength(1);
    expect(storageStore.rows[0]!.wallet_role).toBe("receiver");
    expect(storageStore.rows[0]!.wallet_role).not.toBe("sender");
    assertNoAuthorityFields(storageStore.rows[0]!);

    // Facet 2 — integrity gate. The role-mapping-conflict gate MUST key on identity.wallet_role,
    // not the untrusted body field. Seed a legitimate receiver body (body role == identity), so
    // the seed row carries "receiver" under ANY correct implementation. Then submit a second
    // body at the same (operation_id, path_index) whose AUTHENTICATED role also matches
    // ("receiver") but whose BODY role is forged to "sender". Pre-fix compared the seed's
    // "receiver" to the forged body "sender" -> spurious ROLE_CONFLICT (persisted:false) and
    // FAILS the assertion below; corrected compares to identity "receiver" -> genuine match
    // -> persists. (A fresh store isolates this from Facet 1.)
    const gateStore = new InMemoryProofBodyStore();
    const seedIntake = intakeProofBody(makeIntakeRequest(makeValidBody({ wallet_role: "receiver" })));
    expect(seedIntake.accepted).toBe(true);
    if (!seedIntake.accepted) return;
    const seed = await persistProofBody(
      gateStore,
      makePersistRequest(seedIntake, {
        identity: { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "receiver" },
        path_proof_id: "pp-seed",
        idempotency_key: "key-role-seed",
      }),
    );
    expect(seed.persisted).toBe(true);
    expect(gateStore.rows[0]!.wallet_role).toBe("receiver");

    const forgedRole = intakeProofBody(makeIntakeRequest(makeValidBody({ wallet_role: "sender", b_amount: "7.0" })));
    expect(forgedRole.accepted).toBe(true);
    if (!forgedRole.accepted) return;
    const gated = await persistProofBody(
      gateStore,
      makePersistRequest(forgedRole, {
        identity: { tenant_id: TENANT_ID, operation_id: OPERATION_ID, wallet_role: "receiver" },
        path_proof_id: "pp-forged",
        idempotency_key: "key-role-forged",
      }),
    );

    expect(gated.persisted).toBe(true);
    expect(gateStore.rows).toHaveLength(2);
    expect(gateStore.rows[1]!.wallet_role).toBe("receiver");
    assertNoAuthorityFields(gateStore.rows[1]!);
  });

  // (b) Cross-tenant idempotency-key collision. Pre-fix defect: the idempotency lookup was
  // GLOBAL (keyed on idempotency_key alone), so a second tenant reusing the same key string
  // was mis-adjudicated against the first tenant's row — either silently dropped
  // (IDEMPOTENCY_CONFLICT on differing content) or absorbed into the first tenant's row
  // (treated as an idempotent retry on identical content). Corrected persist scopes the
  // lookup to (tenant_id, operation_id, idempotency_key), isolating each tenant's row.
  it("cross-tenant idempotency collision: second tenant's write is isolated, not dropped nor cross-contaminated", async () => {
    const store = new InMemoryProofBodyStore();
    const SHARED_KEY = "collision-key";

    // Two unrelated tenants/operations; only the idempotency-key string collides. Distinct
    // body content (b_amount) so a GLOBAL lookup would treat tenant B as a content conflict
    // against tenant A's row — the exact pre-fix drop. This is the SPECIFIC defect input.
    const intakeA = intakeProofBody(
      makeIntakeRequest(makeValidBody({ b_amount: "1.0" }), {
        authenticated: { tenant_id: "tenant-A", operation_id: "op-A", wallet_role: "receiver" },
        expected: { tenant_id: "tenant-A", operation_id: "op-A", wallet_role: "receiver" },
      }),
    );
    expect(intakeA.accepted).toBe(true);
    if (!intakeA.accepted) return;

    const intakeB = intakeProofBody(
      makeIntakeRequest(makeValidBody({ b_amount: "2.0" }), {
        authenticated: { tenant_id: "tenant-B", operation_id: "op-B", wallet_role: "receiver" },
        expected: { tenant_id: "tenant-B", operation_id: "op-B", wallet_role: "receiver" },
      }),
    );
    expect(intakeB.accepted).toBe(true);
    if (!intakeB.accepted) return;

    const resultA = await persistProofBody(
      store,
      makePersistRequest(intakeA, {
        identity: { tenant_id: "tenant-A", operation_id: "op-A", wallet_role: "receiver" },
        path_proof_id: "pp-A",
        idempotency_key: SHARED_KEY,
      }),
    );
    expect(resultA.persisted).toBe(true);

    const resultB = await persistProofBody(
      store,
      makePersistRequest(intakeB, {
        identity: { tenant_id: "tenant-B", operation_id: "op-B", wallet_role: "receiver" },
        path_proof_id: "pp-B",
        idempotency_key: SHARED_KEY,
      }),
    );

    // Not silently dropped (pre-fix global lookup -> IDEMPOTENCY_CONFLICT -> persisted:false).
    expect(resultB.persisted).toBe(true);
    // Not cross-contaminated: two independent rows, each isolated to its own tenant.
    expect(store.rows).toHaveLength(2);
    const rowA = store.rows.find((r) => r.tenant_id === "tenant-A");
    const rowB = store.rows.find((r) => r.tenant_id === "tenant-B");
    expect(rowA).toBeDefined();
    expect(rowB).toBeDefined();
    // Tenant B's row carries B's own content and identity, never A's.
    expect(rowB!.b_amount).toBe("2.0");
    expect(rowB!.operation_id).toBe("op-B");
    expect(rowB!.path_proof_id).toBe("pp-B");
    expect(rowB!.idempotency_key).toBe(SHARED_KEY);
    // The shared key resolves to a DIFFERENT row per tenant — proving tenant-scoped lookup.
    expect(rowA!.raw_bytes_sha256).not.toBe(rowB!.raw_bytes_sha256);
    assertNoAuthorityFields(rowB!);
  });
});
