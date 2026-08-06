import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { IMPLEMENTER_SCOPES as FROZEN_IMPLEMENTER_SCOPES } from "@zucoins/generic-node-contracts/api-schema";
import {
  CANONICAL_AUTH_ERROR_HEADERS,
  CANONICAL_AUTH_FAILURE_BODY,
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_AUTH_FAILURE_MESSAGE,
  REJECTED_AUTH_ERROR_CODES,
  isNonOracular,
  normalizeRequestId,
  type WireResponse,
} from "@zucoins/generic-node-contracts/auth-errors";

import { apiErrorResponse } from "../src/api/error-envelope.js";
import {
  assertScope,
  BEARER_KEY_PREFIX,
  CredentialAuthError,
  CredentialError,
  CredentialService,
  CREDENTIAL_STATEMENTS,
  hashCredential,
  IMPLEMENTER_SCOPES,
  SqlCredentialStore,
  validateScopes,
  type CredentialStore,
  type CredentialAuditEntry,
  type StoredCredential,
} from "../src/credential/index.js";
import type { SqlExecutor } from "../src/proof-body/sql-store.js";

class InMemoryCredentialStore implements CredentialStore {
  readonly rows: StoredCredential[] = [];
  readonly audits: CredentialAuditEntry[] = [];

  async issue(
    row: StoredCredential,
    audit: CredentialAuditEntry,
  ): Promise<void> {
    this.rows.push(row);
    this.audits.push(audit);
  }

  async findByHash(credentialHash: string): Promise<StoredCredential | null> {
    return this.rows.find((r) => r.credential_hash === credentialHash) ?? null;
  }

  async findById(credentialId: string, implementerId: string): Promise<StoredCredential | null> {
    return this.rows.find((r) => r.id === credentialId && r.implementer_id === implementerId) ?? null;
  }

  async listByImplementer(implementerId: string): Promise<StoredCredential[]> {
    return this.rows.filter((r) => r.implementer_id === implementerId);
  }

  async rotate(
    credentialId: string,
    implementerId: string,
    replacement: StoredCredential,
    rotatedAt: string,
    graceUntil: string,
    audit: CredentialAuditEntry,
  ): Promise<boolean> {
    const idx = this.rows.findIndex(
      (row) =>
        row.id === credentialId &&
        row.implementer_id === implementerId &&
        row.status === "ACTIVE",
    );
    if (idx === -1) return false;
    this.rows[idx] = {
      ...this.rows[idx]!,
      status: "GRACE",
      rotated_to_id: replacement.id,
      rotated_at: rotatedAt,
      rotation_grace_until: graceUntil,
      revoked_at: graceUntil,
    };
    this.rows.push(replacement);
    this.audits.push(audit);
    return true;
  }

  async revoke(
    credentialId: string,
    implementerId: string,
    revokedAt: string,
    audit: CredentialAuditEntry,
  ): Promise<boolean> {
    const idx = this.rows.findIndex(
      (row) =>
        row.id === credentialId &&
        row.implementer_id === implementerId &&
        (row.status === "ACTIVE" || row.status === "GRACE"),
    );
    if (idx === -1) return false;
    this.rows[idx] = {
      ...this.rows[idx]!,
      status: "REVOKED",
      revoked_at: revokedAt,
    };
    this.audits.push(audit);
    return true;
  }
}

describe("SqlCredentialStore", () => {
  const revokeAudit: CredentialAuditEntry = {
    id: "audit-1",
    implementer_id: "impl-1",
    action: "IMPLEMENTER_CREDENTIAL_REVOKED",
    credential_id: "credential-1",
    replacement_credential_id: null,
    created_at: "2026-07-26T00:00:00.000Z",
  };

  function storedCredential(
    id: string,
    overrides: Partial<StoredCredential> = {},
  ): StoredCredential {
    return {
      id,
      implementer_id: "impl-1",
      public_prefix: "ik_12345678",
      credential_hash: "a".repeat(64),
      scopes: ["receive:read"],
      status: "ACTIVE",
      key_version: 1,
      issued_at: "2026-07-26T00:00:00.000Z",
      expires_at: null,
      revoked_at: null,
      rotated_from_id: null,
      rotated_to_id: null,
      rotated_at: null,
      rotation_grace_until: null,
      ...overrides,
    };
  }

  // An in-process fake cannot demonstrate that PostgreSQL rolls a mutation back — it has no
  // transaction to roll back, and any "nothing was committed" assertion over its own state holds
  // by construction of the fake rather than by anything the store did. What IS provable here is
  // the structural precondition that makes rollback automatic: each mutation reaches the driver
  // as exactly ONE statement, and that statement carries the audit insert. Single-statement
  // semantics then give all-or-nothing for free.
  //
  // The runtime rollback itself is proven against real PostgreSQL in
  // implementer-credentials.pg.test.ts ("a failing audit insert rolls the whole ROTATE back").
  class StatementRecorder implements SqlExecutor {
    readonly statements: string[] = [];

    async query<R>(text: string): Promise<{ readonly rows: R[] }> {
      this.statements.push(text);
      return { rows: [] as R[] };
    }
  }

  it("sends each mutation as one statement that carries its own audit insert", async () => {
    const original = storedCredential("credential-1");
    const replacement = storedCredential("credential-2", {
      key_version: 2,
      rotated_from_id: original.id,
    });

    const mutations: ReadonlyArray<
      readonly [string, (store: SqlCredentialStore) => Promise<unknown>]
    > = [
      ["issue", (store) => store.issue(original, revokeAudit)],
      [
        "rotate",
        (store) =>
          store.rotate(
            original.id,
            "impl-1",
            replacement,
            "2026-07-26T00:01:00.000Z",
            "2026-07-26T00:02:00.000Z",
            {
              ...revokeAudit,
              action: "IMPLEMENTER_CREDENTIAL_ROTATED",
              replacement_credential_id: replacement.id,
            },
          ),
      ],
      [
        "revoke",
        (store) =>
          store.revoke(
            original.id,
            "impl-1",
            "2026-07-26T00:01:00.000Z",
            revokeAudit,
          ),
      ],
    ];

    for (const [name, mutate] of mutations) {
      const recorder = new StatementRecorder();
      await mutate(new SqlCredentialStore(recorder, "node-1"));
      expect(recorder.statements, `${name} must issue exactly one statement`).toHaveLength(1);
      // Coupled, not merely adjacent: the audit insert selects FROM the mutation's own CTE, so
      // there is no statement boundary between them at which one could commit alone.
      expect(recorder.statements[0]).toContain("INSERT INTO audit_log");
      expect(recorder.statements[0]).toMatch(
        /INSERT INTO audit_log[\s\S]*FROM (issued|replacement|revoked)/,
      );
    }
  });

  it("reports revoke success only for a live credential owned by the implementer", async () => {
    const rows = new Map([
      ["credential-1", { implementerId: "impl-1", revokedAt: null as string | null }],
      ["credential-2", { implementerId: "impl-2", revokedAt: null as string | null }],
    ]);
    const sql: SqlExecutor = {
      async query<R>(text: string, params: readonly unknown[]) {
        expect(text).toBe(CREDENTIAL_STATEMENTS.REVOKE);
        const [credentialId, implementerId, revokedAt] = params as [
          string,
          string,
          string,
        ];
        const row = rows.get(credentialId);
        if (
          row === undefined ||
          row.implementerId !== implementerId ||
          row.revokedAt !== null
        ) {
          return { rows: [] };
        }
        row.revokedAt = revokedAt;
        return {
          rows: /UPDATE implementer_credentials[\s\S]*RETURNING id[\s\S]*INSERT INTO audit_log/.test(
            text,
          )
            ? ([{ id: credentialId }] as R[])
            : [],
        };
      },
    };
    const store = new SqlCredentialStore(sql, "node-1");

    await expect(
      store.revoke(
        "credential-2",
        "impl-1",
        "2026-07-26T00:00:00.000Z",
        revokeAudit,
      ),
    ).resolves.toBe(false);
    await expect(
      store.revoke(
        "credential-1",
        "impl-1",
        "2026-07-26T00:00:00.000Z",
        revokeAudit,
      ),
    ).resolves.toBe(true);
    await expect(
      store.revoke(
        "credential-1",
        "impl-1",
        "2026-07-26T00:01:00.000Z",
        revokeAudit,
      ),
    ).resolves.toBe(false);
  });

  it("persists a secret-free audit row with the stored details digest", async () => {
    let captured: { text: string; params: readonly unknown[] } | undefined;
    const sql: SqlExecutor = {
      async query<R>(text: string, params: readonly unknown[]) {
        captured = { text, params };
        return { rows: [] as R[] };
      },
    };
    const store = new SqlCredentialStore(sql, "node-1");
    await store.revoke(
      "credential-1",
      "impl-1",
      "2026-07-26T00:00:00.000Z",
      revokeAudit,
    );

    expect(captured?.text).toBe(CREDENTIAL_STATEMENTS.REVOKE);
    // [0..2] revoke args, then auditParams: id, node_id, actor_kind, actor_id, action,
    // details_text, details_sha256, created_at. actor_kind became a bound parameter with
    // P1#2 (it was a hardcoded literal), which shifted details_text to [8].
    expect(captured?.params[5]).toBe("IMPLEMENTER");
    expect(captured?.params[8]).toBe(
      '{"credential_id":"credential-1","replacement_credential_id":null}',
    );
    expect(captured?.params[9]).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(captured?.params)).not.toContain("ik_");
  });
});

describe("credential scope validation", () => {
  // Identity, not deep equality: a re-minted local copy with byte-identical values would satisfy
  // toEqual and silently stop tracking an api-contract amendment. Only `toBe` proves the module
  // CONSUMES the frozen vocabulary.
  it("consumes the frozen api-contract scope vocabulary rather than a local copy", () => {
    expect(IMPLEMENTER_SCOPES).toBe(FROZEN_IMPLEMENTER_SCOPES);
  });

  it("accepts all defined scopes", () => {
    const result = validateScopes([...IMPLEMENTER_SCOPES]);
    expect(result).toHaveLength(IMPLEMENTER_SCOPES.length);
  });

  it("rejects unknown scopes", () => {
    expect(() => validateScopes(["admin:all"])).toThrow(CredentialError);
  });

  it("rejects empty scope list", () => {
    expect(() => validateScopes([])).toThrow("at least one scope");
  });

  it("deduplicates scopes", () => {
    const result = validateScopes(["receive:create", "receive:create"]);
    expect(result).toEqual(["receive:create"]);
  });
});

describe("credential hashing", () => {
  it("produces a 64-char hex SHA-256", () => {
    expect(hashCredential("ik_test123")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic", () => {
    expect(hashCredential("ik_abc")).toBe(hashCredential("ik_abc"));
  });

  it("different keys produce different hashes", () => {
    expect(hashCredential("ik_a")).not.toBe(hashCredential("ik_b"));
  });
});

// The fingerprint any later read surface renders must be the value stored at issue time,
// never a hash computed at query time. These are code-path assertions on that property, not a
// restatement of how the column is populated.
describe("stored fingerprint is surfaced, never re-derived on the read path", () => {
  const credentialSrc = resolve(dirname(fileURLToPath(import.meta.url)), "../src/credential");

  it("the read layer cannot derive a fingerprint: sql-store.ts never references hashCredential", () => {
    // sql-store.ts owns every read (findByHash / findById / listByImplementer). If it cannot
    // reach the hash function, no read can compute a fingerprint — the only source left is the
    // projected column. This fails the moment a read-time derivation is introduced.
    expect(readFileSync(join(credentialSrc, "sql-store.ts"), "utf8")).not.toContain(
      "hashCredential",
    );
  });

  it("hashCredential is invoked at exactly two sites: issue-time storage and presented-key lookup", () => {
    const calls = [
      ...readFileSync(join(credentialSrc, "types.ts"), "utf8").matchAll(
        /hashCredential\(/g,
      ),
    ];
    // One declaration plus two call sites: `credential_hash: hashCredential(rawKey)` when the row
    // is constructed, and hashing the PRESENTED key in validate() to look a row up. A third call
    // would be a re-derivation and must fail this assertion deliberately.
    expect(calls).toHaveLength(3);
  });

  it("a read returns the stored column byte-for-byte, not a recomputation", async () => {
    // A sentinel that is not the SHA-256 of anything the service holds: if the read path
    // recomputed, it could not reproduce this value.
    const SENTINEL = "f".repeat(64);
    const sql: SqlExecutor = {
      async query<R>(text: string) {
        expect(text).toBe(CREDENTIAL_STATEMENTS.SELECT_BY_ID);
        expect(text).toContain("credential_hash");
        return {
          rows: [
            {
              id: "credential-1",
              implementer_id: "impl-1",
              public_prefix: "ik_12345678",
              credential_hash: SENTINEL,
              scopes: ["receive:read"],
              status: "ACTIVE",
              key_version: 1,
              issued_at: "2026-07-26T00:00:00.000Z",
              expires_at: null,
              revoked_at: null,
              rotated_from_id: null,
              rotated_to_id: null,
              rotated_at: null,
              rotation_grace_until: null,
            },
          ] as R[],
        };
      },
    };
    const found = await new SqlCredentialStore(sql, "node-1").findById(
      "credential-1",
      "impl-1",
    );
    expect(found?.credential_hash).toBe(SENTINEL);
  });
});

describe("CredentialService lifecycle", () => {
  function setup() {
    const store = new InMemoryCredentialStore();
    const service = new CredentialService(store);
    return { store, service };
  }

  it("creates a credential and returns the raw key once", async () => {
    const { store, service } = setup();
    const result = await service.create("impl-1", ["receive:create", "receive:read"]);
    expect(result.raw_key).toMatch(new RegExp(`^${BEARER_KEY_PREFIX}`));
    expect(result.scopes).toEqual(["receive:create", "receive:read"]);
    expect(result.credential_id).toBeDefined();
    expect(result.public_prefix).toBe(result.raw_key.slice(0, 11));
    expect(store.rows[0]!.credential_hash).not.toContain(result.raw_key);
    expect(store.audits.map((audit) => audit.action)).toEqual([
      "IMPLEMENTER_CREDENTIAL_ISSUED",
    ]);
  });

  it("rotates with version metadata and accepts the old key only during grace", async () => {
    let now = new Date("2026-07-26T00:00:00.000Z");
    const store = new InMemoryCredentialStore();
    const service = new CredentialService(store, () => now);
    const original = await service.create("impl-1", ["send:create"]);
    const replacement = await service.rotate(original.credential_id, "impl-1", 60);

    expect(replacement.key_version).toBe(2);
    expect(store.rows[0]).toMatchObject({
      status: "GRACE",
      rotated_to_id: replacement.credential_id,
      rotation_grace_until: "2026-07-26T00:01:00.000Z",
    });
    await expect(service.validate(original.raw_key)).resolves.toMatchObject({
      credential_id: original.credential_id,
    });
    now = new Date("2026-07-26T00:01:00.000Z");
    await expect(service.validate(original.raw_key)).rejects.toThrow(CredentialAuthError);
    await expect(service.validate(replacement.raw_key)).resolves.toMatchObject({
      credential_id: replacement.credential_id,
    });
    expect(store.audits.map((audit) => audit.action)).toEqual([
      "IMPLEMENTER_CREDENTIAL_ISSUED",
      "IMPLEMENTER_CREDENTIAL_ROTATED",
    ]);
  });

  // A past-expiry credential sits at stored status ACTIVE forever — expiry is read-time, nothing
  // writes it back. Without the guard, rotate() would build a replacement with a fresh issued_at
  // and the parent's already-past expires_at, which the schema's `expires_at > issued_at` CHECK
  // rejects; ROTATE being one statement, the abort would also roll back the retirement and leave
  // the credential permanently un-rotatable. The engine side of that CHECK is proven in
  // implementer-credentials.pg.test.ts.
  it("refuses to rotate a credential whose expiry has already passed", async () => {
    let now = new Date("2026-07-26T00:00:00.000Z");
    const store = new InMemoryCredentialStore();
    const service = new CredentialService(store, () => now);
    const created = await service.create(
      "impl-1",
      ["receive:read"],
      "2026-07-27T00:00:00.000Z",
    );

    now = new Date("2026-07-28T00:00:00.000Z");
    await expect(service.rotate(created.credential_id, "impl-1", 60)).rejects.toThrow(
      CredentialError,
    );
    // Nothing was retired and no replacement was minted: the rejection is pre-store.
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0]).toMatchObject({ status: "ACTIVE", rotated_to_id: null });
    expect(store.audits.map((audit) => audit.action)).toEqual([
      "IMPLEMENTER_CREDENTIAL_ISSUED",
    ]);
  });

  it("still rotates a credential whose expiry is in the future", async () => {
    const now = new Date("2026-07-26T00:00:00.000Z");
    const store = new InMemoryCredentialStore();
    const service = new CredentialService(store, () => now);
    const created = await service.create(
      "impl-1",
      ["receive:read"],
      "2026-07-27T00:00:00.000Z",
    );
    const replacement = await service.rotate(created.credential_id, "impl-1", 60);

    expect(replacement.key_version).toBe(2);
    // The replacement inherits the parent's absolute expiry, so it is only ever valid while that
    // expiry is still ahead of the rotation instant — which is exactly what the guard enforces.
    expect(replacement.expires_at).toBe("2026-07-27T00:00:00.000Z");
    expect(Date.parse(replacement.expires_at!)).toBeGreaterThan(
      Date.parse(replacement.issued_at),
    );
  });

  it("rejects an expired credential", async () => {
    let now = new Date("2026-07-26T00:00:00.000Z");
    const service = new CredentialService(
      new InMemoryCredentialStore(),
      () => now,
    );
    const created = await service.create(
      "impl-1",
      ["receive:read"],
      "2026-07-26T00:00:01.000Z",
    );
    now = new Date("2026-07-26T00:00:01.000Z");
    await expect(service.validate(created.raw_key)).rejects.toThrow(CredentialAuthError);
  });

  it("validates a credential by raw key", async () => {
    const { service } = setup();
    const created = await service.create("impl-1", ["move:create"]);
    const validated = await service.validate(created.raw_key);
    expect(validated.implementer_id).toBe("impl-1");
    expect(validated.scopes).toEqual(["move:create"]);
  });

  it("rejects an unknown key", async () => {
    const { service } = setup();
    await expect(service.validate("ik_nonexistent")).rejects.toThrow(CredentialAuthError);
  });

  it("rejects a revoked credential", async () => {
    const { store, service } = setup();
    const created = await service.create("impl-1", ["send:create"]);
    await service.revoke(created.credential_id, "impl-1");
    await expect(service.validate(created.raw_key)).rejects.toThrow(CredentialAuthError);
    expect(store.audits.at(-1)?.action).toBe(
      "IMPLEMENTER_CREDENTIAL_REVOKED",
    );
  });

  it("revokes only for the owning implementer", async () => {
    const { service } = setup();
    const created = await service.create("impl-1", ["send:create"]);
    await expect(service.revoke(created.credential_id, "impl-other")).rejects.toThrow("credential not found");
  });

  it("lists credentials scoped to one implementer", async () => {
    const { service } = setup();
    await service.create("impl-1", ["receive:create"]);
    await service.create("impl-1", ["move:create"]);
    await service.create("impl-2", ["send:create"]);
    const list1 = await service.list("impl-1");
    const list2 = await service.list("impl-2");
    expect(list1).toHaveLength(2);
    expect(list2).toHaveLength(1);
  });

  it("authorize succeeds with correct scope", async () => {
    const { service } = setup();
    const created = await service.create("impl-1", ["receive:create", "receive:read"]);
    const result = await service.authorize(created.raw_key, "receive:create");
    expect(result.implementer_id).toBe("impl-1");
  });

  it("authorize fails with missing scope", async () => {
    const { service } = setup();
    const created = await service.create("impl-1", ["receive:read"]);
    await expect(service.authorize(created.raw_key, "send:create")).rejects.toThrow(
      CredentialAuthError,
    );
  });
});

describe("multi-tenant isolation", () => {
  it("implementer A cannot see implementer B credentials", async () => {
    const store = new InMemoryCredentialStore();
    const service = new CredentialService(store);
    const credA = await service.create("impl-A", ["receive:create"]);
    await service.create("impl-B", ["move:create"]);
    const listA = await service.list("impl-A");
    expect(listA).toHaveLength(1);
    expect(listA[0]!.id).toBe(credA.credential_id);
  });

  it("implementer A cannot revoke implementer B credential", async () => {
    const store = new InMemoryCredentialStore();
    const service = new CredentialService(store);
    await service.create("impl-A", ["receive:create"]);
    const credB = await service.create("impl-B", ["move:create"]);
    await expect(service.revoke(credB.credential_id, "impl-A")).rejects.toThrow("credential not found");
    const validated = await service.validate(credB.raw_key);
    expect(validated.implementer_id).toBe("impl-B");
  });
});

describe("assertScope", () => {
  it("passes when scope is present", () => {
    expect(() =>
      assertScope({ credential_id: "c1", implementer_id: "i1", scopes: ["receive:create"] }, "receive:create"),
    ).not.toThrow();
  });

  it("throws the canonical auth failure when scope is absent, never naming the scope", () => {
    try {
      assertScope({ credential_id: "c1", implementer_id: "i1", scopes: ["receive:read"] }, "send:create");
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(CredentialAuthError);
      expect((e as CredentialAuthError).code).toBe(CANONICAL_AUTH_FAILURE_CODE);
      expect((e as CredentialAuthError).message).toBe(CANONICAL_AUTH_FAILURE_MESSAGE);
      expect((e as Error).message).not.toContain("send:create");
    }
  });
});

// A VALID credential used outside its scope and an UNKNOWN/invalid credential must be
// observably equivalent to the caller: identical 401, identical `invalid_api_key` body code, no
// difference in headers, message text or response shape. These are the runtime states produced by
// the real service, not reconstructed constants.3's matrix already covers the
// contract-level reconstruction.
describe("scope-denial / unknown-credential equivalence", () => {
  const REQUEST_ID = "11111111-2222-4333-8444-555555555555";

  // Every authorization-failure state the storage layer can reach, produced by driving the real
  // CredentialService. OUT_OF_SCOPE is the state three reviews found distinguishable.
  async function authorizationRejections(): Promise<unknown[]> {
    let now = new Date("2026-07-26T00:00:00.000Z");
    const store = new InMemoryCredentialStore();
    const service = new CredentialService(store, () => now);

    const outOfScope = await service.create("impl-1", ["receive:read"]);
    const revoked = await service.create("impl-1", ["receive:read"]);
    const expiring = await service.create("impl-1", ["receive:read"], "2026-07-26T00:00:01.000Z");
    await service.revoke(revoked.credential_id, "impl-1");
    now = new Date("2026-07-26T00:00:02.000Z");

    const attempts: Array<Promise<unknown>> = [
      // MISSING_CREDENTIAL / MALFORMED_CREDENTIAL / UNKNOWN_KEY
      service.authorize("", "receive:read"),
      service.authorize("not-even-a-key", "receive:read"),
      service.authorize("ik_nonexistent", "receive:read"),
      // EXPIRED_KEY / REVOKED_KEY
      service.authorize(expiring.raw_key, "receive:read"),
      service.authorize(revoked.raw_key, "receive:read"),
      // OUT_OF_SCOPE — a valid, live, in-tenant key used outside its granted scope
      service.authorize(outOfScope.raw_key, "send:create"),
    ];

    return Promise.all(
      attempts.map((attempt) =>
        attempt.then(
          () => expect.unreachable("authorization should have been rejected"),
          (error: unknown) => error,
        ),
      ),
    );
  }

  it("throws one indistinguishable rejection for every authorization-failure state", async () => {
    const rejections = await authorizationRejections();
    expect(rejections).toHaveLength(6);

    // The thrown values are identical on every caller-reachable dimension: class, name, code,
    // message, and own-property set. Nothing distinguishes wrong-scope from unknown.
    const shapes = rejections.map((error) => {
      expect(error).toBeInstanceOf(CredentialAuthError);
      return JSON.stringify({
        name: (error as Error).name,
        message: (error as Error).message,
        code: (error as CredentialAuthError).code,
        ownKeys: Object.keys(error as object).sort(),
      });
    });
    expect(new Set(shapes).size).toBe(1);
    expect(JSON.parse(shapes[0]!)).toEqual({
      name: "CredentialAuthError",
      message: CANONICAL_AUTH_FAILURE_MESSAGE,
      code: CANONICAL_AUTH_FAILURE_CODE,
      // Both own properties are compile-time constants of the class, so neither varies by state.
      ownKeys: ["code", "name"],
    });
  });

  it("renders every state to the byte-identical frozen 401 through the production mapper", async () => {
    const rejections = await authorizationRejections();
    // The mapper takes the error's own code — there is no per-state branch a caller could add,
    // because there is only one code to branch on.
    const responses: WireResponse[] = rejections.map((error) =>
      apiErrorResponse((error as CredentialAuthError).code, REQUEST_ID),
    );

    expect(isNonOracular(responses)).toBe(true);
    for (const response of responses) {
      expect(response.status).toBe(401);
      expect(normalizeRequestId(response.body)).toBe(CANONICAL_AUTH_FAILURE_BODY);
      expect(response.headers).toEqual({ ...CANONICAL_AUTH_ERROR_HEADERS });
    }
  });

  it("keeps the rejected 403/scope taxonomy out of the credential module", () => {
    const credentialSrc = resolve(dirname(fileURLToPath(import.meta.url)), "../src/credential");
    const sources = readdirSync(credentialSrc)
      .filter((entry) => entry.endsWith(".ts"))
      .map((entry) => ({ entry, text: readFileSync(join(credentialSrc, entry), "utf8") }));
    expect(sources.length).toBeGreaterThan(0);

    const banned = [...REJECTED_AUTH_ERROR_CODES.map((c) => c.code), "SCOPE_DENIED", "WWW-Authenticate"];
    const hits = sources.flatMap(({ entry, text }) =>
      banned.filter((term) => text.toLowerCase().includes(term.toLowerCase())).map((term) => ({ entry, term })),
    );
    expect(hits).toEqual([]);
  });
});
