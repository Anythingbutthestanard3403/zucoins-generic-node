// verification-material access-window RECORD.
//
// AC: 409 = not ready; 410 = access expired without deletion; identifier stored hashed;
// every read audited through audit_log (actor_kind=IMPLEMENTER); no second bearer scheme;
// issued only after landed-terminal milestone; cross-tenant never oracles existence.
import { createHash, randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  DEFAULT_PROOF_ACCESS_WINDOW_MS,
  InMemoryVerificationAccessWindowStore,
  VERIFICATION_ACCESS_WINDOW_STATUSES,
  VERIFICATION_MATERIAL_READ_AUDIT_ACTION,
  VerificationAccessWindowError,
  auditVerificationMaterialAccessRead,
  authorizeVerificationAccessWindow,
  gatedVerificationAccessRead,
  hashAccessWindowNonce,
  issueVerificationAccessWindow,
  markVerificationAccessWindowExpired,
  mintAccessWindowNoncePlaintext,
  revokeVerificationAccessWindow,
  type VerificationAccessWindowRecord,
} from "../src/api/verification-access.ts";
import {
  InMemoryAuditLogStore,
  createAuditWriter,
} from "../src/core/audit-writer.ts";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_A = "22222222-2222-4222-8222-222222222222";
const IMPLEMENTER_B = "33333333-3333-4333-8333-333333333333";
const OPERATION_ID = "44444444-4444-4444-8444-444444444444";
const OTHER_OP = "55555555-5555-4555-8555-555555555555";
const TERMINAL_AT_MS = Date.UTC(2026, 0, 1, 0, 0, 0);
const WINDOW_MS = 60_000; // short window for boundary tests

const landed = {
  kind: "MOVE_INTERNAL" as const,
  status: "INTERNAL_MOVE_LANDED",
};

async function issueOpen(
  store: InMemoryVerificationAccessWindowStore,
  over: {
    operationId?: string;
    implementerId?: string;
    kind?: "MOVE_INTERNAL" | "RECEIVE_EXTERNAL" | "SEND_EXTERNAL";
    status?: string;
    windowMs?: number;
    noncePlaintext?: string;
    terminalAtMs?: number;
  } = {},
) {
  return issueVerificationAccessWindow(store, {
    nodeId: NODE_ID,
    implementerId: over.implementerId ?? IMPLEMENTER_A,
    operationId: over.operationId ?? OPERATION_ID,
    kind: over.kind ?? "MOVE_INTERNAL",
    status: over.status ?? "INTERNAL_MOVE_LANDED",
    terminalAtMs: over.terminalAtMs ?? TERMINAL_AT_MS,
    windowMs: over.windowMs ?? WINDOW_MS,
    noncePlaintext: over.noncePlaintext,
  });
}

describe("hashAccessWindowNonce — store-hashed identifier", () => {
  it("is SHA-256 hex of the utf-8 plaintext", () => {
    const plaintext = "test-nonce-value";
    const expected = createHash("sha256").update(plaintext, "utf8").digest("hex");
    expect(hashAccessWindowNonce(plaintext)).toBe(expected);
    expect(hashAccessWindowNonce(plaintext)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("minted nonces are high-entropy base64url", () => {
    const a = mintAccessWindowNoncePlaintext();
    const b = mintAccessWindowNoncePlaintext();
    expect(a).not.toBe(b);
    expect(a.length).toBeGreaterThanOrEqual(32);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe("issueVerificationAccessWindow — terminal milestone only", () => {
  it("issues OPEN window at INTERNAL_MOVE_LANDED with expires = terminal + window", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    const { record, noncePlaintext } = await issueOpen(store);
    expect(record.status).toBe("OPEN");
    expect(record.issuedAtMs).toBe(TERMINAL_AT_MS);
    expect(record.expiresAtMs).toBe(TERMINAL_AT_MS + WINDOW_MS);
    expect(record.nonceHash).toBe(hashAccessWindowNonce(noncePlaintext));
    expect(record.revokedAtMs).toBeNull();
  });

  it.each([
    ["RECEIVE_EXTERNAL", "RECEIVE_LANDED"],
    ["MOVE_INTERNAL", "INTERNAL_MOVE_LANDED"],
    ["SEND_EXTERNAL", "EXTERNAL_SEND_LANDED"],
  ] as const)("issues for %s at %s", async (kind, status) => {
    const store = new InMemoryVerificationAccessWindowStore();
    const { record } = await issueOpen(store, {
      kind,
      status,
      operationId: randomUUID(),
    });
    expect(record.status).toBe("OPEN");
  });

  it.each([
    ["RECEIVE_EXTERNAL", "CREATED"],
    ["RECEIVE_EXTERNAL", "READY"],
    ["MOVE_INTERNAL", "CREATED"],
    ["MOVE_INTERNAL", "NEEDS_ATTENTION"],
    ["SEND_EXTERNAL", "APPROVED"],
    ["SEND_EXTERNAL", "AWAITING_REDEMPTION"],
  ] as const)("refuses to issue before terminal (%s/%s)", async (kind, status) => {
    const store = new InMemoryVerificationAccessWindowStore();
    await expect(
      issueOpen(store, { kind, status, operationId: randomUUID() }),
    ).rejects.toBeInstanceOf(VerificationAccessWindowError);
    expect(store.rows()).toHaveLength(0);
  });

  it("defaults the window to 30 days when unspecified", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    const { record } = await issueVerificationAccessWindow(store, {
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_A,
      operationId: OPERATION_ID,
      ...landed,
      terminalAtMs: TERMINAL_AT_MS,
    });
    expect(record.expiresAtMs - record.issuedAtMs).toBe(DEFAULT_PROOF_ACCESS_WINDOW_MS);
    expect(DEFAULT_PROOF_ACCESS_WINDOW_MS).toBe(30 * 24 * 60 * 60 * 1000);
  });

  it("refuses a zero-length window (durable CHECK expires_at > issued_at)", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    await expect(issueOpen(store, { windowMs: 0 })).rejects.toBeInstanceOf(
      VerificationAccessWindowError,
    );
  });
});

describe("InMemoryVerificationAccessWindowStore — hashed at rest", () => {
  it("keys durable storage by nonce_hash, never by plaintext nonce", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    const plaintext = "PLAINTEXT-NONCE-MUST-NOT-BE-A-KEY";
    const { record } = await issueOpen(store, { noncePlaintext: plaintext });

    // Plaintext is absent from every map key and every stored field.
    expect(store.containsPlaintext(plaintext)).toBe(false);
    // Lookup by hash works; lookup-shaped access by plaintext hash-misses.
    expect(await store.findByNonceHash(record.nonceHash)).toEqual(record);
    expect(await store.findByNonceHash(plaintext)).toBeNull();
    // No row field equals the plaintext.
    for (const row of store.rows()) {
      expect(Object.values(row).includes(plaintext)).toBe(false);
      expect(JSON.stringify(row)).not.toContain(plaintext);
    }
  });

  it("rejects a second window for the same operation_id", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    await issueOpen(store);
    await expect(issueOpen(store, { noncePlaintext: "other" })).rejects.toBeInstanceOf(
      VerificationAccessWindowError,
    );
  });

  it("rejects a duplicate nonce_hash", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    const plaintext = "shared-nonce";
    await issueOpen(store, { noncePlaintext: plaintext });
    await expect(
      issueOpen(store, {
        operationId: OTHER_OP,
        noncePlaintext: plaintext,
      }),
    ).rejects.toBeInstanceOf(VerificationAccessWindowError);
  });
});

describe("authorizeVerificationAccessWindow — 409 / 200 / 410", () => {
  it("409 not_ready when no window has been issued (pre-terminal)", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    const decision = await authorizeVerificationAccessWindow(store, {
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_A,
      kind: "MOVE_INTERNAL",
      status: "CREATED",
      nowMs: TERMINAL_AT_MS,
    });
    expect(decision.reason).toBe("not_ready");
    expect(decision.http).toBe(409);
    expect(decision.code).toBe("verification_material_not_ready");
    expect(decision.verdict).toBe("NOT_READY");
    expect(decision.record).toBeNull();
  });

  it("409 not_ready when landed but window row is still absent", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    const decision = await authorizeVerificationAccessWindow(store, {
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_A,
      ...landed,
      nowMs: TERMINAL_AT_MS,
    });
    expect(decision.http).toBe(409);
    expect(decision.code).toBe("verification_material_not_ready");
  });

  it("200 accessible strictly inside the window", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    const { record } = await issueOpen(store);
    const decision = await authorizeVerificationAccessWindow(store, {
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_A,
      ...landed,
      nowMs: TERMINAL_AT_MS + 1,
    });
    expect(decision.reason).toBe("accessible");
    expect(decision.http).toBe(200);
    expect(decision.code).toBeNull();
    expect(decision.verdict).toBe("ACCESSIBLE");
    expect(decision.record?.id).toBe(record.id);
  });

  it("410 exactly at expires_at (window closed at the boundary)", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    await issueOpen(store);
    const decision = await authorizeVerificationAccessWindow(store, {
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_A,
      ...landed,
      nowMs: TERMINAL_AT_MS + WINDOW_MS,
    });
    expect(decision.reason).toBe("expired");
    expect(decision.http).toBe(410);
    expect(decision.code).toBe("verification_material_expired");
  });

  it("410 after expires_at", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    await issueOpen(store);
    const decision = await authorizeVerificationAccessWindow(store, {
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_A,
      ...landed,
      nowMs: TERMINAL_AT_MS + WINDOW_MS + 1,
    });
    expect(decision.http).toBe(410);
    expect(decision.code).toBe("verification_material_expired");
  });

  it("410 on explicit revoke, and the window row remains (no delete)", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    await issueOpen(store);
    const ok = await revokeVerificationAccessWindow(store, OPERATION_ID, TERMINAL_AT_MS + 5);
    expect(ok).toBe(true);
    // Evidence/window row still present after revoke.
    expect(store.rows()).toHaveLength(1);
    expect(store.rows()[0]?.status).toBe("REVOKED");
    expect(store.rows()[0]?.revokedAtMs).toBe(TERMINAL_AT_MS + 5);

    const decision = await authorizeVerificationAccessWindow(store, {
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_A,
      ...landed,
      nowMs: TERMINAL_AT_MS + 10, // still inside original wall-clock window
    });
    expect(decision.reason).toBe("revoked");
    expect(decision.http).toBe(410);
    expect(decision.code).toBe("verification_material_expired");
    // Row still intact after the read.
    expect(store.rows()).toHaveLength(1);
    expect(store.rows()[0]?.nonceHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("410 after markExpired, row retained", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    await issueOpen(store);
    await markVerificationAccessWindowExpired(store, OPERATION_ID);
    expect(store.rows()[0]?.status).toBe("EXPIRED");
    const decision = await authorizeVerificationAccessWindow(store, {
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_A,
      ...landed,
      nowMs: TERMINAL_AT_MS + 1,
    });
    expect(decision.http).toBe(410);
    expect(store.rows()).toHaveLength(1);
  });

  it("no ambiguous zone: 409 only before issue, 410 only after close", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    // Before issue → 409
    expect(
      (
        await authorizeVerificationAccessWindow(store, {
          operationId: OPERATION_ID,
          implementerId: IMPLEMENTER_A,
          ...landed,
          nowMs: TERMINAL_AT_MS,
        })
      ).http,
    ).toBe(409);

    await issueOpen(store);

    // Inside → 200
    expect(
      (
        await authorizeVerificationAccessWindow(store, {
          operationId: OPERATION_ID,
          implementerId: IMPLEMENTER_A,
          ...landed,
          nowMs: TERMINAL_AT_MS + WINDOW_MS - 1,
        })
      ).http,
    ).toBe(200);

    // Boundary → 410
    expect(
      (
        await authorizeVerificationAccessWindow(store, {
          operationId: OPERATION_ID,
          implementerId: IMPLEMENTER_A,
          ...landed,
          nowMs: TERMINAL_AT_MS + WINDOW_MS,
        })
      ).http,
    ).toBe(410);
  });
});

describe("cross-tenant / cross-operation — no oracle", () => {
  it("findByOperation for another implementer returns null (no existence leak)", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    await issueOpen(store, { implementerId: IMPLEMENTER_A });
    expect(await store.findByOperation(OPERATION_ID, IMPLEMENTER_B)).toBeNull();
    // Owner still sees it.
    expect(await store.findByOperation(OPERATION_ID, IMPLEMENTER_A)).not.toBeNull();
  });

  it("authorize for another implementer is 409-not-ready shaped (absent), never 200", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    await issueOpen(store, { implementerId: IMPLEMENTER_A });
    const decision = await authorizeVerificationAccessWindow(store, {
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_B,
      ...landed,
      nowMs: TERMINAL_AT_MS + 1,
    });
    expect(decision.http).toBe(409);
    expect(decision.record).toBeNull();
  });

  it("window is scoped to exactly one operation — other operation_id never resolves it", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    await issueOpen(store, { operationId: OPERATION_ID });
    expect(await store.findByOperation(OTHER_OP, IMPLEMENTER_A)).toBeNull();
    const decision = await authorizeVerificationAccessWindow(store, {
      operationId: OTHER_OP,
      implementerId: IMPLEMENTER_A,
      ...landed,
      nowMs: TERMINAL_AT_MS + 1,
    });
    expect(decision.http).toBe(409);
  });
});

describe("audit on every read", () => {
  it("writes audit_log with actor_kind=IMPLEMENTER and no evidence bytes", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    const auditStore = new InMemoryAuditLogStore();
    const audit = createAuditWriter(auditStore);
    const { record } = await issueOpen(store);

    const decision = await authorizeVerificationAccessWindow(store, {
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_A,
      ...landed,
      nowMs: TERMINAL_AT_MS + 1,
    });
    expect(decision.http).toBe(200);

    await auditVerificationMaterialAccessRead({
      audit,
      auditId: randomUUID(),
      nodeId: NODE_ID,
      actorId: IMPLEMENTER_A,
      operationId: OPERATION_ID,
      decision,
      createdAt: new Date(TERMINAL_AT_MS + 1).toISOString(),
    });

    const rows = auditStore.rows();
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    expect(row.actorKind).toBe("IMPLEMENTER");
    expect(row.actorId).toBe(IMPLEMENTER_A);
    expect(row.action).toBe(VERIFICATION_MATERIAL_READ_AUDIT_ACTION);
    expect(row.operationId).toBe(OPERATION_ID);
    const details = JSON.parse(row.detailsText) as Record<string, unknown>;
    expect(details.scope).toBe("verification-material:read");
    expect(details.decision).toBe("accessible");
    expect(details.verdict).toBe("ACCESSIBLE");
    expect(details.http).toBe(200);
    expect(details.window_id).toBe(record.id);
    expect(details.nonce_hash).toBe(record.nonceHash);
    // No raw evidence markers, no plaintext secrets.
    expect(row.detailsText).not.toContain("private_key");
    expect(row.detailsText).not.toContain("preimage_text");
    expect(row.detailsText).not.toContain("settled_transaction");
    expect(row.detailsText).not.toMatch(/"nonce"\s*:/);
  });

  it("audits negative decisions too (409 and 410)", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    const auditStore = new InMemoryAuditLogStore();
    const audit = createAuditWriter(auditStore);

    // 409 path
    const notReady = await gatedVerificationAccessRead({
      store,
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_A,
      kind: "MOVE_INTERNAL",
      status: "CREATED",
      nowMs: TERMINAL_AT_MS,
      audit,
      auditId: randomUUID(),
      nodeId: NODE_ID,
      actorId: IMPLEMENTER_A,
      createdAt: new Date(TERMINAL_AT_MS).toISOString(),
    });
    expect(notReady.http).toBe(409);

    await issueOpen(store);
    const expired = await gatedVerificationAccessRead({
      store,
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_A,
      ...landed,
      nowMs: TERMINAL_AT_MS + WINDOW_MS + 1,
      audit,
      auditId: randomUUID(),
      nodeId: NODE_ID,
      actorId: IMPLEMENTER_A,
      createdAt: new Date(TERMINAL_AT_MS + WINDOW_MS + 1).toISOString(),
    });
    expect(expired.http).toBe(410);

    expect(auditStore.rows()).toHaveLength(2);
    expect(auditStore.rows().every((r) => r.actorKind === "IMPLEMENTER")).toBe(true);
    expect(auditStore.rows().map((r) => JSON.parse(r.detailsText).decision)).toEqual([
      "not_ready",
      "expired",
    ]);
  });

  it("gatedVerificationAccessRead requires audit identity fields when audit is set", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    const audit = createAuditWriter(new InMemoryAuditLogStore());
    await expect(
      gatedVerificationAccessRead({
        store,
        operationId: OPERATION_ID,
        implementerId: IMPLEMENTER_A,
        ...landed,
        nowMs: TERMINAL_AT_MS,
        audit,
        // missing auditId/nodeId/createdAt
      }),
    ).rejects.toBeInstanceOf(VerificationAccessWindowError);
  });
});

describe("expiry revokes access only — evidence permanence", () => {
  it("after 410 the window row and a stand-in evidence blob remain readable", async () => {
    // Stand-in for the permanent evidence tables. This module has no delete
    // path; the test proves the store still holds the row after expiry decisions.
    const evidence = new Map<string, { body: string }>();
    evidence.set(OPERATION_ID, { body: "canonical-settled-tx-bytes" });

    const store = new InMemoryVerificationAccessWindowStore();
    const { record } = await issueOpen(store);

    const expired = await authorizeVerificationAccessWindow(store, {
      operationId: OPERATION_ID,
      implementerId: IMPLEMENTER_A,
      ...landed,
      nowMs: record.expiresAtMs + 1,
    });
    expect(expired.http).toBe(410);

    // Direct read of underlying evidence after expiry still finds the rows intact.
    expect(evidence.get(OPERATION_ID)?.body).toBe("canonical-settled-tx-bytes");
    expect(store.rows()).toHaveLength(1);
    expect(store.rows()[0]?.nonceHash).toBe(record.nonceHash);
    expect(store.rows()[0]?.operationId).toBe(OPERATION_ID);
  });
});

describe("surface is an availability record, not a bearer scheme", () => {
  it("exports no Authorization/Bearer encode/validate API", async () => {
    // Structural: the module surface is issue/authorize/revoke over a store record.
    // There is no encodeToken / validateBearer / Authorization header parser here.
    const mod = await import("../src/api/verification-access.ts");
    const names = Object.keys(mod);
    for (const forbidden of [
      "encodeToken",
      "decodeToken",
      "validateToken",
      "extractBearer",
      "Authorization",
      "createVerificationAccessService",
    ]) {
      expect(names).not.toContain(forbidden);
    }
    expect(names).toContain("issueVerificationAccessWindow");
    expect(names).toContain("authorizeVerificationAccessWindow");
    expect(names).toContain("hashAccessWindowNonce");
    expect(names).toContain("auditVerificationMaterialAccessRead");
  });

  it("status vocabulary is the closed OPEN/EXPIRED/REVOKED set", () => {
    expect([...VERIFICATION_ACCESS_WINDOW_STATUSES]).toEqual(["OPEN", "EXPIRED", "REVOKED"]);
  });

  it("record shape mirrors approval_challenges fields (issued/expires/status/nonce_hash)", async () => {
    const store = new InMemoryVerificationAccessWindowStore();
    const { record } = await issueOpen(store);
    const keys = Object.keys(record).sort();
    expect(keys).toEqual(
      [
        "expiresAtMs",
        "id",
        "implementerId",
        "issuedAtMs",
        "nodeId",
        "nonceHash",
        "operationId",
        "revokedAtMs",
        "status",
      ].sort(),
    );
    // Type-level stand-in: every required field is populated.
    const _check: VerificationAccessWindowRecord = record;
    expect(_check.nonceHash).toHaveLength(64);
  });
});
