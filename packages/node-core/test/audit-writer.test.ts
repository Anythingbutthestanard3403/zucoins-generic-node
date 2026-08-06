// The load-bearing security tests for the audit_log write-time redaction guard
// (audit-log.contract.ts records the scrubbing obligation). Negative paths feed
// the ACTUAL breaking input — a real private key and a TOTP secret — and prove neither reaches
// the persisted bytes.
import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  AUDIT_REDACTION_PLACEHOLDER,
  AUDIT_SECRET_CLASSED_KEY_TOKENS,
  AUDIT_WRITER_ACTOR_KINDS,
  AuditWriteError,
  InMemoryAuditLogStore,
  buildAuditRow,
  createAuditWriter,
  isSecretClassedKey,
  redactAuditDetails,
  type AuditActorKind,
  type AuditDetailValue,
  type AuditLogRow,
  type AuditWriteInput,
} from "../src/core/audit-writer.ts";
import {
  AUDIT_LOG_ACTOR_KINDS,
  AUDIT_LOG_FORBIDDEN_SECRET_TOKENS,
} from "../src/schema/audit-log.contract.ts";

const BASE: AuditWriteInput = {
  id: "11111111-1111-1111-1111-111111111111",
  nodeId: "22222222-2222-2222-2222-222222222222",
  actorKind: "OPERATOR_SESSION",
  action: "external_send.approved",
  details: { note: "ok" },
  createdAt: "2026-07-25T00:00:00.000Z",
};

const PRIVATE_KEY = "ed25519:MC4CAQAwBQYDK2VwBCIEILEAKMATERIALneverpersist";
const TOTP_SECRET = "JBSWY3DPEHPK3PXP";

describe("audit writer — schema parity", () => {
  it("mirrors the frozen actor_kind closed set exactly", () => {
    expect([...AUDIT_WRITER_ACTOR_KINDS]).toEqual([...AUDIT_LOG_ACTOR_KINDS]);
  });

  it("covers every frozen forbidden secret token", () => {
    const uncovered = AUDIT_LOG_FORBIDDEN_SECRET_TOKENS.filter(
      (token) => !AUDIT_SECRET_CLASSED_KEY_TOKENS.some((writerToken) => writerToken === token),
    );
    expect(uncovered).toEqual([]);
  });
});

describe("audit writer — write-time redaction (load-bearing)", () => {
  it("never persists a private key in cleartext", () => {
    const row = buildAuditRow({ ...BASE, details: { private_key: PRIVATE_KEY, note: "ok" } });
    expect(row.detailsText).not.toContain(PRIVATE_KEY);
    expect(row.detailsText).not.toContain("MATERIAL");
    const parsed = JSON.parse(row.detailsText) as Record<string, unknown>;
    expect(parsed.private_key).toBe(AUDIT_REDACTION_PLACEHOLDER);
    expect(parsed.note).toBe("ok");
  });

  it("never persists a TOTP secret in cleartext, including compound key names", () => {
    const row = buildAuditRow({
      ...BASE,
      details: { totp: TOTP_SECRET, totp_secret: TOTP_SECRET, authorization: "Bearer abc.def", vault: { seed: "x" } },
    });
    expect(row.detailsText).not.toContain(TOTP_SECRET);
    expect(row.detailsText).not.toContain("Bearer abc.def");
    const parsed = JSON.parse(row.detailsText) as Record<string, unknown>;
    expect(parsed.totp).toBe(AUDIT_REDACTION_PLACEHOLDER);
    expect(parsed.totp_secret).toBe(AUDIT_REDACTION_PLACEHOLDER);
    expect(parsed.authorization).toBe(AUDIT_REDACTION_PLACEHOLDER);
    expect(parsed.vault).toBe(AUDIT_REDACTION_PLACEHOLDER);
  });

  it("redacts secrets nested in objects and arrays", () => {
    const details: AuditDetailValue = {
      operator: { device_private_key: PRIVATE_KEY, session_secret: TOTP_SECRET, name: "alice" },
      items: [{ authorization: "Bearer nested" }, { plain: "kept" }],
    };
    const row = buildAuditRow({ ...BASE, details });
    expect(row.detailsText).not.toContain(PRIVATE_KEY);
    expect(row.detailsText).not.toContain(TOTP_SECRET);
    expect(row.detailsText).not.toContain("Bearer nested");
    expect(row.detailsText).toContain('"name":"alice"');
    expect(row.detailsText).toContain('"plain":"kept"');
  });

  it("digests the redacted bytes, not the raw input", () => {
    const row = buildAuditRow({ ...BASE, details: { private_key: PRIVATE_KEY } });
    const expected = createHash("sha256").update(Buffer.from(row.detailsText, "utf8")).digest("hex");
    expect(row.detailsSha256).toBe(expected);
    expect(row.detailsSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("keeps clean details verbatim", () => {
    const row = buildAuditRow({ ...BASE, details: { wallet_id: "w1", amount_zkz: "0.5" } });
    expect(JSON.parse(row.detailsText)).toEqual({ wallet_id: "w1", amount_zkz: "0.5" });
  });
});

describe("audit writer — structural rejects (never emit a row the DDL CHECK rejects)", () => {
  it("rejects an actor_kind outside the closed set", () => {
    expect(() =>
      buildAuditRow({ ...BASE, actorKind: "ROOT" as AuditActorKind }),
    ).toThrow(AuditWriteError);
  });

  it("rejects an empty action", () => {
    expect(() => buildAuditRow({ ...BASE, action: "" })).toThrow(AuditWriteError);
  });

  it("rejects an empty created_at", () => {
    expect(() => buildAuditRow({ ...BASE, createdAt: "" })).toThrow(AuditWriteError);
  });
});

describe("audit writer — append-only store", () => {
  it("writes the redacted row and reads it back", async () => {
    const store = new InMemoryAuditLogStore();
    const writer = createAuditWriter(store);
    const row = await writer.write({ ...BASE, details: { private_key: PRIVATE_KEY } });
    expect(store.rows()).toEqual([row]);
    expect(store.rows()[0]?.detailsText).not.toContain(PRIVATE_KEY);
  });

  it("rejects a duplicate id (id UNIQUE)", async () => {
    const store = new InMemoryAuditLogStore();
    const writer = createAuditWriter(store);
    await writer.write(BASE);
    await expect(writer.write(BASE)).rejects.toBeInstanceOf(AuditWriteError);
  });

  it("propagates a store rejection", async () => {
    const failing = {
      append: (): Promise<void> => Promise.reject(new Error("db down")),
    };
    const writer = createAuditWriter(failing);
    await expect(writer.write(BASE)).rejects.toThrow("db down");
  });
});

describe("audit writer — helpers", () => {
  it("classifies secret-carrying key names", () => {
    for (const key of ["private_key", "totp", "Authorization", "x_totp_secret", "myVault"]) {
      expect(isSecretClassedKey(key)).toBe(true);
    }
    for (const key of ["note", "action", "wallet_id", "operation_id"]) {
      expect(isSecretClassedKey(key)).toBe(false);
    }
  });

  it("redactAuditDetails is pure on primitives", () => {
    expect(redactAuditDetails("plain")).toBe("plain");
    expect(redactAuditDetails(42)).toBe(42);
    expect(redactAuditDetails(null)).toBe(null);
  });
});

// A production caller writes a shaped row; this keeps the exported row type honest.
const _rowType: AuditLogRow = buildAuditRow(BASE);
void _rowType;
