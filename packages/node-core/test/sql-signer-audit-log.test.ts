// The one durable signer-audit sink, unit-level: exact SQL/params over a fake
// SqlQueryFn, so the AUDIT_OUTCOME/AUDIT_PURPOSE mapping and the INSERT shape are proven without
// a real Postgres. The three production call sites (RECEIVE/MOVE/SEND) all compose this same
// function — see apps/generic-node/test/{receive-settle-step,move-advanced-ports,
// send-signer-audit}.pg.test.ts for the real-PG proof that boot recovery observes the rows it
// writes.

import { describe, expect, it, vi } from "vitest";
import { createSqlSignerAuditLog } from "../src/core/sql-signer-audit-log.js";
import type { SignerAuditEntry } from "../src/core/signer-boundary.js";
import type { SqlQueryFn } from "../src/core/sql-query-fn.js";

function makeEntry(overrides: Partial<SignerAuditEntry> = {}): SignerAuditEntry {
  return {
    walletId: "wallet-1",
    operationId: "op-1",
    leaseEpoch: 7n,
    purpose: "SPLITCHAIN_STEP_1",
    preimageSha256: "a".repeat(64),
    outcome: "SIGNED",
    timestamp: "2026-01-15T00:00:00.000Z",
    ...overrides,
  };
}

describe("createSqlSignerAuditLog", () => {
  it("maps SIGNED/SPLITCHAIN_STEP_1 to the signer_audit CHECK vocabulary (SUCCEEDED/STEP_1)", async () => {
    const query = vi.fn<SqlQueryFn>().mockResolvedValue([]);
    const auditLog = createSqlSignerAuditLog(query);

    await auditLog.append(makeEntry());

    expect(query).toHaveBeenCalledTimes(1);
    const [sql, params] = query.mock.calls[0]!;
    expect(sql).toContain("INSERT INTO signer_audit");
    expect(sql).toContain("FROM operations o WHERE o.id = $2::uuid");
    const [id, operationId, leaseEpoch, preimageSha256, timestamp, outcome, purpose] = params;
    expect(typeof id).toBe("string");
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(operationId).toBe("op-1");
    expect(leaseEpoch).toBe("7");
    expect(preimageSha256).toBe("a".repeat(64));
    expect(timestamp).toBe("2026-01-15T00:00:00.000Z");
    expect(outcome).toBe("SUCCEEDED");
    expect(purpose).toBe("STEP_1");
  });

  it("maps REJECTED/SPLITCHAIN_STEP_2 to FAILED/STEP_2", async () => {
    const query = vi.fn<SqlQueryFn>().mockResolvedValue([]);
    const auditLog = createSqlSignerAuditLog(query);

    await auditLog.append(makeEntry({ purpose: "SPLITCHAIN_STEP_2", outcome: "REJECTED" }));

    const [, params] = query.mock.calls[0]!;
    expect(params[5]).toBe("FAILED");
    expect(params[6]).toBe("STEP_2");
  });

  it("mints a fresh id per call — signer_audit is append-only, never upserted", async () => {
    const query = vi.fn<SqlQueryFn>().mockResolvedValue([]);
    const auditLog = createSqlSignerAuditLog(query);

    await auditLog.append(makeEntry());
    await auditLog.append(makeEntry());

    const [firstId] = query.mock.calls[0]![1];
    const [secondId] = query.mock.calls[1]![1];
    expect(firstId).not.toBe(secondId);
  });

  it("propagates a write failure instead of swallowing it (fail-closed at the adapter)", async () => {
    const query = vi.fn<SqlQueryFn>().mockRejectedValue(new Error("insert failed: connection lost"));
    const auditLog = createSqlSignerAuditLog(query);

    await expect(auditLog.append(makeEntry())).rejects.toThrow("insert failed: connection lost");
  });
});
