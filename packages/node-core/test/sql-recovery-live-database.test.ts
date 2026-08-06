// createSqlRecoveryLiveDatabase stamp SQL + parseAdminTotpSecret.

import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import {
  createSqlRecoveryLiveDatabase,
  RECOVERY_STAMP_SQL,
  type RecoveryStampInput,
  type RecoverySqlExecutor,
} from "../src/core/recovery/sql-live-database.js";
import { parseAdminTotpSecret } from "../src/totp/parse-secret.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const WALLET_ID = "22222222-2222-4222-8222-222222222222";
const PUB = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const FIXED = "2026-07-29T12:00:00.000Z";

function baseStamp(over: Partial<RecoveryStampInput> = {}): RecoveryStampInput {
  return {
    ceremonyId: "33333333-3333-4333-8333-333333333333",
    walletId: WALLET_ID,
    method: "AUDITED_EXPORT",
    publicKey: PUB,
    keyVersion: 1,
    exportId: "44444444-4444-4444-8444-444444444444",
    exportSha256: "a".repeat(64),
    verifierIdentity: "operator@test",
    censusMatchedRestored: true,
    censusMatchedLive: true,
    archivedProofVerified: true,
    probeSignature: "sig",
    probePreimageSha256: "b".repeat(64),
    probeVerified: true,
    ...over,
  };
}

describe("parseAdminTotpSecret", () => {
  it("accepts hex ≥16 bytes", () => {
    const hex = Buffer.alloc(20, 9).toString("hex");
    const got = parseAdminTotpSecret(hex);
    expect(got).not.toBeNull();
    expect(got!.length).toBe(20);
  });

  it("accepts base32 ≥16 bytes", () => {
    const secret = parseAdminTotpSecret("A4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYH");
    expect(secret).not.toBeNull();
    expect(secret!.length).toBe(20);
  });

  it("rejects missing, short, and garbage", () => {
    expect(parseAdminTotpSecret(undefined)).toBeNull();
    expect(parseAdminTotpSecret("")).toBeNull();
    expect(parseAdminTotpSecret("aa")).toBeNull();
    expect(parseAdminTotpSecret("not!base32!!")).toBeNull();
  });
});

describe("createSqlRecoveryLiveDatabase.stampRecoveryVerification", () => {
  it("issues the atomic STAMP SQL with audit + verification + two-column wallets update", async () => {
    const calls: { text: string; params: readonly unknown[] }[] = [];
    const sql: RecoverySqlExecutor = {
      async query(text, params) {
        calls.push({ text, params });
        if (text === RECOVERY_STAMP_SQL.STAMP) {
          return { rows: [{ wallet_id: WALLET_ID }] };
        }
        return { rows: [] };
      },
    };
    const live = createSqlRecoveryLiveDatabase({
      sql,
      nodeId: NODE_ID,
      proveCurrentKeyPossession: async () => true,
      now: () => new Date(FIXED),
      newId: (() => {
        let n = 0;
        return () => `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`;
      })(),
    });

    await live.stampRecoveryVerification(baseStamp());

    expect(calls).toHaveLength(1);
    expect(calls[0]!.text).toBe(RECOVERY_STAMP_SQL.STAMP);
    expect(calls[0]!.text).toContain("INSERT INTO audit_log");
    expect(calls[0]!.text).toContain("INSERT INTO wallet_recovery_verifications");
    expect(calls[0]!.text).toContain("UPDATE wallets");
    expect(calls[0]!.text).toContain("recovery_verified_at");
    expect(calls[0]!.text).toContain("recovery_verification_id");
    expect(calls[0]!.params).toContain(NODE_ID);
    expect(calls[0]!.params).toContain(WALLET_ID);
    expect(calls[0]!.params).toContain(PUB);
    expect(calls[0]!.params).toContain("a".repeat(64));

    const details = String(calls[0]!.params[4]);
    const detailsSha = String(calls[0]!.params[5]);
    expect(detailsSha).toBe(createHash("sha256").update(details, "utf8").digest("hex"));
    expect(details).not.toMatch(/private|seed|master/i);
  });

  it("no-ops when stamp matches zero rows because wallet is already recovery-verified", async () => {
    let calls = 0;
    const sql: RecoverySqlExecutor = {
      async query(text: string) {
        calls += 1;
        if (text.includes("UPDATE wallets")) {
          return { rows: [] };
        }
        if (text.includes("SELECT recovery_verified_at")) {
          return { rows: [{ recovery_verified_at: FIXED }] };
        }
        return { rows: [] };
      },
    };
    const live = createSqlRecoveryLiveDatabase({
      sql,
      nodeId: NODE_ID,
      proveCurrentKeyPossession: async () => true,
      now: () => new Date(FIXED),
    });
    await expect(live.stampRecoveryVerification(baseStamp())).resolves.toBeUndefined();
    expect(calls).toBe(2);
  });

  it("throws when stamp matches zero rows and wallet is not already verified", async () => {
    const sql: RecoverySqlExecutor = {
      async query(text: string) {
        if (text.includes("UPDATE wallets")) {
          return { rows: [] };
        }
        if (text.includes("SELECT recovery_verified_at")) {
          return { rows: [{ recovery_verified_at: null }] };
        }
        return { rows: [] };
      },
    };
    const live = createSqlRecoveryLiveDatabase({
      sql,
      nodeId: NODE_ID,
      proveCurrentKeyPossession: async () => true,
      now: () => new Date(FIXED),
    });
    await expect(live.stampRecoveryVerification(baseStamp())).rejects.toThrow(/did not apply/);
  });

  it("refuses incomplete probe flags", async () => {
    const sql: RecoverySqlExecutor = {
      query: vi.fn(async () => ({ rows: [{ wallet_id: WALLET_ID }] })),
    };
    const live = createSqlRecoveryLiveDatabase({
      sql,
      nodeId: NODE_ID,
      proveCurrentKeyPossession: async () => true,
    });
    await expect(
      live.stampRecoveryVerification({
        ...baseStamp(),
        archivedProofVerified: false,
      } as RecoveryStampInput),
    ).rejects.toThrow(/incomplete/);
    expect(sql.query).not.toHaveBeenCalled();
  });
});
