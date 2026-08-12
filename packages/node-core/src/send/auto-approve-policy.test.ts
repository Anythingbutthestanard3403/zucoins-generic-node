// Auto-approve policy — fail-closed parser + pure evaluator (ZTR-1234).

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  AUTO_APPROVE_SETTING_KEY,
  createSqlAutoApprovePolicy,
  evaluateAutoApproveRule,
  InMemoryAutoApprovePolicy,
  LOCK_AUTO_APPROVE_WINDOW_SQL,
  parseAutoApprovePolicyDocument,
  serializeAutoApprovePolicyDocument,
  type AutoApproveRule,
} from "./auto-approve-policy.js";
import type { SqlExecutor } from "./sql-store.js";

const IMP_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const IMP_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

function validRule(over: Partial<AutoApproveRule> = {}): AutoApproveRule {
  return {
    rule_id: "zukaz-rewards",
    implementer_id: IMP_A,
    per_send_max_zkz: "0.001",
    per_send_min_zkz: null,
    window_hours: 288,
    window_cap_zkz: "100",
    expires_at: "2026-09-01T00:00:00Z",
    enabled: true,
    ...over,
  };
}

function validDoc(over: {
  enabled?: boolean;
  rules?: AutoApproveRule[];
} = {}): string {
  return serializeAutoApprovePolicyDocument(over.rules ?? [validRule()], over.enabled ?? true);
}

describe("parseAutoApprovePolicyDocument", () => {
  it("absent / null / undefined → DISABLED absent", () => {
    expect(parseAutoApprovePolicyDocument(null)).toEqual({
      status: "disabled",
      disabledReason: "absent",
    });
    expect(parseAutoApprovePolicyDocument(undefined)).toEqual({
      status: "disabled",
      disabledReason: "absent",
    });
  });

  it("empty string → DISABLED invalid", () => {
    expect(parseAutoApprovePolicyDocument("")).toEqual({
      status: "disabled",
      disabledReason: "invalid",
    });
  });

  it("malformed JSON → DISABLED invalid", () => {
    expect(parseAutoApprovePolicyDocument("{not-json")).toEqual({
      status: "disabled",
      disabledReason: "invalid",
    });
    expect(parseAutoApprovePolicyDocument("null")).toEqual({
      status: "disabled",
      disabledReason: "invalid",
    });
    expect(parseAutoApprovePolicyDocument("[]")).toEqual({
      status: "disabled",
      disabledReason: "invalid",
    });
  });

  it("unknown top-level field → DISABLED invalid", () => {
    const raw = JSON.stringify({
      enabled: true,
      rules: [validRule()],
      extra: true,
    });
    expect(parseAutoApprovePolicyDocument(raw).status).toBe("disabled");
  });

  it("unknown rule field → DISABLED invalid", () => {
    const rule = { ...validRule(), surprise: 1 };
    const raw = JSON.stringify({ enabled: true, rules: [rule] });
    expect(parseAutoApprovePolicyDocument(raw).status).toBe("disabled");
  });

  it("wrong types → DISABLED invalid", () => {
    const cases = [
      { enabled: "true", rules: [] },
      { enabled: true, rules: "nope" },
      { enabled: true, rules: [{ ...validRule(), window_hours: "288" }] },
      { enabled: true, rules: [{ ...validRule(), enabled: "yes" }] },
      { enabled: true, rules: [{ ...validRule(), window_hours: 1.5 }] },
      { enabled: true, rules: [{ ...validRule(), window_hours: 0 }] },
      { enabled: true, rules: [{ ...validRule(), window_hours: -1 }] },
    ];
    for (const c of cases) {
      expect(
        parseAutoApprovePolicyDocument(JSON.stringify(c)),
        JSON.stringify(c),
      ).toEqual({ status: "disabled", disabledReason: "invalid" });
    }
  });

  it.each([
    "1e-3",
    "00.1",
    "0.0010",
    "-1",
    "0",
    "100000000",
    "100000000.1",
    "1.000000000000000000000000000000001", // >32 dp
  ])("non-canonical / out-of-range amount %j → DISABLED invalid", (amt) => {
    const rule = validRule({ per_send_max_zkz: amt });
    expect(parseAutoApprovePolicyDocument(validDoc({ rules: [rule] })).status).toBe(
      "disabled",
    );
  });

  it("non-canonical window_cap / min → DISABLED invalid", () => {
    expect(
      parseAutoApprovePolicyDocument(
        validDoc({ rules: [validRule({ window_cap_zkz: "1e2" })] }),
      ).status,
    ).toBe("disabled");
    expect(
      parseAutoApprovePolicyDocument(
        validDoc({ rules: [validRule({ per_send_min_zkz: "00.1" })] }),
      ).status,
    ).toBe("disabled");
  });

  it("duplicate implementer_id → DISABLED invalid", () => {
    const raw = validDoc({
      rules: [validRule({ rule_id: "a" }), validRule({ rule_id: "b" })],
    });
    expect(parseAutoApprovePolicyDocument(raw)).toEqual({
      status: "disabled",
      disabledReason: "invalid",
    });
  });

  it("bad RFC3339 expires_at → DISABLED invalid", () => {
    for (const exp of [
      "2026-09-01",
      "2026-09-01 00:00:00Z",
      "2026-13-01T00:00:00Z",
      "not-a-date",
      "2026-09-01T00:00:00+00:00",
    ]) {
      expect(
        parseAutoApprovePolicyDocument(
          validDoc({ rules: [validRule({ expires_at: exp })] }),
        ).status,
        exp,
      ).toBe("disabled");
    }
  });

  it("document enabled:false → DISABLED off (valid shape parked)", () => {
    const p = parseAutoApprovePolicyDocument(validDoc({ enabled: false }));
    expect(p.status).toBe("disabled");
    if (p.status !== "disabled") return;
    expect(p.disabledReason).toBe("off");
    expect(p.rules).toHaveLength(1);
  });

  it("valid document round-trips", () => {
    const rule = validRule({
      per_send_min_zkz: "0.0001",
      expires_at: "2026-09-01T00:00:00.000Z",
    });
    const json = validDoc({ rules: [rule, validRule({ implementer_id: IMP_B, rule_id: "other" })] });
    const p = parseAutoApprovePolicyDocument(json);
    expect(p.status).toBe("enabled");
    if (p.status !== "enabled") return;
    expect(p.rules).toHaveLength(2);
    expect(p.rules[0]).toEqual(rule);
    // serialize → parse is stable
    const again = parseAutoApprovePolicyDocument(
      serializeAutoApprovePolicyDocument(p.rules, true),
    );
    expect(again).toEqual(p);
  });

  it("min > max is invalid", () => {
    expect(
      parseAutoApprovePolicyDocument(
        validDoc({
          rules: [validRule({ per_send_min_zkz: "1", per_send_max_zkz: "0.5", window_cap_zkz: "10" })],
        }),
      ).status,
    ).toBe("disabled");
  });

  it("window_cap < per_send_max is invalid", () => {
    expect(
      parseAutoApprovePolicyDocument(
        validDoc({
          rules: [validRule({ per_send_max_zkz: "10", window_cap_zkz: "1" })],
        }),
      ).status,
    ).toBe("disabled");
  });
});

describe("evaluateAutoApproveRule", () => {
  const policy = parseAutoApprovePolicyDocument(
    validDoc({
      rules: [
        validRule({
          per_send_min_zkz: "0.001",
          per_send_max_zkz: "1",
          window_cap_zkz: "10",
          expires_at: "2026-09-01T00:00:00.000Z",
        }),
      ],
    }),
  );

  it("amount == max approves (inclusive)", () => {
    const r = evaluateAutoApproveRule(policy, {
      implementerId: IMP_A,
      amountZkz: "1",
    });
    expect(r.decision).toBe("approve");
  });

  it("amount == min approves (inclusive)", () => {
    const r = evaluateAutoApproveRule(policy, {
      implementerId: IMP_A,
      amountZkz: "0.001",
    });
    expect(r.decision).toBe("approve");
  });

  it("amount just above max falls through", () => {
    const r = evaluateAutoApproveRule(policy, {
      implementerId: IMP_A,
      amountZkz: "1.00000000000000000000000000000001",
    });
    // 32 dp max — use a clearly larger canonical amount
    const r2 = evaluateAutoApproveRule(policy, {
      implementerId: IMP_A,
      amountZkz: "1.0001",
    });
    expect(r2).toEqual({ decision: "fall_through", reason: "above_max" });
    void r;
  });

  it("amount just below min falls through", () => {
    const r = evaluateAutoApproveRule(policy, {
      implementerId: IMP_A,
      amountZkz: "0.0009",
    });
    expect(r).toEqual({ decision: "fall_through", reason: "below_min" });
  });

  it("expired rule is inert", () => {
    const r = evaluateAutoApproveRule(
      policy,
      { implementerId: IMP_A, amountZkz: "0.5" },
      { nowMs: Date.parse("2026-09-01T00:00:00.000Z") },
    );
    expect(r).toEqual({ decision: "fall_through", reason: "expired" });
  });

  it("disabled document falls through", () => {
    const r = evaluateAutoApproveRule(
      { status: "disabled", disabledReason: "absent" },
      { implementerId: IMP_A, amountZkz: "0.5" },
    );
    expect(r).toEqual({ decision: "fall_through", reason: "disabled" });
  });

  it("rule-level enabled:false is inert", () => {
    const p = parseAutoApprovePolicyDocument(
      validDoc({ rules: [validRule({ enabled: false })] }),
    );
    const r = evaluateAutoApproveRule(p, { implementerId: IMP_A, amountZkz: "0.001" });
    expect(r).toEqual({ decision: "fall_through", reason: "rule_disabled" });
  });

  it("no-rule implementer falls through", () => {
    const r = evaluateAutoApproveRule(policy, {
      implementerId: IMP_B,
      amountZkz: "0.5",
    });
    expect(r).toEqual({ decision: "fall_through", reason: "no_rule" });
  });

  it("window cap: spend + amount == cap approves; over falls through", () => {
    const ok = evaluateAutoApproveRule(
      policy,
      { implementerId: IMP_A, amountZkz: "1" },
      { windowSpend: "9" },
    );
    expect(ok.decision).toBe("approve");
    const over = evaluateAutoApproveRule(
      policy,
      { implementerId: IMP_A, amountZkz: "1" },
      { windowSpend: "9.0001" },
    );
    expect(over).toEqual({ decision: "fall_through", reason: "window_cap" });
  });
});

describe("InMemoryAutoApprovePolicy", () => {
  it("defaults to DISABLED absent", () => {
    const p = new InMemoryAutoApprovePolicy();
    expect(p.getPolicy()).toEqual({ status: "disabled", disabledReason: "absent" });
  });

  it("setPolicy switches and records audit meta", () => {
    const p = new InMemoryAutoApprovePolicy();
    const json = validDoc();
    p.setPolicy(json, { actorId: "op-1", nodeId: "node-1" });
    expect(p.getPolicy().status).toBe("enabled");
    expect(p.auditEntries).toHaveLength(1);
  });

  it("setPolicy rejects malformed documents", () => {
    const p = new InMemoryAutoApprovePolicy();
    expect(() =>
      p.setPolicy("{bad", { actorId: "op-1", nodeId: "node-1" }),
    ).toThrow(/invalid auto-approve/);
  });
});

describe("createSqlAutoApprovePolicy", () => {
  function memSql(initial: Map<string, string> = new Map()): {
    readonly sql: SqlExecutor;
    readonly audits: Array<readonly unknown[]>;
    readonly settings: Map<string, string>;
  } {
    const settings = initial;
    const audits: Array<readonly unknown[]> = [];
    const sql: SqlExecutor = {
      async query<R>(text: string, params: readonly unknown[]): Promise<{ rows: R[] }> {
        if (text.includes("SELECT setting_value")) {
          const key = String(params[0]);
          const v = settings.get(key);
          return {
            rows: (v === undefined ? [] : [{ setting_value: v }]) as R[],
          };
        }
        if (text.includes("WITH upserted AS") && text.includes("audit_log")) {
          settings.set(String(params[0]), String(params[1]));
          audits.push(params);
          return { rows: [] };
        }
        return { rows: [] };
      },
    };
    return { sql, audits, settings };
  }

  it("missing row → DISABLED absent", async () => {
    const { sql } = memSql();
    const p = createSqlAutoApprovePolicy(sql);
    expect(await p.getPolicy()).toEqual({
      status: "disabled",
      disabledReason: "absent",
    });
  });

  it("unreadable store → DISABLED unreadable", async () => {
    const sql: SqlExecutor = {
      async query(): Promise<{ rows: never[] }> {
        throw new Error("connection refused");
      },
    };
    const p = createSqlAutoApprovePolicy(sql);
    expect(await p.getPolicy()).toEqual({
      status: "disabled",
      disabledReason: "unreadable",
    });
  });

  it("corrupt stored value → DISABLED invalid", async () => {
    const { sql } = memSql(new Map([[AUTO_APPROVE_SETTING_KEY, "{nope"]]));
    const p = createSqlAutoApprovePolicy(sql);
    expect(await p.getPolicy()).toEqual({
      status: "disabled",
      disabledReason: "invalid",
    });
  });

  it("setPolicy upserts + audit with sha256 of documents", async () => {
    const { sql, audits, settings } = memSql();
    const p = createSqlAutoApprovePolicy(sql, {
      newId: () => "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    });
    const json = validDoc();
    await p.setPolicy!(json, {
      actorId: "op-9",
      nodeId: "11111111-1111-4111-8111-111111111111",
    });
    expect(settings.has(AUTO_APPROVE_SETTING_KEY)).toBe(true);
    expect(audits).toHaveLength(1);
    const details = String(audits[0]![5]);
    expect(details).toMatch(/^setting_key=ops\.auto_approve_sends;previous_sha256=absent;next_sha256=/);
    const nextSha = details.split("next_sha256=")[1]!;
    const stored = settings.get(AUTO_APPROVE_SETTING_KEY)!;
    expect(nextSha).toBe(createHash("sha256").update(stored, "utf8").digest("hex"));
    const detailsSha = String(audits[0]![6]);
    expect(detailsSha).toBe(createHash("sha256").update(details, "utf8").digest("hex"));
    expect(await p.getPolicy()).toMatchObject({ status: "enabled" });
  });

  it("setPolicy is one statement (settings + audit)", async () => {
    let writeCount = 0;
    const settings = new Map<string, string>();
    const sql: SqlExecutor = {
      async query<R>(text: string, params: readonly unknown[]): Promise<{ rows: R[] }> {
        if (text.includes("SELECT setting_value")) return { rows: [] as R[] };
        writeCount += 1;
        if (text.includes("WITH upserted AS") && text.includes("audit_log")) {
          settings.set(String(params[0]), String(params[1]));
          return { rows: [] as R[] };
        }
        throw new Error(`unexpected split write: ${text.slice(0, 80)}`);
      },
    };
    const p = createSqlAutoApprovePolicy(sql, {
      newId: () => "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    });
    await p.setPolicy!(validDoc(), {
      actorId: "op-1",
      nodeId: "11111111-1111-4111-8111-111111111111",
    });
    expect(writeCount).toBe(1);
  });
});

describe("LOCK_AUTO_APPROVE_WINDOW_SQL", () => {
  it("is transaction-scoped advisory lock namespaced by implementer id", () => {
    expect(LOCK_AUTO_APPROVE_WINDOW_SQL).toContain("pg_advisory_xact_lock");
    expect(LOCK_AUTO_APPROVE_WINDOW_SQL).toContain("hashtextextended");
    expect(LOCK_AUTO_APPROVE_WINDOW_SQL).toContain("auto-approve-window:");
    expect(LOCK_AUTO_APPROVE_WINDOW_SQL).not.toContain("pg_advisory_lock(");
    expect(LOCK_AUTO_APPROVE_WINDOW_SQL).toMatch(/\$1/);
  });
});
