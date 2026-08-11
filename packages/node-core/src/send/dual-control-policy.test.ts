// Two-human dual control vs single-operator.

import { describe, expect, it } from "vitest";

import {
  DUAL_CONTROL_COPY,
  DUAL_CONTROL_SETTING_KEY,
  createSqlDualControlPolicy,
  effectiveDualControlMode,
  enforceDualControlOperators,
  InMemoryDualControlPolicy,
  parseDualControlMode,
} from "./dual-control-policy.js";
import { InMemoryApprovalChallengeIssuerStore } from "./challenge-issuer-store.js";
import type { SqlExecutor } from "./sql-store.js";

describe("dual-control policy modes", () => {
  it("resolves only the exact mode literals", () => {
    expect(parseDualControlMode("two_human")).toBe("two_human");
    expect(parseDualControlMode("single_operator")).toBe("single_operator");
  });

  // The fail-open regression this guards: every one of these once resolved to
  // single_operator, so an operator who typed the setting slightly wrong got no
  // dual control and no error (ZTR-1148).
  it.each(["two-human", "TWO_HUMAN", " two_human", "two_human ", "", "TWO-HUMAN", "yes"])(
    "never resolves a present-but-unrecognised value (%j) to a mode",
    (raw) => {
      expect(parseDualControlMode(raw)).toBe("invalid");
    },
  );

  // Deliberate and distinct from the above: doc 01 §4.2 makes node policy OPTIONAL,
  // so absence is "this deployment configured no policy", not a malformed value.
  // It is documented in .env.example, defaulted in the frozen schema, and readable
  // at GET /admin/v1/dual-control-policy — the three things the fail-open bug lacked.
  it("treats an absent setting as the documented no-policy default", () => {
    expect(parseDualControlMode(undefined)).toBe("single_operator");
    expect(parseDualControlMode(null)).toBe("single_operator");
  });

  it("exposes plain-language copy for both modes", () => {
    expect(DUAL_CONTROL_COPY.single_operator.short).toMatch(/Single/i);
    expect(DUAL_CONTROL_COPY.two_human.short).toMatch(/Two-human/i);
    expect(DUAL_CONTROL_COPY.two_human.long).toMatch(/different admin operator/i);
    expect(DUAL_CONTROL_SETTING_KEY).toBe("ops.dual_control_mode");
  });
});

describe("effectiveDualControlMode", () => {
  it("uses defaultMode when the row is absent", () => {
    expect(effectiveDualControlMode(null)).toBe("single_operator");
    expect(effectiveDualControlMode(undefined, "two_human")).toBe("two_human");
  });

  it("returns exact literals", () => {
    expect(effectiveDualControlMode("two_human")).toBe("two_human");
    expect(effectiveDualControlMode("single_operator", "two_human")).toBe("single_operator");
  });

  it("never weakens corrupt stored values (stricter two_human)", () => {
    expect(effectiveDualControlMode("TWO_HUMAN")).toBe("two_human");
    expect(effectiveDualControlMode("garbage", "single_operator")).toBe("two_human");
  });
});

describe("enforceDualControlOperators", () => {
  it("single_operator allows same operator both sides", () => {
    const r = enforceDualControlOperators("single_operator", "op-1", "op-1");
    expect(r.ok).toBe(true);
  });

  it("two_human rejects same operator both sides", () => {
    const r = enforceDualControlOperators("two_human", "op-1", "op-1");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("same_operator_both_sides");
      expect(r.detail).toMatch(/different admin operator/i);
    }
  });

  it("two_human allows distinct operators", () => {
    const r = enforceDualControlOperators("two_human", "op-1", "op-2");
    expect(r.ok).toBe(true);
  });

  it("two_human fails closed when challenge issuer missing", () => {
    const r = enforceDualControlOperators("two_human", null, "op-2");
    expect(r.ok).toBe(false);
  });
});

describe("InMemoryDualControlPolicy + issuer store", () => {
  it("policy port switches modes and always records audit meta (required)", () => {
    const p = new InMemoryDualControlPolicy("single_operator");
    expect(p.getMode()).toBe("single_operator");
    p.setMode("two_human", { actorId: "op-1", nodeId: "node-1" });
    expect(p.getMode()).toBe("two_human");
    expect(p.auditEntries).toEqual([
      { mode: "two_human", actorId: "op-1", nodeId: "node-1" },
    ]);
  });

  it("defaults to two_human so an unwired lab mount does not weaken", () => {
    expect(new InMemoryDualControlPolicy().getMode()).toBe("two_human");
  });

  it("issuer store records and clears", () => {
    const s = new InMemoryApprovalChallengeIssuerStore();
    s.recordIssuer("op-id", "ch-1", "admin-a");
    expect(s.findIssuer("op-id")).toBe("admin-a");
    s.clear("op-id");
    expect(s.findIssuer("op-id")).toBeNull();
  });
});

describe("createSqlDualControlPolicy", () => {
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
        if (text.includes("INSERT INTO node_settings")) {
          settings.set(String(params[0]), String(params[1]));
          return { rows: [] };
        }
        if (text.includes("INSERT INTO audit_log")) {
          audits.push(params);
          return { rows: [] };
        }
        return { rows: [] };
      },
    };
    return { sql, audits, settings };
  }

  it("missing row uses defaultMode (boot env pre-mutation)", async () => {
    const { sql } = memSql();
    const p = createSqlDualControlPolicy(sql, { defaultMode: "two_human" });
    expect(await p.getMode()).toBe("two_human");
  });

  it("stored two_human is durable across reads", async () => {
    const { sql } = memSql(new Map([[DUAL_CONTROL_SETTING_KEY, "two_human"]]));
    const p = createSqlDualControlPolicy(sql, { defaultMode: "single_operator" });
    expect(await p.getMode()).toBe("two_human");
  });

  it("unrecognised stored value never weakens (two_human)", async () => {
    const { sql } = memSql(new Map([[DUAL_CONTROL_SETTING_KEY, "maybe"]]));
    const p = createSqlDualControlPolicy(sql, { defaultMode: "single_operator" });
    expect(await p.getMode()).toBe("two_human");
  });

  it("unreadable store never weakens past two_human (even when defaultMode is single_operator)", async () => {
    const sql: SqlExecutor = {
      async query(): Promise<{ rows: never[] }> {
        throw new Error("connection refused");
      },
    };
    // The weaken path Review B D1 locked against: boot default single_operator
    // must not win over a transient read fault after a durable two_human write.
    const p = createSqlDualControlPolicy(sql, { defaultMode: "single_operator" });
    expect(await p.getMode()).toBe("two_human");
  });

  it("unreadable store still two_human when defaultMode is already two_human", async () => {
    const sql: SqlExecutor = {
      async query(): Promise<{ rows: never[] }> {
        throw new Error("connection refused");
      },
    };
    const p = createSqlDualControlPolicy(sql, { defaultMode: "two_human" });
    expect(await p.getMode()).toBe("two_human");
  });

  it("setMode upserts node_settings and writes audit_log", async () => {
    const { sql, audits, settings } = memSql();
    const p = createSqlDualControlPolicy(sql, {
      newId: () => "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      defaultMode: "single_operator",
    });
    await p.setMode!("two_human", {
      actorId: "op-9",
      nodeId: "11111111-1111-4111-8111-111111111111",
    });
    expect(settings.get(DUAL_CONTROL_SETTING_KEY)).toBe("two_human");
    expect(audits).toHaveLength(1);
    expect(audits[0]![1]).toBe("two_human");
    expect(audits[0]![4]).toBe("op-9");
    expect(String(audits[0]![5])).toMatch(/previous=single_operator;next=two_human/);
    expect(await p.getMode()).toBe("two_human");
  });

  it("setMode issues one statement covering settings and audit (no split autocommit)", async () => {
    let writeCount = 0;
    const settings = new Map<string, string>();
    const sql: SqlExecutor = {
      async query<R>(text: string, params: readonly unknown[]): Promise<{ rows: R[] }> {
        if (text.includes("SELECT setting_value")) {
          return { rows: [] as R[] };
        }
        writeCount += 1;
        if (text.includes("WITH upserted AS") && text.includes("audit_log")) {
          settings.set(String(params[0]), String(params[1]));
          return { rows: [] as R[] };
        }
        throw new Error(`unexpected split write: ${text.slice(0, 80)}`);
      },
    };
    const p = createSqlDualControlPolicy(sql, {
      newId: () => "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    });
    await p.setMode!("single_operator", {
      actorId: "op-1",
      nodeId: "11111111-1111-4111-8111-111111111111",
    });
    expect(writeCount).toBe(1);
    expect(settings.get(DUAL_CONTROL_SETTING_KEY)).toBe("single_operator");
  });
});
