// Additive device-signature policy — fail closed, never request-body alone.

import { describe, expect, it } from "vitest";

import {
  combineDeviceSignatureRequirement,
  DEVICE_SIGNATURE_POLICY_COPY,
  DEVICE_SIGNATURE_POLICY_SETTING_KEY,
  effectiveDeviceSignaturePolicyMode,
  InMemoryDeviceSignaturePolicy,
  parseDeviceSignaturePolicyMode,
  resolveDeviceSignatureRequired,
  createSqlDeviceSignaturePolicy,
} from "./device-signature-policy.js";
import type { SqlExecutor } from "./sql-store.js";

describe("parseDeviceSignaturePolicyMode", () => {
  it("accepts only the exact mode literals", () => {
    expect(parseDeviceSignaturePolicyMode("required")).toBe("required");
    expect(parseDeviceSignaturePolicyMode("optional")).toBe("optional");
  });

  it.each([
    "REQUIRED",
    "required ",
    " required",
    "opt",
    "true",
    "false",
    "1",
    "",
    "two_human",
    "TOTP_AND_DEVICE",
  ])("marks present-but-unrecognised value %j as invalid", (raw) => {
    expect(parseDeviceSignaturePolicyMode(raw)).toBe("invalid");
  });

  it("marks absent values as invalid (fail closed — not a silent optional default)", () => {
    expect(parseDeviceSignaturePolicyMode(undefined)).toBe("invalid");
    expect(parseDeviceSignaturePolicyMode(null)).toBe("invalid");
  });
});

describe("resolveDeviceSignatureRequired — fail closed", () => {
  it("only exact optional yields false", () => {
    expect(resolveDeviceSignatureRequired("optional")).toBe(false);
  });

  it.each([
    "required",
    undefined,
    null,
    "",
    "REQUIRED",
    "optional ",
    "garbage",
    "true",
  ])("requires the device factor for %j", (raw) => {
    expect(resolveDeviceSignatureRequired(raw as string | null | undefined)).toBe(true);
  });

  it("effective mode collapses fail-closed inputs to required", () => {
    expect(effectiveDeviceSignaturePolicyMode(null)).toBe("required");
    expect(effectiveDeviceSignaturePolicyMode("nope")).toBe("required");
    expect(effectiveDeviceSignaturePolicyMode("optional")).toBe("optional");
  });
});

describe("combineDeviceSignatureRequirement", () => {
  it("is policy OR request — never request alone as the only source of true", () => {
    expect(combineDeviceSignatureRequirement(false, false)).toBe(false);
    expect(combineDeviceSignatureRequirement(true, false)).toBe(true);
    expect(combineDeviceSignatureRequirement(false, true)).toBe(true);
    expect(combineDeviceSignatureRequirement(true, true)).toBe(true);
  });
});

describe("InMemoryDeviceSignaturePolicy", () => {
  it("defaults to required (fail closed)", () => {
    const p = new InMemoryDeviceSignaturePolicy();
    expect(p.requiresDeviceSignature()).toBe(true);
    expect(p.getMode()).toBe("required");
  });

  it("setMode switches and records an audit entry", () => {
    const p = new InMemoryDeviceSignaturePolicy("required");
    p.setMode("optional", { actorId: "op-1", nodeId: "node-1" });
    expect(p.requiresDeviceSignature()).toBe(false);
    expect(p.auditEntries).toEqual([
      { mode: "optional", actorId: "op-1", nodeId: "node-1" },
    ]);
  });

  it("exposes plain-language copy for both modes", () => {
    expect(DEVICE_SIGNATURE_POLICY_COPY.required.short).toMatch(/required/i);
    expect(DEVICE_SIGNATURE_POLICY_COPY.optional.long).toMatch(/optional/i);
    expect(DEVICE_SIGNATURE_POLICY_SETTING_KEY).toBe("ops.approval_device_signature");
  });
});

describe("createSqlDeviceSignaturePolicy", () => {
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

  it("missing row fails closed (requires device)", async () => {
    const { sql } = memSql();
    const p = createSqlDeviceSignaturePolicy(sql);
    expect(await p.requiresDeviceSignature()).toBe(true);
    expect(await p.getMode()).toBe("required");
  });

  it("optional row allows TOTP-only", async () => {
    const { sql } = memSql(
      new Map([[DEVICE_SIGNATURE_POLICY_SETTING_KEY, "optional"]]),
    );
    const p = createSqlDeviceSignaturePolicy(sql);
    expect(await p.requiresDeviceSignature()).toBe(false);
    expect(await p.getMode()).toBe("optional");
  });

  it("unrecognised stored value fails closed", async () => {
    const { sql } = memSql(
      new Map([[DEVICE_SIGNATURE_POLICY_SETTING_KEY, "maybe"]]),
    );
    const p = createSqlDeviceSignaturePolicy(sql);
    expect(await p.requiresDeviceSignature()).toBe(true);
  });

  it("unreadable store fails closed", async () => {
    const sql: SqlExecutor = {
      async query(): Promise<{ rows: never[] }> {
        throw new Error("connection refused");
      },
    };
    const p = createSqlDeviceSignaturePolicy(sql);
    expect(await p.requiresDeviceSignature()).toBe(true);
    expect(await p.getMode()).toBe("required");
  });

  it("setMode upserts node_settings and writes audit_log", async () => {
    const { sql, audits, settings } = memSql();
    const p = createSqlDeviceSignaturePolicy(sql, {
      newId: () => "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    });
    await p.setMode!("optional", {
      actorId: "op-9",
      nodeId: "11111111-1111-4111-8111-111111111111",
    });
    expect(settings.get(DEVICE_SIGNATURE_POLICY_SETTING_KEY)).toBe("optional");
    expect(audits).toHaveLength(1);
    expect(audits[0]![2]).toBe("op-9");
    expect(String(audits[0]![3])).toMatch(/previous=required;next=optional/);
    expect(await p.requiresDeviceSignature()).toBe(false);
  });
});
