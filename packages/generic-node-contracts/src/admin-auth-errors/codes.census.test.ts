import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { ADMIN_ERROR_CODES, ADMIN_ERROR_CODE_SET, isAdminErrorCode } from "./codes.js";
import {
  AdminErrorEnvelopeSchema,
  AdminLabReceiveErrorEnvelopeSchema,
  buildAdminErrorBody,
  buildAdminLabReceiveErrorBody,
  coerceAdminErrorCode,
} from "./envelope.js";

const here = dirname(fileURLToPath(import.meta.url));

describe("ADMIN_ERROR_CODES census", () => {
  it("has unique codes", () => {
    const codes = ADMIN_ERROR_CODES.map((e) => e.code);
    expect(new Set(codes).size).toBe(codes.length);
  });

  it("is sorted by code for stable review diffs", () => {
    // Not required to be sorted — pin length + membership instead.
    expect(ADMIN_ERROR_CODES.length).toBeGreaterThan(50);
  });

  it("isAdminErrorCode accepts every frozen entry and rejects unknown", () => {
    for (const { code } of ADMIN_ERROR_CODES) {
      expect(isAdminErrorCode(code)).toBe(true);
      expect(ADMIN_ERROR_CODE_SET.has(code)).toBe(true);
    }
    expect(isAdminErrorCode("totally_invented_code")).toBe(false);
    expect(coerceAdminErrorCode("totally_invented_code")).toBe("internal_error");
  });
});

describe("AdminErrorEnvelopeSchema", () => {
  const rid = "00000000-0000-4000-8000-000000000001";

  it("accepts every frozen code with details present", () => {
    for (const { code } of ADMIN_ERROR_CODES) {
      const body = buildAdminErrorBody(code, "diagnostic", rid);
      const parsed = AdminErrorEnvelopeSchema.safeParse(JSON.parse(body));
      expect(parsed.success, code).toBe(true);
      if (parsed.success) {
        expect(parsed.data.error.details).toEqual({});
        expect(parsed.data.error.request_id).toBe(rid);
      }
    }
  });

  it("rejects missing details under strict parse of raw object without default path", () => {
    // Schema applies default on parse — missing details still succeeds via .default({}).
    // Extra keys fail .strict().
    const extra = {
      error: {
        code: "not_found",
        message: "x",
        request_id: rid,
        details: {},
        extra: true,
      },
    };
    expect(AdminErrorEnvelopeSchema.safeParse(extra).success).toBe(false);
  });

  it("rejects codes outside ADMIN_ERROR_CODES", () => {
    const body = {
      error: {
        code: "not_a_real_admin_code",
        message: "x",
        request_id: rid,
        details: {},
      },
    };
    expect(AdminErrorEnvelopeSchema.safeParse(body).success).toBe(false);
  });

  it("rejects non-uuid request_id", () => {
    const body = {
      error: {
        code: "not_found",
        message: "x",
        request_id: "not-a-uuid",
        details: {},
      },
    };
    expect(AdminErrorEnvelopeSchema.safeParse(body).success).toBe(false);
  });
});

describe("AdminLabReceiveErrorEnvelopeSchema", () => {
  const rid = "00000000-0000-4000-8000-000000000002";

  it("accepts checklist_links and operation_id siblings", () => {
    const body = buildAdminLabReceiveErrorBody("lab_gates_blocked", "blocked", rid, {
      checklist_links: [{ id: "a", href: "/x", title: "t", detail: "d", status: "open" }],
      operation_id: "op_1",
    });
    const parsed = AdminLabReceiveErrorEnvelopeSchema.safeParse(JSON.parse(body));
    expect(parsed.success).toBe(true);
  });

  it("rejects putting checklist_links inside error", () => {
    const body = {
      error: {
        code: "lab_gates_blocked",
        message: "x",
        request_id: rid,
        details: {},
        checklist_links: [],
      },
    };
    expect(AdminLabReceiveErrorEnvelopeSchema.safeParse(body).success).toBe(false);
  });
});

describe("admin-router fail() code census", () => {
  it("every string literal fail(status, \"code\") is in ADMIN_ERROR_CODES", () => {
    // Walk up to repo root from this concern dir:
    // src/admin-auth-errors -> src -> generic-node-contracts -> packages -> root
    // here = packages/generic-node-contracts/src/admin-auth-errors
    // four levels up reaches the monorepo root.
    const routerPath = join(
      here,
      "..",
      "..",
      "..",
      "..",
      "apps",
      "generic-node",
      "src",
      "admin-router.ts",
    );
    const src = readFileSync(routerPath, "utf8");
    const literal = [...src.matchAll(/fail\(\s*\d+\s*,\s*"([a-z0-9_]+)"/g)].map((m) => m[1]!);
    const missing = [...new Set(literal)].filter((c) => !ADMIN_ERROR_CODE_SET.has(c));
    expect(missing, `unfrozen fail() codes: ${missing.join(", ")}`).toEqual([]);
  });

  it("buildAdminErrorBody key sequence is stable (sha of one sample)", () => {
    const body = buildAdminErrorBody(
      "invalid_credentials",
      "authentication required",
      "00000000-0000-4000-8000-000000000099",
    );
    const digest = createHash("sha256").update(body).digest("hex");
    expect(digest).toBe(
      createHash("sha256")
        .update(
          '{"error":{"code":"invalid_credentials","message":"authentication required","request_id":"00000000-0000-4000-8000-000000000099","details":{}}}',
        )
        .digest("hex"),
    );
  });
});
