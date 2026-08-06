// D3 — the 409/200/410 status semantics of
// `GET /v1/operations/:operation_id/verification-material`.
//
// Each status has a test that pins the ONE condition that produces it:
//   409  the operation is not at its kind's landed-terminal status, or is landed with the
//        `verification_material_available_until` column still unpopulated
//   200  landed terminal AND now < verification_material_available_until
//   410  landed terminal AND now >= verification_material_available_until
//   404  the operation is unknown, or belongs to another tenant (stage-5 collapse)
//
// The window boundary is asserted on both sides, and the D2 derivation
// (`verificationMaterialAvailableUntilMs`, the value the terminal-transition writer puts
// in the column) is fed through the handler so the writer and the gate cannot disagree.

import { describe, expect, it } from "vitest";

import {
  handleGetVerificationMaterial,
  VERIFICATION_MATERIAL_FIELD_KEYS,
  type VerificationMaterialRow,
  type VerificationMaterialSource,
} from "../src/api/verification-material.ts";
import {
  DEFAULT_PROOF_ACCESS_WINDOW_MS,
  PROOF_ACCESS_HTTP,
  PROOF_ACCESS_VERDICTS,
  verificationMaterialAvailableUntilMs,
} from "../src/data/retention.ts";
import { API_ERROR_CODES, HTTP_STATUS_BY_CODE } from "../src/api/error-envelope.ts";

const REQUEST_ID = "11111111-1111-4111-8111-111111111111";
const OPERATION_ID = "22222222-2222-4222-8222-222222222222";
const TENANT_ID = "tenant-a";
const TERMINAL_AT_MS = Date.UTC(2026, 0, 1, 0, 0, 0);
const UNTIL_MS = verificationMaterialAvailableUntilMs(TERMINAL_AT_MS);

// The fields between `operation_id` and `available_until`, in document order. The
// handler never builds or inspects these — the evidence lanes assemble them.
const MATERIAL = {
  operation_type: "MOVE_INTERNAL",
  state: "INTERNAL_MOVE_LANDED",
  landed_attempt_no: 1,
  expected_artifact: null,
  observation_evidence: [],
  attempts: [],
  ancestor_proofs: [],
} as const;

const row = (over: Partial<VerificationMaterialRow> = {}): VerificationMaterialRow => ({
  kind: "MOVE_INTERNAL",
  status: "INTERNAL_MOVE_LANDED",
  verificationMaterialAvailableUntilMs: UNTIL_MS,
  material: MATERIAL,
  ...over,
});

const sourceOf = (value: VerificationMaterialRow | null): VerificationMaterialSource => ({
  load: async (operationId, tenantId) =>
    operationId === OPERATION_ID && tenantId === TENANT_ID ? value : null,
});

const get = (
  value: VerificationMaterialRow | null,
  nowMs: number,
  over: { operationId?: string; tenantId?: string } = {},
) =>
  handleGetVerificationMaterial(
    {
      requestId: REQUEST_ID,
      operationId: over.operationId ?? OPERATION_ID,
      tenantId: over.tenantId ?? TENANT_ID,
      nowMs,
    },
    sourceOf(value),
  );

const codeOf = (body: string): string => JSON.parse(body).error.code;

describe("GET /v1/operations/:operation_id/verification-material — 409 not ready", () => {
  // Only the kind's landed-terminal status has material. Every other status is
  // pre-terminal and must never serve, whatever the window says.
  const preTerminal: ReadonlyArray<[VerificationMaterialRow["kind"], string]> = [
    ["RECEIVE_EXTERNAL", "CREATED"],
    ["RECEIVE_EXTERNAL", "READY"],
    ["RECEIVE_EXTERNAL", "EXPIRED"],
    ["MOVE_INTERNAL", "CREATED"],
    ["MOVE_INTERNAL", "NEEDS_ATTENTION"],
    ["SEND_EXTERNAL", "CREATED"],
    ["SEND_EXTERNAL", "APPROVED"],
    ["SEND_EXTERNAL", "AWAITING_REDEMPTION"],
    ["SEND_EXTERNAL", "REJECTED"],
    ["SEND_EXTERNAL", "NEEDS_ATTENTION"],
  ];

  it.each(preTerminal)("409 when %s is at pre-terminal status %s", async (kind, status) => {
    const result = await get(row({ kind, status }), TERMINAL_AT_MS);
    expect(result.status).toBe(409);
    expect(codeOf(result.body)).toBe("verification_material_not_ready");
  });

  it("409 even when a pre-terminal row carries a stray open window", async () => {
    // Defence in depth: a non-landed row must not become accessible because the column
    // was populated in error. Status is checked before the window.
    const result = await get(
      row({ status: "CREATED", verificationMaterialAvailableUntilMs: TERMINAL_AT_MS + 1 }),
      TERMINAL_AT_MS,
    );
    expect(result.status).toBe(409);
    expect(codeOf(result.body)).toBe("verification_material_not_ready");
  });

  it("409 when landed but verification_material_available_until is still null", async () => {
    const result = await get(
      row({ verificationMaterialAvailableUntilMs: null }),
      TERMINAL_AT_MS,
    );
    expect(result.status).toBe(409);
    expect(codeOf(result.body)).toBe("verification_material_not_ready");
  });
});

describe("GET /v1/operations/:operation_id/verification-material — 200 accessible", () => {
  const landed: ReadonlyArray<[VerificationMaterialRow["kind"], string]> = [
    ["RECEIVE_EXTERNAL", "RECEIVE_LANDED"],
    ["MOVE_INTERNAL", "INTERNAL_MOVE_LANDED"],
    ["SEND_EXTERNAL", "EXTERNAL_SEND_LANDED"],
  ];

  it.each(landed)("200 for %s at landed terminal %s inside the window", async (kind, status) => {
    const result = await get(row({ kind, status }), TERMINAL_AT_MS);
    expect(result.status).toBe(200);
    expect(result.headers["content-type"]).toBe("application/json");
  });

  it("200 one millisecond before the window closes (available_until is exclusive)", async () => {
    const result = await get(row(), UNTIL_MS - 1);
    expect(result.status).toBe(200);
  });

  it("serves operation_id first and available_until last, in document order", async () => {
    const result = await get(row(), TERMINAL_AT_MS);
    expect(result.status).toBe(200);
    expect(Object.keys(JSON.parse(result.body))).toEqual([
      "operation_id",
      "operation_type",
      "state",
      "landed_attempt_no",
      "expected_artifact",
      "observation_evidence",
      "attempts",
      "ancestor_proofs",
      "available_until",
    ]);
  });

  it("available_until is the persisted column, RFC 3339 UTC with millisecond precision", async () => {
    const result = await get(row(), TERMINAL_AT_MS);
    const body = JSON.parse(result.body);
    expect(body.operation_id).toBe(OPERATION_ID);
    expect(body.available_until).toBe("2026-01-31T00:00:00.000Z");
    expect(body.available_until).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(Date.parse(body.available_until)).toBe(UNTIL_MS);
  });

  // Break D3: allowlisted field assembly — no open Record spread.
  it("drops forged operation_id and unknown custody keys from material bag", async () => {
    const result = await get(
      row({
        material: {
          ...MATERIAL,
          operation_id: "forged-op",
          private_key: "leak",
          vault_ciphertext: "cipher",
          totp_secret: "otp",
          unrelated_history: [1, 2, 3],
        },
      }),
      TERMINAL_AT_MS,
    );
    expect(result.status).toBe(200);
    const body = JSON.parse(result.body) as Record<string, unknown>;
    expect(body.operation_id).toBe(OPERATION_ID);
    expect(body.operation_id).not.toBe("forged-op");
    for (const poison of [
      "private_key",
      "vault_ciphertext",
      "totp_secret",
      "unrelated_history",
    ]) {
      expect(body).not.toHaveProperty(poison);
      expect(result.body).not.toContain(poison);
    }
    expect(Object.keys(body)).toEqual([
      "operation_id",
      ...VERIFICATION_MATERIAL_FIELD_KEYS,
      "available_until",
    ]);
  });
});

describe("GET /v1/operations/:operation_id/verification-material — 410 expired", () => {
  it("410 exactly at available_until (the window is closed at the boundary)", async () => {
    const result = await get(row(), UNTIL_MS);
    expect(result.status).toBe(410);
    expect(codeOf(result.body)).toBe("verification_material_expired");
  });

  it("410 after available_until", async () => {
    const result = await get(row(), UNTIL_MS + 60_000);
    expect(result.status).toBe(410);
    expect(codeOf(result.body)).toBe("verification_material_expired");
  });

  it.each([
    ["RECEIVE_EXTERNAL", "RECEIVE_LANDED"],
    ["MOVE_INTERNAL", "INTERNAL_MOVE_LANDED"],
    ["SEND_EXTERNAL", "EXTERNAL_SEND_LANDED"],
  ] as ReadonlyArray<[VerificationMaterialRow["kind"], string]>)(
    "410 for %s after the window, and the row is still readable (access revoked, not purged)",
    async (kind, status) => {
      const stored = row({ kind, status });
      const result = await get(stored, UNTIL_MS + 1);
      expect(result.status).toBe(410);
      // Expiry revokes access only. The handler holds no delete
      // path, and the source row it consulted is untouched.
      expect(stored.material).toBe(MATERIAL);
      expect(stored.verificationMaterialAvailableUntilMs).toBe(UNTIL_MS);
    },
  );
});

describe("GET /v1/operations/:operation_id/verification-material — 404 resolution", () => {
  it("404 when the operation does not exist", async () => {
    const result = await get(null, TERMINAL_AT_MS);
    expect(result.status).toBe(404);
    expect(codeOf(result.body)).toBe("not_found");
  });

  it("404 — never 409/410 — for an accessible operation owned by another tenant", async () => {
    // Cross-tenant existence must not leak through the access gate.
    const result = await get(row(), TERMINAL_AT_MS, { tenantId: "tenant-b" });
    expect(result.status).toBe(404);
    expect(codeOf(result.body)).toBe("not_found");
  });

  it("404 for an unknown operation id under the right tenant", async () => {
    const result = await get(row(), TERMINAL_AT_MS, {
      operationId: "33333333-3333-4333-8333-333333333333",
    });
    expect(result.status).toBe(404);
  });
});

describe("D2 derivation and the D3 gate agree", () => {
  // The terminal-transition writer stores verificationMaterialAvailableUntilMs(terminal_at)
  // in operations.verification_material_available_until. Feed exactly that value through
  // the handler: the 30-day window must open at terminal and close at terminal + 30 days.
  const stored = verificationMaterialAvailableUntilMs(TERMINAL_AT_MS);

  it("the written column is terminal_at + 30 days", () => {
    expect(stored - TERMINAL_AT_MS).toBe(DEFAULT_PROOF_ACCESS_WINDOW_MS);
    expect(DEFAULT_PROOF_ACCESS_WINDOW_MS).toBe(30 * 24 * 60 * 60 * 1000);
  });

  it("200 across the whole written window, 410 from its last millisecond onward", async () => {
    const written = row({ verificationMaterialAvailableUntilMs: stored });
    expect((await get(written, TERMINAL_AT_MS)).status).toBe(200);
    expect((await get(written, TERMINAL_AT_MS + DEFAULT_PROOF_ACCESS_WINDOW_MS - 1)).status).toBe(200);
    expect((await get(written, TERMINAL_AT_MS + DEFAULT_PROOF_ACCESS_WINDOW_MS)).status).toBe(410);
  });

  it("a shorter configured window still gates on the written value, not on 30 days", async () => {
    const shortUntil = verificationMaterialAvailableUntilMs(TERMINAL_AT_MS, 60_000);
    const written = row({ verificationMaterialAvailableUntilMs: shortUntil });
    expect((await get(written, TERMINAL_AT_MS + 59_999)).status).toBe(200);
    expect((await get(written, TERMINAL_AT_MS + 60_000)).status).toBe(410);
  });
});

describe("the gate's HTTP projection is the error-envelope taxonomy", () => {
  // The handler passes the gate's code straight to apiErrorResponse. This pins the two
  // surfaces together so neither can drift into a second, disagreeing 409/410 rule.
  const known = new Set<string>(API_ERROR_CODES.map((entry) => entry.code));

  it.each(PROOF_ACCESS_VERDICTS.filter((v) => v !== "ACCESSIBLE"))(
    "%s maps to a real error code whose envelope status equals the gate's",
    (verdict) => {
      const projection = PROOF_ACCESS_HTTP[verdict];
      expect(projection.code).not.toBeNull();
      expect(known.has(projection.code as string)).toBe(true);
      expect(HTTP_STATUS_BY_CODE[projection.code as never]).toBe(projection.http);
    },
  );

  it("ACCESSIBLE carries no error code", () => {
    expect(PROOF_ACCESS_HTTP.ACCESSIBLE).toEqual({ http: 200, code: null });
  });
});
