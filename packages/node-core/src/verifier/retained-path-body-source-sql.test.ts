// direct coverage of `createSqlRetainedPathBodySource`'s two probes and the two
// standalone lookups (`fetchRetainedBodyByObservationId`, `fetchRetainedBodyByStepOneSignature`).
// No pg drill reaches the AMBIGUOUS forks or `countDistinctBodiesWithDigest`'s COUNT forwarding
// — a single seeded fixture pair never produces two rows sharing one backlink/digest/step-1
// signature. A minimal in-memory `SqlQueryPort` stands in for pg here; this file tests the
// adapter's row shaping, dedup and NONE/FOUND/AMBIGUOUS classification only — `verifyHop`'s
// independent re-derivation of every field is covered in ancestry-walker.test.ts.

import { describe, expect, it } from "vitest";

import {
  createSqlRetainedPathBodySource,
  fetchRetainedBodyByObservationId,
  fetchRetainedBodyByStepOneSignature,
  type SqlQueryPort,
} from "./retained-path-body-source-sql.js";

function row(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    observation_id: "11111111-1111-1111-1111-111111111111",
    wallet_public_key: "wallet-pub",
    completed_transaction_text: '{"a":1}',
    completed_transaction_sha256: "a".repeat(64),
    wallet_role: "sender",
    s_signature: "sig-s",
    p_signature: "sig-p",
    b_amount: "2.25",
    inner_preimage_text: '{"inner":true}',
    step_1_signature: "sig-1",
    step_2_signature: "sig-2",
    semantic_fingerprint: "b".repeat(64),
    ...overrides,
  };
}

function portReturning(rows: readonly Record<string, unknown>[]): SqlQueryPort {
  return {
    async query<R extends Record<string, unknown>>() {
      return { rows: rows as readonly R[] };
    },
  };
}

describe("createSqlRetainedPathBodySource", () => {
  it("resolveSuccessorByBacklink: NONE when zero rows match", async () => {
    const source = createSqlRetainedPathBodySource({ sql: portReturning([]) });
    expect(await source.resolveSuccessorByBacklink("w", "p")).toEqual({ kind: "NONE" });
  });

  it("resolveSuccessorByBacklink: FOUND, tagged FRESH_GATEWAY_HEAD, one distinct body", async () => {
    const source = createSqlRetainedPathBodySource({ sql: portReturning([row()]) });
    const result = await source.resolveSuccessorByBacklink("w", "p");
    expect(result.kind).toBe("FOUND");
    if (result.kind !== "FOUND") throw new Error("unreachable");
    expect(result.body.source_kind).toBe("FRESH_GATEWAY_HEAD");
    expect(result.body.completed_transaction_sha256).toBe("a".repeat(64));
  });

  it("resolveSuccessorByBacklink: dedups rows sharing identical completed_transaction_text", async () => {
    const source = createSqlRetainedPathBodySource({ sql: portReturning([row(), row()]) });
    expect((await source.resolveSuccessorByBacklink("w", "p")).kind).toBe("FOUND");
  });

  it("resolveSuccessorByBacklink: AMBIGUOUS on two distinct bodies — never a silent pick", async () => {
    const source = createSqlRetainedPathBodySource({
      sql: portReturning([row(), row({ completed_transaction_text: '{"a":2}' })]),
    });
    expect(await source.resolveSuccessorByBacklink("w", "p")).toEqual({ kind: "AMBIGUOUS" });
  });

  it("countDistinctBodiesWithDigest: forwards the driver's COUNT", async () => {
    const source = createSqlRetainedPathBodySource({ sql: portReturning([{ count: "3" }]) });
    expect(await source.countDistinctBodiesWithDigest("deadbeef")).toBe(3);
  });

  it("countDistinctBodiesWithDigest: 0 when no row is returned", async () => {
    const source = createSqlRetainedPathBodySource({ sql: portReturning([]) });
    expect(await source.countDistinctBodiesWithDigest("deadbeef")).toBe(0);
  });
});

describe("fetchRetainedBodyByObservationId", () => {
  it("returns the row tagged CANONICAL_LEDGER when found", async () => {
    const body = await fetchRetainedBodyByObservationId(
      { sql: portReturning([row()]) },
      "11111111-1111-1111-1111-111111111111",
    );
    expect(body?.source_kind).toBe("CANONICAL_LEDGER");
  });

  it("returns null when the primary-key lookup finds nothing", async () => {
    const body = await fetchRetainedBodyByObservationId({ sql: portReturning([]) }, "missing");
    expect(body).toBeNull();
  });
});

describe("fetchRetainedBodyByStepOneSignature", () => {
  it("FOUND, tagged EXPECTED_OPERATION", async () => {
    const result = await fetchRetainedBodyByStepOneSignature(
      { sql: portReturning([row()]) },
      "wallet-pub",
      "sig-1",
    );
    expect(result.kind).toBe("FOUND");
    if (result.kind !== "FOUND") throw new Error("unreachable");
    expect(result.body.source_kind).toBe("EXPECTED_OPERATION");
  });

  it("NONE when the node's own send is not yet independently observed", async () => {
    const result = await fetchRetainedBodyByStepOneSignature(
      { sql: portReturning([]) },
      "wallet-pub",
      "sig-1",
    );
    expect(result).toEqual({ kind: "NONE" });
  });

  it("AMBIGUOUS when two distinct completed bodies share one step-1 signature — a fork", async () => {
    const result = await fetchRetainedBodyByStepOneSignature(
      { sql: portReturning([row(), row({ completed_transaction_text: '{"a":2}' })]) },
      "wallet-pub",
      "sig-1",
    );
    expect(result).toEqual({ kind: "AMBIGUOUS" });
  });
});
