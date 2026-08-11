// Behavioural proof for the ZTR-1155 change to the genesis T0 observer: the SERIALIZABLE
// capture body is re-run on 40001, and a non-40001 is NOT retried but still maps to
// INDETERMINATE. The census gate proves the retry CALL exists; this proves it fires and that
// the extraction did not swallow the INDETERMINATE mapping back inside the retried body.
import type { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { RECEIVE_T0_OBSERVATION_ROLE } from "@zucoins/node-core";

import { createGenesisT0Observer } from "../src/money-workers/genesis-t0-observer.js";

class SqlStateError extends Error {
  constructor(readonly code: string) {
    super(`pg error ${code}`);
  }
}

/**
 * A pool whose client fails the gateway_observations INSERT on the first `failures` attempts
 * with `code`, then succeeds. Records every statement so BEGIN / COMMIT / ROLLBACK counts are
 * observable — one BEGIN per attempt is what makes "the retry re-ran the body" checkable.
 */
function fakePool(options: { readonly code: string; readonly failures: number }): {
  readonly pool: Pool;
  readonly statements: string[];
  readonly releases: () => number;
} {
  const statements: string[] = [];
  let inserts = 0;
  let released = 0;
  const client = {
    query: async (text: string): Promise<{ rows: unknown[] }> => {
      statements.push(text.trim().split("\n")[0]!.trim());
      if (text.includes("INSERT INTO gateway_observations")) {
        inserts += 1;
        if (inserts <= options.failures) throw new SqlStateError(options.code);
        return { rows: [] };
      }
      if (text.includes("FROM observers")) return { rows: [{ id: "11111111-1111-4111-8111-111111111111" }] };
      if (text.includes("FROM wallets")) return { rows: [{ id: "22222222-2222-4222-8222-222222222222" }] };
      if (text.includes("max(wallet_seq)")) return { rows: [{ m: "7" }] };
      return { rows: [] };
    },
    release: () => {
      released += 1;
    },
  };
  return {
    pool: { connect: async () => client } as unknown as Pool,
    statements,
    releases: () => released,
  };
}

const NODE_ID = "33333333-3333-4333-8333-333333333333";
const WALLET = "zwallet-genesis-test";

describe("genesis T0 observer retry (ZTR-1155)", () => {
  it("re-runs the capture body on 40001 and returns VERIFIED", async () => {
    const { pool, statements, releases } = fakePool({ code: "40001", failures: 1 });

    const result = await createGenesisT0Observer({ pool, nodeId: NODE_ID }).observe(WALLET, RECEIVE_T0_OBSERVATION_ROLE);

    expect(result.kind).toBe("VERIFIED");
    // Two BEGINs = the body ran twice. One BEGIN would mean the retry is dead code — the
    // failure mode the extraction exists to prevent.
    expect(statements.filter((s) => s === "BEGIN ISOLATION LEVEL SERIALIZABLE")).toHaveLength(2);
    // The failed attempt is fully undone before the next one opens.
    expect(statements.filter((s) => s === "ROLLBACK")).toHaveLength(1);
    expect(statements.filter((s) => s === "COMMIT")).toHaveLength(1);
    expect(statements.indexOf("ROLLBACK")).toBeLessThan(statements.lastIndexOf("BEGIN ISOLATION LEVEL SERIALIZABLE"));
    // One checked-out client per attempt, released either way.
    expect(releases()).toBe(2);
  });

  it("does not retry a non-serialization failure, and still maps it to INDETERMINATE", async () => {
    const { pool, statements } = fakePool({ code: "23505", failures: 5 });

    const result = await createGenesisT0Observer({ pool, nodeId: NODE_ID }).observe(WALLET, RECEIVE_T0_OBSERVATION_ROLE);

    expect(result.kind).toBe("INDETERMINATE");
    // Exactly one attempt: withSerializationRetry rethrows a non-40001/40P01 immediately, and
    // the INDETERMINATE mapping sits OUTSIDE the retried body — if it had stayed inline it
    // would swallow the 40001 above and the retry would never see one.
    expect(statements.filter((s) => s === "BEGIN ISOLATION LEVEL SERIALIZABLE")).toHaveLength(1);
    expect(statements.filter((s) => s === "ROLLBACK")).toHaveLength(1);
    expect(statements).not.toContain("COMMIT");
  });

  it("exhausted 40001 retries surface as INDETERMINATE, not as a thrown tick error", async () => {
    const { pool, statements } = fakePool({ code: "40001", failures: 99 });

    const result = await createGenesisT0Observer({ pool, nodeId: NODE_ID }).observe(WALLET, RECEIVE_T0_OBSERVATION_ROLE);

    expect(result.kind).toBe("INDETERMINATE");
    // DEFAULT_SERIALIZATION_RETRY_POLICY.maxAttempts = 5 (CONVENTIONS.md §2).
    expect(statements.filter((s) => s === "BEGIN ISOLATION LEVEL SERIALIZABLE")).toHaveLength(5);
  });
});
