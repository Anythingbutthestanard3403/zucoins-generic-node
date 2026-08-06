import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";

import {
  writeExactHeadLineagePath,
  writeLineagePath,
  type LineageBodyInput,
} from "../src/core/lineage-path-writer.js";

function sha(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function fakeQuery(store: { sql: string[]; params: unknown[][] }) {
  return async (sql: string, params: readonly unknown[] = []) => {
    store.sql.push(sql);
    store.params.push([...params]);
    if (sql.includes("FROM lineage_path_proofs") && sql.includes("path_role")) {
      return [];
    }
    if (sql.includes("FROM gateway_observations")) {
      return [{ ok: 1 }];
    }
    if (sql.includes("FROM operation_transactions")) {
      const body = JSON.stringify({
        inner: {
          version: 1,
          previous_step_1_state_signature: "",
          step_1_state: { amount: "0.000001" },
        },
        step_1_signature: `${"A".repeat(86)}==`,
        step_2_signature: `${"B".repeat(86)}==`,
      });
      return [
        {
          completed_transaction_text: body,
          completed_transaction_sha256: sha(body),
          inner_preimage_text: '{"version":1}',
          inner_sha256: sha('{"version":1}'),
          step_1_signature: `${"A".repeat(86)}==`,
          step_2_signature: `${"B".repeat(86)}==`,
        },
      ];
    }
    return [];
  };
}

describe("lineage-path-writer", () => {
  it("writeLineagePath inserts proof then bodies in path_index order", async () => {
    const store = { sql: [] as string[], params: [] as unknown[][] };
    const body: LineageBodyInput = {
      pathIndex: 0,
      sourceKind: "EXPECTED_OPERATION",
      completedTransactionText: '{"inner":{},"step_1_signature":"x","step_2_signature":"y"}',
      completedTransactionSha256: "aa".repeat(32),
      completedTransactionOctets: 64,
      walletRole: "receiver",
      sSignature: `${"C".repeat(86)}==`,
      pSignature: "",
      bAmount: "0.000001",
      innerPreimageText: "{}",
      innerSha256: "bb".repeat(32),
      step1Signature: `${"D".repeat(86)}==`,
      step2Signature: `${"E".repeat(86)}==`,
    };
    const result = await writeLineagePath(fakeQuery(store), {
      landingProofId: "11111111-1111-4111-8111-111111111111",
      pathRole: "RECEIVER",
      walletId: "22222222-2222-4222-8222-222222222222",
      walletPublicKey: `${"W".repeat(43)}=`,
      t0ObservationId: "33333333-3333-4333-8333-333333333333",
      freshHeadObservationId: "44444444-4444-4444-8444-444444444444",
      expectedCompletedTransactionSha256: "aa".repeat(32),
      freshHeadCompletedTransactionSha256: "aa".repeat(32),
      verdict: "LANDED_EXACT",
      pathDepth: 0,
      proofManifestText: "{}",
      proofManifestSha256: "cc".repeat(32),
      bodies: [body],
    });
    expect(result.reusedExisting).toBe(false);
    expect(result.bodyCount).toBe(1);
    expect(store.sql.some((s) => s.includes("INSERT INTO lineage_path_proofs"))).toBe(true);
    expect(store.sql.some((s) => s.includes("INSERT INTO lineage_path_bodies"))).toBe(true);
  });

  it("writeExactHeadLineagePath loads settled body when bodies omitted", async () => {
    const store = { sql: [] as string[], params: [] as unknown[][] };
    const result = await writeExactHeadLineagePath(fakeQuery(store), {
      operationId: "55555555-5555-4555-8555-555555555555",
      landingProofId: "11111111-1111-4111-8111-111111111111",
      pathRole: "SOURCE",
      walletId: null,
      walletPublicKey: `${"S".repeat(43)}=`,
      t0ObservationId: "33333333-3333-4333-8333-333333333333",
      freshHeadObservationId: "44444444-4444-4444-8444-444444444444",
      verdict: "LANDED_COMPLETE_PATH",
      pathDepth: 3,
      proofManifestText: "{}",
      proofManifestSha256: "dd".repeat(32),
    });
    // Falls back to depth-0 exact head when multi-hop bodies unavailable.
    expect(result.bodyCount).toBe(1);
    expect(store.sql.some((s) => s.includes("FROM operation_transactions"))).toBe(true);
    expect(store.sql.some((s) => s.includes("INSERT INTO lineage_path_proofs"))).toBe(true);
  });
});
