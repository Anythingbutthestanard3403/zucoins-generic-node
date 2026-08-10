import { describe, expect, it, vi } from "vitest";

import { planCapture } from "./capture-writer.js";
import { createSqlAnomalyRecorder } from "./anomaly-recorder-sql.js";

const key = {
  observerId: "11111111-1111-4111-8111-111111111111",
  walletPublicKey: "A".repeat(43) + "=",
};

function malformedCapture(bytes: Uint8Array) {
  return {
    parseResult: "MALFORMED_ENVELOPE" as const,
    rawResponseBytes: bytes,
    isGenesis: false,
    sSignature: "",
    pSignature: "",
    semanticFingerprint: "",
  };
}

describe("createSqlAnomalyRecorder", () => {
  it("appends the exact required parse-result kind in the caller transaction", async () => {
    const query = vi.fn(async () => ({ rows: [] }));
    const capture = malformedCapture(Uint8Array.from([0, 255, 1]));
    const result = planCapture(null, capture);

    await createSqlAnomalyRecorder({ query })({
      key,
      observationId: "22222222-2222-4222-8222-222222222222",
      walletId: "33333333-3333-4333-8333-333333333333",
      priorObservationId: null,
      result,
      capture,
    });

    expect(query).toHaveBeenCalledTimes(1);
    const [sql, params] = query.mock.calls[0] as unknown as [string, readonly unknown[]];
    expect(sql).toContain("INSERT INTO observation_anomalies");
    expect(params[5]).toBe("MALFORMED_ENVELOPE");
    expect(params[6]).toBeNull();
  });

  it("uses the anomalous relationship kind ahead of a verified parse result", async () => {
    const query = vi.fn(async () => ({ rows: [] }));
    const capture = {
      parseResult: "VERIFIED_HEAD" as const,
      rawResponseBytes: Uint8Array.from([7]),
      isGenesis: false,
      sSignature: "S-old",
      pSignature: "P-old",
      semanticFingerprint: "fp-old",
    };
    const prior = {
      nextWalletSeq: 2,
      consecutiveRepeatCount: 0,
      rowCount: 1,
      anomalyCount: 0,
      lastRecordedSeq: 1,
      lastRecorded: {
        verified: true,
        rawResponseSha256: "00".repeat(32),
        rawResponseOctets: 1,
        rawResponseBytes: Uint8Array.from([1]),
      },
      lastAcceptedState: {
        isGenesis: false,
        sSignature: "S-newer",
        pSignature: "P-before",
        semanticFingerprint: "fp-newer",
      },
      acceptedStateSignatureHistory: ["S-old", "S-newer"],
      priorHistoryHasNonGenesis: true,
    };
    const result = planCapture(prior, capture);
    expect(result.plan.kind === "APPEND" && result.plan.observation.relationship).toBe(
      "REGRESSION",
    );

    await createSqlAnomalyRecorder({ query })({
      key,
      observationId: "22222222-2222-4222-8222-222222222222",
      walletId: null,
      priorObservationId: "44444444-4444-4444-8444-444444444444",
      result,
      capture,
    });

    const params = query.mock.calls[0] as unknown as [string, readonly unknown[]];
    expect(params[1][5]).toBe("REGRESSION");
  });
});
