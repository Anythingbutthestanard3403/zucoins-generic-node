import { describe, expect, it } from "vitest";

import { createInMemoryChangedResponseLedger } from "./changed-response-ledger.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

describe("changed-response ledger — consecutive-only dedup", () => {
  it("A,A records one (consecutive verified suppress)", () => {
    const ledger = createInMemoryChangedResponseLedger();
    const a = enc("A");
    const r1 = ledger.append({ rawResponseBytes: a, verified: true, observedAtUnixMs: 1 });
    const r2 = ledger.append({ rawResponseBytes: a, verified: true, observedAtUnixMs: 2 });
    expect(r1.outcome).toBe("APPEND");
    expect(r2.outcome).toBe("SUPPRESS_AS_SIGHTING");
    if (r2.outcome === "SUPPRESS_AS_SIGHTING") {
      expect(r2.consecutiveRepeatCount).toBe(1);
    }
    expect(ledger.records).toHaveLength(1);
    expect(ledger.records[0]!.regression).toBe(false);
  });

  it("A,B,C,A records four with final A retained and flagged as regression", () => {
    const ledger = createInMemoryChangedResponseLedger();
    const A = enc("A");
    const B = enc("B");
    const C = enc("C");
    expect(ledger.append({ rawResponseBytes: A, verified: true, observedAtUnixMs: 1 }).outcome).toBe(
      "APPEND",
    );
    expect(ledger.append({ rawResponseBytes: B, verified: true, observedAtUnixMs: 2 }).outcome).toBe(
      "APPEND",
    );
    expect(ledger.append({ rawResponseBytes: C, verified: true, observedAtUnixMs: 3 }).outcome).toBe(
      "APPEND",
    );
    const last = ledger.append({ rawResponseBytes: A, verified: true, observedAtUnixMs: 4 });
    expect(last.outcome).toBe("APPEND");
    expect(ledger.records).toHaveLength(4);
    expect(ledger.records.map((r) => r.seq)).toEqual([1, 2, 3, 4]);
    expect(ledger.records[3]!.regression).toBe(true);
    expect(ledger.records[0]!.regression).toBe(false);
  });

  it("anomalies always append even on repeated bytes", () => {
    const ledger = createInMemoryChangedResponseLedger();
    const x = enc("X");
    const r1 = ledger.append({
      rawResponseBytes: x,
      verified: false,
      observedAtUnixMs: 1,
      anomalyKind: "MALFORMED_ENVELOPE",
    });
    const r2 = ledger.append({
      rawResponseBytes: x,
      verified: false,
      observedAtUnixMs: 2,
      anomalyKind: "MALFORMED_ENVELOPE",
    });
    expect(r1.outcome).toBe("APPEND");
    expect(r2.outcome).toBe("APPEND");
    expect(ledger.records).toHaveLength(2);
    expect(ledger.records.every((r) => r.kind === "ANOMALY")).toBe(true);
  });
});
