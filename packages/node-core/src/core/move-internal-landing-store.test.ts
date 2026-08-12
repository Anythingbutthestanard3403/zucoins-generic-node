// D2 — the MOVE_INTERNAL landing writes operations.verification_material_available_until.
//
// `verification_material_available_until` is written at the landed terminal as
// terminal_at + window; step 5 sets the proof-access expiry, the default window is 30 days,
// and the 409/200/410 material gate reads the column.
//
// No database: the statement's bound parameters are the observable. The real-Postgres proof
// that the value lands in the column is test/move-internal-landing-store.pg.test.ts, which
// skips without TEST_DATABASE_URL — so the derivation itself is pinned here, where a
// regression reddens with no database at all.
import { randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import { persistMoveOutcome, type SignedNodeEvent } from "./move-internal-landing-store.js";
import { DEFAULT_PROOF_ACCESS_WINDOW_MS } from "../data/retention.js";
import {
  mintLandingPathProofFromOracle,
} from "../protocol/reconcile/landing-oracle-mint.fixture.js";
import type { MoveReconcileOutcome } from "../protocol/reconcile/move.js";

// $5 is the verification_material_available_until parameter; $2 is the next status.
const PROOF_EXPIRY_PARAM = 4;
const STATUS_PARAM = 1;

const OCCURRED_AT = "2026-07-25T01:00:00.000Z";
const PUBKEY = `${"A".repeat(43)}=`;
const SHA = "a".repeat(64);
const SIGNATURE = `${"B".repeat(86)}==`;

const OPERATION_ID = randomUUID();
const SOURCE_TERMINAL = randomUUID();
const DESTINATION_TERMINAL = randomUUID();

const LANDED_VERDICT: MoveReconcileOutcome = {
  kind: "LANDED_VERIFIED",
  moveAttemptId: OPERATION_ID,
  sourcePath: mintLandingPathProofFromOracle({
    walletPubkeyBase64Urlsafe: PUBKEY,
    expectedBodySha256: SHA,
    freshHeadBodySha256: SHA,
    freshHeadObservationId: SOURCE_TERMINAL,
    depth: 0,
  }),
  destinationPath: mintLandingPathProofFromOracle({
    walletPubkeyBase64Urlsafe: PUBKEY,
    expectedBodySha256: SHA,
    freshHeadBodySha256: SHA,
    freshHeadObservationId: DESTINATION_TERMINAL,
    depth: 0,
  }),
};

const INDETERMINATE_VERDICT: MoveReconcileOutcome = {
  kind: "INDETERMINATE",
  moveAttemptId: OPERATION_ID,
  reason: { source: "SUBMIT_OUTCOME_UNKNOWN" },
};

const signedEvent = (eventType: SignedNodeEvent["eventType"]): SignedNodeEvent => ({
  seq: "1",
  eventId: randomUUID(),
  nodeId: randomUUID(),
  walletId: null,
  eventType,
  dataText: "{}",
  dataSha256: SHA,
  preimageText: "{}",
  preimageSha256: SHA,
  signingKeyId: randomUUID(),
  signature: SIGNATURE,
  previousEventHash: null,
  eventHash: SHA,
});

// Captures the bound parameters and answers as a matched CAS, so persistMoveOutcome runs to
// completion without a driver.
function capturingQuery(): {
  readonly values: unknown[][];
  readonly query: (text: string, values: readonly unknown[]) => Promise<readonly Record<string, unknown>[]>;
} {
  const values: unknown[][] = [];
  return {
    values,
    query: async (_text, bound) => {
      values.push([...bound]);
      return [{ status: "INTERNAL_MOVE_LANDED", row_version: 2 }];
    },
  };
}

describe("persistMoveOutcome proof-access expiry (step 5)", () => {
  it("derives terminal_at + the 30-day window when the caller supplies no expiry", async () => {
    const capture = capturingQuery();

    await persistMoveOutcome(capture.query, {
      operationId: OPERATION_ID,
      expectedState: "CREATED",
      expectedRowVersion: 1,
      outcome: LANDED_VERDICT,
      event: signedEvent("internal_move.landed"),
      occurredAt: OCCURRED_AT,
    });

    const bound = capture.values[0]!;
    expect(bound[STATUS_PARAM]).toBe("INTERNAL_MOVE_LANDED");
    // The landing must never commit with the column null: decideProofAccess reads a landed
    // operation with a null window as NOT_READY, so the endpoint would answer 409 forever.
    expect(bound[PROOF_EXPIRY_PARAM]).not.toBeNull();
    expect(bound[PROOF_EXPIRY_PARAM]).toBe(
      new Date(Date.parse(OCCURRED_AT) + DEFAULT_PROOF_ACCESS_WINDOW_MS).toISOString(),
    );
    expect(bound[PROOF_EXPIRY_PARAM]).toBe("2026-08-24T01:00:00.000Z");
  });

  it("honours an explicit expiry and an injected window", async () => {
    const explicit = capturingQuery();
    await persistMoveOutcome(explicit.query, {
      operationId: OPERATION_ID,
      expectedState: "CREATED",
      expectedRowVersion: 1,
      outcome: LANDED_VERDICT,
      event: signedEvent("internal_move.landed"),
      occurredAt: OCCURRED_AT,
      verificationMaterialAvailableUntil: "2026-09-01T00:00:00.000Z",
    });
    expect(explicit.values[0]![PROOF_EXPIRY_PARAM]).toBe("2026-09-01T00:00:00.000Z");

    const windowed = capturingQuery();
    await persistMoveOutcome(windowed.query, {
      operationId: OPERATION_ID,
      expectedState: "CREATED",
      expectedRowVersion: 1,
      outcome: LANDED_VERDICT,
      event: signedEvent("internal_move.landed"),
      occurredAt: OCCURRED_AT,
      proofAccessWindowMs: 24 * 60 * 60 * 1000,
    });
    expect(windowed.values[0]![PROOF_EXPIRY_PARAM]).toBe("2026-07-26T01:00:00.000Z");
  });

  it("derives nothing on the attention branch — no terminal, no window", async () => {
    const capture = capturingQuery();

    await persistMoveOutcome(capture.query, {
      operationId: OPERATION_ID,
      expectedState: "CREATED",
      expectedRowVersion: 1,
      outcome: INDETERMINATE_VERDICT,
      event: signedEvent("operation.needs_attention"),
      occurredAt: OCCURRED_AT,
    });

    const bound = capture.values[0]!;
    expect(bound[STATUS_PARAM]).toBe("NEEDS_ATTENTION");
    // coalesce($5, verification_material_available_until) with a null $5 leaves the stored
    // value untouched, which is what a parked (non-terminal) move must do.
    expect(bound[PROOF_EXPIRY_PARAM]).toBeNull();
  });

  it("fails closed on an unparsable occurredAt rather than writing a null window", async () => {
    const capture = capturingQuery();

    await expect(
      persistMoveOutcome(capture.query, {
        operationId: OPERATION_ID,
        expectedState: "CREATED",
        expectedRowVersion: 1,
        outcome: LANDED_VERDICT,
        event: signedEvent("internal_move.landed"),
        occurredAt: "not-an-instant",
      }),
    ).rejects.toThrow(RangeError);
    expect(capture.values).toEqual([]);
  });

  it("LANDED_VERIFIED binds null attention_reason so stale LINEAGE_GAP clears (ZTR-1245)", async () => {
    const capture = capturingQuery();
    await persistMoveOutcome(capture.query, {
      operationId: OPERATION_ID,
      expectedState: "CREATED",
      expectedRowVersion: 1,
      outcome: LANDED_VERDICT,
      event: signedEvent("internal_move.landed"),
      occurredAt: OCCURRED_AT,
    });
    // $3 = attention_reason
    expect(capture.values[0]![2]).toBeNull();
  });

  it("refuses LANDED_VERIFIED with structural impostor path proofs", async () => {
    const capture = capturingQuery();
    const impostor = {
      kind: "LANDED_EXACT",
      walletPubkeyBase64Urlsafe: PUBKEY,
      expectedBodySha256: SHA,
      freshHeadBodySha256: SHA,
      freshHeadObservationId: SOURCE_TERMINAL,
      depth: 0,
    } as (typeof LANDED_VERDICT)["sourcePath"];
    const forged: MoveReconcileOutcome = {
      kind: "LANDED_VERIFIED",
      moveAttemptId: OPERATION_ID,
      sourcePath: impostor,
      destinationPath: impostor,
    };
    await expect(
      persistMoveOutcome(capture.query, {
        operationId: OPERATION_ID,
        expectedState: "CREATED",
        expectedRowVersion: 1,
        outcome: forged,
        event: signedEvent("internal_move.landed"),
        occurredAt: OCCURRED_AT,
      }),
    ).rejects.toThrow(/issued landing-path oracle capabilities/);
    expect(capture.values).toEqual([]);
  });
});
