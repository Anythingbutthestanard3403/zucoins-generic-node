// Prove no ambiguous submit outcome ever becomes authority. Governing:
// protocol foundation (single-shot submit;
// ACK is receipt-only, never settlement); operations recovery axiom 2 ("absence of
// confirmation is not non-landing proof"), (INDETERMINATE: park/attention — no
// retry/rebuild/resubmit/release), (anomalies park for attention); the state-event reference
// (closed operation states; a landed state is reached only via a verified authoritative
// observation); status:true is receipt-only, (no generic PROVEN_NOT_LANDED
// oracle); the never-blind-retry rule (never blind-retry a submit).
//
// Four properties, each proven against the real decision functions and frozen tables:
//   1. An ambiguous submit outcome (timeout / network error / non-2xx-non-4xx) never
//      transitions an operation to a landed ("completed") state.
//   2. Every ambiguous outcome surfaces on the operator-resolution side (NEEDS_ATTENTION /
//      attention reason SUBMIT_OUTCOME_AMBIGUOUS), never a terminal success.
//   3. No automatic retry follows ambiguity — the single shot is the only call, and reconcile
//      never re-authorizes a submit once a submit claim exists (the never-blind-retry rule).
//   4. Ambiguity evidence is recorded for audit: the exact request bytes + digest, the
//      INDETERMINATE outcome, and (when captured) the exact response bytes + digest.
//
// decision-layer half. Sibling suites on this branch close the
// behavioral/DB acceptance criteria the prior PR deferred:
//   - test/submit-ambiguity-authority.durability.test.ts  (D1 kill/resume wire count, D2 race)
// - test/submit-ambiguity-authority.pg.test.ts (D3 CHECK/UNIQUE on real PG)
// Landed siblings that also discharge parts of the same invariants (cited, not re-owned):
//   - test/move-no-second-attempt.gateway-count.test.ts, test/submit-signing-call-audit.test.ts
//   - test/submit-decision-claim-store.pg.test.ts (229), test/crash-injection.test.ts
//
// TEST-ONLY. Frozen state-event tables reached by direct relative source import (the exports
// map lacks the ./operations/states subpath and there is no built dist/).

import { describe, expect, it } from "vitest";

import {
  FORBIDDEN_STATE_ALIASES,
  MOVE_INTERNAL_STATES,
  MOVE_INTERNAL_TRANSITIONS,
  RECEIVE_EXTERNAL_STATES,
  RECEIVE_EXTERNAL_TRANSITIONS,
  SEND_EXTERNAL_STATES,
  SEND_EXTERNAL_TRANSITIONS,
} from "../../generic-node-contracts/src/operations/states.contract.ts";
import { ATTENTION_REASONS } from "../../generic-node-contracts/src/operations/events.contract.ts";
import {
  SUBMIT_ACTION_NAME,
  buildGatewayRequestBody,
} from "../../generic-node-contracts/src/transfer-code/index.ts";

import {
  GatewayTransportAmbiguityError,
  sha256Hex,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
} from "../src/gateway/capture.js";
import { createGatewaySubmitCredentials, fingerprintEndpoint } from "../src/gateway/client.js";
import type {
  GatewaySubmitAttemptRecord,
  SubmitAttemptRecorder,
  SubmitTransportOutcome,
} from "../src/gateway/records.js";
import {
  SubmitIndeterminateError,
  classifySubmitHttpStatus,
  createSingleShotSubmitTransport,
  submitGatewayActionOnce,
  type SubmitAuthorization,
  type SubmitGatewayActionOptions,
} from "../src/gateway/submit.js";
import type { GatewayLimits } from "../src/gateway/types.js";
import type { GatewayRequest } from "../src/protocol/index.js";
import {
  type LandingPathProof,
} from "../src/protocol/reconcile/landing-proof.js";
import {
  mintLandingPathProofFromOracle,
} from "../src/protocol/reconcile/landing-oracle-mint.fixture.js";
import { classifyMoveReconcile, type MoveReconcileInput } from "../src/protocol/reconcile/move.js";
import { type PathObservation } from "../src/protocol/reconcile/observation-input.js";
import {
  classifyReceiveReconcile,
  type ReceiveReconcileInput,
} from "../src/protocol/reconcile/receive.js";
import {
  classifySendReconcile,
  type SendReconcileInput,
} from "../src/protocol/reconcile/send.js";
import {
  captureSubmitAcknowledgement,
  isSettlementAuthority,
  mintSettlementAuthority,
} from "../src/protocol/reconcile/submit-authority.js";
import {
  toAttentionReason,
  type ReconcileIndeterminateReason,
} from "../src/protocol/reconcile/types.js";

const PRIMARY = "https://gateway-a.invalid/";
const SECONDARY = "https://gateway-b.invalid/";
const ATTEMPT = "attempt-1";
const BODY = "move-body-sha256";

const LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 1_024,
  maxResponseBytes: 1_024,
};

const AUTHORIZATION: SubmitAuthorization = {
  submitDecisionId: "11111111-1111-4111-8111-111111111111",
  operationId: "22222222-2222-4222-8222-222222222222",
  transactionAttemptNo: 1,
};

// {"status":true} — the receipt acknowledgement bytes; receipt only, never settlement.
const RESPONSE_BYTES = Uint8Array.from([
  123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 116, 114, 117, 101, 125,
]);

const LANDED_OBS: PathObservation = {
  result: "PROOF",
  proof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "pub",
      expectedBodySha256: BODY,
      freshHeadBodySha256: BODY,
      freshHeadObservationId: "obs",
      depth: 0,
    }),
};

// Observation evidence that is NOT a positive landing: landing-oracle faults, a clean read that
// found no successor, and transport/lineage anomalies. Each models an ambiguous submit aftermath.
const AMBIGUOUS_OBSERVATIONS: readonly PathObservation[] = [
  { result: "PROOF_INCOMPLETE", fault: "GAP" },
  { result: "PROOF_INCOMPLETE", fault: "MISSING_BODY" },
  { result: "PROOF_INCOMPLETE", fault: "BUDGET_EXHAUSTED" },
  { result: "PROOF_INCOMPLETE", fault: "CONFLICT" },
  { result: "NO_SUCCESSOR" },
  { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" },
  { result: "ANOMALY", anomaly: "MALFORMED_ENVELOPE" },
  { result: "ANOMALY", anomaly: "UNEXPLAINED_JUMP" },
];

// Every observation shape the classifiers accept, used to prove the post-submit boundary
// structurally excludes PROVEN_NOT_STARTED regardless of what the chain read returns.
const ALL_OBSERVATIONS: readonly PathObservation[] = [
  LANDED_OBS,
  ...AMBIGUOUS_OBSERVATIONS,
  { result: "ANOMALY", anomaly: "REGRESSION" },
  { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" },
];

interface ScriptedExchange {
  readonly touched: string[];
  readonly requests: GatewayRequest[];
  readonly exchange: GatewayExchangeTransport;
}

function scriptedExchange(
  outcome: { readonly status: number; readonly body: Uint8Array } | Error,
): ScriptedExchange {
  const touched: string[] = [];
  const requests: GatewayRequest[] = [];
  const exchange: GatewayExchangeTransport = {
    exchange: async (endpoint, request) => {
      touched.push(endpoint);
      requests.push(request);
      if (outcome instanceof Error) {
        throw outcome;
      }
      const capture: GatewayExchangeCapture = {
        endpoint,
        endpointFingerprint: fingerprintEndpoint(endpoint),
        requestBytes: request.bodyBytes,
        requestSha256: sha256Hex(request.bodyBytes),
        responseBytes: outcome.body,
        responseSha256: sha256Hex(outcome.body),
        statusCode: outcome.status,
      };
      return capture;
    },
  };
  return { touched, requests, exchange };
}

interface RecordingRecorder {
  readonly records: GatewaySubmitAttemptRecord[];
  readonly recorder: SubmitAttemptRecorder;
}

function recordingRecorder(): RecordingRecorder {
  const records: GatewaySubmitAttemptRecord[] = [];
  return {
    records,
    recorder: {
      recordSubmitAttempt: async (record) => {
        records.push(record);
      },
    },
  };
}

function options(
  exchange: GatewayExchangeTransport,
  recorder: SubmitAttemptRecorder,
): SubmitGatewayActionOptions {
  return {
    endpoint: PRIMARY,
    limits: LIMITS,
    recorder,
    exchange,
    nowIso: (() => {
      let tick = 0;
      return () => {
        tick += 1;
        return `2026-07-21T00:00:0${tick}.000Z`;
      };
    })(),
  };
}

function receivePostSubmit(observation: PathObservation): ReceiveReconcileInput {
  return {
    boundary: "POST_SUBMIT",
    receiveAttemptId: ATTEMPT,
    receiverWalletId: "wallet-receiver",
    receiverLeaseState: "ACTIVE",
    receiverObservation: observation,
  };
}

function movePostSubmit(
  sourceObservation: PathObservation,
  destinationObservation: PathObservation,
): MoveReconcileInput {
  return {
    boundary: "POST_SUBMIT",
    moveAttemptId: ATTEMPT,
    sourceWalletId: "wallet-source",
    destinationWalletId: "wallet-destination",
    expectedMoveBodySha256: BODY,
    sourceLeaseState: "ACTIVE",
    destinationLeaseState: "ACTIVE",
    sourceObservation,
    destinationObservation,
  };
}

function sendDelivered(observation: PathObservation): SendReconcileInput {
  return {
    boundary: "DELIVERED",
    sendAttemptId: ATTEMPT,
    sourceWalletId: "wallet-source",
    sourceLeaseState: "ACTIVE",
    transferCodeSha256: "transfer-code-sha256",
    sourceObservation: observation,
  };
}

describe("property 1 — an ambiguous submit never transitions an operation to a landed state", () => {
  it("a transport ambiguity (timeout / reset) is classified INDETERMINATE, never ACK", async () => {
    const ambiguity = new GatewayTransportAmbiguityError("scripted", new Error("connect ETIMEDOUT"));
    const scripted = scriptedExchange(ambiguity);
    const recording = recordingRecorder();
    const result = await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      { transaction: "t" },
      AUTHORIZATION,
      options(scripted.exchange, recording.recorder),
    );
    expect(result.transportOutcome).toBe("INDETERMINATE");
    expect(result.transportOutcome).not.toBe("ACK");
    expect(result.capture).toBeNull();
  });

  it.each([100, 301, 302, 500, 502, 503, 599])(
    "a non-2xx/4xx status %i is INDETERMINATE, never ACK authority",
    (status) => {
      expect(classifySubmitHttpStatus(status)).toBe("INDETERMINATE");
      expect(classifySubmitHttpStatus(status)).not.toBe("ACK");
    },
  );

  it("RECEIVE_EXTERNAL: ambiguous post-submit evidence never yields LANDED_VERIFIED", () => {
    for (const observation of AMBIGUOUS_OBSERVATIONS) {
      const outcome = classifyReceiveReconcile(receivePostSubmit(observation));
      expect(outcome.kind).not.toBe("LANDED_VERIFIED");
    }
  });

  it("MOVE_INTERNAL: ambiguous post-submit evidence never yields LANDED_VERIFIED", () => {
    for (const observation of AMBIGUOUS_OBSERVATIONS) {
      // One leg ambiguous against a landed leg (disagreement), and both legs ambiguous.
      expect(classifyMoveReconcile(movePostSubmit(observation, LANDED_OBS)).kind).not.toBe(
        "LANDED_VERIFIED",
      );
      expect(classifyMoveReconcile(movePostSubmit(observation, observation)).kind).not.toBe(
        "LANDED_VERIFIED",
      );
    }
  });

  it("SEND_EXTERNAL: ambiguous delivered-partial evidence never yields LANDED_VERIFIED", () => {
    for (const observation of AMBIGUOUS_OBSERVATIONS) {
      const outcome = classifySendReconcile(sendDelivered(observation));
      expect(outcome.kind).not.toBe("LANDED_VERIFIED");
    }
  });

  it("a submit acknowledgement — even status:true — is never settlement authority", () => {
    const ack = captureSubmitAcknowledgement(ATTEMPT, true, "ok", "2026-07-21T00:00:00.000Z");
    expect(isSettlementAuthority(ack)).toBe(false);
    // Settlement authority is constructible only from a landing path proof, never an ACK.
    const proof: LandingPathProof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "pub",
      expectedBodySha256: BODY,
      freshHeadBodySha256: BODY,
      freshHeadObservationId: "obs",
      depth: 0,
    });
    expect(isSettlementAuthority(mintSettlementAuthority(ATTEMPT, proof))).toBe(true);
  });

  it("the frozen state-event tables reach a landed state only via a verified authoritative guard", () => {
    const tables = [
      { kind: "RECEIVE_EXTERNAL", landed: "RECEIVE_LANDED", table: RECEIVE_EXTERNAL_TRANSITIONS },
      { kind: "MOVE_INTERNAL", landed: "INTERNAL_MOVE_LANDED", table: MOVE_INTERNAL_TRANSITIONS },
      { kind: "SEND_EXTERNAL", landed: "EXTERNAL_SEND_LANDED", table: SEND_EXTERNAL_TRANSITIONS },
    ] as const;
    for (const { kind, landed, table } of tables) {
      const landedTransitions = table.filter((row) => row.to === landed);
      // Non-vacuous: each operation kind reaches its landed state by at least one transition.
      expect(landedTransitions.length, `${kind} reaches ${landed}`).toBeGreaterThan(0);
      // Universal: every path into the landed state requires a verified/authoritative observation
      // and never an ambiguous, indeterminate, or timeout-shaped guard.
      for (const row of landedTransitions) {
        const guard = row.guard.toLowerCase();
        expect(guard, `${kind} ${String(row.from)} -> ${landed}`).toMatch(/verif|authoritative/);
        expect(guard, `${kind} ${String(row.from)} -> ${landed}`).not.toMatch(
          /ambigu|indeterminate|timeout/,
        );
      }
    }
  });
});

describe("property 2 — an ambiguous outcome always surfaces for operator resolution", () => {
  it("the ambiguous-submit reconcile reason maps to the SUBMIT_OUTCOME_AMBIGUOUS attention reason", () => {
    const reason: ReconcileIndeterminateReason = { source: "SUBMIT_OUTCOME_UNKNOWN" };
    expect(toAttentionReason(reason)).toBe("SUBMIT_OUTCOME_AMBIGUOUS");
  });

  it("SUBMIT_OUTCOME_AMBIGUOUS is a member of the closed operator-attention vocabulary", () => {
    expect(ATTENTION_REASONS).toContain("SUBMIT_OUTCOME_AMBIGUOUS");
  });

  it("every indeterminate reconcile reason maps onto the operator-attention vocabulary", () => {
    const reasons: readonly ReconcileIndeterminateReason[] = [
      { source: "SUBMIT_OUTCOME_UNKNOWN" },
      { source: "PATH_DISAGREEMENT" },
      { source: "NO_SUCCESSOR_OBSERVED" },
      { source: "PROOF_INTAKE_REJECTED" },
      { source: "RELEASE_PREDICATE_UNSATISFIED", predicate: "T0" },
      { source: "LANDING_PROOF_INCOMPLETE", fault: "GAP" },
      { source: "OBSERVATION_ANOMALY", anomaly: "TRANSPORT_ERROR" },
    ];
    for (const reason of reasons) {
      expect(ATTENTION_REASONS).toContain(toAttentionReason(reason));
    }
  });

  it("the operator-attention surface is disjoint from every landed (completed) state", () => {
    const landedStates = ["RECEIVE_LANDED", "INTERNAL_MOVE_LANDED", "EXTERNAL_SEND_LANDED"];
    for (const landed of landedStates) {
      expect(ATTENTION_REASONS).not.toContain(landed);
    }
    for (const reason of ATTENTION_REASONS) {
      expect(landedStates).not.toContain(reason);
    }
  });

  it("ambiguous evidence parks rather than completing, with exact kinds per observation shape", () => {
    // Deterministic shapes: PROOF_INCOMPLETE / TRANSPORT_ERROR / MALFORMED → INDETERMINATE;
    // NO_SUCCESSOR on send → WAITING (still awaiting recipient); UNEXPLAINED_JUMP may breach.
    for (const observation of AMBIGUOUS_OBSERVATIONS) {
      const receive = classifyReceiveReconcile(receivePostSubmit(observation));
      const move = classifyMoveReconcile(movePostSubmit(observation, observation));
      const send = classifySendReconcile(sendDelivered(observation));

      // Never a landing — the headline invariant.
      expect(receive.kind).not.toBe("LANDED_VERIFIED");
      expect(move.kind).not.toBe("LANDED_VERIFIED");
      expect(send.kind).not.toBe("LANDED_VERIFIED");

      if (observation.result === "PROOF_INCOMPLETE") {
        expect(receive.kind).toBe("INDETERMINATE");
        expect(move.kind).toBe("INDETERMINATE");
      } else if (observation.result === "NO_SUCCESSOR") {
        // Receive/move with no successor after submit is indeterminate; send waits for recipient.
        expect(receive.kind).toBe("INDETERMINATE");
        expect(move.kind).toBe("INDETERMINATE");
        expect(send.kind).toBe("WAITING");
      } else if (observation.result === "ANOMALY" && observation.anomaly === "UNEXPLAINED_JUMP") {
        // Unexplained jump under lease is the invariant/custody breach class.
        expect(["INDETERMINATE", "INVARIANT_BREACH"]).toContain(receive.kind);
        expect(["INDETERMINATE", "INVARIANT_BREACH"]).toContain(move.kind);
      } else {
        expect(receive.kind).toBe("INDETERMINATE");
        expect(move.kind).toBe("INDETERMINATE");
        expect(send.kind).toBe("INDETERMINATE");
      }
    }
  });
});

describe("property 3 — no automatic retry after ambiguity (the never-blind-retry rule)", () => {
  it("the single shot makes exactly one exchange on the ambiguity branch — no loop, no failover", async () => {
    const ambiguity = new GatewayTransportAmbiguityError("scripted", new Error("socket hang up"));
    const scripted = scriptedExchange(ambiguity);
    const recording = recordingRecorder();
    const transport = createSingleShotSubmitTransport({
      credentials: createGatewaySubmitCredentials(),
      limits: LIMITS,
      recorder: recording.recorder,
      authorization: AUTHORIZATION,
      exchange: scripted.exchange,
    });
    const request: GatewayRequest = { rpc: SUBMIT_ACTION_NAME, bodyBytes: Uint8Array.from([1]) };
    // The adapter converts ambiguity into SubmitIndeterminateError — never a response a caller
    // could trust, and never a second call against the secondary endpoint.
    await expect(transport.submit([PRIMARY, SECONDARY], request)).rejects.toBeInstanceOf(
      SubmitIndeterminateError,
    );
    expect(scripted.touched).toEqual([PRIMARY]);
    expect(recording.records.length).toBe(1);
  });

  it("once a submit claim exists, RECEIVE reconcile never returns PROVEN_NOT_STARTED (the only kind that authorizes a submit)", () => {
    for (const observation of ALL_OBSERVATIONS) {
      expect(classifyReceiveReconcile(receivePostSubmit(observation)).kind).not.toBe(
        "PROVEN_NOT_STARTED",
      );
    }
  });

  it("once a submit claim exists, MOVE reconcile never returns PROVEN_NOT_STARTED for any observation pairing", () => {
    for (const source of ALL_OBSERVATIONS) {
      for (const destination of ALL_OBSERVATIONS) {
        expect(classifyMoveReconcile(movePostSubmit(source, destination)).kind).not.toBe(
          "PROVEN_NOT_STARTED",
        );
      }
    }
  });

  it("once a partial is delivered, SEND reconcile never returns PROVEN_NOT_STARTED", () => {
    for (const observation of ALL_OBSERVATIONS) {
      expect(classifySendReconcile(sendDelivered(observation)).kind).not.toBe("PROVEN_NOT_STARTED");
    }
  });

  it("no post-submit outcome carries a resume action — SUBMIT_ONCE is reachable only before the boundary is crossed", () => {
    // PROVEN_NOT_STARTED is the sole outcome kind that carries a resumeAction (FIRST_FORMATION /
    // SIGN_PERSISTED_PREIMAGE / SUBMIT_ONCE). Excluding it from every post-submit classification
    // proves no reconcile of an ambiguous (or any) post-submit state re-authorizes a submit.
    const resumeCarrying = ["PROVEN_NOT_STARTED"];
    for (const observation of ALL_OBSERVATIONS) {
      expect(resumeCarrying).not.toContain(classifyReceiveReconcile(receivePostSubmit(observation)).kind);
      expect(resumeCarrying).not.toContain(classifySendReconcile(sendDelivered(observation)).kind);
      expect(resumeCarrying).not.toContain(
        classifyMoveReconcile(movePostSubmit(observation, observation)).kind,
      );
    }
  });
});

describe("property 4 — ambiguity evidence is recorded for audit", () => {
  it("a transport ambiguity records the exact request bytes + digest, INDETERMINATE, null response, and timestamps", async () => {
    const ambiguity = new GatewayTransportAmbiguityError("scripted", new Error("connect ETIMEDOUT"));
    const scripted = scriptedExchange(ambiguity);
    const recording = recordingRecorder();
    await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      { transaction: "t" },
      AUTHORIZATION,
      options(scripted.exchange, recording.recorder),
    );
    expect(recording.records.length).toBe(1);
    const record = recording.records[0];
    const expectedRequestBytes = new TextEncoder().encode(
      buildGatewayRequestBody(SUBMIT_ACTION_NAME, { transaction: "t" }),
    );
    expect(record?.requestBytes).toEqual(expectedRequestBytes);
    expect(record?.requestSha256).toBe(sha256Hex(expectedRequestBytes));
    expect(record?.requestSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(record?.transportOutcome).toBe("INDETERMINATE");
    // No complete response was captured: bytes and digest are absent together (the data model biconditional).
    expect(record?.responseBytes).toBeNull();
    expect(record?.responseSha256).toBeNull();
    expect(record?.decisionId).toBe(AUTHORIZATION.submitDecisionId);
    expect(record?.operationId).toBe(AUTHORIZATION.operationId);
    expect(record?.attemptNo).toBe(1);
    expect(record?.transactionAttemptNo).toBe(1);
    expect(record?.startedAt).toBe("2026-07-21T00:00:01.000Z");
    expect(record?.completedAt).toBe("2026-07-21T00:00:02.000Z");
  });

  it("a non-2xx/4xx ambiguity records the exact response bytes + digest alongside the request", async () => {
    const scripted = scriptedExchange({ status: 503, body: RESPONSE_BYTES });
    const recording = recordingRecorder();
    await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      {},
      AUTHORIZATION,
      options(scripted.exchange, recording.recorder),
    );
    const record = recording.records[0];
    expect(record?.transportOutcome).toBe("INDETERMINATE");
    expect(record?.responseBytes).toEqual(RESPONSE_BYTES);
    expect(record?.responseSha256).toBe(sha256Hex(RESPONSE_BYTES));
    expect(record?.requestSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("the recorded transport outcome is always drawn from the closed three-member set", async () => {
    const closedSet: readonly SubmitTransportOutcome[] = ["ACK", "REJECT", "INDETERMINATE"];
    const ambiguity = new GatewayTransportAmbiguityError("scripted", new Error("reset"));
    const scripted = scriptedExchange(ambiguity);
    const recording = recordingRecorder();
    await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      {},
      AUTHORIZATION,
      options(scripted.exchange, recording.recorder),
    );
    for (const record of recording.records) {
      expect(closedSet).toContain(record.transportOutcome);
    }
  });
});

describe("end-to-end — an ambiguous submit never becomes authority", () => {
  it("timeout -> INDETERMINATE attempt recorded -> reconcile parks (no landing) -> operator attention, no retry", async () => {
    // 1. Gateway: an ambiguous exchange yields INDETERMINATE, exactly one exchange, one audit row.
    const ambiguity = new GatewayTransportAmbiguityError("scripted", new Error("connect ETIMEDOUT"));
    const scripted = scriptedExchange(ambiguity);
    const recording = recordingRecorder();
    const result = await submitGatewayActionOnce(
      SUBMIT_ACTION_NAME,
      { transaction: "t" },
      AUTHORIZATION,
      options(scripted.exchange, recording.recorder),
    );
    expect(result.transportOutcome).toBe("INDETERMINATE");
    expect(scripted.touched).toEqual([PRIMARY]);
    expect(recording.records.length).toBe(1);

    // 2. The recorded outcome is INDETERMINATE — never an ACK a caller could treat as authority.
    expect(recording.records[0]?.transportOutcome).toBe("INDETERMINATE");

    // 3. A submit acknowledgement captured from any gateway response is never settlement authority.
    const ack = captureSubmitAcknowledgement(ATTEMPT, true, "ok", "2026-07-21T00:00:00.000Z");
    expect(isSettlementAuthority(ack)).toBe(false);

    // 4. Reconciling the ambiguous aftermath never lands the operation, for any operation kind.
    const ambiguous: PathObservation = { result: "PROOF_INCOMPLETE", fault: "GAP" };
    expect(classifyReceiveReconcile(receivePostSubmit(ambiguous)).kind).not.toBe("LANDED_VERIFIED");
    expect(classifyMoveReconcile(movePostSubmit(ambiguous, ambiguous)).kind).not.toBe("LANDED_VERIFIED");
    expect(classifySendReconcile(sendDelivered(ambiguous)).kind).not.toBe("LANDED_VERIFIED");

    // 5. The ambiguous-submit reason surfaces as operator attention, and no retry is authorized.
    expect(toAttentionReason({ source: "SUBMIT_OUTCOME_UNKNOWN" })).toBe("SUBMIT_OUTCOME_AMBIGUOUS");
    expect(classifyReceiveReconcile(receivePostSubmit(ambiguous)).kind).not.toBe("PROVEN_NOT_STARTED");
  });
});

describe("vocabulary discipline — completion is 'landed', never a forbidden settlement alias", () => {
  it("the landed states are real operation states and none is a forbidden completion alias", () => {
    const allStates = [
      ...RECEIVE_EXTERNAL_STATES,
      ...MOVE_INTERNAL_STATES,
      ...SEND_EXTERNAL_STATES,
    ];
    const landedStates = ["RECEIVE_LANDED", "INTERNAL_MOVE_LANDED", "EXTERNAL_SEND_LANDED"];
    for (const landed of landedStates) {
      expect(allStates).toContain(landed);
      expect(FORBIDDEN_STATE_ALIASES).not.toContain(landed);
    }
  });

  it("forbidden settlement aliases (settled/confirmed/finalised/paid) are never operation states", () => {
    const allStates = [
      ...RECEIVE_EXTERNAL_STATES,
      ...MOVE_INTERNAL_STATES,
      ...SEND_EXTERNAL_STATES,
    ];
    for (const alias of FORBIDDEN_STATE_ALIASES) {
      expect(allStates).not.toContain(alias);
    }
  });
});
