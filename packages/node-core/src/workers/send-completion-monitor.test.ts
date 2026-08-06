import { describe, expect, it, vi } from "vitest";

import {
  mintLandingPathProofFromOracle,
} from "../protocol/reconcile/landing-oracle-mint.fixture.js";
import { type PathObservation } from "../protocol/reconcile/observation-input.js";
import {
  classifySendCompletionPoll,
  createObservationServicePollFn,
  isOperationBoundCandidateMatch,
  isSyntacticallyValidStep2Signature,
  monitorSendCompletion,
  DEFAULT_COMPLETION_MONITOR_CONFIG,
  type CandidateCompletedTx,
  type CompletionEvidenceRecorder,
  type MonitoredSendDescriptor,
  type ObservationWireCapture,
  type SendCompletionEvidence,
  type SendCompletionPollInput,
  type SourcePathObservationService,
} from "./send-completion-monitor.js";

// Syntactically valid padded Ed25519 signature form (86 base64url + ==).
const VALID_STEP2 =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
const VALID_STEP1 =
  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==";

const SOURCE_PUBKEY = "source-wallet-pubkey";
const BODY_SHA = "body-sha-256-of-this-send";
const INNER_SHA = "inner-sha-256-of-this-send";
const CODE_SHA = "code-sha-256-of-this-send";

const DESCRIPTOR: MonitoredSendDescriptor = {
  sendAttemptId: "send-attempt-1",
  sourceWalletId: "wallet-source",
  sourceWalletPubkeyBase64Urlsafe: SOURCE_PUBKEY,
  expectedBodySha256: BODY_SHA,
  transferCodeSha256: CODE_SHA,
  innerSha256: INNER_SHA,
  step1Signature: VALID_STEP1,
};

const MATCHING_CANDIDATE: CandidateCompletedTx = {
  innerSha256: INNER_SHA,
  step1Signature: VALID_STEP1,
  step2Signature: VALID_STEP2,
  transferCodeSha256: CODE_SHA,
};

const MATCHING_PROOF = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE_PUBKEY,
      expectedBodySha256: BODY_SHA,
      freshHeadBodySha256: BODY_SHA,
      freshHeadObservationId: "obs-1",
      depth: 0,
    });

const LANDED_MATCHING_OBS: PathObservation = {
  result: "PROOF",
  proof: MATCHING_PROOF,
};

// Phantom-settle fixture: landed proof for SOMEONE ELSE'S body + wallet.
const PHANTOM_OBS: PathObservation = {
  result: "PROOF",
  proof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "SOMEONE-ELSES-WALLET-PUBKEY",
      expectedBodySha256: "TOTALLY-UNRELATED-BODY-HASH",
      freshHeadBodySha256: "TOTALLY-UNRELATED-BODY-HASH",
      freshHeadObservationId: "obs-99",
      depth: 0,
    }),
};

const NO_SUCCESSOR_OBS: PathObservation = { result: "NO_SUCCESSOR" };
const PROOF_INCOMPLETE_OBS: PathObservation = {
  result: "PROOF_INCOMPLETE",
  fault: "MISSING_BODY",
};
const ANOMALY_OBS: PathObservation = { result: "ANOMALY", anomaly: "SIGNATURE_COLLISION" };
const TRANSPORT_ANOMALY_OBS: PathObservation = {
  result: "ANOMALY",
  anomaly: "TRANSPORT_ERROR",
};
const UNATTRIBUTED_OBS: PathObservation = { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" };

const FAKE_CAPTURE: ObservationWireCapture = {
  responseSha256: "resp-sha-abc",
};

function makePollInput(
  observation: PathObservation,
  overrides: Partial<SendCompletionPollInput> = {},
): SendCompletionPollInput {
  return {
    descriptor: DESCRIPTOR,
    observation,
    observedAt: "2026-01-01T00:00:00.000Z",
    candidate: observation.result === "PROOF" ? MATCHING_CANDIDATE : null,
    capture: null,
    ...overrides,
  };
}

function makeRecorder(): CompletionEvidenceRecorder & { records: SendCompletionEvidence[] } {
  const records: SendCompletionEvidence[] = [];
  return {
    records,
    async recordCompletionEvidence(evidence: SendCompletionEvidence) {
      records.push(evidence);
    },
  };
}

describe("isSyntacticallyValidStep2Signature", () => {
  it("accepts a padded base64url Ed25519 signature form", () => {
    expect(isSyntacticallyValidStep2Signature(VALID_STEP2)).toBe(true);
  });

  it("rejects empty, short, or unpadded forms", () => {
    expect(isSyntacticallyValidStep2Signature("")).toBe(false);
    expect(isSyntacticallyValidStep2Signature("not-a-sig")).toBe(false);
    expect(isSyntacticallyValidStep2Signature(VALID_STEP2.slice(0, -2))).toBe(false);
  });
});

describe("isOperationBoundCandidateMatch — operation-identity binding", () => {
  it("accepts a proof + candidate that both bind to the descriptor", () => {
    expect(
      isOperationBoundCandidateMatch(DESCRIPTOR, MATCHING_PROOF, MATCHING_CANDIDATE),
    ).toBe(true);
  });

  it("refuses a proof for an unrelated body hash (phantom settle)", () => {
    expect(
      isOperationBoundCandidateMatch(
        DESCRIPTOR,
        mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE_PUBKEY,
      expectedBodySha256: "OTHER-BODY",
      freshHeadBodySha256: "OTHER-BODY",
      freshHeadObservationId: "obs",
      depth: 0,
    }),
        MATCHING_CANDIDATE,
      ),
    ).toBe(false);
  });

  it("refuses a proof for a different source wallet pubkey", () => {
    expect(
      isOperationBoundCandidateMatch(
        DESCRIPTOR,
        mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "other-wallet",
      expectedBodySha256: BODY_SHA,
      freshHeadBodySha256: BODY_SHA,
      freshHeadObservationId: "obs",
      depth: 0,
    }),
        MATCHING_CANDIDATE,
      ),
    ).toBe(false);
  });

  it("refuses when candidate inner_sha256 does not match the partial", () => {
    expect(
      isOperationBoundCandidateMatch(DESCRIPTOR, MATCHING_PROOF, {
        ...MATCHING_CANDIDATE,
        innerSha256: "wrong-inner",
      }),
    ).toBe(false);
  });

  it("refuses when candidate step_1_signature does not match the partial", () => {
    expect(
      isOperationBoundCandidateMatch(DESCRIPTOR, MATCHING_PROOF, {
        ...MATCHING_CANDIDATE,
        step1Signature: VALID_STEP2, // well-formed but not our step-1
      }),
    ).toBe(false);
  });

  it("refuses when step_2_signature is not syntactically valid", () => {
    expect(
      isOperationBoundCandidateMatch(DESCRIPTOR, MATCHING_PROOF, {
        ...MATCHING_CANDIDATE,
        step2Signature: "nope",
      }),
    ).toBe(false);
  });

  it("refuses a null candidate even when the proof body/wallet match", () => {
    expect(isOperationBoundCandidateMatch(DESCRIPTOR, MATCHING_PROOF, null)).toBe(false);
  });

  it("refuses when candidate transferCodeSha256 mismatches the descriptor", () => {
    expect(
      isOperationBoundCandidateMatch(DESCRIPTOR, MATCHING_PROOF, {
        ...MATCHING_CANDIDATE,
        transferCodeSha256: "wrong-code",
      }),
    ).toBe(false);
  });
});

describe("classifySendCompletionPoll", () => {
  it("returns CANDIDATE_MATCH only when proof + candidate bind to this operation", () => {
    const result = classifySendCompletionPoll(makePollInput(LANDED_MATCHING_OBS));
    expect(result).not.toBeNull();
    if (result === null) throw new Error("expected non-null");
    expect(result.kind).toBe("CANDIDATE_MATCH");
    if (result.kind === "CANDIDATE_MATCH") {
      expect(result.sendAttemptId).toBe("send-attempt-1");
      expect(result.proof.expectedBodySha256).toBe(BODY_SHA);
      expect(result.proof.walletPubkeyBase64Urlsafe).toBe(SOURCE_PUBKEY);
      expect(result.candidate.innerSha256).toBe(INNER_SHA);
      expect(result.matchedAt).toBe("2026-01-01T00:00:00.000Z");
    }
  });

  it("NEGATIVE: refuses COMPLETED/CANDIDATE_MATCH for an unrelated body (phantom settle)", () => {
    // QA D1 probe — proof for SOMEONE-ELSES body must never complete THIS send.
    const result = classifySendCompletionPoll(
      makePollInput(PHANTOM_OBS, {
        candidate: {
          innerSha256: "unrelated-inner",
          step1Signature: VALID_STEP1,
          step2Signature: VALID_STEP2,
        },
      }),
    );
    expect(result).toBeNull();
  });

  it("NEGATIVE: refuses match when body matches but candidate step_1 does not", () => {
    const result = classifySendCompletionPoll(
      makePollInput(LANDED_MATCHING_OBS, {
        candidate: {
          ...MATCHING_CANDIDATE,
          step1Signature: VALID_STEP2,
        },
      }),
    );
    expect(result).toBeNull();
  });

  it("NEGATIVE: refuses match when candidate is absent (proof alone is not enough)", () => {
    const result = classifySendCompletionPoll(
      makePollInput(LANDED_MATCHING_OBS, { candidate: null }),
    );
    expect(result).toBeNull();
  });

  it("returns null on NO_SUCCESSOR (recipient has not acted yet)", () => {
    const verdict = classifySendCompletionPoll(makePollInput(NO_SUCCESSOR_OBS));
    expect(verdict).toBeNull();
  });

  it("returns INDETERMINATE on PROOF_INCOMPLETE", () => {
    const result = classifySendCompletionPoll(makePollInput(PROOF_INCOMPLETE_OBS));
    expect(result).not.toBeNull();
    if (result === null) throw new Error("expected non-null");
    expect(result.kind).toBe("INDETERMINATE");
    if (result.kind === "INDETERMINATE") {
      expect(result.reason.source).toBe("LANDING_PROOF_INCOMPLETE");
    }
  });

  it("returns INVARIANT_BREACH on SIGNATURE_COLLISION (not downgraded)", () => {
    const result = classifySendCompletionPoll(makePollInput(ANOMALY_OBS));
    expect(result).not.toBeNull();
    if (result === null) throw new Error("expected non-null");
    expect(result.kind).toBe("INVARIANT_BREACH");
    if (result.kind === "INVARIANT_BREACH") {
      expect(result.reason.source).toBe("OBSERVATION_ANOMALY");
      if (result.reason.source === "OBSERVATION_ANOMALY") {
        expect(result.reason.anomaly).toBe("SIGNATURE_COLLISION");
      }
    }
  });

  it("returns INVARIANT_BREACH on UNATTRIBUTED_SUCCESSOR_UNDER_LEASE", () => {
    const verdict = classifySendCompletionPoll(makePollInput(UNATTRIBUTED_OBS));
    expect(verdict).not.toBeNull();
    if (verdict === null) throw new Error("expected non-null");
    expect(verdict.kind).toBe("INVARIANT_BREACH");
    if (verdict.kind === "INVARIANT_BREACH") {
      expect(verdict.reason.source).toBe("UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE");
    }
  });

  it("returns INDETERMINATE on non-breach observation anomaly (TRANSPORT_ERROR)", () => {
    const result = classifySendCompletionPoll(makePollInput(TRANSPORT_ANOMALY_OBS));
    expect(result).not.toBeNull();
    if (result === null) throw new Error("expected non-null");
    expect(result.kind).toBe("INDETERMINATE");
  });
});

describe("createObservationServicePollFn", () => {
  it("routes every poll through the observation service (no direct gateway submit)", async () => {
    const observeSourcePath = vi.fn().mockResolvedValue({
      observation: LANDED_MATCHING_OBS,
      observedAt: "2026-01-01T00:00:01.000Z",
      candidate: MATCHING_CANDIDATE,
      capture: FAKE_CAPTURE,
    });
    const service: SourcePathObservationService = { observeSourcePath };
    const poll = createObservationServicePollFn(service);

    const input = await poll(DESCRIPTOR);

    expect(observeSourcePath).toHaveBeenCalledTimes(1);
    expect(observeSourcePath).toHaveBeenCalledWith({
      sourceWalletPubkeyBase64Urlsafe: SOURCE_PUBKEY,
      expectedBodySha256: BODY_SHA,
    });
    expect(input.observation).toBe(LANDED_MATCHING_OBS);
    expect(input.capture?.responseSha256).toBe("resp-sha-abc");
    expect(input.candidate?.innerSha256).toBe(INNER_SHA);
  });
});

describe("monitorSendCompletion", () => {
  const noopSleep = async () => {};
  let clock = 0;
  const nowMs = () => clock;
  const nowIso = () => new Date(clock).toISOString();

  function resetClock() {
    clock = 0;
  }

  it("returns CANDIDATE_MATCH when the first poll finds a bound landing proof", async () => {
    resetClock();
    const recorder = makeRecorder();
    const poll = vi.fn().mockResolvedValue(
      makePollInput(LANDED_MATCHING_OBS, { capture: FAKE_CAPTURE }),
    );

    const verdict = await monitorSendCompletion(DESCRIPTOR, {
      poll,
      recorder,
      sleep: noopSleep,
      nowMs,
      nowIso,
    });

    expect(verdict.kind).toBe("CANDIDATE_MATCH");
    expect(poll).toHaveBeenCalledTimes(1);
    expect(recorder.records).toHaveLength(1);
    expect(recorder.records[0].verdict.kind).toBe("CANDIDATE_MATCH");
    expect(recorder.records[0].sourceWalletId).toBe("wallet-source");
    expect(recorder.records[0].expectedBodySha256).toBe(BODY_SHA);
    expect(recorder.records[0].transferCodeSha256).toBe(CODE_SHA);
    expect(recorder.records[0].lastResponseSha256).toBe("resp-sha-abc");
  });

  it("polls until a bound candidate appears (NO_SUCCESSOR then CANDIDATE_MATCH)", async () => {
    resetClock();
    const recorder = makeRecorder();
    const poll = vi
      .fn()
      .mockResolvedValueOnce(makePollInput(NO_SUCCESSOR_OBS))
      .mockResolvedValueOnce(makePollInput(NO_SUCCESSOR_OBS))
      .mockResolvedValueOnce(makePollInput(LANDED_MATCHING_OBS));

    const verdict = await monitorSendCompletion(DESCRIPTOR, {
      poll,
      recorder,
      sleep: noopSleep,
      nowMs,
      nowIso,
    });

    expect(verdict.kind).toBe("CANDIDATE_MATCH");
    expect(poll).toHaveBeenCalledTimes(3);
    expect(recorder.records).toHaveLength(1);
  });

  it("keeps polling past a phantom (unrelated-body) settle and does not complete", async () => {
    resetClock();
    const recorder = makeRecorder();
    const poll = vi
      .fn()
      .mockResolvedValueOnce(
        makePollInput(PHANTOM_OBS, {
          candidate: {
            innerSha256: "x",
            step1Signature: VALID_STEP1,
            step2Signature: VALID_STEP2,
          },
        }),
      )
      .mockResolvedValueOnce(makePollInput(LANDED_MATCHING_OBS));

    const verdict = await monitorSendCompletion(DESCRIPTOR, {
      config: { maxPolls: 5, pollIntervalMs: 1, windowMs: 999_999 },
      poll,
      recorder,
      sleep: noopSleep,
      nowMs,
      nowIso,
    });

    expect(verdict.kind).toBe("CANDIDATE_MATCH");
    expect(poll).toHaveBeenCalledTimes(2);
  });

  it("returns TIMED_OUT when the window elapses without a candidate match", async () => {
    resetClock();
    const recorder = makeRecorder();
    const advancingNowMs = () => {
      clock += 6_000;
      return clock;
    };
    const poll = vi.fn().mockResolvedValue(makePollInput(NO_SUCCESSOR_OBS));

    const verdict = await monitorSendCompletion(DESCRIPTOR, {
      config: { maxPolls: 100, pollIntervalMs: 1_000, windowMs: 10_000 },
      poll,
      recorder,
      sleep: noopSleep,
      nowMs: advancingNowMs,
      nowIso,
    });

    expect(verdict.kind).toBe("TIMED_OUT");
    if (verdict.kind === "TIMED_OUT") {
      expect(verdict.sendAttemptId).toBe("send-attempt-1");
      expect(verdict.pollsExecuted).toBeGreaterThanOrEqual(1);
    }
    expect(recorder.records).toHaveLength(1);
    expect(recorder.records[0].verdict.kind).toBe("TIMED_OUT");
  });

  it("returns TIMED_OUT when maxPolls is exhausted with successful no-match reads", async () => {
    resetClock();
    const recorder = makeRecorder();
    const poll = vi.fn().mockResolvedValue(makePollInput(NO_SUCCESSOR_OBS));

    const verdict = await monitorSendCompletion(DESCRIPTOR, {
      config: { maxPolls: 3, pollIntervalMs: 1_000, windowMs: 999_999 },
      poll,
      recorder,
      sleep: noopSleep,
      nowMs,
      nowIso,
    });

    expect(verdict.kind).toBe("TIMED_OUT");
    expect(poll).toHaveBeenCalledTimes(3);
    expect(recorder.records).toHaveLength(1);
  });

  it("returns INDETERMINATE on an unrecoverable observation fault", async () => {
    resetClock();
    const recorder = makeRecorder();
    const poll = vi.fn().mockResolvedValue(makePollInput(PROOF_INCOMPLETE_OBS));

    const verdict = await monitorSendCompletion(DESCRIPTOR, {
      poll,
      recorder,
      sleep: noopSleep,
      nowMs,
      nowIso,
    });

    expect(verdict.kind).toBe("INDETERMINATE");
    if (verdict.kind === "INDETERMINATE") {
      expect(verdict.reason.source).toBe("LANDING_PROOF_INCOMPLETE");
    }
    expect(recorder.records).toHaveLength(1);
  });

  it("returns INVARIANT_BREACH (not INDETERMINATE) on unattributed successor", async () => {
    resetClock();
    const recorder = makeRecorder();
    const poll = vi.fn().mockResolvedValue(makePollInput(UNATTRIBUTED_OBS));

    const verdict = await monitorSendCompletion(DESCRIPTOR, {
      poll,
      recorder,
      sleep: noopSleep,
      nowMs,
      nowIso,
    });

    expect(verdict.kind).toBe("INVARIANT_BREACH");
    expect(recorder.records[0].verdict.kind).toBe("INVARIANT_BREACH");
  });

  it("continues polling after a transport error (poll throws) then matches", async () => {
    resetClock();
    const recorder = makeRecorder();
    const poll = vi
      .fn()
      .mockRejectedValueOnce(new Error("network timeout"))
      .mockResolvedValueOnce(makePollInput(LANDED_MATCHING_OBS));

    const verdict = await monitorSendCompletion(DESCRIPTOR, {
      config: { maxPolls: 5, pollIntervalMs: 1_000, windowMs: 999_999 },
      poll,
      recorder,
      sleep: noopSleep,
      nowMs,
      nowIso,
    });

    expect(verdict.kind).toBe("CANDIDATE_MATCH");
    expect(poll).toHaveBeenCalledTimes(2);
  });

  it("returns POLL_TRANSPORT_EXHAUSTED when every poll throws (not TIMED_OUT)", async () => {
    resetClock();
    const recorder = makeRecorder();
    const poll = vi.fn().mockRejectedValue(new Error("gateway down"));

    const verdict = await monitorSendCompletion(DESCRIPTOR, {
      config: { maxPolls: 3, pollIntervalMs: 1, windowMs: 999_999 },
      poll,
      recorder,
      sleep: noopSleep,
      nowMs,
      nowIso,
    });

    expect(verdict.kind).toBe("INDETERMINATE");
    if (verdict.kind === "INDETERMINATE") {
      expect(verdict.reason.source).toBe("POLL_TRANSPORT_EXHAUSTED");
      expect(verdict.pollsExecuted).toBe(3);
    }
    expect(recorder.records).toHaveLength(1);
  });

  it("records evidence with correct poll count on CANDIDATE_MATCH", async () => {
    resetClock();
    const recorder = makeRecorder();
    const poll = vi
      .fn()
      .mockResolvedValueOnce(makePollInput(NO_SUCCESSOR_OBS))
      .mockResolvedValueOnce(makePollInput(LANDED_MATCHING_OBS));

    await monitorSendCompletion(DESCRIPTOR, {
      poll,
      recorder,
      sleep: noopSleep,
      nowMs,
      nowIso,
    });

    expect(recorder.records).toHaveLength(1);
    expect(recorder.records[0].pollCount).toBe(2);
    expect(recorder.records[0].sendAttemptId).toBe("send-attempt-1");
    // transferCodeSha256 and expectedBodySha256 are read into evidence (D1).
    expect(recorder.records[0].transferCodeSha256).toBe(CODE_SHA);
    expect(recorder.records[0].expectedBodySha256).toBe(BODY_SHA);
  });

  it("uses default config values when none provided", () => {
    expect(DEFAULT_COMPLETION_MONITOR_CONFIG.maxPolls).toBe(60);
    expect(DEFAULT_COMPLETION_MONITOR_CONFIG.pollIntervalMs).toBe(5_000);
    expect(DEFAULT_COMPLETION_MONITOR_CONFIG.windowMs).toBe(300_000);
  });

  it("never mutates the descriptor (passive monitoring)", async () => {
    resetClock();
    const recorder = makeRecorder();
    const frozenDescriptor = Object.freeze({ ...DESCRIPTOR });
    const poll = vi.fn().mockResolvedValue(makePollInput(LANDED_MATCHING_OBS));

    const verdict = await monitorSendCompletion(frozenDescriptor, {
      poll,
      recorder,
      sleep: noopSleep,
      nowMs,
      nowIso,
    });

    expect(verdict.kind).toBe("CANDIDATE_MATCH");
    expect(frozenDescriptor).toEqual(DESCRIPTOR);
  });

  it("integrates observation-service poll end-to-end", async () => {
    resetClock();
    const recorder = makeRecorder();
    const service: SourcePathObservationService = {
      async observeSourcePath() {
        return {
          observation: LANDED_MATCHING_OBS,
          observedAt: "2026-01-01T00:00:00.000Z",
          candidate: MATCHING_CANDIDATE,
          capture: FAKE_CAPTURE,
        };
      },
    };

    const verdict = await monitorSendCompletion(DESCRIPTOR, {
      poll: createObservationServicePollFn(service),
      recorder,
      sleep: noopSleep,
      nowMs,
      nowIso,
    });

    expect(verdict.kind).toBe("CANDIDATE_MATCH");
    expect(recorder.records[0].lastResponseSha256).toBe("resp-sha-abc");
  });
});
