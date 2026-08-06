// RECEIVE_EXTERNAL settle step (closes). Governing:
// Settle steps 8–13, under the exact-byte rules and the signing chokepoint;
// the one-in-flight-per-wallet and byte-exact signing rules, 4.
//
// Offline throughout: real Ed25519 keys, a fake gateway exchange, and an in-memory stand-in for
// the UNIQUE (operation_id, transaction_attempt_no) mint. No live chain (live is Wave 4).
//
// The exit properties, one per fault test below:
// Byte-exact — the step-2 preimage is the persisted inner spliced verbatim, byte for byte, and the
// bytes that leave for the gateway still carry the completed body verbatim.
// One-in-flight — a second operation on the same wallet cannot co-sign, so it never reaches submit.
// No-blind-retry — a pass resumed at a durable rung a crash can actually leave behind reconciles through
// the confirm-read before any submit path, and never resubmits.
// Step 8 — a drifted preimage, a bad payer signature, or a receiver key the signed inner
// does not name stops before the signer.

import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { describe, expect, it } from "vitest";

import type { GatewayExchangeTransport } from "../gateway/capture.js";
import type { GatewaySubmitAttemptRecord, SubmitAttemptRecorder } from "../gateway/records.js";
import type { GatewayRequest } from "../protocol/index.js";
import { ATTEMPT_PHASE_LADDER, type AttemptPhase } from "./execution-phase.js";
import {
  RECEIVE_SUBMIT_ACTION_NAME,
  settleReceiveAttempt,
  verifyPersistedCandidate,
  type ReceiveSettleAttempt,
  type ReceiveSettleDeps,
} from "./receive-settle.js";
import type { ReceiveSubmitClaim, SubmitClaimStore } from "./receive-submit-once.js";
import type {
  ActiveLeaseRecord,
  MoneyPathSignerGates,
  SignerAuditEntry,
  SignerBoundaryDeps,
} from "./signer-boundary.js";
import type { SqlQueryFn } from "./sql-query-fn.js";

const OPERATION_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_OPERATION_ID = "22222222-2222-4222-8222-222222222222";
const RECEIVER_WALLET_ID = "33333333-3333-4333-8333-333333333333";
const LEASE_EPOCH = 7n;
const NOW = "2026-01-01T00:00:00.000Z";

// --- test-only filled-byte Ed25519 seeds (same construction as the A.8.1 golden vector) ------
const keyFromSeed = (byte: number) =>
  createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, byte),
    ]),
    type: "pkcs8",
    format: "der",
  });
const publicKeyOf = (pk: ReturnType<typeof keyFromSeed>): string =>
  createPublicKey(pk)
    .export({ type: "spki", format: "der" })
    .subarray(-32)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

const payerKey = keyFromSeed(0x02);
const receiverKey = keyFromSeed(0x03);
const payerPublic = publicKeyOf(payerKey);
const receiverPublic = publicKeyOf(receiverKey);

/** A well-formed v2 inner in canonical insertion sequence. Serialized ONCE; every assertion
 * below compares against these exact bytes rather than re-stringifying. */
const INNER_PREIMAGE_TEXT = JSON.stringify({
  type: "unique_combinable",
  version: "2",
  unix_time_secs: "1767225600",
  signer_steps: 2,
  step_1_signer: "sender",
  step_2_signer: "receiver",
  step_1_key_public__base64urlsafe: payerPublic,
  step_2_key_public__base64urlsafe: receiverPublic,
  step_1_state: { amount: "9.99", nonce: "n1" },
  step_2_state: { amount: "0.01", nonce: "n2" },
  previous_step_1_state_signature: "prev-s1",
  previous_step_2_state_signature: "",
  expiry__unix_time_secs: "1767229200",
});

const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");

const PAYER_STEP1_SIGNATURE = paddedBase64Url(
  Buffer.from(edSign(null, Buffer.from(INNER_PREIMAGE_TEXT, "utf8"), payerKey)),
);

const ATTEMPT: ReceiveSettleAttempt = {
  operationId: OPERATION_ID,
  receiveAttemptId: OPERATION_ID,
  receiverWalletId: RECEIVER_WALLET_ID,
  receiverPublicKey: receiverPublic,
  leaseEpoch: LEASE_EPOCH,
  innerPreimageText: INNER_PREIMAGE_TEXT,
  payerStep1Signature: PAYER_STEP1_SIGNATURE,
  attemptPhase: "STEP1_SIGNATURE_PERSISTED",
};

// --- fakes ------------------------------------------------------------------------------------

/** Records phase advances the way the one-way UPDATE does: only the immediately prior ladder
 * phase advances, and a column already set is never overwritten. */
function makeMaterialStore(startPhase: AttemptPhase = "STEP1_SIGNATURE_PERSISTED") {
  const columns = new Map<string, string>();
  let phase = startPhase;
  const advances: AttemptPhase[] = [];
  const query: SqlQueryFn = async (text, values) => {
    const match = /attempt_phase = '([A-Z0-9_]+)'/.exec(text);
    const toPhase = match?.[1] as AttemptPhase | undefined;
    if (toPhase === undefined) return [];
    const priorPhase = values[1] as AttemptPhase;
    if (phase !== priorPhase) return []; // advanceAttemptPhase throws on an empty result
    const added = ATTEMPT_PHASE_LADDER.includes(toPhase);
    if (!added) return [];
    for (const [index, value] of values.slice(2).entries()) {
      columns.set(`${toPhase}#${index}`, String(value));
    }
    phase = toPhase;
    advances.push(toPhase);
    return [{ attempt_phase: toPhase }];
  };
  return {
    query,
    advances,
    columns,
    get phase() {
      return phase;
    },
  };
}

const attemptKey = (claim: ReceiveSubmitClaim): string =>
  `${claim.operationId}#${claim.transactionAttemptNo}`;

/** In-memory stand-in for the UNIQUE (operation_id, transaction_attempt_no) mint. Shared
 * across calls so a resumed attempt sees the durable claim a crash would have left behind. */
function makeClaimStore(): SubmitClaimStore & { readonly mints: number } {
  const claims = new Map<string, ReceiveSubmitClaim>();
  let mints = 0;
  return {
    get mints() {
      return mints;
    },
    claimSubmitOnce: async (claim) => {
      const existing = claims.get(attemptKey(claim));
      if (existing !== undefined) return { claim: existing, minted: false };
      claims.set(attemptKey(claim), claim);
      mints += 1;
      return { claim, minted: true };
    },
  };
}

function makeExchange(statusCode = 200, body = '{"status":true,"code":"ok","message":"OK","data":{}}') {
  const calls: GatewayRequest[] = [];
  const transport: GatewayExchangeTransport = {
    exchange: async (endpoint: string, request: GatewayRequest) => {
      calls.push(request);
      return {
        endpoint,
        endpointFingerprint: "offline-fp",
        requestBytes: request.bodyBytes,
        requestSha256: "req-sha",
        responseBytes: new TextEncoder().encode(body),
        responseSha256: "resp-sha",
        statusCode,
      };
    },
  };
  return { transport, calls };
}

function makeRecorder(): SubmitAttemptRecorder & { records: GatewaySubmitAttemptRecord[] } {
  const records: GatewaySubmitAttemptRecord[] = [];
  return { records, recordSubmitAttempt: async (r) => void records.push(r) };
}

const openGates: MoneyPathSignerGates = {
  assertMoneyAdmitted: () => {},
  assertCanOperate: () => {},
  assertWalletMaySign: async () => {},
};

/**
 * The signer over a real Ed25519 key. The lease reader is the One-in-flight surface: it reports the
 * ONE operation currently holding the wallet, exactly as wallet_active_leases does.
 */
function makeSignerDeps(options?: {
  readonly leaseHeldBy?: string | null;
  readonly audit?: SignerAuditEntry[];
}): SignerBoundaryDeps & MoneyPathSignerGates {
  const leaseHeldBy = options?.leaseHeldBy === undefined ? OPERATION_ID : options.leaseHeldBy;
  const audit = options?.audit ?? [];
  return {
    leadership: { held: true },
    leaseReader: {
      readActiveLease: async (walletId: string): Promise<ActiveLeaseRecord | null> =>
        leaseHeldBy === null
          ? null
          : {
              walletId,
              operationId: leaseHeldBy,
              epoch: LEASE_EPOCH,
              role: "RECEIVE_WINDOW",
              lifecycle: "ACTIVE",
            },
    },
    vaultSigner: {
      // The padded base64url spelling the frozen scalar domains accept, as the
      // production vault signer emits it.
      sign: async (_walletId: string, preimageBytes: Uint8Array) =>
        paddedBase64Url(Buffer.from(edSign(null, Buffer.from(preimageBytes), receiverKey))),
    },
    auditLog: { append: async (entry) => void audit.push(entry) },
    ...openGates,
  };
}

function makeDeps(overrides?: {
  readonly material?: ReturnType<typeof makeMaterialStore>;
  readonly claimStore?: SubmitClaimStore;
  readonly exchange?: ReturnType<typeof makeExchange>;
  readonly signerDeps?: SignerBoundaryDeps & MoneyPathSignerGates;
  /** What the confirm-read reports as the receiver head's step_2_signature. */
  readonly headStep2Signature?: string | null;
}): ReceiveSettleDeps & {
  readonly exchange: ReturnType<typeof makeExchange>;
  readonly headReads: string[];
} {
  const material = overrides?.material ?? makeMaterialStore();
  const exchange = overrides?.exchange ?? makeExchange();
  const headReads: string[] = [];
  return {
    exchange,
    headReads,
    query: material.query,
    signerDeps: overrides?.signerDeps ?? makeSignerDeps(),
    claimStore: overrides?.claimStore ?? makeClaimStore(),
    submitOptions: {
      endpoint: "https://gateway.offline.test",
      limits: { readTimeoutMs: 1000, maxRequestBytes: 65536, maxResponseBytes: 65536 },
      recorder: makeRecorder(),
      exchange: exchange.transport,
    },
    submitDecisionId: OPERATION_ID,
    readReceiverHeadStep2Signature: async (key) => {
      headReads.push(key);
      return overrides?.headStep2Signature ?? null;
    },
    nowIso: () => NOW,
  };
}

/** The bytes the gateway actually received, decoded out of the frozen form body. */
function wireBodyOf(request: GatewayRequest): string {
  const wire = new TextDecoder().decode(request.bodyBytes);
  return decodeURIComponent(wire.slice(wire.indexOf("=") + 1));
}

// --- tests ------------------------------------------------------------------------------------

describe("settleReceiveAttempt — steps 8–13 offline end to end", () => {
  it("co-signs and submits exactly once, landing the attempt at STEP2_SIGNATURE_PERSISTED", async () => {
    const material = makeMaterialStore();
    const deps = makeDeps({ material });

    const outcome = await settleReceiveAttempt(ATTEMPT, deps);

    expect(outcome.kind).toBe("SUBMITTED");
    if (outcome.kind !== "SUBMITTED") return;

    // Steps 9 and 11 both committed, in ladder sequence.
    expect(material.advances).toEqual(["STEP2_PREIMAGE_PERSISTED", "STEP2_SIGNATURE_PERSISTED"]);
    expect(material.phase).toBe("STEP2_SIGNATURE_PERSISTED");

    // The byte-exact signing rule: the step-2 preimage is the persisted inner spliced verbatim between the
    // two frozen keys — asserted against the exact bytes, not against a re-serialization.
    //
    // Residual ceiling, stated exactly: swapping the splice for a re-serialization of the
    // parsed inner is NOT detectable in process, because assertPersistedInnerRoundTrips has
    // already proven the two produce identical bytes under this engine — that is what it
    // asserts. The splice is the hedge for the day an engine change breaks that equality. What
    // IS detectable, and asserted below, is any reshaping of the body on the way to the wire:
    // the outgoing bytes are checked against the completed text, so a reorder or reformat
    // anywhere between step 11 and the gateway reddens this suite.
    expect(outcome.step2PreimageText).toContain(INNER_PREIMAGE_TEXT);
    expect(outcome.step2PreimageText.indexOf(INNER_PREIMAGE_TEXT)).toBe('{"inner":'.length);
    expect(outcome.step2PreimageText).toBe(
      `{"inner":${INNER_PREIMAGE_TEXT},"step_1_signature":${JSON.stringify(PAYER_STEP1_SIGNATURE)}}`,
    );
    expect(outcome.completedTransactionText).toBe(
      `${outcome.step2PreimageText.slice(0, -1)},"step_2_signature":${JSON.stringify(outcome.step2Signature)}}`,
    );

    // The receiver signature verifies against the exact step-2 preimage bytes the signer saw.
    expect(
      edVerify(
        null,
        Buffer.from(outcome.step2PreimageText, "utf8"),
        createPublicKey(receiverKey),
        Buffer.from(outcome.step2Signature, "base64url"),
      ),
    ).toBe(true);

    // The never-blind-retry rule: one exchange, carrying the frozen submit action.
    expect(deps.exchange.calls).toHaveLength(1);
    expect(deps.exchange.calls[0]?.rpc).toBe(RECEIVE_SUBMIT_ACTION_NAME);
    expect(RECEIVE_SUBMIT_ACTION_NAME).toBe("submit_transaction__v1");

    // The byte-exact signing rule at the boundary that actually matters: the bytes that left the node carry
    // the signed body verbatim. The request is built from a re-parse of the completed text, so
    // this is the assertion that catches a reserialization that reorders or reformats it.
    expect(wireBodyOf(deps.exchange.calls[0]!)).toContain(outcome.completedTransactionText);

    // A first pass never confirm-reads: there is no submit outcome to reconcile yet.
    expect(deps.headReads).toEqual([]);
  });

  it("step 8: the receiver key must be the step-2 key the SIGNED inner names", () => {
    // The row says one key, the signed inner names another. Signing on the row's authority
    // would produce a step-2 signature by a key the transaction does not name — and burn the
    // one-shot claim on a body the chain can never accept.
    expect(
      verifyPersistedCandidate({ ...ATTEMPT, receiverPublicKey: payerPublic }),
    ).toBe("RECEIVER_KEY_NOT_NAMED_BY_INNER");
  });

  it("a mismatched receiver key stops before the signer and before submit", async () => {
    const material = makeMaterialStore();
    const exchange = makeExchange();
    const outcome = await settleReceiveAttempt(
      { ...ATTEMPT, receiverPublicKey: payerPublic },
      makeDeps({ material, exchange }),
    );
    expect(outcome).toMatchObject({
      kind: "REJECTED",
      reason: "RECEIVER_KEY_NOT_NAMED_BY_INNER",
    });
    expect(material.advances).toEqual([]);
    expect(exchange.calls).toHaveLength(0);
  });

  it("No-blind-retry duplicate settle: two passes over one clean attempt mint one claim and submit once", async () => {
    // Two workers racing the same first-rung row, not a crash: each has its own view of the
    // material (the loser's phase advance is what the real one-way UPDATE would refuse), and
    // they share the one durable claim. The crash cases are the two tests that follow.
    const claimStore = makeClaimStore();
    const exchange = makeExchange();

    const first = await settleReceiveAttempt(
      ATTEMPT,
      makeDeps({ claimStore, exchange, material: makeMaterialStore() }),
    );
    expect(first.kind).toBe("SUBMITTED");
    expect(exchange.calls).toHaveLength(1);
    expect(claimStore.mints).toBe(1);

    const second = await settleReceiveAttempt(
      ATTEMPT,
      makeDeps({ claimStore, exchange, material: makeMaterialStore() }),
    );

    expect(second.kind).toBe("RECONCILE_REQUIRED");
    if (second.kind === "RECONCILE_REQUIRED") {
      expect(second.reason.source).toBe("SUBMIT_OUTCOME_UNKNOWN");
    }
    // The load-bearing assertion: still exactly one gateway exchange, still one claim.
    expect(exchange.calls).toHaveLength(1);
    expect(claimStore.mints).toBe(1);
  });

  it("crash between the step-9 commit and the signer: resumes on the persisted preimage bytes", async () => {
    // The reference ceremony, uninterrupted, over the same inner.
    const reference = await settleReceiveAttempt(ATTEMPT, makeDeps());
    expect(reference.kind).toBe("SUBMITTED");
    if (reference.kind === "REJECTED") return;

    // The real post-crash durable state: phase already at STEP2_PREIMAGE_PERSISTED, the step-2
    // preimage durable, nothing signed. Rewinding the phase instead would model a state a
    // crash cannot produce, because advanceAttemptPhase is one-way.
    const material = makeMaterialStore("STEP2_PREIMAGE_PERSISTED");
    const claimStore = makeClaimStore();
    const deps = makeDeps({ material, claimStore });
    const resumed = await settleReceiveAttempt(
      {
        ...ATTEMPT,
        attemptPhase: "STEP2_PREIMAGE_PERSISTED",
        step2PreimageText: reference.step2PreimageText,
      },
      deps,
    );

    expect(resumed.kind).toBe("SUBMITTED");
    if (resumed.kind === "REJECTED") return;
    // Byte-identical to the uninterrupted run: the resume signed the persisted text, and did
    // not re-derive it from the inner.
    expect(resumed.step2PreimageText).toBe(reference.step2PreimageText);
    expect(resumed.completedTransactionText).toBe(reference.completedTransactionText);
    // Only the step-11 advance ran; step 9 was already durable and is never re-committed.
    expect(material.advances).toEqual(["STEP2_SIGNATURE_PERSISTED"]);
    expect(claimStore.mints).toBe(1);
    expect(deps.exchange.calls).toHaveLength(1);
    // No submit had started, so there was nothing to reconcile before submitting.
    expect(deps.headReads).toEqual([]);
  });

  it("crash between submit and the landing write: reconciles on the head, never resubmits", async () => {
    const reference = await settleReceiveAttempt(ATTEMPT, makeDeps());
    expect(reference.kind).toBe("SUBMITTED");
    if (reference.kind === "REJECTED") return;

    // Durable state after a crash past step 12: body signed and persisted, claim minted,
    // submit outcome unknown. The confirm-read reports this attempt's own body at the head.
    const claimStore = makeClaimStore();
    await claimStore.claimSubmitOnce({
      attemptId: OPERATION_ID,
      operationId: OPERATION_ID,
      transactionAttemptNo: 1,
      claimedAt: NOW,
    });
    const material = makeMaterialStore("STEP2_SIGNATURE_PERSISTED");
    const deps = makeDeps({
      material,
      claimStore,
      headStep2Signature: reference.step2Signature,
    });

    const resumed = await settleReceiveAttempt(
      {
        ...ATTEMPT,
        attemptPhase: "STEP2_SIGNATURE_PERSISTED",
        step2PreimageText: reference.step2PreimageText,
        step2Signature: reference.step2Signature,
        completedTransactionText: reference.completedTransactionText,
      },
      deps,
    );

    expect(resumed.kind).toBe("OBSERVED_AT_HEAD");
    // The load-bearing assertions: the head was read, nothing was signed again, nothing was
    // advanced again, and no second body reached the gateway.
    expect(deps.headReads).toEqual([receiverPublic]);
    expect(material.advances).toEqual([]);
    expect(deps.exchange.calls).toHaveLength(0);
    expect(claimStore.mints).toBe(1);
  });

  it("the head is matched on the decoded signature, not on its base64url spelling", async () => {
    const reference = await settleReceiveAttempt(ATTEMPT, makeDeps());
    if (reference.kind === "REJECTED") return;

    // Everything this node persists is the PADDED spelling, but the head value comes
    // through the envelope stage, which asks only for a non-empty string — canonical
    // scalar validation is a later stage. A gateway emitting the unpadded spelling must still answer
    // the resubmit question, or every resumed attempt parks on the claim check forever.
    const unpadded = reference.step2Signature.replace(/=+$/, "");
    expect(unpadded).not.toBe(reference.step2Signature);

    const claimStore = makeClaimStore();
    await claimStore.claimSubmitOnce({
      attemptId: OPERATION_ID,
      operationId: OPERATION_ID,
      transactionAttemptNo: 1,
      claimedAt: NOW,
    });
    const deps = makeDeps({
      material: makeMaterialStore("STEP2_SIGNATURE_PERSISTED"),
      claimStore,
      headStep2Signature: unpadded,
    });

    const resumed = await settleReceiveAttempt(
      {
        ...ATTEMPT,
        attemptPhase: "STEP2_SIGNATURE_PERSISTED",
        step2PreimageText: reference.step2PreimageText,
        step2Signature: reference.step2Signature,
        completedTransactionText: reference.completedTransactionText,
      },
      deps,
    );

    expect(resumed.kind).toBe("OBSERVED_AT_HEAD");
    expect(deps.exchange.calls).toHaveLength(0);
  });

  // The resume branch is the one route to the gateway that skips signUnderLease, so the
  // gates that chokepoint would have applied are restated inside it. A node that lost leadership
  // during an overlapping deployment, or whose engines have quiesced, must not push a money body
  // just because the body was signed before the loss (the signing chokepoint and custody claim boundary).
  const shutGate: readonly (readonly [
    string,
    Partial<SignerBoundaryDeps & MoneyPathSignerGates>,
  ])[] = [
    ["signer leadership is lost", { leadership: { held: false, reason: "advisory lock lost" } }],
    [
      "engines have quiesced",
      {
        assertCanOperate: () => {
          throw new Error("engines quiesced");
        },
      },
    ],
  ];

  it.each(shutGate)(
    "a resume refuses before the confirm-read when %s",
    async (_label, closed) => {
      const reference = await settleReceiveAttempt(ATTEMPT, makeDeps());
      if (reference.kind === "REJECTED") return;

      // No claim exists and the head shows a different transaction, so an ungated pass would
      // read the head and then submit — which is exactly what the gates have to prevent.
      const claimStore = makeClaimStore();
      const deps = makeDeps({
        material: makeMaterialStore("STEP2_SIGNATURE_PERSISTED"),
        claimStore,
        signerDeps: { ...makeSignerDeps(), ...closed },
        headStep2Signature: "some-other-transaction-signature",
      });

      await expect(
        settleReceiveAttempt(
          {
            ...ATTEMPT,
            attemptPhase: "STEP2_SIGNATURE_PERSISTED",
            step2PreimageText: reference.step2PreimageText,
            step2Signature: reference.step2Signature,
            completedTransactionText: reference.completedTransactionText,
          },
          deps,
        ),
      ).rejects.toThrow();

      // Load-bearing: nothing observed, nothing claimed, nothing on the wire.
      expect(deps.headReads).toEqual([]);
      expect(deps.exchange.calls).toHaveLength(0);
      expect(claimStore.mints).toBe(0);
    },
  );

  it("a resumed signed body whose submit never started reconciles first, then submits once", async () => {
    const reference = await settleReceiveAttempt(ATTEMPT, makeDeps());
    if (reference.kind === "REJECTED") return;

    // Crash between the step-11 commit and the claim mint: no claim exists, so no submit ever
    // crossed the wire. The head does not show this body — which proves nothing on its own,
    // so the submit is authorised by the mint winning, not by the head read.
    const claimStore = makeClaimStore();
    const deps = makeDeps({
      material: makeMaterialStore("STEP2_SIGNATURE_PERSISTED"),
      claimStore,
      headStep2Signature: "some-other-transaction-signature",
    });

    const resumed = await settleReceiveAttempt(
      {
        ...ATTEMPT,
        attemptPhase: "STEP2_SIGNATURE_PERSISTED",
        step2PreimageText: reference.step2PreimageText,
        step2Signature: reference.step2Signature,
        completedTransactionText: reference.completedTransactionText,
      },
      deps,
    );

    expect(resumed.kind).toBe("SUBMITTED");
    // The confirm-read happened BEFORE the gateway was touched (the never-blind-retry rule).
    expect(deps.headReads).toEqual([receiverPublic]);
    expect(deps.exchange.calls).toHaveLength(1);
    expect(wireBodyOf(deps.exchange.calls[0]!)).toContain(reference.completedTransactionText);
    expect(claimStore.mints).toBe(1);
  });

  it("a resume whose row is missing the material its phase claims is refused, not rebuilt", async () => {
    const material = makeMaterialStore("STEP2_SIGNATURE_PERSISTED");
    const deps = makeDeps({ material });
    const outcome = await settleReceiveAttempt(
      { ...ATTEMPT, attemptPhase: "STEP2_SIGNATURE_PERSISTED", step2PreimageText: null },
      deps,
    );
    expect(outcome).toMatchObject({ kind: "REJECTED", reason: "RESUME_MATERIAL_MISSING" });
    expect(material.advances).toEqual([]);
    expect(deps.exchange.calls).toHaveLength(0);
    expect(deps.headReads).toEqual([]);
  });

  it("One-in-flight one in-flight per wallet: an operation without the wallet's lease never reaches submit", async () => {
    // The wallet's active lease belongs to OPERATION_ID; a second operation targets the same
    // wallet. signUnderLease re-reads the lease and refuses on the operation mismatch, so the
    // second transaction is never formed — there is no path around the signer to submit.
    const audit: SignerAuditEntry[] = [];
    const exchange = makeExchange();
    const deps = makeDeps({
      exchange,
      signerDeps: makeSignerDeps({ leaseHeldBy: OPERATION_ID, audit }),
    });

    await expect(
      settleReceiveAttempt({ ...ATTEMPT, operationId: OTHER_OPERATION_ID }, deps),
    ).rejects.toThrow();

    expect(exchange.calls, "a second in-flight transaction reached the gateway").toHaveLength(0);
    // The refusal is audited as a rejection, not silently swallowed.
    expect(audit.map((entry) => entry.outcome)).toEqual(["REJECTED"]);
  });

  it("One-in-flight: a released lease refuses the co-sign too", async () => {
    const exchange = makeExchange();
    const deps = makeDeps({ exchange, signerDeps: makeSignerDeps({ leaseHeldBy: null }) });
    await expect(settleReceiveAttempt(ATTEMPT, deps)).rejects.toThrow();
    expect(exchange.calls).toHaveLength(0);
  });

  it("an ambiguous transport reports RECONCILE_REQUIRED and does not retry", async () => {
    // A 5xx is the transport-ambiguity class: reconcile by observation, never resubmit.
    const exchange = makeExchange(503, "gateway unavailable");
    const deps = makeDeps({ exchange });

    const outcome = await settleReceiveAttempt(ATTEMPT, deps);

    expect(outcome.kind).toBe("RECONCILE_REQUIRED");
    expect(exchange.calls).toHaveLength(1);
  });

  it("step 8: a drifted persisted preimage stops before the signer and before submit", async () => {
    const material = makeMaterialStore();
    const exchange = makeExchange();
    // Whitespace a jsonb-style re-emission would introduce: parses fine, is not the same bytes.
    const drifted = INNER_PREIMAGE_TEXT.replace('{"type"', '{ "type"');

    const outcome = await settleReceiveAttempt(
      { ...ATTEMPT, innerPreimageText: drifted },
      makeDeps({ material, exchange }),
    );

    expect(outcome).toMatchObject({ kind: "REJECTED", reason: "PREIMAGE_DRIFT" });
    expect(material.advances, "a drifted preimage advanced the phase ladder").toEqual([]);
    expect(exchange.calls).toHaveLength(0);
  });

  it("step 8: an invalid payer step-1 signature stops before the signer and before submit", async () => {
    const material = makeMaterialStore();
    const exchange = makeExchange();
    // A syntactically valid signature over different bytes.
    const wrong = paddedBase64Url(
      Buffer.from(edSign(null, Buffer.from("other", "utf8"), payerKey)),
    );

    const outcome = await settleReceiveAttempt(
      { ...ATTEMPT, payerStep1Signature: wrong },
      makeDeps({ material, exchange }),
    );

    expect(outcome).toMatchObject({
      kind: "REJECTED",
      reason: "PAYER_STEP1_SIGNATURE_INVALID",
    });
    expect(material.advances).toEqual([]);
    expect(exchange.calls).toHaveLength(0);
  });

  it("verifies the payer signature against the key the SIGNED inner names, not a row field", () => {
    // A candidate whose inner names the receiver as step-1 signer, carrying a signature the
    // payer made. If the verifier took the key from anywhere but the signed text, this passes.
    const forged = INNER_PREIMAGE_TEXT.replace(
      `"step_1_key_public__base64urlsafe":"${payerPublic}"`,
      `"step_1_key_public__base64urlsafe":"${receiverPublic}"`,
    );
    expect(forged).not.toBe(INNER_PREIMAGE_TEXT);
    expect(
      verifyPersistedCandidate({
        ...ATTEMPT,
        innerPreimageText: forged,
        payerStep1Signature: paddedBase64Url(
          Buffer.from(edSign(null, Buffer.from(forged, "utf8"), payerKey)),
        ),
      }),
    ).toBe("PAYER_STEP1_SIGNATURE_INVALID");
  });

  it("accepts the honest candidate (the negative tests above are not vacuous)", () => {
    expect(verifyPersistedCandidate(ATTEMPT)).toBeNull();
  });
});
