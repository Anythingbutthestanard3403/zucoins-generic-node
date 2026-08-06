// exhaustive negative vectors + ordering + single-winner + amount-bound.
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as signEd25519,
  type KeyObject,
} from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import {
  CANDIDATE_CAPTURE_FIELDS,
  CANDIDATE_INTAKE_PHASE,
  CandidateIntakeError,
  createCandidateIntakeService,
  createFixedClock,
  createInMemoryCandidatePersistPort,
  createInMemoryRawCapturePort,
  RECEIVE_SENDER_PREFLIGHT_ROLE,
  type CandidateIntakeDeps,
  type CandidateIntakeRequest,
  type CandidateIntakeSignerProbe,
  type LocatedReceive,
  type LocateReceivePort,
  type SenderPreflightObservation,
  type SenderPreflightObserver,
} from "./candidate-intake.js";
import { buildReceiveMessage } from "../protocol/receive-transfer-code.js";

// ── Fixtures ────────────────────────────────────────────────────────────────────────────────

const OP_ID = "33333333-3333-4333-8333-333333333333";
const ANCHOR = "ord_7YQ3";
const AMOUNT = "2.25";
const EXPIRY = "1784336400";
const NOW_MS = 1_700_000_000_000; // well before EXPIRY

function ed25519Pair(): { publicKey: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return { publicKey: Buffer.from(raw).toString("base64url") + "=", privateKey };
}

function signText(privateKey: KeyObject, text: string): string {
  const sig = signEd25519(null, Buffer.from(text, "utf8"), privateKey);
  // Canonical padded base64url (88 chars, trailing ==).
  const unpadded = Buffer.from(sig).toString("base64url");
  const pad = (4 - (unpadded.length % 4)) % 4;
  return unpadded + "=".repeat(pad);
}

/** A real padded Ed25519 signature string (valid encoding; content is irrelevant). */
function realSig(seedLabel = "link"): string {
  const pair = ed25519Pair();
  return signText(pair.privateKey, `fixture-${seedLabel}-${pair.publicKey}`);
}

interface InnerFields {
  readonly senderPubkey: string;
  readonly receiverPubkey: string;
  readonly step1Amount: string;
  readonly step2Amount: string;
  readonly prevStep1: string;
  readonly prevStep2: string;
  readonly message: string;
  readonly expiry?: string;
  readonly type?: string;
  readonly version?: string;
  readonly signer_steps?: number;
  readonly step_1_signer?: string;
  readonly step_2_signer?: string;
}

/** Build insertion-sequenced inner JSON text (ordering). The byte-exact signing rule. */
function buildInnerText(f: InnerFields): string {
  const type = f.type ?? "unique_combinable";
  const version = f.version ?? "2";
  const signerSteps = f.signer_steps ?? 2;
  const s1 = f.step_1_signer ?? "sender";
  const s2 = f.step_2_signer ?? "receiver";
  const expiry = f.expiry ?? EXPIRY;
  // Hand-built so key ordering is exact and we never rely on engine property ordering.
  return (
    `{"type":${JSON.stringify(type)}` +
    `,"version":${JSON.stringify(version)}` +
    `,"unix_time_secs":"1700000000"` +
    `,"signer_steps":${signerSteps}` +
    `,"step_1_signer":${JSON.stringify(s1)}` +
    `,"step_2_signer":${JSON.stringify(s2)}` +
    `,"step_1_key_public__base64urlsafe":${JSON.stringify(f.senderPubkey)}` +
    `,"step_2_key_public__base64urlsafe":${JSON.stringify(f.receiverPubkey)}` +
    `,"step_1_state":{"amount":${JSON.stringify(f.step1Amount)}}` +
    `,"step_2_state":{"amount":${JSON.stringify(f.step2Amount)}}` +
    `,"previous_step_1_state_signature":${JSON.stringify(f.prevStep1)}` +
    `,"previous_step_2_state_signature":${JSON.stringify(f.prevStep2)}` +
    `,"expiry__unix_time_secs":${JSON.stringify(expiry)}` +
    `,"message":${JSON.stringify(f.message)}}`
  );
}

function defaultLocated(overrides: Partial<LocatedReceive> = {}): LocatedReceive {
  const receiver = ed25519Pair();
  const baseT0 = {
    S0: "", // genesis
    // Distinct non-empty P0 so a mistaken P0-comparison cannot accidentally equal S0.
    P0: realSig("default-p0-must-not-compare"),
    B0: "0",
    observationId: "obs-receiver-t0-1",
  };
  const { receiverT0: t0Override, ...rest } = overrides;
  return {
    operationId: OP_ID,
    amountZkz: AMOUNT,
    discriminator: OP_ID,
    anchor: ANCHOR,
    expiryUnixTimeSecs: EXPIRY,
    receiverPubkey: receiver.publicKey,
    receiverWalletId: "55555555-5555-4555-8555-555555555555",
    state: "READY",
    armed: true,
    attentionRequired: false,
    leaseOwned: true,
    ...rest,
    receiverT0: { ...baseT0, ...(t0Override ?? {}) },
  };
}

interface Scenario {
  readonly sender: { publicKey: string; privateKey: KeyObject };
  readonly receiverPubkey: string;
  readonly located: LocatedReceive;
  readonly senderHeadS: string;
  readonly senderHeadB: string;
  readonly innerText: string;
  readonly step1Signature: string;
  readonly request: CandidateIntakeRequest;
}

function buildHappyScenario(opts: {
  readonly located?: LocatedReceive;
  readonly step1Amount?: string;
  readonly step2Amount?: string;
  readonly prevStep1?: string;
  readonly prevStep2?: string;
  readonly senderHeadS?: string;
  readonly senderHeadB?: string;
  readonly message?: string;
  readonly innerMutator?: (text: string) => string;
  readonly signWith?: KeyObject;
} = {}): Scenario {
  const sender = ed25519Pair();
  const located = opts.located ?? defaultLocated();
  // Ensure receiver pubkey on located matches what we put in the inner.
  const receiverPubkey = located.receiverPubkey;
  const message = opts.message ?? buildReceiveMessage(located.discriminator, located.anchor);
  const prevStep2 = opts.prevStep2 ?? located.receiverT0.S0;
  const senderHeadS = opts.senderHeadS ?? "";
  const prevStep1 = opts.prevStep1 ?? senderHeadS;
  const step1Amount = opts.step1Amount ?? "7.75"; // B_sender_after = 7.75; head B = 10 → delta 2.25
  const step2Amount = opts.step2Amount ?? "2.25"; // B0=0 + 2.25
  const senderHeadB = opts.senderHeadB ?? "10";

  let innerText = buildInnerText({
    senderPubkey: sender.publicKey,
    receiverPubkey,
    step1Amount,
    step2Amount,
    prevStep1,
    prevStep2,
    message,
  });
  if (opts.innerMutator) innerText = opts.innerMutator(innerText);

  const step1Signature = signText(opts.signWith ?? sender.privateKey, innerText);
  const request: CandidateIntakeRequest = {
    locate: {
      receiverPubkey,
      discriminator: located.discriminator,
      expiry: located.expiryUnixTimeSecs,
    },
    inner_preimage_text: innerText,
    step_1_signature: step1Signature,
  };
  return {
    sender,
    receiverPubkey,
    located,
    senderHeadS,
    senderHeadB,
    innerText,
    step1Signature,
    request,
  };
}

function makeDeps(scenario: Scenario, overrides: {
  readonly locateImpl?: LocateReceivePort;
  readonly observeImpl?: SenderPreflightObserver;
  readonly signer?: CandidateIntakeSignerProbe;
  readonly persist?: ReturnType<typeof createInMemoryCandidatePersistPort>;
  readonly capture?: ReturnType<typeof createInMemoryRawCapturePort>;
  readonly clockMs?: number;
} = {}): {
  readonly deps: CandidateIntakeDeps;
  readonly persist: ReturnType<typeof createInMemoryCandidatePersistPort>;
  readonly capture: ReturnType<typeof createInMemoryRawCapturePort>;
  readonly observeCalls: Array<{ pubkey: string; role: string }>;
  readonly parseOrder: string[];
} {
  const clock = createFixedClock(overrides.clockMs ?? NOW_MS);
  const capture = overrides.capture ?? createInMemoryRawCapturePort(clock);
  const persist = overrides.persist ?? createInMemoryCandidatePersistPort();
  const observeCalls: Array<{ pubkey: string; role: string }> = [];
  const parseOrder: string[] = [];

  // Instrument capture to record ordering relative to JSON.parse.
  const instrumentedCapture = {
    ...capture,
    port: {
      captureRaw: async (input: { innerPreimageText: string; step1Signature: string }) => {
        parseOrder.push("capture");
        return capture.port.captureRaw(input);
      },
    },
  };

  const locate: LocateReceivePort = overrides.locateImpl ?? {
    async locate() {
      return scenario.located;
    },
    async recheck() {
      return scenario.located;
    },
  };

  const observeSender: SenderPreflightObserver = overrides.observeImpl ?? {
    async observe(pubkey, role) {
      observeCalls.push({ pubkey, role });
      parseOrder.push("observe");
      const obs: SenderPreflightObservation = {
        kind: "VERIFIED",
        observationId: "obs-sender-preflight-1",
        S: scenario.senderHeadS,
        P: "",
        B: scenario.senderHeadB,
      };
      return obs;
    },
  };

  // Wrap persist to note ordering
  const instrumentedPersist: typeof persist.port = {
    async claimAndPersist(input) {
      parseOrder.push("persist");
      return persist.port.claimAndPersist(input);
    },
  };

  return {
    deps: {
      locate,
      capture: instrumentedCapture.port,
      observeSender,
      persist: instrumentedPersist,
      clock,
      signer: overrides.signer,
    },
    persist,
    capture,
    observeCalls,
    parseOrder,
  };
}

async function expectReject(
  service: ReturnType<typeof createCandidateIntakeService>,
  request: CandidateIntakeRequest,
  reason: string,
  persist: ReturnType<typeof createInMemoryCandidatePersistPort>,
  observeCalls: Array<unknown>,
  opts: { readonly expectObserve?: boolean } = {},
): Promise<void> {
  const observeBefore = observeCalls.length;
  const rowsBefore = persist.rows.size;
  await expect(service.intake(request)).rejects.toMatchObject({
    name: "CandidateIntakeError",
    reason,
  });
  expect(persist.rows.size).toBe(rowsBefore);
  if (opts.expectObserve === false) {
    expect(observeCalls.length).toBe(observeBefore);
  }
}

// ── Contract surface ────────────────────────────────────────────────────────────────────────

describe("candidate-intake contract surface", () => {
  it("freezes capture fields and phase literal", () => {
    expect(CANDIDATE_CAPTURE_FIELDS).toEqual(["inner_preimage_text", "step_1_signature"]);
    expect(CANDIDATE_INTAKE_PHASE).toBe("STEP1_SIGNATURE_PERSISTED");
    expect(RECEIVE_SENDER_PREFLIGHT_ROLE).toBe("RECEIVE_SENDER_PREFLIGHT");
  });
});

// ── Happy path ──────────────────────────────────────────────────────────────────────────────

describe("candidate-intake happy path", () => {
  it("accepts a valid candidate, persists at STEP1_SIGNATURE_PERSISTED, never signs", async () => {
    const scenario = buildHappyScenario();
    const signerCalls: string[] = [];
    const signer: CandidateIntakeSignerProbe = {
      async sign(id) {
        signerCalls.push(id);
        throw new Error("signer must not be called");
      },
    };
    const { deps, persist, capture, observeCalls, parseOrder } = makeDeps(scenario, { signer });
    // Intercept JSON.parse to prove capture-before-parse.
    const realParse = JSON.parse;
    const parseSpy = vi.spyOn(JSON, "parse").mockImplementation((text: string, reviver?) => {
      parseOrder.push("json_parse");
      return realParse(text, reviver);
    });

    const service = createCandidateIntakeService(deps);
    const result = await service.intake(scenario.request);

    parseSpy.mockRestore();

    expect(result.ok).toBe(true);
    expect(result.attemptPhase).toBe("STEP1_SIGNATURE_PERSISTED");
    expect(result.operationId).toBe(OP_ID);
    expect(result.innerPreimageText).toBe(scenario.innerText);
    expect(result.step1Signature).toBe(scenario.step1Signature);
    expect(result.innerSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(result.validationManifest.receiver_link_compared_to).toBe("S0");
    expect(result.validationManifest.receiver_link_compared_to_p0).toBe(false);
    expect(result.senderObservationId).toBe("obs-sender-preflight-1");

    expect(persist.rows.size).toBe(1);
    expect(persist.rows.get(OP_ID)?.attemptPhase).toBe("STEP1_SIGNATURE_PERSISTED");
    expect(persist.rows.get(OP_ID)?.validationManifest.receiver_link_compared_to).toBe("S0");

    expect(capture.records).toHaveLength(1);
    expect(capture.records[0]!.innerPreimageText).toBe(scenario.innerText);

    expect(observeCalls).toEqual([
      { pubkey: scenario.sender.publicKey, role: "RECEIVE_SENDER_PREFLIGHT" },
    ]);
    expect(signerCalls).toEqual([]);

    // Capture runs strictly before JSON.parse.
    const captureIdx = parseOrder.indexOf("capture");
    const parseIdx = parseOrder.indexOf("json_parse");
    expect(captureIdx).toBeGreaterThanOrEqual(0);
    expect(parseIdx).toBeGreaterThan(captureIdx);
  });

  it("runs sender-preflight observation only after local checks (ordering)", async () => {
    // Bad schema must never reach observe.
    const scenario = buildHappyScenario({
      innerMutator: () => `{"type":"nope"}`,
    });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "BAD_SCHEMA", persist, observeCalls, {
      expectObserve: false,
    });
  });
});

// ── Exhaustive negative vectors ─────────────────────────────────────────────────────────────

describe("candidate-intake negative vectors (zero DB-TX write, zero signer)", () => {
  it("rejects OPERATION_NOT_FOUND", async () => {
    const scenario = buildHappyScenario();
    const { deps, persist, observeCalls } = makeDeps(scenario, {
      locateImpl: {
        async locate() {
          return null;
        },
        async recheck() {
          return null;
        },
      },
    });
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "OPERATION_NOT_FOUND", persist, observeCalls, {
      expectObserve: false,
    });
  });

  it("rejects UNARMED operation", async () => {
    const located = defaultLocated({ armed: false });
    const scenario = buildHappyScenario({ located });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "UNARMED", persist, observeCalls, {
      expectObserve: false,
    });
  });

  it("rejects NOT_READY on recheck", async () => {
    const located = defaultLocated({ state: "READY" });
    const scenario = buildHappyScenario({ located });
    const { deps, persist, observeCalls } = makeDeps(scenario, {
      locateImpl: {
        async locate() {
          return located;
        },
        async recheck() {
          return { ...located, state: "CREATED" };
        },
      },
    });
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "NOT_READY", persist, observeCalls);
  });

  // the payer builds the partial with its OWN expiry; it does not echo the one the
  // node put in the transfer code. Observed live: node issued 1785470676, a real wallet returned
  // 1785470688 (12s later), and intake rejected a correctly-paid receive. The node's own frozen
  // expiry is the only authority; the payer's value must not be an identity key or a match target.
  it("accepts when the payer's inner expiry differs from the node's issued expiry", async () => {
    for (const payerExpiry of [
      String(Number(EXPIRY) + 12), // later than ours — the live failure
      String(Number(EXPIRY) - 12), // earlier than ours
    ]) {
      const located = defaultLocated();
      const scenario = buildHappyScenario({
        located,
        innerMutator: (text) =>
          text.replace(
            `"expiry__unix_time_secs":${JSON.stringify(EXPIRY)}`,
            `"expiry__unix_time_secs":${JSON.stringify(payerExpiry)}`,
          ),
      });
      const { deps } = makeDeps(scenario);
      const service = createCandidateIntakeService(deps);
      const result = await service.intake(scenario.request);
      expect(result.ok, `payer expiry ${payerExpiry} must be accepted`).toBe(true);
      // Byte-exactness (the byte-exact signing rule): what is captured for co-signing is the payer's exact
      // inner text, including the payer's own expiry — never a value the node substituted.
      expect(result.innerPreimageText).toBe(scenario.innerText);
      expect(result.innerPreimageText).toContain(
        `"expiry__unix_time_secs":${JSON.stringify(payerExpiry)}`,
      );
    }
  });

  it("rejects EXPIRED operation", async () => {
    const located = defaultLocated({ expiryUnixTimeSecs: "1000" }); // far in the past
    const scenario = buildHappyScenario({ located });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "EXPIRED", persist, observeCalls, {
      expectObserve: false,
    });
  });

  it("rejects ATTENTION_SET on recheck", async () => {
    const located = defaultLocated();
    const scenario = buildHappyScenario({ located });
    const { deps, persist, observeCalls } = makeDeps(scenario, {
      locateImpl: {
        async locate() {
          return located;
        },
        async recheck() {
          return { ...located, attentionRequired: true };
        },
      },
    });
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "ATTENTION_SET", persist, observeCalls);
  });

  it("rejects LEASE_NOT_OWNED on recheck", async () => {
    const located = defaultLocated();
    const scenario = buildHappyScenario({ located });
    const { deps, persist, observeCalls } = makeDeps(scenario, {
      locateImpl: {
        async locate() {
          return located;
        },
        async recheck() {
          return { ...located, leaseOwned: false };
        },
      },
    });
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "LEASE_NOT_OWNED", persist, observeCalls);
  });

  it("rejects MALFORMED_PREIMAGE (invalid JSON)", async () => {
    const scenario = buildHappyScenario();
    const request = { ...scenario.request, inner_preimage_text: "not-json{{{" };
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, request, "MALFORMED_PREIMAGE", persist, observeCalls, {
      expectObserve: false,
    });
  });

  it("rejects BAD_SCHEMA (wrong type/version)", async () => {
    const scenario = buildHappyScenario({
      innerMutator: (t) => t.replace('"unique_combinable"', '"other_type"'),
    });
    // Re-sign is unnecessary — schema fails before sig. But keep original sig so sig isn't the fail.
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "BAD_SCHEMA", persist, observeCalls, {
      expectObserve: false,
    });
  });

  it("rejects BAD_SCHEMA (non-grammar string unix_time_secs) — zero DB write", async () => {
    // Field 3: foreign UnixTimeSecsV2 grammar; "not-a-unix-time" must not reach STEP1.
    const scenario = buildHappyScenario({
      innerMutator: (t) => t.replace('"unix_time_secs":"1700000000"', '"unix_time_secs":"not-a-unix-time"'),
    });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "BAD_SCHEMA", persist, observeCalls, {
      expectObserve: false,
    });
    expect(persist.rows.size).toBe(0);
  });

  it("rejects BAD_SCHEMA (number unix_time_secs) — zero DB write", async () => {
    // JSON number is wrong_type vs UnixTimeSecsV2 string grammar (shared narrowSplitChainInner).
    const scenario = buildHappyScenario({
      innerMutator: (t) => t.replace('"unix_time_secs":"1700000000"', '"unix_time_secs":1700000000'),
    });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "BAD_SCHEMA", persist, observeCalls, {
      expectObserve: false,
    });
    expect(persist.rows.size).toBe(0);
  });

  it("rejects BAD_SCHEMA (non-string step amount) as CandidateIntakeError — not TypeError", async () => {
    // contracts inspectForeignAmount throws TypeError on non-string; shared narrow uses
    // inspectForeignSignedAmount (returns NON_STRING) so intake stays CandidateIntakeError.
    const scenario = buildHappyScenario({
      innerMutator: (t) => t.replace('"step_1_state":{"amount":"7.75"}', '"step_1_state":{"amount":7.75}'),
    });
    const signerCalls: string[] = [];
    const signer: CandidateIntakeSignerProbe = {
      async sign(id) {
        signerCalls.push(id);
        throw new Error("signer must not be called");
      },
    };
    const { deps, persist, observeCalls } = makeDeps(scenario, { signer });
    const service = createCandidateIntakeService(deps);
    try {
      await service.intake(scenario.request);
      expect.unreachable("should reject");
    } catch (e) {
      expect(e).toBeInstanceOf(CandidateIntakeError);
      expect((e as CandidateIntakeError).reason).toBe("BAD_SCHEMA");
      expect(e).not.toBeInstanceOf(TypeError);
    }
    expect(persist.rows.size).toBe(0);
    expect(observeCalls).toHaveLength(0);
    expect(signerCalls).toHaveLength(0);
  });

  it("rejects WRONG_KEY_ROLE (step_1_signer not sender)", async () => {
    const scenario = buildHappyScenario({
      innerMutator: (t) => t.replace('"step_1_signer":"sender"', '"step_1_signer":"receiver"'),
    });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "WRONG_KEY_ROLE", persist, observeCalls, {
      expectObserve: false,
    });
  });

  it("rejects BAD_MESSAGE (wrong discriminator/anchor encoding)", async () => {
    const scenario = buildHappyScenario({
      message: "zp1:00000000-0000-4000-8000-000000000000:wrong_anchor",
    });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "BAD_MESSAGE", persist, observeCalls, {
      expectObserve: false,
    });
  });

  it("rejects MALFORMED_SIGNATURE (wrong-length encoding) — reachable, not collapsed to SIGNATURE_INVALID", async () => {
    const scenario = buildHappyScenario();
    const request = {
      ...scenario.request,
      step_1_signature: "!!!not-base64url!!!",
    };
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    try {
      await service.intake(request);
      expect.unreachable("should reject");
    } catch (e) {
      expect(e).toBeInstanceOf(CandidateIntakeError);
      expect((e as CandidateIntakeError).reason).toBe("MALFORMED_SIGNATURE");
    }
    expect(persist.rows.size).toBe(0);
    expect(observeCalls.length).toBe(0);
  });

  it("rejects MALFORMED_SIGNATURE (short base64url that decodes but is not 64 bytes)", async () => {
    const scenario = buildHappyScenario();
    // Valid base64url alphabet but wrong decoded length → parseEd25519Signature fails.
    const request = {
      ...scenario.request,
      step_1_signature: "c2hvcnQ=", // "short"
    };
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, request, "MALFORMED_SIGNATURE", persist, observeCalls, {
      expectObserve: false,
    });
  });

  it("rejects SIGNATURE_INVALID (signed by wrong key)", async () => {
    const wrong = ed25519Pair();
    const scenario = buildHappyScenario({ signWith: wrong.privateKey });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "SIGNATURE_INVALID", persist, observeCalls, {
      expectObserve: false,
    });
  });

  it("rejects RECEIVER_LINK_MISMATCH when previous_step_2 != S0", async () => {
    // Real encoding, content is NOT equal to S0 ("").
    const bogusLink = realSig("receiver-wrong-link");
    expect(bogusLink.length).toBe(88);
    const scenario = buildHappyScenario({ prevStep2: bogusLink });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "RECEIVER_LINK_MISMATCH", persist, observeCalls, {
      expectObserve: false,
    });
  });

  it("rejects RECEIVER_LINK_MISMATCH when a mistaken P0 comparison would have accepted (S0 rule)", async () => {
    // T0: S0 = settled head H, P0 = prior link L. Candidate carries previous = L (P0).
    // Correct rule (compare to S0) MUST reject. A P0-comparison bug would accept.
    const settledHead = realSig("settled-head-s0");
    const priorLink = realSig("prior-link-p0");
    expect(settledHead).not.toBe(priorLink);
    const located = defaultLocated({
      receiverT0: {
        S0: settledHead,
        P0: priorLink,
        B0: "0",
        observationId: "obs-t0",
      },
    });
    // Candidate links to P0 (the v1 defect) rather than S0.
    const scenario = buildHappyScenario({ located, prevStep2: priorLink });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "RECEIVER_LINK_MISMATCH", persist, observeCalls, {
      expectObserve: false,
    });
    // And the happy path with S0 still works under the same T0.
    const good = buildHappyScenario({ located, prevStep2: settledHead });
    const goodDeps = makeDeps(good);
    const goodService = createCandidateIntakeService(goodDeps.deps);
    const ok = await goodService.intake(good.request);
    expect(ok.validationManifest.receiver_link_compared_to).toBe("S0");
    expect(ok.validationManifest.receiver_link_compared_to_p0).toBe(false);
  });

  it("rejects RECEIVER_DELTA_MISMATCH (wrong step_2 amount)", async () => {
    const scenario = buildHappyScenario({ step2Amount: "9.99" });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(service, scenario.request, "RECEIVER_DELTA_MISMATCH", persist, observeCalls, {
      expectObserve: false,
    });
  });

  it("rejects SENDER_PREFLIGHT_INDETERMINATE", async () => {
    const scenario = buildHappyScenario();
    const { deps, persist, observeCalls } = makeDeps(scenario, {
      observeImpl: {
        async observe(pubkey, role) {
          observeCalls.push({ pubkey, role });
          return { kind: "INDETERMINATE", detail: "gateway timeout" };
        },
      },
    });
    const service = createCandidateIntakeService(deps);
    await expectReject(
      service,
      scenario.request,
      "SENDER_PREFLIGHT_INDETERMINATE",
      persist,
      observeCalls,
    );
  });

  it("rejects SENDER_PREFLIGHT_LINK_MISMATCH", async () => {
    const scenario = buildHappyScenario({
      senderHeadS: "",
      prevStep1: realSig("sender-wrong-prev"),
    });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(
      service,
      scenario.request,
      "SENDER_PREFLIGHT_LINK_MISMATCH",
      persist,
      observeCalls,
    );
  });

  it("rejects SENDER_PREFLIGHT_DELTA_MISMATCH", async () => {
    // head B=10, step1 amount=7.75 → delta 2.25 OK normally; set head B wrong.
    const scenario = buildHappyScenario({ senderHeadB: "5" });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(
      service,
      scenario.request,
      "SENDER_PREFLIGHT_DELTA_MISMATCH",
      persist,
      observeCalls,
    );
  });

  it("rejects ALREADY_CLAIMED (second candidate after a winner)", async () => {
    const first = buildHappyScenario();
    const { deps, persist } = makeDeps(first);
    const service = createCandidateIntakeService(deps);
    await service.intake(first.request);
    expect(persist.rows.size).toBe(1);

    const second = buildHappyScenario({ located: first.located });
    // Same locate/persist — second must lose the unique slot.
    const secondService = createCandidateIntakeService({
      ...deps,
      // fresh capture/observe still fine; shared persist enforces single-winner
    });
    await expect(secondService.intake(second.request)).rejects.toMatchObject({
      reason: "ALREADY_CLAIMED",
    });
    expect(persist.rows.size).toBe(1);
  });
});

// ── Amount-bound (canonical ZKZ amount contract) ────────────────────────────────────────────────────────────────────

describe("candidate-intake amount bounds (canonical ZKZ amount contract)", () => {
  it("accepts genesis/zero balance in non-amount_zkz candidate fields", async () => {
    // Sender head B = amount (swept-to-exact), step1 amount = "0" (post-state zero).
    // Delta: 2.25 - 0 = 2.25. Receiver B0="0" is already the happy-path genesis case.
    const scenario = buildHappyScenario({
      step1Amount: "0",
      senderHeadB: AMOUNT,
    });
    const { deps, persist } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    const result = await service.intake(scenario.request);
    expect(result.ok).toBe(true);
    expect(persist.rows.size).toBe(1);
  });

  it("rejects zero operation.amount_zkz (PositiveZkzAmount)", async () => {
    const located = defaultLocated({ amountZkz: "0" });
    const scenario = buildHappyScenario({
      located,
      step2Amount: "0",
      step1Amount: "10",
      senderHeadB: "10",
    });
    const { deps, persist, observeCalls } = makeDeps(scenario);
    const service = createCandidateIntakeService(deps);
    await expectReject(
      service,
      scenario.request,
      "INVALID_OPERATION_AMOUNT",
      persist,
      observeCalls,
      { expectObserve: false },
    );
  });
});

// ── Single-winner concurrency ───────────────────────────────────────────────────────────────

describe("candidate-intake single-winner concurrency", () => {
  it("exactly one of two concurrent valid candidates reaches STEP1_SIGNATURE_PERSISTED", async () => {
    const located = defaultLocated();
    const a = buildHappyScenario({ located });
    const b = buildHappyScenario({ located });

    // Shared persist with a tiny serialization gap so both can race the has-check.
    type InMemoryPersisted = {
      operationId: string;
      attemptPhase: typeof CANDIDATE_INTAKE_PHASE;
    };
    let held: InMemoryPersisted | null = null;
    const gate = { resolvers: [] as Array<() => void>, open: false };
    const slowPersist = {
      rows: new Map<string, unknown>(),
      port: {
        async claimAndPersist(input: { operationId: string }) {
          // Wait until both callers have entered, then serialize.
          await new Promise<void>((resolve) => {
            gate.resolvers.push(resolve);
            if (gate.resolvers.length >= 2) {
              for (const r of gate.resolvers) r();
              gate.open = true;
            }
          });
          if (held !== null) {
            return { ok: false as const, reason: "ALREADY_CLAIMED" as const };
          }
          held = { operationId: input.operationId, attemptPhase: CANDIDATE_INTAKE_PHASE };
          slowPersist.rows.set(input.operationId, held);
          return { ok: true as const, attemptPhase: CANDIDATE_INTAKE_PHASE };
        },
      },
    };

    const clock = createFixedClock(NOW_MS);
    const mk = (scenario: Scenario) => {
      const capture = createInMemoryRawCapturePort(clock);
      return createCandidateIntakeService({
        locate: {
          async locate() {
            return located;
          },
          async recheck() {
            return located;
          },
        },
        capture: capture.port,
        observeSender: {
          async observe() {
            return {
              kind: "VERIFIED",
              observationId: `obs-${scenario.sender.publicKey.slice(0, 8)}`,
              S: scenario.senderHeadS,
              P: "",
              B: scenario.senderHeadB,
            };
          },
        },
        persist: slowPersist.port as never,
        clock,
      });
    };

    const results = await Promise.allSettled([
      mk(a).intake(a.request),
      mk(b).intake(b.request),
    ]);

    const resolved = results.filter((r) => r.status === "fulfilled"); // contract-allow:fulfilled:Promise.allSettled status literal (ECMAScript), not settlement vocabulary
    const rejected = results.filter((r) => r.status === "rejected");
    expect(resolved).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect((resolved[0] as PromiseFulfilledResult<{ attemptPhase: string }>).value.attemptPhase).toBe(
      "STEP1_SIGNATURE_PERSISTED",
    );
    expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({
      reason: "ALREADY_CLAIMED",
    });
    expect(slowPersist.rows.size).toBe(1);
  });
});

// Silence unused import warning for createPrivateKey/createPublicKey if tree-shaken differently.
void createPrivateKey;
void createPublicKey;
