/**
 * send-non-landing-exclusion.test.ts
 *
 * The two live chain reads F1.2's close decision needs, and the much longer list of
 * situations in which it must decide nothing.
 *
 * Every body here is really signed with the golden Ed25519 seeds and really re-derived by
 * `verifyHop`, so a "positive" in this suite is a positive under the same per-hop gate the
 * landing walks use — never a hand-asserted flag.
 *
 * Appendix B §5.3.1 F1.2 / D9.6 (complete-path rule; no generic PROVEN_NOT_LANDED oracle).
 */
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  proveSendNonLanding,
  type SendNonLandingOutcome,
} from "../src/verifier/non-landing-exclusion.js";
import type {
  PathBaseline,
  RetainedPathBody,
  RetainedPathBodySource,
  SuccessorResolution,
} from "../src/verifier/ancestry-walker.js";
import { parseGatewayEnvelope } from "../src/verifier/gateway-envelope.js";
import type { FreshHeadRead, ReadFreshHead } from "../src/verifier/landing-path-oracle.js";
import { verifySettledTransaction } from "../src/verifier/transaction-verify.js";

const GEN_DIR = new URL("../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
};
const SOURCE = MANIFEST.public_keys.seed_02 as string;
const DEST = MANIFEST.public_keys.seed_03 as string;

const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");

const keyFromSeed = (byte: number) =>
  createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, byte),
    ]),
    format: "der",
    type: "pkcs8",
  });

const seed02 = keyFromSeed(0x02);
const seed03 = keyFromSeed(0x03);

const signText = (text: string, key: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(sign(null, Buffer.from(text, "utf8"), key));

function headRead(settledText: string, observationId = "obs-head"): FreshHeadRead {
  return {
    observationId,
    envelope: parseGatewayEnvelope(
      new TextEncoder().encode(
        `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
      ),
    ),
  };
}

function genesisRead(observationId = "obs-genesis"): FreshHeadRead {
  return {
    observationId,
    envelope: parseGatewayEnvelope(
      new TextEncoder().encode(`{"status":true,"code":"success","message":"","data":[]}`),
    ),
  };
}

/** One real sender-side hop, signed by both parties. */
function buildHop(previousStep2Signature: string, amountOut: string, remaining: string, time: string) {
  const inner = {
    type: "unique_combinable" as const,
    version: "2" as const,
    unix_time_secs: time,
    signer_steps: 2 as const,
    step_1_signer: "sender" as const,
    step_2_signer: "receiver" as const,
    step_1_key_public__base64urlsafe: SOURCE,
    step_2_key_public__base64urlsafe: DEST,
    step_1_state: { amount: remaining },
    step_2_state: { amount: amountOut },
    previous_step_1_state_signature: previousStep2Signature,
    previous_step_2_state_signature: previousStep2Signature,
  };
  const step1Signature = signText(JSON.stringify(inner), seed02);
  const step2Signature = signText(
    JSON.stringify({ inner, step_1_signature: step1Signature }),
    seed03,
  );
  return JSON.stringify({ inner, step_1_signature: step1Signature, step_2_signature: step2Signature });
}

/**
 * Promote signed bytes to the retained row shape by re-deriving every column from the bytes
 * themselves — the same derivation `verifyHop` re-runs, so a body built here is admissible
 * exactly when it is genuinely well-formed.
 */
function retained(text: string, observationId: string): RetainedPathBody {
  const verdict = verifySettledTransaction(
    (() => {
      const envelope = headRead(text).envelope;
      if (envelope.classification !== "HEAD") throw new Error("fixture is not a HEAD envelope");
      return envelope.parsed;
    })(),
    SOURCE,
  );
  if (verdict.verdict !== "VERIFIED") throw new Error(`fixture must verify: ${verdict.verdict}`);
  return {
    source_kind: "CANONICAL_LEDGER",
    observation_id: observationId,
    wallet_public_key: SOURCE,
    completed_transaction_text: verdict.completedTransactionText,
    completed_transaction_sha256: verdict.completedTransactionSha256,
    completed_transaction_octets: new TextEncoder().encode(verdict.completedTransactionText)
      .byteLength,
    wallet_role: verdict.projection.role as "sender" | "receiver",
    s_signature: verdict.projection.S,
    p_signature: verdict.projection.P,
    b_amount: verdict.projection.B,
    inner_preimage_text: verdict.innerPreimageText,
    inner_sha256: sha256Hex(verdict.innerPreimageText),
    step_1_signature: verdict.transaction.step_1_signature,
    step_2_signature: verdict.transaction.step_2_signature,
    semantic_fingerprint: verdict.semanticFingerprint,
  };
}

const stepOne = (body: RetainedPathBody): string => body.step_1_signature;

// A three-hop sender chain off genesis: T0 → H1 → H2. Our send is a fourth signature that
// exists nowhere on it.
const T0_TEXT = buildHop("", "1.00", "9.00", "1784332000");
const T0 = retained(T0_TEXT, "obs-t0");
const H1_TEXT = buildHop(T0.s_signature, "1.00", "8.00", "1784332100");
const H1 = retained(H1_TEXT, "obs-h1");
const H2_TEXT = buildHop(H1.s_signature, "1.00", "7.00", "1784332200");
const H2 = retained(H2_TEXT, "obs-h2");

// The send under adjudication: formed against T0 but never submitted by the recipient.
const OUR_SEND_TEXT = buildHop(T0.s_signature, "2.50", "6.50", "1784332300");
const OUR_SEND = retained(OUR_SEND_TEXT, "obs-ours");
const OUR_STEP1 = stepOne(OUR_SEND);

const T0_BASELINE: PathBaseline = { kind: "HEAD", body: T0 };

/** A retained source backed by an explicit backlink table. */
function sourceOf(
  bodies: readonly RetainedPathBody[],
  overrides: Partial<RetainedPathBodySource> = {},
): RetainedPathBodySource {
  return {
    async resolveSuccessorByBacklink(_wallet, previousStateSignature): Promise<SuccessorResolution> {
      const hit = bodies.find((b) => b.p_signature === previousStateSignature);
      return hit === undefined ? { kind: "NONE" } : { kind: "FOUND", body: hit };
    },
    async countDistinctBodiesWithDigest(): Promise<number> {
      return 1;
    },
    ...overrides,
  };
}

/** A head reader returning a fixed script of reads, one per call. */
function readsOf(...script: readonly FreshHeadRead[]): ReadFreshHead {
  let i = 0;
  return async () => script[Math.min(i++, script.length - 1)]!;
}

const indeterminateFault = (outcome: SendNonLandingOutcome): string =>
  outcome.kind === "INDETERMINATE" ? outcome.fault : `not indeterminate: ${outcome.kind}`;

describe("proveSendNonLanding — the two positives", () => {
  it("FRESH_HEAD_EQUALS_T0 when the source head is byte-identical to the recorded Ts0", async () => {
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      sourceOf([]),
      readsOf(headRead(T0_TEXT, "obs-a"), headRead(T0_TEXT, "obs-b")),
    );
    expect(outcome).toEqual({ kind: "FRESH_HEAD_EQUALS_T0", headObservationId: "obs-b" });
  });

  it("FRESH_HEAD_EQUALS_T0 on a genesis head under a genesis baseline", async () => {
    const outcome = await proveSendNonLanding(
      {
        walletPublicKey: SOURCE,
        baseline: { kind: "GENESIS", observation_id: "obs-t0" },
        step1Signature: OUR_STEP1,
      },
      sourceOf([]),
      readsOf(genesisRead("obs-a"), genesisRead("obs-b")),
    );
    expect(outcome).toEqual({ kind: "FRESH_HEAD_EQUALS_T0", headObservationId: "obs-b" });
  });

  it("COMPLETE_PATH_EXCLUSION when the head moved but our send is absent from the whole path", async () => {
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      sourceOf([H1, H2]),
      readsOf(headRead(H2_TEXT, "obs-a"), headRead(H2_TEXT, "obs-b")),
    );
    expect(outcome).toEqual({
      kind: "COMPLETE_PATH_EXCLUSION",
      headObservationId: "obs-b",
      depth: 2,
    });
  });
});

describe("proveSendNonLanding — a landed send is never an exclusion", () => {
  it("OWN_SEND_ON_PATH when our own send sits on the path to the head", async () => {
    const afterOurs = retained(
      buildHop(OUR_SEND.s_signature, "1.00", "5.50", "1784332400"),
      "obs-after",
    );
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      sourceOf([OUR_SEND, afterOurs]),
      readsOf(headRead(afterOurs.completed_transaction_text)),
    );
    expect(outcome).toEqual({
      kind: "OWN_SEND_ON_PATH",
      bodySha256: OUR_SEND.completed_transaction_sha256,
    });
  });

  it("OWN_SEND_ON_PATH when the head itself IS our send", async () => {
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      sourceOf([OUR_SEND]),
      readsOf(headRead(OUR_SEND_TEXT)),
    );
    expect(outcome).toMatchObject({ kind: "OWN_SEND_ON_PATH" });
  });

  it("OWN_SEND_ON_PATH when the recorded Ts0 baseline already IS our send", async () => {
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: { kind: "HEAD", body: OUR_SEND }, step1Signature: OUR_STEP1 },
      sourceOf([]),
      readsOf(headRead(OUR_SEND_TEXT)),
    );
    expect(outcome).toEqual({
      kind: "OWN_SEND_ON_PATH",
      bodySha256: OUR_SEND.completed_transaction_sha256,
    });
  });
});

describe("proveSendNonLanding — every refusal is INDETERMINATE", () => {
  it("budget exhaustion: the path is longer than the allowed depth", async () => {
    const outcome = await proveSendNonLanding(
      {
        walletPublicKey: SOURCE,
        baseline: T0_BASELINE,
        step1Signature: OUR_STEP1,
        maxPathDepth: 1,
      },
      sourceOf([H1, H2]),
      readsOf(headRead(H2_TEXT)),
    );
    expect(indeterminateFault(outcome)).toBe("BUDGET_EXHAUSTED");
  });

  it("budget exhaustion: the path's bytes exceed the allowed octets", async () => {
    const outcome = await proveSendNonLanding(
      {
        walletPublicKey: SOURCE,
        baseline: T0_BASELINE,
        step1Signature: OUR_STEP1,
        maxPathBodyOctets: 1,
      },
      sourceOf([H1, H2]),
      readsOf(headRead(H2_TEXT)),
    );
    expect(indeterminateFault(outcome)).toBe("BUDGET_EXHAUSTED");
  });

  it("budget exhaustion: a depth override above the default ceiling fails closed", async () => {
    const outcome = await proveSendNonLanding(
      {
        walletPublicKey: SOURCE,
        baseline: T0_BASELINE,
        step1Signature: OUR_STEP1,
        maxPathDepth: 1_000_000,
      },
      sourceOf([H1, H2]),
      readsOf(headRead(H2_TEXT)),
    );
    expect(indeterminateFault(outcome)).toBe("BUDGET_EXHAUSTED");
  });

  it("missing body: the retained path has a hole between Ts0 and the head", async () => {
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      sourceOf([H2]), // H1 absent — nothing backlinks to T0
      readsOf(headRead(H2_TEXT)),
    );
    expect(indeterminateFault(outcome)).toBe("MISSING_BODY");
  });

  it("link gap: a body that does not backlink to its predecessor", async () => {
    // H2 is served as T0's successor. Its P is H1's S, not T0's, so continuity fails.
    const gapped = sourceOf([], {
      async resolveSuccessorByBacklink(): Promise<SuccessorResolution> {
        return { kind: "FOUND", body: H2 };
      },
    });
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      gapped,
      readsOf(headRead(H2_TEXT)),
    );
    expect(indeterminateFault(outcome)).toBe("GAP");
  });

  it("anomaly: a retained body whose re-derived columns contradict its signed bytes", async () => {
    const tampered: RetainedPathBody = { ...H1, b_amount: "999.00" };
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      sourceOf([tampered, H2]),
      readsOf(headRead(H2_TEXT)),
    );
    expect(indeterminateFault(outcome)).toBe("ANOMALOUS_OR_CONTRADICTORY");
  });

  it("anomaly: a genesis head under a non-genesis Ts0 is the chain contradicting our baseline", async () => {
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      sourceOf([]),
      readsOf(genesisRead()),
    );
    expect(indeterminateFault(outcome)).toBe("ANOMALOUS_OR_CONTRADICTORY");
  });

  it("moved head: the head changes between the anchor read and the confirm read", async () => {
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      sourceOf([H1, H2]),
      readsOf(headRead(H2_TEXT, "obs-a"), headRead(H1_TEXT, "obs-b")),
    );
    expect(indeterminateFault(outcome)).toBe("CONFLICT");
  });

  it("moved head: an unchanged-head positive is withdrawn when the confirm read has moved on", async () => {
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      sourceOf([]),
      readsOf(headRead(T0_TEXT, "obs-a"), headRead(H1_TEXT, "obs-b")),
    );
    expect(indeterminateFault(outcome)).toBe("CONFLICT");
  });

  it("moved head: a genesis positive is withdrawn when the confirm read is no longer genesis", async () => {
    const outcome = await proveSendNonLanding(
      {
        walletPublicKey: SOURCE,
        baseline: { kind: "GENESIS", observation_id: "obs-t0" },
        step1Signature: OUR_STEP1,
      },
      sourceOf([]),
      readsOf(genesisRead("obs-a"), headRead(T0_TEXT, "obs-b")),
    );
    expect(indeterminateFault(outcome)).toBe("CONFLICT");
  });

  it("conflict: two distinct bodies share one digest on the path", async () => {
    const forked = sourceOf([H1, H2], {
      async countDistinctBodiesWithDigest(): Promise<number> {
        return 2;
      },
    });
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      forked,
      readsOf(headRead(H2_TEXT)),
    );
    expect(indeterminateFault(outcome)).toBe("CONFLICT");
  });

  it("conflict: an ambiguous successor is never a choice", async () => {
    const ambiguous = sourceOf([], {
      async resolveSuccessorByBacklink(): Promise<SuccessorResolution> {
        return { kind: "AMBIGUOUS" };
      },
    });
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: T0_BASELINE, step1Signature: OUR_STEP1 },
      ambiguous,
      readsOf(headRead(H2_TEXT)),
    );
    expect(indeterminateFault(outcome)).toBe("CONFLICT");
  });

  it("anomaly: a Ts0 baseline that does not itself verify decides nothing", async () => {
    const tamperedT0: RetainedPathBody = { ...T0, s_signature: "not-the-signed-value" };
    const outcome = await proveSendNonLanding(
      { walletPublicKey: SOURCE, baseline: { kind: "HEAD", body: tamperedT0 }, step1Signature: OUR_STEP1 },
      sourceOf([H1, H2]),
      readsOf(headRead(H2_TEXT)),
    );
    expect(indeterminateFault(outcome)).toBe("ANOMALOUS_OR_CONTRADICTORY");
  });
});
