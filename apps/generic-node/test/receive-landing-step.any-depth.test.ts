// ZTR-1140 — RECEIVE any-depth landing proof wiring.
//
// Proves landOneReceive / resolveReceiveSuccessorBodies assemble successor bodies from a
// RetainedPathBodySource (not a hardcoded empty list) and drive proveReceiveLanding to a
// positive LANDED_COMPLETE_PATH when the retained path is complete — and fail closed to
// INDETERMINATE (REJECTED/PROOF_NOT_POSITIVE, lease untouched) on every incomplete class.
//
// Golden chain (seed_02): predecessor credits 10 ZKZ from genesis; target then spends 2.25
// with target.P == predecessor.S. Extra hops after target are signed with the same seeds as
// packages/node-core late-landing-reconcile tests.

import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

import {
  InMemoryReceiveLandingStore,
  InMemoryRetainedPathBodySource,
  parseGatewayEnvelope,
  verifySettledTransaction,
  type FreshHeadRead,
  type ParsedSettledTransaction,
  type ReadFreshHead,
  type RetainedPathBody,
} from "@zucoins/node-core";

import {
  landOneReceive,
  parseStoredSettledBody,
  resolveReceiveSuccessorBodies,
  retainedExpectedBodyFromSettledText,
  type ReceiveLandingCandidate,
} from "../src/money-workers/receive-landing-step.js";

const GEN_DIR = new URL(
  "../../../packages/generic-node-contracts/src/receive-golden/gen/",
  import.meta.url,
);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
};
const RECEIVER_KEY = MANIFEST.public_keys.seed_02 as string;
const DEST_KEY = MANIFEST.public_keys.seed_03 as string;

const PREDECESSOR_TEXT = fixtureText("predecessor.settled.json");
const TARGET_TEXT = fixtureText("target.settled.json");

const TERMINAL_OBS = "44444444-4444-4444-8444-444444444444";
const OPERATION_ID = "11111111-1111-4111-8111-111111111111";
const WALLET_ROW_ID = "22222222-2222-4222-8222-222222222222";
const T0_OBS = "33333333-3333-4333-8333-333333333333";

function headEnvelope(settledText: string, observationId = TERMINAL_OBS): FreshHeadRead {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
  );
  return { observationId, envelope: parseGatewayEnvelope(bytes) };
}

function parsedBody(settledText: string): ParsedSettledTransaction {
  const verdict = headEnvelope(settledText).envelope;
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD");
  return verdict.parsed;
}

const TARGET = parsedBody(TARGET_TEXT);

function staticReader(settledText: string): ReadFreshHead {
  return async () => headEnvelope(settledText);
}

function movingReader(first: string, rest: string): ReadFreshHead {
  let calls = 0;
  return async () => {
    calls += 1;
    return headEnvelope(calls === 1 ? first : rest);
  };
}

function withForeignStepTwoSignature(settledText: string, donorText: string): string {
  const marker = ',"step_2_signature":"';
  const donorStart = donorText.indexOf(marker) + marker.length;
  const donorSignature = donorText.slice(donorStart, donorText.indexOf('"', donorStart));
  const start = settledText.indexOf(marker) + marker.length;
  const end = settledText.indexOf('"', start);
  return settledText.slice(0, start) + donorSignature + settledText.slice(end);
}

const paddedBase64Url = (buf: Buffer): string =>
  buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

const keyFromSeed = (byte: number) => {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, byte),
  ]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
};

const signText = (text: string, privateKey: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(sign(null, Buffer.from(text, "utf8"), privateKey));

const seed02 = keyFromSeed(0x02);
const seed03 = keyFromSeed(0x03);

/** Hop after TARGET on seed_02's sender role-view (depth burial). */
function buildHop(prevStep2: string, amountOut: string, remaining: string, time: string) {
  const inner = {
    type: "unique_combinable" as const,
    version: "2" as const,
    unix_time_secs: time,
    signer_steps: 2 as const,
    step_1_signer: "sender" as const,
    step_2_signer: "receiver" as const,
    step_1_key_public__base64urlsafe: RECEIVER_KEY,
    step_2_key_public__base64urlsafe: DEST_KEY,
    step_1_state: { amount: remaining },
    step_2_state: { amount: amountOut },
    previous_step_1_state_signature: prevStep2,
    previous_step_2_state_signature: prevStep2,
  };
  const step1 = JSON.stringify(inner);
  const step1Sig = signText(step1, seed02);
  const step2Pre = JSON.stringify({ inner, step_1_signature: step1Sig });
  const step2Sig = signText(step2Pre, seed03);
  const text = JSON.stringify({
    inner,
    step_1_signature: step1Sig,
    step_2_signature: step2Sig,
  });
  return { text, body: parsedBody(text) };
}

const HOP3 = buildHop(TARGET.step_2_signature, "1.00", "6.75", "1784332900");
const HOP4 = buildHop(HOP3.body.step_2_signature, "0.50", "6.25", "1784332910");
const HOP5 = buildHop(HOP4.body.step_2_signature, "0.25", "6.00", "1784332920");

function retainedBody(
  bodyText: string,
  walletPublicKey: string,
  observationId: string,
  sourceKind: RetainedPathBody["source_kind"],
): RetainedPathBody {
  const parsed = JSON.parse(bodyText) as ParsedSettledTransaction;
  const verdict = verifySettledTransaction(parsed, walletPublicKey);
  if (verdict.verdict !== "VERIFIED") throw new Error(`fixture body did not verify: ${verdict.verdict}`);
  const { role, S, P, B } = verdict.projection;
  if (role !== "sender" && role !== "receiver") throw new Error("no role");
  return {
    source_kind: sourceKind,
    observation_id: observationId,
    wallet_public_key: walletPublicKey,
    completed_transaction_text: bodyText,
    completed_transaction_sha256: verdict.completedTransactionSha256,
    completed_transaction_octets: Buffer.byteLength(bodyText, "utf8"),
    wallet_role: role,
    s_signature: S,
    p_signature: P,
    b_amount: B,
    inner_preimage_text: verdict.innerPreimageText,
    inner_sha256: createHash("sha256")
      .update(verdict.innerPreimageText, "utf8")
      .digest("hex"),
    step_1_signature: parsed.step_1_signature,
    step_2_signature: parsed.step_2_signature,
    semantic_fingerprint: verdict.semanticFingerprint,
  };
}

function sourceWith(...bodies: readonly RetainedPathBody[]): InMemoryRetainedPathBodySource {
  const source = new InMemoryRetainedPathBodySource();
  for (const body of bodies) source.put(body);
  return source;
}

function candidate(overrides: Partial<ReceiveLandingCandidate> = {}): ReceiveLandingCandidate {
  return {
    operationId: OPERATION_ID,
    rowVersion: 1,
    amountZkz: "10",
    t0ObservationId: T0_OBS,
    receiverPublicKey: RECEIVER_KEY,
    expectedBodyText: PREDECESSOR_TEXT,
    t0BodyText: null,
    ...overrides,
  };
}

function seededStore(): InMemoryReceiveLandingStore {
  const store = new InMemoryReceiveLandingStore();
  store.seed(OPERATION_ID, "READY", WALLET_ROW_ID, 1);
  return store;
}

/** Fake pool — landOneReceive needs pool for SQL retained source default; tests inject InMemory. */
const FAKE_POOL = {
  query: async () => {
    throw new Error("fake pool must not be queried when retainedSource is injected");
  },
} as never;

const GENESIS_BASELINE = { kind: "GENESIS" as const, observation_id: T0_OBS };

describe("retainedExpectedBodyFromSettledText", () => {
  it("builds an EXPECTED_OPERATION row whose columns re-verify", () => {
    const body = retainedExpectedBodyFromSettledText(PREDECESSOR_TEXT, RECEIVER_KEY);
    expect(body).not.toBeNull();
    expect(body!.source_kind).toBe("EXPECTED_OPERATION");
    expect(body!.wallet_role).toBe("receiver");
    expect(body!.completed_transaction_text).toBe(PREDECESSOR_TEXT);
  });

  it("returns null for byte-normalized garbage", () => {
    expect(retainedExpectedBodyFromSettledText("{not-json", RECEIVER_KEY)).toBeNull();
  });
});

describe("resolveReceiveSuccessorBodies — any-depth (ZTR-1140)", () => {
  it("depth 0: expected is head → empty successors", async () => {
    const source = sourceWith(
      retainedBody(PREDECESSOR_TEXT, RECEIVER_KEY, "obs-pred", "EXPECTED_OPERATION"),
    );
    const result = await resolveReceiveSuccessorBodies(candidate(), {
      readFreshHead: staticReader(PREDECESSOR_TEXT),
      retainedSource: source,
      baseline: GENESIS_BASELINE,
    });
    expect(result).toEqual([]);
  });

  it("depth 1: buried under target → one successor body", async () => {
    const source = sourceWith(
      retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-target", "PROOF_CHANNEL"),
    );
    const result = await resolveReceiveSuccessorBodies(candidate(), {
      readFreshHead: staticReader(TARGET_TEXT),
      retainedSource: source,
      baseline: GENESIS_BASELINE,
    });
    expect(result).not.toBeNull();
    expect(result!).toHaveLength(1);
    expect(JSON.stringify(result![0])).toBe(TARGET_TEXT);
  });

  it("depth N>1: buried under HOP5 → complete ordered path of 4 successors", async () => {
    const source = sourceWith(
      retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL"),
      retainedBody(HOP3.text, RECEIVER_KEY, "obs-h3", "PROOF_CHANNEL"),
      retainedBody(HOP4.text, RECEIVER_KEY, "obs-h4", "PROOF_CHANNEL"),
      retainedBody(HOP5.text, RECEIVER_KEY, "obs-h5", "FRESH_GATEWAY_HEAD"),
    );
    const result = await resolveReceiveSuccessorBodies(candidate(), {
      readFreshHead: staticReader(HOP5.text),
      retainedSource: source,
      baseline: GENESIS_BASELINE,
    });
    expect(result).not.toBeNull();
    expect(result!).toHaveLength(4);
    expect(JSON.stringify(result![0])).toBe(TARGET_TEXT);
    expect(JSON.stringify(result![3])).toBe(HOP5.text);
  });

  it("MISSING_BODY when a hop is absent from retained storage", async () => {
    // Head is HOP5 but only TARGET is retained — walk cannot bridge.
    const source = sourceWith(
      retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL"),
    );
    const result = await resolveReceiveSuccessorBodies(candidate(), {
      readFreshHead: staticReader(HOP5.text),
      retainedSource: source,
      baseline: GENESIS_BASELINE,
    });
    expect(result).toBeNull();
  });

  it("GAP / incomplete path when a middle hop is missing", async () => {
    // TARGET → HOP5 with HOP3/HOP4 absent: backlink from HOP5 does not resolve from TARGET.
    const source = sourceWith(
      retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL"),
      retainedBody(HOP5.text, RECEIVER_KEY, "obs-h5", "FRESH_GATEWAY_HEAD"),
    );
    const result = await resolveReceiveSuccessorBodies(candidate(), {
      readFreshHead: staticReader(HOP5.text),
      retainedSource: source,
      baseline: GENESIS_BASELINE,
    });
    expect(result).toBeNull();
  });

  it("ANOMALOUS when a retained successor body has a forged step_2 signature", async () => {
    const forgedText = withForeignStepTwoSignature(TARGET_TEXT, PREDECESSOR_TEXT);
    // Stage under the genuine predecessor's S so the backlink probe finds it, but bytes fail verify.
    const genuine = retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL");
    const forged: RetainedPathBody = {
      ...genuine,
      observation_id: "obs-forged",
      completed_transaction_text: forgedText,
      // Keep columns from genuine so the only failure is Ed25519 on the mutated text —
      // verifyHop re-derives and rejects (false-accept guard).
    };
    const source = sourceWith(forged);
    const result = await resolveReceiveSuccessorBodies(candidate(), {
      readFreshHead: staticReader(TARGET_TEXT),
      retainedSource: source,
      baseline: GENESIS_BASELINE,
    });
    expect(result).toBeNull();
  });

  it("CONFLICT when the fresh head moves mid-walk", async () => {
    const source = sourceWith(
      retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL"),
    );
    const result = await resolveReceiveSuccessorBodies(candidate(), {
      readFreshHead: movingReader(TARGET_TEXT, PREDECESSOR_TEXT),
      retainedSource: source,
      baseline: GENESIS_BASELINE,
    });
    expect(result).toBeNull();
  });

  it("BUDGET_EXHAUSTED when maxPathDepth is below the required depth", async () => {
    const source = sourceWith(
      retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL"),
      retainedBody(HOP3.text, RECEIVER_KEY, "obs-h3", "PROOF_CHANNEL"),
    );
    // Depth needed = 2 (TARGET + HOP3); budget 1 → exhausted.
    const result = await resolveReceiveSuccessorBodies(
      candidate(),
      {
        readFreshHead: staticReader(HOP3.text),
        retainedSource: source,
        baseline: GENESIS_BASELINE,
      },
      1,
    );
    expect(result).toBeNull();
  });
});

describe("landOneReceive — any-depth commit (ZTR-1140)", () => {
  it("lands LANDED_COMPLETE_PATH at depth 1 with a complete retained path", async () => {
    const store = seededStore();
    const source = sourceWith(
      retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL"),
    );
    const outcome = await landOneReceive(
      candidate(),
      { pool: FAKE_POOL, readFreshHead: staticReader(TARGET_TEXT), store },
      { retainedSource: source, baseline: GENESIS_BASELINE },
    );
    expect(outcome.outcome).toBe("APPLIED");
    if (outcome.outcome !== "APPLIED") return;
    expect(outcome.proof.verdict).toBe("LANDED_COMPLETE_PATH");
    expect(outcome.proof.pathDepth).toBe(1);
    expect(outcome.path).toHaveLength(2);
    expect(outcome.receiverLeaseStillHeld).toBe(true);
    expect(store.leases.has(WALLET_ROW_ID)).toBe(true);
  });

  it("lands LANDED_COMPLETE_PATH at depth N>1 with a complete retained path", async () => {
    const store = seededStore();
    const source = sourceWith(
      retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL"),
      retainedBody(HOP3.text, RECEIVER_KEY, "obs-h3", "PROOF_CHANNEL"),
      retainedBody(HOP4.text, RECEIVER_KEY, "obs-h4", "PROOF_CHANNEL"),
      retainedBody(HOP5.text, RECEIVER_KEY, "obs-h5", "FRESH_GATEWAY_HEAD"),
    );
    const outcome = await landOneReceive(
      candidate(),
      { pool: FAKE_POOL, readFreshHead: staticReader(HOP5.text), store },
      { retainedSource: source, baseline: GENESIS_BASELINE },
    );
    expect(outcome.outcome).toBe("APPLIED");
    if (outcome.outcome !== "APPLIED") return;
    expect(outcome.proof.verdict).toBe("LANDED_COMPLETE_PATH");
    expect(outcome.proof.pathDepth).toBe(4);
    expect(outcome.path).toHaveLength(5);
    expect(outcome.receiverLeaseStillHeld).toBe(true);
  });

  it("depth 0 still lands LANDED_EXACT when head is the expected body", async () => {
    const store = seededStore();
    const source = new InMemoryRetainedPathBodySource();
    const outcome = await landOneReceive(
      candidate(),
      { pool: FAKE_POOL, readFreshHead: staticReader(PREDECESSOR_TEXT), store },
      { retainedSource: source, baseline: GENESIS_BASELINE },
    );
    expect(outcome.outcome).toBe("APPLIED");
    if (outcome.outcome !== "APPLIED") return;
    expect(outcome.proof.verdict).toBe("LANDED_EXACT");
    expect(outcome.proof.pathDepth).toBe(0);
  });

  it("INDETERMINATE (PROOF_NOT_POSITIVE) on missing body — lease held, nothing written", async () => {
    const store = seededStore();
    const source = new InMemoryRetainedPathBodySource(); // empty
    const outcome = await landOneReceive(
      candidate(),
      { pool: FAKE_POOL, readFreshHead: staticReader(TARGET_TEXT), store },
      { retainedSource: source, baseline: GENESIS_BASELINE },
    );
    expect(outcome).toMatchObject({
      outcome: "REJECTED",
      reason: "PROOF_NOT_POSITIVE",
    });
    expect(store.operations.get(OPERATION_ID)!.status).toBe("READY");
    expect(store.proofs).toHaveLength(0);
    expect(store.events).toHaveLength(0);
    expect(store.leases.has(WALLET_ROW_ID)).toBe(true);
  });

  it("INDETERMINATE on link gap — lease held", async () => {
    const store = seededStore();
    const source = sourceWith(
      retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL"),
      retainedBody(HOP5.text, RECEIVER_KEY, "obs-h5", "FRESH_GATEWAY_HEAD"),
    );
    const outcome = await landOneReceive(
      candidate(),
      { pool: FAKE_POOL, readFreshHead: staticReader(HOP5.text), store },
      { retainedSource: source, baseline: GENESIS_BASELINE },
    );
    expect(outcome).toMatchObject({ outcome: "REJECTED", reason: "PROOF_NOT_POSITIVE" });
    expect(store.leases.has(WALLET_ROW_ID)).toBe(true);
    expect(store.proofs).toHaveLength(0);
  });

  it("INDETERMINATE on anomalous/forged successor — false-accept guard", async () => {
    const store = seededStore();
    const forgedText = withForeignStepTwoSignature(TARGET_TEXT, PREDECESSOR_TEXT);
    const genuine = retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL");
    const source = sourceWith({
      ...genuine,
      observation_id: "obs-forged",
      completed_transaction_text: forgedText,
    });
    const outcome = await landOneReceive(
      candidate(),
      { pool: FAKE_POOL, readFreshHead: staticReader(TARGET_TEXT), store },
      { retainedSource: source, baseline: GENESIS_BASELINE },
    );
    expect(outcome).toMatchObject({ outcome: "REJECTED", reason: "PROOF_NOT_POSITIVE" });
    expect(store.leases.has(WALLET_ROW_ID)).toBe(true);
    expect(store.proofs).toHaveLength(0);
  });

  it("INDETERMINATE when fresh head moves mid-verification", async () => {
    const store = seededStore();
    const source = sourceWith(
      retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL"),
    );
    const outcome = await landOneReceive(
      candidate(),
      {
        pool: FAKE_POOL,
        readFreshHead: movingReader(TARGET_TEXT, PREDECESSOR_TEXT),
        store,
      },
      { retainedSource: source, baseline: GENESIS_BASELINE },
    );
    expect(outcome).toMatchObject({ outcome: "REJECTED", reason: "PROOF_NOT_POSITIVE" });
    expect(store.leases.has(WALLET_ROW_ID)).toBe(true);
  });

  it("INDETERMINATE on budget exhaustion", async () => {
    const store = seededStore();
    const source = sourceWith(
      retainedBody(TARGET_TEXT, RECEIVER_KEY, "obs-t", "PROOF_CHANNEL"),
      retainedBody(HOP3.text, RECEIVER_KEY, "obs-h3", "PROOF_CHANNEL"),
    );
    const outcome = await landOneReceive(
      candidate(),
      { pool: FAKE_POOL, readFreshHead: staticReader(HOP3.text), store },
      { retainedSource: source, baseline: GENESIS_BASELINE, maxPathDepth: 1 },
    );
    expect(outcome).toMatchObject({ outcome: "REJECTED", reason: "PROOF_NOT_POSITIVE" });
    expect(store.leases.has(WALLET_ROW_ID)).toBe(true);
    expect(store.proofs).toHaveLength(0);
  });

  it("INDETERMINATE releases nothing and retries nothing (no store side effects)", async () => {
    const store = seededStore();
    const releaseSpy = vi.spyOn(store, "commitLanding");
    const source = new InMemoryRetainedPathBodySource();
    const outcome = await landOneReceive(
      candidate(),
      { pool: FAKE_POOL, readFreshHead: staticReader(TARGET_TEXT), store },
      { retainedSource: source, baseline: GENESIS_BASELINE },
    );
    expect(outcome.outcome).toBe("REJECTED");
    // Fail-closed before commit: commitLanding is never invoked on an unprovable path.
    expect(releaseSpy).not.toHaveBeenCalled();
    expect(store.leases.has(WALLET_ROW_ID)).toBe(true);
  });
});

describe("parseStoredSettledBody still byte-exact", () => {
  it("round-trips the golden predecessor", () => {
    const body = parseStoredSettledBody(PREDECESSOR_TEXT);
    expect(body).not.toBeNull();
    expect(JSON.stringify(body)).toBe(PREDECESSOR_TEXT);
  });
});
