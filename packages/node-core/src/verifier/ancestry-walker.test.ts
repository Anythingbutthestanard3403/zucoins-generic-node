// vectors for the any-depth ancestry walker.
//
// Every body here is signed with REAL Ed25519 over REAL signed bytes, built by the same
// byte sequence the node's own constructor emits (protocol/transactions.ts): inner is
// serialized once by JSON.stringify, step 1 signs that text, step 2 signs
// {"inner":<text>,"step_1_signature":<sig1>}, and the completed body is those three in
// the fixed top-level sequence. Nothing is hand-assembled and no signature is faked, so a test that
// expects PATH_PROVEN cannot pass by construction. Every retained column is DERIVED from
// the bytes by `retainedBody` below, so the negative vectors have to construct their
// disagreement explicitly — and each is asserted to turn the walk red and write nothing.
//
// Deterministic 32-byte filled seeds, as the frozen A.8.1 golden generator uses. Test
// keys only; nothing here is a node signing key (the key-custody rule).

import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";

import { describe, expect, it } from "vitest";

import { GENESIS_PROJECTION, type WalletStateProjection } from "../protocol/wallet-role.js";
import {
  InMemoryLineagePathProofStore,
  InMemoryRetainedPathBodySource,
  walkAncestryPath,
  type AncestryWalkInput,
  type AncestryWalkOutcome,
  type RetainedPathBody,
  type RetainedPathBodySource,
  type SuccessorResolution,
  type WalkOperation,
} from "./ancestry-walker.js";
import { parseGatewayEnvelope } from "./gateway-envelope.js";
import type { FreshHeadRead, ReadFreshHead } from "./landing-path-oracle.js";
import { computeWalletHeadFingerprint, verifySettledTransaction } from "./transaction-verify.js";

// --- test-only Ed25519 -----------------------------------------------------------------

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function paddedBase64Url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
}

interface Party {
  readonly publicKey: string;
  readonly privateKey: KeyObject;
}

function partyFromSeedByte(seedByte: number): Party {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  // The 44-byte SPKI export is a 12-byte header followed by the raw 32-byte key.
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return { publicKey: paddedBase64Url(spki.subarray(12)), privateKey };
}

function signText(text: string, privateKey: KeyObject): string {
  return paddedBase64Url(sign(null, Buffer.from(text, "utf8"), privateKey));
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const octets = (text: string): number => new TextEncoder().encode(text).byteLength;

// --- real signed SplitChain v2 bodies ----------------------------------------------------

interface BuiltBody {
  readonly text: string;
  readonly innerText: string;
  readonly stepOneSignature: string;
  readonly stepTwoSignature: string;
}

// The fixed top-level sequence. The verifier reconstructs exactly this from the parsed
// object, so a fixture that assembles its bytes any other way would fail the byte gate for
// the wrong reason.
function completedText(innerText: string, stepOneSignature: string, stepTwoSignature: string): string {
  return (
    `{"inner":${innerText}` +
    `,"step_1_signature":${JSON.stringify(stepOneSignature)}` +
    `,"step_2_signature":${JSON.stringify(stepTwoSignature)}}`
  );
}

const stepTwoPreimageText = (innerText: string, stepOneSignature: string): string =>
  `{"inner":${innerText},"step_1_signature":${JSON.stringify(stepOneSignature)}}`;

function buildBody(args: {
  readonly sender: Party;
  readonly receiver: Party;
  readonly unixTimeSecs: string;
  readonly senderPostBalance: string;
  readonly receiverPostBalance: string;
  readonly previousSenderStateSignature: string;
  readonly previousReceiverStateSignature: string;
}): BuiltBody {
  // Protocol positions 1-12, inserted in their exact sequence. JSON.stringify emits that
  // sequence, and that text is the preimage both signatures are taken over.
  const inner = {
    type: "unique_combinable",
    version: "2",
    unix_time_secs: args.unixTimeSecs,
    signer_steps: 2,
    step_1_signer: "sender",
    step_2_signer: "receiver",
    step_1_key_public__base64urlsafe: args.sender.publicKey,
    step_2_key_public__base64urlsafe: args.receiver.publicKey,
    step_1_state: { amount: args.senderPostBalance },
    step_2_state: { amount: args.receiverPostBalance },
    previous_step_1_state_signature: args.previousSenderStateSignature,
    previous_step_2_state_signature: args.previousReceiverStateSignature,
  };

  const innerText = JSON.stringify(inner);
  const stepOneSignature = signText(innerText, args.sender.privateKey);
  const stepTwoSignature = signText(
    stepTwoPreimageText(innerText, stepOneSignature),
    args.receiver.privateKey,
  );
  return {
    text: completedText(innerText, stepOneSignature, stepTwoSignature),
    innerText,
    stepOneSignature,
    stepTwoSignature,
  };
}

/**
 * A retained lineage row whose every column is DERIVED from the exact body text, through
 * the same verifier the walker uses. A fixture therefore cannot accidentally supply a
 * column the bytes disagree with; the tests that want that disagreement spread over the
 * result and override one field explicitly.
 */
function retainedBody(
  bodyText: string,
  walletPublicKey: string,
  observationId: string,
  sourceKind: RetainedPathBody["source_kind"],
): RetainedPathBody {
  const parsed = JSON.parse(bodyText) as Parameters<typeof verifySettledTransaction>[0];
  const verdict = verifySettledTransaction(parsed, walletPublicKey);
  if (verdict.verdict !== "VERIFIED") throw new Error(`fixture body did not verify: ${verdict.verdict}`);
  const { role, S, P, B } = verdict.projection;
  if (role !== "sender" && role !== "receiver") throw new Error("fixture body has no wallet role");
  return {
    source_kind: sourceKind,
    observation_id: observationId,
    wallet_public_key: walletPublicKey,
    completed_transaction_text: bodyText,
    completed_transaction_sha256: verdict.completedTransactionSha256,
    completed_transaction_octets: octets(bodyText),
    wallet_role: role,
    s_signature: S,
    p_signature: P,
    b_amount: B,
    inner_preimage_text: verdict.innerPreimageText,
    inner_sha256: sha256Hex(verdict.innerPreimageText),
    step_1_signature: parsed.step_1_signature,
    step_2_signature: parsed.step_2_signature,
    semantic_fingerprint: verdict.semanticFingerprint,
  };
}

/** The role-relative projection of one genuine body, for a counterparty leg's T0 baseline. */
function projectionOf(bodyText: string, walletPublicKey: string): WalletStateProjection {
  const parsed = JSON.parse(bodyText) as Parameters<typeof verifySettledTransaction>[0];
  const verdict = verifySettledTransaction(parsed, walletPublicKey);
  if (verdict.verdict !== "VERIFIED") throw new Error(`fixture body did not verify: ${verdict.verdict}`);
  return verdict.projection;
}

interface ParsedFixtureInner {
  readonly step_1_key_public__base64urlsafe: string;
  readonly step_1_state: { readonly amount: string };
  readonly step_2_state: { readonly amount: string };
  readonly previous_step_1_state_signature: string;
  readonly previous_step_2_state_signature: string;
}

/**
 * Every lineage column derived from a body's exact bytes WITHOUT routing through
 * `verifySettledTransaction` — the only way to build a retained row for a body whose
 * signatures do not verify, since `retainedBody` throws on one.
 *
 * This is what isolates "both Ed25519 signatures" clause. A signature-forgery fixture
 * that reuses a genuine body's columns is rejected by whichever column the mutation moved
 * (the A.7 fingerprint covers both step signatures), so the signature check never runs. Here
 * S/P/B, the inner preimage and digest, both step signatures and the fingerprint are all
 * recomputed over the MUTATED text, leaving the Ed25519 verification as the only
 * disagreement the walker can find.
 *
 * S is `step_2_signature` in either role; P and B are the role-relative fields.
 */
function unverifiedRetainedBody(
  bodyText: string,
  walletPublicKey: string,
  observationId: string,
  sourceKind: RetainedPathBody["source_kind"],
): RetainedPathBody {
  const parsed = JSON.parse(bodyText) as {
    inner: ParsedFixtureInner;
    step_1_signature: string;
    step_2_signature: string;
  };
  const innerText = JSON.stringify(parsed.inner);
  const innerSha256 = sha256Hex(innerText);
  const isSender = parsed.inner.step_1_key_public__base64urlsafe === walletPublicKey;
  const role = isSender ? "sender" : "receiver";
  const sSignature = parsed.step_2_signature;
  const pSignature = isSender
    ? parsed.inner.previous_step_1_state_signature
    : parsed.inner.previous_step_2_state_signature;
  const bAmount = (isSender ? parsed.inner.step_1_state : parsed.inner.step_2_state).amount;
  return {
    source_kind: sourceKind,
    observation_id: observationId,
    wallet_public_key: walletPublicKey,
    completed_transaction_text: bodyText,
    completed_transaction_sha256: sha256Hex(bodyText),
    completed_transaction_octets: octets(bodyText),
    wallet_role: role,
    s_signature: sSignature,
    p_signature: pSignature,
    b_amount: bAmount,
    inner_preimage_text: innerText,
    inner_sha256: innerSha256,
    step_1_signature: parsed.step_1_signature,
    step_2_signature: parsed.step_2_signature,
    semantic_fingerprint: computeWalletHeadFingerprint({
      walletPublicKey,
      stateKind: "HEAD",
      sSignature,
      pSignature,
      bAmount,
      innerSha256,
      step1Signature: parsed.step_1_signature,
      step2Signature: parsed.step_2_signature,
    }),
  };
}

// --- the fixture chain -------------------------------------------------------------------
//
// W is the queried wallet. From genesis it is credited 10 ZKZ by a payer, then spends
// twice, so its role-view runs receiver -> sender -> sender and the head sits two hops past
// the expected body. That is the buried-landing shape exists for.

const WALLET = partyFromSeedByte(0x11);
const PAYER = partyFromSeedByte(0x22);
const PAYEE_ONE = partyFromSeedByte(0x33);
const PAYEE_TWO = partyFromSeedByte(0x44);
const STRANGER = partyFromSeedByte(0x55);

// A grammar-valid predecessor pointer for a counterparty whose own history is outside this
// fixture's role-view and is never walked here.
const FOREIGN_PRIOR_STATE = paddedBase64Url(Buffer.alloc(64, 0x07));

// T1 — the expected RECEIVE_EXTERNAL body: W is credited 10 from a genesis baseline.
const T1 = buildBody({
  sender: PAYER,
  receiver: WALLET,
  unixTimeSecs: "1784332800",
  senderPostBalance: "90",
  receiverPostBalance: "10",
  previousSenderStateSignature: FOREIGN_PRIOR_STATE,
  previousReceiverStateSignature: "",
});

// T2 — W spends 3; its role-relative P is T1's S.
const T2 = buildBody({
  sender: WALLET,
  receiver: PAYEE_ONE,
  unixTimeSecs: "1784332900",
  senderPostBalance: "7",
  receiverPostBalance: "3",
  previousSenderStateSignature: T1.stepTwoSignature,
  previousReceiverStateSignature: "",
});

// T3 — W spends 3 more; its role-relative P is T2's S. T3 is the fresh head.
const T3 = buildBody({
  sender: WALLET,
  receiver: PAYEE_TWO,
  unixTimeSecs: "1784333000",
  senderPostBalance: "4",
  receiverPostBalance: "3",
  previousSenderStateSignature: T2.stepTwoSignature,
  previousReceiverStateSignature: "",
});

// A body W is not party to at all — neither step-1 nor step-2 key is W.
const UNRELATED = buildBody({
  sender: PAYER,
  receiver: STRANGER,
  unixTimeSecs: "1784333100",
  senderPostBalance: "80",
  receiverPostBalance: "10",
  previousSenderStateSignature: T1.stepTwoSignature,
  previousReceiverStateSignature: "",
});

// --- signature-isolating forgeries -------------------------------------------------------
//
// Two versions of T2 whose ONLY defect is an Ed25519 signature. Each is signed by the wrong
// key over the right preimage, so it is well-formed base64url of the right length and dies
// only at the verification itself. Each gets a genuine successor built on the forgery's own
// S (= its step_2_signature), so the backlink still closes and the walk reaches the
// real head — the signature check is therefore the sole barrier, not the chain shape.

// Step 2 forged: PAYEE_ONE is T2's step-2 signer, STRANGER is not.
const T2_FORGED_STEP_TWO_SIGNATURE = signText(
  stepTwoPreimageText(T2.innerText, T2.stepOneSignature),
  STRANGER.privateKey,
);
const T2_STEP_TWO_FORGED = completedText(
  T2.innerText,
  T2.stepOneSignature,
  T2_FORGED_STEP_TWO_SIGNATURE,
);

// Step 1 forged: WALLET is T2's step-1 signer, STRANGER is not. Step 2 is then genuinely
// re-signed by PAYEE_ONE over the MUTATED step-2 preimage, so step 2 verifies and only the
// step-1 check can reject.
const T2_FORGED_STEP_ONE_SIGNATURE = signText(T2.innerText, STRANGER.privateKey);
const T2_STEP_ONE_FORGED_STEP_TWO_SIGNATURE = signText(
  stepTwoPreimageText(T2.innerText, T2_FORGED_STEP_ONE_SIGNATURE),
  PAYEE_ONE.privateKey,
);
const T2_STEP_ONE_FORGED = completedText(
  T2.innerText,
  T2_FORGED_STEP_ONE_SIGNATURE,
  T2_STEP_ONE_FORGED_STEP_TWO_SIGNATURE,
);

// Genuine heads that continue W's chain from each forgery's state signature.
const T3_AFTER_STEP_TWO_FORGERY = buildBody({
  sender: WALLET,
  receiver: PAYEE_TWO,
  unixTimeSecs: "1784333000",
  senderPostBalance: "4",
  receiverPostBalance: "3",
  previousSenderStateSignature: T2_FORGED_STEP_TWO_SIGNATURE,
  previousReceiverStateSignature: "",
});

const T3_AFTER_STEP_ONE_FORGERY = buildBody({
  sender: WALLET,
  receiver: PAYEE_TWO,
  unixTimeSecs: "1784333000",
  senderPostBalance: "4",
  receiverPostBalance: "3",
  previousSenderStateSignature: T2_STEP_ONE_FORGED_STEP_TWO_SIGNATURE,
  previousReceiverStateSignature: "",
});

// --- the MOVE_INTERNAL fixture -----------------------------------------------------------
//
// One dual-signed transaction between two independently leased wallets. W moves 4
// ZKZ from its T1 baseline (B=10) to MOVE_DEST, which is at genesis (S="", B="0"). The two
// baselines are deliberately DIFFERENT, so a leg that evaluated its delta against the other
// leg's baseline cannot pass.

const MOVE_DEST = partyFromSeedByte(0x66);

const MOVE = buildBody({
  sender: WALLET,
  receiver: MOVE_DEST,
  unixTimeSecs: "1784333200",
  senderPostBalance: "6",
  receiverPostBalance: "4",
  previousSenderStateSignature: T1.stepTwoSignature,
  previousReceiverStateSignature: "",
});

const RECEIVE_OPERATION: WalkOperation = {
  kind: "RECEIVE_EXTERNAL",
  amountZkz: "10",
  receiverPubkey: WALLET.publicKey,
};

const MOVE_SOURCE_OPERATION: WalkOperation = {
  kind: "MOVE_INTERNAL",
  leg: "SOURCE",
  amountZkz: "4",
  sourcePubkey: WALLET.publicKey,
  destinationPubkey: MOVE_DEST.publicKey,
  counterpartyWalletPublicKey: MOVE_DEST.publicKey,
  counterpartyBaseline: GENESIS_PROJECTION,
};

const MOVE_DESTINATION_OPERATION: WalkOperation = {
  kind: "MOVE_INTERNAL",
  leg: "DESTINATION",
  amountZkz: "4",
  sourcePubkey: WALLET.publicKey,
  destinationPubkey: MOVE_DEST.publicKey,
  counterpartyWalletPublicKey: WALLET.publicKey,
  counterpartyBaseline: projectionOf(T1.text, WALLET.publicKey),
};

const T1_EXPECTED = (): RetainedPathBody =>
  retainedBody(T1.text, WALLET.publicKey, "obs-t1", "EXPECTED_OPERATION");
const T2_BODY = (): RetainedPathBody =>
  retainedBody(T2.text, WALLET.publicKey, "obs-t2", "CANONICAL_LEDGER");
const T3_BODY = (): RetainedPathBody =>
  retainedBody(T3.text, WALLET.publicKey, "obs-t3", "FRESH_GATEWAY_HEAD");

function headRead(bodyText: string, observationId: string): FreshHeadRead {
  return {
    observationId,
    envelope: parseGatewayEnvelope(
      new TextEncoder().encode(
        `{"status":true,"code":"success","message":"","data":[${bodyText}]}`,
      ),
    ),
  };
}

function staticReader(bodyText: string, observationId = "obs-head"): ReadFreshHead {
  return () => Promise.resolve(headRead(bodyText, observationId));
}

function movingReader(first: string, then: string): ReadFreshHead {
  let calls = 0;
  return () => {
    calls += 1;
    return Promise.resolve(headRead(calls === 1 ? first : then, `obs-head-${calls}`));
  };
}

function genesisReader(): ReadFreshHead {
  return () =>
    Promise.resolve({
      observationId: "obs-genesis-head",
      envelope: parseGatewayEnvelope(
        new TextEncoder().encode(
          `{"status":false,"code":"account_not_found","message":"none","data":null}`,
        ),
      ),
    });
}

function baseInput(overrides: Partial<AncestryWalkInput> = {}): AncestryWalkInput {
  return {
    pathProofId: "11111111-1111-4111-8111-111111111111",
    landingProofId: "22222222-2222-4222-8222-222222222222",
    walletId: null,
    walletPublicKey: WALLET.publicKey,
    operation: RECEIVE_OPERATION,
    expectedBody: T1_EXPECTED(),
    baseline: { kind: "GENESIS", observation_id: "obs-t0" },
    ...overrides,
  };
}

function sourceWith(...bodies: readonly RetainedPathBody[]): InMemoryRetainedPathBodySource {
  const source = new InMemoryRetainedPathBodySource();
  for (const body of bodies) source.put(body);
  return source;
}

async function walk(
  input: AncestryWalkInput,
  source: RetainedPathBodySource,
  reader: ReadFreshHead,
): Promise<{ outcome: AncestryWalkOutcome; store: InMemoryLineagePathProofStore }> {
  const store = new InMemoryLineagePathProofStore();
  return { outcome: await walkAncestryPath(input, source, reader, store), store };
}

function expectFault(outcome: AncestryWalkOutcome, fault: string): void {
  expect(outcome.kind).toBe("PROOF_INCOMPLETE");
  if (outcome.kind !== "PROOF_INCOMPLETE") return;
  expect(outcome.fault).toBe(fault);
}

// --- positive paths ----------------------------------------------------------------------

describe("walkAncestryPath — proven paths", () => {
  it("proves depth 0 when the expected body IS the fresh head", async () => {
    const { outcome, store } = await walk(baseInput(), sourceWith(), staticReader(T1.text, "obs-t1"));

    expect(outcome.kind).toBe("PATH_PROVEN");
    if (outcome.kind !== "PATH_PROVEN") return;
    expect(outcome.proof.kind).toBe("LANDED_EXACT");
    expect(outcome.proof.depth).toBe(0);
    expect(outcome.pathProof.body_count).toBe(1);
    expect(outcome.pathProof.path_depth).toBe(0);
    expect(outcome.pathProof.path_role).toBe("RECEIVER");
    expect(outcome.pathProof.expected_completed_transaction_sha256).toBe(sha256Hex(T1.text));
    expect(outcome.pathProof.fresh_head_completed_transaction_sha256).toBe(sha256Hex(T1.text));
    expect(store.written).toHaveLength(1);
    expect(store.written[0].bodies.map((b) => b.path_index)).toEqual([0]);
  });

  it("proves depth 1 across one intermediate hop", async () => {
    const { outcome } = await walk(baseInput(), sourceWith(T2_BODY()), staticReader(T2.text, "obs-t2"));

    expect(outcome.kind).toBe("PATH_PROVEN");
    if (outcome.kind !== "PATH_PROVEN") return;
    expect(outcome.proof.kind).toBe("LANDED_COMPLETE_PATH");
    expect(outcome.pathProof.body_count).toBe(2);
    expect(outcome.pathProof.path_depth).toBe(1);
  });

  it("proves depth 2 and persists the ordered lineage rows", async () => {
    const { outcome, store } = await walk(
      baseInput(),
      sourceWith(T2_BODY(), T3_BODY()),
      staticReader(T3.text, "obs-t3"),
    );

    expect(outcome.kind).toBe("PATH_PROVEN");
    if (outcome.kind !== "PATH_PROVEN") return;
    expect(outcome.pathProof.body_count).toBe(3);
    // CHECK (path_depth = body_count - 1).
    expect(outcome.pathProof.path_depth).toBe(outcome.pathProof.body_count - 1);
    expect(outcome.pathProof.fresh_head_observation_id).toBe("obs-t3");
    expect(outcome.pathProof.t0_observation_id).toBe("obs-t0");

    const [written] = store.written;
    expect(written.proof).toEqual(outcome.pathProof);
    // Body 0 is the exact expected completed transaction; body n is the fresh head.
    expect(written.bodies.map((b) => b.path_index)).toEqual([0, 1, 2]);
    expect(written.bodies[0].completed_transaction_text).toBe(T1.text);
    expect(written.bodies[2].completed_transaction_text).toBe(T3.text);
    expect(written.bodies.map((b) => b.wallet_role)).toEqual(["receiver", "sender", "sender"]);
    expect(written.bodies.map((b) => b.source_kind)).toEqual([
      "EXPECTED_OPERATION",
      "CANONICAL_LEDGER",
      "FRESH_GATEWAY_HEAD",
    ]);
    for (const body of written.bodies) {
      expect(body.path_proof_id).toBe(outcome.pathProof.id);
      expect(sha256Hex(body.completed_transaction_text)).toBe(body.completed_transaction_sha256);
      expect(sha256Hex(body.inner_preimage_text)).toBe(body.inner_sha256);
      expect(sha256Hex(body.verification_manifest_text)).toBe(body.verification_manifest_sha256);
      expect(body.completed_transaction_octets).toBe(octets(body.completed_transaction_text));
    }
    // Adjacent bodies satisfy P(W,T[i]) == S(W,T[i-1]) in the persisted rows too.
    expect(written.bodies[1].p_signature).toBe(written.bodies[0].s_signature);
    expect(written.bodies[2].p_signature).toBe(written.bodies[1].s_signature);
  });

  it("freezes the per-body manifest tuple in its exact key sequence", async () => {
    const { outcome } = await walk(baseInput(), sourceWith(), staticReader(T1.text, "obs-t1"));
    expect(outcome.kind).toBe("PATH_PROVEN");
    if (outcome.kind !== "PATH_PROVEN") return;

    // The manifest tuple: "(path_index, body digest, byte length, S, P, B, role, per-body verification
    // digest)". A reordering here breaks independent re-derivation of the digest.
    expect(Object.keys(JSON.parse(outcome.bodies[0].verification_manifest_text) as object)).toEqual([
      "path_index",
      "completed_transaction_sha256",
      "completed_transaction_octets",
      "s_signature",
      "p_signature",
      "b_amount",
      "wallet_role",
      "inner_sha256",
    ]);
  });

  it("re-derives the T0 baseline from a real prior head rather than a stored balance", async () => {
    // W's baseline is T1 (B=10) and the expected body is T2, a 3 ZKZ external send.
    const sendOperation: WalkOperation = {
      kind: "SEND_EXTERNAL",
      amountZkz: "3",
      sourcePubkey: WALLET.publicKey,
      destinationAddress: PAYEE_ONE.publicKey,
    };
    const input = baseInput({
      operation: sendOperation,
      expectedBody: retainedBody(T2.text, WALLET.publicKey, "obs-t2", "EXPECTED_OPERATION"),
      baseline: { kind: "HEAD", body: T1_EXPECTED() },
    });

    const { outcome } = await walk(input, sourceWith(T3_BODY()), staticReader(T3.text, "obs-t3"));

    expect(outcome.kind).toBe("PATH_PROVEN");
    if (outcome.kind !== "PATH_PROVEN") return;
    expect(outcome.pathProof.path_role).toBe("SOURCE");
    expect(outcome.pathProof.path_depth).toBe(1);
    expect(outcome.pathProof.t0_observation_id).toBe("obs-t1");
  });

  it("rejects a T0 baseline body whose columns disagree with its bytes", async () => {
    const input = baseInput({
      operation: {
        kind: "SEND_EXTERNAL",
        amountZkz: "3",
        sourcePubkey: WALLET.publicKey,
        destinationAddress: PAYEE_ONE.publicKey,
      },
      expectedBody: retainedBody(T2.text, WALLET.publicKey, "obs-t2", "EXPECTED_OPERATION"),
      baseline: { kind: "HEAD", body: { ...T1_EXPECTED(), b_amount: "10.000000001" } },
    });

    const { outcome, store } = await walk(input, sourceWith(T3_BODY()), staticReader(T3.text, "obs-t3"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });
});

// --- break each property, one at a time --------------------------------------------------

describe("walkAncestryPath — per-hop landing-path oracle verification", () => {
  it("rejects a forged Ed25519 signature on an intermediate body", async () => {
    // T2 carrying T3's step-2 signature: shape, scalars, digest, octets and every derived
    // column still line up against the mutated text — only the signature does not verify.
    const marker = ',"step_2_signature":"';
    const start = T2.text.indexOf(marker) + marker.length;
    const forgedText =
      T2.text.slice(0, start) + T3.stepTwoSignature + T2.text.slice(T2.text.indexOf('"', start));
    expect(forgedText).not.toBe(T2.text);

    const genuine = T2_BODY();
    const forged: RetainedPathBody = {
      ...genuine,
      completed_transaction_text: forgedText,
      completed_transaction_sha256: sha256Hex(forgedText),
      completed_transaction_octets: octets(forgedText),
      step_2_signature: T3.stepTwoSignature,
      s_signature: T3.stepTwoSignature,
    };
    const { outcome, store } = await walk(baseInput(), sourceWith(forged), staticReader(forgedText, "obs-forged"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("rejects an intermediate body whose step-2 signature alone does not verify", async () => {
    // "both Ed25519 signatures", step 2, isolated. Every retained column is derived
    // from the forged text by `unverifiedRetainedBody` — including the A.7 fingerprint,
    // which covers both step signatures and is what makes a naive forgery fixture die at a
    // column bind instead of at the signature. The successor is a GENUINE body built on the
    // forgery's own state signature, so the backlink closes and the head is reached; the
    // step-2 verification is the only thing left that can refuse this path.
    const forged = unverifiedRetainedBody(
      T2_STEP_TWO_FORGED,
      WALLET.publicKey,
      "obs-t2-step2-forged",
      "CANONICAL_LEDGER",
    );
    expect(forged.s_signature).toBe(T2_FORGED_STEP_TWO_SIGNATURE);

    const head = retainedBody(
      T3_AFTER_STEP_TWO_FORGERY.text,
      WALLET.publicKey,
      "obs-t3f",
      "FRESH_GATEWAY_HEAD",
    );
    // The chain is otherwise sound: the genuine head's backlink closes on the forgery's S.
    expect(head.p_signature).toBe(forged.s_signature);

    const { outcome, store } = await walk(
      baseInput(),
      sourceWith(forged, head),
      staticReader(T3_AFTER_STEP_TWO_FORGERY.text, "obs-t3f"),
    );

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("rejects an intermediate body whose step-1 signature alone does not verify", async () => {
    // Same shape for step 1. Step 2 is genuinely re-signed by the real receiver over the
    // MUTATED step-2 preimage, so step 2 verifies and only the step-1 check can reject.
    const forged = unverifiedRetainedBody(
      T2_STEP_ONE_FORGED,
      WALLET.publicKey,
      "obs-t2-step1-forged",
      "CANONICAL_LEDGER",
    );
    expect(forged.step_1_signature).toBe(T2_FORGED_STEP_ONE_SIGNATURE);

    const head = retainedBody(
      T3_AFTER_STEP_ONE_FORGERY.text,
      WALLET.publicKey,
      "obs-t3f",
      "FRESH_GATEWAY_HEAD",
    );
    expect(head.p_signature).toBe(forged.s_signature);

    const { outcome, store } = await walk(
      baseInput(),
      sourceWith(forged, head),
      staticReader(T3_AFTER_STEP_ONE_FORGERY.text, "obs-t3f"),
    );

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("rejects a retained wallet_public_key column that is not the queried wallet", async () => {
    // The mirror of the wrong-role vector below: here the BYTES name W and every derived
    // column is W's, but the row files itself under a different wallet. A store that answers
    // W's probe with it anyway — a mis-scoped index, or a splice from another wallet's
    // role-view — is refused on the provenance column alone, before the bytes are parsed.
    const misScoped: RetainedPathBodySource = {
      resolveSuccessorByBacklink: () =>
        Promise.resolve<SuccessorResolution>({
          kind: "FOUND",
          body: { ...T2_BODY(), wallet_public_key: STRANGER.publicKey },
        }),
      countDistinctBodiesWithDigest: () => Promise.resolve(1),
    };
    const { outcome, store } = await walk(baseInput(), misScoped, staticReader(T2.text, "obs-t2"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("rejects a re-serialized body whose digest and octet columns both follow the reformatting", async () => {
    // One space after the opening brace, with the digest and octet columns recomputed over
    // the reformatted bytes. The byte gate at ancestry-walker.ts:402 rejects this vector
    // first (it precedes the digest bind at :409), but the digest bind is a redundant net
    // for the same vector, so removing either guard alone leaves this test green. It
    // therefore isolates neither; the test below isolates the byte gate by making the
    // digest bind pass (canonical digest + true reformatted octet count).
    const reformatted = T2.text.replace('{"inner":', '{ "inner":');
    expect(reformatted).not.toBe(T2.text);

    const body: RetainedPathBody = {
      ...T2_BODY(),
      completed_transaction_text: reformatted,
      completed_transaction_sha256: sha256Hex(reformatted),
      completed_transaction_octets: octets(reformatted),
    };
    const { outcome, store } = await walk(baseInput(), sourceWith(body), staticReader(reformatted, "obs-reformatted"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("rejects reformatted bytes carrying the canonical digest (the byte-exact signing rule, isolated)", async () => {
    // The vector the column binds cannot see: an attacker whose lineage columns are INTERNALLY
    // CONSISTENT. The text is reformatted, but `completed_transaction_sha256` is the digest
    // of the reconstruction (so the digest bind passes) and `completed_transaction_octets`
    // is the reformatted text's own true length (so the octet bind passes). Every other
    // column is derived from a parse that reformatting does not change. Only
    // `ancestry-walker.ts` "the reconstruction must BE the retained bytes" can reject this,
    // and if it is removed a path proof is minted over a body that is not the signed object.
    const reformatted = T2.text.replace('{"inner":', '{ "inner":');
    expect(reformatted).not.toBe(T2.text);

    const genuine = T2_BODY();
    const body: RetainedPathBody = {
      ...genuine,
      completed_transaction_text: reformatted,
      completed_transaction_sha256: genuine.completed_transaction_sha256,
      completed_transaction_octets: octets(reformatted),
    };
    // The two column binds this vector has to survive to reach the byte gate.
    expect(body.completed_transaction_sha256).toBe(sha256Hex(T2.text));
    expect(body.completed_transaction_octets).toBe(octets(reformatted));

    const { outcome, store } = await walk(baseInput(), sourceWith(body), staticReader(reformatted, "obs-head"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("rejects a duplicate top-level key whose retained digest column follows the smuggling", async () => {
    const smuggled = T2.text.replace(
      ',"step_2_signature":"',
      `,"step_2_signature":${JSON.stringify(T3.stepTwoSignature)},"step_2_signature":"`,
    );
    expect(smuggled).not.toBe(T2.text);

    const body: RetainedPathBody = {
      ...T2_BODY(),
      completed_transaction_text: smuggled,
      completed_transaction_sha256: sha256Hex(smuggled),
      completed_transaction_octets: octets(smuggled),
    };
    const { outcome, store } = await walk(baseInput(), sourceWith(body), staticReader(T2.text, "obs-t2"));

    expect(outcome.kind).toBe("PROOF_INCOMPLETE");
    expect(store.written).toHaveLength(0);
  });

  it("rejects a body whose top-level fields are out of the fixed sequence", async () => {
    const parsed = JSON.parse(T2.text) as Record<string, unknown>;
    const resequenced = JSON.stringify({
      inner: parsed.inner,
      step_2_signature: parsed.step_2_signature,
      step_1_signature: parsed.step_1_signature,
    });
    const body: RetainedPathBody = {
      ...T2_BODY(),
      completed_transaction_text: resequenced,
      completed_transaction_sha256: sha256Hex(resequenced),
      completed_transaction_octets: octets(resequenced),
    };
    const { outcome, store } = await walk(baseInput(), sourceWith(body), staticReader(T2.text, "obs-t2"));

    expectFault(outcome, "MALFORMED_BODY");
    expect(store.written).toHaveLength(0);
  });

  it("rejects a hop the queried wallet is not a party to (wrong role)", async () => {
    // Claim the row belongs to W's role-view; the signed bytes name neither key as W.
    const foreign = retainedBody(UNRELATED.text, PAYER.publicKey, "obs-unrelated", "CANONICAL_LEDGER");
    const body: RetainedPathBody = { ...foreign, wallet_public_key: WALLET.publicKey };
    const { outcome, store } = await walk(
      baseInput(),
      sourceWith(body),
      staticReader(UNRELATED.text, "obs-unrelated"),
    );

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("rejects a retained wallet_role column that disagrees with the re-derived role", async () => {
    // The bytes make W the sender of T2; the row claims receiver.
    const body: RetainedPathBody = { ...T2_BODY(), wallet_role: "receiver" };
    const { outcome, store } = await walk(baseInput(), sourceWith(body), staticReader(T2.text, "obs-t2"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it.each([
    ["b_amount", { b_amount: "9999" }],
    ["completed_transaction_sha256", { completed_transaction_sha256: "0".repeat(64) }],
    ["completed_transaction_octets", { completed_transaction_octets: 1 }],
    ["inner_preimage_text", { inner_preimage_text: '{"tampered":true}' }],
    ["inner_sha256", { inner_sha256: "1".repeat(64) }],
    ["step_1_signature", { step_1_signature: paddedBase64Url(Buffer.alloc(64, 0x09)) }],
    ["semantic_fingerprint", { semantic_fingerprint: "2".repeat(64) }],
  ])("rejects a retained %s that disagrees with the signed bytes", async (_column, override) => {
    const body: RetainedPathBody = { ...T2_BODY(), ...override };
    const { outcome, store } = await walk(baseInput(), sourceWith(body), staticReader(T2.text, "obs-t2"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("binds the A.7 fingerprint column to the queried wallet's own head material", () => {
    // Guards the fingerprint check above against being satisfiable by any wallet's digest.
    const body = T2_BODY();
    const strangerFingerprint = computeWalletHeadFingerprint({
      walletPublicKey: STRANGER.publicKey,
      stateKind: "HEAD",
      sSignature: body.s_signature,
      pSignature: body.p_signature,
      bAmount: body.b_amount,
      innerSha256: body.inner_sha256,
      step1Signature: body.step_1_signature,
      step2Signature: body.step_2_signature,
    });
    expect(strangerFingerprint).not.toBe(body.semantic_fingerprint);
  });

  it("rejects an expected body that fails the economic predicate against T0", async () => {
    // The chain is genuine; the operation claims 25 ZKZ where the body credits 10.
    const input = baseInput({
      operation: { kind: "RECEIVE_EXTERNAL", amountZkz: "25", receiverPubkey: WALLET.publicKey },
    });
    const { outcome, store } = await walk(input, sourceWith(T2_BODY()), staticReader(T2.text, "obs-t2"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("rejects an expected body bound to a different receiver than the operation", async () => {
    const input = baseInput({
      operation: { kind: "RECEIVE_EXTERNAL", amountZkz: "10", receiverPubkey: STRANGER.publicKey },
    });
    const { outcome } = await walk(input, sourceWith(T2_BODY()), staticReader(T2.text, "obs-t2"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
  });

  it("rejects a body 0 that is not the EXPECTED_OPERATION body", async () => {
    const input = baseInput({
      expectedBody: retainedBody(T1.text, WALLET.publicKey, "obs-t1", "PROOF_CHANNEL"),
    });
    const { outcome, store } = await walk(input, sourceWith(), staticReader(T1.text, "obs-t1"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });
});

// --- MOVE_INTERNAL: both legs of the one dual-signed transaction ---------------------------
//
// "MOVE_INTERNAL requires independently complete source and destination paths anchored
// to the same expected move body and both exact economic deltas." Each leg is its own walk,
// producing its own path_role. The two baselines differ (W is at T1/B=10, MOVE_DEST is at
// genesis/B=0), so a leg that evaluated its delta against the other leg's baseline — the
// inverted source/destination swap — cannot pass either test below.

describe("walkAncestryPath — MOVE_INTERNAL legs", () => {
  it("proves the SOURCE leg and stamps path_role SOURCE", async () => {
    const input = baseInput({
      operation: MOVE_SOURCE_OPERATION,
      expectedBody: retainedBody(MOVE.text, WALLET.publicKey, "obs-move", "EXPECTED_OPERATION"),
      baseline: { kind: "HEAD", body: T1_EXPECTED() },
    });
    const { outcome, store } = await walk(input, sourceWith(), staticReader(MOVE.text, "obs-move"));

    expect(outcome.kind).toBe("PATH_PROVEN");
    if (outcome.kind !== "PATH_PROVEN") return;
    expect(outcome.pathProof.path_role).toBe("SOURCE");
    expect(outcome.pathProof.wallet_public_key).toBe(WALLET.publicKey);
    // W is the step-1 sender of the move, so its role-view of the shared body is sender.
    expect(store.written[0].bodies[0].wallet_role).toBe("sender");
    expect(store.written[0].bodies[0].b_amount).toBe("6");
  });

  it("proves the DESTINATION leg of the same body and stamps path_role DESTINATION", async () => {
    const input = baseInput({
      walletPublicKey: MOVE_DEST.publicKey,
      operation: MOVE_DESTINATION_OPERATION,
      expectedBody: retainedBody(MOVE.text, MOVE_DEST.publicKey, "obs-move", "EXPECTED_OPERATION"),
      baseline: { kind: "GENESIS", observation_id: "obs-dest-t0" },
    });
    const { outcome, store } = await walk(input, sourceWith(), staticReader(MOVE.text, "obs-move"));

    expect(outcome.kind).toBe("PATH_PROVEN");
    if (outcome.kind !== "PATH_PROVEN") return;
    expect(outcome.pathProof.path_role).toBe("DESTINATION");
    expect(outcome.pathProof.wallet_public_key).toBe(MOVE_DEST.publicKey);
    // Same bytes, opposite role-view — the destination reads itself as the step-2 receiver.
    expect(store.written[0].bodies[0].completed_transaction_text).toBe(MOVE.text);
    expect(store.written[0].bodies[0].wallet_role).toBe("receiver");
    expect(store.written[0].bodies[0].b_amount).toBe("4");
  });

  it("refuses the SOURCE leg when handed the wrong counterparty baseline", async () => {
    // The destination is at genesis; this hands the source's own T1 baseline in as the
    // counterparty's. If the walker did not evaluate each leg against its OWN baseline the
    // move would still "prove", so this is the vector an inverted leg swap has to survive.
    const input = baseInput({
      operation: {
        ...MOVE_SOURCE_OPERATION,
        kind: "MOVE_INTERNAL",
        leg: "SOURCE",
        counterpartyBaseline: projectionOf(T1.text, WALLET.publicKey),
      },
      expectedBody: retainedBody(MOVE.text, WALLET.publicKey, "obs-move", "EXPECTED_OPERATION"),
      baseline: { kind: "HEAD", body: T1_EXPECTED() },
    });
    const { outcome, store } = await walk(input, sourceWith(), staticReader(MOVE.text, "obs-move"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("refuses a move leg whose amount does not match both exact deltas", async () => {
    const input = baseInput({
      operation: { ...MOVE_SOURCE_OPERATION, kind: "MOVE_INTERNAL", leg: "SOURCE", amountZkz: "5" },
      expectedBody: retainedBody(MOVE.text, WALLET.publicKey, "obs-move", "EXPECTED_OPERATION"),
      baseline: { kind: "HEAD", body: T1_EXPECTED() },
    });
    const { outcome, store } = await walk(input, sourceWith(), staticReader(MOVE.text, "obs-move"));

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });
});

describe("walkAncestryPath — path integrity", () => {
  it("reports GAP when a supplied successor's backlink does not close", async () => {
    // A store that answers the backlink probe with a body whose real P(W) is T2's S, not
    // T1's — the index says adjacent, the signed bytes say otherwise.
    const liar: RetainedPathBodySource = {
      resolveSuccessorByBacklink: () =>
        Promise.resolve<SuccessorResolution>({ kind: "FOUND", body: T3_BODY() }),
      countDistinctBodiesWithDigest: () => Promise.resolve(1),
    };
    const { outcome, store } = await walk(baseInput(), liar, staticReader(T3.text, "obs-t3"));

    expectFault(outcome, "GAP");
    expect(store.written).toHaveLength(0);
  });

  it("reports GAP when a supplied successor carries no backlink at all", async () => {
    // P(W) === "" is the genesis-position marker. A body claiming that position
    // can never be anyone's successor, so it is refused rather than treated as adjacent.
    const genesisPositioned = buildBody({
      sender: PAYER,
      receiver: WALLET,
      unixTimeSecs: "1784333300",
      senderPostBalance: "70",
      receiverPostBalance: "10",
      previousSenderStateSignature: FOREIGN_PRIOR_STATE,
      previousReceiverStateSignature: "",
    });
    const rootless = retainedBody(
      genesisPositioned.text,
      WALLET.publicKey,
      "obs-rootless",
      "PROOF_CHANNEL",
    );
    expect(rootless.p_signature).toBe("");

    const supplier: RetainedPathBodySource = {
      resolveSuccessorByBacklink: () =>
        Promise.resolve<SuccessorResolution>({ kind: "FOUND", body: rootless }),
      countDistinctBodiesWithDigest: () => Promise.resolve(1),
    };
    const { outcome, store } = await walk(
      baseInput(),
      supplier,
      staticReader(genesisPositioned.text, "obs-rootless"),
    );

    expectFault(outcome, "GAP");
    expect(store.written).toHaveLength(0);
  });

  it("reports DUPLICATE and terminates when the store rings a body already on the path", async () => {
    // The classic loop: the successor probe keeps returning a body already walked. A
    // walker without the seen-body guard never returns.
    let probes = 0;
    const ring: RetainedPathBodySource = {
      resolveSuccessorByBacklink: () => {
        probes += 1;
        return Promise.resolve<SuccessorResolution>({
          kind: "FOUND",
          body: retainedBody(T1.text, WALLET.publicKey, "obs-t1-again", "PROOF_CHANNEL"),
        });
      },
      countDistinctBodiesWithDigest: () => Promise.resolve(1),
    };
    const { outcome, store } = await walk(baseInput(), ring, staticReader(T3.text, "obs-t3"));

    expectFault(outcome, "DUPLICATE");
    expect(probes).toBe(1);
    expect(store.written).toHaveLength(0);
  });

  it("reports DUPLICATE when the same body is retained at two path positions", async () => {
    // T2 re-staged as if it were also T3's successor. The bytes are identical, so the
    // digest guard fires on the second sighting and the whole path is refused.
    let probes = 0;
    const restaging: RetainedPathBodySource = {
      resolveSuccessorByBacklink: () => {
        probes += 1;
        return Promise.resolve<SuccessorResolution>({
          kind: "FOUND",
          body: probes === 1 ? T2_BODY() : { ...T2_BODY(), observation_id: "obs-t2-restaged" },
        });
      },
      countDistinctBodiesWithDigest: () => Promise.resolve(1),
    };
    const { outcome, store } = await walk(baseInput(), restaging, staticReader(T3.text, "obs-t3"));

    expectFault(outcome, "DUPLICATE");
    expect(probes).toBe(2);
    expect(store.written).toHaveLength(0);
  });

  it("reports MISSING_BODY when an intermediate hop was never retained", async () => {
    // The head moved to T3 but only T3 is retained — T2 is the missing hop. There is no
    // lease anywhere in this call: "a lease is never evidence for missing chain
    // history" holds structurally here, not as a runtime branch.
    const { outcome, store } = await walk(baseInput(), sourceWith(T3_BODY()), staticReader(T3.text, "obs-t3"));

    expectFault(outcome, "MISSING_BODY");
    expect(store.written).toHaveLength(0);
  });

  it("reports CONFLICT when two distinct bodies claim the same predecessor", async () => {
    const source = sourceWith(T2_BODY());
    const fork = retainedBody(UNRELATED.text, PAYER.publicKey, "obs-fork", "PROOF_CHANNEL");
    source.put({ ...fork, wallet_public_key: WALLET.publicKey, p_signature: T1.stepTwoSignature });

    const { outcome } = await walk(baseInput(), source, staticReader(T2.text, "obs-t2"));

    expectFault(outcome, "CONFLICT");
  });

  it("reports CONFLICT when the digest index holds two distinct bodies for one digest", async () => {
    const colliding: RetainedPathBodySource = {
      resolveSuccessorByBacklink: () =>
        Promise.resolve<SuccessorResolution>({ kind: "FOUND", body: T2_BODY() }),
      countDistinctBodiesWithDigest: () => Promise.resolve(2),
    };
    const { outcome } = await walk(baseInput(), colliding, staticReader(T2.text, "obs-t2"));

    expectFault(outcome, "CONFLICT");
  });

  it("reports CONFLICT when the head moves during the verification window", async () => {
    const { outcome, store } = await walk(
      baseInput(),
      sourceWith(T2_BODY(), T3_BODY()),
      movingReader(T2.text, T3.text),
    );

    expectFault(outcome, "CONFLICT");
    expect(store.written).toHaveLength(0);
  });

  it("reports MISSING_BODY when the authoritative head reads genesis", async () => {
    const { outcome } = await walk(baseInput(), sourceWith(T2_BODY()), genesisReader());

    expectFault(outcome, "MISSING_BODY");
  });
});

describe("walkAncestryPath — configured budgets fail closed", () => {
  it("exhausts the depth budget rather than truncating to a shorter path", async () => {
    const { outcome, store } = await walk(
      baseInput({ maxPathDepth: 1 }),
      sourceWith(T2_BODY(), T3_BODY()),
      staticReader(T3.text, "obs-t3"),
    );

    expectFault(outcome, "BUDGET_EXHAUSTED");
    // The critical half: a truncated path is NOT quietly proven at depth 1.
    expect(store.written).toHaveLength(0);
  });

  it("exhausts the octet budget rather than truncating to a shorter path", async () => {
    const { outcome, store } = await walk(
      baseInput({ maxPathBodyOctets: octets(T1.text) + 1 }),
      sourceWith(T2_BODY(), T3_BODY()),
      staticReader(T3.text, "obs-t3"),
    );

    expectFault(outcome, "BUDGET_EXHAUSTED");
    expect(store.written).toHaveLength(0);
  });

  it("admits depth 0 but refuses the first hop when maxPathDepth is 0", async () => {
    // The budget's boundary in both directions: a zero-depth budget is not "no budget", and
    // an exact-head path is still provable under it.
    const { outcome: exhausted, store } = await walk(
      baseInput({ maxPathDepth: 0 }),
      sourceWith(T2_BODY()),
      staticReader(T2.text, "obs-t2"),
    );
    expectFault(exhausted, "BUDGET_EXHAUSTED");
    expect(store.written).toHaveLength(0);

    const { outcome: proven } = await walk(
      baseInput({ maxPathDepth: 0 }),
      sourceWith(),
      staticReader(T1.text, "obs-t1"),
    );
    expect(proven.kind).toBe("PATH_PROVEN");
  });

  it("still proves the same path when both budgets are exactly sufficient", async () => {
    const total = octets(T1.text) + octets(T2.text) + octets(T3.text);
    const { outcome } = await walk(
      baseInput({ maxPathDepth: 2, maxPathBodyOctets: total }),
      sourceWith(T2_BODY(), T3_BODY()),
      staticReader(T3.text, "obs-t3"),
    );

    expect(outcome.kind).toBe("PATH_PROVEN");
  });
});
