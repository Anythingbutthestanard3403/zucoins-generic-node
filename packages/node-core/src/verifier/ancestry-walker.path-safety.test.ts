// path safety and resource bounds for the landing-path oracle landing oracle.
//
//
// own suite (ancestry-walker.test.ts) proves each landing-path oracle clause fires on a short
// path. This file proves the SAFETY and BOUNDS half: that the walk is total under an
// adversarial store, that every configured budget actually binds and fails closed rather
// than truncating, that the walk cost is O(depth) rather than O(retained bodies), that
// MOVE's two independently complete paths cannot be forged from one, and that the two
// signals it is most tempting to substitute for a missing body — a held lease and unbroken
// poll continuity — are structurally incapable of influencing the outcome.
//
// Every body is signed with REAL Ed25519 over REAL signed bytes by the same byte sequence
// the node's constructor emits, so no assertion here can pass by construction of its own
// fixture. Deterministic filled 32-byte seeds; test keys only, never a node signing key
// (the key-custody rule). All amounts are ZKZ.
//
// Not covered here, deliberately: there is no real-Postgres arm. The lineage schema's
// `operation_landing_proofs` / `lineage_path_proofs` / `lineage_path_bodies` DDL is
// deferred to, and observation-ledger-parent.rollup.test.ts asserts on main that the
// assembled schema does NOT contain those CREATE TABLE statements. The constraints this
// ticket names are therefore modelled here over the rows the walker emits
// (`lineagePathProofUniquenessViolations`), and the model is labelled as a model.

import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";

import { describe, expect, it } from "vitest";

import { adjudicateLanding } from "../protocol/reconcile/landing-adjudicator.js";
import type { LandingAdjudicationEvidence } from "../protocol/reconcile/landing-adjudicator.js";
import type { WalletStateProjection } from "../protocol/wallet-role.js";
import {
  DEFAULT_MAX_PATH_BODY_OCTETS,
  InMemoryLineagePathProofStore,
  InMemoryRetainedPathBodySource,
  walkAncestryPath,
  type AncestryWalkInput,
  type AncestryWalkOutcome,
  type LineagePathBodyRow,
  type LineagePathProofRow,
  type RetainedPathBody,
  type RetainedPathBodySource,
  type SuccessorResolution,
  type WalkOperation,
} from "./ancestry-walker.js";
import { parseGatewayEnvelope } from "./gateway-envelope.js";
import { DEFAULT_MAX_PATH_DEPTH, type FreshHeadRead, type ReadFreshHead } from "./landing-path-oracle.js";
import { verifyMoveDualPath, type MoveArtifact, type PathObservation } from "./move-path-verify.js";
import { verifySettledTransaction } from "./transaction-verify.js";

// --- test-only Ed25519 -------------------------------------------------------------------

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
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return { publicKey: paddedBase64Url(spki.subarray(12)), privateKey };
}

function signText(text: string, privateKey: KeyObject): string {
  return paddedBase64Url(sign(null, Buffer.from(text, "utf8"), privateKey));
}

const sha256Hex = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");
const octets = (text: string): number => new TextEncoder().encode(text).byteLength;

// --- real signed SplitChain v2 bodies -----------------------------------------------------

interface BuiltBody {
  readonly text: string;
  readonly stepTwoSignature: string;
}

/** Protocol positions 1-12 in their exact sequence; step 1 signs the inner text, step 2 signs
 * `{"inner":<text>,"step_1_signature":<sig1>}`, completed body is the three in fixed sequence. */
function buildBody(args: {
  readonly sender: Party;
  readonly receiver: Party;
  readonly unixTimeSecs: string;
  readonly senderPostBalance: string;
  readonly receiverPostBalance: string;
  readonly previousSenderStateSignature: string;
  readonly previousReceiverStateSignature: string;
  /** Opaque step_1_state.metadata — used only to inflate body octets for budget tests. */
  readonly senderStateMetadata?: unknown;
}): BuiltBody {
  const step1State =
    args.senderStateMetadata === undefined
      ? { amount: args.senderPostBalance }
      : { amount: args.senderPostBalance, metadata: args.senderStateMetadata };
  const inner = {
    type: "unique_combinable",
    version: "2",
    unix_time_secs: args.unixTimeSecs,
    signer_steps: 2,
    step_1_signer: "sender",
    step_2_signer: "receiver",
    step_1_key_public__base64urlsafe: args.sender.publicKey,
    step_2_key_public__base64urlsafe: args.receiver.publicKey,
    step_1_state: step1State,
    step_2_state: { amount: args.receiverPostBalance },
    previous_step_1_state_signature: args.previousSenderStateSignature,
    previous_step_2_state_signature: args.previousReceiverStateSignature,
  };
  const innerText = JSON.stringify(inner);
  const stepOneSignature = signText(innerText, args.sender.privateKey);
  const stepTwoPreimage = `{"inner":${innerText},"step_1_signature":${JSON.stringify(stepOneSignature)}}`;
  const stepTwoSignature = signText(stepTwoPreimage, args.receiver.privateKey);
  const text =
    `{"inner":${innerText}` +
    `,"step_1_signature":${JSON.stringify(stepOneSignature)}` +
    `,"step_2_signature":${JSON.stringify(stepTwoSignature)}}`;
  return { text, stepTwoSignature };
}

/** A lineage row whose every column is DERIVED from the exact bytes by the same verifier the
 * walker uses, so a fixture cannot silently supply a column the bytes disagree with. */
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

/** The role-relative projection of a body, re-derived from its signed bytes (never a cached
 * balance column) — used to supply a MOVE leg's counterparty T0 baseline. */
function projectionOf(bodyText: string, walletPublicKey: string): WalletStateProjection {
  const parsed = JSON.parse(bodyText) as Parameters<typeof verifySettledTransaction>[0];
  const verdict = verifySettledTransaction(parsed, walletPublicKey);
  if (verdict.verdict !== "VERIFIED") throw new Error(`fixture projection did not verify`);
  return verdict.projection;
}

// --- the long-path fixture ----------------------------------------------------------------
//
// W receives 100 ZKZ from a genesis baseline (E0, the expected RECEIVE_EXTERNAL body), then
// spends 1 ZKZ to PAYEE seventy times. Both wallets' own chains link properly, so every hop
// is a genuine role-relative successor for W and the path is arbitrarily deep on demand.

const W = partyFromSeedByte(0xa1);
const PAYER = partyFromSeedByte(0xa2);
const PAYEE = partyFromSeedByte(0xa3);
const STRANGER = partyFromSeedByte(0xa4);
const OTHER_PAYEE = partyFromSeedByte(0xa5);

// A grammar-valid predecessor for a counterparty whose own history is outside this role-view.
const FOREIGN_PRIOR_STATE = paddedBase64Url(Buffer.alloc(64, 0x07));

const RECEIVE_AMOUNT = 100;
const CHAIN_HOPS = 70;

const E0 = buildBody({
  sender: PAYER,
  receiver: W,
  unixTimeSecs: "1784332800",
  senderPostBalance: "900",
  receiverPostBalance: String(RECEIVE_AMOUNT),
  previousSenderStateSignature: FOREIGN_PRIOR_STATE,
  previousReceiverStateSignature: "",
});

/** HOPS[i] is the (i+1)-th body past E0 in W's role-view; HOPS[0].P == S(W, E0). */
const HOPS: readonly BuiltBody[] = (() => {
  const built: BuiltBody[] = [];
  for (let i = 1; i <= CHAIN_HOPS; i += 1) {
    const previousW = i === 1 ? E0.stepTwoSignature : built[i - 2].stepTwoSignature;
    const previousPayee = i === 1 ? "" : built[i - 2].stepTwoSignature;
    built.push(
      buildBody({
        sender: W,
        receiver: PAYEE,
        unixTimeSecs: String(1784332800 + i),
        senderPostBalance: String(RECEIVE_AMOUNT - i),
        receiverPostBalance: String(i),
        previousSenderStateSignature: previousW,
        previousReceiverStateSignature: previousPayee,
      }),
    );
  }
  return built;
})();

const RECEIVE_OPERATION: WalkOperation = {
  kind: "RECEIVE_EXTERNAL",
  amountZkz: String(RECEIVE_AMOUNT),
  receiverPubkey: W.publicKey,
};

const EXPECTED = (): RetainedPathBody => retainedBody(E0.text, W.publicKey, "obs-e0", "EXPECTED_OPERATION");

/** The first `depth` hops as retained rows, provenance rotating through the non-expected kinds. */
function hopBodies(depth: number): RetainedPathBody[] {
  const kinds = ["CANONICAL_LEDGER", "PROOF_CHANNEL", "FRESH_GATEWAY_HEAD"] as const;
  return HOPS.slice(0, depth).map((hop, index) =>
    retainedBody(hop.text, W.publicKey, `obs-hop-${index + 1}`, kinds[index % kinds.length]),
  );
}

// --- readers and instrumented sources ------------------------------------------------------

function headRead(bodyText: string, observationId: string): FreshHeadRead {
  return {
    observationId,
    envelope: parseGatewayEnvelope(
      new TextEncoder().encode(`{"status":true,"code":"success","message":"","data":[${bodyText}]}`),
    ),
  };
}

/** A single-endpoint head reader that counts its reads. The gateway is
 * head-only, so this count must stay at 2 (anchor + confirm) whatever the path depth. */
class CountingReader {
  reads = 0;
  constructor(
    private readonly bodyText: string,
    private readonly observationId: string,
  ) {}
  readonly read: ReadFreshHead = () => {
    this.reads += 1;
    return Promise.resolve(headRead(this.bodyText, this.observationId));
  };
}

/** Two configured endpoints whose fresh-head reads disagree. `first` answers the anchor read,
 * `second` the confirm read; swapping them is how "no silent preference" is proven. */
function twoEndpointReader(
  first: { readonly text: string; readonly observationId: string },
  second: { readonly text: string; readonly observationId: string },
): ReadFreshHead {
  let reads = 0;
  return () => {
    reads += 1;
    const endpoint = reads === 1 ? first : second;
    return Promise.resolve(headRead(endpoint.text, endpoint.observationId));
  };
}

/** Counts the two index probes the walk is allowed to make. A walk that is O(depth)
 * makes exactly `depth` of each; an O(n²) duplicate scan would not. */
class CountingSource implements RetainedPathBodySource {
  backlinkProbes = 0;
  digestProbes = 0;
  constructor(private readonly inner: RetainedPathBodySource) {}
  resolveSuccessorByBacklink(wallet: string, previous: string): Promise<SuccessorResolution> {
    this.backlinkProbes += 1;
    return this.inner.resolveSuccessorByBacklink(wallet, previous);
  }
  countDistinctBodiesWithDigest(digest: string): Promise<number> {
    this.digestProbes += 1;
    return this.inner.countDistinctBodiesWithDigest(digest);
  }
}

function sourceWith(...bodies: readonly RetainedPathBody[]): InMemoryRetainedPathBodySource {
  const source = new InMemoryRetainedPathBodySource();
  for (const body of bodies) source.put(body);
  return source;
}

function baseInput(overrides: Partial<AncestryWalkInput> = {}): AncestryWalkInput {
  return {
    pathProofId: "11111111-1111-4111-8111-111111111111",
    landingProofId: "22222222-2222-4222-8222-222222222222",
    walletId: null,
    walletPublicKey: W.publicKey,
    operation: RECEIVE_OPERATION,
    expectedBody: EXPECTED(),
    baseline: { kind: "GENESIS", observation_id: "obs-t0" },
    ...overrides,
  };
}

async function walk(
  input: AncestryWalkInput,
  source: RetainedPathBodySource,
  reader: ReadFreshHead,
  store = new InMemoryLineagePathProofStore(),
): Promise<{ outcome: AncestryWalkOutcome; store: InMemoryLineagePathProofStore }> {
  return { outcome: await walkAncestryPath(input, source, reader, store), store };
}

function expectFault(outcome: AncestryWalkOutcome, fault: string): void {
  expect(outcome.kind).toBe("PROOF_INCOMPLETE");
  if (outcome.kind !== "PROOF_INCOMPLETE") return;
  expect(outcome.fault).toBe(fault);
}

/** Walk the standard receive path to `depth`, with instrumentation on both the store probes
 * and the head reads. */
async function walkDepth(
  depth: number,
  overrides: Partial<AncestryWalkInput> = {},
): Promise<{
  outcome: AncestryWalkOutcome;
  store: InMemoryLineagePathProofStore;
  source: CountingSource;
  reader: CountingReader;
}> {
  const source = new CountingSource(sourceWith(...hopBodies(depth)));
  const headText = depth === 0 ? E0.text : HOPS[depth - 1].text;
  const reader = new CountingReader(headText, `obs-head-${depth}`);
  const { outcome, store } = await walk(baseInput(overrides), source, reader.read);
  return { outcome, store, source, reader };
}

// --- 1. depth 0 / 1 / N and long paths ------------------------------------------------------

describe("depth 0, 1, N and long paths", () => {
  it.each([0, 1, 2, 7, 32, 64])("proves a depth-%i path over real signed bodies", async (depth) => {
    const { outcome, store } = await walkDepth(depth);

    expect(outcome.kind).toBe("PATH_PROVEN");
    if (outcome.kind !== "PATH_PROVEN") return;
    expect(outcome.proof.kind).toBe(depth === 0 ? "LANDED_EXACT" : "LANDED_COMPLETE_PATH");
    expect(outcome.proof.depth).toBe(depth);
    expect(outcome.pathProof.path_depth).toBe(depth);
    // CHECK (path_depth = body_count - 1).
    expect(outcome.pathProof.body_count).toBe(depth + 1);
    expect(store.written).toHaveLength(1);
    expect(store.written[0].bodies.map((body) => body.path_index)).toEqual(
      Array.from({ length: depth + 1 }, (_, index) => index),
    );
  });

  it("keeps a deep path contiguous, gap-free and duplicate-free in the persisted rows", async () => {
    const depth = 64;
    const { outcome } = await walkDepth(depth);
    expect(outcome.kind).toBe("PATH_PROVEN");
    if (outcome.kind !== "PATH_PROVEN") return;

    const bodies = outcome.bodies;
    // Body 0 is the exact expected completed transaction; body n is the fresh head.
    expect(bodies[0].completed_transaction_text).toBe(E0.text);
    expect(bodies[depth].completed_transaction_text).toBe(HOPS[depth - 1].text);
    // Every adjacent pair satisfies the role-relative backlink P(W,T[i]) == S(W,T[i-1]).
    for (let index = 1; index <= depth; index += 1) {
      expect(bodies[index].p_signature).toBe(bodies[index - 1].s_signature);
    }
    // Duplicate-free by digest AND by state signature, across the whole depth.
    expect(new Set(bodies.map((body) => body.completed_transaction_sha256)).size).toBe(depth + 1);
    expect(new Set(bodies.map((body) => body.s_signature)).size).toBe(depth + 1);
    // Every persisted digest/octet column re-derives from the persisted bytes.
    for (const body of bodies) {
      expect(sha256Hex(body.completed_transaction_text)).toBe(body.completed_transaction_sha256);
      expect(sha256Hex(body.inner_preimage_text)).toBe(body.inner_sha256);
      expect(sha256Hex(body.verification_manifest_text)).toBe(body.verification_manifest_sha256);
      expect(body.completed_transaction_octets).toBe(octets(body.completed_transaction_text));
    }
  });

  it.each([0, 1, 64])(
    "reads the head exactly twice at depth %i — a chain-side walk is forbidden",
    async (depth) => {
      const { outcome, reader } = await walkDepth(depth);
      expect(outcome.kind).toBe("PATH_PROVEN");
      // Anchor + confirm, and nothing else: no historical-body lookup, at any depth.
      expect(reader.reads).toBe(2);
    },
  );
});

// --- 2. resource bounds bind and fail closed -------------------------------------------------

describe("configured budgets bind and fail closed", () => {
  it("pins the depth off-by-one: maxPathDepth == depth proves, depth - 1 exhausts", async () => {
    const depth = 12;

    const exact = await walkDepth(depth, { maxPathDepth: depth });
    expect(exact.outcome.kind).toBe("PATH_PROVEN");

    const short = await walkDepth(depth, { maxPathDepth: depth - 1 });
    expectFault(short.outcome, "BUDGET_EXHAUSTED");
    // The critical half: no shorter path is quietly proven in place of the real one.
    expect(short.store.written).toHaveLength(0);
  });

  it("pins the octet off-by-one: exact total proves, one octet less exhausts", async () => {
    const depth = 6;
    const total = octets(E0.text) + HOPS.slice(0, depth).reduce((sum, hop) => sum + octets(hop.text), 0);

    const exact = await walkDepth(depth, { maxPathDepth: depth, maxPathBodyOctets: total });
    expect(exact.outcome.kind).toBe("PATH_PROVEN");

    const short = await walkDepth(depth, { maxPathDepth: depth, maxPathBodyOctets: total - 1 });
    expectFault(short.outcome, "BUDGET_EXHAUSTED");
    expect(short.store.written).toHaveLength(0);
  });

  // post-merge D1: at depth 0 the hop loop never runs, so the per-hop
  // octet check is unreachable. The body-0 pre-loop bound is the only budget in play —
  // without it an over-budget expected body that is also the fresh head returns PATH_PROVEN.
  it("pins the body-0 octet budget at depth 0: exact proves, one octet less exhausts with 0 writes", async () => {
    const body0 = octets(E0.text);

    const exact = await walkDepth(0, { maxPathDepth: 0, maxPathBodyOctets: body0 });
    expect(exact.outcome.kind).toBe("PATH_PROVEN");
    if (exact.outcome.kind === "PATH_PROVEN") {
      expect(exact.outcome.pathProof.path_depth).toBe(0);
      expect(exact.outcome.bodies).toHaveLength(1);
      expect(exact.outcome.bodies[0].completed_transaction_octets).toBe(body0);
    }

    const short = await walkDepth(0, { maxPathDepth: 0, maxPathBodyOctets: body0 - 1 });
    expectFault(short.outcome, "BUDGET_EXHAUSTED");
    expect(short.store.written).toHaveLength(0);
    // Depth 0 never probes successors — the bind must fire before any store lookup.
    expect(short.source.backlinkProbes).toBe(0);
  });

  it("binds the DEFAULT depth budget with no caller opt-in", async () => {
    // A budget a caller must ask for is not a budget. Nothing below supplies maxPathDepth.
    expect(DEFAULT_MAX_PATH_DEPTH).toBe(64);

    const atLimit = await walkDepth(DEFAULT_MAX_PATH_DEPTH);
    expect(atLimit.outcome.kind).toBe("PATH_PROVEN");

    const pastLimit = await walkDepth(DEFAULT_MAX_PATH_DEPTH + 1);
    expectFault(pastLimit.outcome, "BUDGET_EXHAUSTED");
    expect(pastLimit.store.written).toHaveLength(0);
    // It stopped AT the budget rather than running away past it.
    expect(pastLimit.source.backlinkProbes).toBe(DEFAULT_MAX_PATH_DEPTH);
  });

    it("binds the DEFAULT octet budget as the binding constraint (no caller opt-in)", async () => {
    // Realistic ~750 B bodies never reach 4 MiB inside the depth-64 ceiling, so pad
    // step_1_state.metadata on body 0 only until the DEFAULT octet ceiling is what stops
    // the walk — nothing below supplies maxPathBodyOctets.
    expect(DEFAULT_MAX_PATH_BODY_OCTETS).toBe(4_194_304);

    const buildPair = (padLen: number): { e0: BuiltBody; hop: BuiltBody; total: number } => {
      const pad = padLen === 0 ? undefined : "x".repeat(padLen);
      const e0 = buildBody({
        sender: FUNDER,
        receiver: W,
        unixTimeSecs: "1784332800",
        senderPostBalance: "0",
        receiverPostBalance: String(RECEIVE_AMOUNT),
        previousSenderStateSignature: "",
        previousReceiverStateSignature: "",
        ...(pad === undefined ? {} : { senderStateMetadata: pad }),
      });
      const hop = buildBody({
        sender: W,
        receiver: PAYEE,
        unixTimeSecs: "1784332801",
        senderPostBalance: String(RECEIVE_AMOUNT - 1),
        receiverPostBalance: "1",
        previousSenderStateSignature: e0.stepTwoSignature,
        previousReceiverStateSignature: "",
        // hop unpadded — pad only body 0 so +1 char == +1 octet on the path total
      });
      return { e0, hop, total: octets(e0.text) + octets(hop.text) };
    };

    // Unpadded baseline must sit strictly under the default ceiling.
    const baseline = buildPair(0);
    expect(baseline.total).toBeLessThan(DEFAULT_MAX_PATH_BODY_OCTETS);

    // Binary-search a pad on body 0 that lands the path total on the default ceiling.
    let lo = 0;
    let hi = DEFAULT_MAX_PATH_BODY_OCTETS - baseline.total + 64;
    while (lo < hi) {
      const mid = Math.floor((lo + hi) / 2);
      if (buildPair(mid).total < DEFAULT_MAX_PATH_BODY_OCTETS) lo = mid + 1;
      else hi = mid;
    }
    // If the metadata JSON envelope jumps the total over the ceiling, step down until
    // we sit on or one-under, then walk both sides of the off-by-one.
    let exactLen = lo;
    while (exactLen > 0 && buildPair(exactLen).total > DEFAULT_MAX_PATH_BODY_OCTETS) exactLen -= 1;
    const atCeiling = buildPair(exactLen);
    // Prefer exact equality; if the envelope made exact unreachable, land one under and
    // prove exact+1 (next char) exhausts — still the DEFAULT binding the walk.
    const overPair = buildPair(exactLen + 1);
    expect(atCeiling.total).toBeLessThanOrEqual(DEFAULT_MAX_PATH_BODY_OCTETS);
    expect(overPair.total).toBeGreaterThan(DEFAULT_MAX_PATH_BODY_OCTETS);
    // The jump across the ceiling must be the binding event (not depth).
    expect(overPair.total - atCeiling.total).toBeGreaterThan(0);

    const runPair = async (pair: { e0: BuiltBody; hop: BuiltBody }) => {
      const input: AncestryWalkInput = {
        pathProofId: "11111111-1111-4111-8111-111111111111",
        landingProofId: "22222222-2222-4222-8222-222222222222",
        walletId: null,
        walletPublicKey: W.publicKey,
        operation: {
          kind: "RECEIVE_EXTERNAL",
          amountZkz: String(RECEIVE_AMOUNT),
          receiverPubkey: W.publicKey,
        },
        expectedBody: retainedBody(pair.e0.text, W.publicKey, "obs-e0-pad", "EXPECTED_OPERATION"),
        baseline: { kind: "GENESIS", observation_id: "obs-t0-pad" },
        // Deliberately omit maxPathBodyOctets — the DEFAULT must bind.
      };
      const source = new CountingSource(
        sourceWith(retainedBody(pair.hop.text, W.publicKey, "obs-hop-pad", "PROOF_CHANNEL")),
      );
      const { outcome, store } = await walk(
        input,
        source,
        new CountingReader(pair.hop.text, "obs-head-pad").read,
      );
      return { outcome, store, probes: source.backlinkProbes };
    };

    const under = await runPair(atCeiling);
    expect(under.outcome.kind).toBe("PATH_PROVEN");
    if (under.outcome.kind === "PATH_PROVEN") {
      const consumed = under.outcome.bodies.reduce(
        (sum, body) => sum + body.completed_transaction_octets,
        0,
      );
      expect(consumed).toBe(atCeiling.total);
      expect(consumed).toBeLessThanOrEqual(DEFAULT_MAX_PATH_BODY_OCTETS);
    }

    const over = await runPair(overPair);
    expectFault(over.outcome, "BUDGET_EXHAUSTED");
    expect(over.store.written).toHaveLength(0);
    // And pin that we really crossed the DEFAULT, not some tighter override.
    expect(overPair.total).toBeGreaterThan(DEFAULT_MAX_PATH_BODY_OCTETS);
    expect(atCeiling.total).toBeLessThanOrEqual(DEFAULT_MAX_PATH_BODY_OCTETS);
  });

  it("terminates on an UNBOUNDED adversarially deep chain rather than hanging", async () => {
    // A store that mints a fresh, fully valid, correctly backlinked successor on demand and
    // never runs out. Only the budget can stop this walk.
    let minted = 0;
    let previousW = E0.stepTwoSignature;
    let previousPayee = "";
    const endless: RetainedPathBodySource = {
      resolveSuccessorByBacklink: () => {
        minted += 1;
        const body = buildBody({
          sender: W,
          receiver: PAYEE,
          unixTimeSecs: String(1794332800 + minted),
          senderPostBalance: String(RECEIVE_AMOUNT - minted),
          receiverPostBalance: String(minted),
          previousSenderStateSignature: previousW,
          previousReceiverStateSignature: previousPayee,
        });
        previousW = body.stepTwoSignature;
        previousPayee = body.stepTwoSignature;
        return Promise.resolve<SuccessorResolution>({
          kind: "FOUND",
          body: retainedBody(body.text, W.publicKey, `obs-endless-${minted}`, "PROOF_CHANNEL"),
        });
      },
      countDistinctBodiesWithDigest: () => Promise.resolve(1),
    };
    const source = new CountingSource(endless);
    // A head that is never reached — the chain always continues past it.
    const reader = new CountingReader(HOPS[CHAIN_HOPS - 1].text, "obs-unreachable-head");

    const { outcome, store } = await walk(baseInput({ maxPathDepth: 24 }), source, reader.read);

    expectFault(outcome, "BUDGET_EXHAUSTED");
    expect(store.written).toHaveLength(0);
    expect(source.backlinkProbes).toBe(24);
    expect(minted).toBe(24);
  });

  it.each([
    ["Infinity", Number.POSITIVE_INFINITY],
    ["NaN", Number.NaN],
    ["negative", -1],
    ["non-integer", 3.5],
    ["above default (2**53)", 2 ** 53],
    ["above default (DEFAULT+1)", DEFAULT_MAX_PATH_DEPTH + 1],
  ] as const)(
    "rejects a hostile maxPathDepth override (%s) — hard stop ≤ default, 0 writes",
    async (_label, override) => {
      // Endless valid-successor store: only a real finite clamp can terminate this.
      let minted = 0;
      let previousW = E0.stepTwoSignature;
      let previousPayee = "";
      const endless: RetainedPathBodySource = {
        resolveSuccessorByBacklink: () => {
          minted += 1;
          const body = buildBody({
            sender: W,
            receiver: PAYEE,
            unixTimeSecs: String(1794332800 + minted),
            senderPostBalance: String(RECEIVE_AMOUNT - minted),
            receiverPostBalance: String(minted),
            previousSenderStateSignature: previousW,
            previousReceiverStateSignature: previousPayee,
          });
          previousW = body.stepTwoSignature;
          previousPayee = body.stepTwoSignature;
          return Promise.resolve<SuccessorResolution>({
            kind: "FOUND",
            body: retainedBody(body.text, W.publicKey, `obs-hostile-depth-${minted}`, "PROOF_CHANNEL"),
          });
        },
        countDistinctBodiesWithDigest: () => Promise.resolve(1),
      };
      const source = new CountingSource(endless);
      const reader = new CountingReader(HOPS[CHAIN_HOPS - 1].text, "obs-unreachable-head");

      const { outcome, store } = await walk(
        baseInput({ maxPathDepth: override }),
        source,
        reader.read,
      );

      expectFault(outcome, "BUDGET_EXHAUSTED");
      expect(store.written).toHaveLength(0);
      // Clamp rejects before any hop is admitted — probe count stays at 0, never escapes
      // past DEFAULT_MAX_PATH_DEPTH.
      expect(source.backlinkProbes).toBe(0);
      expect(minted).toBe(0);
      expect(source.backlinkProbes).toBeLessThanOrEqual(DEFAULT_MAX_PATH_DEPTH);
    },
  );

  it.each([
    ["Infinity", Number.POSITIVE_INFINITY],
    ["NaN", Number.NaN],
    ["negative", -1],
    ["non-integer", 1.5],
    ["above default (2**53)", 2 ** 53],
    ["above default (DEFAULT+1)", DEFAULT_MAX_PATH_BODY_OCTETS + 1],
  ] as const)(
    "rejects a hostile maxPathBodyOctets override (%s) — hard stop, 0 writes",
    async (_label, override) => {
      // A path that would otherwise prove at depth 2 under the defaults.
      const { outcome, store, source } = await walkDepth(2, { maxPathBodyOctets: override });
      expectFault(outcome, "BUDGET_EXHAUSTED");
      expect(store.written).toHaveLength(0);
      expect(source.backlinkProbes).toBe(0);
    },
  );

  it.each([
    [
      "always returns the same already-seen body",
      (): RetainedPathBodySource => ({
        resolveSuccessorByBacklink: () =>
          Promise.resolve<SuccessorResolution>({
            kind: "FOUND",
            body: retainedBody(HOPS[0].text, W.publicKey, "obs-stuck", "PROOF_CHANNEL"),
          }),
        countDistinctBodiesWithDigest: () => Promise.resolve(1),
      }),
    ],
    [
      "rotates through a fixed ring of valid bodies",
      (): RetainedPathBodySource => {
        let index = 0;
        return {
          resolveSuccessorByBacklink: () => {
            const body = HOPS[index % 5];
            index += 1;
            return Promise.resolve<SuccessorResolution>({
              kind: "FOUND",
              body: retainedBody(body.text, W.publicKey, `obs-ring-${index}`, "PROOF_CHANNEL"),
            });
          },
          countDistinctBodiesWithDigest: () => Promise.resolve(1),
        };
      },
    ],
    [
      "always answers NONE",
      (): RetainedPathBodySource => ({
        resolveSuccessorByBacklink: () => Promise.resolve<SuccessorResolution>({ kind: "NONE" }),
        countDistinctBodiesWithDigest: () => Promise.resolve(1),
      }),
    ],
    [
      "always answers AMBIGUOUS",
      (): RetainedPathBodySource => ({
        resolveSuccessorByBacklink: () => Promise.resolve<SuccessorResolution>({ kind: "AMBIGUOUS" }),
        countDistinctBodiesWithDigest: () => Promise.resolve(1),
      }),
    ],
  ])("is TOTAL against a store that %s", async (_label, build) => {
    const source = new CountingSource(build());
    const { outcome, store } = await walk(
      baseInput({ maxPathDepth: 16 }),
      source,
      new CountingReader(HOPS[CHAIN_HOPS - 1].text, "obs-unreachable-head").read,
    );

    // Any fault is acceptable; returning at all, bounded, writing nothing, is the property.
    expect(outcome.kind).toBe("PROOF_INCOMPLETE");
    expect(store.written).toHaveLength(0);
    expect(source.backlinkProbes).toBeLessThanOrEqual(16);
  });

  it("walks in O(depth) index probes, not O(depth²)", async () => {
    for (const depth of [1, 8, 32]) {
      const { outcome, source } = await walkDepth(depth);
      expect(outcome.kind).toBe("PATH_PROVEN");
      // One backlink probe and one digest probe per hop. A pairwise duplicate scan over the
      // path would be depth·(depth-1)/2 comparisons; a scan of retained storage would depend
      // on the store's size, which the next test pins.
      expect(source.backlinkProbes).toBe(depth);
      expect(source.digestProbes).toBe(depth);
    }
  });

  it("keeps walk cost independent of how many unrelated bodies are retained", async () => {
    const depth = 8;
    const small = sourceWith(...hopBodies(depth));

    // Same path, but the store also holds 400 unrelated retained rows in distinct backlink
    // buckets. An O(retained bodies) scan — the deep-path DoS — would show up here.
    const large = sourceWith(...hopBodies(depth));
    const filler = hopBodies(1)[0];
    for (let index = 0; index < 400; index += 1) {
      large.put({ ...filler, p_signature: `unreferenced-backlink-${index}` });
    }

    const results = [];
    for (const inner of [small, large]) {
      const source = new CountingSource(inner);
      const { outcome } = await walk(
        baseInput(),
        source,
        new CountingReader(HOPS[depth - 1].text, "obs-head").read,
      );
      expect(outcome.kind).toBe("PATH_PROVEN");
      results.push({ backlink: source.backlinkProbes, digest: source.digestProbes });
    }
    expect(results[1]).toEqual(results[0]);
    expect(results[0]).toEqual({ backlink: depth, digest: depth });
  });
});

// --- 3. MOVE requires two independently complete paths -----------------------------------------

const SRC = partyFromSeedByte(0xb1);
const DST = partyFromSeedByte(0xb2);
const FUNDER = partyFromSeedByte(0xb3);
const SRC_PAYEE = partyFromSeedByte(0xb4);
const DST_PAYEE = partyFromSeedByte(0xb5);

const MOVE_AMOUNT = "4";
const MOVE_OPERATION_ID = "33333333-3333-4333-8333-333333333333";

// SRC's T0: funded with 50. DST's T0: funded with 20 (FUNDER's own chain links across both).
const SRC0 = buildBody({
  sender: FUNDER,
  receiver: SRC,
  unixTimeSecs: "1784400000",
  senderPostBalance: "950",
  receiverPostBalance: "50",
  previousSenderStateSignature: FOREIGN_PRIOR_STATE,
  previousReceiverStateSignature: "",
});
const DST0 = buildBody({
  sender: FUNDER,
  receiver: DST,
  unixTimeSecs: "1784400100",
  senderPostBalance: "930",
  receiverPostBalance: "20",
  previousSenderStateSignature: SRC0.stepTwoSignature,
  previousReceiverStateSignature: "",
});

// M — the one dual-signed MOVE body. Both legs' body 0.
const M = buildBody({
  sender: SRC,
  receiver: DST,
  unixTimeSecs: "1784400200",
  senderPostBalance: "46",
  receiverPostBalance: "24",
  previousSenderStateSignature: SRC0.stepTwoSignature,
  previousReceiverStateSignature: DST0.stepTwoSignature,
});

// Each leg buries M by one hop under its OWN wallet's later activity.
const SRC_HEAD = buildBody({
  sender: SRC,
  receiver: SRC_PAYEE,
  unixTimeSecs: "1784400300",
  senderPostBalance: "40",
  receiverPostBalance: "6",
  previousSenderStateSignature: M.stepTwoSignature,
  previousReceiverStateSignature: "",
});
const DST_HEAD = buildBody({
  sender: DST,
  receiver: DST_PAYEE,
  unixTimeSecs: "1784400400",
  senderPostBalance: "20",
  receiverPostBalance: "4",
  previousSenderStateSignature: M.stepTwoSignature,
  previousReceiverStateSignature: "",
});

const SRC_BASELINE_PROJECTION = projectionOf(SRC0.text, SRC.publicKey);
const DST_BASELINE_PROJECTION = projectionOf(DST0.text, DST.publicKey);

function moveOperation(leg: "SOURCE" | "DESTINATION"): WalkOperation {
  return {
    kind: "MOVE_INTERNAL",
    leg,
    amountZkz: MOVE_AMOUNT,
    sourcePubkey: SRC.publicKey,
    destinationPubkey: DST.publicKey,
    counterpartyWalletPublicKey: leg === "SOURCE" ? DST.publicKey : SRC.publicKey,
    counterpartyBaseline: leg === "SOURCE" ? DST_BASELINE_PROJECTION : SRC_BASELINE_PROJECTION,
  };
}

function moveLegInput(
  leg: "SOURCE" | "DESTINATION",
  overrides: Partial<AncestryWalkInput> = {},
): AncestryWalkInput {
  const wallet = leg === "SOURCE" ? SRC : DST;
  const t0 = leg === "SOURCE" ? SRC0 : DST0;
  return {
    pathProofId: leg === "SOURCE" ? "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1" : "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2",
    landingProofId: MOVE_OPERATION_ID,
    walletId: null,
    walletPublicKey: wallet.publicKey,
    operation: moveOperation(leg),
    expectedBody: retainedBody(M.text, wallet.publicKey, "obs-move", "EXPECTED_OPERATION"),
    baseline: {
      kind: "HEAD",
      body: retainedBody(t0.text, wallet.publicKey, `obs-${leg.toLowerCase()}-t0`, "CANONICAL_LEDGER"),
    },
    ...overrides,
  };
}

async function walkMoveLeg(
  leg: "SOURCE" | "DESTINATION",
  options: { readonly retainHead?: boolean; readonly overrides?: Partial<AncestryWalkInput> } = {},
): Promise<{ outcome: AncestryWalkOutcome; store: InMemoryLineagePathProofStore }> {
  const wallet = leg === "SOURCE" ? SRC : DST;
  const head = leg === "SOURCE" ? SRC_HEAD : DST_HEAD;
  const retained =
    options.retainHead === false
      ? []
      : [retainedBody(head.text, wallet.publicKey, `obs-${leg.toLowerCase()}-head`, "FRESH_GATEWAY_HEAD")];
  return walk(
    moveLegInput(leg, options.overrides ?? {}),
    sourceWith(...retained),
    new CountingReader(head.text, `obs-${leg.toLowerCase()}-head`).read,
  );
}

/** `lineage_path_proofs`: UNIQUE (landing_proof_id, path_role) and
 * UNIQUE (landing_proof_id, wallet_public_key). MODEL ONLY — the DDL is deferred to
 * (observation-ledger-parent.rollup.test.ts asserts it is absent from the assembled schema),
 * so this evaluates the constraints against the rows the walker actually emits. */
function lineagePathProofUniquenessViolations(rows: readonly LineagePathProofRow[]): string[] {
  const violations: string[] = [];
  const byRole = new Set<string>();
  const byWallet = new Set<string>();
  for (const row of rows) {
    const roleKey = `${row.landing_proof_id}|${row.path_role}`;
    const walletKey = `${row.landing_proof_id}|${row.wallet_public_key}`;
    if (byRole.has(roleKey)) violations.push(`UNIQUE (landing_proof_id, path_role): ${roleKey}`);
    if (byWallet.has(walletKey)) {
      violations.push(`UNIQUE (landing_proof_id, wallet_public_key): ${walletKey}`);
    }
    byRole.add(roleKey);
    byWallet.add(walletKey);
  }
  return violations;
}

function pathObservation(
  proof: LineagePathProofRow,
  body: LineagePathBodyRow,
): PathObservation {
  return {
    walletPublicKey: proof.wallet_public_key,
    stateSignature: body.s_signature,
    balance: body.b_amount,
    transactionSignature: body.step_2_signature,
  };
}

const MOVE_ARTIFACT: MoveArtifact = {
  sourcePublicKey: SRC.publicKey,
  destinationPublicKey: DST.publicKey,
  amountZkz: MOVE_AMOUNT,
  operationId: MOVE_OPERATION_ID,
  step1Signature: (JSON.parse(M.text) as { step_1_signature: string }).step_1_signature,
  step2Signature: M.stepTwoSignature,
  previousStep1StateSignature: SRC0.stepTwoSignature,
  previousStep2StateSignature: DST0.stepTwoSignature,
};

describe("MOVE requires exactly two independently complete paths", () => {
  it("proves both legs and anchors them to the SAME expected move body", async () => {
    const source = await walkMoveLeg("SOURCE");
    const destination = await walkMoveLeg("DESTINATION");

    expect(source.outcome.kind).toBe("PATH_PROVEN");
    expect(destination.outcome.kind).toBe("PATH_PROVEN");
    if (source.outcome.kind !== "PATH_PROVEN" || destination.outcome.kind !== "PATH_PROVEN") return;

    expect(source.outcome.pathProof.path_role).toBe("SOURCE");
    expect(destination.outcome.pathProof.path_role).toBe("DESTINATION");
    // Both legs' body 0 bytes/digest are the same expected move transaction.
    expect(source.outcome.bodies[0].completed_transaction_text).toBe(M.text);
    expect(destination.outcome.bodies[0].completed_transaction_text).toBe(M.text);
    expect(destination.outcome.pathProof.expected_completed_transaction_sha256).toBe(
      source.outcome.pathProof.expected_completed_transaction_sha256,
    );
    // Independently complete: each leg has its OWN T0, its OWN head, its OWN role-view.
    expect(destination.outcome.pathProof.t0_observation_id).not.toBe(
      source.outcome.pathProof.t0_observation_id,
    );
    expect(destination.outcome.pathProof.fresh_head_completed_transaction_sha256).not.toBe(
      source.outcome.pathProof.fresh_head_completed_transaction_sha256,
    );
    expect(
      lineagePathProofUniquenessViolations([source.outcome.pathProof, destination.outcome.pathProof]),
    ).toEqual([]);
  });

  it("yields no landing when the DESTINATION path is missing but SOURCE is complete", async () => {
    const source = await walkMoveLeg("SOURCE");
    const destination = await walkMoveLeg("DESTINATION", { retainHead: false });

    expect(source.outcome.kind).toBe("PATH_PROVEN");
    expectFault(destination.outcome, "MISSING_BODY");
    expect(destination.store.written).toHaveLength(0);
    if (source.outcome.kind !== "PATH_PROVEN") return;

    // required_path_count = 2 cannot be met: only one lineage_path_proofs row exists.
    const rows = [source.outcome.pathProof];
    expect(rows).toHaveLength(1);
    expect(new Set(rows.map((row) => row.path_role))).toEqual(new Set(["SOURCE"]));

    // And the dual-path composer refuses to call it landed.
    const verdict = verifyMoveDualPath(
      {
        baselineObservation: {
          walletPublicKey: SRC.publicKey,
          stateSignature: SRC0.stepTwoSignature,
          balance: "50",
          transactionSignature: SRC0.stepTwoSignature,
        },
        settledObservation: pathObservation(source.outcome.pathProof, source.outcome.bodies[0]),
        operationId: MOVE_OPERATION_ID,
      },
      {
        // No destination lineage path proof exists, so there is no settled destination
        // observation to supply: the baseline is all the evidence there is.
        baselineObservation: {
          walletPublicKey: DST.publicKey,
          stateSignature: DST0.stepTwoSignature,
          balance: "20",
          transactionSignature: DST0.stepTwoSignature,
        },
        settledObservation: {
          walletPublicKey: DST.publicKey,
          stateSignature: DST0.stepTwoSignature,
          balance: "20",
          transactionSignature: DST0.stepTwoSignature,
        },
        operationId: MOVE_OPERATION_ID,
      },
      MOVE_ARTIFACT,
    );
    expect(verdict.outcome).toBe("SOURCE_ONLY_VERIFIED");
    expect(verdict.outcome).not.toBe("BOTH_PATHS_VERIFIED");
    expect(verdict.destinationVerified).toBe(false);
  });

  it("yields no landing when the SOURCE path is missing but DESTINATION is complete", async () => {
    const source = await walkMoveLeg("SOURCE", { retainHead: false });
    const destination = await walkMoveLeg("DESTINATION");

    expectFault(source.outcome, "MISSING_BODY");
    expect(source.store.written).toHaveLength(0);
    expect(destination.outcome.kind).toBe("PATH_PROVEN");
    if (destination.outcome.kind !== "PATH_PROVEN") return;
    expect(new Set([destination.outcome.pathProof.path_role])).toEqual(new Set(["DESTINATION"]));
  });

  it("cannot coerce a SOURCE-only proof into a second path by re-walking the same leg", async () => {
    const first = await walkMoveLeg("SOURCE");
    const second = await walkMoveLeg("SOURCE", {
      overrides: { pathProofId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9" },
    });
    expect(first.outcome.kind).toBe("PATH_PROVEN");
    expect(second.outcome.kind).toBe("PATH_PROVEN");
    if (first.outcome.kind !== "PATH_PROVEN" || second.outcome.kind !== "PATH_PROVEN") return;

    // Two rows, but the uniqueness constraints reject the pair on BOTH keys — the walker cannot be
    // talked into producing a fake dual path from one leg.
    const violations = lineagePathProofUniquenessViolations([
      first.outcome.pathProof,
      second.outcome.pathProof,
    ]);
    expect(violations).toHaveLength(2);
    expect(violations[0]).toContain("UNIQUE (landing_proof_id, path_role)");
    expect(violations[1]).toContain("UNIQUE (landing_proof_id, wallet_public_key)");
  });

  it("derives path_role from the operation kind, so a receive path cannot be labelled SOURCE", async () => {
    // RECEIVE and SEND require one path; MOVE requires SOURCE and DESTINATION. The
    // role is not a caller field on AncestryWalkInput, and these pin the mapping so it cannot
    // drift into one.
    const receive = await walkDepth(2);
    expect(receive.outcome.kind).toBe("PATH_PROVEN");
    if (receive.outcome.kind !== "PATH_PROVEN") return;
    expect(receive.outcome.pathProof.path_role).toBe("RECEIVER");

    const send = await walk(
      baseInput({
        operation: {
          kind: "SEND_EXTERNAL",
          amountZkz: "1",
          sourcePubkey: W.publicKey,
          destinationAddress: PAYEE.publicKey,
        },
        expectedBody: retainedBody(HOPS[0].text, W.publicKey, "obs-hop-1", "EXPECTED_OPERATION"),
        baseline: { kind: "HEAD", body: EXPECTED() },
      }),
      sourceWith(...hopBodies(2).slice(1)),
      new CountingReader(HOPS[1].text, "obs-hop-2").read,
    );
    expect(send.outcome.kind).toBe("PATH_PROVEN");
    if (send.outcome.kind !== "PATH_PROVEN") return;
    expect(send.outcome.pathProof.path_role).toBe("SOURCE");

    const sourceLeg = await walkMoveLeg("SOURCE");
    const destinationLeg = await walkMoveLeg("DESTINATION");
    if (sourceLeg.outcome.kind !== "PATH_PROVEN" || destinationLeg.outcome.kind !== "PATH_PROVEN") {
      throw new Error("both MOVE legs must prove for the path_role mapping case");
    }
    expect(sourceLeg.outcome.pathProof.path_role).toBe("SOURCE");
    expect(destinationLeg.outcome.pathProof.path_role).toBe("DESTINATION");
  });

  it("refuses a leg relabelled DESTINATION while still walking the SOURCE wallet", async () => {
    // path_role is fixed by the operation, so the only way to forge a DESTINATION row is to
    // claim the leg — and the move economics reject it, because the source wallet is the
    // step-1 sender and a destination leg must be the step-2 receiver.
    const relabelled: AncestryWalkInput = {
      ...moveLegInput("SOURCE"),
      operation: {
        kind: "MOVE_INTERNAL",
        leg: "DESTINATION",
        amountZkz: MOVE_AMOUNT,
        sourcePubkey: SRC.publicKey,
        destinationPubkey: DST.publicKey,
        counterpartyWalletPublicKey: DST.publicKey,
        counterpartyBaseline: DST_BASELINE_PROJECTION,
      },
    };
    const { outcome, store } = await walk(
      relabelled,
      sourceWith(retainedBody(SRC_HEAD.text, SRC.publicKey, "obs-src-head", "FRESH_GATEWAY_HEAD")),
      new CountingReader(SRC_HEAD.text, "obs-src-head").read,
    );

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("drives the dual-path composer from the walker's own lineage rows and lands both legs", async () => {
    const source = await walkMoveLeg("SOURCE");
    const destination = await walkMoveLeg("DESTINATION");
    if (source.outcome.kind !== "PATH_PROVEN" || destination.outcome.kind !== "PATH_PROVEN") {
      throw new Error("both MOVE legs must prove for the positive dual-path case");
    }

    const verdict = verifyMoveDualPath(
      {
        baselineObservation: {
          walletPublicKey: SRC.publicKey,
          stateSignature: SRC0.stepTwoSignature,
          balance: "50",
          transactionSignature: SRC0.stepTwoSignature,
        },
        settledObservation: pathObservation(source.outcome.pathProof, source.outcome.bodies[0]),
        operationId: MOVE_OPERATION_ID,
      },
      {
        baselineObservation: {
          walletPublicKey: DST.publicKey,
          stateSignature: DST0.stepTwoSignature,
          balance: "20",
          transactionSignature: DST0.stepTwoSignature,
        },
        settledObservation: pathObservation(destination.outcome.pathProof, destination.outcome.bodies[0]),
        operationId: MOVE_OPERATION_ID,
      },
      MOVE_ARTIFACT,
    );
    expect(verdict.outcome).toBe("BOTH_PATHS_VERIFIED");
    expect(verdict.failures).toEqual([]);
  });
});

// --- 4. provenance grants no authority -----------------------------------------------------

describe("retained provenance grants no authority", () => {
  it.each(["CANONICAL_LEDGER", "PROOF_CHANNEL", "FRESH_GATEWAY_HEAD"] as const)(
    "proves the same path with every intermediate body labelled %s",
    async (sourceKind) => {
      const bodies = HOPS.slice(0, 3).map((hop, index) =>
        retainedBody(hop.text, W.publicKey, `obs-hop-${index + 1}`, sourceKind),
      );
      const { outcome } = await walk(
        baseInput(),
        sourceWith(...bodies),
        new CountingReader(HOPS[2].text, "obs-head").read,
      );
      expect(outcome.kind).toBe("PATH_PROVEN");
      if (outcome.kind !== "PATH_PROVEN") return;
      expect(outcome.bodies.slice(1).map((body) => body.source_kind)).toEqual([
        sourceKind,
        sourceKind,
        sourceKind,
      ]);
    },
  );

  it.each(["CANONICAL_LEDGER", "PROOF_CHANNEL", "FRESH_GATEWAY_HEAD"] as const)(
    "rejects a never-verified body labelled %s exactly as hard as any other provenance",
    async (sourceKind) => {
      // Every earlier body remains untrusted until the landing-path oracle verifier accepts the
      // entire path". This body carries a signature lifted from a different transaction; the
      // privileged-looking provenance buys it nothing.
      const marker = ',"step_2_signature":"';
      const start = HOPS[0].text.indexOf(marker) + marker.length;
      const forgedText =
        HOPS[0].text.slice(0, start) +
        HOPS[1].stepTwoSignature +
        HOPS[0].text.slice(HOPS[0].text.indexOf('"', start));
      expect(forgedText).not.toBe(HOPS[0].text);

      const genuine = retainedBody(HOPS[0].text, W.publicKey, "obs-hop-1", sourceKind);
      const forged: RetainedPathBody = {
        ...genuine,
        completed_transaction_text: forgedText,
        completed_transaction_sha256: sha256Hex(forgedText),
        completed_transaction_octets: octets(forgedText),
        step_2_signature: HOPS[1].stepTwoSignature,
        s_signature: HOPS[1].stepTwoSignature,
      };
      const { outcome, store } = await walk(
        baseInput(),
        sourceWith(forged),
        new CountingReader(forgedText, "obs-forged-head").read,
      );

      expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
      expect(store.written).toHaveLength(0);
    },
  );

  it("requires the FINAL path body to byte-equal the fresh observation's completed body", async () => {
    const depth = 4;
    const { outcome, reader } = await walkDepth(depth);
    expect(outcome.kind).toBe("PATH_PROVEN");
    if (outcome.kind !== "PATH_PROVEN") return;
    expect(outcome.bodies[depth].completed_transaction_text).toBe(HOPS[depth - 1].text);
    expect(outcome.pathProof.fresh_head_completed_transaction_sha256).toBe(sha256Hex(HOPS[depth - 1].text));
    expect(reader.reads).toBe(2);
  });
});

// --- 5. unknown completed target -----------------------------------------------------------

describe("an unknown declared target is rejected, never partially matched", () => {
  it("rejects a SEND whose declared destination appears LATER in the path but not in body 0", async () => {
    // The tempting partial match: OTHER_PAYEE is a real party to a later body in this wallet's
    // history, so a best-effort matcher would find it. Body 0 pays PAYEE, and body 0 is the
    // only body the operation's artifact binding may be satisfied by.
    const laterBody = buildBody({
      sender: W,
      receiver: OTHER_PAYEE,
      unixTimeSecs: "1784339000",
      senderPostBalance: String(RECEIVE_AMOUNT - 2),
      receiverPostBalance: "1",
      previousSenderStateSignature: HOPS[0].stepTwoSignature,
      previousReceiverStateSignature: "",
    });
    const input = baseInput({
      operation: {
        kind: "SEND_EXTERNAL",
        amountZkz: "1",
        sourcePubkey: W.publicKey,
        destinationAddress: OTHER_PAYEE.publicKey,
      },
      expectedBody: retainedBody(HOPS[0].text, W.publicKey, "obs-hop-1", "EXPECTED_OPERATION"),
      baseline: { kind: "HEAD", body: EXPECTED() },
    });
    const { outcome, store } = await walk(
      input,
      sourceWith(retainedBody(laterBody.text, W.publicKey, "obs-later", "CANONICAL_LEDGER")),
      new CountingReader(laterBody.text, "obs-later").read,
    );

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("accepts the same SEND once the declared destination matches body 0", async () => {
    // The control for the test above: only the declared target changed.
    const input = baseInput({
      operation: {
        kind: "SEND_EXTERNAL",
        amountZkz: "1",
        sourcePubkey: W.publicKey,
        destinationAddress: PAYEE.publicKey,
      },
      expectedBody: retainedBody(HOPS[0].text, W.publicKey, "obs-hop-1", "EXPECTED_OPERATION"),
      baseline: { kind: "HEAD", body: EXPECTED() },
    });
    const { outcome } = await walk(
      input,
      sourceWith(...hopBodies(2).slice(1)),
      new CountingReader(HOPS[1].text, "obs-hop-2").read,
    );
    expect(outcome.kind).toBe("PATH_PROVEN");
    if (outcome.kind !== "PATH_PROVEN") return;
    expect(outcome.pathProof.path_role).toBe("SOURCE");
  });

  it("rejects a RECEIVE whose declared receiver is a wallet in no body of the path", async () => {
    const input = baseInput({
      operation: {
        kind: "RECEIVE_EXTERNAL",
        amountZkz: String(RECEIVE_AMOUNT),
        receiverPubkey: STRANGER.publicKey,
      },
    });
    const { outcome, store } = await walk(
      input,
      sourceWith(...hopBodies(3)),
      new CountingReader(HOPS[2].text, "obs-head").read,
    );

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });

  it("rejects a MOVE leg whose declared counterparty is an unknown wallet", async () => {
    const { outcome, store } = await walkMoveLeg("SOURCE", {
      overrides: {
        operation: {
          kind: "MOVE_INTERNAL",
          leg: "SOURCE",
          amountZkz: MOVE_AMOUNT,
          sourcePubkey: SRC.publicKey,
          destinationPubkey: STRANGER.publicKey,
          counterpartyWalletPublicKey: STRANGER.publicKey,
          counterpartyBaseline: DST_BASELINE_PROJECTION,
        },
      },
    });

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
  });
});

// --- 6. chunked ingestion is never a partial verdict -----------------------------------------

describe("a chunk commit is evidence ingestion, never a partial verdict", () => {
  it("writes NOTHING when a deep path fails after many hops already verified", async () => {
    // Hops 1..20 are retained; hop 21 is not. Twenty bodies pass the full landing-path oracle gate and the
    // path still proves nothing.
    const source = new CountingSource(sourceWith(...hopBodies(20)));
    const { outcome, store } = await walk(
      baseInput(),
      source,
      new CountingReader(HOPS[24].text, "obs-head-25").read,
    );

    expectFault(outcome, "MISSING_BODY");
    expect(store.written).toHaveLength(0);
    expect(source.backlinkProbes).toBe(21);
  });

  it("re-validates from body 0 on resume rather than trusting the earlier partial ingest", async () => {
    const missingHopIndex = 3;
    const head = HOPS[4];
    const partial = hopBodies(5).filter((_, index) => index !== missingHopIndex - 1);

    const firstSource = new CountingSource(sourceWith(...partial));
    const store = new InMemoryLineagePathProofStore();
    const first = await walk(baseInput(), firstSource, new CountingReader(head.text, "obs-head-5").read, store);
    expectFault(first.outcome, "MISSING_BODY");
    expect(store.written).toHaveLength(0);
    expect(firstSource.backlinkProbes).toBe(missingHopIndex);

    // Resume against the SAME store, with the missing body now retained.
    const secondSource = new CountingSource(sourceWith(...hopBodies(5)));
    const second = await walk(baseInput(), secondSource, new CountingReader(head.text, "obs-head-5").read, store);

    expect(second.outcome.kind).toBe("PATH_PROVEN");
    if (second.outcome.kind !== "PATH_PROVEN") return;
    // Five probes, not two: hops 1..3 are walked and verified AGAIN, not resumed from the
    // partially ingested state.
    expect(secondSource.backlinkProbes).toBe(5);
    expect(secondSource.digestProbes).toBe(5);
    expect(second.outcome.bodies.map((body) => body.path_index)).toEqual([0, 1, 2, 3, 4, 5]);
  });

  it("grants nothing to a pre-existing written proof for the same path_proof_id", async () => {
    // A crashed earlier run left a complete-looking row behind. The walker is write-only over
    // the store, so that row cannot shortcut anything: the same missing hop still fails.
    const store = new InMemoryLineagePathProofStore();
    const seeded = await walk(baseInput(), sourceWith(...hopBodies(3)), new CountingReader(HOPS[2].text, "obs-head-3").read, store);
    expect(seeded.outcome.kind).toBe("PATH_PROVEN");
    expect(store.written).toHaveLength(1);

    const { outcome } = await walk(
      baseInput(),
      sourceWith(...hopBodies(1)),
      new CountingReader(HOPS[2].text, "obs-head-3").read,
      store,
    );

    expectFault(outcome, "MISSING_BODY");
    // Still exactly the one earlier row — the failed walk added nothing.
    expect(store.written).toHaveLength(1);
  });
});

// --- 7. corruption is permanently INDETERMINATE ------------------------------------------------

describe("corruption yields a permanent INDETERMINATE, never a first-match pick", () => {
  // A genuine fork: a second body W really signed, whose role-relative P is also S(W, E0).
  const FORK = buildBody({
    sender: W,
    receiver: OTHER_PAYEE,
    unixTimeSecs: "1784336000",
    senderPostBalance: String(RECEIVE_AMOUNT - 5),
    receiverPostBalance: "5",
    previousSenderStateSignature: E0.stepTwoSignature,
    previousReceiverStateSignature: "",
  });

  it.each([
    ["genuine hop first", true],
    ["fork first", false],
  ])("reports CONFLICT for two bodies at one path_index — %s", async (_label, genuineFirst) => {
    const genuine = retainedBody(HOPS[0].text, W.publicKey, "obs-hop-1", "CANONICAL_LEDGER");
    const fork = retainedBody(FORK.text, W.publicKey, "obs-fork", "PROOF_CHANNEL");
    expect(fork.p_signature).toBe(genuine.p_signature);

    const source = sourceWith(...(genuineFirst ? [genuine, fork] : [fork, genuine]));
    const { outcome, store } = await walk(
      baseInput(),
      source,
      new CountingReader(HOPS[0].text, "obs-hop-1").read,
    );

    expectFault(outcome, "CONFLICT");
    expect(store.written).toHaveLength(0);
  });

  it("returns the SAME fault on every re-run — the conflict is permanent, not retryable", async () => {
    const genuine = retainedBody(HOPS[0].text, W.publicKey, "obs-hop-1", "CANONICAL_LEDGER");
    const fork = retainedBody(FORK.text, W.publicKey, "obs-fork", "PROOF_CHANNEL");

    const outcomes: AncestryWalkOutcome[] = [];
    for (let run = 0; run < 3; run += 1) {
      const { outcome, store } = await walk(
        baseInput(),
        sourceWith(genuine, fork),
        new CountingReader(HOPS[0].text, "obs-hop-1").read,
      );
      expect(store.written).toHaveLength(0);
      outcomes.push(outcome);
    }
    expect(outcomes[1]).toEqual(outcomes[0]);
    expect(outcomes[2]).toEqual(outcomes[0]);
    expectFault(outcomes[0], "CONFLICT");
  });

  it("catches a corrupted body at depth 40, not just at the first hop", async () => {
    const depth = 45;
    const corruptAt = 40;
    const bodies = hopBodies(depth);
    // The digest column no longer matches the bytes it names.
    bodies[corruptAt - 1] = {
      ...bodies[corruptAt - 1],
      completed_transaction_sha256: "0".repeat(64),
    };
    const source = new CountingSource(sourceWith(...bodies));
    const { outcome, store } = await walk(
      baseInput(),
      source,
      new CountingReader(HOPS[depth - 1].text, "obs-head").read,
    );

    expectFault(outcome, "ANOMALOUS_OR_CONTRADICTORY");
    expect(store.written).toHaveLength(0);
    // It walked all the way to the corrupted hop and stopped there.
    expect(source.backlinkProbes).toBe(corruptAt);
  });

  it("terminates on a pairwise-valid ring that re-presents a body already on the path", async () => {
    // Twenty genuine hops, then the store starts replaying hop 5. Every pairwise backlink in
    // the replayed segment genuinely holds, so only the seen-body guard can stop this — and
    // it fires before the backlink is even consulted.
    const retained = hopBodies(20);
    let probes = 0;
    const ringing: RetainedPathBodySource = {
      resolveSuccessorByBacklink: (wallet, previous) => {
        probes += 1;
        if (probes > 20) {
          return Promise.resolve<SuccessorResolution>({
            kind: "FOUND",
            body: retainedBody(HOPS[4].text, W.publicKey, "obs-replayed-hop-5", "PROOF_CHANNEL"),
          });
        }
        const body = retained[probes - 1];
        expect(body.p_signature).toBe(previous);
        expect(body.wallet_public_key).toBe(wallet);
        return Promise.resolve<SuccessorResolution>({ kind: "FOUND", body });
      },
      countDistinctBodiesWithDigest: () => Promise.resolve(1),
    };
    const { outcome, store } = await walk(
      baseInput(),
      ringing,
      new CountingReader(HOPS[CHAIN_HOPS - 1].text, "obs-unreachable-head").read,
    );

    expectFault(outcome, "DUPLICATE");
    expect(probes).toBe(21);
    expect(store.written).toHaveLength(0);
  });
});

// --- 8. endpoint disagreement defers ----------------------------------------------------------

describe("endpoint disagreement defers instead of preferring an endpoint", () => {
  const endpointA = { text: HOPS[2].text, observationId: "obs-endpoint-a" };
  const endpointB = { text: HOPS[3].text, observationId: "obs-endpoint-b" };

  it.each([
    ["endpoint A answers the anchor read", endpointA, endpointB],
    ["endpoint B answers the anchor read", endpointB, endpointA],
  ])("reports CONFLICT and writes nothing when %s", async (_label, first, second) => {
    const { outcome, store } = await walk(
      baseInput(),
      sourceWith(...hopBodies(4)),
      twoEndpointReader(first, second),
    );

    expectFault(outcome, "CONFLICT");
    // Neither endpoint is silently preferred: no proof is minted from either head, and the
    // walker records nothing itself — disagreement recording belongs to layer.
    expect(store.written).toHaveLength(0);
  });

  it("folds the endpoint disagreement to INDETERMINATE, never to a landing or a rejection", async () => {
    const { outcome } = await walk(
      baseInput(),
      sourceWith(...hopBodies(4)),
      twoEndpointReader(endpointA, endpointB),
    );
    expect(outcome.kind).toBe("PROOF_INCOMPLETE");
    if (outcome.kind !== "PROOF_INCOMPLETE") return;

    const adjudication = adjudicateLanding({ landingProof: outcome, economic: { ok: true } });
    expect(adjudication.verdict).toBe("INDETERMINATE");
    if (adjudication.verdict !== "INDETERMINATE") return;
    expect(adjudication.reason).toEqual({ source: "LANDING_PROOF_INCOMPLETE", fault: "CONFLICT" });
  });
});

// --- 9. a lease is never evidence for a missing body -------------------------------------------

// Compile-time ratchets. landing-path oracle: "A lease is authorization/exclusivity evidence, never evidence
// for missing chain history." These fail `tsc -b` the day a lease or poll-continuity field is
// added to any of the three surfaces the oracle reads.
type LeaseIsNotAWalkInput = "lease" extends keyof AncestryWalkInput ? true : false;
type LeaseIsNotARetainedBody = "lease" extends keyof RetainedPathBody ? true : false;
type LeaseIsNotAdjudicationEvidence = "lease" extends keyof LandingAdjudicationEvidence ? true : false;
type PollIsNotAWalkInput = "pollContinuity" extends keyof AncestryWalkInput ? true : false;

const LEASE_IS_NOT_A_WALK_INPUT: LeaseIsNotAWalkInput = false;
const LEASE_IS_NOT_A_RETAINED_BODY: LeaseIsNotARetainedBody = false;
const LEASE_IS_NOT_ADJUDICATION_EVIDENCE: LeaseIsNotAdjudicationEvidence = false;
const POLL_IS_NOT_A_WALK_INPUT: PollIsNotAWalkInput = false;

describe("lease and poll continuity are never a substitute for a body", () => {
  it("has no lease or poll-continuity field on any surface the oracle reads", () => {
    expect(LEASE_IS_NOT_A_WALK_INPUT).toBe(false);
    expect(LEASE_IS_NOT_A_RETAINED_BODY).toBe(false);
    expect(LEASE_IS_NOT_ADJUDICATION_EVIDENCE).toBe(false);
    expect(POLL_IS_NOT_A_WALK_INPUT).toBe(false);
  });

  it("produces a byte-identical outcome when lease and poll evidence is smuggled onto the input", async () => {
    const depth = 3;
    const retained = hopBodies(depth).slice(1);
    const reader = (): ReadFreshHead => new CountingReader(HOPS[depth - 1].text, "obs-head-3").read;

    const plain = await walk(baseInput(), sourceWith(...retained), reader());
    const smuggled = await walk(
      {
        ...baseInput(),
        // Extra properties a future shortcut might key on. The walker must not see them.
        lease: { held: true, unbrokenSinceSeq: 1 },
        pollContinuity: { unbroken: true, observedSeqs: [1, 2, 3, 4] },
      } as unknown as AncestryWalkInput,
      sourceWith(...retained),
      reader(),
    );

    expect(smuggled.outcome).toEqual(plain.outcome);
    expectFault(smuggled.outcome, "MISSING_BODY");
    expect(smuggled.store.written).toHaveLength(0);
  });

  it("adjudicates INDETERMINATE for every fault a missing body can present as", async () => {
    // No fault in the frozen set may be talked into a landing by any other evidence.
    for (const fault of ["MISSING_BODY", "GAP", "CONFLICT", "DUPLICATE", "CYCLE"] as const) {
      const evidence: LandingAdjudicationEvidence = {
        landingProof: { kind: "PROOF_INCOMPLETE", fault },
        economic: { ok: true },
      };
      expect(adjudicateLanding(evidence).verdict).toBe("INDETERMINATE");
    }
  });
});
