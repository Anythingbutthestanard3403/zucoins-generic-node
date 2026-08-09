// the any-depth ancestry walker: the proof-CONSTRUCTION half of the landing-path oracle
// landing oracle. It never writes an adjudicated verdict: the persisted lineage-path row it produces
// carries no `verdict` column (see LineagePathProofRow below), and rendering
// `lineage_proof_verdict` is. It DOES return an in-memory
// `LandingPathProof` describing what it constructed — the same shape the merged sibling
// `proveReceiveLanding` returns — which is the walk's result handed to its caller, not a
// durable verdict the walker has graded itself against.
//
// The landing-path oracle is this module's checklist, verbatim:
//
// "every body passes exact JSON.stringify preimage reconstruction, both Ed25519
// signatures, strict scalar/role validation, and the role-relative backlink
// P(W,T[i]) = S(W,T[i-1]); the expected body passes the operation artifact and
// economic predicate against T0; and the path is contiguous, gap-free, conflict-free,
// duplicate-free, and cycle-free."
//
// Every clause is executed here on real bytes. `verifySettledTransaction` is the per-body
// engine: the protocol's closed 14-field shape in its exact
// insertion sequence through the branded scalar validators, exact JSON.stringify preimage
// reconstruction, BOTH Ed25519 signatures against the keys inside the signed body, the
// role-relative projection, and the A.7 semantic fingerprint. This module runs it on the
// object parsed out of each retained body's exact text, then binds EVERY lineage-path column of
// that row back to what the bytes produced. A supplied digest, a supplied projection, a
// supplied role, and a stored "verified" flag are all worthless here.
//
// Where (landing-path-oracle.ts) is the caller-supplies-the-bodies form for
// RECEIVE_EXTERNAL at any depth, this is the retained-storage form for any operation and
// any of the three path roles, and it persists the lineage rows the adjudicator reads.
//
// Two rules bound what the walker may do:
// - No arbitrary chain-side walk by signature: the gateway is HEAD-ONLY
// and offers no historical-body lookup. Intermediate bodies come from retained storage
// (source_kind in its four values) and are UNTRUSTED supplied evidence until this
// walker verifies each one. They are NOT read from `lineage_path_bodies`: the schema models
// that table as the verifier's assembly table, where every row
// already references a `lineage_path_proofs` row. A caller-supplied candidate body
// exists *before* any `lineage_path_proofs` row does, so storing it there would
// fabricate the proof-path authority the landing-path oracle forbids. The PROOF_CHANNEL intake
// lane is `proof_channel_candidate_bodies`, and EXPECTED_OPERATION, CANONICAL_LEDGER
// and FRESH_GATEWAY_HEAD bodies "are node-derived, never arrive through intake, and
// remain in the verifier lane". `lineage_path_bodies` is this walker's OUTPUT only —
// promoted by verbatim byte copy, never re-serialised.
// landing-path oracle lease separation, quoted verbatim: "A lease is authorization/exclusivity
// evidence, never evidence for missing chain history." No lease is read here — the
// input type has no lease field — so a hop that cannot be retrieved stays MISSING_BODY
// however the wallet is leased.
//
// The walk is TOTAL: a seen-body guard, a seen-state-signature guard, and bounded
// depth/octet budgets mean it always returns. Every failure is a frozen LandingProofFault,
// which folds to INDETERMINATE downstream — there is no negative landing verdict, because
// says there is no generic PROVEN_NOT_LANDED oracle.
//
// Pure of clocks and keys: no Date.*, no private key, no signing (the key-custody rule).

import { createHash } from "node:crypto";

import {
  evaluateExternalSendDelta,
  evaluateInternalMoveDelta,
  evaluateReceiveDelta,
} from "../protocol/economic-predicates.js";
import type { SettledSplitChainTransaction } from "../protocol/inner.js";
import { mintLandingPathProofFromOracle } from "../protocol/reconcile/landing-oracle-mint.js";
import type {
  LandingPathProof,
  LandingProofFailure,
  LandingProofFault,
} from "../protocol/reconcile/landing-proof.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "../protocol/wallet-role.js";
import {
  SETTLED_TRANSACTION_FIELDS,
  SUPPORTED_TRANSACTION_VERSION,
  type ParsedSettledTransaction,
  type ParsedTransactionInner,
} from "./gateway-envelope.js";
import {
  anchorFromRead,
  DEFAULT_MAX_PATH_DEPTH,
  fault,
  pathContinuityFault,
  type ReadFreshHead,
} from "./landing-path-oracle.js";
import { verifySettledTransaction } from "./transaction-verify.js";

// The `lineage_path_bodies.source_kind` CHECK, verbatim: source_kind "records
// provenance only and grants no authority" — a FRESH_GATEWAY_HEAD row is verified exactly
// as hard as a PROOF_CHANNEL one.
export const LINEAGE_PATH_BODY_SOURCE_KINDS = [
  "EXPECTED_OPERATION",
  "CANONICAL_LEDGER",
  "PROOF_CHANNEL",
  "FRESH_GATEWAY_HEAD",
] as const;
export type LineagePathBodySourceKind = (typeof LINEAGE_PATH_BODY_SOURCE_KINDS)[number];

// The `lineage_path_proofs.path_role` CHECK, verbatim. RECEIVE_EXTERNAL and
// SEND_EXTERNAL each require one path; MOVE_INTERNAL requires two independently complete
// paths, SOURCE and DESTINATION.
export const LINEAGE_PATH_ROLES = ["RECEIVER", "SOURCE", "DESTINATION"] as const;
export type LineagePathRole = (typeof LINEAGE_PATH_ROLES)[number];

// "verifier resource/budget exhaustion" byte bound, the companion to
// DEFAULT_MAX_PATH_DEPTH's count bound (the schema freezes "count/byte/time budgets" into the
// manifest). A path that would exceed either fails closed with BUDGET_EXHAUSTED and is
// never silently truncated to a shorter "complete" path — a truncated path that still
// minted a proof would be a false landing.
export const DEFAULT_MAX_PATH_BODY_OCTETS = 4_194_304;

/**
 * Resolve a caller-supplied path budget against its default ceiling.
 *
 * Overrides may only *tighten* the default. Non-finite values (`Infinity`, `NaN`),
 * non-integers, negatives, and values above the default all fail closed as
 * `BUDGET_EXHAUSTED` — a hostile or mistaken caller cannot disable the bound by
 * opting into `Infinity` / `Number.MAX_SAFE_INTEGER` / a negative "sentinel".
 *
 * Returns the effective non-negative integer budget, or `null` when the walk must
 * refuse before any hop is admitted.
 */
export function resolvePathBudget(override: number | undefined, defaultCeiling: number): number | null {
  if (override === undefined) return defaultCeiling;
  if (!Number.isFinite(override)) return null;
  if (!Number.isInteger(override)) return null;
  if (override < 0) return null;
  if (override > defaultCeiling) return null;
  return override;
}

/**
 * One retained candidate body as it sits in storage: the `lineage_path_bodies`
 * column set (minus the node-assigned `path_proof_id`/`path_index`/manifest columns this
 * walker assigns) plus the `gateway_observations` row it was captured from.
 *
 * Every field is SUPPLIED EVIDENCE. `verifyHop` re-derives all of them from the exact
 * signed text and rejects the body if any one disagrees.
 */
export interface RetainedPathBody {
  readonly source_kind: LineagePathBodySourceKind;
  readonly observation_id: string;
  readonly wallet_public_key: string;
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
  readonly completed_transaction_octets: number;
  readonly wallet_role: "sender" | "receiver";
  readonly s_signature: string;
  readonly p_signature: string;
  readonly b_amount: string;
  readonly inner_preimage_text: string;
  readonly inner_sha256: string;
  readonly step_1_signature: string;
  readonly step_2_signature: string;
  readonly semantic_fingerprint: string;
}

/**
 * The T0 baseline the expected body's economics are evaluated against. A genesis baseline
 * has no body at all (S="", P="", B="0"); every other baseline is a retained
 * body re-verified here, never a cached balance column.
 */
export type PathBaseline =
  | { readonly kind: "GENESIS"; readonly observation_id: string }
  | { readonly kind: "HEAD"; readonly body: RetainedPathBody };

export type SuccessorResolution =
  | { readonly kind: "FOUND"; readonly body: RetainedPathBody }
  | { readonly kind: "NONE" }
  | { readonly kind: "AMBIGUOUS" };

/**
 * The retained-body source the walk resolves hops through. Both members are single indexed
 * probes, so a walk costs O(depth) probes rather than an in-memory scan of every retained
 * body against every other (the ticket's anti-O(n²) requirement):
 *
 * - `resolveSuccessorByBacklink(wallet, S)` — the successor whose role-relative backlink
 * is `S`, scoped to one wallet's role-view.
 * - `countDistinctBodiesWithDigest(digest)` — conflicting-body detection by digest.
 *
 * The wallet scoping is the port's own requirement, not a restatement of a frozen index:
 * The `lineage_path_bodies_backlink_idx` is `(path_proof_id, p_signature)` and that table
 * carries no wallet column (`wallet_public_key` lives on `lineage_path_proofs`), so it
 * cannot serve this probe — and it is not the intake table anyway. Supplying an
 * index that answers both probes in O(1) is the concrete adapter's obligation; this module
 * only requires that neither member is implemented as a full scan.
 *
 * More than one successor for a state signature is `AMBIGUOUS` and never silently
 * resolved — two bodies claiming the same predecessor is a fork, not a choice.
 */
export interface RetainedPathBodySource {
  resolveSuccessorByBacklink(
    walletPublicKey: string,
    previousStateSignature: string,
  ): Promise<SuccessorResolution>;
  countDistinctBodiesWithDigest(bodySha256: string): Promise<number>;
}

// The `lineage_path_bodies` row, the ordered assembly row this walker produces. Column set
// and PRIMARY KEY (path_proof_id, path_index) are the schema's, field for field.
export interface LineagePathBodyRow {
  readonly path_proof_id: string;
  readonly path_index: number;
  readonly source_kind: LineagePathBodySourceKind;
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
  readonly completed_transaction_octets: number;
  readonly wallet_role: "sender" | "receiver";
  readonly s_signature: string;
  readonly p_signature: string;
  readonly b_amount: string;
  readonly inner_preimage_text: string;
  readonly inner_sha256: string;
  readonly step_1_signature: string;
  readonly step_2_signature: string;
  readonly verification_manifest_text: string;
  readonly verification_manifest_sha256: string;
}

/**
 * The `lineage_path_proofs` row, restricted to the columns the CONSTRUCTION half owns.
 *
 * `verdict`, `proof_manifest_text`, and `proof_manifest_sha256` are deliberately absent:
 * The schema types `verdict` as `lineage_proof_verdict`, and the row's landing verdict is
 * adjudication output. A DURABLE row carrying its own verdict would be
 * the walker grading its own work — the false-landing shape landing-path oracle exists to prevent. (The
 * `LandingPathProof` returned from `walkAncestryPath` is not that row: it is the walk's
 * in-memory result, and nothing here persists it.) `id`, `landing_proof_id`, `wallet_id`,
 * and `created_at` belong to the caller, which holds the parent `operation_landing_proofs`
 * row and the clock.
 */
export interface LineagePathProofRow {
  readonly id: string;
  readonly landing_proof_id: string;
  readonly path_role: LineagePathRole;
  readonly wallet_id: string | null;
  readonly wallet_public_key: string;
  readonly t0_observation_id: string;
  readonly fresh_head_observation_id: string;
  readonly expected_completed_transaction_sha256: string;
  readonly fresh_head_completed_transaction_sha256: string;
  readonly body_count: number;
  readonly path_depth: number;
}

/**
 * The durable sink for a constructed path. One `lineage_path_proofs` row and its ordered
 * `lineage_path_bodies` children commit together — a partially written path proves nothing
 * ("a chunk commit is only evidence ingestion, never a partial verdict"), and the
 * walker only ever calls this after the whole path has verified.
 */
export interface LineagePathProofStore {
  writePathProof(
    proof: LineagePathProofRow,
    bodies: readonly LineagePathBodyRow[],
  ): Promise<void>;
}

/**
 * The operation predicate the expected body must satisfy against T0. The kind also fixes
 * `path_role`, so a caller cannot label a receive path SOURCE, and there is no
 * "skip economics" member — economic clause has no opt-out.
 */
export type WalkOperation =
  | {
      readonly kind: "RECEIVE_EXTERNAL";
      readonly amountZkz: string;
      readonly receiverPubkey: string;
    }
  | {
      readonly kind: "SEND_EXTERNAL";
      readonly amountZkz: string;
      readonly sourcePubkey: string;
      readonly destinationAddress: string;
    }
  | {
      readonly kind: "MOVE_INTERNAL";
      readonly leg: "SOURCE" | "DESTINATION";
      readonly amountZkz: string;
      readonly sourcePubkey: string;
      readonly destinationPubkey: string;
      // A move is ONE dual-signed transaction, so its predicate needs both leased
      // wallets' T0 baselines. This leg supplies its own via `baseline`; the counterparty's
      // is the other leg's, re-derived by that leg's own walk.
      readonly counterpartyWalletPublicKey: string;
      readonly counterpartyBaseline: WalletStateProjection;
      readonly spawnedFromReceive?: { readonly receiveTransactionStepTwoSignature: string };
    };

export interface AncestryWalkInput {
  readonly pathProofId: string;
  readonly landingProofId: string;
  readonly walletId: string | null;
  readonly walletPublicKey: string;
  readonly operation: WalkOperation;
  // The operation's expected completed body — path_index 0 ("Body 0 is the exact
  // expected completed transaction"). Its source_kind must be EXPECTED_OPERATION.
  readonly expectedBody: RetainedPathBody;
  readonly baseline: PathBaseline;
  readonly maxPathDepth?: number;
  readonly maxPathBodyOctets?: number;
}

export type AncestryWalkOutcome =
  | {
      readonly kind: "PATH_PROVEN";
      readonly proof: LandingPathProof;
      readonly pathProof: LineagePathProofRow;
      readonly bodies: readonly LineagePathBodyRow[];
    }
  | LandingProofFailure;

const TEXT_ENCODER = new TextEncoder();

const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

// A body that has passed the whole per-hop gate, carried with the exact text it verified
// against so nothing downstream can pair a verified signature with a different body.
// Every field is taken from the SIGNED BYTES, never from a retained column.
export interface VerifiedHop {
  readonly source_kind: LineagePathBodySourceKind;
  readonly role: "sender" | "receiver";
  readonly transaction: SettledSplitChainTransaction;
  readonly completedTransactionText: string;
  readonly completedTransactionSha256: string;
  readonly innerPreimageText: string;
  readonly sSignature: string;
  readonly pSignature: string;
  readonly bAmount: string;
  readonly stepOneSignature: string;
  readonly stepTwoSignature: string;
}

/**
 * The fixed top-level sequence over one retained body text: exactly
 * `{inner, step_1_signature, step_2_signature}`, a known inner version, and nothing else.
 * The parsed object keeps JSON.parse's insertion sequence, which is what the preimage
 * reconstruction depends on — it is never spread, sorted, or rebuilt (A.9 #15).
 *
 * A duplicate top-level or inner key needs no separate scanner: JSON.parse collapses it,
 * so the reconstruction `verifySettledTransaction` builds no longer byte-equals the
 * retained text and the byte comparison in `verifyHop` rejects the body.
 */
function parseCompletedBody(text: string): ParsedSettledTransaction | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;

  const fields = value as Record<string, unknown>;
  const keys = Object.keys(fields);
  if (
    keys.length !== SETTLED_TRANSACTION_FIELDS.length ||
    keys.some((key, index) => key !== SETTLED_TRANSACTION_FIELDS[index])
  ) {
    return null;
  }

  const { inner, step_1_signature, step_2_signature } = fields;
  if (typeof inner !== "object" || inner === null || Array.isArray(inner)) return null;
  if ((inner as Record<string, unknown>).version !== SUPPORTED_TRANSACTION_VERSION) return null;
  if (typeof step_1_signature !== "string" || typeof step_2_signature !== "string") return null;

  return { inner: inner as ParsedTransactionInner, step_1_signature, step_2_signature };
}

/**
 * The per-hop landing-path oracle gate on one retained body.
 *
 * Sequence: provenance and role-view binding, then the top-level parse, then the full
 * settled-transaction verification, then the byte-exactness gate, then every column bound
 * back to the bytes.
 *
 * The byte gate is the load-bearing one: `verifySettledTransaction` rebuilds the completed
 * text from the parsed object using only JSON.stringify on the insertion-sequenced inner,
 * so if that reconstruction is not byte-identical to the retained text, the retained text
 * is not the signed object. Reformatting, added whitespace, key reordering, and duplicate
 * keys all survive a parse and all die here.
 *
 * The column binding is the second: a row whose digest, octet count, role, S/P/B, inner
 * preimage, inner digest, step signatures, or A.7 fingerprint says one thing while its
 * bytes say another is a forgery attempt, not a stale index.
 */
export function verifyHop(
  body: RetainedPathBody,
  walletPublicKey: string,
): VerifiedHop | LandingProofFault {
  if (!(LINEAGE_PATH_BODY_SOURCE_KINDS as readonly string[]).includes(body.source_kind)) {
    return "ANOMALOUS_OR_CONTRADICTORY";
  }
  if (body.wallet_public_key !== walletPublicKey) return "ANOMALOUS_OR_CONTRADICTORY";

  const text = body.completed_transaction_text;
  const parsed = parseCompletedBody(text);
  if (parsed === null) return "MALFORMED_BODY";

  const verdict = verifySettledTransaction(parsed, walletPublicKey);
  if (verdict.verdict === "MALFORMED_TRANSACTION") return "MALFORMED_BODY";
  if (verdict.verdict !== "VERIFIED") return "ANOMALOUS_OR_CONTRADICTORY";

  // The byte-exact signing rule — the reconstruction from the signed object must BE the retained bytes.
  if (verdict.completedTransactionText !== text) return "ANOMALOUS_OR_CONTRADICTORY";

  const { role, S, P, B } = verdict.projection;
  if (role !== "sender" && role !== "receiver") return "ANOMALOUS_OR_CONTRADICTORY";

  // Every column re-derived and compared: "digest indexes are not equality
  // authority" — the digests below are checked against recomputation, never trusted.
  if (verdict.completedTransactionSha256 !== body.completed_transaction_sha256) {
    return "ANOMALOUS_OR_CONTRADICTORY";
  }
  if (TEXT_ENCODER.encode(text).byteLength !== body.completed_transaction_octets) {
    return "ANOMALOUS_OR_CONTRADICTORY";
  }
  if (role !== body.wallet_role) return "ANOMALOUS_OR_CONTRADICTORY";
  if (S !== body.s_signature || P !== body.p_signature || B !== body.b_amount) {
    return "ANOMALOUS_OR_CONTRADICTORY";
  }
  if (verdict.innerPreimageText !== body.inner_preimage_text) {
    return "ANOMALOUS_OR_CONTRADICTORY";
  }
  if (sha256Hex(verdict.innerPreimageText) !== body.inner_sha256) {
    return "ANOMALOUS_OR_CONTRADICTORY";
  }
  if (
    parsed.step_1_signature !== body.step_1_signature ||
    parsed.step_2_signature !== body.step_2_signature
  ) {
    return "ANOMALOUS_OR_CONTRADICTORY";
  }
  if (verdict.semanticFingerprint !== body.semantic_fingerprint) {
    return "ANOMALOUS_OR_CONTRADICTORY";
  }

  return {
    source_kind: body.source_kind,
    role,
    transaction: verdict.transaction,
    completedTransactionText: verdict.completedTransactionText,
    completedTransactionSha256: verdict.completedTransactionSha256,
    innerPreimageText: verdict.innerPreimageText,
    sSignature: S,
    pSignature: P,
    bAmount: B,
    stepOneSignature: parsed.step_1_signature,
    stepTwoSignature: parsed.step_2_signature,
  };
}

/**
 * The T0 baseline projection, re-derived from the exact signed bytes of the T0 body — the
 * "no cached-balance fallback or P0/S0 substitution" rule. A GENESIS
 * baseline is the fixed genesis projection and has no body to verify.
 */
function baselineProjection(
  baseline: PathBaseline,
  walletPublicKey: string,
): { readonly projection: WalletStateProjection } | LandingProofFault {
  if (baseline.kind === "GENESIS") return { projection: GENESIS_PROJECTION };
  const hop = verifyHop(baseline.body, walletPublicKey);
  if (typeof hop === "string") return hop;
  return {
    projection: {
      role: hop.role,
      S: hop.sSignature,
      P: hop.pSignature,
      B: hop.bAmount,
      I: sha256Hex(hop.innerPreimageText),
    },
  };
}

/** `path_role` is fixed by the operation kind — never taken as a free caller field. */
function pathRoleOf(operation: WalkOperation): LineagePathRole {
  switch (operation.kind) {
    case "RECEIVE_EXTERNAL":
      return "RECEIVER";
    case "SEND_EXTERNAL":
      return "SOURCE";
    default:
      return operation.leg;
  }
}

/**
 * "the expected body passes the operation artifact and economic predicate against
 * T0", dispatched to frozen predicates. Every branch runs a real predicate;
 * there is no pass-through case.
 */
function economicPredicateHolds(
  operation: WalkOperation,
  expectedTx: SettledSplitChainTransaction,
  baseline: WalletStateProjection,
  walletPublicKey: string,
): boolean {
  switch (operation.kind) {
    case "RECEIVE_EXTERNAL":
      return evaluateReceiveDelta({
        baseline,
        candidateTx: expectedTx,
        reservedWalletPublicKey: walletPublicKey,
        operation: { amountZkz: operation.amountZkz, receiverPubkey: operation.receiverPubkey },
      }).ok;
    case "SEND_EXTERNAL":
      return evaluateExternalSendDelta({
        baseline,
        candidateTx: expectedTx,
        sourceWalletPublicKey: walletPublicKey,
        operation: {
          amountZkz: operation.amountZkz,
          sourcePubkey: operation.sourcePubkey,
          destinationAddress: operation.destinationAddress,
        },
      }).ok;
    default: {
      // Both legs verify the SAME dual-signed transaction; this leg supplies its
      // own baseline and wallet, the counterparty supplies theirs.
      const own = { baseline, candidateTx: expectedTx, walletPublicKey };
      const other = {
        baseline: operation.counterpartyBaseline,
        candidateTx: expectedTx,
        walletPublicKey: operation.counterpartyWalletPublicKey,
      };
      return evaluateInternalMoveDelta({
        source: operation.leg === "SOURCE" ? own : other,
        destination: operation.leg === "SOURCE" ? other : own,
        operation: {
          amountZkz: operation.amountZkz,
          sourcePubkey: operation.sourcePubkey,
          destinationPubkey: operation.destinationPubkey,
        },
        ...(operation.spawnedFromReceive === undefined
          ? {}
          : { spawnedFromReceive: operation.spawnedFromReceive }),
      }).ok;
    }
  }
}

/**
 * The per-body verification digest each path manifest must freeze: "the
 * ordered list of (path_index, body digest, byte length, S, P, B, role, per-body
 * verification digest)". Built by explicit key insertion so JSON.stringify emits this exact
 * sequence and a later field addition cannot silently reorder an already-frozen manifest
 * (the byte-exact signing rule), matching the convention observation/verification/material.ts uses for
 * the served path manifest.
 */
function buildVerificationManifestText(entry: {
  readonly path_index: number;
  readonly completed_transaction_sha256: string;
  readonly completed_transaction_octets: number;
  readonly s_signature: string;
  readonly p_signature: string;
  readonly b_amount: string;
  readonly wallet_role: "sender" | "receiver";
  readonly inner_sha256: string;
}): string {
  const row: {
    path_index: number;
    completed_transaction_sha256: string;
    completed_transaction_octets: number;
    s_signature: string;
    p_signature: string;
    b_amount: string;
    wallet_role: "sender" | "receiver";
    inner_sha256: string;
  } = {
    path_index: entry.path_index,
    completed_transaction_sha256: entry.completed_transaction_sha256,
    completed_transaction_octets: entry.completed_transaction_octets,
    s_signature: entry.s_signature,
    p_signature: entry.p_signature,
    b_amount: entry.b_amount,
    wallet_role: entry.wallet_role,
    inner_sha256: entry.inner_sha256,
  };
  return JSON.stringify(row);
}

function toBodyRow(pathProofId: string, pathIndex: number, hop: VerifiedHop): LineagePathBodyRow {
  const octets = TEXT_ENCODER.encode(hop.completedTransactionText).byteLength;
  const innerSha256 = sha256Hex(hop.innerPreimageText);
  const manifestText = buildVerificationManifestText({
    path_index: pathIndex,
    completed_transaction_sha256: hop.completedTransactionSha256,
    completed_transaction_octets: octets,
    s_signature: hop.sSignature,
    p_signature: hop.pSignature,
    b_amount: hop.bAmount,
    wallet_role: hop.role,
    inner_sha256: innerSha256,
  });
  return {
    path_proof_id: pathProofId,
    path_index: pathIndex,
    source_kind: hop.source_kind,
    completed_transaction_text: hop.completedTransactionText,
    completed_transaction_sha256: hop.completedTransactionSha256,
    completed_transaction_octets: octets,
    wallet_role: hop.role,
    s_signature: hop.sSignature,
    p_signature: hop.pSignature,
    b_amount: hop.bAmount,
    inner_preimage_text: hop.innerPreimageText,
    inner_sha256: innerSha256,
    step_1_signature: hop.stepOneSignature,
    step_2_signature: hop.stepTwoSignature,
    verification_manifest_text: manifestText,
    verification_manifest_sha256: sha256Hex(manifestText),
  };
}

/**
 * Construct and persist the any-depth ancestry path for one wallet role-view.
 *
 * Returns PATH_PROVEN only when: the expected body verifies and is the operation's own
 * EXPECTED_OPERATION body at path_index 0; every hop from it to the freshly read
 * authoritative head verifies in full; each adjacent pair satisfies
 * P(W,T[i]) == S(W,T[i-1]); the path is duplicate-free, cycle-free, conflict-free and
 * within both budgets; the terminal hop byte-equals the fresh head; the expected body
 * satisfies the operation's economic predicate against T0; and a second head read confirms
 * the head did not move during the verification window. Everything else is a
 * LandingProofFailure, which authorizes no landing, no non-landing, and no retry, release,
 * or resubmit — and writes nothing.
 */
export async function walkAncestryPath(
  input: AncestryWalkInput,
  source: RetainedPathBodySource,
  readFreshHead: ReadFreshHead,
  store: LineagePathProofStore,
): Promise<AncestryWalkOutcome> {
  const wallet = input.walletPublicKey;
  const maxDepth = resolvePathBudget(input.maxPathDepth, DEFAULT_MAX_PATH_DEPTH);
  const maxOctets = resolvePathBudget(input.maxPathBodyOctets, DEFAULT_MAX_PATH_BODY_OCTETS);
  // A caller that cannot name a finite budget inside the default ceiling gets nothing —
  // not an unbounded walk, not a silently-clamped longer path.
  if (maxDepth === null || maxOctets === null) return fault("BUDGET_EXHAUSTED");

  if (input.expectedBody.source_kind !== "EXPECTED_OPERATION") {
    return fault("ANOMALOUS_OR_CONTRADICTORY");
  }

  // Anchor on the authoritative head as it reads RIGHT NOW, before any supplied body is
  // admitted — the path is proven against the chain, not the other way round.
  const anchorRead = await readFreshHead(wallet);
  const anchor = anchorFromRead(anchorRead, wallet);
  if (typeof anchor === "string") return fault(anchor);

  const baseline = baselineProjection(input.baseline, wallet);
  if (typeof baseline === "string") return fault(baseline);

  const expected = verifyHop(input.expectedBody, wallet);
  if (typeof expected === "string") return fault(expected);

  // Step 3 — the operation artifact and economic predicate against T0, evaluated on
  // the object the signatures were verified over, never on a re-parse or a projection.
  if (!economicPredicateHolds(input.operation, expected.transaction, baseline.projection, wallet)) {
    return fault("ANOMALOUS_OR_CONTRADICTORY");
  }

  const hops: VerifiedHop[] = [expected];
  const seenBodyDigests = new Set<string>([expected.completedTransactionSha256]);
  const seenStateSignatures = new Set<string>([expected.sSignature]);
  let totalOctets = TEXT_ENCODER.encode(expected.completedTransactionText).byteLength;
  if (totalOctets > maxOctets) return fault("BUDGET_EXHAUSTED");

  // Forward walk: from the expected body at path_index 0 toward the head, resolving each
  // successor by the role-relative backlink through the backlink index.
  let current = expected;
  while (current.completedTransactionSha256 !== anchor.completedTransactionSha256) {
    if (hops.length - 1 >= maxDepth) return fault("BUDGET_EXHAUSTED");

    const resolution = await source.resolveSuccessorByBacklink(wallet, current.sSignature);
    if (resolution.kind === "NONE") return fault("MISSING_BODY");
    if (resolution.kind === "AMBIGUOUS") return fault("CONFLICT");

    const next = verifyHop(resolution.body, wallet);
    if (typeof next === "string") return fault(next);

    // per-hop continuity gate, run from its single shared copy
    // (landing-path-oracle.ts `pathContinuityFault`): already-seen body, then already-seen
    // state signature, then the backlink. `previousS` is always supplied here because the
    // expected body is seeded at path_index 0 outside this loop — the supplied-bodies
    // oracle is the only walk whose first body has no predecessor.
    const continuity = pathContinuityFault({
      bodySha256: next.completedTransactionSha256,
      S: next.sSignature,
      P: next.pSignature,
      previousS: current.sSignature,
      seenBodyDigests,
      seenStateSignatures,
    });
    if (continuity !== null) return fault(continuity);

    // Retained-storage-only guards, which the supplied-bodies oracle has no source to run:
    // conflicting bodies under one digest, through the digest index rather than by
    // comparing every pair ("digest indexes are not equality authority").
    if ((await source.countDistinctBodiesWithDigest(next.completedTransactionSha256)) > 1) {
      return fault("CONFLICT");
    }

    totalOctets += TEXT_ENCODER.encode(next.completedTransactionText).byteLength;
    if (totalOctets > maxOctets) return fault("BUDGET_EXHAUSTED");

    seenBodyDigests.add(next.completedTransactionSha256);
    seenStateSignatures.add(next.sSignature);
    hops.push(next);
    current = next;
  }

  // Byte comparison, not digest comparison, against the head's own reconstruction (
  // "Exact equality always includes byte comparison"). Like the CYCLE and empty-P guards
  // (now inside `pathContinuityFault`) this is a declared backstop rather than an
  // independently reachable branch: the loop above exits only once the two digests are
  // equal, and both digests are SHA-256 over the text being compared, so reaching this
  // line with differing text requires a SHA-256 collision. It is kept because "digests
  // agreed" is not the property the schema asks for.
  if (current.completedTransactionText !== anchor.completedTransactionText) return fault("CONFLICT");

  // The current-exact-head rule: re-read and require the same head the path was
  // anchored against. A head that moved mid-verification decides nothing either way.
  const confirmRead = await readFreshHead(wallet);
  const confirmed = anchorFromRead(confirmRead, wallet);
  if (typeof confirmed === "string") return fault(confirmed);
  if (confirmed.completedTransactionText !== anchor.completedTransactionText) {
    return fault("CONFLICT");
  }

  const bodies = hops.map((hop, index) => toBodyRow(input.pathProofId, index, hop));
  const bodyCount = bodies.length;
  const pathProof: LineagePathProofRow = {
    id: input.pathProofId,
    landing_proof_id: input.landingProofId,
    path_role: pathRoleOf(input.operation),
    wallet_id: input.walletId,
    wallet_public_key: wallet,
    t0_observation_id:
      input.baseline.kind === "GENESIS"
        ? input.baseline.observation_id
        : input.baseline.body.observation_id,
    fresh_head_observation_id: confirmRead.observationId,
    expected_completed_transaction_sha256: expected.completedTransactionSha256,
    fresh_head_completed_transaction_sha256: confirmed.completedTransactionSha256,
    body_count: bodyCount,
    // CHECK (path_depth = body_count - 1).
    path_depth: bodyCount - 1,
  };

  await store.writePathProof(pathProof, bodies);

  return {
    kind: "PATH_PROVEN",
    proof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: wallet,
      expectedBodySha256: expected.completedTransactionSha256,
      freshHeadBodySha256: confirmed.completedTransactionSha256,
      freshHeadObservationId: confirmRead.observationId,
      depth: pathProof.path_depth,
    }),
    pathProof,
    bodies,
  };
}

/**
 * In-memory `RetainedPathBodySource` for composition tests and offline drills. Both probes
 * are backed by a bucket rather than a scan, so a walk that passes here exercises the same
 * probe sequence it will against a real adapter. Two DIFFERENT bodies staged under one
 * predecessor resolve to AMBIGUOUS; two different bodies under one digest make
 * `countDistinctBodiesWithDigest` report the conflict.
 */
export class InMemoryRetainedPathBodySource implements RetainedPathBodySource {
  // The wallet-scoped backlink probe: (wallet, p_signature) -> bodies.
  private readonly byBacklink = new Map<string, RetainedPathBody[]>();
  // The digest probe: digest -> distinct exact texts.
  private readonly textsByDigest = new Map<string, Set<string>>();

  put(body: RetainedPathBody): void {
    const key = `${body.wallet_public_key} ${body.p_signature}`;
    const bucket = this.byBacklink.get(key);
    if (bucket === undefined) this.byBacklink.set(key, [body]);
    else bucket.push(body);

    let texts = this.textsByDigest.get(body.completed_transaction_sha256);
    if (texts === undefined) {
      texts = new Set<string>();
      this.textsByDigest.set(body.completed_transaction_sha256, texts);
    }
    texts.add(body.completed_transaction_text);
  }

  resolveSuccessorByBacklink(
    walletPublicKey: string,
    previousStateSignature: string,
  ): Promise<SuccessorResolution> {
    const bucket = this.byBacklink.get(`${walletPublicKey} ${previousStateSignature}`) ?? [];
    const distinct = new Map<string, RetainedPathBody>();
    for (const body of bucket) {
      if (!distinct.has(body.completed_transaction_text)) {
        distinct.set(body.completed_transaction_text, body);
      }
    }
    if (distinct.size === 0) return Promise.resolve({ kind: "NONE" });
    if (distinct.size > 1) return Promise.resolve({ kind: "AMBIGUOUS" });
    const [body] = distinct.values();
    return Promise.resolve({ kind: "FOUND", body });
  }

  countDistinctBodiesWithDigest(bodySha256: string): Promise<number> {
    return Promise.resolve(this.textsByDigest.get(bodySha256)?.size ?? 0);
  }
}

/** In-memory `LineagePathProofStore` for tests; keeps each proof and its bodies together. */
export class InMemoryLineagePathProofStore implements LineagePathProofStore {
  readonly written: { proof: LineagePathProofRow; bodies: readonly LineagePathBodyRow[] }[] = [];

  writePathProof(
    proof: LineagePathProofRow,
    bodies: readonly LineagePathBodyRow[],
  ): Promise<void> {
    this.written.push({ proof, bodies });
    return Promise.resolve();
  }
}
