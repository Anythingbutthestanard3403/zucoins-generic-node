/**
 * SOURCE: the observation-verification spec (relationship classes, complete-path walk) and the
 * complete-path landing-proof rule. the landing-proof index/walk — the pure exact-body signature ancestry index: build it from
 * the observation concern verified head records, and walk it to any finite ancestor depth.
 *
 * Pure and stateless: no storage, no network, no worker, no keys. The only external call is
 * `node:crypto` SHA-256 to recompute a body digest for the byte-exact check — a pure transform.
 */

import { createHash } from "node:crypto";

import {
  type GatewayObservationRecord,
  isValidGatewayObservationRecord,
} from "../observation/record-verifier.ts";
import {
  type IngestOutcome,
  type WalkOutcome,
  WALK_STEP_BUDGET_DEFAULT,
} from "./linkage.contract.ts";

export interface AncestryIndexEntry {
  readonly wallet_public_key: string;
  readonly step_2_signature: string;
  readonly wallet_role: "sender" | "receiver";
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
  readonly s_signature: string;
  readonly p_signature: string;
  readonly step_1_signature: string;
  readonly source_observation_id: string;
}

export interface IndexCollision {
  readonly wallet_public_key: string;
  readonly step_2_signature: string;
  readonly existing_sha256: string;
  readonly conflicting_sha256: string;
  readonly conflicting_observation_id: string;
}

export interface AncestryIndex {
  readonly byKey: ReadonlyMap<string, AncestryIndexEntry>;
  readonly byState: ReadonlyMap<string, readonly AncestryIndexEntry[]>;
  readonly collisions: readonly IndexCollision[];
}

export interface IngestLogEntry {
  readonly wallet_public_key: string;
  readonly step_2_signature: string;
  readonly outcome: IngestOutcome;
}

export interface WalkStep {
  readonly depth: number;
  readonly entry: AncestryIndexEntry;
}

export interface WalkResult {
  readonly outcome: WalkOutcome;
  readonly chain: readonly WalkStep[];
}

const sha256hex = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

const keyOf = (wallet: string, stepTwoSig: string): string => `${wallet}\n${stepTwoSig}`;
const stateKeyOf = (wallet: string, sig: string): string => `${wallet}\n${sig}`;

/** True iff the entry's stored digest equals the SHA-256 of its verbatim body (byte-exact). */
export const bodyDigestMatches = (entry: {
  readonly completed_transaction_text: string;
  readonly completed_transaction_sha256: string;
}): boolean => sha256hex(entry.completed_transaction_text) === entry.completed_transaction_sha256;

/**
 * Project an indexable record to an entry, or null for a non-indexable record: a completely-verified
 * HEAD row that passes the observation concern's record verifier and carries a full completed body plus the signatures
 * the index keys and links on. Genesis and every non-verified disposition project to null. Field
 * narrowing (rather than casts) proves the non-null projection.
 */
export const entryFromRecord = (record: GatewayObservationRecord): AncestryIndexEntry | null => {
  if (record.parse_result !== "VERIFIED_HEAD") return null;
  if (!isValidGatewayObservationRecord(record)) return null;

  const {
    completed_transaction_text,
    completed_transaction_sha256,
    step_2_signature,
    s_signature,
    p_signature,
    step_1_signature,
    wallet_role,
  } = record;

  if (
    completed_transaction_text === null ||
    completed_transaction_sha256 === null ||
    step_2_signature === null ||
    s_signature === null ||
    p_signature === null ||
    step_1_signature === null
  ) {
    return null;
  }
  if (wallet_role !== "sender" && wallet_role !== "receiver") return null;

  return {
    wallet_public_key: record.wallet_public_key,
    step_2_signature,
    wallet_role,
    completed_transaction_text,
    completed_transaction_sha256,
    s_signature,
    p_signature,
    step_1_signature,
    source_observation_id: record.id,
  };
};

/** True iff a record is an indexable full-body chain entry (projects to a non-null entry). */
export const isIndexableRecord = (record: GatewayObservationRecord): boolean =>
  entryFromRecord(record) !== null;

/**
 * True iff `child` links to `parent` as its role-relative predecessor: same wallet role-view, and
 * the child's previous state signature equals the parent's current state signature (the SUCCESSOR backlink). A
 * genesis-rooted body (empty predecessor) links to no parent.
 */
export const linksToPredecessor = (
  child: AncestryIndexEntry,
  parent: AncestryIndexEntry,
): boolean =>
  child.wallet_public_key === parent.wallet_public_key &&
  child.p_signature !== "" &&
  child.p_signature === parent.s_signature;

/**
 * Fold a set of observed records into the ancestry index. Each record's disposition is recorded in
 * the ingest log; a same-key different-bytes body is surfaced as a collision and never merged; a
 * body whose recomputed digest disagrees with its stored digest is rejected.
 */
export const buildAncestryIndex = (
  records: readonly GatewayObservationRecord[],
): { readonly index: AncestryIndex; readonly ingestLog: readonly IngestLogEntry[] } => {
  const byKey = new Map<string, AncestryIndexEntry>();
  const byState = new Map<string, AncestryIndexEntry[]>();
  const collisions: IndexCollision[] = [];
  const ingestLog: IngestLogEntry[] = [];

  for (const record of records) {
    const entry = entryFromRecord(record);
    if (entry === null) {
      ingestLog.push({
        wallet_public_key: record.wallet_public_key,
        step_2_signature: record.step_2_signature ?? "",
        outcome: "REJECTED_NOT_INDEXABLE",
      });
      continue;
    }

    const log = (outcome: IngestOutcome): void => {
      ingestLog.push({
        wallet_public_key: entry.wallet_public_key,
        step_2_signature: entry.step_2_signature,
        outcome,
      });
    };

    if (!bodyDigestMatches(entry)) {
      log("REJECTED_DIGEST_MISMATCH");
      continue;
    }

    const key = keyOf(entry.wallet_public_key, entry.step_2_signature);
    const existing = byKey.get(key);
    if (existing === undefined) {
      byKey.set(key, entry);
      const stateKey = stateKeyOf(entry.wallet_public_key, entry.s_signature);
      const bucket = byState.get(stateKey);
      if (bucket === undefined) byState.set(stateKey, [entry]);
      else bucket.push(entry);
      log("INDEXED");
      continue;
    }

    if (existing.completed_transaction_text === entry.completed_transaction_text) {
      log("IDEMPOTENT");
      continue;
    }

    collisions.push({
      wallet_public_key: entry.wallet_public_key,
      step_2_signature: entry.step_2_signature,
      existing_sha256: existing.completed_transaction_sha256,
      conflicting_sha256: entry.completed_transaction_sha256,
      conflicting_observation_id: entry.source_observation_id,
    });
    log("COLLISION");
  }

  return { index: { byKey, byState, collisions }, ingestLog };
};

/**
 * Bounds for {@link walkAncestry}. `stepBudget` caps hops (default `WALK_STEP_BUDGET_DEFAULT`).
 * `terminalStepTwoSig`, when set, is a required expected-body terminus (path_index 0): the walk is
 * `COMPLETE_CONTIGUOUS` only once that body is on the chain — the canon-minimum expected→head prefix
 * (the canonical completeness rule, matching node-core `walkAncestryPath`). Bodies older than the terminal are not
 * required and are not walked. If the walk reaches genesis without hitting the bound, the outcome is
 * `INCOMPLETE_MISSING_HOP` (genesis COMPLETE only when unbound).
 */
export interface WalkAncestryBounds {
  readonly stepBudget?: number;
  readonly terminalStepTwoSig?: string;
}

/**
 * Walk a wallet's chain from the fresh verified head (identified by its step-2 signature) at depth 0
 * back along role-relative predecessors. Completeness terminals (canon):
 * - with `terminalStepTwoSig`: the expected body is reached (bounded expected→head prefix — does NOT
 *   require genesis; genesis without the bound is `INCOMPLETE_MISSING_HOP`);
 * - without a terminal: the genesis root (`p_signature === ""`).
 * A missing or ambiguous predecessor stops the walk as incomplete and the returned chain is exactly
 * the contiguous prefix that WAS resolvable.
 *
 * The fourth argument accepts a plain `stepBudget` number (legacy callers) or a {@link WalkAncestryBounds}
 * object so callers can bind the expected-body terminal without an options race on positional args.
 *
 * The walk is TOTAL. Two deterministic termination guards make an adversarial or corrupt index fail
 * closed instead of hanging (the complete-path landing-proof rule): a VISITED-SET cycle guard (a predecessor that resolves back to an
 * entry already on the path — a two-node state-signature cycle, a self-loop, or any longer loop —
 * yields `INCOMPLETE_CYCLE`), and a bounded STEP BUDGET (`stepBudget`, defaulting to
 * `WALK_STEP_BUDGET_DEFAULT`; a chain that would exceed it yields `INCOMPLETE_BUDGET_EXHAUSTED`). The
 * visited-set is exact, so every cycle is reported as a cycle; the budget only ever binds on a
 * genuinely over-long acyclic chain and is the belt-and-suspenders bound.
 */
export const walkAncestry = (
  index: AncestryIndex,
  wallet: string,
  headStepTwoSig: string,
  stepBudgetOrBounds: number | WalkAncestryBounds = WALK_STEP_BUDGET_DEFAULT,
): WalkResult => {
  const bounds: WalkAncestryBounds =
    typeof stepBudgetOrBounds === "number"
      ? { stepBudget: stepBudgetOrBounds }
      : stepBudgetOrBounds;
  const stepBudget = bounds.stepBudget ?? WALK_STEP_BUDGET_DEFAULT;
  const terminalStepTwoSig = bounds.terminalStepTwoSig;

  const head = index.byKey.get(keyOf(wallet, headStepTwoSig));
  if (head === undefined) return { outcome: "INCOMPLETE_MISSING_HOP", chain: [] };

  const chain: WalkStep[] = [{ depth: 0, entry: head }];
  const visited = new Set<string>([keyOf(head.wallet_public_key, head.step_2_signature)]);
  let current = head;
  let depth = 0;

  for (;;) {
    // Bound terminus first: expected body on the chain is COMPLETE even when p is non-empty
    // (buried landing whose expected body is not the wallet's first transaction).
    if (terminalStepTwoSig !== undefined && current.step_2_signature === terminalStepTwoSig) {
      return { outcome: "COMPLETE_CONTIGUOUS", chain };
    }
    // Genesis COMPLETE only when unbound. A named terminal that never appeared is a missing hop.
    if (current.p_signature === "") {
      if (terminalStepTwoSig !== undefined) {
        return { outcome: "INCOMPLETE_MISSING_HOP", chain };
      }
      return { outcome: "COMPLETE_CONTIGUOUS", chain };
    }

    const parents = index.byState.get(stateKeyOf(wallet, current.p_signature));
    if (parents !== undefined && parents.length > 1) {
      return { outcome: "INCOMPLETE_AMBIGUOUS_HOP", chain };
    }
    const parent = parents?.length === 1 ? parents[0] : undefined;
    if (parent === undefined) return { outcome: "INCOMPLETE_MISSING_HOP", chain };

    const parentKey = keyOf(parent.wallet_public_key, parent.step_2_signature);
    if (visited.has(parentKey)) return { outcome: "INCOMPLETE_CYCLE", chain };
    if (chain.length >= stepBudget) return { outcome: "INCOMPLETE_BUDGET_EXHAUSTED", chain };

    visited.add(parentKey);
    current = parent;
    depth += 1;
    chain.push({ depth, entry: current });
  }
};

/**
 * True iff any entry on a resolved walk chain shares its (wallet, step-2 signature) key with a
 * surfaced index collision — i.e. a hop on the path is one of two conflicting exact bodies the index
 * refused to merge (`COLLISION_RULE`). `buildAncestryIndex` keeps the FIRST body under a colliding key
 * and records the conflict in `index.collisions`, so a `COMPLETE_CONTIGUOUS` walk can still traverse a
 * key that has an unresolved collision (notably a collision on the claimed head). This producer bridges
 * that index-level fact into the landing-proof e2e determination's `indexCollisionOnPath` signal so a collision
 * on the path fails closed to INDETERMINATE rather than being silently ignored.
 */
export const collisionOnPath = (
  index: AncestryIndex,
  chain: readonly WalkStep[],
): boolean => {
  if (index.collisions.length === 0 || chain.length === 0) return false;
  const pathKeys = new Set<string>(
    chain.map((step) => keyOf(step.entry.wallet_public_key, step.entry.step_2_signature)),
  );
  return index.collisions.some((collision) =>
    pathKeys.has(keyOf(collision.wallet_public_key, collision.step_2_signature)),
  );
};

/** The depth at which the body with `stepTwoSig` appears in a walk chain, or null if absent. */
export const depthOfBody = (result: WalkResult, stepTwoSig: string): number | null => {
  const step = result.chain.find((s) => s.entry.step_2_signature === stepTwoSig);
  return step === undefined ? null : step.depth;
};
