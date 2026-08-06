/**
 * SOURCE: the observation-verification spec (SUCCESSOR backlink, complete-path walk), the
 * protocol foundation, and the complete-path landing-proof rule. the landing-proof index/walk —
 * the frozen linkage / walk / exact-body / collision semantics of the index.
 *
 * Boundary: the landing-proof index/walk freezes the index primitive and the completeness DISTINCTION a walk produces.
 * The fail-closed disposition of an incomplete walk — its full INDETERMINATE cause taxonomy and the
 * rule that it confers no retry / later-attempt / release / resubmit authority — is the landing-proof e2e's; this
 * slice does not enumerate it.
 */

/**
 * Role-relative predecessor linkage — the any-depth ancestry-walk primitive. A body's role-relative
 * PREDECESSOR is the entry (same wallet role-view) whose current state signature (`s_signature`)
 * equals this body's previous state signature (`p_signature`). This is the SUCCESSOR backlink
 * ("new P equals prior S"), walked backwards from a fresh verified head at depth 0.
 */
export const LINKAGE_RULE = {
  predecessorPointer: "p_signature",
  resolvesAgainst: "s_signature",
  sameWalletRoleView: true,
  headDepth: 0,
  genesisRootPredecessor: "",
  backlinkSource: "SUCCESSOR backlink (new P equals prior S)",
} as const;

/**
 * Byte-exact keying (the byte-exact signing rule). The entry stores the completed transaction body verbatim; its
 * digest must equal `completed_transaction_sha256`. A normalized / reformatted body has a different
 * digest and is rejected — the index never keys off, stores, or merges a re-serialized body.
 */
export const EXACT_BODY_RULE = {
  storedVerbatim: true,
  digestField: "completed_transaction_sha256",
  digestAlgo: "sha256",
  normalizedBodyRejected: true,
  reason: "the signed bytes are the identity; a reformatted body is a different, unverifiable object",
} as const;

/**
 * Collision / conflicting-mapping rule. The same (wallet, step-2 signature) key must map to exactly
 * one exact body. A second record under the same key with IDENTICAL bytes is idempotent (the same
 * body re-observed); a second record with DIFFERING bytes is a COLLISION — surfaced, never merged or
 * overwritten. A same-signature-different-bytes body is an attack or a corrupt read, not an update.
 */
export const COLLISION_RULE = {
  keyMapsToExactlyOneBody: true,
  identicalBytesIdempotent: true,
  differingBytesIsCollision: true,
  collisionSurfacedNeverMerged: true,
} as const;

/**
 * The disposition of a single record presented to the index.
 * `INDEXED` — a new indexable entry was admitted; `IDEMPOTENT` — its key already held a byte-identical
 * body; `COLLISION` — its key already held a DIFFERENT body (surfaced, not merged);
 * `REJECTED_DIGEST_MISMATCH` — its body's recomputed digest does not equal its stored digest (a
 * normalized or corrupt body); `REJECTED_NOT_INDEXABLE` — not a verified head with a complete body.
 */
export const INGEST_OUTCOMES = [
  "INDEXED",
  "IDEMPOTENT",
  "COLLISION",
  "REJECTED_DIGEST_MISMATCH",
  "REJECTED_NOT_INDEXABLE",
] as const;
export type IngestOutcome = (typeof INGEST_OUTCOMES)[number];

/**
 * The outcome of a walk from a fresh verified head back along role-relative predecessors.
 * `COMPLETE_CONTIGUOUS` — every predecessor on the walked path resolved to exactly one byte-exact
 * entry, and the walk terminated at a valid terminus: either a named expected-body terminal (the
 * canon-minimum expected→head prefix) or the genesis root (`p_signature === ""`)
 * when no terminal is bound; `INCOMPLETE_MISSING_HOP` — a needed predecessor body is absent from the
 * index (an unobserved / unretained body); `INCOMPLETE_AMBIGUOUS_HOP` — a predecessor resolved to more
 * than one entry (a state-signature collision), so no single chain can be trusted; `INCOMPLETE_CYCLE`
 * — a predecessor pointer resolves back to an entry already on the walk (a state-signature cycle or
 * self-loop); `INCOMPLETE_BUDGET_EXHAUSTED` — the walk hit its bounded step budget before a terminus.
 * Only `COMPLETE_CONTIGUOUS` is a reconstructable path; every incomplete outcome confers no landed
 * conclusion. The two termination-guard outcomes (`INCOMPLETE_CYCLE`, `INCOMPLETE_BUDGET_EXHAUSTED`)
 * make the walk TOTAL — it always returns, never loops or grows unbounded — so a cyclic or over-large
 * index fails closed to an incomplete outcome (the complete-path landing-proof rule duplicate/cycle and verifier resource/budget
 * exhaustion) instead of hanging. the landing-proof e2e maps each incomplete outcome to its INDETERMINATE cause.
 */
export const WALK_OUTCOMES = [
  "COMPLETE_CONTIGUOUS",
  "INCOMPLETE_MISSING_HOP",
  "INCOMPLETE_AMBIGUOUS_HOP",
  "INCOMPLETE_CYCLE",
  "INCOMPLETE_BUDGET_EXHAUSTED",
] as const;
export type WalkOutcome = (typeof WALK_OUTCOMES)[number];

/**
 * The completeness contract a walk enforces. An incomplete walk confers NO landed conclusion; the
 * fail-closed taxonomy that turns that into an INDETERMINATE with no downstream authority is owned by
 * the landing-proof e2e. The gateway stays head-only and observations are never assumed to be complete history —
 * a walk only trusts contiguous exact bodies actually held in the index. Canon (the ancestor
 * rule) requires a gap-free expected→head path, NOT a walk all the way to
 * genesis: `terminatesAtGenesisRoot` is therefore false. A named `terminalStepTwoSig` (the expected
 * body at path_index 0) is a sufficient terminus; genesis remains an optional terminus when the
 * caller wants a full role-view history and has not bound a terminal. The walk is total: a
 * deterministic visited-set cycle guard and a bounded step budget mean it always returns a
 * `WalkOutcome` — a cyclic or over-budget index yields `INCOMPLETE_CYCLE` / `INCOMPLETE_BUDGET_EXHAUSTED`,
 * never a non-terminating loop (the phantom-settle "fail-closed that never closes" is thereby closed).
 */
export const WALK_COMPLETENESS = {
  headDepth: 0,
  completeRequiresContiguousExactChain: true,
  /** Canon puts the terminus at the expected body (or genesis only when unbound) — never genesis-required. */
  terminatesAtGenesisRoot: false,
  /** Canonical minimum path: expected transaction through fresh head, nothing earlier. */
  boundedExpectedToHeadPrefixSufficient: true,
  incompleteConfersNoLandedConclusion: true,
  gatewayRemainsHeadOnly: true,
  observationsNotAssumedCompleteHistory: true,
  walkAlwaysTerminates: true,
  terminationGuards: ["visited-set cycle guard", "bounded step budget"],
  failClosedTaxonomyOwner: "fail-closed-determination",
} as const;

/**
 * The frozen default per-walk step budget: the maximum number of hops a walk will include in a chain
 * before failing closed with `INCOMPLETE_BUDGET_EXHAUSTED`. A deterministic backstop, NOT a history
 * limit. The visited-set cycle guard already terminates ANY cyclic index in O(distinct entries on the
 * path), so this bound only ever binds on a NON-cyclic chain longer than any plausible real wallet
 * role-view history. Frozen generously at 1,000,000 because: (a) a role-view history that deep is
 * itself an anomaly the oracle must refuse (the complete-path landing-proof rule "verifier resource/budget exhaustion yields
 * INDETERMINATE"), never silently truncate to a shorter "complete" path; (b) the walk does O(1) work
 * per hop, so even a full 1e6-hop walk returns in well under a second — the bound can never reintroduce
 * the phantom-settle hang it exists to prevent. `walkAncestry` takes the budget as an explicit
 * parameter defaulting to this constant; a smaller positive budget keeps the walk total.
 */
export const WALK_STEP_BUDGET_DEFAULT = 1_000_000 as const;
