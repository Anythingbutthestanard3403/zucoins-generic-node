# Landing-proof concern — CONTRACT_FREEZE

Frozen artifacts for the frozen any-depth complete-path landing proof — the only oracle that may
prove a buried (non-head) transaction landed. Canonical rule: `complete-path-adjudication`
(any-depth complete-path landing proof anchored at a fresh head). Governing sources: protocol
foundation: chain-link, signing, and settlement rules; operation flows: landing checkpoints per
operation kind; observation-verification: complete-path walk, anomaly classes, retention;
operations-recovery: landing determination in recovery flows; integration: boundary evidence only.
Gate: contract + verifiers + tests only — no runtime/production walk implementation.

Depends on the `observation` concern (the observation ledger). This slice consumes its frozen
`gateway_observations` head-row shape and `verifyGatewayObservationRecord`, and re-freezes none of
them; `observation` wins on any conflict.

## What the ancestry-index layer freezes

The **exact-body signature ancestry index**: the index keyed off byte-identical signed transaction
bodies, and the any-depth ancestry-walk primitive over it.

- **`index-fields.contract.ts`** — the index KEY `(wallet_public_key, step_2_signature)` and the
  ENTRY field shape (exact `completed_transaction_text`, its recomputable digest, `wallet_role`,
  `s_signature`, the role-relative predecessor `p_signature`, `step_1_signature`, source provenance),
  plus `INDEXABILITY_RULE` — only a completely-verified HEAD row with a full body is a chain entry;
  genesis is a terminal, every non-verified disposition is never indexed.
- **`linkage.contract.ts`** — `LINKAGE_RULE` (a child's `p_signature` resolves to the parent's
  `s_signature`, same wallet role-view — the observation-verification SUCCESSOR backlink, walked
  from a fresh head at depth 0); `EXACT_BODY_RULE` (verbatim storage, digest recomputed and
  byte-compared, normalized bodies rejected — the byte-exact signing rule); `COLLISION_RULE` (same
  key + identical bytes is idempotent, same key + differing bytes is a collision surfaced not
  merged); the `INGEST_OUTCOMES` and `WALK_OUTCOMES`
  vocabularies (`WALK_OUTCOMES` = `COMPLETE_CONTIGUOUS`, `INCOMPLETE_MISSING_HOP`,
  `INCOMPLETE_AMBIGUOUS_HOP`, `INCOMPLETE_CYCLE`, `INCOMPLETE_BUDGET_EXHAUSTED` — covering every
  enumerated termination); `WALK_COMPLETENESS` — a walk is `COMPLETE_CONTIGUOUS` when every
  predecessor on the walked path resolves to exactly one byte-exact entry and the walk reaches a
  valid terminus: a **named expected-body terminal** (the canon-minimum expected→head prefix — the
  observation-verification walk and the API proof surface; `terminatesAtGenesisRoot: false`,
  `boundedExpectedToHeadPrefixSufficient: true`)
  or the genesis root when no terminal is bound; an incomplete walk confers no landed conclusion, and
  the walk **always terminates** (a visited-set cycle guard and a bounded step budget); and
  `WALK_STEP_BUDGET_DEFAULT` (the frozen `1_000_000`-hop backstop).
- **`ancestry-index.ts`** — the pure, stateless index: `entryFromRecord` / `isIndexableRecord`,
  `bodyDigestMatches`, `buildAncestryIndex` (folding records to entries + surfacing collisions and
  digest-mismatch rejections), `linksToPredecessor`, `walkAncestry` (head at depth 0 back toward a
  named `terminalStepTwoSig` expected body, or genesis only when unbound — a bound terminal never
  hit is `INCOMPLETE_MISSING_HOP`; **total** — a state-signature cycle /
  self-loop yields `INCOMPLETE_CYCLE` via a deterministic visited-set guard, and a chain longer than
  `stepBudget` (default `WALK_STEP_BUDGET_DEFAULT`) yields `INCOMPLETE_BUDGET_EXHAUSTED`, so an
  adversarial or corrupt index fails closed instead of hanging), `depthOfBody`, and
  `collisionOnPath` (bridges a surfaced index collision on a walked key into the determination
  layer's `indexCollisionOnPath` signal). No storage, network, worker, or keys; the only
  external call is `node:crypto` SHA-256 to recompute a body digest (a pure transform).

**Predecessor linkage is string-equality, not cryptographic — the single load-bearing crypto gate.**
`linksToPredecessor` / `walkAncestry` resolve a body's role-relative predecessor purely by
STRING-comparing a child's `p_signature` against a candidate parent's `s_signature`. Both fields are
only FORMAT-validated (`isPaddedSignature` / `isEmptyOrPaddedSignature`, the padded-base64url shape
the DB CHECK enforces) by the `observation` record verifier before an entry is admitted to the
index — neither this file nor `observation` ever independently verifies that `s_signature` is a
canonical Ed25519 signature over the entry it is attached to. Consequently a record whose
`s_signature` merely happens to STRING-MATCH a child's `p_signature` — a structurally-unique-match
FORGED predecessor that was never produced by validly signing that specific body — traverses the
walk exactly as a genuine predecessor would; `walkAncestry` returning `COMPLETE_CONTIGUOUS` is a
STRUCTURAL claim about pointer matching, not a cryptographic one. The gate that closes this gap is
NOT here: the Ed25519 signature check is the separately-attested `BOTH_SIGNATURES` member of
`REQUIRED_PER_BODY_PREDICATES` (`proof-manifest.contract.ts`), and the determination layer's
`classifyLanding` refuses every positive landing until `attestedPredicatesEstablished` holds — a
`COMPLETE_CONTIGUOUS` walk assembled entirely from string-matched pointers is, by itself,
`PREDICATE_UNVERIFIABLE`, never a landing. Any future consumer of `walkAncestry` /
`linksToPredecessor` directly (bypassing `classifyLanding`) must not treat walk completeness as a
substitute for the attested crypto gate.
- **`fixtures.contract.ts` + `gen/landing-proof.json`** — frozen byte-exact anchors: a 3-hop chain
  (genesis → A depth 2 → B depth 1 → C fresh head depth 0), a MOVE transaction T under both
  sender/receiver role-views, and a reformatted `A_NORMALIZED`. Every `bodySha256` is the real
  SHA-256 of its verbatim body; `ancestry-index.test.ts` recomputes each and asserts the pinned value.

## What the proof-manifest layer freezes

The **any-depth operation proof manifest**: the durable, independently re-verifiable artifact a node
emits to prove a specific expected operation body landed at any finite ancestor depth of a fresh
verified head, plus the re-verification predicate a third party re-runs from that manifest ALONE.
It consumes the ancestry-index layer's index/walk/completeness primitives and the frozen
`OperationKind` domain (from the `operations` concern), and re-freezes neither.

- **`proof-manifest.contract.ts`** — the frozen manifest SHAPE (`OPERATION_IDENTITY_FIELDS`,
  `CLAIMED_LANDED_FIELDS`, `HEAD_READ_PROVENANCE_FIELDS`, `MANIFEST_HOP_FIELDS`,
  `VERIFICATION_SEMANTICS_FIELDS`, `SINGLE_PATH_MANIFEST_FIELDS`, `MOVE_PROOF_MANIFEST_FIELDS`); the
  two positive classifications (`LANDING_CLASSIFICATIONS` = `LANDED_EXACT` / `LANDED_COMPLETE_PATH`);
  the `REQUIRED_PER_BODY_PREDICATES` a valid manifest must declare; `ECONOMIC_EVALUATION_BASIS`
  (`EXPECTED_BODY_T0`, not a later balance); `DEPTH_SEMANTICS` (head is depth 0, **no cap** —
  bounded/incomplete handling is the determination layer's); `REVERIFICATION_PREDICATE` (runs from
  the manifest alone, trusts no producing node, never accepts a partial prefix);
  `MANIFEST_RETENTION` (proof manifests are permanent under the observation-verification retention
  rule; the terminal-plus-30-day window governs endpoint access only, never the underlying
  evidence); and the closed `MANIFEST_REVERIFY_FAILURES` / `REVERIFY_VERDICTS`
  vocabularies. The two positive verdicts are named `STRUCTURALLY_REVERIFIED_LANDED_EXACT` /
  `STRUCTURALLY_REVERIFIED_LANDED_COMPLETE_PATH`: a standalone re-verify attests manifest STRUCTURE
  only (byte-exact bodies, contiguous cycle-free chain, backlinks, head anchor, declared predicates)
  and cannot re-run the deferred Ed25519 / economic crypto — so the name can never be misread as a
  completed, crypto-verified landing (the determination layer gates a landing on the attested
  predicates separately).
- **`proof-manifest.ts`** — the pure, stateless implementation: `buildProofManifest` (truncates an
  ancestry walk at the claimed body's depth into a single-path manifest; returns null when the claimed
  body is absent — no manifest, no verdict), `reVerifyProofManifest` (re-runs the walk from the
  manifest alone: per-hop SHA-256 recompute + byte-compare, role-relative backlink `P == S`,
  depth-0 head anchor, claimed-body-is-chain-terminal, duplicate/cycle and contiguous-depth checks,
  classification consistency, `EXPECTED_BODY_T0` basis, and the required-predicate declaration), and
  `reVerifyMoveProofManifest` (both role-view paths independently, plus the shared-anchor and
  sender/receiver role bindings). Only external call is `node:crypto` SHA-256 — a pure transform,
  exactly as `ancestry-index.ts`.
- **`proof-manifest.golden.contract.ts` + `gen/landing-proof.json`** — frozen golden manifests built
  from the 3-hop fixture chain: a depth-2 buried `LANDED_COMPLETE_PATH` (claimed A, chain
  C→B→A), a depth-1 bounded prefix that stops at the claimed body without reaching genesis (claimed
  B, chain C→B), a depth-0 `LANDED_EXACT` (claimed C), and a MOVE dual-path over fixture T under both
  role-views. Each hop copies a fixture's exact byte-for-byte body and pinned digest;
  `proof-manifest.census.test.ts` recomputes every digest, re-verifies each golden, and drives the
  real index/walk through `buildProofManifest` to prove it reproduces the goldens exactly.

## What the determination layer freezes

The **fail-closed determination side**: what an incomplete or bounded landing attempt CONCLUDES, and
the rule that it concludes nothing actionable. It consumes the ancestry-index layer's `WalkOutcome`
and the proof-manifest layer's `ReverifyVerdict`/`MANIFEST_REVERIFY_FAILURES` and re-freezes neither
(both upstream layers win on any conflict).

- **`fail-closed.contract.ts`** — the `LANDING_DETERMINATIONS` outcome space (`LANDED_EXACT` /
  `LANDED_COMPLETE_PATH` / `INDETERMINATE` — the two positives ARE the proof-manifest layer's
  classifications, plus `INDETERMINATE`; **there is no `PROVEN_NOT_LANDED` member and the type space
  cannot name one**); the closed `INDETERMINATE_CAUSES` taxonomy (`FRESH_HEAD_UNAVAILABLE`,
  `ENDPOINT_CONFLICT`, `WORK_BUDGET_EXHAUSTED`, `INDEX_COLLISION`, `WALK_AMBIGUOUS_HOP`,
  `WALK_MISSING_HOP`, `WALK_CYCLE`, `EXPECTED_BODY_ABSENT_FROM_PATH`, `REVERIFY_REJECTED`,
  `PREDICATE_UNVERIFIABLE`, `INVARIANT_ANOMALY` — covering every enumerated INDETERMINATE trigger,
  `WALK_CYCLE` mapping the walk's
  `INCOMPLETE_CYCLE`) with its `INDETERMINATE_CAUSE_TAXONOMY` traceability list; `FRESH_HEAD_STATUSES`;
  `DETERMINATION_AUTHORITY` (the consumer contract, as data — INDETERMINATE confers ZERO authority and
  holds the lease; **no outcome ever authorizes concluding not-landed**); `REWALK_SEMANTICS` (only new
  observations may change an INDETERMINATE; identical evidence yields the identical outcome; no
  time-based fold to terminal); and `FAIL_CLOSED_INVARIANTS`.
- **`landing-determination.ts`** — the pure, total, deterministic `classifyLanding` classifier over an
  already-computed `LandingEvidence` bundle, plus `buildLandingEvidence`, the sole sanctioned producer
  that DERIVES the walk- and index-sourced signals from the real ancestry-index upstreams
  (`walkOutcome` from the total walk — carrying `INCOMPLETE_CYCLE` / `INCOMPLETE_BUDGET_EXHAUSTED`;
  `indexCollisionOnPath` from
  `collisionOnPath(index, walk.chain)`), closing the "free hand-supplied boolean with no producer" gap.
  No storage/network/worker/keys/clock/hash. The classifier's return outcome type is
  `LandingDeterminationOutcome` (three members, none non-landing), so it CANNOT construct a not-landed
  value — the impossibility is structural, not a runtime guard. The single positive exits require an
  authoritative fresh head, no anomaly, no budget exhaustion, no cycle, no collision, a
  `COMPLETE_CONTIGUOUS` walk, a clean standalone re-verify, AND established attested predicates (a clean
  STRUCTURAL re-verify alone is `PREDICATE_UNVERIFIABLE`, never a landing).
- **`fail-closed.census.test.ts` / `fail-closed.negatives.test.ts` / `landing-evidence.e2e.test.ts`** —
  the closed-set census; the disjointness census (`INDETERMINATE_CAUSES` ∩ `MANIFEST_REVERIFY_FAILURES`
  = ∅) with `REVERIFY_REJECTED` as the single documented bridge; the no-`PROVEN_NOT_LANDED` proofs (a
  `@ts-expect-error` compile-time impossibility plus the runtime census); an exhaustive drive of the
  classifier over the entire finite **480-combination** input type space (`3·2·2·5·4·2`, re-derived
  after budget exhaustion folded into `walkOutcome`; total, cause-disciplined, surjective onto the full
  taxonomy, never a non-landing); a determinism check; one fail-closed negative per cause class; and an
  end-to-end drive that a real cyclic index (`WALK_CYCLE`), a real over-budget walk
  (`WORK_BUDGET_EXHAUSTED`), a real collision on the claimed head (`INDEX_COLLISION`), and a
  structural-re-verify-alone (`PREDICATE_UNVERIFIABLE`) each fail closed through
  `buildLandingEvidence` → `classifyLanding` — the fail-closed actually FIRES, it does not hang.

## Layering held (proof-manifest REJECTED vs determination INDETERMINATE)

- The proof-manifest layer's `reVerifyProofManifest` returns a STRUCTURAL `REJECTED` about a defective
  SUPPLIED manifest ARTIFACT (tampered body, gap, wrong claim). The determination layer's
  `INDETERMINATE` is a landing DETERMINATION about an OPERATION. The two vocabularies are
  **disjoint**: `MANIFEST_REVERIFY_FAILURES`
  are artifact-structural; `INDETERMINATE_CAUSES` are evidence-insufficiency. They connect at exactly
  one point — a proof-manifest `REJECTED` maps up to the determination cause `REVERIFY_REJECTED` (a
  rejected proof proves nothing, and nothing is not-landing).
- The ancestry-index layer owns the index/walk/completeness distinction (`COMPLETE_CONTIGUOUS` vs the
  two incomplete outcomes). The proof-manifest and determination layers consume its
  `WalkResult`/`WalkOutcome` and re-freeze none of it.

The gateway stays head-only and observations are never assumed to be complete history — a walk only
trusts contiguous exact bodies actually held in the index (which may include locally retained,
never-re-observed bodies).

## Negatives (one per fact class)

**Ancestry index:** Collision (same-signature-different-bytes surfaced, never merged); normalized body (a
reformatted body whose recomputed digest no longer matches is rejected); missing hop (a walk over a
chain with an unobserved predecessor is `INCOMPLETE_MISSING_HOP`); ambiguous hop (two entries sharing
a state signature stop the walk as `INCOMPLETE_AMBIGUOUS_HOP`); **cycle** (a two-node state-signature
cycle AND a self-loop — both admitted as `INDEXED` — terminate the real `walkAncestry` as
`INCOMPLETE_CYCLE` under a wall-clock guard proving no hang); **budget exhaustion** (a chain longer
than `stepBudget` terminates as `INCOMPLETE_BUDGET_EXHAUSTED` with the bounded prefix, and a chain
exactly at the budget still completes); **collision-on-path** (`collisionOnPath` flags a surfaced
collision on the claimed head that a `COMPLETE_CONTIGUOUS` walk would otherwise ignore, and does NOT
flag a collision on an off-path wallet key).

**Proof manifest:** tampered hop body (`HOP_DIGEST_MISMATCH`); missing interior hop rejected whole, never a
partial landing (`BROKEN_BACKLINK` + `NON_CONTIGUOUS_DEPTHS`); claimed body ≠ chain terminal
(`CLAIMED_BODY_NOT_CHAIN_TERMINAL`); classification/shape mismatch (`CLASSIFICATION_MISMATCH`); head
anchor mismatch (`HEAD_ANCHOR_MISMATCH`); non-authoritative head (`HEAD_NOT_AUTHORITATIVE`);
later-balance economics (`ECONOMIC_BASIS_NOT_EXPECTED_BODY_T0`); missing required predicate
(`INCOMPLETE_PER_BODY_PREDICATES`); unknown version (`UNKNOWN_MANIFEST_VERSION`); MOVE role/anchor
mismatch (`MOVE_PATH_ROLE_MISMATCH` / `MOVE_ANCHOR_MISMATCH`); duplicate/cycle hop
(`DUPLICATE_OR_CYCLE_HOP`). Each is demonstrated to fire.

**Determination:** one fail-closed negative per cause class — each forces `INDETERMINATE` with exactly that
cause and zero authority: stale/unverifiable head (`FRESH_HEAD_UNAVAILABLE`); disagreeing endpoints
(`ENDPOINT_CONFLICT`); over-budget bounded walk (`WORK_BUDGET_EXHAUSTED`, driven by
`walkOutcome === INCOMPLETE_BUDGET_EXHAUSTED`); state-signature cycle (`WALK_CYCLE`, driven by
`walkOutcome === INCOMPLETE_CYCLE`); surfaced index collision (`INDEX_COLLISION`); ambiguous
predecessor (`WALK_AMBIGUOUS_HOP`); missing predecessor body (`WALK_MISSING_HOP`); complete chain
lacking the expected body — INDETERMINATE, never not-landed (`EXPECTED_BODY_ABSENT_FROM_PATH`);
a re-verify `REJECTED` bridged up (`REVERIFY_REJECTED`); an unestablished attested predicate
(`PREDICATE_UNVERIFIABLE`); a custody/invariant anomaly (`INVARIANT_ANOMALY`). Plus: precedence fails
closed (an anomaly dominates an otherwise-clean exact proof); re-interpreting identical evidence never
flips; and only a NEW observation flips an INDETERMINATE to a landing. A `@ts-expect-error` proves
`PROVEN_NOT_LANDED` is not expressible. `landing-evidence.e2e.test.ts` proves the same fail-closed
outcomes fire end-to-end from a real index/walk through `buildLandingEvidence`, including the S2 safety
property that a clean STRUCTURAL re-verify with the crypto predicates NOT attested is
`PREDICATE_UNVERIFIABLE`, never a landing.

## Encoding tiers

1. `.contract.ts` `as const` sources — the byte authority.
2. `gen/landing-proof.json` — review-diff snapshot of `LANDING_PROOF_CONTRACT`, never byte authority;
   `gen-sync.test.ts` asserts it equals a fresh emit. Its sha256 is pinned in
   `LANDING_PROOF_CONCERN_MANIFEST.goldenRefs` and cross-checked by `manifest.census.test.ts`.
   Regenerate with `JSON.stringify(toSortedPlainObject(LANDING_PROOF_CONTRACT), null, 2) + "\n"`.
3. The byte-exact bodies + pinned SHA-256 digests in `fixtures.contract.ts` are the tier-3 anchor;
   the test recomputes each digest rather than trusting the transcription.
