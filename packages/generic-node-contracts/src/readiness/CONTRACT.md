# Readiness concern — CONTRACT_FREEZE

Aligns node readiness with signer leadership. Canonical rules: `startup-sequence` (readiness is
decoupled from signer-lock ownership) and `vault-storage-model` guard 4 (the C-02 lease is the sole
wallet sequencing authority; signing takes no vault row lock). Governing sources: node-core: runtime
components and the readiness sentence; operations-recovery: boot recovery and degraded operation.
Gate: contract/documentation freeze only — frozen `as const` data plus pure verifiers, no endpoint,
no probe, no I/O, no ZKZ.

## The reconciliation this freezes

The draft gates readiness on signer leadership in three places — the node-core readiness sentence
("readiness is false until ... signer leadership is held by exactly one instance"), the
operations-recovery boot sequence step 8 ("report readiness only when ... exactly one signer leader
is active"), and the degraded-operation clause ("readiness is false" when the signer is
unavailable). `startup-sequence` is canonical and decouples them: coupling readiness to leadership
re-introduces the overlap-deploy deadlock that rule fixed. This concern freezes the canonical
semantics and records the superseded draft clauses as data in `RECONCILIATION`.

## What this concern freezes

- **`readiness-checks.contract.ts`** — the closed readiness-check set. Each check names exactly one
  stamping authority and an assertion scope (what it asserts, what it does not). Four gating checks
  (`schema_migrated`, `database_reachable`, `vault_available`, `observation_read_capable`) and one
  reported non-gating check (`signer_leadership`). Structurally removes the v1 `checks.gateway`
  stays-false ambiguity: a check is false only because its single named authority has not stamped it.
  `READINESS_LEADERSHIP_SEPARATION` and `RECONCILIATION` record the predicate split and the
  draft-vs-canonical resolution.
- **`boot-sequence.contract.ts`** — the frozen boot stage sequence and the key-ring load → vault
  census verify → leadership acquisition prerequisite chain, plus the invariants that readiness is
  reachable before leadership and signer authority flips on last (`startup-sequence`).
- **`degraded-modes.contract.ts`** — the four readiness × leadership modes with each mode's allowed
  and forbidden operation classes as a total partition of the operation vocabulary. The money path
  (`SIGN`/`SUBMIT`/`RUN_MONEY_ENGINES`/`MUTATE_ECONOMIC_STATE`) runs only in `READY_AND_LEADER`;
  `READY_NOT_LEADER` is the overlap-deploy standby; `LEADER_NOT_READY` fails closed.
- **`fail-closed.contract.ts`** — the fail-closed rules, and `WALLET_SEQUENCING_AUTHORITY` bound to
  the `vault` concern's own `LEADERSHIP_RULES.wallet_ordering_authority` (C-02) so this concern
  provably introduces no second sequencing authority. Leadership is a node-level writer role;
  leadership loss quiesces signing and never releases or re-sequences wallet leases.
- **`predicates.ts`** — pure predicates over a frozen `NodeReadinessState`: `evaluateReadiness`
  (gating checks only), `hasSignerLeadership` (lock held AND the vault available — key-ring loaded
  AND census verified), `maySign` (READY **and** leadership — exactly the `READY_AND_LEADER` mode,
  so a `LEADER_NOT_READY` instance cannot sign and the DB single-in-flight One-in-flight backstop is never
  bypassed; the C-02 wallet lease is a separate authority checked elsewhere), and the fail-closed
  `assertSigningPermitted`.
- **`verifiers.ts`** — pure conformance verifiers returning frozen violation ids: registry
  ambiguity, boot-sequence prerequisite breaks (schema-before-vault sequencing and duplicate stages
  included), shutdown-sequence prerequisite breaks, a second wallet sequencing authority, and
  node-mode classification.

## Boundaries

Downstream: `engine-startup` implements leader-gated engine startup against these predicates;
`handoff-proof` proves two-instance handoff. Neither is in this slice. `src/index.ts`/
`src/registry.ts` belong to the package registry assembly and are untouched here.

## Encoding tiers

1. `.contract.ts` `as const` sources — authority.
2. `gen/readiness.json` (package `gen/`) — review-diff snapshot of `READINESS_CONTRACT`, never byte
   authority; `gen-sync.test.ts` asserts it equals a fresh emit; its sha256 is pinned in
   `READINESS_CONCERN_MANIFEST.goldenRefs` and cross-checked by `manifest.census.test.ts`.
3. No tier-3 raw byte artifact: this slice freezes semantics, not a signed preimage.
