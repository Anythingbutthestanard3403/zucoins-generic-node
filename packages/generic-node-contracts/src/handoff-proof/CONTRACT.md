# Handoff-proof concern — CONTRACT_FREEZE

The two-instance handoff proof matrix. Canonical rules: `two-instance-handoff-backstop` (overlap
deploy, lock loss, the DB single-in-flight backstop) and `vault-storage-envelope` guard 4 (C-02 is
the sole wallet-sequencing authority). Governing sources: node-core: wallet leases and the
leadership lock; operations-recovery: boot recovery. Gate: contract/documentation freeze
only — frozen `as const` scenario data plus pure proof functions that drive the REAL `readiness` /
`engine-startup` contracts. No two live processes, no runtime, no ZKZ.

## What this concern freezes

- **`scenario-matrix.contract.ts`** — `SCENARIO_MATRIX`: one cell per scenario class
  (`OVERLAP_DEPLOY`, `GRACEFUL_HANDOFF`, `CRASH_FAILOVER`, `SPLIT_BRAIN_ATTEMPT`,
  `READINESS_TRUTH`). Each cell carries two instance `NodeReadinessState` snapshots, the shared
  wallet's in-flight lease state, the takeover step, and the frozen expected outcome (each
  instance's readiness and leadership, whether B may write the shared wallet, the no-concurrent-
  double-write theorem, and takeover acceptance).
- **`proof.ts`** — the pure proof functions. `evaluateCell` computes a cell's ACTUAL outcome by
  driving the real `readiness` `evaluateReadiness` / `hasSignerLeadership` and the `engine-startup`
  `verifyTakeover`; `verifyCell` returns the frozen violation ids where actual differs from
  expected, plus a hard `DOUBLE_WRITE_SAFETY_BREACH` whenever the safety theorem actually fails.
  The two safety layers are modelled independently: `leadershipGateBlocksSharedWrite` (layer 1)
  and `c02LeaseBlocksSharedWrite` (layer 2). The shared wallet carries TWO independent
  observations — `aWriteUnresolved` (A's write may still land; a physical fact that survives A's
  crash) and `walletSequencingHeld` (the C-02 lease / DB single-in-flight row is held) — so the
  "both instances write wallet W" state is representable and the theorem is non-vacuous.

## The proof

- **Overlap deploy** — the new instance is READY-not-leader; its leader-gated write on the shared
  wallet is blocked by layer 1 (it holds no leadership).
- **Graceful handoff** — the outgoing instance has quiesced (leaderA false) before the new leader
  arms; the takeover verifier accepts only quiesce-before-arm.
- **Crash failover** — the incumbent is dead and holds no leadership, yet its economic write is
  still unresolved (`aWriteUnresolved`) and the wallet's C-02 lease / DB in-flight row SURVIVES the
  crash (`boot-recovery-lease-survival`: no time-based lease deletion). That surviving DB
  single-in-flight backstop — not a still-live leader — blocks the recovered leader's second write.
  This is the residual TCP-death window backstop that `engine-startup/split-brain.contract.ts`
  freezes.
- **Split-brain attempt** — both instances believe they are leader (layer 1 bypassed), yet the
  shared wallet's active lease (layer 2) still blocks the phantom leader. The two layers are
  independent: layer 2 alone preserves single-writer safety.
- **Readiness truth** — a booting instance reports not-ready and not-leader; readiness and the
  `signer_leadership` value are computed per the `readiness` registry in every cell.

The safety theorem `noConcurrentDoubleWrite` holds for every cell in which the C-02 + DB backstop
invariant `aWriteUnresolved → walletSequencingHeld` holds: while A's write is unresolved the
wallet's lease/in-flight row is held, so B is not admitted. It is non-vacuous — a cell that
violates that invariant (A's write unresolved while the sequencing authority is free) is a real
concurrent double-write and fires `DOUBLE_WRITE_SAFETY_BREACH`, which the negative paths in
`two-layer.test.ts` exercise.

## Boundaries

This slice freezes the proof matrix and drives the frozen contracts; it stands up no live
processes. `src/index.ts`/`src/registry.ts` belong to the package registry assembly and are
untouched here.

## Encoding tiers

1. `.contract.ts` `as const` source — authority.
2. `gen/handoff-proof.json` — review-diff snapshot of `HANDOFF_PROOF_CONTRACT`, never byte
   authority; `gen-sync.test.ts` asserts it equals a fresh emit; its sha256 is pinned in
   `HANDOFF_PROOF_CONCERN_MANIFEST.goldenRefs` and cross-checked by `manifest.census.test.ts`.
3. No tier-3 raw byte artifact: this slice freezes a proof matrix, not a signed preimage.
