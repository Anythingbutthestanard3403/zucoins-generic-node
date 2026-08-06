# Engine-startup concern — CONTRACT_FREEZE

Leader-gated money-engine startup. Governing decisions: **`startup-sequence`**
(startMoneyEngines runs only on the lock holder; the signer authority flips on last; on lock loss
markLost then graceful restart; the DB single-in-flight-per-wallet constraint is the ultimate
backstop) and **`vault-storage-model`** guard 4 (the universal wallet lease is the sole
wallet-sequencing authority), with **`leadership-lease`** governing the lock itself. Governing
sources: node-core startup; operations recovery. Gate: contract/documentation freeze only —
frozen `as const` data plus pure verifiers, no runtime engine, no I/O, no ZKZ. Consumes the
readiness predicates and operation vocabulary; the wallet lease stays the sole
wallet-sequencing authority.

## What this slice freezes

- **`engines.contract.ts`** — the engine registry. Each engine is classified `LEADER_REQUIRED` or
  `FOLLOWER_SAFE`. A leader-gated engine is an economic-state writer (leases, wallet state,
  signatures, submissions, minted keys) and runs only on the leader; a follower-safe engine is not
  an economic-state writer and names the non-economic operations it may run without leadership.
- **`startup-sequence.contract.ts`** — the leader-only startup sub-sequence expanding the readiness
  concern's `ENGINE_ACTIVATION` boot stage (rebuild queues → reconciler → mutation workers → arm
  signer authority last), and the leadership-loss shutdown sub-sequence (mark lost → stop new work →
  in-flight completes under its wallet lease → graceful exit). Loss never force-releases or
  re-sequences a lease and never creates a second authority.
- **`split-brain.contract.ts`** — the no-split-brain invariant (two safety layers: at most one
  leader holds the lock and a follower's leader-gated engines cannot economic-write; the wallet
  lease plus the DB single-in-flight-per-wallet constraint as the physical backstop) and the
  takeover boundary (the old leader quiesces before the new acquires the lock; the new leader runs
  boot recovery, then engines, then arms authority last).
- **`predicates.ts`** — pure predicates over a readiness `NodeReadinessState`: `engineMayRun`,
  `engineMayEconomicWrite` (economic-writer engine AND leadership), and the fail-closed
  `assertEngineEconomicWritePermitted`.
- **`verifiers.ts`** — pure conformance verifiers returning frozen violation ids: registry
  consistency (follower operations bounded by the readiness concern's `READY_NOT_LEADER` allowed
  set), startup/shutdown sequence breaks, and the takeover boundary.

## Boundaries

Downstream: the handoff-proof concern proves the two-instance handoff empirically (overlap deploy,
delayed release, connection loss, DB failover, split-brain attempts, in-flight recovery,
exactly-one-signer). That proof matrix is NOT in this slice — this freezes the contract it verifies
against. `src/index.ts`/`src/registry.ts` belong to the package registry slice and are untouched
here.

## Encoding tiers

1. `.contract.ts` `as const` sources — authority.
2. `gen/engine-startup.json` (package `gen/`) — review-diff snapshot of `ENGINE_STARTUP_CONTRACT`,
   never byte authority; `gen-sync.test.ts` asserts it equals a fresh emit; its sha256 is pinned in
   `ENGINE_STARTUP_CONCERN_MANIFEST.goldenRefs` and cross-checked by `manifest.census.test.ts`.
3. No tier-3 raw byte artifact: this slice freezes semantics, not a signed preimage.
