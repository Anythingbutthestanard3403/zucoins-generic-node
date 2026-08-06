# Pool-policy concern — frozen contract

Receive-pool sizing, growth, backpressure, and retirement policy. Binding decisions:
**`receive-queue-backpressure`** and its dual-run addendum, refined by
**`recovery-gated-eligibility`**. Tier-1 grounds: **`permanent-key-material-cap`** (floor 5 /
cap 50-to-500 / 10% headroom / never-retire), **`pool-sizing-policy`** (exact-integer headroom),
**`custody-evidence-requirements`** (advisory-lock CAS). LIVE-CUSTODY-SENSITIVE: this freezes
the *policy* only; it mints nothing and authorizes no send.

This concern is native integer/count arithmetic — it has **no** `bignumber.js` dependency and
imports no other concern.

## Frozen facts

- Sizing (backpressure rule 1): `POOL_FLOOR = 5`; `POOL_CAP_DEFAULT = 50`,
  implementer-configurable to `POOL_CAP_CEILING = 500`. Provisioning target as a TOTAL:
  `ceil(open_sessions * 11 / 10)` clamped to `[POOL_FLOOR, pool_cap]` — the **exact integer**
  form (11/10), never the float `open_sessions * 1.10` (a permanent over-mint). The idle-spare
  `POOL_TARGET_AVAILABLE` knob does not exist.
- Growth (rule 3): `computeMintBatch` mints `min(deficit, cap_headroom, MINT_BATCH_LIMIT=5)`,
  never negative; minting STOPS at cap (fail-closed, rule 4).
- Cap counting (rule 2): `pool_cap` counts ALL non-deleted wallets incl. PINNED / QUARANTINED /
  RETIRED (`capCount = wallets.length`; nothing is ever deleted). Retirement never restores
  capacity. Counting only non-retired wallets is forbidden: retire→mint would be an unbounded
  permanent-key vector.
- Recovery-gated availability (**`recovery-gated-eligibility`**): `availableWalletCount` counts
  ONLY `key_origin='node_generated' AND recovery_verified_at IS NOT NULL AND state='AVAILABLE'`.
  A minted-but-unverified wallet raises the cap but never the available count — **replenishment
  is the recovery ceremony, not the mint loop**. Two distinct counts (`availableWalletCount` vs
  `capCount`) are the load-bearing refinement.
- Backpressure (rule 4, fail-closed): `receiveAdmissionDecision` → assign if a verified-AVAILABLE
  wallet exists; else queue FIFO (202) while depth `< RECEIVE_QUEUE_CAP = pool_cap`; else reject
  `503 receive_queue_full` with a `Retry-After` (`retryAfterSeconds = RECEIVE_QUEUE_RETRY_AFTER_SECONDS`,
  derived from the max-wait — the soonest a queued receive expires and frees a slot), create nothing.
  A queued receive is the existing unassigned `RECEIVE_EXTERNAL / CREATED` shape — never a new
  `QUEUED` state. `RECEIVE_QUEUE_DEQUEUE_ORDER` sequences operations by `created_at ASC`, then
  semantic `operation_id ASC`, independently of wallet selection. Promotion locks the oldest
  operation row with `FOR UPDATE` and no `SKIP LOCKED`, captures decision time after that lock, and
  atomically chooses expire-or-assign. `isReceiveExpired` remains strictly
  `> RECEIVE_QUEUE_MAX_WAIT`: equality may proceed to wallet selection; the first time unit beyond
  it transitions `CREATED → EXPIRED` with no wallet association, lease, T0, code, artifact, or
  signing work. The assignment branch rechecks the queued predicate under the same transaction.
- Retirement / key retention (rules 5-6, the key-custody rule / `permanent-key-material-cap`):
  `RETIRED` is a logical pool-membership flag only (removed from new-receive selection and
  automatic-sink eligibility, but observable and a valid send-side MOVE source so funds stay
  sweepable). `AVAILABLE → RETIRED` only, never from PINNED, no un-retire that skips
  re-verification. Both layers are frozen: the legal-transition predicate in `states.ts`, and the
  WRITE mechanism `RETIRE_WALLET_CAS_SQL` + pure `retireWallet` in `retirement.ts` (row_version
  CAS guarded on `state='AVAILABLE'`, symmetric with the reserve CAS) — so a downstream naked
  `UPDATE … SET state='RETIRED' WHERE id=$1` cannot retire a live-leased wallet and strand its
  funds. Keys are never deleted in any state (`POOL_KEY_DELETION_ALLOWED = false`; no DELETED
  state / transition); the schema-privileges slice enforces this structurally by revoking the DB
  `DELETE` grant.

## Retirement-collision resolution

The enum literal `RETIRED` reads as a collision with the "never retired/deleted" key-custody
rule, and needs either a rename or an explicit binding. This freeze **binds the literal to
logical-only semantics** (keeps `RETIRED`, adds `POOL_KEY_DELETION_ALLOWED = false` + no-delete
state/transition) rather than renaming to `DEACTIVATED`/`WITHDRAWN` — keeping the term the
sizing, eligibility and key-custody rules all use, while resolving the collision structurally.

## Operator-flagged constants (recorded as data, operative values frozen)

`POOL_POLICY_FLAGS` records the four flagged numbers. Most important:
`RECEIVE_QUEUE_MAX_WAIT_MS` operative **30s**, dual-run **recommended ~120s** (clears one
replenishment cycle while remaining bounded), `status: flagged_for_operator`. The
operative value stays 30s until an operator confirms the change; the recommendation is data,
not a silent change.

## Clause → code

| Clause | Code |
|---|---|
| Exact-integer proportional target, POOL_FLOOR/cap clamp | `sizing.ts` `computeProvisioningTarget` |
| Bounded mint, fail-closed at cap | `sizing.ts` `computeMintBatch` |
| Cap counts all non-deleted; RETIRED counts | `states.ts` `countsTowardCap`, `eligibility.ts` `capCount` |
| Recovery-gated availability | `eligibility.ts` `isAvailableForReceive` / `availableWalletCount` |
| Retirement state machine, never-from-PINNED, no un-retire | `states.ts` `POOL_WALLET_TRANSITIONS` / `isValidPoolTransition` |
| Retirement WRITE mechanism, row_version CAS never-from-PINNED | `retirement.ts` `RETIRE_WALLET_CAS_SQL` / `retireWallet` |
| Permanent key retention, no delete | `states.ts` `POOL_KEY_DELETION_ALLOWED` |
| Fail-closed queue admission, FIFO dequeue, atomic expire-or-assign, 503-at-cap + Retry-After | `queue.ts` `receiveAdmissionDecision` / `selectNextQueuedReceive` / `receiveQueuePromotionDecision`; `constants.ts` `RECEIVE_QUEUE_RETRY_AFTER_SECONDS` |
| Flagged constants | `manifest.ts` `POOL_POLICY_FLAGS` |

## Regeneration

- `gen/pool-policy.json` is a committed snapshot of `poolPolicyContract`; `manifest.test.ts`
  fails on drift. Regenerate via `JSON.stringify(poolPolicyContract, null, 2)`.
- `__tables__/capacity.table.json` is generated from `computeProvisioningTarget` /
  `computeMintBatch` and digest-pinned in `capacity-table.test.ts` (`TABLE_SHA256`, no trailing
  newline). To change it, regenerate and re-pin the new `shasum -a 256`; the per-row test also
  recomputes every row against the live functions.

## Selection / reservation / scale-up transaction contract (frozen) <!-- contract-allow:frozen-concern-vocabulary -->

The pool-selection and scaling transaction semantics, frozen as data + pure models. SQL text is
contract-level (bindable by the schema and runtime slices to the final data model); the pure
models are the executable, testable semantics. No SQL is executed here.

- **Available-wallet selection** (`selection.ts`): `SELECT_ASSIGNABLE_WALLET_SQL` — the
  recovery-gated eligibility conjunction (`key_origin='node_generated' AND
  recovery_verified_at IS NOT NULL AND state='AVAILABLE'`),
  `ORDER BY created_at ASC, id ASC`, `FOR UPDATE SKIP LOCKED LIMIT 1`. <!-- contract-allow:frozen-sql-text -->
  `selectAssignableWallet(candidates, lockedIds)` is the pure model: eligible AND not locked by
  another txn (SKIP LOCKED), oldest first. Concurrent selectors claim different wallets; when every
  eligible row is locked it returns null (falls through to the queue).
- **Reservation** (`reservation.ts`): `RESERVE_WALLET_CAS_SQL` flips `AVAILABLE -> PINNED` under a <!-- contract-allow:reservation-module-path -->
  `row_version` optimistic CAS; `reserveWallet` reserves iff the version matches and the row is
  still AVAILABLE (a stale version or non-AVAILABLE state loses, matching a 0-row UPDATE).
  `isAssignable` is the assignment-time defence-in-depth: a decryptable secret (boot probe) AND
  receive-eligibility — this blocks a resurrected/un-retired wallet (its `recovery_verified_at` is
  null). `REPLENISHMENT_CRASH_SAFETY` freezes the crash-atomic invariant (wallet row + vault
  envelope in one txn; boot verifies 1:1 and quarantines undecryptable wallets before selection —
  contingent on the vault storage model).
- **Retirement** (`retirement.ts`): `RETIRE_WALLET_CAS_SQL` flips `AVAILABLE -> RETIRED` under the
  SAME `row_version` optimistic CAS as the reserve write; `retireWallet` retires iff the version matches
  and the row is still AVAILABLE. Because reserve and retire share the `state='AVAILABLE' AND
  row_version=$n` guard on one row, at most one wins a given `(id, row_version)` — a retire can
  never clobber a live lease (never-from-PINNED) and never strands funds mid-lease.
- **Scale-up serialization** (`scaling.ts`): `SCALE_UP_ADVISORY_LOCK_NAMESPACE` +
  `CAP_COUNT_UNDER_LOCK_SQL`; `planScaleUp` recomputes the mint batch from the count re-read UNDER
  the lock. Serialized scalers never exceed cap; the tests show the naive stale-count path would
  double-mint past cap (why the advisory lock exists). The demand side is frozen too, in
  its own module (`open-sessions.ts`, symmetric with `reservation.ts`/`retirement.ts`'s <!-- contract-allow:reservation-module-path -->
  one-module-per-rule layout): `OPEN_SESSIONS_COUNT_SQL` + `OPEN_SESSIONS_COMPONENTS` /
  `OPEN_SESSIONS_EXCLUDED_COMPONENTS` define `open_sessions` (sizing rule 1) — RECEIVE-pinned pool
  wallets + unassigned CREATED receive operations INCLUDED; a node-internal transfer between two
  node-controlled wallets and forming a partial for an external recipient to co-sign EXCLUDED —
  read under the same lock so demand and supply are consistent at the mint decision. There is one
  SQL definition of `open_sessions` (`OPEN_SESSIONS_COUNT_SQL`), never a second differently-shaped
  copy.

## Capacity / retirement pressure matrix (frozen)

The full pressure matrix as freeze tests over the policy and transaction models, plus a
published scenario catalog. `POOL_PRESSURE_SCENARIOS` (`scenarios.ts`, snapshot
`gen/pool-scenarios.json`) names eight scenario classes and their frozen invariants;
`pressure.test.ts` drives the real pure models through each and asserts the outcome, with >=1
negative per class:

- **empty_pool** — born-blocked: the first receive on a fresh node queues; minting from empty does
  NOT make receives assignable (mint != availability).
- **burst_admission** — verified wallets assigned FIFO, then queue; a receive past the verified set
  is never assigned.
- **pinned_saturation** — all-PINNED: selection returns null; receives queue then 503 at cap.
- **cap_exhaustion** — at cap the mint batch is 0 and a full queue rejects 503 (fail-closed).
- **concurrent_scalers** — serialized scalers never exceed cap; the naive stale-count path over-mints.
- **retirement** — RETIRED excluded from selection but still counts toward cap; cannot retire a
  PINNED wallet.
- **restart_recovery** — a restored wallet failing the secret probe is quarantined, not assignable.
- **key_permanence** — no delete transition; a RETIRED wallet is never removed from the cap count.

The broken-run demo (disabling fail-closed backpressure) fires the burst, pinned-saturation, and
cap-exhaustion scenarios at once — the matrix is load-bearing against a policy regression.

## Scope boundary

The sizing/retirement policy, the selection/scaling transaction contract, and the pressure
matrix freeze constants / predicates / SQL-text data / scenario tests only (CONTRACT_FREEZE):
no DB schema, no migration, no scaler/queue runtime, no key mint, no send. The schema and
runtime slices bind the SQL text to the real schema and implement the runtime.
