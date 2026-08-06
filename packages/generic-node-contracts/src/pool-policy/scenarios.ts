// the named concern — the published receive-pool pressure-scenario catalog. Each entry names a scenario
// class and its frozen invariant; pressure.test.ts drives .1's policy and .2's transaction models
// through each scenario and asserts the outcome (with >=1 negative per class). Consumed by the
// the named concern runtime builders (the DB-domains concern/the named concern) and the named concern's own freeze tests.
export const POOL_PRESSURE_SCENARIOS = [
  {
    name: "empty-pool",
    class: "empty_pool",
    invariant:
      "A fresh node is born-blocked: it has no recovery-verified wallet, so the first receive queues (never assigned) until a recovery ceremony verifies a minted wallet.",
  },
  {
    name: "burst-admission",
    class: "burst_admission",
    invariant:
      "Verified wallets are assigned FIFO; once exhausted, further receives queue below RECEIVE_QUEUE_CAP, never assigned off an empty verified set.",
  },
  {
    name: "pinned-saturation",
    class: "pinned_saturation",
    invariant:
      "When every wallet is PINNED, selection returns nothing and receives queue, then 503 at cap — minting cannot relieve pinned pressure.",
  },
  {
    name: "cap-exhaustion",
    class: "cap_exhaustion",
    invariant:
      "At cap the mint batch is 0 (fail-closed) and receives with no verified wallet queue then reject 503 receive_queue_full with a Retry-After; the cap is a true lifetime bound.",
  },
  {
    name: "concurrent-scalers",
    class: "concurrent_scalers",
    invariant:
      "Serialized scalers re-read the count under the advisory lock and never exceed cap; the naive stale-count path over-mints past cap.",
  },
  {
    name: "retirement-with-active-evidence",
    class: "retirement",
    invariant:
      "RETIRED is removed from selection but still counts toward cap and stays a sweepable outbound source; retirement is AVAILABLE->RETIRED only, via a row_version CAS — a PINNED (live-leased) wallet or a concurrent lease loses, so funds are never stranded mid-lease.", // contract-allow:frozen-scenario-invariant
  },
  {
    name: "restart-crash-recovery",
    class: "restart_recovery",
    invariant:
      "On boot a wallet lacking a decryptable secret is quarantined before selection and is not assignable, even if recovery_verified_at is set.",
  },
  {
    name: "no-key-deletion",
    class: "key_permanence",
    invariant:
      "Keys are never deleted in any state; there is no delete transition; a RETIRED wallet retains its keys and ledger permanently.",
  },
] as const;

export type PoolPressureScenario = (typeof POOL_PRESSURE_SCENARIOS)[number];
