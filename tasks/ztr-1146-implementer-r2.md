# ZTR-1146 implementer r2 — SEND park dual-chain (PR #56 rework)

**Lane:** implementer run=6217c60c-c04f-4500-9d7c-e4e1eb00b14c
**Prior FAIL head:** c9e45a9871f63a78b6c752de5e909f7db1a0007b
**PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/56

## Blocking defect closed

Review A/B B1: production SEND park (`parkSendNeedsAttention` in
`send-completion-lander.ts`) committed `NEEDS_ATTENTION` with only slice-local
`external_send_attention_events` — no dual-chain / implementer leg. The
`parkPastExpiryAwaitingRedemption({ dualChain })` port was dead code (no
production caller). Live path is the lander.

## Fix

1. **`parkSendNeedsAttention`** — after successful CAS + operations mirror, on the
   **same** client/TX: resolve implementer + source wallet from `send_operations`,
   `appendDurableDualChainEvent` for `operation.needs_attention` with payload matching
   the CAS CTE shape (`current_state`, `attention_reason`, `attention_episode`,
   `operator_action_required`). Null EVENT_SIGNING / quota → throw → ROLLBACK
   (fail-closed; no attention without tenant proof).
2. **`SendObserveLanderDeps`** gains `eventSigner` + `eventQuota`;
   `start-money-workers` wires them into `tickSendCompletionLander`.
3. **Census hardening** — require every production
   `CAS_AWAITING_TO_NEEDS_ATTENTION` site to co-locate a dual-chain marker (or
   library `dualChain` / `SendExpiryDualChainEmitter` port); explicit assert that
   `send-completion-lander.ts` calls `appendDurableDualChainEvent`.
4. **PG park proof** — B4 park asserts node + implementer chains; new fail-closed
   test with `eventSigner: null`.
5. Stale isolation-census OPEN OBLIGATION text for `emitExpired` pool tear rewritten
   (production already routes through TX `db` from r1). Isolation census still has
   pre-existing undeclared BEGIN sites on main tip of this branch (not introduced here).

## AC (operation.needs_attention)

| Path | Status |
|---|---|
| Receive expiry / landing attention | already dual-chain (r1) |
| Move NEEDS_ATTENTION | already implementer-leg (r1) |
| **SEND completion-lander park** | **fixed this rev** |

## Verification (this head)

```
pnpm exec tsc -b --pretty false          → exit 0
pnpm --filter @zucoins/node-core exec vitest run \
  test/boundaries.test.ts \
  test/durable-events-implementer-emitter.census.test.ts \
  test/event-ledger.census.test.ts \
  test/send-form-and-sign.test.ts \
  test/send-external-create.test.ts \
  src/send/expiry-attention.test.ts \
  test/move-internal-create.test.ts
  → 7 files, 202 passed
pnpm --filter @zucoins/generic-node exec vitest run test/money-workers.test.ts
  → 8 passed
pnpm --filter @zucoins/generic-node exec vitest run \
  test/send-completion-lander.pg.test.ts -t 'B4: changed head|B4/ZTR-1146'
  → 2 passed (dual-chain park + fail-closed null signer)
pnpm --filter @zucoins/generic-node exec vitest run \
  test/durable-events-nine-types.pg.test.ts
  → 1 passed
```

Pre-existing (base c9e45a9 also fails): lander PG `setSignedExpiry` hits
`EXTERNAL_SEND_SIGN_INTENTS_INSERT_ONLY` (AC3 T0 window / F1.1 expiry drills);
isolation census undeclared BEGIN on receive-landing-step (r1 dual-chain TX not
registered in TRANSACTION_SITES). Not regressions of this patch.

## Files

- `apps/generic-node/src/money-workers/send-completion-lander.ts`
- `apps/generic-node/src/money-workers/start-money-workers.ts`
- `apps/generic-node/test/send-completion-lander.pg.test.ts`
- `apps/generic-node/test/transaction-isolation.census.test.ts`
- `packages/node-core/test/durable-events-implementer-emitter.census.test.ts`
