# ZTR-1146 implementer report

**Claim:** lane=implementer run=74ef996b-3060-4d38-8ac6-c5053c3a78c9  
**Branch:** `ztr-1146-closed-events-tenant-stream`  
**Governing spec:** Appendix B durable public events (closed nine); doc 05 §8.1 implementer stream; dual continuity via `event-log/dual-chain-appender.ts`.

## Acceptance criteria

| AC | Status |
|---|---|
| `external_send.created` appended in send create TX → implementer stream | Satisfied — `SqlSendCreateStore` + `main.ts` dual-chain appender |
| `external_send.awaiting_redemption` same commit as partial → stream | Satisfied — `createSqlPartialPort` after `persistSendPartialSql` |
| `internal_move.created`, `internal_move.landed`, `operation.needs_attention`, `operation.expired` → stream | Satisfied — dual-chain move created; move landed implementer leg; receive expiry dual-chain; receive-landing attention dual-chain; queue-age expired dual-chain |
| Appends share TX with state change | Satisfied — all paths use caller's TX / withTransaction |
| Hash chain + gapless seq under concurrent appends | Unchanged dual-chain appender (D8.36) |
| `awaiting_redemption` never before partial durable | Satisfied — append only after successful partial+CAS |
| Census gate for DURABLE_EVENTS → implementer emitter | Satisfied — `durable-events-implementer-emitter.census.test.ts` |
| Consumer integration observes all nine types | Satisfied — `durable-events-nine-types.pg.test.ts` |

## Files touched

- `packages/node-core/src/event-log/dual-chain-appender.ts` — `appendDurableDualChainEvent` (generalizes terminal landed helper)
- `packages/node-core/src/send/sql-store.ts` — create TX + `SendCreatedEventAppender` port
- `packages/node-core/src/move/sql-store.ts` — `createDualChainMoveCreatedEventAppender`
- `packages/node-core/src/receive/expiry-release.ts` — dual-chain emitter port on expire/attention
- `packages/node-core/src/send/expiry-attention.ts` — optional dual-chain after park CAS
- `apps/generic-node/src/main.ts` — wire send/move create dual-chain
- `apps/generic-node/src/money-workers/*` — partial, move landed, expiry, landing attention
- Tests: emitter census + nine-types PG consumer proof

## Verification (at head SHA)

```
rtk tsc                         → No errors found
pnpm --filter @zucoins/node-core exec vitest run \
  test/boundaries.test.ts \
  test/durable-events-implementer-emitter.census.test.ts \
  test/send-form-and-sign.test.ts \
  test/send-external-create.test.ts \
  src/send/expiry-attention.test.ts \
  test/move-internal-create.test.ts \
  test/event-ledger.census.test.ts
  → 5+2 files, 200 tests passed
pnpm --filter @zucoins/generic-node exec vitest run \
  test/durable-events-nine-types.pg.test.ts
  → 1 passed (PG)
```

Lint: pre-existing `no-useless-catch` in `leadership.ts` (untouched). Touched files clean under eslint when scoped.

## Notes / deferrals

- Send expiry park dual-chain is ported on `parkPastExpiryAwaitingRedemption` (`dualChain` input); production worker wiring for send-expiry tick was not present on main — receive expiry + move park cover the primary `operation.needs_attention` paths. Census passes via those emitters.
- Overlap with ZTR-1145 (verifier): this ticket delivers events; verifier ticket is separate.
