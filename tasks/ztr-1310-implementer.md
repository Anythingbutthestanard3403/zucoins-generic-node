# ZTR-1310 implementer — Candidate A remediations (PR #166)

**Linear:** https://linear.app/zutopia/issue/ZTR-1310
**Branch:** `ztr-1310-dest-idempotency`
**PR:** #166
**Claim run:** `16d07a35-2a66-4abd-b6c7-666371bf6dcd`
**Pinned origin/main:** `be826b9a1d4e18670ab26941be13b5364e626ab0`
**Pinned prior head:** `bb51881e6f9d73d5c3f988be73fadbb358512de7`
**Plan:** `tasks/plan-ZTR-1310.md`

## Problem (Review B)

PR #166 persisted `destinations.idempotency_key` and taught live
`findByIdempotencyKey` to SELECT it. That only closed **serial** retry after a
committed key. Production `generate` still dest-on-minted with a **NULL** key
on the pool, then `store.insert` claimed UNIQUE. Overlap / timeout-after-mint
left a committed wallet+dest with no key.

## Candidate A (this change)

UNIQUE `(node_id, idempotency_key)` is the first committed write of a register.
No wallet/dest for this attempt commits unless that row set already carries
the key.

```
findByIdempotencyKey → hit? already_registered
materialize ed25519 in memory
BEGIN
  INSERT wallets
  INSERT destinations (…, idempotency_key)
COMMIT          -- loser 23505 → ROLLBACK → no wallet, no dest
vault.seal      -- after commit, other connection
onWalletMinted  -- post-seal only
```

23505 → typed `DestinationIdempotencyKeyClaimedError` → find →
`already_registered`. Never delete a committed mint.

## Files

- `packages/node-core/src/api/insert-node-generated-wallet.ts` — dest INSERT
  binds optional `idempotency_key`; keyed mint must share one txn client
- `packages/node-core/src/api/destination.ts` — `generate(nodeId, claim?)`;
  register catches claim-miss
- `packages/node-core/src/api/sql-destination-store.ts` — unchanged (find +
  23505 replay; missing winner still throws)
- `apps/generic-node/src/main.ts` — keyed generate: pinned client BEGIN →
  helper(tx, {idempotencyKey,label}) → COMMIT → seal → hook. 23505 ROLLBACK
  + claim-miss. Pool/funding stay key-less.
- Tests per plan §4 (concurrent overlap, timeout-after-keyed-persist, 23505
  loser wallet rollback, serial retry keep, register generate binds key)
- `tasks/plan-ZTR-1310.md` — reviewed plan copied into the worktree
- `apps/generic-node/test/transaction-isolation.census.test.ts` — classify
  the new keyed-mint BEGIN (`other` / CONSTRAINT)

## Not done (per plan §5)

Bless / retire / MOVE; drop UNIQUE; reservation table; nullable wallet_id;
delete loser mint as primary fix; seal inside txn; serialization retry around
seal; `onWalletMinted` on rolled-back mint; pool/funding register key;
forbidden terms.
