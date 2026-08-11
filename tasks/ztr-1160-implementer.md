# ZTR-1160 implementer

- **PR:** #52 (https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/52)
- **Head SHA:** `90926a5179e21c2e9869f72d056325ac3c4e109a`
- **Branch:** `ztr-1160-sign-under-lease-toctou`
- **Claim:** released → QA Review (run=07db18b8-b869-45a7-a54b-3259548f53dc)

## What shipped

Transaction-scoped signing (ticket option 1):

1. `SignerBoundaryDeps.withSignTransaction` — pinned-client TX for lease lock + vault + audit
2. `createSqlSignUnderLeaseTransaction` in `send-signer-deps.ts` — BEGIN / FOR UPDATE / COMMIT; statement_timeout (ZTR-1156)
3. SEND / MOVE / RECEIVE production wirings pass the TX scope
4. REJECTED path commits FAILED audit then throws (no deadlock / no rollback of audit)
5. Isolation census: ROW_LOCK / READ COMMITTED (vault non-DB)

## Evidence

| Check | Result |
|---|---|
| signer-boundary unit | 25 passed |
| sign-under-lease-toctou.pg | 4 passed (concurrent release blocks; REJECTED audit) |
| send-signer-audit.pg | 2 passed |
| isolation census | 9 passed |
| boundaries | 71 passed |
| root tsc -b | clean |

## Files

- `packages/node-core/src/core/signer-boundary.ts`
- `packages/node-core/src/money-path-admission.ts`
- `packages/node-core/test/signer-boundary.test.ts`
- `apps/generic-node/src/money-workers/send-signer-deps.ts`
- `apps/generic-node/src/money-workers/start-money-workers.ts`
- `apps/generic-node/src/money-workers/move-advanced-ports.ts`
- `apps/generic-node/src/money-workers/receive-settle-step.ts`
- `apps/generic-node/test/sign-under-lease-toctou.pg.test.ts`
- `apps/generic-node/test/send-signer-audit.pg.test.ts`
- `apps/generic-node/test/transaction-isolation.census.test.ts`
