# ZTR-1235 — implementer notes

## Delivered
- `apps/generic-node/src/money-workers/start-money-workers.ts` — `autoApprovePendingSends` step before `advanceApprovedSends` in `executeTickBody`
- `apps/generic-node/src/money-workers/send-sql-ports.ts` — `loadApprovalPendingSendCandidates` (CREATED + APPROVAL_PENDING, LIMIT 100)
- `apps/generic-node/src/money-workers/index.ts` — export loader
- `apps/generic-node/test/money-workers.test.ts` — wiring + ordering pin
- `apps/generic-node/test/auto-approve-worker.pg.test.ts` — disposable PG ACs

## Design
- Policy once per tick via `createSqlAutoApprovePolicy` / injectable `autoApprovePolicy`
- Disabled ⇒ one debug log, return (no per-send spam)
- Per op: `stopped()` → money admitted → halt admits SEND_EXTERNAL → pure `evaluateAutoApproveRule` → `commitAutoApproval`
- No signer deps on auto-approve; formation still defers when vault/leadership unarmed
- Fall-throughs silent (remain manual queue); APPLIED logs one line

## Verify
- unit money-workers: 8/8
- pg auto-approve-worker: 3/3
- eslint touched files: clean

## Out of scope
- Money-path dual review (later)
- Admin surface (ZTR-1237)
- Merge
