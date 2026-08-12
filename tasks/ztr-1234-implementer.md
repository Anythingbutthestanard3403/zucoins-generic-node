# ZTR-1234 — implementer notes

## Delivered
- `packages/node-core/src/send/auto-approve-policy.ts` — fail-closed parser, SQL policy port, pure evaluator, `commitAutoApproval` one-TX path
- `packages/node-core/src/send/auto-approve-policy.test.ts` — 39 unit tests (parser + evaluator + ports + lock SQL pin)
- `packages/node-core/test/auto-approve-policy.pg.test.ts` — 7 live PG drills + 1 PG_REQUIRED guard
- Barrel export from `packages/node-core/src/send/index.ts`

## Design notes
- Fail-closed: absent / unreadable / invalid / document `enabled:false` (`off`) → DISABLED
- Amounts: `parsePositiveZkzAmount` + contracts `addAmounts` / `compareAmounts` only
- Window spend: SUM of AUTO_POLICY approvals in trailing window (never released)
- Commit TX steps: implementer-scoped `pg_advisory_xact_lock` (`LOCK_AUTO_APPROVE_WINDOW_SQL` / `auto-approve-window:` + implementer id) → FOR UPDATE send row → bound recheck → window recheck → `buildSendExternalApproval` → INSERT AUTO_POLICY → frozen CREATED→APPROVED CAS → SYSTEM audit
- Race posture: single leader-gated worker (ZTR-1235) is the intended sole *caller*; TX is multi-writer safe via xact advisory lock serializing window spend + AUTO_POLICY insert. FOR UPDATE + CAS still arbitrate same-row manual contention.
- CAS miss throws `AutoApproveCasMissError` so `withTx` rolls back (no orphan approval/audit)
- Policy write: single CTE upsert `node_settings` + `audit_log` (`ops.auto_approve_sends_changed`, sha256 of docs)

## r2 remediation (dual FAIL fix — PR #100)
- **FAIL A:** moved `registerPgRequiredGuard` to top-level *after* live `describeIfPg` (leadership.pg pattern) so `PG_REQUIRED=1` guard sees `schemaReady` after `beforeAll`
- **FAIL B:** `LOCK_AUTO_APPROVE_WINDOW_SQL` + `lockAutoApproveWindow` as first TX step in `commitAutoApproval`; header race note corrected
- **Drill:** concurrent same-implementer two-op amount=cap race → exactly one approve, one `window_cap` fall_through; durable AUTO_POLICY sum ≤ cap
- Unit pin: lock SQL contains `pg_advisory_xact_lock` + `hashtextextended` + namespace prefix

## Verification (r2)
- unit: 39/39 pass (`auto-approve-policy.test.ts`)
- pg `PG_REQUIRED=1`: 8/8 pass (7 live + guard)
- `tsc -b packages/node-core`: clean
- eslint on touched files: clean
- node-core `test/boundaries.test.ts`: 73/73 pass
- forbidden vocab on touched `packages/node-core/src` files: clean (real scanner)
- repo `pnpm test:boundaries` still fails on pre-existing `drain` in `apps/generic-node` (origin/main; not this change)

## Out of scope
- ZTR-1235 worker caller
- ZTR-1237 admin surface
