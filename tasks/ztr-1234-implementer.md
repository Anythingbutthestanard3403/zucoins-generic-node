# ZTR-1234 — implementer notes

## Delivered
- `packages/node-core/src/send/auto-approve-policy.ts` — fail-closed parser, SQL policy port, pure evaluator, `commitAutoApproval` one-TX path
- `packages/node-core/src/send/auto-approve-policy.test.ts` — 38 unit tests (parser + evaluator + ports)
- `packages/node-core/test/auto-approve-policy.pg.test.ts` — 7 real-PG drills (cap, CAS atomicity, concurrent reject, window exclusions, audit byte-shape)
- Barrel export from `packages/node-core/src/send/index.ts`

## Design notes
- Fail-closed: absent / unreadable / invalid / document `enabled:false` (`off`) → DISABLED
- Amounts: `parsePositiveZkzAmount` + contracts `addAmounts` / `compareAmounts` only
- Window spend: SUM of AUTO_POLICY approvals in trailing window (never released)
- Commit TX: FOR UPDATE → bound recheck → window recheck → `buildSendExternalApproval` → INSERT AUTO_POLICY → frozen CREATED→APPROVED CAS → SYSTEM audit
- CAS miss throws `AutoApproveCasMissError` so `withTx` rolls back (no orphan approval/audit)
- Policy write: single CTE upsert `node_settings` + `audit_log` (`ops.auto_approve_sends_changed`, sha256 of docs)

## Verification
- unit: 38/38 pass
- pg: 7/7 pass
- tsc -b: clean
- eslint on touched files: clean
- node-core `test/boundaries.test.ts`: 73/73 pass
- forbidden vocab on touched files: clean
- repo `pnpm test:boundaries` fails on pre-existing `drain` in `apps/generic-node` (present on origin/main; not this change)

## Out of scope
- ZTR-1235 worker caller
- ZTR-1237 admin surface
