# ZTR-1137 implementer r2 — dual-FAIL rework

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/45
- **New head:** `bc2e0d21619ad62e8ed9c65cc306a608028c70b1`
- **Prior FAIL head:** `004b8df9ad960c949b60a41f6ebaa07656e70afb`
- **Claim parent:** implementer run=e9337770-9784-45f3-a38c-adaddcac5582
- **Isolated clone:** `/Volumes/Ai Building/.zup-scratch/ztr-1137-r2/`

## Reviews addressed

| Review | Blocker | r2 response |
|---|---|---|
| A F1 | Hosted `startup_failure` / `BuildFailed`, 0 jobs | Re-pushed; **still** `BuildFailed` at new head (runs 31448970879 push, 31448973820 PR). actionlint 0; yaml ok; Actions permissions enabled. Residual = account/private-repo runner entitlement — not YAML parse. |
| A F2 | Branch protection 403 | Reconfirmed 403 Pro/public plan gate. **No admin claim.** Residual documented. |
| A F3 | Deliberately broken not proven hosted | Local census mutation battery proves fail-closed; hosted proof blocked by F1 residual. |
| A F4 / B D2 | `pnpm test` / permanently red gates | Fixed base-owned lint/scan/migration/harness reds that blocked green delivery gates (see below). Full 12k suite not fully re-run end-to-end in r2 wall-clock; targeted suites that were red are green. |
| B D1 | Census substring-open (comment / \|\| true) | **Fixed:** active-step parser; mutations RED then GREEN. |

## Code changes (9 files)

1. `.github/workflows/ci.yml` — SHA-pin checkout/pnpm/setup-node
2. `packages/node-core/test/ci-workflow.census.test.ts` — fail-closed active-step census + SHA pin assert
3. `packages/node-core/src/workers/leadership.ts` — remove no-useless-catch
4. `packages/node-core/src/workers/leadership.test.ts` — forbidden `drain` → `flush`
5. `packages/node-core/test/migration-integrity.test.ts` — inventory byte-immutability; GREENFIELD enum-first misses; composition pgcrypto; NO_TABLE allows CREATE FUNCTION/TRIGGER
6. `apps/generic-node/test/destination-bless-atomic.pg.test.ts` — destinations.label fixture
7. `apps/generic-node/test/reporting/durable-security-ports.pg.test.ts` — vaultRootKey for SqlAdminUserStore
8. `apps/generic-node/test/send-completion-lander.pg.test.ts` — seed-time signed expiry (insert-only intents)
9. `tasks/ZTR-1137-ci-gates.md` — r2 evidence

## Local verification (scratch @ `bc2e0d21619ad62e8ed9c65cc306a608028c70b1`)

- census 6/6 + mutation battery (comment-out, \|\| true, echo-skip, continue-on-error, strip PG_REQUIRED) RED→GREEN
- lint 0 errors; boundaries 162/162; contracts previously 2732/2732 after scan fix
- Playwright 23/23; schema census OK
- migration-integrity 10/10; destination-bless 4/4; durable-security 13/13; send-completion AC3+F1.1 PASS

## Residuals (honest)

1. **Hosted Actions never schedules jobs** — `path=BuildFailed` on push+PR at r2 head. Outside implementer YAML authority if account minutes/plan/entitlement is the cause. Sibling private repos also show recent BuildFailed patterns.
2. **Branch protection / required checks** — API 403 without GitHub Pro or public repo. Cannot mark quality-and-tests / admin-playwright required from this lane.
3. Full monolithic `pnpm test` wall-clock not completed green in r2 (multi-hour PG suite; machine contention). Gate-blocking classes identified by dual review are fixed and re-proven targeted.

## Release

Requesting **QA Review** of head `bc2e0d21619ad62e8ed9c65cc306a608028c70b1`. Do not merge from this lane.
