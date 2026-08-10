# ZTR-1196 implementer r2 (FAIL remediation)

- **PR:** #34 (`ztr-1196-admin-error-envelope`)
- **Plan:** `tasks/plan-ZTR-1196.md` (PASS review)
- **Clears:** `tasks/ztr-1196-review-ec972dc.md` D1/D2
- **Base head: `ec972dcb6a6764b3c756248bf3ae86ce14fc2b7a`
- **New head:** `a42cd381148d9f9bdff13f917566cbeffd64f7ee`

## Changes

1. **`POST /admin/v1/enrol-totp`** → `fromAuthResult(result, requestId)` (was passthrough `JSON.stringify(result.body)`).
2. **`fail(..., extraHeaders?)`** merges `{ ...JSON_HEADERS, ...extraHeaders, ...JSON_HEADERS }` so Retry-After survives and content-type stays JSON.
3. **`fromAuthResult` error branch** passes `result.headers` into `fail`.
4. **Tests T1/T2** in `admin-error-envelope.test.ts`: enrol 401 envelope; login 429 envelope + `retry-after`.

Scope: `apps/generic-node/src/admin-router.ts`, `apps/generic-node/test/admin-error-envelope.test.ts` only.

## Gates (this commit)

| Command | Result |
|---|---|
| `pnpm --filter @zucoins/generic-node exec vitest run test/admin-error-envelope.test.ts` | **6/6** pass |
| `pnpm --filter @zucoins/generic-node exec vitest run test/admin-` | **15 files / 142** pass |
| `pnpm exec tsc -b` | exit 0 |
| `pnpm --filter @zucoins/generic-node lint` | exit 0 |
| `pnpm --filter @zucoins/generic-node-contracts exec vitest run src/admin-auth-errors/codes.census.test.ts` | **11/11** pass |
| `git diff` contracts / `error-envelope.ts` | empty |

## AC

| # | Criterion | Status |
|---|---|---|
| AC1 | enrol-totp non-2xx parses AdminErrorEnvelopeSchema | satisfied (T1) |
| AC2 | enrol uses fromAuthResult | satisfied |
| AC3 | fromAuthResult error merges headers | satisfied (T2) |
| AC4 | login 429 envelope + Retry-After | satisfied (T2) |
| AC5 | success Set-Cookie unchanged | satisfied (no success-path edit) |
| AC6 | API_ERROR_CODES / public envelope untouched | satisfied |
| AC7 | no contracts freeze churn | satisfied |
| AC8 | prior envelope tests pass | satisfied (6/6) |

- **Pushed head:** `a42cd381148d9f9bdff13f917566cbeffd64f7ee`
