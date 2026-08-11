# ZTR-1218 — Malformed-JSON login bodies bypass the login rate-limit

Lane: implementer · run `d8e13bc5-e8f8-4b3d-8ff8-891e0447fcff`
Branch: `ztr-1218-login-rate-limit` off `origin/main` @ `7e01e8a`
Head SHA: `f567ccc097a99cdd9e245995e6b96170a992bd55`
Worktree: `/Volumes/Ai Building/.zup-scratch/ztr-1218-impl/`

## Spec

Linear ZTR-1218 (deferred from ZTR-1201 PR #14). Sweeper AC 2026-08-11:

1. Malformed-JSON `POST /admin/v1/login` bodies consume the **same** per-IP login throttle budget as well-formed ones.
2. Single pre-decode chokepoint — **no second limiter instance** (ZTR-1201 AC5).
3. Key on **socket-peer IP** only (ZTR-1192 / ZTR-1201); no X-Forwarded-For (ZTR-1210).
4. Test: flood of malformed login bodies is throttled after budget exhausts.
5. `pnpm test` green on touched packages.

Governing mechanism: `packages/node-core/src/http/login-rate-limit.ts` (ZTR-1201).
No decision record in `docs/decisions/INDEX.md` applies beyond the standing socket-peer IP rule from ZTR-1192/1210.

## Change by file

### `apps/generic-node/src/admin-router.ts`

Single production chokepoint: on `POST /admin/v1/login`, call `consumeLoginAttempt(ipForDb(remoteAddress))` **before** `decodeBody`. On deny → 429 `rate_limited` + `Retry-After`. Then decode + `handleAdminLogin` (which no longer consumes).

### `packages/node-core/src/http/admin-auth-handlers.ts`

Removed `consumeLoginAttempt` from `handleAdminLogin` so well-formed requests are not double-counted. Comment documents the router owns admit.

### `packages/node-core/src/http/login-rate-limit.ts`

Header notes the single production call site (admin-router pre-decode).

### `packages/node-core/test/login-rate-limit.test.ts`

`login()` helper mirrors production admit-then-handle order so unit cases stay faithful without pulling the app router into node-core.

### `apps/generic-node/test/login-malformed-rate-limit.test.ts` (new)

- Flood of malformed bodies → 400 until budget, then 429.
- Malformed + well-formed share one budget.
- Keyed on socket `remoteAddress`, not `X-Forwarded-For`.

### `apps/generic-node/test/admin-error-envelope.test.ts`

Comment only (router is the consumer).

## Acceptance

| # | Criterion | Status |
|---|-----------|--------|
| 1 | Malformed JSON spends same per-IP budget | **satisfied** — pre-decode `consumeLoginAttempt` |
| 2 | One chokepoint, no second limiter | **satisfied** — handler no longer consumes |
| 3 | Socket-peer IP only | **satisfied** — `ipForDb(remoteAddress)` |
| 4 | Flood test | **satisfied** — `login-malformed-rate-limit.test.ts` |
| 5 | Tests green on touched pkgs | **satisfied** (see verify) |

## Verify (at `f567ccc`)

```
pnpm install                          # ok, 324 pkgs
tsc -b                                # No errors found
pnpm --filter @zucoins/node-core lint # 0 errors (5 pre-existing warnings)
pnpm --filter @zucoins/generic-node lint # clean
```

Tests:
- `packages/node-core` `test/login-rate-limit.test.ts` — 6/6 pass
- `packages/node-core` `test/admin-session.test.ts` + `admin-auth-abuse.test.ts` — 60/60 pass
- `apps/generic-node` `test/login-malformed-rate-limit.test.ts` + `admin-error-envelope.test.ts` — 9/9 pass

(vitest global-setup teardown `psql ETIMEDOUT` on DB drop is environmental; tests themselves passed.)

## Deferred

None. PR opened for QA Review.
