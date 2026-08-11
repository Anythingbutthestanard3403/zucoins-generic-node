# ZTR-1218 implementer rebase (PR #72)

- **lane:** implementer
- **run:** `e0d41209-7043-441d-8756-de74b04f4ae1`
- **prior dual-PASS head (VOID):** `2b6a9420a7f0b947598fe6f75260e33b6038caca`
- **new HEAD:** `3bf1c562b33a9bdfc7cffd0c5befdd3c3ecc7d79`
- **base:** `origin/main` @ `d833039ec838cadeb991255bdacd21e3afb3f601`
- **PR:** #72 (`ztr-1218-login-rate-limit`)
- **worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1218-rebase`
- **local branch during rebase:** `ztr-1218-login-rate-limit-rebase` → force-with-lease pushed to `origin/ztr-1218-login-rate-limit`

## Why

PR #72 was CONFLICTING after main moved (notably ZTR-1210 lockout IP unification
and later merges). Dual PASS at `2b6a942` is void after rebase.

## Commits after rebase

```
3bf1c56 docs(tasks): ZTR-1218 implementer r2 handoff (Date.now freeze)
23515af fix(test): freeze Date.now in malformed login rate-limit suite (ZTR-1218)
1f623ee docs(tasks): ZTR-1218 implementer handoff
495f832 fix(admin): count malformed login JSON against login rate limit (ZTR-1218)
```

## Conflicts (commit 1/4 only: product admit)

File: `apps/generic-node/src/admin-router.ts` — keep **both**:

| Concern | Resolution |
|---------|------------|
| Imports | Keep main `resolveClientIp` + `trustProxyOptionsFromEnv` **and** ZTR-1218 `consumeLoginAttempt` + `LOGIN_RATE_WINDOW_MS` |
| Volume throttle key | Pre-decode `consumeLoginAttempt(ipForDb(remoteAddress))` — **socket-peer only** (ZTR-1218 AC3 / ZTR-1201) |
| Lockout / session IP | `handleAdminLogin({ ip: resolveAdminLockoutIp(headers, remoteAddress) })` — ZTR-1210 shared pair identity; XFF only when `TRUST_PROXY_HOPS` set |

Commits 2–4 (docs handoff, Date.now freeze test, r2 handoff) applied cleanly.

## Product work preserved

- Single production `consumeLoginAttempt` call site at admin-router pre-decode
- `handleAdminLogin` does not re-consume
- Malformed JSON flood + shared-budget + peer-IP tests
- `Date.now` freeze in `login-malformed-rate-limit.test.ts` (r2 hermetic fix)

## Local verify (PASS) @ `3bf1c562b33a9bdfc7cffd0c5befdd3c3ecc7d79`

| Command | Result |
|---------|--------|
| `tsc -b` | 0 |
| `pnpm --filter @zucoins/node-core lint` | 0 errors (5 pre-existing warnings) |
| `pnpm --filter @zucoins/generic-node lint` | clean |
| node-core `login-rate-limit.test.ts` | **6/6** |
| gn `login-malformed-rate-limit` + `admin-error-envelope` | **9/9** |
| gn `admin-lockout-ip-unification` (ZTR-1210 keep-both) | **7/7** |
| serial `-t 'share one per-IP'` ×5 | **SERIAL_FAILS=0** |

## Push

`git push --force-with-lease origin HEAD:ztr-1218-login-rate-limit`

Dual must re-run — rebase voids prior dual PASS.
