# ZTR-1215 — implementer rework r3 (Review B r2 FAIL)

**PR:** #78  
**Prior failed head:** `14c3bb7bf352ae4003677e32f922d8cc10785b3b`  
**Branch:** `ztr-1215-log-redaction-residuals`

## FAIL addressed (Review B r2 D1)

`TEXT_URL_USERINFO` allowed `/ ? #` in the userinfo class, so greedy last-`@`
was not authority-scoped:

- `file:///C:/…/vitest@3.2.7/…` → over-redacted (Windows drive `:` + path `@`)
- `https://user:pass@host/path/pkg@1.2.3` → collapsed host/path to last path-`@`

Prior r2 @-in-password fix (last-`@` with required `:`) is retained.

### Fix

`packages/node-core/src/observability/safe-log.ts` — userinfo class is now
`[^\s"'<>/?#]*:[^\s"'<>/?#]*` so `/ ? #` terminate authority. Greedy last-`@`
still captures `@`-in-password inside authority only.

### Tests added

`packages/node-core/test/safe-log-redaction.test.ts`:
- Windows `file:///C:/…/vitest@3.2.7/…` unchanged
- `https://api:…@gateway.example/v1/packages/foo@1.2.3/tgz` →
  `https://[redacted]@gateway.example/v1/packages/foo@1.2.3/tgz`
- Existing @-in-password / DATABASE_URL / colon-in-password / unix file:// retained

## Acceptance

| AC | Status |
|---|---|
| Every raw `console.*` in DR CLI + operator CLIs routes through redactor | **yes** (unchanged) |
| `scrubText` catches bare high-entropy + URL userinfo without over-redacting prose | **yes** — authority-bounded last-`@` |
| Tests: assignment / bare / URL / `@`-in-password / Windows file:// / path-`@` / CLI | **yes** |
| Do not duplicate raw-Zod-400 (ZTR-1200) | **yes** |
| Targeted tests green | **yes** |

## Verify

```
CI=true pnpm install          # Already up to date
tsc -b                        # exit 0
pnpm --filter @zucoins/node-core exec vitest run test/safe-log-redaction.test.ts
  → 39 passed (1 file)
pnpm --filter @zucoins/generic-node exec vitest run \
  test/safe-logger.test.ts test/dr/cli.test.ts test/db/client.import-smoke.test.ts
  → 42 passed (3 files); teardown spawnSync psql ETIMEDOUT (pre-existing, no local pg)
pnpm --filter @zucoins/node-core lint   # 0 errors (5 pre-existing warnings)
pnpm --filter @zucoins/generic-node lint # clean
```

Live probes (post-fix):
- Windows file:// frame unchanged
- path-`@` after real userinfo keeps host+path
- `postgres://u:P@ssw0rd@h/db` → `postgres://[redacted]@h/db`
- multi-`@` password still fully censored

## Files touched (r3)

- `packages/node-core/src/observability/safe-log.ts` — exclude `/?#` from userinfo class
- `packages/node-core/test/safe-log-redaction.test.ts` — Windows file:// + path-`@` regressions
- `tasks/ztr-1215-implementer-r3.md` — this handoff

## Deferred

- `full-http-mount.ts` audit `console.info` through safe logger (optional, non-blocking)
- deploy/triad scripts (out of AC1 scope)
