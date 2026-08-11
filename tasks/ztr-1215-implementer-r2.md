# ZTR-1215 — implementer rework r2 (Review B FAIL)

**PR:** #78  
**Prior failed head:** `1f48fa1a6ecdfba747d085725d484a7e5560fac5`  
**Branch:** `ztr-1215-log-redaction-residuals`

## FAIL addressed (Review B D1)

`TEXT_URL_USERINFO` stopped userinfo at the **first** `@`, so passwords containing `@`
(`P@ssw0rd`, `p@art@two`, `MyP@ss-Word-99`) leaked the suffix after the first `@`.

### Fix

`packages/node-core/src/observability/safe-log.ts` — allow `@` inside the userinfo
character class and keep a required `:` so the greedy match ends at the **last** `@`
before the host. Username-only and `file:///…/pkg@ver` frames stay unchewed (still
require `:` in userinfo).

### Tests added

`packages/node-core/test/safe-log-redaction.test.ts`:
- `postgresql://u:p@art@two@localhost/db` → `postgresql://[redacted]@localhost/db`
- `postgres://u:P@ssw0rd@h/db` — no `ssw0rd` leak
- free-text `DATABASE_URL=postgres://node:p@ssw0rd-UniqueXX@db.internal/generic` — unique tail absent
- error-line `MyP@ss-Word-99` host form — tail absent
- existing colon-in-password + file:// regression tests retained

## Acceptance

| AC | Status |
|---|---|
| Every raw `console.*` in DR CLI + operator CLIs routes through redactor | **yes** (unchanged from r1) |
| `scrubText` catches bare high-entropy + URL userinfo without over-redacting prose | **yes** — last-`@` delimiter |
| Tests: assignment / bare / URL / `@`-in-password / CLI redactor path | **yes** |
| Do not duplicate raw-Zod-400 (ZTR-1200) | **yes** |
| Targeted tests green | **yes** |

## Verify

```
CI=true pnpm install          # Already up to date
tsc -b                        # exit 0
pnpm --filter @zucoins/node-core exec vitest run test/safe-log-redaction.test.ts
  → 37 passed (1 file)
pnpm --filter @zucoins/generic-node exec vitest run \
  test/safe-logger.test.ts test/dr/cli.test.ts test/db/client.import-smoke.test.ts
  → 42 passed (3 files); teardown spawnSync psql ETIMEDOUT (pre-existing, no local pg)
pnpm --filter @zucoins/node-core lint   # 0 errors (pre-existing warnings only)
pnpm --filter @zucoins/generic-node lint # clean
```

## Files touched (r2)

- `packages/node-core/src/observability/safe-log.ts` — last-`@` URL userinfo
- `packages/node-core/test/safe-log-redaction.test.ts` — @-in-password + DATABASE_URL cases
- `tasks/ztr-1215-implementer-r2.md` — this handoff

## Review A

No separate Review A FAIL notes found in workspace (`tasks/ztr-1215-review-1f48fa1a.md`
absent / empty search). Optional non-blocking follow-up from B (full-http-mount
console.info) deferred.

## Deferred

- `full-http-mount.ts` audit `console.info` through safe logger (optional, non-blocking)
- deploy/triad scripts (out of AC1 scope, deferred in r1)
