# ZTR-1218 implementer r2 — Review A FAIL rework

Lane: implementer · run `78efce13-23d3-42e4-b53f-f58b2878f815`
Branch: `ztr-1218-login-rate-limit` (rebased onto `origin/main`)
Failed head: `fedd398bf62cf0b04e432fb7ac32c9b498ac6c37`
New head: `1ca1da4656d9fa6eaf054513f50377eb692da2e0`
PR: #72

## FAIL addressed

Review A: `login-malformed-rate-limit.test.ts` shared-budget case is wall-clock
fixed-window flaky — bcrypt wrong-password path can cross the 60s
`LOGIN_RATE_WINDOW_MS` bucket mid-case → final malformed returns 400 not 429.

## Fix (test-only)

`apps/generic-node/test/login-malformed-rate-limit.test.ts`:
- import `vi` from vitest
- `beforeEach`: `_resetLoginRateLimitForTests()` +
  `vi.spyOn(Date, "now").mockReturnValue(1_800_000_000_000)`
- `afterEach`: `vi.restoreAllMocks()` + reset

Same pattern as `packages/node-core/test/login-rate-limit.test.ts`.
No production admit-path change.

## Acceptance criteria

1. [x] Malformed JSON spends same per-IP budget (pre-decode chokepoint)
2. [x] Single production `consumeLoginAttempt` call site
3. [x] Socket-peer IP only (no XFF)
4. [x] Flood of malformed → 429 after budget
5. [x] Touched-package tests/lint green + shared-budget hermetic ≥5×

## Governing spec

Linear ZTR-1218; `packages/node-core/src/http/login-rate-limit.ts`; peer-IP
standing rule ZTR-1192/1210.

## Verify at `1ca1da4656d9fa6eaf054513f50377eb692da2e0`

```
pnpm install
tsc -b                                          # tsc_ec=0
pnpm --filter @zucoins/generic-node lint        # gn_lint_ec=0
pnpm --filter @zucoins/node-core lint           # nc_lint_ec=0
```

Shared-budget serial `-t 'share one per-IP'` ×5: **PASS PASS PASS PASS PASS**
(`SERIAL_FAILS=0`; case durations ~18–61s wall under load — freeze holds).

Full:
- generic-node `login-malformed-rate-limit` + `admin-error-envelope`: **9/9**
- node-core `login-rate-limit.test.ts`: **6/6**

## Files this rework

| File | Why |
|------|-----|
| `apps/generic-node/test/login-malformed-rate-limit.test.ts` | Freeze Date.now for suite |
| `tasks/ztr-1218-implementer-r2.md` | This handoff |

## Deferred

None.
