# ZTR-1220 — implementer r7 (lint-only; merger BLOCKED clearance)

Claim run: `7be9a03f-0b91-473a-9701-dc8a6d855c38`

## Binding BLOCKED
Dual r6 PASS @ `083cd88dc91a9b5fbb36e2016a62d7ae248fcb52` but merger refused:
PR-introduced ESLint `amounts-admin/no-float-amount` at
`apps/generic-node/admin/src/lib/money.ts:1591` — `run.push(Number(c))` inside
digit-Fibonacci structure guard. CI main job red; dual fence satisfied but
merge gate refuses self-introduced lint.

## Fix (lint only — no seal policy change)

1. Replace SPA digit parse `Number(c)` with `c.charCodeAt(0) - 48` (digits already
   gated `c >= "0" && c <= "9"`). Same 0–9 integer for Fibonacci structure math;
   no `Number(` in admin SPA (rule scope).
2. **Do not** weaken r6 generate-only seal: create/reissue still refuse
   caller-supplied secrets; CSPRNG seal path untouched.
3. Rebased onto latest `origin/main` (`594214cc…`) before the fix.

## Verification

```
pnpm --filter @zucoins/generic-node-ui run lint
  # exit 0 (no amounts-admin/no-float-amount)

pnpm --filter @zucoins/generic-node-ui exec eslint src/lib/money.ts
  # exit 0

pnpm --filter @zucoins/generic-node exec vitest run \
  src/ops/recovery-pack.test.ts test/admin-recovery-pack.test.ts
  # 51 passed (generate-only seal retained)

pnpm --filter @zucoins/generic-node-contracts build && \
pnpm --filter @zucoins/generic-node-ui exec vitest run src/lib/money.test.ts
  # 39 passed
```

## Files

- `apps/generic-node/admin/src/lib/money.ts` — digit run parse without `Number(`
- `tasks/ztr-1220-implementer-r7.md`

## Dual-review VOID fence
Prior r6 dual PASS at `083cd88d…` is VOID at this tip — lint-only head move.
Re-run opposed A+B at the new head before merge.

## Head SHA

`df6cba4a93270ed89239aeba8d1764ea86bc2727`
