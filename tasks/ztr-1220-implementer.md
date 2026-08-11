# ZTR-1220 — implementer handoff

## Summary
Recovery-pack creation no longer accepts secrets via the charset×length entropy
proxy. `recoverySecretWeakness` requires the `generateRecoverySecret()` shape:
exactly 26 Crockford base32 characters (`0-9A-Z` except `I/L/O/U`), ≥10 distinct
chars, no pure period-tiling, no ≥8-symbol monotone alphabet run.

SPA `generateRecoveryPackSecret` redraws on the same structure guards so a rare
CSPRNG miss cannot 400 at create (ZTR-1126 reviewer B3).

## Acceptance criteria
1. **Satisfied** — ticket false-accepts refused:
   `"abcdefghij".repeat(3)`, `qwertyuiop…`, `correct horse…`, 28-digit+letter,
   period-tiling Crockford strings.
2. **Satisfied** — shape + structure checks in `recovery-pack.ts`.
3. **Satisfied** — SPA still CSPRNG generate-by-default; field path unchanged.
4. **Satisfied** — unit + HTTP + SPA tests for accept strong / reject weak.

## Governing spec
- `docs/operations/recovery-ceremony.md` — Recovery pack section
- Prior: ZTR-1126 (`apps/generic-node/src/ops/recovery-pack.ts`)

## Deferred (explicit non-goals from ticket comments)
- B5 throttle symmetry for `from_pack_secret` failures → not this ticket
- B4 passcode dead code → ZTR-1225

## Head SHA
`db8e175375cbfdd42249d58c518dd4db6bca4a40`

## Verification (at head)
```
pnpm install                          # ok (CI=true --force in fresh worktree)
pnpm exec tsc -b                      # exit 0
pnpm --filter @zucoins/generic-node-ui typecheck  # exit 0
pnpm --filter @zucoins/generic-node lint          # exit 0
pnpm --filter @zucoins/generic-node-ui lint       # exit 0
pnpm --filter @zucoins/generic-node exec vitest run \
  src/ops/recovery-pack.test.ts test/admin-recovery-pack.test.ts
  # 44 passed (33 + 11); vitest worker teardown/psql DROP noise only
pnpm --filter @zucoins/generic-node-ui exec vitest run src/lib/money.test.ts
  # 37 passed
```

## Files
- `apps/generic-node/src/ops/recovery-pack.ts` — shape + structure floor
- `apps/generic-node/src/ops/recovery-pack.test.ts` — unit cases
- `apps/generic-node/test/admin-recovery-pack.test.ts` — HTTP create rejects
- `apps/generic-node/src/admin-router.ts` — comment
- `apps/generic-node/admin/src/lib/money.ts` — SPA redraw loop
- `apps/generic-node/admin/src/lib/money.test.ts` — SPA generator tests
- `docs/operations/recovery-ceremony.md` — drop free-form escape-hatch wording
