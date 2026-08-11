# ZTR-1225 — implementer

## Summary
`apps/generic-node/test/**` was outside `tsc` (`tsconfig.json` include is `src/**` only). Added `apps/generic-node/tsconfig.tests.json` + `typecheck:tests` / root `typecheck`, wired CI after Build, and cleared all surfaced TS errors (~130 → 0).

## Acceptance criteria
1. **Satisfied** — `apps/generic-node/tsconfig.tests.json` includes `src/**` + `test/**`.
2. **Satisfied** — `pnpm --filter @zucoins/generic-node typecheck:tests` is green; includes `passcode` → `secret` at `admin-recovery-pack.test.ts`.
3. **Satisfied** — root `pnpm typecheck` runs `build:tsc` + `typecheck:tests`; CI step `Typecheck generic-node tests`.
4. **Satisfied** — production behaviour unchanged except `createGatewayT0Observer` / `createGenesisT0Observer` now accept the second `ReceiveT0Observer.observe` role argument (already required by the interface; callers in prod already pass it).

## Governing docs
- Ticket ZTR-1225 (sweeper AC 2026-08-11).
- No D-register decision required (tooling/test hygiene).

## Head SHA
`de81d63a75b80741e6fba5f718f7a3c599d8839b`

## Verification
- `pnpm install` — ok
- `pnpm build:tsc` / `tsc -b` — ok
- `pnpm --filter @zucoins/generic-node typecheck:tests` — 0 errors
- `pnpm typecheck` — ok
- `pnpm --filter @zucoins/generic-node lint` — ok
- Focused vitest (7 files): **119 passed** (teardown `psql` ETIMEDOUT only)

## Files
- Gate: `apps/generic-node/tsconfig.tests.json`, `apps/generic-node/package.json`, `package.json`, `.github/workflows/ci.yml`, `apps/generic-node/test/types/ambient-modules.d.ts`
- Prod surface align: `gateway-t0-observer.ts`, `genesis-t0-observer.ts` (`observe(wallet, role)`)
- Tests: ~40 files (dualControlMode, brands, readonly spreads, recovery pack secret, etc.)

## Deferred
None.
