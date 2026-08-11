# ZTR-1228 implementer evidence

**PR:** (filled after create)
**Head SHA:** `04235566e166f8edcc7a2352f436e8402060e9b3`
**Branch:** `ztr-1228-vitest-contracts-resolve`
**Base:** `origin/main` @ `b66163ed845b3bdd5105c2b50bff0148e4522804`

## Ticket

Consumer vitest projects resolved `@zucoins/generic-node-contracts` from `dist/`. Cold clone (no pre-build) false-FAILed collection with "Failed to resolve entry for package".

## Governing pattern

ZTR-1149 / `vitest.aliases.ts` `packageSourceAliases` — derive src aliases from package `exports`, longest-`find`-first so subpaths sit above package root.

No `docs/decisions/D*` entry required (test harness resolve only). Spec path: ticket AC + `vitest.aliases.ts` doc comment / CLAUDE.md vitest alias note.

## Change

- `packages/generic-node-consumer/vitest.config.ts` — add `packageSourceAliases(../generic-node-contracts/)` before node-core.
- `packages/consumer-example/vitest.config.ts` — same contracts aliases alongside existing consumer + node-core.

## Acceptance criteria

1. **Satisfied** — consumer vitest projects alias contracts (+ subpaths) to src via `packageSourceAliases`.
2. **Satisfied** — helper sorts descending find length; root is last within the contracts block (`rootIdx=24`, `after root=0`, `descending length true`).
3. **Satisfied** — cold clone (no contracts/node-core/consumer dist) green:
   - `@zucoins/generic-node-consumer`: 16 files / 84 tests passed
   - `@zucoins/consumer-example`: 2 files / 3 tests passed
4. **Satisfied** — mirrors ZTR-1149 pattern (same helper already used for node-core).

## Verification (at head `04235566e166f8edcc7a2352f436e8402060e9b3`)

```
CI=true pnpm install
  → Done in ~6s, lockfile up to date

# dist absent for contracts, node-core, generic-node-consumer
pnpm --filter @zucoins/generic-node-consumer test
  → Test Files  16 passed (16) / Tests  84 passed (84)

pnpm --filter @zucoins/consumer-example test
  → Test Files  2 passed (2) / Tests  3 passed (3)

pnpm exec tsc -b
  → exit 0 (clean)

pnpm --filter @zucoins/generic-node-consumer lint
  → eslint src --max-warnings 0 (exit 0)

pnpm --filter @zucoins/consumer-example lint
  → eslint src test --max-warnings 0 (exit 0)
```

## Files touched

| File | Why |
|------|-----|
| packages/generic-node-consumer/vitest.config.ts | contracts src aliases |
| packages/consumer-example/vitest.config.ts | contracts src aliases |

## Deferred

None. node-core / apps/generic-node already hand-list contracts aliases; out of ticket scope.
