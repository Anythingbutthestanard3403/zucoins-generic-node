# ZTR-1313 implementer r2 — alias/exports CI bounce

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/165
- **Branch:** `ztr-1313-consumer-publishable`
- **Prior reviewed head:** `b06d3fbad90ff1d913d8b59b28bbc29a97913745`
- **Claim run:** `8c380a5c-b90c-4421-97bd-5758b497b90d`

## Defect
`exports["."]` became `{types, import}`. `packageSourceAliases` called `target.replace` assuming a string. `packages/consumer-example/vitest.config.ts` threw `TypeError: target.replace is not a function`; `pnpm test` could not start.

## Fix
`vitest.aliases.ts` resolves a conditions object via `import` / `default` / `types` before `.replace`. Publishable consumer package shape unchanged (`private: false`, files, repository, conditions export). Regression: `packages/consumer-example/src/package-source-aliases.test.ts`.

## Verification
- `pnpm --filter @zucoins/generic-node-consumer test` — 18 files / 106 tests
- `pnpm --filter @zucoins/generic-node-consumer lint`
- `pnpm --filter @zucoins/consumer-example test` — 3 files / 6 tests (includes alias suite)
- `pnpm --filter @zucoins/consumer-example lint`
- `packageSourceAliases(consumer)` → `@zucoins/generic-node-consumer` → `src/index.ts`
