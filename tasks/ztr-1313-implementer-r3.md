# ZTR-1313 implementer r3 — tsc rootDir CI bounce

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/165
- **Branch:** `ztr-1313-consumer-publishable`
- **Prior head:** `d2b1721d80687a557d153063f723cad3fac79eff`
- **Claim run:** `74aab20a-93f4-4a30-a620-449b4cda8c2b`

## Defect
r2 put `package-source-aliases.test.ts` under `packages/consumer-example/src/`. It imports repo-root `vitest.aliases.ts`. `pnpm exec tsc -b` failed TS6059 (not under `rootDir` `src`) and TS6307 (not listed in `tsconfig.json`).

## Fix
`git mv` the file to `packages/consumer-example/test/package-source-aliases.test.ts`. Same relative import (`../../../vitest.aliases.ts`). Vitest already collects `test/`. `tsconfig.json` `include` stays `src/**/*.ts`.

## Verification
- `pnpm exec tsc -b` — exit 0
- `pnpm --filter @zucoins/generic-node-consumer test` — 18 files / 106 tests
- `pnpm --filter @zucoins/consumer-example test` — 3 files / 6 tests (alias suite still runs)
