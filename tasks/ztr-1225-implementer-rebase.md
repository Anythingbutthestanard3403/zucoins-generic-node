# ZTR-1225 implementer rebase (PR #90)

- **lane:** implementer
- **run:** `7be9a03f-0b91-473a-9701-dc8a6d855c38`
- **prior CONFLICTING head:** `4b99a62a0cdfc41e265adef2dc86e9342aee1d52`
- **new HEAD:** `db84f06b1b1a0a2ee126fd51c504ebf981b1cd2e`
- **base:** `origin/main` @ `dac8a97ccfbedba730672a3fa2cc2263db46e8fe`
- **PR:** #90 (`ztr-1225-typecheck-tests`)
- **worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1225-rebase`
- **local branch during rebase:** `ztr-1225-typecheck-tests-rebase` → force-with-lease pushed to `origin/ztr-1225-typecheck-tests`

## Why

PR #90 was **CONFLICTING** vs main after intervening merges (release scripts on
root `package.json`, ZTR-1217 wallet inventory D3 fixtures). Dual/review at
`4b99a62` is void after rebase. r2 nodeId restore must be kept.

## Rebase result

```
git rebase origin/main
# commit 1/4 (de81d63 typecheck:tests product): CONFLICT package.json only
# commits 2–4 (evidence, r2 nodeId, r2 pin): clean
# + follow-up commit: inventory D3 stub casts for typecheck green on new main
```

### Conflict resolution (`package.json`)

Keep **both**:

| Side | Scripts kept |
|------|----------------|
| main | `release:validate`, `release:test`, `release:fence` |
| ZTR-1225 | `typecheck` → `build:tsc` + `@zucoins/generic-node typecheck:tests` |

### Post-rebase typecheck fix

ZTR-1217 D3 tests in `admin-inventory.test.ts` annotated stubs as
`InventorySqlExecutor` with concrete row literals; `tsc -p tsconfig.tests.json`
rejects that under generic `R`. Fixed by matching the file's existing pattern
(untyped stub + `as InventorySqlExecutor`) — no production change.

## Commits after rebase (onto `dac8a97ccfbedba730672a3fa2cc2263db46e8fe`)

```
db84f06b docs(tasks): ZTR-1225 implementer rebase handoff (PR #90)
c06cc242 fix(test): cast ZTR-1217 inventory SQL stubs for typecheck:tests (ZTR-1225)
8ab615c4 docs(tasks): ZTR-1225 r2 implementer evidence head pin
cf32f670 fix(test): restore nodeId on admin router fixtures (ZTR-1225 r2)
1eab06c4 docs(tasks): ZTR-1225 implementer evidence
7eb5da93 fix(test): typecheck apps/generic-node/test and clear latent TS errors (ZTR-1225)
```

## Product preserved (r2)

| item | status |
|------|--------|
| `tsconfig.tests.json` + `typecheck:tests` + CI + root `typecheck` | kept |
| `createRecoveryPack` passcode→secret | kept |
| gateway/genesis T0 `.observe` role arity | kept |
| **r2** restore `nodeId` on admin router fixtures; drop deps `as never` | **kept** (`cf32f670` replay) |

## Verify at product HEAD

| Command | Result |
|---|---|
| `CI=true pnpm install --frozen-lockfile` | ok |
| `pnpm build:tsc` / `tsc -b` | ok |
| `pnpm --filter @zucoins/generic-node typecheck:tests` | **0 errors** |
| `pnpm typecheck` | ok |
| focused vitest (device-keys, g4 dual-push, inventory, recovery-pack) | **54 passed** |

## Files touched this rebase lane

- `package.json` (conflict resolve: typecheck + release scripts)
- `apps/generic-node/test/admin-inventory.test.ts` (D3 stub casts)
- `tasks/ztr-1225-implementer-rebase.md` (this file)
