# ZTR-1214 implementer rebase (PR #77)

- **lane:** implementer
- **run:** `a3c0869e-aa7d-4187-9150-2e512c69d55f`
- **prior dual-PASS head (void after rebase):** `b435ded4666ea26dc8bc593977afd2e98dcdf2de`
- **base:** `origin/main` @ `e65e1805e36aa157ddf72020fe096db57d36b9a8`
- **PR:** #77 (`ztr-1214-dual-control-policy`)
- **worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1214-rebase`
- **product HEAD (pre-docs tip):** `685250811860c1b94343da3057d3591e3e73cdb2`

## Why

Merger blocked: branch was ~17+ commits behind `origin/main` with reported
`admin-router.ts` conflict risk. Rebased six branch commits onto latest main
so dual can re-run on a current base.

## Rebase result

```
git rebase origin/main
# 6/6 commits applied cleanly — zero conflict markers
```

Commits after rebase (onto `e65e1805e36aa157ddf72020fe096db57d36b9a8`):

```
6852508 docs: ZTR-1214 r2 implementer handoff (Review B D1-D4)
bffeed0 fix(ops): dual-control fail-closed on unreadable store and missing port (ZTR-1214)
ad4176c docs: ZTR-1214 handoff final HEAD
c4d4b19 docs: fix ZTR-1214 handoff HEAD SHA
8e4c9d0 docs: ZTR-1214 implementer handoff PR #77 + HEAD
90b3c29 fix(ops): durable dual-control policy mutation with fresh TOTP + audit (ZTR-1214)
```

No conflict resolution required. `admin-router.ts` and dual-control product
files replayed without manual merge.

## Product preserved (D1–D4 + durable mutation)

| item | status |
|------|--------|
| D1 unreadable store → `two_human` | kept (`createSqlDualControlPolicy.getMode`) |
| D2 missing port → `two_human` (GET/approve) | kept (`admin-router.ts`) |
| D3 boot logs SQL `getMode` effective mode | kept (`main.ts`) |
| D4 InMemory `setMode` requires audit meta | kept (`InMemoryDualControlPolicy`) |
| SQL port + single-statement audit journal | kept |
| money-pack `dual-control-policy` slice | kept |
| POST `/admin/v1/dual-control-policy` fresh TOTP | kept |

## Local verify (PASS)

| suite | result |
|-------|--------|
| `pnpm exec tsc -b` | exit 0 |
| `dual-control-policy.test.ts` | included in 85 |
| `migration-integrity.test.ts` | 10 PASS |
| `dual-control-mode-wiring.test.ts` | included |
| `admin-g4-device-dual-push.test.ts` | 23 PASS |
| `admin-never-403-auth.gate.test.ts` | 5 PASS |
| `config-mutable.test.ts` | included |
| `atomic-admin-mutation.pg.test.ts` | 6 PASS |
| **focused total** | **91/91 PASS** @ `685250811860c1b94343da3057d3591e3e73cdb2` |

(Vitest global teardown hit intermittent `psql ETIMEDOUT` on DROP DATABASE;
test bodies all green.)

## Push

`git push --force-with-lease origin ztr-1214-dual-control-policy`

Prior dual-PASS void — reviewers must re-run dual on new HEAD.
