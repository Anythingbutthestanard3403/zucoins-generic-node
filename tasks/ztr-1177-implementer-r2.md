# ZTR-1177 implementer r2 — Review B FAIL remediation

- **Lane:** implementer · run=`5501196c-8c12-495b-8e2b-351631f9b70f`
- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/53
- **Branch:** `ztr-1177-vault-unlock-canary`
- **Prior FAIL head:** `30a965ed15f1e728512c3106911ebab5cc7f6703`
- **New head:** `7139b9158d8854ffcb9a94fae19feede7f6ab612`
- **Worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1177-r2/wt`
- **Blocker (Review B):** boot canary outside master-key rotation — after rotate, unlock dies on stale canary under the correct new key
- **Released to:** QA Review

## Root cause

`vault.boot_canary_v1` is a durable root-keyed envelope (apps `node_settings`) that gates
`vault-unlock`, but rotation only rewrapped `SEALED_STORES` (wallet / signing / push / TOTP).
Canary insert is `ON CONFLICT DO NOTHING` with no UPDATE path, so a successful rotate left the
stale envelope under the old root. Next boot opened rewrapped stores (`assertRoot` checked:true)
then failed `proveVaultRootWithBootCanary` with `VAULT_BOOT_CANARY_DOES_NOT_OPEN` — permanent
brick until an operator deleted the settings row.

## Fix (Review B option 1 — rewrap in ceremony)

1. **`boot-canary.ts`:** `loadVaultBootCanary`, `countVaultBootCanaryRows` (0-or-1),
   `rewrapVaultBootCanary` (open under old → seal under new → round-trip), `commitVaultBootCanary`
   (UPDATE + `row_version++`). Refuse rewrap when open-under-old fails. Unlock prove path
   unchanged (still insert-only; no wrong-key overwrite).
2. **`master-key-rotation.ts`:** optional ports `bootCanary` / `countBootCanaryRows` /
   `rewrapBootCanary` / `commitBootCanary`. When count port is wired, always run 0-or-1 canary
   step inside the ceremony UoW (parity, rewrap, commit with other stores). Finalize path
   verifies canary under new root when wired. Report id `VAULT_BOOT_CANARY` (apps-level; not
   elevated into packages `SEALED_STORES` census — seal site remains under apps/).
3. **`rotate-master-key.cli.ts`:** always requires `nodeId`, `loadBootCanaryCensus`,
   `countBootCanaryRows`; refuses when count>0 and `commitBootCanary` unwired; wires
   `rewrapVaultBootCanary` with node AAD.

## Files

| Path | Change |
|------|--------|
| `apps/generic-node/src/vault/boot-canary.ts` | rewrap / count / load / commit |
| `apps/generic-node/src/operations/rotate-master-key.cli.ts` | wire canary ports + nodeId |
| `packages/node-core/src/vault/master-key-rotation.ts` | ceremony step + finalize |
| `packages/node-core/src/vault/index.ts` | export `BootCanaryRotationCensus` |
| `apps/generic-node/test/vault/boot-canary.test.ts` | rewrap + post-rotate prove + no overwrite |
| `apps/generic-node/test/operations/rotate-master-key.cli.test.ts` | ceremony rewrites canary; refuse unwired commit |

## AC map (r2)

| Criterion | Status |
|-----------|--------|
| Post-rotation unlock under new key succeeds (canary rewrapped) | yes |
| Wrong root still fails closed; prove does not overwrite | yes |
| Rotation refuses if canary present but cannot open under old root | yes (rewrap throws → ROTATION_ABORTED) |
| Same UoW as other sealed commits | yes |
| Zero-wallet / missing canary still rotates (count 0) | yes |
| Prior ACs (virgin seal, wrong key, boot-lane throw path) | unchanged; tests still green |

## Verify (this head)

```
pnpm exec tsc -b --pretty false                                    # exit 0
cd apps/generic-node && npx vitest run \
  test/vault/boot-canary.test.ts \
  test/operations/rotate-master-key.cli.test.ts \
  test/boot-lane.test.ts --pool=threads                            # 3 files / 59 tests passed
pnpm --filter @zucoins/generic-node lint                           # exit 0
pnpm exec vitest run \
  packages/node-core/test/master-key-rotation.test.ts \
  packages/node-core/test/totp-sealed-store.test.ts \
  packages/node-core/test/push-sealed-store-rotation.test.ts       # 3 files / 58 tests passed
pnpm exec vitest run \
  packages/node-core/test/boundaries.test.ts \
  packages/node-core/test/manifest-boundaries.test.ts \
  packages/generic-node-contracts/src/scan/dependency-boundary.test.ts
# 3 files / 153 tests passed
```

## Residuals

- Canary remains apps-level (not in `SEALED_STORES`); any future apps root-keyed durable blob needs the same rotation checklist.
- Composition roots that call `runRotateMasterKeyCli` must now pass `nodeId` + canary census/count/commit ports (CLI main still fails closed until adapters are wired).
