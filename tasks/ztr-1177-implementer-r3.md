# ZTR-1177 implementer r3 — Review A r2 FAIL remediation

- **Lane:** implementer · run=`0c2be9d5-0966-4a3d-802b-141653be44e8`
- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/53
- **Branch:** `ztr-1177-vault-unlock-canary`
- **Prior FAIL head:** `cfa1af3a907c38182edd6a5d99cb0769ee27fb88`
- **Worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1177-r3/wt`
- **Blocker (Review A r2):** canary rewrap old-only + finalize/resume used pre-rotation census → ROTATING/D-B5 brick
- **Released to:** QA Review (dual custody A+B)

## Root cause

1. `rewrapVaultBootCanary` opened only under `oldRootKey`. After vault-durable crash the live canary is already under **new**; resume re-entered rewrap with old-first → `VAULT_BOOT_CANARY_DOES_NOT_OPEN` → `ROTATION_ABORTED` while wallets may already be new-root.
2. Ceremony + `verifyCompletedStoreCensus` (D-B5) proved against `input.bootCanary.envelope` (caller snapshot). Post-durable that snapshot is stale old ciphertext → finalize refuses a correct DB.

## Fix

1. **`boot-canary.ts`:** open **new then old** (writer-first / key-ring parity with push+TOTP); skip reseal when already under new; else reseal + round-trip; refuse only if neither root opens.
2. **`master-key-rotation.ts`:** require `loadBootCanaryEnvelope` whenever `countBootCanaryRows` is wired; ceremony + D-B5 always resolve the **live** `node_settings` envelope (never snapshot alone).
3. **`rotate-master-key.cli.ts`:** wire `loadBootCanaryEnvelope` by re-invoking `loadBootCanaryCensus`.
4. **Tests:** already-under-new skip; neither-root refuse; ROTATING resume + D-B5 finalize with stale census; refuse missing live loader; CLI ROTATING resume.

## Files

| Path | Change |
|------|--------|
| `apps/generic-node/src/vault/boot-canary.ts` | new-then-old rewrap; carry-through |
| `packages/node-core/src/vault/master-key-rotation.ts` | live loader port + resolve |
| `apps/generic-node/src/operations/rotate-master-key.cli.ts` | wire live loader |
| `apps/generic-node/test/vault/boot-canary.test.ts` | resume skip + neither-root |
| `apps/generic-node/test/operations/rotate-master-key.cli.test.ts` | ROTATING resume |
| `packages/node-core/test/master-key-rotation.test.ts` | ROTATING + D-B5 stale census |

## AC map (r3)

| Criterion | Status |
|-----------|--------|
| Canary rewrap opens new then old; skip if already under new | yes |
| Resume + D-B5 prove live envelope, not stale snapshot | yes |
| Clean-path rotation rewrap still works | yes |
| Unlock prove insert-only / wrong-key no overwrite | yes (unchanged) |
| Zero-wallet / missing canary | yes (unchanged) |

## Verify (this head)

```
pnpm exec tsc -b --pretty false                                    # exit 0
apps/generic-node: boot-canary + rotate-cli                        # 2 files / 28 passed
packages/node-core: master-key-rotation.test.ts                    # 1 file / 45 passed
boundaries×2 + contracts boundary + boot-lane                      # 4 files / 187 passed
pnpm --filter @zucoins/generic-node lint                           # exit 0
# node-core lint: pre-existing no-useless-catch in leadership.ts (untouched)
```

## Residuals

- Concurrent first-boot insert during count=0 rotation (B r2 residual) unchanged.
- Direct `rotateMasterKey` without canary ports still skips canary; production CLI always wires count+live+commit.
