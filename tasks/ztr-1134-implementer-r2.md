# ZTR-1134 implementer r2 — FAIL B remediation

**PR:** #42 · **Branch:** `ztr-1134-totp-seal`  
**Claim:** implementer run=`f2cf3a31-bcc2-4256-a1aa-bd76f599ebf7`  
**Plan:** `tasks/plan-ZTR-1134.md` (PASS) · **Against:** FAIL B `tasks/ztr-1134-review-B-dd9b6c1.md`

## Head SHA

`d31d1cdb92bc80f9a50c0fae9683a450f6a716c6` (implementation commit; PR tip may add docs-only commits)

## Fixes

| ID | Change |
|----|--------|
| **B1a** | `SqlAdminUserStore.armVaultRoot()`; `setPending`/`setActive` throw `VaultSealingNotArmedError` until armed. `main.unlockVault` arms after rederive + self-check + `migrateTotpSecretsAtRest`. Enrol maps to 503 `vault_locked`. |
| **B1b/c** | `migrateTotpSecretsAtRest` trial-opens every non-null `totp_secret_sealed` under final root; any `TotpOpenError` fails boot (named error). |
| **B1d** | `main.ts` comments: buffer may be held pre-gate; seal-on-write must not run until arm. |
| **B2a** | `requireActiveTotpFactor` catches `TotpOpenError` → 401 `totp_required`. |
| **B2b** | `resolveOperatorTotpConfig` catches open error → null / lab-if-armed only. |
| **B2c** | Readiness: open fail → `totpEnrolled=false` (not null). |
| **B2d** | No forged secret; lab only when `isUsableLabTotp`. |
| **B3a/b** | Removed `Buffer.alloc(32,0)`; require non-zero 32-byte `vaultRootKey` when defaulting SQL store. Recovery + tests pass real roots; recovery arms store. |

## Files

- `packages/node-core/src/http/admin-user-sql-store.ts`, `admin-session.ts`, `admin-auth-handlers.ts`, `index.ts`
- `packages/node-core/src/totp/migrate-plaintext.ts`
- `apps/generic-node/src/main.ts`, `full-http-mount.ts`, `admin-router.ts`, `ops/run-recovery-ceremony.ts`
- Tests: `totp-sealed-store.test.ts` (+arm/census/B2), mount suites + `route-policies-mount` B3, recovery arm

## Verify (this head)

```
tsc -b                          → 0 errors
vitest node-core totp-sealed-store + admin-totp-enrol → 22/22
vitest generic-node mount/composition suites → 61/61 (route-policies 21, dual-control 3, discovery 7, census 3, verification 10, durable-mount 2, destinations 10, stream 5)
```

## AC

- [x] B1a–d, B2a–d, B3a–b as plan
- [x] Registry/HKDF/AAD/rewrap unchanged
- [ ] Dual A+B re-review at new head (next lane)

## Deferred

None for FAIL B blockers.
