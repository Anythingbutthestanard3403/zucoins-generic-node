# ZTR-1220 — implementer r3 (Review B r2 FAIL clearance)

## Summary
Closed the residual digit-broken dictionary / keyboard / alternating-skeleton
false-accept class that still sealed under the r2 letter-run / near-tile floor.
SPA structure mirror kept in lockstep; throw-not-emit retained.

## Review B r2 clearance
1. **Class alternation** — `hasClassAlternationRun` rejects digit↔letter runs ≥10
   (closes `0A1B2C3D4E5F6G7H8J9KMNPRST`, `A1B2C3D4E5F6G7H8J9K0M1N2P3`,
   `C001R2R3E4C5T6H708R9S0E1B2`, alt-digit MASTERKEY/PASSWORD skeletons).
2. **Class pair sequences** — `hasClassPairRun` rejects ≥6 consecutive LD/DL pairs
   from either alignment (complements alternation).
3. **Keyboard rows** — contiguous Crockford-legal keyboard substrings ≥5
   (QWERTY/ASDF/ZXCV/digit rows + row-stitches; letter-skeleton match for
   digit-broken keyboard rows). Closes `QWERTYASD1FGHZXCVBN12345AB`.
4. **Dictionary skeleton** — letter skeleton + leet fold (0→O,1→I,3→E,4→A,5→S,7→T)
   against ≥5-letter tokens, or ≥2 distinct 4-letter custody/password tokens.
   Closes digit-broken `C0RRECT…`, `P1EASE…`, `W1NTER…`, `MAYTHE…`, `NEVER…`,
   `MANC0DE…PASS…NODE`.
5. **Prior r2 floor retained** — near-period / same-run / step-k / letter-run /
   vacuous-belt / SPA throw-not-emit unchanged.
6. **SPA** — `recoveryPackSecretStructureOk` mirrors the new guards byte-for-byte
   (exported for parity tests only); generate still throws after 64 redraws.
7. **Tests** — unit + seal + HTTP + SPA cover the named r2 residual list.

## Acceptance criteria
1. **Satisfied** — r2 residual false-accepts refuse `weak_secret` / HTTP
   `weak_recovery_secret`; `createRecoveryPack` throws (named list below).
2. **Satisfied** — shape + extended structure floor in `recovery-pack.ts`.
3. **Satisfied** — SPA CSPRNG generate-by-default; mirror rejects same residual
   set; no weak last-resort emit.
4. **Satisfied** — unit / HTTP / SPA tests for residual class.

## Named residual list (must reject)
- `C0RRECTH0RSEBATTERY0STAP1E`
- `C0RRECTH0RSEBATT3RYSTAP1E0`
- `C001R2R3E4C5T6H708R9S0E1B2`
- `P1EASE1ETME1NT0THEN0DE2024`
- `QWERTYASD1FGHZXCVBN12345AB`
- `0A1B2C3D4E5F6G7H8J9KMNPRST`
- `A1B2C3D4E5F6G7H8J9K0M1N2P3`
- `MANC0DE7P1NGETP1NPASS4N0DE`
(+ extended set in unit tests: winter/force/rickroll/masterkey/password alts)

## Design note
Generate-only (refuse caller-supplied secrets) was considered and deferred: the
SPA ceremony posts a client-CSPRNG secret that must still open the same seal the
operator is shown; server-side generate would require returning the secret in the
create response, which is explicitly forbidden (idempotency durable row). The
structure floor closes the residual class without changing that wire contract.

## Verification
```
pnpm exec tsc -b                                      # exit 0
pnpm --filter @zucoins/generic-node-ui typecheck      # exit 0
pnpm --filter @zucoins/generic-node lint              # exit 0
pnpm --filter @zucoins/generic-node-ui lint           # exit 0
pnpm --filter @zucoins/generic-node exec vitest run src/ops/recovery-pack.test.ts
  # 35 passed
pnpm --filter @zucoins/generic-node exec vitest run test/admin-recovery-pack.test.ts
  # 11 passed
pnpm --filter @zucoins/generic-node-ui exec vitest run src/lib/money.test.ts
  # 39 passed
```

## Files
- `apps/generic-node/src/ops/recovery-pack.ts` — alternation / pair / keyboard / dict
- `apps/generic-node/src/ops/recovery-pack.test.ts` — r2 residual unit + seal
- `apps/generic-node/test/admin-recovery-pack.test.ts` — HTTP residual rejects
- `apps/generic-node/admin/src/lib/money.ts` — SPA mirror
- `apps/generic-node/admin/src/lib/money.test.ts` — SPA parity residual rejects
- `docs/operations/recovery-ceremony.md` — structure floor wording
- `tasks/ztr-1220-implementer-r3.md` — this handoff

## Head SHA
(filled after push)
