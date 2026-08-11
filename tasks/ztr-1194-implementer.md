# ZTR-1194 implementer

## Ticket
Wrong TOTP on approve returns 403 so SPA prompt aborts.

## Governing
- Doc 01 §4.2 dual-control / opaque factor failure (policy denial distinguishable; factor reasons collapse)
- `packages/node-core/src/send/approve.ts` `toOpaqueApprovalFailure`
- SPA contract: `apps/generic-node/admin/src/totp/useTotpGatedMutation.ts` (401 challenge re-prompt)
- Sibling never-403 reconciliation: ZTR-1191 (broader 403 surface); this ticket is the approve factor AC

## Change
1. **Server** — `APPROVAL_FACTOR_FAILURE_HTTP_STATUS` 403 → **401**. Policy denial stays **403** via new `APPROVAL_POLICY_DENIAL_HTTP_STATUS`. Router uses constants for opaque approve reject. Body code/message unchanged (`approval_rejected` / `approval rejected`).
2. **Contracts** — `ADMIN_ERROR_CODES` typical http for `approval_rejected` → 401 (membership freeze; pair matrix not frozen).
3. **SPA** — `isTotpChallenge` accepts `401 approval_rejected`; `totpErrorMessage` maps it to *Code invalid — try again.*; second consecutive failure adds client-only wait-for-next-code hint.
4. **TransferDetailPage** — device signature + challenge nonce held in a ref outside the TOTP retry loop so a wrong code does not re-sign or re-fetch challenge.

## Out of scope
- Bless/device-enrol/origin/password 403 sites (ZTR-1191)
- Server-side distinguishable `totp_replay` code (would reopen oracle)
- ApproveInboxPage TOTP-only path (no device ceremony today)

## Verification

Head SHA is the PR head (see `gh pr view` / merge commit parent). Recorded at release time.
| Command | Result |
|---|---|
| `tsc -b` (root via package builds) | green |
| `pnpm --filter @zucoins/node-core exec vitest run src/send/approve.test.ts` | 25/25 |
| `pnpm --filter @zucoins/generic-node exec vitest run test/admin-g4-device-dual-push.test.ts` | 18/18 (teardown psql noise only) |
| `pnpm --filter @zucoins/generic-node-ui test` | 40 files / **317/317** |
| `pnpm --filter @zucoins/generic-node-contracts exec vitest run src/admin-auth-errors gen/json-sync` | 63/63 |
| lint on touched files | green |
| `pnpm test:boundaries` | 1 pre-existing fail on main (`drain`/`sweep` terms in ZTR-1156 files) — not this change |
| root `pnpm test` | pre-existing neutrality/scan-gate + flaky lockout/pg setup on this host |

## AC
- [x] Wrong TOTP on approve → **401**
- [x] SPA re-prompts *Code invalid — try again.*; challenge/device sig survive retry
- [x] Correct second code completes without re-challenge / re-sign
- [x] Client-only second-failure wait hint; server opaque unchanged
- [x] Factor reasons remain byte-identical body (same code/message); only status number changed
- [x] SPA suite green with new coverage
- [x] Approve/node-core + g4 green; boundaries pre-existing only

## Files
- `packages/node-core/src/send/approve.ts` (+ index, test)
- `apps/generic-node/src/admin-router.ts`
- `packages/generic-node-contracts/src/admin-auth-errors/codes.ts`
- `apps/generic-node/test/admin-g4-device-dual-push.test.ts`
- `apps/generic-node/admin/src/totp/useTotpGatedMutation.ts` (+ test)
- `apps/generic-node/admin/src/pages/transfers/TransferDetailPage.tsx`
