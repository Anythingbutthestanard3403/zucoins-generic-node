# ZTR-1191 implementer

## Choice
**Option 2** — carve out named non-authorization 403s; collapse authorization/factor failures to 401.

## Changes
1. `AuthClassPolicy.nonAuthorizationStatuses` data field; `OPERATOR_SESSION: [403]`.
2. `APPROVAL_FACTOR_FAILURE_HTTP_STATUS` 403 → 401; approve/bless/device enrol/revoke emit 401.
3. Nested-error status extraction on device enrol + revoke (throw `{status}` was previously swallowed as 500).
4. ADMIN_ERROR_CODES http for auth-refusal codes flipped to 401; carve-out codes stay 403.
5. Served-surface gate: `apps/generic-node/test/admin-never-403-auth.gate.test.ts`.
6. route-policy golden + drift-manifest sha regenerated.

## Acceptance
- [x] approve/bless/device enrol/revoke → 401 on auth/factor failure; no 403 in admin-router.ts
- [x] APPROVAL_FACTOR_FAILURE_HTTP_STATUS equals router approve failure (401); gate asserts
- [x] carve-out is data on auth-classes; verifier reads authFailureStatus only
- [x] gate drives real adminRouter authenticated-but-refused table
- [x] opaque approve collapse unchanged (code/body); only status number
- [x] emit-json equivalent: golden + contract-drift-manifest sha updated, freeze tests green
- [x] tests green on touched packages (pre-existing scan gate + leadership lint on main)

## Verify (implementation SHA)
```
npx tsc -b                                    # green
pnpm --filter @zucoins/generic-node-contracts test
  # 2732 passed; 1 pre-existing fail: generic-core.scan-gate (drain/sweep on main)
pnpm --filter @zucoins/node-core targeted auth suite
  # 7 files, 151 passed
apps/generic-node targeted admin suite (incl. gate)
  # 7 files, 69 passed (gate 4/4)
```

## Governing
- `packages/generic-node-contracts/src/route-policy/CONTRACT.md` J2
- `packages/generic-node-contracts/src/route-policy/auth-classes.ts`

## PR
#55 — https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/55

## Head SHA
`6003f5e9f84aa8139e7589dd720d032d33fa5a55`
