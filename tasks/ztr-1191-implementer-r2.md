# ZTR-1191 implementer r2 — dual-FAIL rework

**Lane:** implementer run=`aeec1a67-1fad-4f50-bc01-0d5be5c74003`  
**PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/55  
**Branch:** `ztr-1191-never-403-reconcile` (rebased on `origin/main`)  
**Prior FAIL head:** `cbabdccb9708d16851b97a5fc24b8ed6b8ea3410`  
**New head:** 38b61aa07b09444baec6b6ad4da3c7acb180384e

## Dual-FAIL defects closed

1. **Bless nested status/code extraction** on `mutation_threw` (parity enrol/revoke) so
   `authorization_rejected` serves **401 `approval_rejected`**, not 500 `mutation_failed`.
   - `apps/generic-node/src/admin-router.ts` bless failure arm extracts nested `status`/`code`
     from `guarded.error` when `reason === "mutation_threw"`.
2. **Gate drives real bless authorization refusal** with valid `BlessBody` (UUID nonce,
   RFC3339ms timestamps, padded Ed25519 sig, UUID `device_key_id`) and
   `destinationService.bless → { status: "authorization_rejected" }` on **both**
   `AdminRouteDeps.destinationService` and atomic `AdminMutationTxPorts.destinationService`.
   Asserts `status === 401` and `code === "approval_rejected"`.

## Rebase notes (main moved)

- Rebased onto `origin/main` after ZTR-1194 (`APPROVAL_FACTOR_FAILURE_HTTP_STATUS=401` +
  `APPROVAL_POLICY_DENIAL_HTTP_STATUS`).
- Kept Option-2 never-403: policy denial stays distinguishable by **code**
  (`same_operator_both_sides`) but HTTP status is **401** (not 403). Catalog +
  `APPROVAL_POLICY_DENIAL_HTTP_STATUS` + G4 expectations aligned.
- Carve-out 403s remain origin/password posture only via
  `AUTH_CLASS_POLICY.OPERATOR_SESSION.nonAuthorizationStatuses: [403]`.

## Verify (exact head)

```
pnpm install (CI=true)
tsc -b                                     # EXIT 0
pnpm --filter @zucoins/generic-node-contracts exec vitest run \
  src/route-policy/manifest.freeze.test.ts src/admin-auth-errors/codes.census.test.ts
  → 31/31 PASS
pnpm --filter @zucoins/node-core exec vitest run src/send/approve.test.ts
  → 25/25 PASS
pnpm --filter @zucoins/generic-node exec vitest run \
  test/admin-never-403-auth.gate.test.ts test/admin-g4-device-dual-push.test.ts
  → 22/22 PASS
```

## Files touched (r2 delta on top of rebased 1191)

- `apps/generic-node/src/admin-router.ts` — bless nested extract
- `apps/generic-node/test/admin-never-403-auth.gate.test.ts` — real bless auth refusal + ports wiring
- `apps/generic-node/test/admin-g4-device-dual-push.test.ts` — policy 401 (rebase)
- `packages/node-core/src/send/approve.ts` — POLICY status 401 + comment
- `packages/node-core/src/send/approve.test.ts` — policy distinguishable by code at 401
- `packages/generic-node-contracts/src/admin-auth-errors/codes.ts` — same_operator http 401
- route-policy Option-2 data field (prior 1191 commit, rebased)

## AC checklist

- [x] approve auth/factor failure → 401; no 403 literal in admin-router.ts
- [x] bless auth/factor failure → 401 approval_rejected (nested extract; gate asserts)
- [x] device enrol/revoke auth failure → 401
- [x] APPROVAL_FACTOR_FAILURE_HTTP_STATUS === 401; gate pins equality
- [x] carve-out is data: nonAuthorizationStatuses; verifier reads authFailureStatus only
- [x] served-surface gate real adminRouter; bless positive 401 assertion
