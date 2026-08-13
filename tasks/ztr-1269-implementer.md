# ZTR-1269 implementer — Admin API + dashboard: set wallet money mode

**Linear:** https://linear.app/zutopia/issue/ZTR-1269  
**Epic:** ZTR-1266  
**Branch:** `ztr-1269-wallet-money-mode-admin`  
**Base:** `ztr-1267-wallet-money-capability` (PR #125 — schema not yet on main)  
**Claim run:** `1912efd4-754c-4097-8064-9875a6465b17`

## Scope

1. Admin HTTP `PATCH /admin/v1/wallets/:wallet_id/money-capability`
2. TOTP-gated + required Idempotency-Key + atomic admin mutation TX
3. `row_version` CAS on `wallets`
4. Audit log before→after (mode + flags)
5. SPA list badge + detail mode selector + plain help; multiple INTERNAL_ONLY allowed
6. Soft fleet warnings (zero send-capable / zero receive-capable)
7. `flagsFromMode` from contracts money-capability
8. API + component tests
9. Drift-gate clean copy

## Implementation

| Surface | Path |
|--------|------|
| Store (SQL + memory) | `packages/node-core/src/operator/wallet-money-capability.ts` |
| Admin route | `apps/generic-node/src/admin-router.ts` (`admin_wallet_money_capability`) |
| TX wiring | `apps/generic-node/src/full-http-mount.ts` `portsFor` |
| SPA client | `apps/generic-node/admin/src/lib/money.ts` `patchWalletMoneyCapability` |
| Labels | `apps/generic-node/admin/src/lib/labels.ts` `MONEY_MODE_LABELS` |
| List badge | `MoneyModeBadge` + `WalletsPage` |
| Detail editor | `WalletDetailPage` mode select + TOTP save |

Body: `{ "mode": "RECEIVE_ONLY"|"SEND_ONLY"|"INTERNAL_ONLY"|"FULL", "expected_row_version": N }`.  
Mode is sole control; flags derived via `flagsFromMode`. Audit action `wallet.money_capability_changed`.

## AC checklist

| AC | Status | Evidence |
|----|--------|----------|
| TOTP-gated PATCH sets mode | Done | `admin-wallet-money-capability.test.ts` |
| row_version CAS | Done | same (409 on stale) |
| Audit before→after | Done | store unit + API tests |
| UI list + detail | Done | WalletsPage badge; WalletDetailPage selector |
| Multiple INTERNAL_ONLY | Done | API + UI copy |
| Keyboard-usable control | Done | labelled `<select id=…>` |
| Forbidden-terms clean | Done | hub/internal-only/float wording |
| Help covers four modes | Done | `wallet-money-mode-help-all` |

## Tests run

- `packages/node-core` — `wallet-money-capability.test.ts` (6) + `boundaries.test.ts` (74) PASS
- `apps/generic-node` — `admin-wallet-money-capability.test.ts` (6) PASS; `tsc -b` PASS
- `apps/generic-node/admin` — MoneyModeBadge + WalletsPage + WalletDetailPage (13) PASS; typecheck PASS

## Out of scope

- ZTR-1268 admission gates
- Top-up composition / optional source API

## PR base note

Stacks on #125 (`ztr-1267-wallet-money-capability`). If 1267 merges first, rebase onto `origin/main` and retarget PR base to `main`.
