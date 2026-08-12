# ZTR-1255 implementer

- **lane:** implementer · run=`7fc76851-6044-4e32-8613-508ca6300fd4`
- **branch:** `ztr-1255-wallet-hold-cause`

## Done

1. Contract + SQL projection: `holding_lease_role`, `holding_operation_type` on wallet inventory (lease sole hold-cause authority; `wallets.state` remains custody standing).
2. `StatusTag`: `quarantined` → danger; removed undifferentiated `busy` map key; `retired` muted.
3. `WalletHoldCause` component + list/detail/Overview wiring — pinned names holding op + link + countdown; quarantine shows reason; no bare "busy" pill.
4. e2e fixtures: AVAILABLE + QUARANTINED rows; Playwright assert danger severity.
5. Unit tests for StatusTag, hold cause, WalletsPage quarantine/pinned.

## AC

- [x] Pinned wallet names holding op with link
- [x] Quarantined danger everywhere (list, detail, Overview StatusTag)
- [x] No bare "busy" for non-AVAILABLE
- [x] e2e/unit: QUARANTINED alarmed; AVAILABLE not busy
