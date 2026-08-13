# ZTR-1273 — Acceptance suite + ops runbooks (epic exit bar)

**Linear:** https://linear.app/zutopia/issue/ZTR-1273  
**Epic:** ZTR-1266  
**Depends on:** ZTR-1269 + ZTR-1270 + ZTR-1271 on main; ZTR-1272 (PR #131) merged  
**Branch:** `ztr-1273-acceptance-suite`  
**Claim run:** `4a4c60ce-bae8-4ac5-b3ef-a9c32f560314`

## Deliverables

1. Scenario matrix automation (unit composition + PG selection)
2. Ops runbook `docs/operations/wallet-money-capabilities.md` + README index
3. Attention triage composition failure modes
4. Evidence comment on ZTR-1266 (test names + doc paths)
5. Drift-gate clean; STRICT dual money-path (expected)

## Scenario → test map

| ID | Expect | Unit | PG |
| -- | -- | -- | -- |
| S1 hub funded / worker empty | MOVE then SEND | matrix S1 | acceptance.pg S1 + assign-and-topup.pg |
| S2 worker pre-funded | no MOVE | matrix S2 | acceptance.pg S2 |
| S3 only INTERNAL_ONLY | reject | matrix S3 | acceptance.pg S3 |
| S4 only RECEIVE_ONLY | reject | matrix S4 | acceptance.pg S4 |
| S5 underfunded + empty hubs | no_hub_liquidity | matrix S5 | acceptance.pg S5 |
| S6 two hubs second covers | second hub | matrix S6 | acceptance.pg S6 |
| S7 explicit INTERNAL_ONLY source | reject | matrix S7 | (composition + gates) |
| S8 omit source | node assigns | matrix S8 | assign-and-topup.pg |
| S9 SEND_ONLY ∉ receive | never select | matrix S9 | acceptance.pg S9 + gates.pg |
| S10 two INTERNAL_ONLY MOVE | allowed | matrix S10 | acceptance.pg S10 + gates.pg |
| S11 halt | blocks formation | matrix S11 | halt-kind-scope (existing) |


## AC status

- [x] Scenario table automated (S1–S11) — matrix unit + PG selection; no waivers
- [x] Ops runbook `docs/operations/wallet-money-capabilities.md` + README index
- [x] Attention triage composition failure modes
- [x] Parent epic evidence comment path (test names + doc paths)
- [x] Drift-gate clean (SCAN_SCOPE); money-path STRICT dual expected on PR
