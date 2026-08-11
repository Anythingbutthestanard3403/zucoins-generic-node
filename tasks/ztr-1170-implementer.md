# ZTR-1170 implementer

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/64
- **Head SHA:** `79bcc1d356cf1a3af5ab8fba1a849be8ef258769`
- **Branch:** `ztr-1170-api-contract-residuals` (from origin/main @ dcb1feb + rebase)
- **Claim run:** `bbcb7f8f-7a26-40dd-bc76-d3b88811ed82`

## ACs

| # | Criterion | Disposition |
|---|-----------|-------------|
| 1 | POST /v1/receives 201 | **Superseded** — `RECEIVE_CREATE_SYNC_201_SUPERSESSION` (create always 202/NOT_CREATED; READY body is worker-async) |
| 2 | Admin envelope `details` | **Prior ZTR-1196** — `buildAdminErrorBody` + `AdminErrorEnvelopeSchema`; tests green |
| 3 | Admin codes / conflict | `operation_version_conflict` on wire; `operation_conflict` alias kept in `ADMIN_ERROR_CODES` |
| 4 | Snapshot §3 + move_eligible | `renderSnapshotBody` + PG reader join wallets + `verifyAutomaticSinkEligibility` |
| 5 | RECEIVE_TTL_DEFAULT_SECS | `receiveTtlDefaultSecs` on route store; main threads config |
| 6 | Bless opacity | Service collapses `wallet_not_node_generated` → `authorization_rejected`; admin emits `approval_rejected` @ 401 |
| 7 | OpenAPI freeze | green (no yaml regen required) |

## Verify @ 79bcc1d356cf1a3af5ab8fba1a849be8ef258769

- root `tsc -b` 0; generic-node `tsc -b` 0
- node-core: ttl(3)+snapshot(6)+route(2)+destination(28); openapi-freeze(27)+api-validation(71)
- generic-node: admin-error-envelope(6), never-403(4), g4(18)
- contracts: supersession(2), admin census(11)
- Pre-existing fails (main): neutrality/scan-gate order/drain/sweep; schema-census; boundaries observation allowlist; some PG offline

## Files (16)

See PR diff. Key: supersession contract, snapshot-service/reader, operation-route-store+main TTL, destination bless collapse, admin-router conflict rename.
