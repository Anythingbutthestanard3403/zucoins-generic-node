# ZTR-1236 — Multi-implementer registry (implementer lane)

## Summary

Named integration identities (`implementers`) can be created/listed/retired via admin
routes; API key issuance accepts optional `implementer_id` (default = genesis). SPA Keys
page gains an integration picker; new Integrations page for create/retire/list. Audit
actions `implementer.created` / `implementer.retired`. Retirement is an issuance gate —
existing credentials keep authenticating.

## Files

### node-core
- `src/implementer/*` — registry port + SQL + in-memory adapters
- `src/credential/*` — `listAll` / `findByCredentialId` for multi-implementer admin
- `src/api/production-route-census.ts` — `LIVE_IMPLEMENTER_ROUTES`
- `test/boundaries.test.ts` — `implementer` module edge

### generic-node
- `src/admin-router.ts` — GET/POST implementers, retire; api-keys implementer_id
- `src/full-http-mount.ts` — wire registry + TX ports + genesis resolve fallback
- `test/admin-implementers.test.ts` — TOTP/idempotency/audit/retire/binding ACs
- admin SPA: Keys picker, Integrations page, nav, census fixtures

## Verify (head SHA after commit)

- `pnpm --filter @zucoins/node-core build` green
- `pnpm --filter @zucoins/generic-node build` green
- admin-implementers + admin-api-keys + route-policies-mount: 64/64
- generic-node-ui full: 310/310
- node-core boundaries: 73/73
- lint node-core / generic-node / generic-node-ui: 0 errors
- `pnpm test:boundaries` scan-gate has pre-existing `drain` hits on main (unrelated)

## Acceptance

- [x] create/list/retire + TOTP gating + idempotency replay
- [x] second implementer key → validate() returns that implementer_id (tenant binding)
- [x] retired issuance refused; existing keys auth
- [x] api-keys without implementer_id = genesis
- [x] audit created/retired
- [x] SPA + census
