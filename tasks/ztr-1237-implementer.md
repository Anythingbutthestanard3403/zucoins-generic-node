# ZTR-1237 implementer

## Delivered
- `GET/POST /admin/v1/auto-approve-policy` on admin router (session GET; TOTP+idempotency POST via `runRequiredAdminMutation`)
- TX-scoped `autoApprovePolicy` port on atomic admin mutation (settings+audit+idempotency one TX)
- Window-spend enrichment via `queryWindowSpend` / `WINDOW_SPEND_SQL`
- Fail-closed GET when port absent/unreadable; invalid POST body → 422, nothing stored
- App census: `LIVE_AUTO_APPROVE_POLICY_ROUTES` (out of frozen ROUTE_POLICIES)
- SPA page `admin/src/pages/auto-approve/` + nav `/auto-approve` + TOTP-gated save
- Parser retains rules when `disabledReason: "off"` for operator edit

## Tests
- `admin-auto-approve-policy.test.ts` — GET/POST/422/TOTP/idempotent replay
- `atomic-admin-mutation.pg.test.ts` — setPolicy rollback drill
- SPA page + a11y-axe + App nav census + route-policies-mount
- unit: `auto-approve-policy.test.ts` still green (off retains rules)

## Notes
- Money-path dual review deferred to later lane (ticket: dual later)
- Forbidden-vocab clean on new surfaces; pre-existing `drain` hits in shutdown-registry are out of scope
