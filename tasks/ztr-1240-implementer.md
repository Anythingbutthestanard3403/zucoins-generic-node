# ZTR-1240 — implementer

## Delivered
- `packages/node-core/src/implementer/integration-requests.ts` — list/approve/decline store (SQL + in-memory); CAS + audit
- Admin routes: `GET /admin/v1/integration-requests`, `POST …/:id/approve`, `POST …/:id/decline` (TOTP + idempotency)
- Approve TX: create implementer → merge rule into auto-approve policy → CAS PENDING→APPROVED (shared atomic ports)
- Decline: CAS PENDING→DECLINED + audit only
- SPA Approve inbox: pending integration cards, edit caps, TOTP approve/decline
- Operator push attention type `integration_request_pending` (emit optional; inbox poll is SoT)
- Census: `LIVE_INTEGRATION_REQUEST_ROUTES`

## Tests
- `integration-requests.test.ts` (unit store)
- `admin-integration-requests.test.ts` (list/approve/decline/TOTP/idempotency/CAS/policy-invalid)
- SPA ApproveInboxPage + route-policies-mount census
- boundaries 73/73; builds green

## Dual review
Money-path (creates identities + policy) — strict dual later per ticket note.
