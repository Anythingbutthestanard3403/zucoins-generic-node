# ZTR-1239 — implementer

## Ticket
Route 2 public handshake: `POST /v1/integration-requests` + one-time key claim poll.

## PR
https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/104

## Claim
run=`e27b131d-1e96-4b8e-b68d-b2061964b3b8` → release QA-Review

## What landed
- `packages/node-core/src/integration-request/` — store + handlers + public router
  - Intake: validate display_name / scopes ⊆ {send:create,send:read} / proposed_rule (ZTR-1234 grammar, no implementer_id)
  - `irq_` claim token once; durable `claim_token_hash` only
  - Per-IP rate limit + global PENDING cap (100)
  - GET claim: uniform 404 oracle; lazy EXPIRE; APPROVED→CLAIMED + credential issue one TX; key once
- Frozen churn: PUBLIC_ROUTES, ROUTE_POLICIES, ROUTE_SCHEMAS, openapi.yaml, gen/routes.json, route-policy golden, censuses 19/27
- Mount: `runtime-listener` + `full-http-mount` / `main` wire `SqlIntegrationRequestStore`

## Tests
- Unit: intake, validation, rate limit, pending cap, one-time claim, 404 oracle, lazy expiry, proposed-rule
- Freeze: routes census, route-policy manifest, openapi, boundaries, pipeline scope, api-validation, mount census

## Out of scope
- Operator approve UI (ZTR-1240) — tests seed APPROVED
- Money-path dual later per dispatch note
