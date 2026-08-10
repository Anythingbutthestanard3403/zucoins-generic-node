# ZTR-1199 — BlessBody / RetireBody boundary schemas

## Summary
Declared Zod `bodySchema` for admin destination bless and retire, tightened bless field
shapes to match suite encoders / padded Ed25519 signature, and replaced the hand
`parseBlessBody` with `BlessBody.safeParse` so shape errors answer `400 invalid_scalar` /
`400 unknown_field` at the admin boundary.

## Acceptance
1. **bodySchema declared** — `BlessBody` + `RetireBody` on ROUTE_SCHEMAS rows; OpenAPI
   `BODY_BY_ROUTE` + regenerated `api/openapi.yaml` request bodies.
2. **Shape validation** — `nonce`/`device_key_id` via `UuidSchema`; `issued_at`/`expires_at`
   via `Rfc3339MsSchema` (pattern + calendar round-trip, same as `encodeCanonicalTimestamp`);
   `device_signature` via `Ed25519SignatureSchema` (padded base64url 88). No ceremony-window
   ceiling in Zod.
3. **Unknown fields rejected** — both bodies `.strict()`; parser maps `unrecognized_keys` →
   `unknown_field`.
4. **Tests non-vacuous** — `api-validation.test.ts` accepts valid bless, rejects bad UUID /
   ms-less timestamp / calendar-invalid month / bad sig / missing field / unknown keys;
   retire empty OK + unknown key rejected; ROUTE_SCHEMAS identity assertions.
5. **Gates** — see PR body.

## Governing
- Ticket ZTR-1199 (audit 2026-08-06 §6 / §8 correction)
- Sibling body pattern: `packages/node-core/src/api/route-schemas.ts` ApproveBody / pipeline
  unknown_field mapping
- Encoder agreement: `encodeUuid`, `encodeCanonicalTimestamp`, `isPaddedSignature` /
  `Ed25519SignatureSchema`

## Files
| File | Why |
|---|---|
| `packages/node-core/src/api/route-schemas.ts` | BlessBody, RetireBody, ROUTE_SCHEMAS wiring |
| `packages/node-core/src/api/scalars.ts` | Rfc3339MsSchema calendar round-trip refine |
| `packages/node-core/src/api/index.ts` | export BlessBody, RetireBody |
| `packages/node-core/src/api/openapi/request-bodies.ts` | BLESS_BODY, RETIRE_BODY inventories |
| `packages/node-core/api/openapi.yaml` | freeze regen (requestBody on bless/retire) |
| `packages/node-core/test/api-validation.test.ts` | non-vacuous schema tests |
| `apps/generic-node/src/admin-router.ts` | parseBlessBody → BlessBody.safeParse |

## Deferred
- `as never` on branded Uuid args into `destinationService.bless` remain (Zod yields plain
  string; service wants `Uuid` brand) — same pattern as approve path.
- `parseRetireBody` hand parser left as-is (already correct); only declaration added.
- Ceremony-window / never-403 reconciliation remains a separate ticket.

## Evidence (at push SHA)
See PR body for command summaries.
