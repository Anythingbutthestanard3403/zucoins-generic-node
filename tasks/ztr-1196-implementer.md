# ZTR-1196 — Admin error envelope (implementer)

**HEAD:** `5e79ad9c2525c81558fe89a6ed69392ccf0f2f95`  
**Branch:** `ztr-1196-admin-error-envelope`  
**Governing:** ticket body (audit §7.5 / `PIPELINE_INVARIANTS`); `packages/generic-node-contracts/src/route-policy/auth-classes.ts` J2 (OPERATOR_SESSION taxonomy deferred → now `admin-auth-errors`); public envelope shape from `packages/node-core/src/api/error-envelope.ts` (shape only — `API_ERROR_CODES` **not** widened).

## Acceptance

| Criterion | Status |
|---|---|
| Every admin-emittable code in frozen contract data | Yes — `ADMIN_ERROR_CODES` |
| Every admin non-2xx carries `details` and parses strict envelope (or lab sibling) | Yes — `fail()` / `fromAuthResult` / lab-receive path |
| Census test fails on new unfrozen `fail("…")` literal | Yes — `codes.census.test.ts` |
| `API_ERROR_CODES` + 401/404 SHA-256 pins unchanged | Yes — no touch to `error-envelope.ts` |
| `checklist_links` / `operation_id` named sibling schema | Yes — `AdminLabReceiveErrorEnvelopeSchema` |
| Public receiver channels untouched | Yes |
| `emit-json` / gen drift updated | Yes — `gen/contract-drift-manifest.json` |
| Forbidden-terms | No new markers; renamed test string that hit `order` stem |
| Gates green | Yes (see evidence) |

## What changed

1. **New concern** `@zucoins/generic-node-contracts/admin-auth-errors`  
   - `ADMIN_ERROR_CODES` (~105 codes): shared `/v1` overlaps + session/auth + admin domain + device lowercased rejection codes + vault master + lab-receive.  
   - `AdminErrorEnvelopeSchema` (strict, `details` default `{}`).  
   - `AdminLabReceiveErrorEnvelopeSchema` sibling for checklist extension.  
   - `buildAdminErrorBody` / `buildAdminLabReceiveErrorBody` / `coerceAdminErrorCode` (unknown → `internal_error`).  
   - Wired into `registry.ts`, drift-audit `CONCERN_MODULES`, package export, vitest aliases, app boundaries allowlist.

2. **`apps/generic-node/src/admin-router.ts`**  
   - `fail()` → `buildAdminErrorBody(coerceAdminErrorCode(code), …)`.  
   - `fromAuthResult` re-renders non-2xx auth handler bodies through `fail()` so login/me/logout errors also get `request_id` + `details`.  
   - Lab-receive extended errors use `buildAdminLabReceiveErrorBody`.

3. **SPA** `ApiErrorBody` accepts optional `details` (forward-compat; still reads `code`/`message`/`request_id`).

4. **Tests**  
   - `admin-auth-errors/codes.census.test.ts` (schema + fail-literal census).  
   - `apps/generic-node/test/admin-error-envelope.test.ts` (live router 401/404/validation/me).

## Evidence (at `5e79ad9`)

```
npx tsc -b                                          # exit 0
pnpm --filter @zucoins/generic-node-contracts test  # 225 files / 2732 tests pass
pnpm --filter @zucoins/generic-node exec vitest run test/admin-
                                                    # 15 files / 140 tests pass
pnpm --filter @zucoins/generic-node exec vitest run test/admin-error-envelope.test.ts
                                                    # 4/4 pass
pnpm --filter @zucoins/generic-node-ui exec vitest run src/lib/api.test.ts
                                                    # 13/13 pass
pnpm --filter @zucoins/node-core exec vitest run test/boundaries.test.ts
                                                    # 71/71 pass
pnpm --filter @zucoins/generic-node-contracts lint  # clean
pnpm --filter @zucoins/generic-node lint            # clean
```

## Deferred / notes

- HTTP status is still chosen by each handler; freeze is code membership, not a full (code,status) matrix.  
- Unknown codes coerce to `internal_error` (fail-closed) rather than throwing — census prevents new *literals*; dynamic device codes are pre-enumerated lowercased.  
- 403 admin codes (`origin_forbidden`, `password_change_required`, `approval_rejected`) frozen as currently served; never-403 reconciliation ticket may remint statuses later without widening `API_ERROR_CODES`.  
- Public `/v1` and receiver channels unchanged.
