# route-policy — CONTRACT

Freeze slice: **align middleware and route mappings** (depends on the auth-errors freeze).
Gate: `CONTRACT_FREEZE`.

## Scope boundary (read first)

"Centralize authentication, authorization, error envelope, status, request id, audit policy, and
idempotency behaviour across every route" reads as runtime middleware. This slice is under
`CONTRACT_FREEZE`, so it has **no production implementation authority**. It therefore freezes the
**contract** those centralized middlewares must satisfy — the route→policy catalog, the auth-class
failure mapping, and the pipeline stage sequence — and builds no runtime middleware. Wiring the
actual middleware onto a running server is a later (post-freeze) implementation slice.

Governing sources: the API contract's wire/idempotency conventions, auth classes, route
definitions, and retired paths. Decision: `non-oracular-auth-errors`. **On any conflict with the
auth-errors freeze, auth-errors wins** — its canonical codes and `AUTH_CHECK_ORDER` are
imported here, never redefined, and `manifest.freeze.test.ts` asserts the pipeline's auth stages
equal `AUTH_CHECK_ORDER` in sequence.

## What is frozen

- **`auth-classes.ts` — `AUTH_CLASS_POLICY`.** The five auth classes and their non-oracular
  failure posture. The three implementer-facing classes (`IMPLEMENTER_BEARER`,
  `REPORTING_CREDENTIAL`, `SUBSCRIPTION_HANDLE`) are the multi-tenant surface where credentials
  are probed; their full collapse is frozen — credential/scope failure → `invalid_api_key` (401),
  cross-tenant/absent object → `not_found` (404), never 403. `OPERATOR_SESSION` freezes
  authFailureStatus=401 (never 403 for auth denial) plus `nonAuthorizationStatuses` for closed
  non-auth gates; its specific admin-auth code taxonomy is deferred to the
  operation-schemas concern. `PUBLIC` never authenticates.
- **`routes.ts` — `ROUTE_POLICIES`.** Every launch route with its auth class, scope,
  tenant-scoping, and idempotency requirement. `FORBIDDEN_ROUTE_PREFIXES` records the retired
  paths as data; `DEFERRED_UNFROZEN_ROUTES` records that the exact proof-body intake route remains
  unauthorized until a later slice freezes its method, path, authentication, body, and idempotency
  contract.
- **`pipeline.ts` — `REQUEST_PIPELINE`.** The centralized stage sequence every route inherits:
  request-id → authenticate → authorize scope → idempotency → object+tenant resolution → handler
  → audit → error-envelope emission. `PIPELINE_INVARIANTS` records the cross-cutting guarantees.
- **`verifier.ts`.** Pure verifiers the credential-matrix concern consumes:
  `isAuthClassNonOracular`, `isRoutePolicyNonOracular`, `isForbiddenRoute`, `firstOracularRoute`.

## Non-oracular invariant

Every route inherits the same centralized pipeline, so no route can define a bespoke auth error.
Because scope authorization runs before object resolution (stage 3 before stage 5, matching
the auth-errors concern's `AUTH_CHECK_ORDER`), an unauthorized caller never reaches an object
lookup and cannot probe existence. Scope denial is the generic 401, never 403
(`non-oracular-auth-errors`). Cross-tenant object access collapses to the same `not_found` as an
absent object. **Fail-closed rule:** a tenant-scoped route — the multi-implementer probing
surface — must resolve through a class whose full non-oracular collapse is *frozen*;
`isRoutePolicyNonOracular` rejects a tenant-scoped route backed by a `nonOracularFrozen:false`
class rather than free-passing it (its credential/tenant codes are deferred and cannot be asserted
non-oracular). Non-tenant-scoped admin/public routes legitimately ride the partial freeze
(auth denial never 403; see judgment call J2 for the nonAuthorizationStatuses carve-out). The freeze test proves the census (no route is oracular or
forbidden) and the mandatory negatives (a 403 auth class, a per-class bespoke credential code, a
retired forbidden route, and a tenant-scoped route on an unfrozen class are each rejected).

## Deferred (owned elsewhere)

- Idempotency-Key mechanism (length, storage, replay body, `idempotency_conflict`) → the
  idempotency runtime slice; this concern freezes only the per-route "required?" flag and the
  pipeline stage position.
- Audit-record shape and storage → the audit-record slice; this concern freezes only that audit is
  server-side and never leaks into a response (so it is not an oracle).
- Wider error taxonomy (400/409/410/422/429/503 codes, the full 404 sub-taxonomy, the
  `OPERATOR_SESSION` admin-auth codes) → the operation-schemas concern.
- The runtime middleware implementation and the exact `/admin/v1` step-up (CSRF/TOTP/device)
  enforcement → post-freeze implementation slices; the API contract names the requirements, and
  they are not frozen here.
- Package index/registry (`src/index.ts`, `src/registry.ts`) → the package registry slice.

## Judgment calls

- **J1 — single credential code across classes.** Every frozen class maps its credential failure
  to the one auth-errors `invalid_api_key`, not to v1-style per-class codes
  (`invalid_reporting_key`, `invalid_credentials`). This stays consistent with the auth-errors
  freeze (which wins on conflict) and avoids minting taxonomy the operation-schemas concern owns.
  Per-class 401 code names, if wanted, are an additive refinement there — the verifier
  deliberately rejects a per-class code swap today (negative test) to keep the collapse
  single-code until then.
- **J2 — `OPERATOR_SESSION` partial freeze.** Auth/scope denial freezes to status 401 (never 403
  as `authFailureStatus`). A closed non-authorization carve-out lives in
  `nonAuthorizationStatuses: [403]` for CSRF origin policy and first-login password-change posture
  only — authorization/factor failures (approve, bless, device enrol/revoke) collapse to 401
  (ZTR-1191). Wider admin-auth codes remain deferred. The admin surface is a different threat
  model (operator login) than the implementer credential-probing this concern targets.
- **J3 — `tenantScoped` = the cross-implementer boundary.** Implementer/reporting/handle routes
  are tenant-scoped (multi-implementer node); admin/public are not (the operator sees the whole
  node). A missing object on any route still 404s; only the tenant-collapse dimension differs.

## Evolving a frozen fact

Edit the fact, then regenerate `gen/route-policy.json` (`buildRoutePolicyManifest`) in the same
commit. The paired diff is the review acknowledgement the freeze test enforces.
