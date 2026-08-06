# auth-errors — CONTRACT

Freeze slice: **non-oracular auth errors**. Gate: `CONTRACT_FREEZE` — this directory freezes a
contract and its documentation only; it contains no runtime auth implementation. Middleware and
route wiring live in the route-policy concern; the full credential/error matrix test lives in
the credential-matrix concern; the wider error surface is outside this package.

Governing spec: the API contract — error envelope and authentication classes. Canonical
authority: the `non-oracular-auth-errors` decision, which overrides the descriptive text on
conflict.

## The resolution (403 rejected, generic 401 canon)

The earlier status table carried the row:

> `403 | Authenticated principal lacks scope.`

**`non-oracular-auth-errors` resolves this against a generic 401.** An authenticated key
presented outside its scope returns the *same* `401 invalid_api_key` body as an unknown key,
deliberately, so there is no "valid key, wrong scope" oracle. This slice freezes that resolution:

- There is **no `403`/`forbidden` code** in the auth-error contract. The rejected codes are
  recorded as data in `REJECTED_AUTH_ERROR_CODES` (`codes.ts`) so a future edit cannot silently
  reintroduce the oracle; the census test asserts none of them appears in `AUTH_ERROR_CODES`.
- The **canonical credential-failure response** is `invalid_api_key` / HTTP 401, one frozen
  byte-exact body for every credential failure: missing, malformed, unknown, expired, revoked,
  and valid-but-out-of-scope (`AUTH_FAILURE_STATE_TO_CODE`, `classes.ts`).
- The **cross-tenant / absent collapse** is `not_found` / HTTP 404 (the API contract: "Object is
  absent or outside the authenticated tenant"). A cross-tenant object read is byte-identical to a
  genuinely-absent one, so it is not an existence oracle across tenants.

## Frozen facts

| Fact | Value | Source |
|---|---|---|
| Credential-failure code | `invalid_api_key` (401) | API contract: error envelope; non-oracular-auth-errors |
| Resolution-failure code | `not_found` (404) | API contract: error envelope |
| Rejected codes | `forbidden`/403, `insufficient_scope`/403, `wrong_tenant`/404 | non-oracular-auth-errors |
| Envelope field sequence | `code, message, request_id, details` | API contract: error envelope (byte sequence, the byte-exact signing rule) |
| `details` for auth errors | always `{}` (never scope/tenant/existence) | API contract: error envelope |
| Auth-error response headers | `content-type: application/json; charset=utf-8`; **no `WWW-Authenticate`**, identical for 401 and 404 | API contract: wire conventions; J3; non-oracular-auth-errors |
| Frozen 401 body sha256 | `44fa5568…961e7e` (130 bytes) | tier-3 pin |
| Frozen 404 body sha256 | `949585…64d147` (118 bytes) | tier-3 pin |

## Check sequencing (why the mapping is non-oracular)

`AUTH_CHECK_ORDER` (`classes.ts`) freezes the gate sequence:

1. **authenticate credential** → fail `invalid_api_key` (401);
2. **authorize scope** → fail `invalid_api_key` (401), *not* 403 (`non-oracular-auth-errors`);
3. **resolve object with a tenant predicate baked into the lookup** → fail `not_found` (404).

Scope authorization (2) precedes any object lookup (3), so an out-of-scope caller never
reaches the object store and learns nothing about whether a resource exists. The tenant
predicate is part of the lookup, so a cross-tenant object is indistinguishable from an absent
one. The API contract's "verifies tenant scope before object lookup" is this sequencing.

## Non-oracularity predicate

`non-oracular.ts` is the pure verifier the credential-matrix concern consumes: two responses are `indistinguishable`
when, after `normalizeRequestId` neutralizes the only legitimately-varying field, they have the
identical HTTP status, the identical client-visible header set (`canonicalizeHeaders`, fail-closed),
and byte-identical body. The header dimension closes the RFC 6750 channel: two 401s differing only
in `WWW-Authenticate: error="invalid_token"` vs `error="insufficient_scope"` are now caught, where a
status+body-only comparison was blind to them. `firstOracleDivergence` / `isNonOracular` scan a
collapse-class group. The freeze test proves the positive control (valid-key-wrong-scope ≡
unknown-key), the mandatory negatives (a 403 scope oracle and a scope-leaking message are both
rejected), and the header breaking input (the `WWW-Authenticate`-only-differing 401 pair is rejected).

## Judgment calls

- **J1 — `not_found` naming.** The API contract describes the 404 semantics but names no code
  literal; the code `not_found` is taken from the canonical `ERROR_CODES` set rather than invented.
  The full 404 sub-taxonomy (`wallet_not_found`, `session_not_found`, …) is outside this concern.
- **J2 — frozen message strings.** The API contract calls `message` "diagnostic, not stable". For
  the two non-oracular codes that latitude is deliberately narrowed to a constant per code, because
  a per-subcase message is itself the oracle. The latitude still applies to the non-collapse
  codes (400/409/422/…) outside this concern. The exact strings ("Invalid API key." / "Not found.") are
  the frozen canonical values; changing one is a paired golden-body regeneration.
- **J3 — `missing`/`malformed` folded into the 401 class; header channel frozen.** A truly missing
  credential could be distinguished without creating a *key-existence* oracle, but folding it into
  the single generic 401 is simpler and strictly stronger; **no `WWW-Authenticate` challenge is
  emitted.** This is no longer prose-only: the response header set is frozen as data in
  `CANONICAL_AUTH_ERROR_HEADERS` (identical for the 401 and 404, carrying only the API contract's
  media type, never a Bearer challenge), and `non-oracular.ts` compares headers fail-closed — so a future edit
  that added an `error="…"` challenge (the RFC 6750 scope oracle) is caught by the freeze test.

## Evolving a frozen fact

Edit the fact, then in the SAME commit regenerate `gen/auth-errors.json`
(`buildAuthErrorsManifest`) and, if a body changed, its raw `gen/*.body.json` artifact and its
`digests.ts` pin. The paired diff is the review acknowledgement the freeze test enforces.
