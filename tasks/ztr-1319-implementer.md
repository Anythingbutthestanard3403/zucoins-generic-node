# ZTR-1319 — implementer

**Linear:** https://linear.app/zutopia/issue/ZTR-1319
**Branch:** `ztr-1319-verification-mode-docs`
**Base:** `origin/main` `e1d457cd327298e205f492bd7cab5359ec80252b` (rebased after #170 landed on the original canon `f858ca8f9`)
**Claim run:** `d86f515b-71e3-4f4f-8947-ee4ae3f76cf8`
**Lane:** `/Volumes/Ai Building/.zup-scratch/impl-ztr-1319-d86f515b`

## Ticket
Consumer SDK types `verification_mode` non-optional on discovery / implementer-identity documents and `parseVerificationMode(undefined)` silently returns `INDEPENDENT`. The node never sent the field: `NodeIdentityDocumentSchema` is `.strict()` without it, and `GET /v1/implementer/identity` returned five keys. The SDK therefore asserted a default the node never stated.

Preferred fix: the node emits `verification_mode` truthfully on both documents; the SDK keeps parsing the closed vocabulary; omit on those documents fails closed.

Do **not** reopen ZTR-1313 packaging. After #165, `@zucoins/generic-node-consumer` is `private: false`; contracts / node-core remain unpublished `private: true` / `workspace:*` by design.

## Design
- Discovery field list grows from 9 → 10: append `verification_mode` after the ZTR-1288 funding pin.
- `buildNodeIdentityDocument` always writes `verification_mode` (`config.verificationMode ?? DEFAULT_VERIFICATION_MODE`, currently `INDEPENDENT`).
- Implementer-identity 200 body adds the same field. This is the node's default create-time mode, not a per-implementer override (policy still gates `NODE_VERIFIED` at admission).
- Consumer parsers require the field. Omit / null → `IdentityDocumentError`; unknown token still `VerificationModeDriftError`. `parseVerificationMode(undefined)` remains INDEPENDENT for create-body omit only.
- OpenAPI: `DiscoveryResponse.required` includes `verification_mode`; new `ImplementerIdentityResponse` replaces the identity 200 `additionalProperties: true` blob.
- `API_SCHEMA_VERSION` 3 → 4; golden `api-schema.json` + digest + drift-manifest note updated.

## Acceptance

| Criterion | Status |
|-----------|--------|
| Node emits `verification_mode` on `GET /.well-known/zupay-node` | Yes — always present, currently `INDEPENDENT` |
| Node emits `verification_mode` on `GET /v1/implementer/identity` | Yes |
| SDK does not invent INDEPENDENT when the node omitted the field | Yes — fail-closed on omit/null |
| Unknown token still fails closed | Yes |
| Tests fail if emission or fail-closed parse breaks | Yes |
| Contracts packaging not reopened | Yes — still `private: true` |
| No ZTR-1317 / 1318 / 1274 files | Yes |
| Drift-gate forbidden terms | Yes |

## Files
- `packages/generic-node-contracts/src/api-schema/discovery.ts` — 10th field
- `packages/generic-node-contracts/src/api-schema/{version,manifest,gen/api-schema}.ts|json` + census + drift notes
- `packages/node-core/src/api/discovery.ts` — schema + builder
- `packages/node-core/src/api/implementer-identity-router.ts` — sixth body key
- `packages/node-core/src/api/openapi/generate.ts` + `api/openapi.yaml`
- `packages/generic-node-consumer/src/http/discovery.ts` — required parse
- Tests: consumer discovery, node-core discovery / identity / deployment-health, generic-node discovery-document
- `docs/operations/verification-modes.md` — discovery/identity surface row

## Verification

```
pnpm install                                 # lockfile up to date
pnpm exec tsc -b                             # exit 0 (also after rebase onto e1d457cd)
pnpm --filter @zucoins/generic-node-contracts test
# Test Files 228 passed | Tests 2773 passed
UPDATE_OPENAPI=1 pnpm --filter @zucoins/node-core exec vitest run \
  test/openapi-freeze.test.ts test/discovery.test.ts \
  src/api/implementer-identity-router.test.ts test/deployment-health.test.ts
# Test Files 4 passed | Tests 70 passed
pnpm --filter @zucoins/generic-node-consumer test
# Test Files 18 passed | Tests 109 passed
pnpm --filter @zucoins/generic-node-consumer lint
# eslint src --max-warnings 0
pnpm --filter @zucoins/generic-node exec vitest run test/discovery-document.test.ts
# Test Files 1 passed | Tests 8 passed
```

Full `apps/generic-node` filter run also executed discovery-document (8 passed) inside the package suite; that invocation later hit an unrelated vitest-worker `onTaskUpdate` timeout after 1322 passing tests — not this change.

## Not in this PR
- Publishing `@zucoins/generic-node-contracts` (still private after #165; out of scope).
- Per-implementer advertised mode (policy still admission-only).
- Changing create-body omit → INDEPENDENT (that default is stated by the node).
