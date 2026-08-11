# ZTR-1167 implementer handoff

**PR:** (filled after open)  
**Head SHA:** `e7233ecc4330ebe28bd9b961688662be4e703978`  
**Branch:** `ztr-1167-contract-gate-doc-drift`

## Acceptance

| Item | Status |
| --- | --- |
| 1 — sixteen stems in CONTRACT.md + CLAUDE.md; count derived from `FORBIDDEN_TERMS.length` | satisfied |
| 2 — SCAN_SCOPE + `*.tsx` globs; zero admin unmarked hits; Login/nav/packs reworded | satisfied |
| 2 — FROZEN_EXEMPTION_COUNT=239, FROZEN_SUPPRESSED_VIOLATION_COUNT=220 | satisfied |
| 3 — six dead edges removed; boundaries green | satisfied |
| 4 — whole-graph acyclicity + `ACCEPTED_INTERNAL_CYCLES = data↔schema` | satisfied |
| 5 — standalone manifest exception in CLAUDE.md + CONVENTIONS.md §3.1 | satisfied |
| 6a — `request-pipeline-stage-order.test.ts` pins stage sequence | satisfied |
| 6b — stage 5 `deferredTo: "tenant-object-resolution-contract"` + golden | satisfied (contract amendment) |
| No test-written golden | satisfied (golden edited as contract amendment) |

## Governing

- Ticket body + sweeper locks 2026-08-11 (item 4 accept cycle; item 6b defer stage 5)
- `packages/generic-node-contracts/CONTRACT.md` drift-gate section
- `packages/node-core/test/boundaries.test.ts` architecture graph
- `packages/generic-node-contracts/src/route-policy/pipeline.ts` REQUEST_PIPELINE

## Evidence (at `e7233ecc4330ebe28bd9b961688662be4e703978`)

```
# pnpm install (CI=true) — ok
# npx tsc -b — exit 0
# packages/generic-node-contracts vitest (4 files): 52 passed
#   forbidden-terms, generic-core.scan-gate, coupling-exceptions.manifest, route-policy/manifest.freeze
# packages/node-core vitest: 75 passed (boundaries 72 + pipeline-order 3)
# apps/generic-node/admin vitest (7 files): 81 passed
# pnpm --filter @zucoins/generic-node-contracts lint — exit 0
# pnpm --filter @zucoins/node-core lint — 0 errors (5 pre-existing warnings)
# Root pnpm test:boundaries / full pnpm test need live Postgres globalSetup; package-local
# runs above cover the ticket gates. psql ETIMEDOUT on teardown is environment noise.
```

## Files

- Scan scope/globs/counts/manifest + CONTRACT.md + route-policy pipeline/golden
- Admin SPA rewords + selective `contract-allow` for negative-citation guards
- boundaries dead edges + acyclicity; pipeline order test; CONVENTIONS §3.1; CLAUDE.md restored

## Contract amendment (6b)

Stage 5 `resolve_object_with_tenant_predicate` is now `deferredTo: "tenant-object-resolution-contract"`
(same pattern as stages 4 and 7). Production compositions remain handler-level tenant
predicate; implementing inline stage 5 is out of scope.
