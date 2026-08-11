# ZTR-1207 — Push action suffix rotation policy (implementer)

## Decision

**Runbook-only** recovery (sweeper default, 2026-08-11). No client-side suffix derivation.
No invented host discovery endpoint.

## Acceptance criteria

1. Operator runbook: probe-failure signature, four literal locations, manual transcription recovery — **yes** (`docs/operations/push-action-suffix-rotation.md`)
2. No suffix-derivation helper — **yes** (docs only; no code)
3. Option A discovery documented as future IF host offers — **yes** (runbook § Future)
4. Opaque host error `code` tokens; classification stays message-primary — **yes** (runbook § Classification note)
5. Link from ops README — **yes** (documents table + dedicated section)

## Governing material

- Ticket ZTR-1207 + sweeper AC comment
- ZTR-1152 implementation (transcribed literals + boot probe) in:
  - `packages/node-core/src/gateway/actions.ts`
  - `apps/generic-node/src/push/gateway-actions.ts`
  - `apps/generic-node/src/main.ts` (probe call site)
- Ops index: `docs/operations/README.md`

## Files

| Path | Why |
| --- | --- |
| `docs/operations/push-action-suffix-rotation.md` | Runbook |
| `docs/operations/README.md` | Documents table row + short section link |
| `tasks/ztr-1207-implementer.md` | This handoff |

## Verification (head commit)

| Command | Result |
| --- | --- |
| `CI=true pnpm install` | ok |
| `tsc -b` | No errors |
| `pnpm exec vitest run test/operator-docs.census.test.ts` (apps/generic-node, with `TEST_DATABASE_URL`) | 1 file / **35 passed** |
| `pnpm exec eslint src test` (apps/generic-node) | clean (exit 0) |

Money-path code: unchanged.
