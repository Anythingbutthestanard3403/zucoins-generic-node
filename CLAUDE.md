# CLAUDE.md — working guide

pnpm workspace, Node >= 22. Commands: `pnpm install`, `pnpm build`, `pnpm lint`, `pnpm test`,
`pnpm test:boundaries`. Layout: `packages/generic-node-contracts` (frozen leaf) →
`packages/node-core` → `apps/generic-node` (+ `admin/` operator SPA).

## Drift-gate forbidden vocabulary

The scanner lives at `packages/generic-node-contracts/src/scan/forbidden-terms.ts`.
`FORBIDDEN_TERMS` is the authority; the prose count is descriptive only and must match
`FORBIDDEN_TERMS.length` (sixteen today):

`payment`, `refund`, `sweep`, `treasury`, `checkout`, `payout`, `withdrawal`, `order`,
`merchant`, `reservation`, `outbound`, `drain`, `ZUC`, `finalised`, `fulfilled`,
`treasury settlement`.

`SCAN_SCOPE` covers contracts, node-core, generic-node app sources, and
`apps/generic-node/admin/src` (`.ts` / `.tsx` / `.md`).

## Module graph

`packages/node-core/test/boundaries.test.ts` `ALLOWED_INTERNAL_IMPORTS` is the architecture
spec for cross-module relative imports. Dead edges are not pre-granted. The graph is
acyclic except for the explicit `data ↔ schema` cycle recorded as
`ACCEPTED_INTERNAL_CYCLES` in that file.

## Schema contracts

DDL slices are normally a `NNNN_description.sql` + matching `*.contract.ts` pair. A
`.contract.ts` may stand alone when it is a cross-cutting / multi-table manifest. Named
exceptions: `registry-group.contract.ts`, `sealed-store-exclusions.contract.ts`,
`sealed-store-registry.contract.ts` (see `packages/node-core/src/schema/CONVENTIONS.md` §3.1).
