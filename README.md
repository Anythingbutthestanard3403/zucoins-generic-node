# Zucoins generic node

A self-hosted SplitChain custody node. It holds the private key of every wallet in its pool
and performs exactly three money operations — `RECEIVE_EXTERNAL`, `MOVE_INTERNAL`,
`SEND_EXTERNAL` — and nothing else. Anything shaped like a business process belongs to the
implementer layered above it.

There is no sandbox mode. Every configured gateway is a live production gateway.

## Running one

**Start here: [`docs/operations/README.md`](docs/operations/README.md).** It covers the two
process entries, required configuration, boot order, endpoints and the operator tooling — and
lists the procedures that are currently blocked, which you want to know before an incident
rather than during one.

| You are | Read |
| --- | --- |
| Deploying or starting a node | [`docs/operations/README.md`](docs/operations/README.md) |
| Rebuilding from a backup | [`docs/operations/restore.md`](docs/operations/restore.md) |
| Working an alert | [`docs/operations/incidents.md`](docs/operations/incidents.md) |
| Looking at a flagged operation | [`docs/operations/attention-triage.md`](docs/operations/attention-triage.md) |
| Stamping wallets as recovery-verified | [`docs/operations/recovery-ceremony.md`](docs/operations/recovery-ceremony.md) |
| Wiring Prometheus | [`docs/operations/alerts/generic-node.rules.yml`](docs/operations/alerts/generic-node.rules.yml) |

## Developing

pnpm workspace, Node >= 22, pnpm 11.13.0 (`corepack enable`).

```bash
pnpm install
pnpm build                 # operator SPA (admin/dist/index.html) then tsc -b across the project-reference graph
pnpm lint                  # eslint .
pnpm test                  # root vitest across every projects entry
pnpm test:boundaries       # architecture gates only
```

`CLAUDE.md` is the working guide for this repository: commands, layout, the architectural
invariants the test suite enforces, and the conventions a change is expected to match.

## Layout

| Path | Role |
| --- | --- |
| `packages/generic-node-contracts` | Frozen contracts. Pure leaf — no I/O, no state, no dependencies on anything else here |
| `packages/node-core` | The product-neutral protocol, persistence and operation engine |
| `apps/generic-node` | Composition root: configuration, boot lane, migrations, HTTP mount, workers, DR |
| `apps/generic-node/admin` | React/Vite operator SPA, served by the node itself |
| `packages/generic-node-consumer`, `packages/consumer-example` | Downstream consumption surface and a worked example |

Dependency direction is strictly `contracts → node-core → generic-node`, enforced by
`packages/node-core/test/boundaries.test.ts`.
