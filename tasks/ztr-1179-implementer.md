# ZTR-1179 — Include event-signer loss in /health/ready

Implementer evidence. Branch `ztr-1179-ready-event-signer-loss`, based on `origin/main` @ `3762c0c`.

## Defect

Runtime `EVENT_SIGNING` loss quiesced the money surface but `/health/ready`
(`apps/generic-node/src/health/routes.ts:77`) and money admission
(`apps/generic-node/src/main.ts` `snapshotReadiness`) both read
`readiness.core.snapshot()` — node-core's `NodeCoreReadinessState` — while the
`eventSigner` conjunct lived only in the shell wrapper (`boot/readiness.ts`
private field). Two readiness answers in one process; the quiesced node kept
answering 200.

## Fix (ticket Option 1)

Add the conjunct to node-core so both consumers see it for free.

Design decision: `eventSignerAvailable` is a **verdict-forcing input**, following
the existing `stopping` precedent — it forces `ready: false` in
`evaluateReadinessFromProbes` without joining the frozen reported check set.
`readiness-checks.contract.ts` freezes the check census in the contracts package
(frozen artifact, no additions), and `stopping` already established that a
gating input need not be a reported check. node-core does not cross-validate its
check-ID arrays against the contract, so no contract change was needed.

Default semantics: node-core defaults the conjunct **open** (`true`) — a
deployment with no EVENT_SIGNING authority (createNodeCore consumers, stage1,
chaos harness) is vacuously open. The custody shell (`NodeReadiness`
constructor) stamps `false` at construction, so boot stays fail-closed and
`arm` remains the only opener — the existing "arming is the only thing that
opens the readiness conjunct" test still passes unchanged in meaning.

Overlap-deploy deadlock argument carried across from the shell comment (not
re-derived, per ticket): safe to gate because the EVENT_SIGNING ensure always
runs after leadership is already held, so this cannot reproduce the deadlock
class that keeps `signer_leadership` non-gating.

## Files touched

| File | Why |
|---|---|
| `packages/node-core/src/core/readiness-state.ts` | `eventSignerAvailable` on `ReadinessStateInputs` + private field (default `true`) + `setEventSignerAvailable` + snapshot inclusion; header check list gained `event_signer_available → EVENT_SIGNING_AUTHORITY (setEventSignerAvailable)` (the list is the spec). |
| `packages/node-core/src/api/health.ts` | `gatesPass` now conjoins `state.eventSignerAvailable` (verdict-forcing, like `stopping`); header documents the two verdict-forcing inputs outside the closed check set. |
| `packages/node-core/src/core/money-admission.ts` | New refusal code `event_signer_unavailable`; conjunct added to `isGatingReadyForMoney` and `moneyAdmissionRefusal`. |
| `apps/generic-node/src/boot/readiness.ts` | Private `eventSignerAvailable` field **deleted**; pure forwarder to `inner.setEventSignerAvailable`; constructor stamps `false` (shell installs an authority, so the conjunct starts closed); snapshot reads `inputs.eventSignerAvailable`. |
| `apps/generic-node/src/boot/event-signer-authority.ts` | The stale "scope of readiness" comment (former :20-24, which documented the gap) replaced with the new one-conjunct/three-consumer behaviour; two other shell-local references cleaned up. |
| `packages/node-core/test/health-probes.test.ts` | New describe: evaluator forces not-ready on `eventSignerAvailable: false` with empty `failing` and no such check name (census untouched); default-open + stamp round-trip. Base literal gained the field. |
| `apps/generic-node/test/health-routes.test.ts` | New describe: real authority arm → 200, runtime sign failure → withdrawal → 503 `not_ready`; boot-unarmed signer keeps 503 with every other gate open. `fullyReadyStamps()` gained the signer stamp (red on origin/main — this churn is the fix working). |
| `apps/generic-node/test/event-signer-authority.test.ts` | New describe: money admission throws `MoneyAdmissionRefusedError` code `event_signer_unavailable` and `evaluateReadinessFromProbes` goes `not_ready`, both on `readiness.core.snapshot()` after `withdraw`. |
| `apps/generic-node/test/metrics-snapshot-source.test.ts`, `apps/generic-node/test/metrics-postgres-deadline.pg.test.ts` | Base `ReadinessStateInputs` literals gained `eventSignerAvailable: true` (compile requirement from the new interface field). |
| `apps/generic-node/test/storage-pressure.test.ts`, `apps/generic-node/test/health-route-order.test.ts` | Their `fullyReady()` helpers gained the signer stamp — red at the full-suite run because the shell constructor now starts the conjunct closed (fix working, same class as health-routes). |

12 files, +176/−17. No `main.ts` change needed — admission already reads
`readiness.core.snapshot()`. `stage1-main.ts` has its own inline health handler,
unaffected. No new node-core cross-module import, so `ALLOWED_INTERNAL_IMPORTS`
is untouched.

## Acceptance criteria

- [x] `ReadinessStateInputs` carries the event-signer conjunct; `readiness-state.ts` header check list documents its stamping authority (`EVENT_SIGNING_AUTHORITY`).
- [x] `/health/ready` returns not-ready after runtime withdrawal — `health-routes.test.ts` "a runtime EVENT_SIGNING withdrawal flips /health/ready to 503".
- [x] Money admission refuses on the same transition — `event-signer-authority.test.ts` "money admission refuses with event_signer_unavailable after a runtime loss".
- [x] `boot/readiness.ts` holds no private `eventSignerAvailable` field — pure forwarder.
- [x] `event-signer-authority.ts:20-24` comment updated to describe the new behaviour.
- [x] Boot-time signer failure unchanged — existing boot-lane + installEventSigner tests pass unchanged (readiness stays closed, workers never start).
- [x] No new node-core cross-module import → no `ALLOWED_INTERNAL_IMPORTS` entry needed (verified: boundaries suite green).
- [x] `pnpm test` and `pnpm test:boundaries` green (evidence below).

## Verification (all at the pushed head)

- `pnpm install` — up to date.
- `pnpm build` (`tsc -b`) — exit 0, no output.
- `pnpm lint` — 0 errors, 6 warnings, all pre-existing in untouched files (`admin/public/sw.js`, live-chain killing test, `move-internal-create.pg.test.ts`, `push-subscription-gate.test.ts`).
- `pnpm test:boundaries` — 5 files, 162 passed.
- node-core targeted (`health-probes`, `deployment-health`, `metrics`, `metrics-route`, `degraded-mode.fault`) — 102 passed | 2 skipped.
- generic-node targeted (readiness, event-signer-authority, health-routes, boot-lane, graceful-stop, deployment-scenarios, reference-deployment, metrics-snapshot-source, metrics-routes, operator-halt, money-workers) — 200 passed.
- `PG_REQUIRED=1 TEST_DATABASE_URL=…/ztr1179_impl pnpm test` (full suite, final tree) — **773 passed | 3 failed | 3 skipped files; 11666 tests passed | 3 failed | 15 skipped | 5 todo**. The 3 failures (`receive-settle-step.pg.test.ts` beforeAll timeout, `send-completion-lander.pg.test.ts` permission-revocation drill, `chaos/overlap-crash-handoff.pg.test.ts` failover race) are all PG-load/timing suites far from this diff; standalone re-runs at the same tree: **20/20 passed** (the two generic-node files) and **29/29 passed** (chaos). Environment note: the local Postgres is shared with concurrent lanes, so full-suite attempts hit load artifacts, each proven environmental by a quiet standalone re-run:
  - attempt 1: SIGTERMed externally mid-run; one 30s timeout in `transaction-material-store.pg.test.ts` (file total 79.6s under parallel load) → standalone: **17/17 passed, 3.49s**.
  - attempt 2: 9 failed files | 767 passed | 11666 tests passed. 2 of the 9 were this diff's fail-closed constructor reaching `storage-pressure.test.ts` / `health-route-order.test.ts` helpers — fixed (signer stamp added), re-run **47/47 passed**. The other 7 were `FATAL: sorry, too many clients already` (connection exhaustion from concurrent lanes) → standalone re-run of all 7 files: **76/76 passed, 4.93s**.
