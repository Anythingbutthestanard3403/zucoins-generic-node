# ZTR-1187 — Wire safe-log redaction into the logger, and stop returning raw values past the depth limit

Lane: implementer · run `c843dfad-ef62-4a54-99bd-e5da534f9fdb`
Branch: `ztr-1187-safe-log-redaction` off `origin/main` @ `6c29b0a`
Lane clone: `/Volumes/Ai Building/.zup-scratch/ztr-1187`

## Spec

Linear ZTR-1187 (`python3 scripts/linear.py get ZTR-1187`) — the body carries the
file:line evidence and the acceptance criteria; it is the governing contract here.
Source audit: `tasks/audit-2026-08-06.md` section 4, "Redaction helpers dead".
Repo conventions applied: `CLAUDE.md` (ESM NodeNext, contracts→node-core→generic-node,
forbidden-terms drift gate, `ALLOWED_INTERNAL_IMPORTS`).

No decision record in `docs/decisions/INDEX.md` governs safe-log; the module's own header
(`safe-log.ts:1-3`, "adapters wrap pino/console via `redactLogFields`") is the standing
statement of intent, and this ticket is the missing adapter.

## Change by file

### `packages/node-core/src/observability/safe-log.ts` — the root fix

1. **Depth fail-open closed.** `redactValue` past `MAX_REDACT_DEPTH` returned the caller's
   raw value. It now returns a new `MAX_DEPTH_MARKER = "[max-depth]"`.
2. **`scrubText` added.** Free-text counterpart of the field-name redactor: replaces the
   value of `key=value` / `key: value` fragments whose key is `isNeverLog`. The key class
   stops at quotes, so a JSON fragment (`"password":"…"`) never matches — structured
   payloads stay parseable and are redacted structurally instead.
3. **`Error` no longer emits `stack`/`message` verbatim.** Both go through `scrubText`.
4. **Census un-blinded.** `findUnredactedSecretKeys` dropped its `depth` cap (which was the
   *same* `MAX_REDACT_DEPTH`, so it was blind over exactly the range the redactor leaked —
   the two defects cancelled each other's detection). It is now depth-unlimited with a
   `seen` cycle guard, walks arrays as index-keyed objects (`rows.0.private_key` is now
   reachable), and reports `MAX_DEPTH_MARKER` positions as uninspected.

### `packages/node-core/src/observability/index.ts`

Re-exports `MAX_DEPTH_MARKER` and `scrubText`.

### `apps/generic-node/src/boot/safe-logger.ts` — new, the adapter

`createSafeConsoleLogger(sink = console)` returns a `BootLogger` that scrubs the message
text and routes the error through `scrubErrorDetails`; `safeJsonLine(fields)` is the
structured path. Placed in the app, not node-core, because `safe-log.ts:2-3` is explicit
that the module holds no logger-framework dependency and adapters wrap it.

Two details worth the reviewer's attention:
- The error is wrapped (`scrubErrorDetails({ err })`) rather than passed directly, because
  `message` and `stack` are **non-enumerable** on `Error` — `redactLogFields(err)` returns
  `{}`. The redactor's `Error` branch is only reachable through a field *value*.
  `boot/fatal-exception.ts` already does exactly this; the adapter matches it.
- `BootLogger` is imported `import type`, so this module gains no runtime edge to
  `boot-lane.ts` (which imports the node-core **root barrel**). `stage1-main.ts` builds its
  logger here and must stay off the vault/signing/submit surfaces.

### `apps/generic-node/src/main.ts`, `apps/generic-node/src/stage1-main.ts`

Both entry points now build their logger from the adapter, and **every** raw `console.*`
call in both files routes through it — not just the ones the ticket named. `main.ts` had
four more beyond the logger block (config fatal, storage-pressure alert, safety-alert
channel, identity-seed fatal, top-level boot-failure catch); `stage1-main.ts` had the
backup-scheduler logger, the RPO monitor pair, three startup lines, the graceful-stop
logger and the top-level catch. `stage1-main.ts` also now passes the logger to
`installFatalExceptionHandler`, which was falling back to its raw-console default.

`runtimeListenerLogger` stringifies through `safeJsonLine` so the structured event is
redacted by field name and the emitted line stays valid JSON.

### `packages/node-core/test/boundaries.test.ts`

Comment only. The `@zucoins/node-core/observability` allowlist entry named
`fatal-exception.ts` as its sole reason; `safe-logger.ts` now shares it. No new allowlist
entry was needed — the specifier was already sanctioned, and no new node-core
cross-module import was introduced (`ALLOWED_INTERNAL_IMPORTS` untouched).

## Decisions taken

**Placeholder: a distinct `MAX_DEPTH_MARKER`, not `REDACTED`.** The ticket left this open.
`REDACTED` means "inspected and censored"; the depth cut-off means "never inspected". The
census needs to tell them apart, which is what makes the next decision possible.

**`assertDumpSecretFree` refuses a dump nested past the limit.** This is the one place the
criteria needed a judgement call, and the reviewer should check it deliberately.

The two criteria "`:63` returns a placeholder past `MAX_REDACT_DEPTH`" and
"`assertDumpSecretFree` **throws** for a dump with a secret nested deeper than eight
levels" cannot both hold in the obvious reading: the function censuses the *redacted*
output, so once the depth hole is closed, the deep secret is gone and there is nothing left
to throw about. Censusing the raw dump instead would satisfy the criterion but flips the
existing `assertDumpSecretFree accepts ciphertext field names after redact path` test
(which asserts a root-level `private_key` in a raw dump does **not** throw) — a re-spec of
the function's contract that the ticket did not ask for.

Resolution: the census reports `MAX_DEPTH_MARKER` positions as uninspected, so
`assertDumpSecretFree` refuses to certify a dump the redactor stopped inside. That is the
ticket's own posture — "a guard that cannot see the failure it guards against is worse than
no guard, because it produces a green assertion" — and it satisfies both criteria without
changing redact-first semantics. **Honest limit:** it refuses any dump nested past eight
levels, secret or not. Blast radius is zero (the function has no production callers), and
the fix is to flatten the dump or raise `MAX_REDACT_DEPTH` deliberately.

**`stack` scrubbed, not dropped.** The ticket allowed either. Dropping it would leave
`boot/fatal-exception.ts` — the process-level fatal net, and today the only
`scrubErrorDetails` caller — with no frames at all on a production fatal. `scrubText`
covers the stack's header line, which is where the message (and its quoted input) repeats.

**Forbidden terms / frozen counts: untouched.** No new usage of the thirteen stems, so
`FROZEN_EXEMPTION_COUNT` and `FROZEN_SUPPRESSED_VIOLATION_COUNT` are unchanged and the
drift gate passes as-is.

## Tests

`packages/node-core/test/safe-log-redaction.test.ts` (10 → 16 tests):
never-log field nested at depth 12 censored; marker emitted past the bound and a value one
level *inside* it still visible; marker distinct from `REDACTED`; `Error.message`/`.stack`
scrubbed with the source `Error` unmutated; `scrubText` leaves JSON and non-secret text
alone; deep-copy asserted at every level including past the bound;
`assertDumpSecretFree` **throws** for a depth-12 secret; `findUnredactedSecretKeys` returns
the full `l1.…​.l11.privateKey` path; census walks arrays and terminates on cycles.

The ticket said to "update the existing depth assertions" — there were none. The existing
file had no test that exercised `MAX_REDACT_DEPTH` at all, which is why both defects
survived. All ten pre-existing tests pass unchanged.

`apps/generic-node/test/safe-logger.test.ts` (new, 7 tests): placeholder not value through
the production logger; structured line stays parseable; info message scrubbed; error
message and stack scrubbed; caller's `Error` unmutated. Plus a **source gate** asserting
`main.ts` and `stage1-main.ts` contain no `console.*` call — the regression that matters,
because the enduring risk is a contributor adding one log line that opts out.

**Proof the new tests bite.** With the two `safe-log.ts` source lines reverted to their
pre-fix form (`return value`, raw `message`/`stack`) and the new tests in place:
`3 failed | 13 passed (16)` — the depth-12 censoring test, the marker test, and the Error
scrub test. The `assertDumpSecretFree` throw test bites against the *census* defect rather
than the depth defect: with the old depth-capped census it cannot see past level 8 either
way, which is the two-bugs-cancelling-out shape the ticket describes.

## Verification (at this branch head — exact SHA in the PR body)

- `pnpm install` — exit 0.
- `npx tsc -b` — exit 0.
- `npx eslint .` — **0 errors, 6 warnings**, all pre-existing and untouched by this change
  (`admin/public/sw.js:8`, `live-chain/receive-execute-guards.killing.test.ts:213-214` ×3,
  `move-internal-create.pg.test.ts:399`, `push-subscription-gate.test.ts:302`).
- `pnpm test:boundaries` — **162 passed** (5 files).
- Targeted — `safe-log-redaction` + `safe-logger` + `fatal-exception` + `stage1-production`
  + `stage1-shutdown`: **46 passed** (5 files).
- `pnpm test` — **11628 passed, 1 failed, 9 skipped, 5 todo (11643)**; 769 files passed,
  4 failed, 3 skipped. Duration 421s.

### The 4 red files, attributed

All four are Postgres scratch-DB contention under the 776-file parallel run, and **none
imports the observability module**:

| File | Symptom |
| -- | -- |
| `node-core/test/zkz-amount-domains.pg.test.ts` | `psql setup failed on postgres: unknown error` (beforeAll) |
| `node-core/test/observation-anomaly-indexes.pg.test.ts` | same |
| `node-core/test/reporting-rate-limit-buckets-pk-collapse.pg.test.ts` | `afterAll` `DROP DATABASE` hook timed out at 30000ms |
| `generic-node/test/metrics-postgres-deadline.pg.test.ts` | `pool.idleCount` 0 ≠ `totalCount` 1 — pool-return timing |

Re-run in isolation at the same SHA: **4 files, 25 tests, all passed.** The run also logged
two `[vitest-worker]: Timeout calling "onTaskUpdate"` unhandled errors, the same
host-saturation signature.

No Postgres path was touched; the pg suites ran because the full-suite gate runs them, not
because this change reaches them.

## Deferred (for the orchestrator to file, not done here)

- **`apps/generic-node/src/dr/cli.js` and the other operator CLIs still write raw
  `console.*`.** Out of the ticket's scope (it names the two entry points), but the same
  class: a DR CLI prints restore diagnostics, which is where driver errors live. Worth its
  own ticket.
- **`scrubText` matches assignment-shaped fragments only.** A secret pasted as a bare
  token, or a URL credential (`postgres://user:pass@host`), is not matched. Marked with a
  `ponytail:` comment at the definition naming the ceiling and where to widen it.
- **Raw Zod `error.message` in 400 bodies** — the audit's separate finding, explicitly
  carved out of this ticket by its own text. Not addressed.

## Mechanics

```
python3 scripts/claim.py check   ZTR-1187
python3 scripts/claim.py beat    ZTR-1187 implementer "<progress>" --run c843dfad-ef62-4a54-99bd-e5da534f9fdb
python3 scripts/claim.py release ZTR-1187 implementer "PR #<n>" "QA Review" --run c843dfad-ef62-4a54-99bd-e5da534f9fdb
```
