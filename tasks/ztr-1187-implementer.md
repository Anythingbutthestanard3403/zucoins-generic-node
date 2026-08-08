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

---

## Rework r1 — lane=implementer run=870e0c3c-6940-486b-bd5d-82a0246d774b

Review of `a16481f` returned **FAIL** on one blocking regression (`tasks/ztr-1187-review.md`,
PR #9 `issuecomment-5225211439`). Everything else PASSed and was left untouched.

**Rebased** `ztr-1187-safe-log-redaction` onto `origin/main` @ `276b0e7` (was `6c29b0a`);
one commit `f3a9c2b` (was `a16481f`) + the rework commit, which is the branch head — exact SHA
in the PR #9 body, since it cannot be written into itself.

### The defect

`main.ts:171-179` composes `logger.error(safeJsonLine(event))`. `safeJsonLine` serializes, then
`createSafeConsoleLogger.error` runs `scrubText` over the resulting JSON *string*.
`TEXT_ASSIGNMENT`'s unquoted-value class `[^\s,;)\]}]+` did not exclude `"`, so a never-log
assignment running to the end of a JSON string value consumed the closing quote.
`cause_message` is the last declared field of `RuntimeListenerFailureEvent`, so the corruption
always landed at the line terminus → `SyntaxError: Unterminated string in JSON`.

Reachable because `sanitizeFailureCause`'s `\b`-anchored keyword list does not cover
`vaultMasterKey` / `sessionToken` / `pwd`, while `isNeverLog` does. Before the PR: parseable but
leaky. At `a16481f`: redacted but unparseable. Both are broken controls.

### The fix — `packages/node-core/src/observability/safe-log.ts:74`

One regex, and it goes one alternative past the reviewer's prescribed form:

```
- ("[^"]*"|'[^']*'|[^\s,;)\]}]+)
+ ("[^"]*"|'[^']*'|\\"[^"]*\\"|[^\s,;)\]}"']+)
```

Excluding the quotes alone (the prescribed form) fixes the bare-value cases but leaves an
escaped-quote value inside a JSON line **both unparseable and leaking**. Probed all three forms
(`/Volumes/Ai Building/.zup-scratch/regex-probe.mjs`):

| input | a16481f | quote-exclusion only | shipped |
| -- | -- | -- | -- |
| `{…"cause_message":"… pwd=hunter2"}` | JSON BROKEN | JSON OK, clean | JSON OK, clean |
| `{…"cause_message":"… vaultMasterKey=MK-LEAK"}` | JSON BROKEN | JSON OK, clean | JSON OK, clean |
| `{…"cause_message":"… sessionToken=ST-LEAK"}` | JSON BROKEN | JSON OK, clean | JSON OK, clean |
| `{…"cause_message":"… pwd=\"hunter2\""}` | JSON BROKEN | **JSON BROKEN, LEAK** | JSON OK, clean |
| `VAULT_MASTER_KEY=MK-…` | redacted | redacted | redacted |
| `totpSecret: 123456` | redacted | redacted | redacted |
| `connect failed password=hunter2 host=db.internal` | redacted, host kept | same | same |
| `password="hunter2"` | redacted | redacted | redacted |
| `{"password":"hunter2"}` (structural) | untouched | untouched | untouched |

Excluding `\` instead was considered and rejected: the whole match then fails at `pwd=\"…` and
the secret prints raw — strictly worse.

The doc comment at `:69-79` now states *why* the class excludes quotes, so the "must stay
parseable" claim in that header is in force rather than merely asserted.

### The test — `apps/generic-node/test/safe-logger.test.ts`

Three cases on the **composed** path (the gap that let this through: `:39-43` only ever
exercised `safeJsonLine` in isolation). Each drives
`createSafeConsoleLogger(sink).error(safeJsonLine(event))` on a full
`RuntimeListenerFailureEvent`, spreading `sanitizeFailureCause(new Error(cause))` exactly as
`main.ts` does, and asserts: `JSON.parse` succeeds, no `UNIQUE-VALUE` in the emitted line, and
`cause_message` contains `[redacted]`.

Fails before / passes after, both at this SHA:

- `git checkout -- safe-log.ts` (revert to `a16481f` form), tests present →
  **3 failed | 7 passed (10)**, all three `SyntaxError: Unterminated string in JSON`
  (positions 231, 220, …).
- fix restored → **10 passed (10)**.

### Verification at the head SHA

| Command | Result |
| -- | -- |
| `npx tsc -b` | exit 0 |
| `npx eslint .` | 0 errors, **6 warnings** — the exact pre-existing six |
| `pnpm test:boundaries` | **162 passed** (5 files) |
| node-core `safe-log-redaction` + `neutrality` | **50 passed** (2 files) |
| contracts `forbidden-terms` | **18 passed** (1 file) |
| generic-node `safe-logger` + `fatal-exception` + `runtime-listener` + `stage1-production` + `stage1-shutdown` | **63 passed** (5 files) |

Reconciles exactly with the reviewer's two runs at `a16481f` (60 + 68 = 128): 50 + 18 + 63 = 131
= 128 + 3 new cases. No existing redaction assertion moved.

Full `pnpm test` not repeated — the diff since `a16481f` is one regex and one test file, neither
reachable from any pg suite. The `a16481f` pg attribution (ZTR-1209-class contention) stands.

### Out of scope, per the review

`db/client.ts:126`'s raw driver `err` → ZTR-1215. The fatal-path double-wrap (`{err:{err}}`) is
cosmetic and was left alone.

## Rework r2

Review r1 (`f9b2c8f`) FAILed: the r1 regex stopped eating the JSON string terminator but
opened a new fail-open — a never-log value whose opening quote is never closed matched no
alternative at all and was emitted verbatim. r0 had the mirror defect. The two properties
were in tension **because one pattern was doing two jobs**: scrubbing free text, and
scrubbing an already-serialized JSON document.

### Approach: structural, not another regex shape

I took the fallback the brief authorized, because the mechanical fix cannot close the class.
Measured on the real built `scrubText` / composed path at `f9b2c8f` (harness below), head
failed **more** shapes than the review found:

| shape | head `f9b2c8f` |
| -- | -- |
| unbalanced `"` / `'` / `\"` / truncation-shaped (Property A) | **1 of 8 redacted** — 7 leak |
| composed-path JSON validity (Property B) | **3 of 9** parse clean |
| `cause_message` ending exactly at `pwd=` | invalid JSON — scrub runs on into the *next* field |
| `cause_message` ending at `pwd="` | invalid JSON |
| `scrubText(scrubText(x))` | not idempotent — grows a `]` per pass |

The last three are not in the review's table. Any further quote-class tuning trades one of
them for another: a class that consumes `"` destroys a serialized line, a class that refuses
`"` emits truncated values. Neither is a shape problem; running a text pattern across JSON
is the defect.

So the three changes separate the two jobs:

1. **`packages/node-core/src/observability/safe-log.ts` — `redactValue`** now scrubs a plain
   string value (`if (typeof value === "string") return scrubText(value);`). Free text held
   in an ordinarily-named field (`cause_message`) is redacted **before** the caller
   serializes, so the JSON `safeJsonLine` emits is already clean *and* parseable — `JSON.stringify`
   does the escaping, so there is no quote balancing to get wrong.
2. **`TEXT_ASSIGNMENT`** goes back to a free-text-only pattern that consumes quotes
   (`"[^"]*"|'[^']*'|[^\s,;)}]+`), which is the form that redacted 6 of 6 unbalanced inputs
   before r1. It is now only ever run on free text. `]` was dropped from the terminator set:
   that makes the scrub idempotent (`[redacted]` is consumed whole and rewritten to itself)
   and closes a bypass where a caller-controlled `pwd=[redacted]still-secret` kept its tail —
   my own new test caught that one.
3. **`apps/generic-node/src/boot/safe-logger.ts` — `redactMessage`** routes: a line that
   parses as a JSON object is re-redacted *structurally* (`safeJsonLine(JSON.parse(line))`),
   everything else gets `scrubText`. Re-redacting rather than passing through keeps it
   fail-closed — a JSON line built anywhere else is still redacted — and both redactors are
   idempotent, so on a line `safeJsonLine` already produced the second pass is a no-op.

The text pattern now never sees serialized JSON, and serialized JSON is never text-scrubbed.
Both properties hold by construction rather than by shape enumeration.

### Both-properties harness — red before, green after

One script, run against the **built dist** of the tree under test, checking both properties
plus idempotence in a single pass
(`scratchpad/both-properties.mjs`; the same cases are committed as tests, see below):

- **Property A (no leak)** — `scrubText` output must not contain the never-log plaintext for
  the review's six unbalanced-quote inputs, plus the escaped-unbalanced `pwd=\"…` shape and a
  400-char input that `sanitizeFailureCause` truncates mid-value on its own.
- **Property B (valid JSON)** — the composed production path
  `createSafeConsoleLogger(sink).error(safeJsonLine({ …event, ...sanitizeFailureCause(err) }))`
  must `JSON.parse` **and** not contain the plaintext, for the r0 blocker (bare value ending
  the string), balanced quoted, unbalanced double/single/escaped, truncation-shaped, and the
  two degenerate `pwd=` / `pwd="` shapes. A `tail_field: "sentinel"` sits **after** the cause
  so a scrub that runs on across the string boundary into the next field cannot hide.
- **Idempotence** — `scrubText(scrubText(x)) === scrubText(x)`.

| | `f9b2c8f` (before) | this head (after) |
| -- | -- | -- |
| Property A — no leak | **1 / 8** | **8 / 8** |
| Property B — parseable + clean | **3 / 9** | **9 / 9** |
| Idempotence | 6 / 8 | **8 / 8** |
| script exit code | 1 | **0** |

Before-row output, verbatim (built dist at `f9b2c8f`):

```
LEAK    "db auth failed pwd=\"PW-UNIQUE-VALUE"          -> unchanged
LEAK    "session rejected sessionToken=\"ST-UNIQUE-VALUE" -> unchanged
LEAK    "vault unlock failed vaultMasterKey=\"MK-UNIQUE-VALUE" -> unchanged
LEAK    "db auth failed pwd='PW-UNIQUE-VALUE"           -> unchanged
LEAK    "db auth failed pwd=\"PW-UNIQUE-VALUE…"         -> unchanged
redact  "db auth failed pwd=\"PW-UNIQUE-VALUE\""        -> "db auth failed pwd=[redacted]"
LEAK    "db auth failed pwd=\\\"PW-UNIQUE-VALUE"        -> "db auth failed pwd=[redacted]\"PW-UNIQUE-VALUE"
LEAK    "db auth failed pwd=\"PW-UNIQUE-VALUExxx…"      -> unchanged
Property A: 1/8 redacted

FAIL unbalanced double quote
     line=…"cause_message":"db auth failed pwd=[redacted]"PW-UNIQUE-VALUE","tail_field":"sentinel"}
     parse=Expected ',' or '}' after property value in JSON at position 220   leak=true
FAIL assignment with empty value
     line=…"cause_message":"db auth failed pwd=[redacted]tail_field":"sentinel"}
     parse=Expected ',' or '}' after property value in JSON at position 230   leak=false
Property B: 3/9 parseable+clean
```

After: every Property A row `redact`, every Property B row `PASS`, exit 0.

### The cases are committed, not throwaway

- `packages/node-core/test/safe-log-redaction.test.ts` — a `SHAPES` table pinning the
  free-text invariant where the pattern lives: unbalanced double / single / escaped quote,
  truncation-shaped, balanced, bare, plus a never-log key `sanitizeFailureCause` does not
  cover; an idempotence assertion over every shape; the `pwd=[redacted]still-secret` bypass;
  and the pre-serialization structural scrub (`cause_message` redacted, `amount: "1.00"`
  untouched).
- `apps/generic-node/test/safe-logger.test.ts` — `LISTENER_CAUSES` grows from 3 to 10 on the
  same composed path, each asserting `JSON.parse` succeeds, the plaintext is absent, and the
  trailing sentinel field survives. Two more tests pin the routing itself: a JSON line built
  outside `safeJsonLine` is still redacted by field name, and a message that only *looks*
  like JSON still gets the text scrub.

### Certified behaviour left undisturbed

- Depth fail-open census: `packages/node-core/test/safe-log-redaction.test.ts` — the depth
  and dump-census assertions are untouched and green (26 tests in that file, up from 16 by the
  new cases only).
- Single chokepoint: `packages/node-core/test/boundaries.test.ts` **71/71**; the
  `safe-logger.ts` import set is unchanged (`redactLogFields`, `scrubErrorDetails`,
  `scrubText` all still used), and both entry points still log only through the adapter —
  the raw-`console` source gate is unchanged and green.

### Verification at the rework head

| Command | Result |
| -- | -- |
| `npx tsc -b` | exit 0 |
| `npx eslint .` | 6 problems, **0 errors**, 6 warnings — the exact pre-existing six |
| `pnpm test:boundaries` | **162 passed** (5 files) |
| node-core `safe-log-redaction` + `boundaries` + app `safe-logger` | **116 passed** (3 files) |
| app `safe-logger` + `stage1-*` | **35 passed** (3 files) — was 26, +9 new composed-path cases |
| both-properties harness | A **8/8**, B **9/9**, idempotence **8/8**, exit 0 |
| `pnpm test` (full) | **11658 passed**, 20 skipped, 5 todo, **2 failed** |

The two failures are both `.pg.test.ts` and are provisioning contention, not this diff — which
touches one regex, one `typeof value === "string"` branch and one logger routing function, and
has no DB surface at all. Re-run without the contention:

- `metrics-postgres-deadline.pg` + `send-completion-lander.pg` alone at this head → **14/14 passed**.
- All five pg files that failed in the full run, re-run at this head → 42 passed, only
  `receive-settle-step.pg` failing, and on `duplicate key … pg_extension_name_index
  (extname)=(pgcrypto)` — two files racing `CREATE EXTENSION` in the same scratch cluster.
- The `send-completion-lander` failure mode was `role "degraded_lowpriv" does not exist`: that
  role is **cluster-wide**, created in `beforeAll` and dropped in `afterAll` (lines 817, 856), so
  a concurrent or interrupted run of the same file removes it out from under a live one.

### Out of scope, unchanged

`db/client.ts:126`'s raw driver `err` → ZTR-1215. The fatal-path double-wrap (`{err:{err}}`) is
cosmetic and was left alone.
