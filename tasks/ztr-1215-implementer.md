# ZTR-1215 — implementer handoff

**PR:** #78  
**HEAD:** `5834d99ce6209f4f73cbe50256dbb8a9f48699cf`  
**Branch:** `ztr-1215-log-redaction-residuals` off `origin/main` @ `7e01e8a`

## Ticket

Log-redaction residuals deferred from ZTR-1187 (PR #9):
1. DR / operator CLIs still wrote raw `console.*`
2. `scrubText` only matched assignment-shaped fragments
3. Comment add-on: `db/client.ts` pool idle-error handler logged raw driver `err`

## Governing surface

- `packages/node-core/src/observability/safe-log.ts` (central redactor)
- `apps/generic-node/src/boot/safe-logger.ts` (console adapter / chokepoint)
- Prior work: ZTR-1187 (`tasks/ztr-1187-implementer.md`)

## What changed

### 1. `scrubText` widened (node-core)

Three idempotent passes:
1. URL userinfo with password: `scheme://user:pass@host` → `scheme://[redacted]@host` (colon required in userinfo so `file:///…/pkg@ver` stack frames are not chewed)
2. Existing never-log assignments (`key=value` / `key: value`)
3. Bare high-entropy tokens (≥24 chars; hex ≥32; mixed-case+digit; base64url-ish with uppercase). Excludes pure digits, UUIDs, path segments (`/` not in candidate alphabet)

Exported `isHighEntropyToken` for tests.

### 2. CLI / residual surfaces → same redactor

| Surface | Change |
|---|---|
| `dr/cli.ts` | `defaultIo = createSafeCliIo()` |
| `dr/schedule.ts` | default logger = `createSafeConsoleLogger()` |
| `ops/run-recovery-ceremony.ts` | all console → `cliIo` |
| `operations/rotate-master-key.cli.ts` | `defaultLogger = createSafeRotationLogger()` |
| `db/migrate.ts` main | `createSafeConsoleLogger()` |
| `db/client.ts` pool `error` | `createSafeConsoleLogger().error(...)` |

New helpers on `boot/safe-logger.ts`: `createSafeCliIo`, `createSafeRotationLogger`, `safeConsoleText`, `safeFormatError`.

### 3. Tests that bite

- `packages/node-core/test/safe-log-redaction.test.ts` — bare token, URL credential, colon-in-password, prose/UUID non-over-redact, file:// stack frame, idempotence (+ existing assignment shapes)
- `apps/generic-node/test/safe-logger.test.ts` — source-gate census over the six CLI/pool surfaces (no raw `console.*` call); `createSafeCliIo` redacts bare secret; pool idle-error handler redacts DSN password in driver message

## Acceptance

| AC | Status |
|---|---|
| Every raw `console.*` in DR CLI + operator CLIs routes through redactor | **yes** — census + wiring |
| `scrubText` catches bare high-entropy + URL userinfo without over-redacting prose | **yes** — tests |
| Tests: assignment (existing), bare token, URL credential; CLI path uses redactor | **yes** |
| Do not duplicate raw-Zod-400 (ZTR-1200) | **yes** — untouched |
| `pnpm test` green (targeted packages) | **yes** — see verify |

## Verify (at HEAD `5834d99`)

```
CI=true pnpm install          # Already up to date
tsc -b                        # exit 0
pnpm --filter @zucoins/node-core exec vitest run test/safe-log-redaction.test.ts
  → 35 passed (1 file)
pnpm --filter @zucoins/generic-node exec vitest run \
  test/safe-logger.test.ts test/dr/cli.test.ts test/db/client.import-smoke.test.ts
  → 42 passed (3 files)
pnpm --filter @zucoins/node-core lint   # 0 errors (pre-existing warnings only)
pnpm --filter @zucoins/generic-node lint # clean
```

Note: full-package `vitest run` teardown may hit `spawnSync psql ETIMEDOUT` when local Postgres is absent — tests themselves pass before teardown.

## Files touched

- `packages/node-core/src/observability/safe-log.ts`
- `packages/node-core/src/observability/index.ts`
- `packages/node-core/test/safe-log-redaction.test.ts`
- `apps/generic-node/src/boot/safe-logger.ts`
- `apps/generic-node/src/dr/cli.ts`
- `apps/generic-node/src/dr/schedule.ts`
- `apps/generic-node/src/ops/run-recovery-ceremony.ts`
- `apps/generic-node/src/operations/rotate-master-key.cli.ts`
- `apps/generic-node/src/db/client.ts`
- `apps/generic-node/src/db/migrate.ts`
- `apps/generic-node/test/safe-logger.test.ts`

## Deferred / out of scope

- Raw Zod `error.message` in 400 bodies → ZTR-1200
- Deploy smoke scripts / triad-composition.mjs console (not DR/operator CLI runtime)
- Base64 secrets that contain `/` are split by the bare-token candidate (path-safe alphabet); assignment-shaped and URL-userinfo paths still catch the common DSN/API-key forms
