import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

// (minimal): scope the network-containment guard to this package's own tests.
// Used when running vitest directly inside packages/node-core; the repo-root suite
// (vitest.config.ts) discovers these same test files via its existing include globs.
//
// This project entry is standalone (see root vitest.config.ts's `projects` array) and does
// NOT extend the root config, so it does not inherit the root's resolve.alias. is the
// first consumer of @zucoins/generic-node-contracts from this package; that package has no
// built dist/ yet (root vitest.config.ts source-aliases @zupayments/splitchain and
// @zupayments/shared the same way, for the same reason). tsc -b resolves the real dependency
// via the project reference in tsconfig.json instead.
// a FILTERED standalone run (`pnpm --filter @zucoins/node-core exec vitest run
// config vitest.config.ts <files>` — exactly the shape every decision-gate / decision-gate command shape-style
// gate command uses) that resolves to ZERO files must FAIL, not pass silently: vitest's own
// filter matching silently DROPS a filter that matches nothing rather than erroring — two of
// eight gate commands each named one renamed/nonexistent file this way and still
// recorded a PASS. `passWithNoTests: true` stays safe ONLY
// for a genuinely bare standalone run (no filters at all) — this package always has hundreds
// of real test files, so that path is inert today; kept so a real config regression there
// still fails loudly on its own terms rather than being silently absorbed by this fix.
//
// This must NOT change when this same file is loaded as one of several `projects` entries
// under the root's aggregate `pnpm exec vitest run <target>` (see root vitest.config.ts) — a
// target meant for a DIFFERENT package legitimately matches zero files here, and that must
// not fail the whole run (scripts/verify-local.sh's own aggregate zero-test check,
// already covers the case that actually matters: total tests across ALL projects). The two
// shapes are distinguishable by process.cwd: a standalone run's cwd IS this package's own
// directory (`pnpm --filter` cd's into it before exec'ing); an aggregate run's cwd is the
// repo root regardless of which project is being loaded — confirmed empirically both ways.
// Fail closed on a FILTERED direct run of THIS config that matches zero files
// (`vitest run --config vitest.unit.config.ts <missing>`). When this file is loaded as one
// of several workspace projects (root pnpm test, or the package umbrella vitest.config.ts),
// a filter aimed at the sibling pg project legitimately matches zero files here — that must
// not fail the whole run. Distinguish by whether --config/-c names this file.
const THIS_CONFIG_BASENAME = "vitest.unit.config.ts";

function thisConfigIsDirectCliTarget(): boolean {
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--config" || arg === "-c") {
      const value = argv[i + 1] ?? "";
      return value === THIS_CONFIG_BASENAME || value.endsWith(`/${THIS_CONFIG_BASENAME}`);
    }
  }
  return false;
}

// ponytail: scoped to the one invocation shape this package's own gate commands use
// (`<subcommand> [--config|-c <path>] [filters...]`) — a flag we don't yet know about that
// also consumes a value would be misread as a filter.
function standaloneRunHasPathFilters(): boolean {
  const VITEST_SUBCOMMANDS = new Set(["run", "watch", "dev", "related", "bench", "list"]);
  const FLAGS_WITH_VALUE = new Set(["--config", "-c"]);
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (VITEST_SUBCOMMANDS.has(arg)) continue;
    if (FLAGS_WITH_VALUE.has(arg)) {
      i++; // also skip the flag's value
      continue;
    }
    if (arg.startsWith("-")) continue; // a boolean/other flag, not a path filter
    return true; // first non-subcommand, non-flag token IS a path filter
  }
  return false;
}

export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  resolve: {
    // Ordered array form: alias entries match by prefix and the first match wins, so the
    // transfer-code subpath must precede the package-root entry or the root
    // alias would swallow the subpath import.
    alias: [
      {
        find: "@zucoins/generic-node-contracts/transfer-code",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/transfer-code/index.ts", import.meta.url),
        ),
      },
      {
        // the `./testkit` subpath (guard-free reporting serializer confinement).
        // Like transfer-code above, it must precede the package-root entry or the prefix
        // match would swallow it into `.../src/index.ts/testkit`.
        find: "@zucoins/generic-node-contracts/testkit",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/testkit/index.ts", import.meta.url),
        ),
      },
      {
        // The `./api-schema` subpath (frozen IMPLEMENTER_SCOPES consumed by
        // src/credential/types.ts). Like the subpaths above, it must precede the package-root
        // entry or the prefix match would swallow it into `.../src/index.ts/api-schema`.
        find: "@zucoins/generic-node-contracts/api-schema",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/api-schema/index.ts", import.meta.url),
        ),
      },
            {
        find: "@zucoins/generic-node-contracts/admin-auth-errors",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/admin-auth-errors/index.ts", import.meta.url),
        ),
      },
{
        find: "@zucoins/generic-node-contracts/auth-errors",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/auth-errors/index.ts", import.meta.url),
        ),
      },
      {
        // The `./observation` subpath (frozen decideAppend / anomaly kinds, consumed
        // by src/observation/dedup.ts and the reconcile landing path). Like the subpaths
        // above, it must precede the package-root entry or the prefix match would swallow
        // it into `.../src/index.ts/observation`.
        find: "@zucoins/generic-node-contracts/observation",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/observation/index.ts", import.meta.url),
        ),
      },
      {
        // The `./amounts` subpath (frozen amount contract consumed by
        // src/protocol/amounts.ts). Like the subpaths above, it must precede the
        // package-root entry or the prefix match would swallow it into
        // `.../src/index.ts/amounts`.
        find: "@zucoins/generic-node-contracts/amounts",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/amounts/index.ts", import.meta.url),
        ),
      },

      {
        // ./operations/events subpath — must precede ./operations (prefix match).
        find: "@zucoins/generic-node-contracts/operations/events",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/operations/events.contract.ts", import.meta.url),
        ),
      },
      {
        // The `./operations` subpath (frozen OperationKind single source, consumed by
        // src/proof/types.ts and src/api/discovery.ts). Like the subpaths above, it must precede
        // the package-root entry or the prefix match would swallow it into `.../src/index.ts/operations`.
        find: "@zucoins/generic-node-contracts/operations",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/operations/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/wallet-state",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/wallet-state/index.ts", import.meta.url),
        ),
      },
      {
        // The `./route-policy` subpath (frozen ROUTE_POLICIES, cross-validated
        // against ROUTE_SCHEMAS by test/api-validation.test.ts, and by src/api/pipeline.ts to
        // resolve each route's required scope). Like the subpaths
        // above, it must precede the package-root entry or the prefix match would swallow it
        // into `.../src/index.ts/route-policy`.
        find: "@zucoins/generic-node-contracts/route-policy",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/route-policy/index.ts", import.meta.url),
        ),
      },
      {
        // wallet-vault AAD + HKDF-info builders. Must precede the package-root
        // alias or the prefix match swallows `/vault` into `.../src/index.ts/vault`.
        find: "@zucoins/generic-node-contracts/vault",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/vault/index.ts", import.meta.url),
        ),
      },
      {
        // custody predicates for the claim-boundary service.
        find: "@zucoins/generic-node-contracts/custody",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/custody/index.ts", import.meta.url),
        ),
      },
      {
        // instruction-origin pin predicates.
        // Must precede the package-root alias or the prefix match swallows the subpath.
        find: "@zucoins/generic-node-contracts/instruction-origin",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/instruction-origin/index.ts", import.meta.url),
        ),
      },
      {
        // frozen zp-implementer-event-v1 tuple consumed by the dual-chain event
        // appender. Must precede the package-root alias or the prefix match swallows it.
        find: "@zucoins/generic-node-contracts/implementer-events",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/implementer-events/index.ts", import.meta.url),
        ),
      },
      {
        // Closed recovery-action catalog (halt.contract) — SPA + recovery store
        // derive live/reserved from this subpath. Must precede the package-root alias.
        find: "@zucoins/generic-node-contracts/operator-halt",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/operator-halt/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts",
        replacement: fileURLToPath(
          new URL("../generic-node-contracts/src/index.ts", import.meta.url),
        ),
      },
    ],
  },
  test: {
    name: "node-core",
    // see the thisConfigIsDirectCliTarget / standaloneRunHasPathFilters comment
    // above defineConfig for the full rationale.
    passWithNoTests: !thisConfigIsDirectCliTarget() || !standaloneRunHasPathFilters(),
    // Non-PG files only. Real-PostgreSQL suites live in vitest.pg.config.ts (singleFork)
    // so multi-file parallel contention cannot deadlock shared scratch DDL (ZTR-1209).
    include: ["src/**/*.test.ts", "test/**/*.test.ts", "scripts/**/*.test.mjs"],
    exclude: [
      "**/node_modules/**",
      "**/dist/**",
      "**/*.pg.test.ts",
      "**/*-pg.test.ts",
      "**/pg-concurrency.test.ts",
      // Live-Postgres openers hosted by vitest.pg.config.ts (singleFork) — ZTR-1209 r5.
      "**/capture.concurrency.test.ts",
      "**/quarantine.integration.test.ts",
      "**/custody-eligibility-lease-pk.test.ts",
      "**/degraded-mode.fault.test.ts",
      "**/disk-db-exhaustion.fault.test.ts",
      "**/migration-integrity.test.ts",
      "**/observation-migration-integrity.test.ts",
      "**/operation-lifecycle-concurrency.test.ts",
      "**/registry-isolation-rotation.test.ts",
    ],
    // this project is standalone (see the comment above) so it inherits NONE of the
    // root project's options — including the testTimeout/hookTimeout the root config raised for
    // exactly this reason. That gap became load-bearing once vitest.global-setup.ts started
    // assigning TEST_DATABASE_URL: the real-PostgreSQL suites here (migration-integrity,
    // custody-eligibility-lease-pk) stopped skipping, and their
    // psql child processes carry their OWN 15s timeouts — longer than vitest's 10s default hook
    // budget, so a scratch-database CREATE/DROP under full-suite parallel contention could time
    // the hook out before psql itself gave up. Match the root project's values so the hook budget
    // is never shorter than the operation it awaits.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    setupFiles: [fileURLToPath(new URL("./test/setup-network-guard.ts", import.meta.url))],
    // Same hermetic TEST_DATABASE_URL provisioner apps/generic-node uses. Without this,
    // standalone `pnpm exec vitest run --config packages/node-core/vitest.unit.config.ts …`
    // leaves PG-touching non-suffix suites on describe.skip and greens having proven nothing.
    globalSetup: [fileURLToPath(new URL("../../vitest.global-setup.ts", import.meta.url))],
  },
});
