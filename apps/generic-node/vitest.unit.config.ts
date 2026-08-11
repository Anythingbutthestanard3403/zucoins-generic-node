import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Scope the network-containment guard to this package's own tests.
// Used when running vitest directly inside apps/generic-node; the repo-root suite
// (vitest.config.ts) discovers these same test files via its existing include globs.
//
// Subpath aliases for @zucoins/generic-node-contracts must precede the package-root entry
// (same reason as packages/node-core/vitest.config.ts): a prefix match would otherwise
// swallow `@zucoins/generic-node-contracts/amounts` into `.../src/index.ts/amounts`. The
// POST /v1/receives route imports @zucoins/node-core, which pulls those subpaths in.
export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  resolve: {
    alias: [
      {
        find: "@zucoins/node-core/data",
        replacement: fileURLToPath(
          new URL("../../packages/node-core/src/data/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/node-core/observability",
        replacement: fileURLToPath(
          new URL("../../packages/node-core/src/observability/index.ts", import.meta.url),
        ),
      },
      {
        // Boot golden-fixture refusal (ZTR-1174) imports the consumer kit matcher.
        // Must precede the package-root alias (prefix match).
        find: "@zucoins/node-core/verifier/consumer/pinning",
        replacement: fileURLToPath(
          new URL("../../packages/node-core/src/verifier/consumer/pinning/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/node-core/verifier/consumer",
        replacement: fileURLToPath(
          new URL("../../packages/node-core/src/verifier/consumer/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/node-core",
        replacement: fileURLToPath(
          new URL("../../packages/node-core/src/index.ts", import.meta.url),
        ),
      },
      {
        // Operator-console operations list/detail wire shapes — src/admin-inventory/types.ts
        // imports this subpath, so every suite reaching the admin router needs it.
        find: "@zucoins/generic-node-contracts/admin-inventory",
        replacement: fileURLToPath(
          new URL(
            "../../packages/generic-node-contracts/src/admin-inventory/index.ts",
            import.meta.url,
          ),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/transfer-code",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/transfer-code/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/testkit",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/testkit/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/api-schema",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/api-schema/index.ts", import.meta.url),
        ),
      },
            {
        find: "@zucoins/generic-node-contracts/admin-auth-errors",
        replacement: fileURLToPath(
          new URL(
            "../../packages/generic-node-contracts/src/admin-auth-errors/index.ts",
            import.meta.url,
          ),
        ),
      },
{
        find: "@zucoins/generic-node-contracts/auth-errors",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/auth-errors/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/observation",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/observation/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/amounts",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/amounts/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/operations",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/operations/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/wallet-state",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/wallet-state/index.ts", import.meta.url),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts/route-policy",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/route-policy/index.ts", import.meta.url),
        ),
      },
      {
        // Vault AAD/HKDF builders (node-core pulls this subpath).
        find: "@zucoins/generic-node-contracts/vault",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/vault/index.ts", import.meta.url),
        ),
      },
      {
        // Custody predicates — node-core custody-claim imports this
        // subpath; without the alias, generic-node vitest fails to collect any suite that
        // imports @zucoins/node-core (including metrics-routes /metrics wiring).
        find: "@zucoins/generic-node-contracts/custody",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/custody/index.ts", import.meta.url),
        ),
      },
      {
        // Frozen zp-implementer-event-v1 tuple — node-core's dual-chain event
        // appender imports this subpath, so every generic-node suite that touches
        // @zucoins/node-core needs it. Must precede the package-root alias.
        find: "@zucoins/generic-node-contracts/implementer-events",
        replacement: fileURLToPath(
          new URL(
            "../../packages/generic-node-contracts/src/implementer-events/index.ts",
            import.meta.url,
          ),
        ),
      },
      {
        // Closed recovery-action catalog (halt.contract). Must precede the package-root alias.
        find: "@zucoins/generic-node-contracts/operator-halt",
        replacement: fileURLToPath(
          new URL(
            "../../packages/generic-node-contracts/src/operator-halt/index.ts",
            import.meta.url,
          ),
        ),
      },
      {
        find: "@zucoins/generic-node-contracts",
        replacement: fileURLToPath(
          new URL("../../packages/generic-node-contracts/src/index.ts", import.meta.url),
        ),
      },
    ],
  },
  test: {
    name: "generic-node",
    passWithNoTests: true,
    // Non-PG files only. Real-PostgreSQL suites live in vitest.pg.config.ts (singleFork)
    // so multi-file parallel contention cannot deadlock shared scratch DDL (ZTR-1209).
    include: ["src/**/*.test.ts", "test/**/*.test.ts", "scripts/**/*.test.mjs"],
    exclude: [
      "**/node_modules/**",
      "**/dist/**",
      "**/*.pg.test.ts",
      "**/*-pg.test.ts",
    ],
    // Remaining suites may still open Postgres (e.g. reporting/durable-store). Keep global
    // setup so TEST_DATABASE_URL is assigned under package and root runs alike.
    globalSetup: [fileURLToPath(new URL("../../vitest.global-setup.ts", import.meta.url))],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    setupFiles: [fileURLToPath(new URL("./test/setup-network-guard.ts", import.meta.url))],
  },
});
