import { cpus } from "node:os";

/**
 * : the single canonical Vitest execution policy for this package.
 *
 * Before this module the same test files ran under two different budgets: the repo-root
 * project (vitest.config.ts) sets `testTimeout`/`hookTimeout` to 30 s and its
 * `packages/*\/src/**` include glob matched this package, while
 * `pnpm --dir packages/generic-node-contracts test` used the package config, which set no
 * timeouts at all and therefore inherited Vitest's 5 s default. A test whose real work takes
 * ~3 s passed under one command and timed out under the other, which is exactly the
 * run-to-run variance reports. The root config now routes this package to its own
 * standalone project, so both commands execute this one policy.
 *
 * The package default stays at Vitest's 5 s. Only the three classes measured to need more
 * are widened, per class, by the constants below — no blanket raise, and each stays far
 * under any genuine hang.
 */

/**
 * Measured uncontended worst case per class (11-core darwin, `vitest --reporter=verbose`,
 * one file at a time, 2026-07-25 at origin/main 315cfd51):
 *
 * - `ed25519`  — 2,889 ms ("the lenient reference verifier is faithful"); the twelve
 *   cofactored-verification cases are pure CPU and degrade the most under fork
 *   oversubscription. 20,000 ms is ~7x the measured worst case.
 * - `realTree` — 2,914 ms ("no module REACHES a network/DB/worker/process specifier");
 *   every real-tree scan walks and reads ~1,200 files synchronously and is I/O bound.
 *   15,000 ms is ~5x the measured worst case.
 * - `fuzz500`  — 302 ms for a 500-run property; the default 5 s is only 16x that, and the
 *   ticket still observed a contended fuzz timeout. 15,000 ms restores real headroom.
 *
 * A hung verifier or an unbounded scan never returns, so every class still fails closed.
 */
export const EXECUTION_TIMEOUTS = Object.freeze({
  ed25519: 20_000,
  realTree: 15_000,
  fuzz500: 15_000,
});

/**
 * Vitest's default fork count is the full CPU count. On an 11-core box the canonical run
 * spent 85 s in `prepare` and 18 s in `transform` alone — every fork transpiling at once,
 * starving the CPU-bound crypto cases past their timeout. Halving the pool removes that
 * oversubscription while keeping file parallelism on; the ceiling of 4 keeps the policy
 * comparable across machines.
 */
export const maxTestForks = (): number => Math.max(2, Math.min(4, Math.floor(cpus().length / 2)));
