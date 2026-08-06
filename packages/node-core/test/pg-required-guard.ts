// Shared fail-closed harness guard for PG-gated vitest suites.
//
// A vitest suite whose beforeAll throws reports its tests as `skipped`, not failed. Under
// PG_REQUIRED=1 that is a BROKEN HARNESS, never "no Postgres here" — otherwise a money-path
// suite can report green having proven nothing. Register this top-level (outside any
// describe.skipIf) so the guard still runs when the live block skips itself.
//
// Callers own a mutable readiness flag set to true only at the END of a successful beforeAll
// (or equivalent setup). The guard reads it via isReady() so a throwing setup leaves the flag
// false and the guard fails.

import { expect, it } from "vitest";

export interface PgRequiredGuardOptions {
  /** Short suite label used in the generated test name. */
  readonly name: string;
  /** process.env.TEST_DATABASE_URL (may be undefined / empty when global-setup did not provision). */
  readonly databaseUrl: string | undefined;
  /** True only when the live block's setup completed successfully. */
  readonly isReady: () => boolean;
  readonly urlMessage?: string;
  readonly readyMessage?: string;
}

/**
 * Registers a top-level `it(...)` that fails under PG_REQUIRED=1 when the live block
 * would otherwise silently skip. No-ops when PG_REQUIRED is unset (optional local runs).
 */
export function registerPgRequiredGuard(options: PgRequiredGuardOptions): void {
  it(`${options.name} must execute under PG_REQUIRED=1 (no silent skip)`, () => {
    if (process.env.PG_REQUIRED !== "1") return;
    expect(
      options.databaseUrl,
      options.urlMessage ??
        "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts provisioned no test database, so the live block skipped",
    ).toBeTruthy();
    expect(
      options.isReady(),
      options.readyMessage ??
        "PG_REQUIRED=1 but the suite beforeAll never completed — live assertions were skipped, not proven",
    ).toBe(true);
  });
}
