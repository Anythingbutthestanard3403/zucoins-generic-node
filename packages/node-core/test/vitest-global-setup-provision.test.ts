/**
 * Unit coverage for vitest.global-setup.ts contention handling (ZTR-1204).
 *
 * Does not open PostgreSQL — only classifies spawn errors and exercises the
 * bounded retry helper so a silent soft-skip after ETIMEDOUT cannot regress.
 */
import { describe, expect, it, vi } from "vitest";
import {
  classifyPsqlError,
  PROVISION_ATTEMPTS,
  sleepSync,
  withPsqlRetries,
} from "../../../vitest.global-setup.ts";

describe("vitest.global-setup provision helpers (ZTR-1204)", () => {
  it("classifies execFileSync timeout as transient (lane contention)", () => {
    expect(
      classifyPsqlError(Object.assign(new Error("spawnSync psql ETIMEDOUT"), { code: "ETIMEDOUT", signal: "SIGTERM" })),
    ).toBe("transient");
  });

  it("classifies too-many-clients server text as transient", () => {
    expect(
      classifyPsqlError({
        message: "psql failed",
        stderr: "FATAL:  sorry, too many clients already\n",
      }),
    ).toBe("transient");
  });

  it("classifies connection refused as absent (no Postgres)", () => {
    expect(
      classifyPsqlError(
        Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:5432"), { code: "ECONNREFUSED" }),
      ),
    ).toBe("absent");
  });

  it("classifies plain SQL errors as other (no retry laundry)", () => {
    expect(
      classifyPsqlError({
        message: "psql failed",
        stderr: 'ERROR:  syntax error at or near "CREAT"\n',
      }),
    ).toBe("other");
  });

  it("withPsqlRetries retries transient then throws a loud wrapped error", () => {
    let calls = 0;
    const started = Date.now();
    expect(() =>
      withPsqlRetries(() => {
        calls += 1;
        throw Object.assign(new Error("spawnSync psql ETIMEDOUT"), {
          code: "ETIMEDOUT",
          signal: "SIGTERM",
        });
      }, "CREATE DATABASE testdb_unit"),
    ).toThrow(/failed after \d+ attempts under PostgreSQL contention/);
    expect(calls).toBe(PROVISION_ATTEMPTS);
    // Backoff should have slept at least one interval (allow clock skew).
    expect(Date.now() - started).toBeGreaterThanOrEqual(50);
  });

  it("withPsqlRetries does not retry absent errors", () => {
    let calls = 0;
    expect(() =>
      withPsqlRetries(() => {
        calls += 1;
        throw Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
      }, "probe"),
    ).toThrow(/ECONNREFUSED/);
    expect(calls).toBe(1);
  });

  it("withPsqlRetries succeeds after a transient blip", () => {
    let calls = 0;
    withPsqlRetries(() => {
      calls += 1;
      if (calls < 3) {
        throw Object.assign(new Error("spawnSync psql ETIMEDOUT"), {
          code: "ETIMEDOUT",
          signal: "SIGTERM",
        });
      }
    }, "CREATE DATABASE ok");
    expect(calls).toBe(3);
  });

  it("sleepSync waits approximately the requested duration", () => {
    const spy = vi.spyOn(Atomics, "wait");
    sleepSync(0);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
    const t0 = Date.now();
    sleepSync(30);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(20);
  });
});
