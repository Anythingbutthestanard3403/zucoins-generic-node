import { describe, expect, it } from "vitest";
import { deriveLiveConnectionParams } from "./run-recovery-ceremony.js";

describe("deriveLiveConnectionParams", () => {
  it("swaps only the database segment, preserving host/port/credentials", () => {
    const connectionString = deriveLiveConnectionParams(
      "postgres://ceremony_user:s3cr%40t@db.internal.example.com:5555/mydb",
      "postgres",
    );
    const parsed = new URL(connectionString);
    expect(parsed.hostname).toBe("db.internal.example.com");
    expect(parsed.port).toBe("5555");
    expect(parsed.username).toBe("ceremony_user");
    expect(parsed.pathname).toBe("/postgres");
  });

  it("preserves a URL-encoded password byte-for-byte", () => {
    const connectionString = deriveLiveConnectionParams(
      "postgres://ceremony_user:s3cr%40t@db.internal.example.com:5555/mydb",
      "run_recovery_ceremony_restore_abc123",
    );
    expect(connectionString).toContain("s3cr%40t");
  });

  it("preserves sslmode and other query params", () => {
    const connectionString = deriveLiveConnectionParams(
      "postgres://user:pass@db.example.com/mydb?sslmode=require",
      "postgres",
    );
    const parsed = new URL(connectionString);
    expect(parsed.pathname).toBe("/postgres");
    expect(parsed.searchParams.get("sslmode")).toBe("require");
  });

  it("preserves an omitted port rather than defaulting it", () => {
    const connectionString = deriveLiveConnectionParams(
      "postgres://user:pass@db.example.com/mydb",
      "postgres",
    );
    expect(new URL(connectionString).port).toBe("");
  });

  it("handles a unix-socket DSN (host= query, empty URL host)", () => {
    const connectionString = deriveLiveConnectionParams(
      "postgres://ceremony_user@/mydb?host=/var/run/postgresql",
      "run_recovery_ceremony_restore_abc123",
    );
    const parsed = new URL(connectionString);
    expect(parsed.pathname).toBe("/run_recovery_ceremony_restore_abc123");
    expect(parsed.searchParams.get("host")).toBe("/var/run/postgresql");
  });
});
