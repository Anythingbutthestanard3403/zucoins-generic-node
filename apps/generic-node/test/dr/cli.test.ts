import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { runDrCli } from "../../src/dr/cli.js";

describe("dr CLI", () => {
  const tmpDirs: string[] = [];

  afterEach(async () => {
    for (const d of tmpDirs.splice(0)) {
      await rm(d, { recursive: true, force: true });
    }
  });

  it("prints usage on help", async () => {
    const lines: string[] = [];
    const code = await runDrCli(["help"], {}, {
      log: (l) => lines.push(l),
      error: (l) => lines.push(l),
    });
    expect(code).toBe(0);
    expect(lines.join("\n")).toMatch(/backup/);
    expect(lines.join("\n")).toMatch(/restore/);
    expect(lines.join("\n")).toMatch(/drill/);
    expect(lines.join("\n")).toMatch(/status/);
  });

  it("fails closed without BACKUP_MASTER_KEY on backup", async () => {
    const errs: string[] = [];
    const code = await runDrCli(
      ["backup", "--out", "/tmp/x.zbkp"],
      { DATABASE_URL: "postgresql://localhost/db" },
      { log: () => undefined, error: (l) => errs.push(l) },
    );
    expect(code).toBe(1);
    expect(errs.join("\n")).toMatch(/BACKUP_MASTER_KEY/);
  });

  it("restore fails closed without --in", async () => {
    const errs: string[] = [];
    const code = await runDrCli(
      ["restore"],
      {
        DATABASE_URL: "postgresql://localhost/db",
        BACKUP_MASTER_KEY: "k".repeat(32),
      },
      { log: () => undefined, error: (l) => errs.push(l) },
    );
    expect(code).toBe(1);
    expect(errs.join("\n")).toMatch(/--in/);
  });

  it("restore fails closed without BACKUP_MASTER_KEY", async () => {
    const errs: string[] = [];
    const code = await runDrCli(
      ["restore", "--in", "/tmp/missing.zbkp"],
      { DATABASE_URL: "postgresql://localhost/db" },
      { log: () => undefined, error: (l) => errs.push(l) },
    );
    expect(code).toBe(1);
    expect(errs.join("\n")).toMatch(/BACKUP_MASTER_KEY/);
  });

  it("drill fails closed without BACKUP_MASTER_KEY", async () => {
    const errs: string[] = [];
    const code = await runDrCli(
      ["drill"],
      { DATABASE_URL: "postgresql://localhost/db" },
      { log: () => undefined, error: (l) => errs.push(l) },
    );
    expect(code).toBe(1);
    expect(errs.join("\n")).toMatch(/BACKUP_MASTER_KEY/);
  });

  it("status fails closed without BACKUP_OUTPUT_DIR", async () => {
    const errs: string[] = [];
    const code = await runDrCli(
      ["status"],
      {},
      { log: () => undefined, error: (l) => errs.push(l) },
    );
    expect(code).toBe(1);
    expect(errs.join("\n")).toMatch(/BACKUP_OUTPUT_DIR/);
  });

  it("status reports RPO posture for an empty output dir (no committed artifacts)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ztr-1183-dr-status-"));
    tmpDirs.push(dir);
    const lines: string[] = [];
    const code = await runDrCli(
      ["status"],
      { BACKUP_OUTPUT_DIR: dir },
      { log: (l) => lines.push(l), error: (l) => lines.push(l) },
    );
    // Empty dir → no newest artifact → RPO breached → exit 2.
    expect(code).toBe(2);
    const payload = JSON.parse(lines.find((l) => l.startsWith("{")) ?? "{}") as {
      command?: string;
      rpoBreached?: boolean;
      newestArtifactAtMs?: number | null;
    };
    expect(payload.command).toBe("status");
    expect(payload.rpoBreached).toBe(true);
    expect(payload.newestArtifactAtMs).toBeNull();
  });

  it("status reports newestArtifactAtMs when an envelope file exists (CLI-level, no DB)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ztr-1183-dr-status-ok-"));
    tmpDirs.push(dir);
    // newestBackupArtifactMtimeMs keys on BACKUP_ENVELOPE_EXTENSION (.zbkp).
    await writeFile(join(dir, "generic-node-fixture.zbkp"), Buffer.from("not-a-real-envelope"));
    const lines: string[] = [];
    const code = await runDrCli(
      ["status"],
      { BACKUP_OUTPUT_DIR: dir },
      { log: (l) => lines.push(l), error: (l) => lines.push(l) },
    );
    const payload = JSON.parse(lines.find((l) => l.startsWith("{")) ?? "{}") as {
      command?: string;
      rpoBreached?: boolean;
      newestArtifactAtMs?: number | null;
      outputDir?: string;
      ageMs?: number | null;
    };
    expect(payload.command).toBe("status");
    expect(typeof payload.newestArtifactAtMs).toBe("number");
    expect(payload.newestArtifactAtMs).not.toBeNull();
    // ageMs is computed from wall clock vs mtime; a just-written file is near zero.
    // (isRpoBreached treats mtime slightly ahead of Date.now as breach — do not couple
    // the CLI gate test to that clock edge; empty-dir case already covers breach exit 2.)
    expect(typeof payload.ageMs === "number" || payload.ageMs === null).toBe(true);
    if (typeof payload.ageMs === "number") {
      expect(payload.ageMs).toBeLessThan(60_000);
    }
    // Exit 0 when not breached; exit 2 is also acceptable only if the policy
    // clock edge trips — assert the envelope was discovered either way.
    expect([0, 2]).toContain(code);
  });

  it("markers release refuses with a typed missing-trusted-source reason", async () => {
    const lines: string[] = [];
    const code = await runDrCli(
      ["markers", "release", "--file", "/definitely/missing/continuity.json"],
      {
        DATABASE_URL: "postgresql://localhost/unused",
        NODE_ID: "11111111-1111-4111-8111-111111111111",
      },
      { log: (line) => lines.push(line), error: (line) => lines.push(line) },
    );
    expect(code).toBe(2);
    expect(JSON.parse(lines.find((line) => line.startsWith("{")) ?? "{}")).toMatchObject({
      ok: false,
      command: "markers-release",
      reason: "missing_trusted_source",
    });
  });
});
