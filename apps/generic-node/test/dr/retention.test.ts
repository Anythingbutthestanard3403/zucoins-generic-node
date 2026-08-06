import { mkdtemp, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { pruneRetainedBackups } from "../../src/dr/retention.js";

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function touch(path: string, mtimeMs: number): Promise<void> {
  const at = new Date(mtimeMs);
  await utimes(path, at, at);
}

describe("pruneRetainedBackups", () => {
  it("prunes .zbkp older than retention and keeps recent + non-backup files", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gn-ret-"));
    dirs.push(dir);
    const now = Date.UTC(2026, 6, 26);
    const oldPath = join(dir, "old.zbkp");
    const newPath = join(dir, "new.zbkp");
    const other = join(dir, "notes.txt");
    await writeFile(oldPath, "x");
    await writeFile(newPath, "y");
    await writeFile(other, "z");
    await touch(oldPath, now - 20 * 24 * 60 * 60 * 1000);
    await touch(newPath, now - 2 * 24 * 60 * 60 * 1000);
    await touch(other, now - 40 * 24 * 60 * 60 * 1000);

    const report = await pruneRetainedBackups({
      directory: dir,
      retentionDays: 14,
      nowMs: now,
    });
    expect(report.pruned).toEqual(["old.zbkp"]);
    expect(report.kept).toEqual(["new.zbkp"]);
    expect(report.skipped).toContain("notes.txt");
  });
});
