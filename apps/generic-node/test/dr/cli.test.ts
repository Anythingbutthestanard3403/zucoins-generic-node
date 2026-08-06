import { describe, expect, it } from "vitest";

import { runDrCli } from "../../src/dr/cli.js";

describe("dr CLI", () => {
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
});
