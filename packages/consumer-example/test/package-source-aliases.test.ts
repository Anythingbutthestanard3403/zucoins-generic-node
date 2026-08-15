import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";

import { packageSourceAliases, resolveExportTarget } from "../../../vitest.aliases.ts";

describe("packageSourceAliases conditional exports", () => {
  it("picks import/default/types string from a conditions object", () => {
    expect(resolveExportTarget("./dist/index.js")).toBe("./dist/index.js");
    expect(
      resolveExportTarget({ types: "./dist/index.d.ts", import: "./dist/index.js" }),
    ).toBe("./dist/index.js");
    expect(resolveExportTarget({ default: "./dist/fallback.js" })).toBe("./dist/fallback.js");
    expect(resolveExportTarget({ types: "./dist/index.d.ts" })).toBe("./dist/index.d.ts");
  });

  it("does not throw when a workspace package uses a conditions-object export", () => {
    const dir = mkdtempSync(join(tmpdir(), "vitest-aliases-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({
          name: "@tmp/conditions-export",
          exports: {
            ".": { types: "./dist/index.d.ts", import: "./dist/index.js" },
          },
        }),
      );
      const aliases = packageSourceAliases(pathToFileURL(`${dir}/`));
      expect(aliases).toHaveLength(1);
      expect(aliases[0]?.find).toBe("@tmp/conditions-export");
      expect(aliases[0]?.replacement.endsWith("src/index.ts")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("aliases @zucoins/generic-node-consumer to src/index.ts", () => {
    const aliases = packageSourceAliases(new URL("../../generic-node-consumer/", import.meta.url));
    const root = aliases.find((entry) => entry.find === "@zucoins/generic-node-consumer");
    expect(root).toBeDefined();
    expect(root?.replacement.endsWith("src/index.ts")).toBe(true);
  });
});
