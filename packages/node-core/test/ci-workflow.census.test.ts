import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const REPO_ROOT = fileURLToPath(new URL("../../..", import.meta.url));
const readRepoFile = (path: string): string => readFileSync(`${REPO_ROOT}/${path}`, "utf8");
const workflow = readRepoFile(".github/workflows/ci.yml");

describe("required CI gates", () => {
  it("runs on pull requests and pushes to main", () => {
    expect(workflow).toMatch(/push:\s*\n\s*branches: \[main\]/);
    expect(workflow).toMatch(/pull_request:\s*\n\s*branches: \[main\]/);
  });

  it("fails closed around every doc-11 command gate", () => {
    for (const command of [
      "pnpm build",
      "pnpm lint",
      "pnpm --filter @zucoins/generic-node-contracts test",
      "pnpm test",
      "pnpm test:boundaries",
      "node scripts/check-schema-census.mjs",
      "pnpm --filter @zucoins/generic-node-ui test",
    ]) {
      expect(workflow, `${command} must be a required workflow step`).toContain(`run: ${command}`);
    }
    expect(workflow).not.toContain("continue-on-error");
  });

  it("requires a healthy PostgreSQL service rather than permitting DB skips", () => {
    expect(workflow).toContain("image: postgres:16");
    expect(workflow).toContain('PG_REQUIRED: "1"');
    expect(workflow).toContain('PGHOST: 127.0.0.1');
    expect(workflow).toContain("pg_isready");
  });

  it("runs the real admin browser suite in Chromium", () => {
    expect(workflow).toContain("admin-playwright:");
    expect(workflow).toContain("playwright install --with-deps chromium");
    expect(workflow).toContain("run: pnpm --filter @zucoins/generic-node-ui test:e2e");
  });

  it("keeps both consumer projects on guarded source aliases", () => {
    const consumer = readRepoFile("packages/generic-node-consumer/vitest.config.ts");
    const example = readRepoFile("packages/consumer-example/vitest.config.ts");

    for (const config of [consumer, example]) {
      expect(config).toContain("setup-network-guard.ts");
      expect(config).toContain("packageSourceAliases");
      expect(config).toContain('new URL("../node-core/", import.meta.url)');
    }
  });
});
