import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";
import { computeProvisioningTarget, computeMintBatch } from "./sizing.js";

// Byte-frozen deterministic capacity table (digest-pinned). Regenerate + re-pin per CONTRACT.md.
const TABLE_SHA256 = "2bc9238701c5cc4a9927151088df412c8ffc49a368b682bcf4a52b3a476fea09";

const tablePath = fileURLToPath(new URL("./__tables__/capacity.table.json", import.meta.url));
const tableBytes = readFileSync(tablePath);
const table = JSON.parse(tableBytes.toString("utf8")) as {
  targets: Array<{ openSessions: number; poolCap: number; target: number }>;
  mintBatches: Array<{ target: number; capCount: number; poolCap: number; mintBatch: number }>;
};

describe("capacity table — byte-frozen, digest-pinned", () => {
  it("matches its pinned sha256 and has no trailing newline", () => {
    expect(createHash("sha256").update(tableBytes).digest("hex")).toBe(TABLE_SHA256);
    expect(tableBytes[tableBytes.length - 1]).not.toBe(0x0a);
  });
});

describe("capacity table — every row reproduced by the live sizing functions", () => {
  it.each(table.targets)("target for open=$openSessions cap=$poolCap is $target", (row) => {
    expect(computeProvisioningTarget(row.openSessions, row.poolCap)).toBe(row.target);
  });
  it.each(table.mintBatches)(
    "mintBatch for target=$target cap=$capCount/$poolCap is $mintBatch",
    (row) => {
      expect(computeMintBatch(row.target, row.capCount, row.poolCap)).toBe(row.mintBatch);
    },
  );
});

describe("capacity table — covers the frozen rule boundary values", () => {
  it("includes the {50,100,110,200} integer-headroom boundary rows", () => {
    const covered = new Set(
      table.targets.filter((r) => r.poolCap === 500).map((r) => r.openSessions),
    );
    for (const boundary of [50, 100, 110, 200]) {
      expect(covered).toContain(boundary);
    }
  });
});
