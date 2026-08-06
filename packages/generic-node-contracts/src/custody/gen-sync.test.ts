import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { toSortedPlainObject } from "../testkit/serialize.ts";
import { CUSTODY_CONTRACT } from "./manifest.ts";

const genPath = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "gen", "custody.json");
const freshEmit = (): string => `${JSON.stringify(toSortedPlainObject(CUSTODY_CONTRACT), null, 2)}\n`;

describe("gen/custody.json sync with CUSTODY_CONTRACT", () => {
  it("committed snapshot equals a deterministic fresh emit", () => {
    expect(readFileSync(genPath, "utf8")).toBe(freshEmit());
  });
  it("rejects a stale committed snapshot", () => {
    const stale = `${JSON.stringify(toSortedPlainObject({ ...CUSTODY_CONTRACT, evidence: {} }), null, 2)}\n`;
    expect(stale).not.toBe(freshEmit());
  });
});
