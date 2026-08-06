import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { OBSERVATION_CONTRACT } from "./manifest.ts";
import { toSortedPlainObject } from "../testkit/serialize.ts";

const here = dirname(fileURLToPath(import.meta.url));
const genPath = join(here, "..", "..", "gen", "observation.json");

const freshEmit = (): string =>
  `${JSON.stringify(toSortedPlainObject(OBSERVATION_CONTRACT), null, 2)}\n`;

describe("gen/observation.json sync with OBSERVATION_CONTRACT (the observation dedup freeze tier 2)", () => {
  it("committed snapshot equals a fresh emit", () => {
    expect(readFileSync(genPath, "utf8")).toBe(freshEmit());
  });

  it("rejects a stale committed snapshot (negative path)", () => {
    const stale = `${JSON.stringify(toSortedPlainObject({ ...OBSERVATION_CONTRACT, dedup: {} }), null, 2)}\n`;
    expect(() => expect(stale).toBe(freshEmit())).toThrow();
  });
});
