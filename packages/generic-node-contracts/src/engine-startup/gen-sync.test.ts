import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { ENGINE_STARTUP_CONTRACT } from "./manifest.ts";
import { toSortedPlainObject } from "../testkit/serialize.ts";

const here = dirname(fileURLToPath(import.meta.url));
const genPath = join(here, "..", "..", "gen", "engine-startup.json");

const freshEmit = (): string =>
  `${JSON.stringify(toSortedPlainObject(ENGINE_STARTUP_CONTRACT), null, 2)}\n`;

describe("gen/engine-startup.json sync with ENGINE_STARTUP_CONTRACT (the named concern tier 2)", () => {
  it("committed snapshot equals a fresh emit", () => {
    expect(readFileSync(genPath, "utf8")).toBe(freshEmit());
  });

  it("rejects a stale committed snapshot (negative path)", () => {
    const stale = `${JSON.stringify(toSortedPlainObject({ ...ENGINE_STARTUP_CONTRACT, engines: {} }), null, 2)}\n`;
    expect(() => expect(stale).toBe(freshEmit())).toThrow();
  });
});
