import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { LANDING_PROOF_CONTRACT } from "./manifest.ts";
import { toSortedPlainObject } from "../testkit/serialize.ts";

const here = dirname(fileURLToPath(import.meta.url));
const genPath = join(here, "..", "..", "gen", "landing-proof.json");

const freshEmit = (): string =>
  `${JSON.stringify(toSortedPlainObject(LANDING_PROOF_CONTRACT), null, 2)}\n`;

describe("gen/landing-proof.json sync with LANDING_PROOF_CONTRACT (the landing-proof concern tier 2)", () => {
  it("committed snapshot equals a fresh emit", () => {
    expect(readFileSync(genPath, "utf8")).toBe(freshEmit());
  });

  it("rejects a stale committed snapshot (negative path)", () => {
    const stale = `${JSON.stringify(toSortedPlainObject({ ...LANDING_PROOF_CONTRACT, linkage: {} }), null, 2)}\n`;
    expect(() => expect(stale).toBe(freshEmit())).toThrow();
  });
});
