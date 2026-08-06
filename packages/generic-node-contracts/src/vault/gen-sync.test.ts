import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { VAULT_CONTRACT } from "./manifest.ts";
import { toSortedPlainObject } from "../testkit/serialize.ts";

const here = dirname(fileURLToPath(import.meta.url));
const genPath = join(here, "..", "..", "gen", "vault.json");

const freshEmit = (): string =>
  `${JSON.stringify(toSortedPlainObject(VAULT_CONTRACT), null, 2)}\n`;

describe("gen/vault.json sync with VAULT_CONTRACT (the vault model freeze tier 2)", () => {
  it("committed snapshot equals a fresh emit", () => {
    expect(readFileSync(genPath, "utf8")).toBe(freshEmit());
  });

  it("rejects a stale committed snapshot (negative path)", () => {
    const stale = `${JSON.stringify(toSortedPlainObject({ ...VAULT_CONTRACT, aad: {} }), null, 2)}\n`;
    expect(() => expect(stale).toBe(freshEmit())).toThrow();
  });
});
