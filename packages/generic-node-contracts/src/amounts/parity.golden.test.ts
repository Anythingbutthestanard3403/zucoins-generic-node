import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";
import { emitAmount } from "./emitter.js";

// Byte-frozen golden: any edit to the vectors file must be a deliberate re-pin of this
// digest. See CONTRACT.md for the vectors' provenance and the regeneration command.
const GOLDEN_SHA256 = "76d1ec5fda143cc12c22f10486335eae9b1e899d62ac1db9895d1dd3cb5f218d";

const goldenPath = fileURLToPath(new URL("./__vectors__/emission.golden.json", import.meta.url));
const goldenBytes = readFileSync(goldenPath);
const vectors = JSON.parse(goldenBytes.toString("utf8")) as Array<[string, string]>;

describe("emission golden — byte-frozen, digest-pinned", () => {
  it("file bytes match the pinned sha256", () => {
    expect(createHash("sha256").update(goldenBytes).digest("hex")).toBe(GOLDEN_SHA256);
  });
  it("has no trailing newline", () => {
    expect(goldenBytes[goldenBytes.length - 1]).not.toBe(0x0a);
  });
});

describe("emission parity — emitAmount reproduces the splitchain amount vectors", () => {
  it.each(vectors)("emitAmount(%j) === %j", (input, expected) => {
    expect(emitAmount(input)).toBe(expected);
  });
});
