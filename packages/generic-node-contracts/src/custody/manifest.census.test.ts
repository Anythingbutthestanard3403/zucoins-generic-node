import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CUSTODY_CONCERN_MANIFEST } from "./manifest.ts";

const genPath = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "gen", "custody.json");

describe("CUSTODY_CONCERN_MANIFEST (the custody concern)", () => {
  it("declares the canonical decisions and scan gates", () => {
    expect(CUSTODY_CONCERN_MANIFEST.concernId).toBe("custody");
    expect(CUSTODY_CONCERN_MANIFEST.decisionRefs).toEqual(["custody-classification-policy", "custody-evidence-requirements", "custody-binding-obligations"]);
    expect(CUSTODY_CONCERN_MANIFEST.scanRules).toHaveLength(2);
  });
  it("pins gen/custody.json exactly", () => {
    const ref = CUSTODY_CONCERN_MANIFEST.goldenRefs.find((item) => item.path === "gen/custody.json");
    expect(ref?.sha256).toBe(createHash("sha256").update(readFileSync(genPath)).digest("hex"));
  });
});
