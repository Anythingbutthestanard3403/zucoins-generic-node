import { describe, expect, it } from "vitest";

import golden from "./gen/artifacts.json" with { type: "json" };
import { sha256OfGolden } from "../testkit/byteGolden.ts";
import { ARTIFACTS_CONCERN_MANIFEST } from "./manifest.ts";

// goldenRefs paths are package-root-relative (e.g. "goldens/artifacts/..."), matching every other
// wired concern's convention; strip the leading "goldens/" to get the byteGolden-relative path.
const GOLDENS_PREFIX = "goldens/";

describe("the artifacts concern manifest freeze", () => {
  it("the frozen artifacts values match the committed gen snapshot", () => {
    expect(JSON.parse(JSON.stringify(ARTIFACTS_CONCERN_MANIFEST.frozenValues))).toEqual(golden);
  });

  it("the ConcernManifest self-registers the artifacts concern with its canonical decisions", () => {
    expect(ARTIFACTS_CONCERN_MANIFEST.concernId).toBe("artifacts");
    expect(ARTIFACTS_CONCERN_MANIFEST.decisionRefs).toContain("artifacts-freeze");
  });

  it("every ConcernManifest goldenRef digest matches the on-disk bytes", () => {
    for (const ref of ARTIFACTS_CONCERN_MANIFEST.goldenRefs) {
      expect(ref.path.startsWith(GOLDENS_PREFIX)).toBe(true);
      expect(sha256OfGolden(ref.path.slice(GOLDENS_PREFIX.length))).toBe(ref.sha256);
    }
  });
});
