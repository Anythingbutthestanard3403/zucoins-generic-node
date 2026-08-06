import { describe, expect, it } from "vitest";

import golden from "./gen/approval.json" with { type: "json" };
import { sha256OfGolden } from "../testkit/byteGolden.ts";
import { APPROVAL_CONCERN_MANIFEST, buildApprovalManifest } from "./manifest.ts";

const GOLDENS_PREFIX = "goldens/";

describe("the approval concern manifest freeze", () => {
  it("the serialized approval manifest matches the committed gen snapshot", () => {
    expect(buildApprovalManifest()).toEqual(golden);
  });

  it("the ConcernManifest self-registers the approval concern with its canonical decisions", () => {
    expect(APPROVAL_CONCERN_MANIFEST.concernId).toBe("approval");
    expect(APPROVAL_CONCERN_MANIFEST.decisionRefs).toContain("approval-tuple-freeze");
    expect(APPROVAL_CONCERN_MANIFEST.decisionRefs).toContain("two-timer-separation");
    expect(APPROVAL_CONCERN_MANIFEST.goldenRefs).toHaveLength(3);
  });

  it("every ConcernManifest goldenRef digest matches the on-disk bytes", () => {
    for (const ref of APPROVAL_CONCERN_MANIFEST.goldenRefs) {
      expect(ref.path.startsWith(GOLDENS_PREFIX)).toBe(true);
      expect(sha256OfGolden(ref.path.slice(GOLDENS_PREFIX.length))).toBe(ref.sha256);
    }
  });
});
