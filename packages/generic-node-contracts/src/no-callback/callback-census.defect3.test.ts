// Attack-census audit correction (defect 3 — comment-masking blind spots). Regressions proving the
// census masks comments (so a comment-only mention is neutral) WITHOUT the two blind spots the audit
// named: it still enters code inside template interpolation (`${...}`), and it understands regex
// literals/classes (so an inner `//` is not misread as a line comment that swallows real code).
//
// CONTRACT_FREEZE.
import { describe, expect, it } from "vitest";

import { maskComments, scanForCallbackSurfaces } from "./callback-census.js";

describe("attack-census defect 3: comment-only mentions are neutral", () => {
  it("does not flag a line-comment mention", () => {
    expect(scanForCallbackSurfaces("// legacy callback_url field, since removed")).toEqual([]);
  });

  it("does not flag a block-comment mention", () => {
    expect(scanForCallbackSurfaces("/* a webhook_url / push_subscription used to live here */")).toEqual([]);
  });

  it("does not flag a slash-joined mention in a comment (webhook/push)", () => {
    // The exact false positive in channels.ts's own doc comment: "webhook/push" -> "/push".
    expect(scanForCallbackSurfaces("// a webhook/push is an implementer projection")).toEqual([]);
  });
});

describe("attack-census defect 3: masking enters template-interpolation code (no false negative)", () => {
  it("preserves code inside ${...}", () => {
    expect(maskComments("const u = `pre${ webhookUrl }post`;")).toContain("webhookUrl");
  });

  it("detects a surface built inside an interpolation", () => {
    expect(scanForCallbackSurfaces("const u = `x${ registerWebhook() }y`;")).toContain("register_push_endpoint");
  });
});

describe("attack-census defect 3: masking understands regex literals/classes", () => {
  it("does not treat an inner // of a regex literal as a comment that swallows real code", () => {
    // /a\/\/b/ contains a literal `//`; a comment-blind masker would blank to end-of-line and lose
    // the real `callback_url` that follows.
    const src = 'const re = /a\\/\\/b/; const field = "callback_url";';
    expect(maskComments(src)).toContain("callback_url");
    expect(scanForCallbackSurfaces(src)).toContain("callback_url_field");
  });

  it("does not treat a / inside a regex char class as a comment", () => {
    const src = 'const re = /[/]webhook_url/; const x = 1;';
    expect(scanForCallbackSurfaces(src)).toContain("webhook_url_field");
  });
});
