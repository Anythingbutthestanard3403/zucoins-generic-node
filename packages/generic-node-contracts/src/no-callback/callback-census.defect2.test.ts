// Attack-census audit correction (defect 2 — exemption over-breadth + verb-variant census). Regressions:
//  (a) the directory-prefix exemption is separator-bounded, so a sibling like no-callback-evil/ is
//      NOT exempt; (b) the concern exemption is scoped to known metadata contexts, so a real
//      send-side URL is a detected label that is NOT in the frozen-golden allowlist (i.e. it cannot
//      hide inside a concern file); (c) the matrix covers callback/webhook/push verb variants.
//
// CONTRACT_FREEZE.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { isConcernPathExempt, scanForCallbackSurfaces } from "./callback-census.js";

const THIS_DIR = dirname(fileURLToPath(import.meta.url));

// The allowlist of labels the no-callback concern may declare, derived from its two frozen goldens.
const CONCERN_ALLOWED_LABELS = new Set([
  ...scanForCallbackSurfaces(readFileSync(resolve(THIS_DIR, "gen/no-callback.json"), "utf8")),
  ...scanForCallbackSurfaces(readFileSync(resolve(THIS_DIR, "gen/attack-surface.json"), "utf8")),
]);

describe("attack-census defect 2: directory-prefix exemption is separator-bounded", () => {
  it("does not swallow a sibling no-callback-evil/ tree", () => {
    expect(isConcernPathExempt("/x/src/no-callback-evil/leak.ts", "/x/src/no-callback")).toBe(false);
  });

  it("still exempts the concern dir itself and its files", () => {
    expect(isConcernPathExempt("/x/src/no-callback", "/x/src/no-callback")).toBe(true);
    expect(isConcernPathExempt("/x/src/no-callback/manifest.ts", "/x/src/no-callback")).toBe(true);
    expect(isConcernPathExempt("/x/src/no-callback/gen/no-callback.json", "/x/src/no-callback")).toBe(true);
  });
});

describe("attack-census defect 2: concern exemption is scoped to known metadata contexts", () => {
  it("a real send-side URL is detected and is NOT an allowlisted metadata label", () => {
    const labels = scanForCallbackSurfaces('const leak = "https://operator.example/hook";');
    expect(labels).toContain("outbound_url_literal");
    // Not present in the frozen goldens, so it cannot hide inside a concern file either.
    expect(CONCERN_ALLOWED_LABELS.has("outbound_url_literal")).toBe(false);
  });

  it("a real callback route is detected and is NOT an allowlisted metadata label", () => {
    const labels = scanForCallbackSurfaces('router.post("/callbacks", handler);');
    expect(labels).toContain("callback_route");
    expect(CONCERN_ALLOWED_LABELS.has("callback_route")).toBe(false);
  });
});

describe("attack-census defect 2: matrix covers callback/webhook/push verb variants", () => {
  it("catches webhook variants", () => {
    expect(scanForCallbackSurfaces("registerWebhook(cfg)")).toContain("register_push_endpoint");
    expect(scanForCallbackSurfaces('const webhook_url = "";')).toContain("webhook_url_field");
    expect(scanForCallbackSurfaces('app.get("/webhooks", h)')).toContain("webhook_route");
    expect(scanForCallbackSurfaces("emitWebhook(evt)")).toContain("dispatch_push");
  });

  it("catches push variants", () => {
    expect(scanForCallbackSurfaces("const push_subscription = {}")).toContain("push_subscription");
    expect(scanForCallbackSurfaces('const push_url = "";')).toContain("push_url_field");
    expect(scanForCallbackSurfaces('fetch("/push/register")')).toContain("push_route");
  });

  it("does not flag legitimately-named identifiers (register/delivery/subscription noise)", () => {
    expect(scanForCallbackSurfaces("buildRegisterPreimage(payload)")).toEqual([]);
    expect(scanForCallbackSurfaces("evaluateConcurrentRedelivery(keys, false)")).toEqual([]);
    expect(scanForCallbackSurfaces("const subscription_handle = hash;")).toEqual([]);
    expect(scanForCallbackSurfaces("items.push(row);")).toEqual([]);
  });
});
