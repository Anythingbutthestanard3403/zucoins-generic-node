import net from "node:net";

import { describe, expect, it } from "vitest";

// src/setup-network-guard.ts is wired in by this package's own vite.config.ts. The repo-root
// config did not list this package as a project at all, so none of the operator SPA's suites ran
// in `pnpm test` and nothing proved they stayed off the network. This test fails if that wiring
// is ever dropped again — the census in packages/node-core/test only proves it is *declared*.
describe("network containment", () => {
  it("denies fetch", async () => {
    await expect(fetch("https://unreachable.invalid/")).rejects.toThrow(/network-contained/);
  });

  it("denies the jsdom XHR and WebSocket surfaces a component would reach for", () => {
    expect(() => new XMLHttpRequest()).toThrow(/network-contained/);
    expect(() => new WebSocket("wss://unreachable.invalid/")).toThrow(/network-contained/);
  });

  it("denies a raw socket connect", () => {
    expect(() => net.connect(443, "unreachable.invalid")).toThrow(/network-contained/);
  });
});
