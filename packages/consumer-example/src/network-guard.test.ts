import net from "node:net";

import { describe, expect, it } from "vitest";

// test/setup-network-guard.ts is wired in by this package's own vitest.config.ts. The repo-root
// config used to declare this package as an inline project entry, which inherited none of that,
// so these suites were the only ones in `pnpm test` able to reach a real socket. This test fails
// if that wiring is ever dropped again.
describe("network containment", () => {
  it("denies fetch", async () => {
    await expect(fetch("https://unreachable.invalid/")).rejects.toThrow(/network-contained/);
  });

  it("denies a raw socket connect", () => {
    expect(() => net.connect(443, "unreachable.invalid")).toThrow(/network-contained/);
  });
});
