// Live-chain entry census — a missing public-operation live file must fail, not pass green.
//
// Doc 11 §10 requires a live acceptance entry per public money operation. The dedicated
// vitest.live-chain.config.ts also sets passWithNoTests: false so an empty include globs
// fails; this census is the always-on half that runs in the default gate.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "../../../..");

/** One live entry per public operation kind. */
const LIVE_ENTRIES = [
  {
    kind: "RECEIVE_EXTERNAL",
    file: "packages/node-core/test/live-chain/receive-execute.live.test.ts",
  },
  {
    kind: "SEND_EXTERNAL",
    file: "packages/node-core/test/live-chain/send-execute.live.test.ts",
  },
  {
    kind: "MOVE_INTERNAL",
    file: "packages/node-core/test/live-chain/move-execute.live.test.ts",
  },
] as const;

describe("live-chain public-operation census", () => {
  it.each(LIVE_ENTRIES)("$kind has a live acceptance entry on disk", ({ file }) => {
    expect(existsSync(join(repoRoot, file)), `missing ${file}`).toBe(true);
  });

  it("live-chain config refuses passWithNoTests (absence must not report green)", () => {
    const cfg = readFileSync(
      join(repoRoot, "packages/node-core/vitest.live-chain.config.ts"),
      "utf8",
    );
    expect(cfg).toMatch(/passWithNoTests:\s*false/);
    expect(cfg).not.toMatch(/passWithNoTests:\s*true/);
  });

  it("D10.4 branded submit capability is re-exported from the live-chain types surface", () => {
    const types = readFileSync(join(here, "types.ts"), "utf8");
    expect(types).toContain("enableGatewaySubmit");
    expect(types).toContain("GatewaySubmitCapability");
    expect(types).toMatch(/D10\.4/);
  });
});
