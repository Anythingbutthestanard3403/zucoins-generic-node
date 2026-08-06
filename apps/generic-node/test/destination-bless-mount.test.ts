// Production main mounts live device blessing authorizer (not fail-closed stub).
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const mainSrc = readFileSync(join(here, "../src/main.ts"), "utf8");

describe("destination bless production mount", () => {
  it("wires createDeviceBlessingAuthorizer (not a null-returning stub)", () => {
    expect(mainSrc).toContain("createDeviceBlessingAuthorizer");
    expect(mainSrc).toContain("createSqlActiveDeviceLookup");
    expect(mainSrc).toContain("createSqlBlessingArtifactPersister");
    expect(mainSrc).not.toMatch(
      /blessingAuthorizer:\s*\{[\s\S]*?async authorize\(\)\s*\{[\s\S]*?return null/,
    );
  });

  it("does not log private key material scaffolding in the bless mount path", () => {
    const blessRegion = mainSrc.slice(
      mainSrc.indexOf("createDeviceBlessingAuthorizer"),
      mainSrc.indexOf("createDeviceBlessingAuthorizer") + 800,
    );
    expect(blessRegion).not.toMatch(/privateKey|PRIVATE KEY|secretKey/i);
  });
});
