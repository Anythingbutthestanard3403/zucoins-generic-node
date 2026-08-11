// Regression guard: ZTR-1148 moved DUAL_CONTROL_MODE off a raw env read inside
// full-http-mount.ts and onto the frozen schema, which made the mode a *caller*
// responsibility. That closed the parse-level fail-open and opened a wiring-level one:
// deleting `dualControlMode: config.DUAL_CONTROL_MODE` from main.ts, or hardcoding the
// mount's InMemoryDualControlPolicy to "single_operator", each left tsc green and every
// test passing while a two_human deployment silently approved an EXTERNAL SEND on one
// human — the exact bug the ticket exists to close.
//
// Same shape as destination-service-for-sql-wiring.test.ts: an optional
// ProductionSurfaceConfig field with a `??` fallback and an unpinned main.ts caller.
// That one degraded loudly (a 503); this one degrades silently, so it gets both halves —
// a source census over main.ts's wiring, and a behavioural assert that the mount composes
// the policy from the config it was handed.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { createProductionRouteSurface } from "../src/full-http-mount.js";


/** Non-zero 32-byte test vault root for SqlAdminUserStore composition (ZTR-1134 B3). */
const ZTR_1134_TEST_VAULT_ROOT = Buffer.alloc(32, 0xa7);


const here = dirname(fileURLToPath(import.meta.url));
const mainSrc = readFileSync(join(here, "../src/main.ts"), "utf8");

const NODE_ID = "11111111-1111-4111-8111-111111111111";

// The surface only touches the pool lazily (discovery/registry reads); no route in this
// test drives a query, so an empty result set is enough to construct it.
const fakePool = { query: async () => ({ rows: [] }) } as never;

describe("DUAL_CONTROL_MODE production wiring", () => {
  it("main.ts hands createProductionRouteSurface the validated config value", () => {
    const call = mainSrc.slice(
      mainSrc.indexOf("createProductionRouteSurface({"),
      mainSrc.indexOf("createProductionRouteSurface({") + 4000,
    );
    // Not just "the key appears somewhere in main.ts" — it must be inside the surface
    // config literal, and its value must be the validated field, never a literal mode.
    expect(call).toContain("dualControlMode: config.DUAL_CONTROL_MODE");
    expect(call).not.toMatch(/dualControlMode:\s*"(single_operator|two_human)"/);
  });

  it("main.ts boot log resolves effective mode via dualControlPolicy.getMode (ZTR-1214 D3)", () => {
    // Must not claim "effective" while only printing env DUAL_CONTROL_MODE.
    expect(mainSrc).toMatch(/dualControlPolicy[\s\S]{0,200}getMode\s*\(/);
    expect(mainSrc).toMatch(/dual-control mode env=\$\{envMode\} effective=\$\{effectiveMode\}/);
    expect(mainSrc).not.toMatch(
      /dual-control mode=\$\{config\.DUAL_CONTROL_MODE\}/,
    );
  });

  it("the mount composes the dual-control policy from the mode it was handed", async () => {
    const surface = createProductionRouteSurface({
      nodeId: NODE_ID,
      pool: fakePool,
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      dualControlMode: "two_human",
    });
    // Reads back through the same deps object the admin router mounts, so this also
    // catches dualControlPolicy being dropped from the composition (it has been once).
    // SQL port with empty node_settings uses dualControlMode as defaultMode (ZTR-1214).
    expect(await surface.adminRouteDeps.dualControlPolicy?.getMode()).toBe("two_human");
  });

  it("single_operator is carried through as configured, not as a fallback", async () => {
    const surface = createProductionRouteSurface({
      nodeId: NODE_ID,
      pool: fakePool,
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      dualControlMode: "single_operator",
    });
    expect(await surface.adminRouteDeps.dualControlPolicy?.getMode()).toBe("single_operator");
  });
});
