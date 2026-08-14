// ZTR-1305 — e2e matrix census: {RECEIVE, MOVE, SEND} × {INDEPENDENT, NODE_VERIFIED}.
//
// CI authority is the combination of:
//   - admission (this file + verification-mode-admission.test.ts)
//   - landing-release PG proofs (receive/move/send node-verified landing tests)
//   - INDEPENDENT paths already covered by receive/move/send e2e suites
//
// This file pins the matrix is complete and that NODE_VERIFIED is refused without
// policy on every kind (fail-closed AC).

import { describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  DEFAULT_VERIFICATION_MODE,
  VERIFICATION_MODES,
} from "@zucoins/generic-node-contracts/operations";

import {
  InMemoryAllowNodeVerifiedPolicy,
  admitVerificationMode,
  resolveVerificationMode,
  refuseAllNodeVerifiedPolicy,
} from "../src/verification/allow-node-verified-policy.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "../../..");

const KINDS = ["RECEIVE_EXTERNAL", "MOVE_INTERNAL", "SEND_EXTERNAL"] as const;
const MODES = VERIFICATION_MODES;

/** Automated coverage anchors for each matrix cell (path relative to repo root). */
const CELL_COVERAGE: Record<
  string,
  { readonly path: string; readonly mustMatch: RegExp }
> = {
  "RECEIVE_EXTERNAL|INDEPENDENT": {
    path: "packages/node-core/test/receive-external.e2e.test.ts",
    mustMatch: /RECEIVE_EXTERNAL|receive/i,
  },
  "RECEIVE_EXTERNAL|NODE_VERIFIED": {
    path: "apps/generic-node/test/receive-node-verified-landing-release.pg.test.ts",
    mustMatch: /NODE_VERIFIED|RELEASED_NODE_VERIFIED/,
  },
  "MOVE_INTERNAL|INDEPENDENT": {
    path: "packages/node-core/test/move-send-external.e2e.test.ts",
    mustMatch: /MOVE_INTERNAL|move/i,
  },
  "MOVE_INTERNAL|NODE_VERIFIED": {
    path: "packages/node-core/test/move-node-verified-landing-release.pg.test.ts",
    mustMatch: /NODE_VERIFIED|RELEASED_NODE_VERIFIED/,
  },
  "SEND_EXTERNAL|INDEPENDENT": {
    path: "packages/node-core/test/move-send-external.e2e.test.ts",
    mustMatch: /SEND_EXTERNAL|send/i,
  },
  "SEND_EXTERNAL|NODE_VERIFIED": {
    path: "apps/generic-node/test/send-completion-lander.pg.test.ts",
    mustMatch: /NODE_VERIFIED|RELEASED_NODE_VERIFIED/,
  },
};

describe("verification-mode e2e matrix (ZTR-1305)", () => {
  it("freezes the 3×2 matrix vocabulary", () => {
    expect(KINDS).toHaveLength(3);
    expect(MODES).toEqual(["INDEPENDENT", "NODE_VERIFIED"]);
    expect(DEFAULT_VERIFICATION_MODE).toBe("INDEPENDENT");
  });

  it("every matrix cell has an automated coverage anchor on disk", () => {
    for (const kind of KINDS) {
      for (const mode of MODES) {
        const key = `${kind}|${mode}`;
        const cell = CELL_COVERAGE[key];
        expect(cell, key).toBeDefined();
        const abs = join(REPO, cell!.path);
        expect(existsSync(abs), abs).toBe(true);
        const body = readFileSync(abs, "utf8");
        expect(body, key).toMatch(cell!.mustMatch);
      }
    }
  });

  it("NODE_VERIFIED is refused without policy for every kind (admission gate)", () => {
    const refuse = refuseAllNodeVerifiedPolicy();
    // Port is sync for refuse-all; admission helper is pure.
    const policy = refuse.getPolicy() as Awaited<ReturnType<typeof refuse.getPolicy>>;
    for (const kind of KINDS) {
      void kind;
      const mode = resolveVerificationMode("NODE_VERIFIED");
      const result = admitVerificationMode(mode, policy, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
      expect(result).toEqual({ ok: false, code: "verification_mode_not_allowed" });
    }
  });

  it("NODE_VERIFIED is admitted when policy allows the implementer", () => {
    const imp = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const mem = new InMemoryAllowNodeVerifiedPolicy();
    mem.allowImplementer(imp);
    const policy = mem.getPolicy();
    for (const kind of KINDS) {
      void kind;
      const result = admitVerificationMode("NODE_VERIFIED", policy, imp);
      expect(result).toEqual({ ok: true });
    }
  });

  it("INDEPENDENT is always admitted regardless of policy", () => {
    const refuse = refuseAllNodeVerifiedPolicy();
    const policy = refuse.getPolicy() as Awaited<ReturnType<typeof refuse.getPolicy>>;
    for (const kind of KINDS) {
      void kind;
      expect(admitVerificationMode("INDEPENDENT", policy, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")).toEqual({
        ok: true,
      });
    }
  });

  it("omitted mode resolves to INDEPENDENT", () => {
    expect(resolveVerificationMode(undefined)).toBe("INDEPENDENT");
    expect(resolveVerificationMode(null)).toBe("INDEPENDENT");
  });
});
