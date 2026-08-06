// rejection-site census for the RECEIVE_EXTERNAL disposition surface.
//
// failed dual review three times on guards that could not fail. Hand-listing the
// guards is what let that happen: the list and the code drifted apart silently. This census
// derives the guard set from the source text itself, so the three views — the `GUARD:` markers
// at the rejection sites, the exported RECEIVE_DISPOSITION_GUARDS declaration, and the killing
// tests — cannot disagree without a red test.
//
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { RECEIVE_DISPOSITION_GUARDS, RECEIVE_RELEASE_SEQUENCE } from "./receive-disposition.js";

const SOURCE_PATH = fileURLToPath(new URL("./receive-disposition.ts", import.meta.url));
const TEST_PATH = fileURLToPath(new URL("./receive-disposition.test.ts", import.meta.url));

const source = readFileSync(SOURCE_PATH, "utf8");
const tests = readFileSync(TEST_PATH, "utf8");

/** Every `// GUARD: <id>` marker standing at a rejection site, in source order. */
function markersInSource(): string[] {
  return [...source.matchAll(/^\s*\/\/ GUARD: ([a-z0-9_]+)$/gm)].map((m) => m[1] as string);
}

/** Every guard id named in a killing test's title as `guard=<id>`. */
function guardsCoveredByTests(): string[] {
  return [...tests.matchAll(/\bit\("guard=([a-z0-9_]+)/g)].map((m) => m[1] as string);
}

/**
 * Every `return { ok: false, ... }` in the module. Each one is a rejection site and must
 * carry a marker, so a new refusal path cannot be added without declaring it.
 */
function rejectionReturnCount(): number {
  return [...source.matchAll(/^\s*return \{\s*$\n\s*ok: false,/gm)].length;
}

describe("rejection-site census", () => {
  it("finds guard markers in the source at all", () => {
    // Guards against a regex that silently matches nothing and passes everything below.
    expect(markersInSource().length).toBeGreaterThan(20);
    expect(guardsCoveredByTests().length).toBeGreaterThan(20);
    expect(rejectionReturnCount()).toBeGreaterThan(20);
  });

  it("declares exactly the guards the source marks — no undeclared rejection site", () => {
    const marked = new Set(markersInSource());
    const declared = new Set<string>(RECEIVE_DISPOSITION_GUARDS);
    expect([...marked].filter((g) => !declared.has(g))).toEqual([]);
    expect([...declared].filter((g) => !marked.has(g))).toEqual([]);
  });

  it("covers every declared guard with a named killing test", () => {
    const covered = new Set(guardsCoveredByTests());
    expect(RECEIVE_DISPOSITION_GUARDS.filter((g) => !covered.has(g))).toEqual([]);
  });

  it("names no guard in a test that the source does not mark", () => {
    const marked = new Set(markersInSource());
    expect([...new Set(guardsCoveredByTests())].filter((g) => !marked.has(g))).toEqual([]);
  });

  it("marks every rejection return, so no refusal path is undeclared", () => {
    // Each `return { ok: false` is preceded by exactly one marker; a bare rejection would
    // make the marker count fall short.
    expect(markersInSource().length).toBe(rejectionReturnCount());
  });

  it("declares each guard id exactly once", () => {
    expect(new Set(RECEIVE_DISPOSITION_GUARDS).size).toBe(RECEIVE_DISPOSITION_GUARDS.length);
  });

  it("pushes each release step exactly once, in the normative source order", () => {
    // The ordering is carried by control flow, so this is where it is ratcheted: each step
    // is pushed once, and the pushes appear in the spec's order. A refactor that reorders the
    // steps reddens here rather than passing a runtime branch that could never be false.
    const pushed = [...source.matchAll(/releaseSequence\.push\("([A-Z_0-9]+)"\)/g)].map(
      (m) => m[1] as string,
    );
    expect(pushed).toEqual([...RECEIVE_RELEASE_SEQUENCE]);
  });

  it("never issues a submit, a re-sign or a code re-serve from this surface", () => {
    // The never-blind-retry rule — the disposition surface has no write path to the gateway.
    expect(source).not.toMatch(/\bsubmitTransaction\b|\bsubmit\(/);
    expect(source).not.toMatch(/\bsignText\b|\bcreateSign\b|privateKey/i);
    expect(source).not.toMatch(/\breissueTransferCode\b|\bresendCode\b/);
  });
});
