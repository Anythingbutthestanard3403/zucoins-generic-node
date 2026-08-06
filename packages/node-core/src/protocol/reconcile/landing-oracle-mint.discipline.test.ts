// production src may not mint LandingPathProof except landing-path oracle producers.
// Governing residual: deep-import string mint outside the complete oracle must not be the
// production settle path; Stage-2 consumers only identity-check issued proofs.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const srcRoot = resolve(here, "../..");

const ALLOWED_MINT_PRODUCTION_RELATIVE = new Set([
  "protocol/reconcile/landing-oracle-mint.ts",
  "protocol/reconcile/landing-oracle-mint.fixture.ts",
  "verifier/landing-path-oracle.ts",
  "verifier/ancestry-walker.ts",
  "send/late-landing-reconcile.ts",
]);

const IMPORT_MINT_CHANNEL = /landing-oracle-mint\.js/;
const IMPORT_FIXTURE = /landing-oracle-mint\.fixture\.js/;
const MINT_IDENTIFIERS =
  /\b(?:mintLandingPathProofFromOracle|mintLandingPathProof|issueLandingOracleSeal)\b/;

function listTsFiles(dir: string): string[] {
  return (readdirSync(dir, { recursive: true }) as string[])
    .map((entry) => join(dir, entry))
    .filter((file) => extname(file) === ".ts" && statSync(file).isFile());
}

function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

describe("landing oracle mint discipline", () => {
  it("non-producer production sources do not import mint channel or call mint identifiers", () => {
    const violations: string[] = [];
    for (const file of listTsFiles(srcRoot)) {
      if (file.endsWith(".test.ts")) continue;
      const rel = relative(srcRoot, file).replaceAll("\\", "/");
      if (ALLOWED_MINT_PRODUCTION_RELATIVE.has(rel)) continue;
      const code = stripComments(readFileSync(file, "utf8"));
      if (rel === "protocol/reconcile/landing-proof.ts") {
        if (MINT_IDENTIFIERS.test(code)) {
          violations.push(`${rel}: exposes mint identifier`);
        }
        continue;
      }
      if (IMPORT_MINT_CHANNEL.test(code)) {
        violations.push(`${rel}: imports landing-oracle-mint`);
      }
      if (IMPORT_FIXTURE.test(code)) {
        violations.push(`${rel}: imports mint fixture outside tests`);
      }
      if (MINT_IDENTIFIERS.test(code)) {
        violations.push(`${rel}: mint identifier`);
      }
    }
    expect(violations).toEqual([]);
  });

  it("landing-proof facade export list does not include mint/seal issue", () => {
    const code = stripComments(
      readFileSync(resolve(srcRoot, "protocol/reconcile/landing-proof.ts"), "utf8"),
    );
    expect(code).not.toMatch(MINT_IDENTIFIERS);
    expect(code).toMatch(/isLandingPathProof/);
    expect(code).toMatch(/revalidateLandingPathProofBindings/);
  });

  it("src tests do not deep-import mint channel (fixture only)", () => {
    const violations: string[] = [];
    for (const file of listTsFiles(srcRoot)) {
      if (!file.endsWith(".test.ts")) continue;
      const code = stripComments(readFileSync(file, "utf8"));
      if (IMPORT_MINT_CHANNEL.test(code)) {
        violations.push(relative(srcRoot, file).replaceAll("\\", "/"));
      }
    }
    expect(violations).toEqual([]);
  });

  it("only test files import the mint fixture", () => {
    const violations: string[] = [];
    for (const file of listTsFiles(srcRoot)) {
      if (file.endsWith(".test.ts")) continue;
      const rel = relative(srcRoot, file).replaceAll("\\", "/");
      if (rel === "protocol/reconcile/landing-oracle-mint.fixture.ts") continue;
      const code = stripComments(readFileSync(file, "utf8"));
      if (IMPORT_FIXTURE.test(code)) {
        violations.push(rel);
      }
    }
    expect(violations).toEqual([]);
  });
});
