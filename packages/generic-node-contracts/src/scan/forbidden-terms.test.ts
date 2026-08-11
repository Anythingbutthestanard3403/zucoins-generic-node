import { globSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  FORBIDDEN_TERMS,
  scanTextForForbiddenTerms,
  countExemptionMarkers,
  countSuppressedViolations,
  FROZEN_EXEMPTION_COUNT,
  FROZEN_SUPPRESSED_VIOLATION_COUNT,
  SCAN_SCOPE,
} from "./forbidden-terms.ts";
import { D99_ALLOWLIST } from "./allowlist.d99.ts";
import { assertFieldOrder } from "../testkit/freeze.ts";

describe("forbidden-terms scanner self-test (the scan/dependency-boundary gate)", () => {
  it("catches every forbidden category when present, unmarked", () => {
    const fixture = FORBIDDEN_TERMS.map((term) => `this line mentions ${term} in prose.`).join(
      "\n",
    );
    const violations = scanTextForForbiddenTerms(fixture, "fixture.ts");
    const caughtTerms = new Set(violations.map((violation) => violation.term));
    for (const term of FORBIDDEN_TERMS) {
      expect(caughtTerms.has(term)).toBe(true);
    }
    expect(violations).toHaveLength(FORBIDDEN_TERMS.length);
  });

  it("produces zero hits for every the compatibility-literal preservation rule allowlisted literal", () => {
    const fixture = D99_ALLOWLIST.map((literal) => `identifier uses ${literal} here.`).join(
      "\n",
    );
    const violations = scanTextForForbiddenTerms(fixture, "fixture.ts", D99_ALLOWLIST);
    expect(violations).toEqual([]);
  });

  it("pins D99_ALLOWLIST at exactly its frozen 13 entries, in sequence, so it cannot grow silently (F3 hardening)", () => {
    assertFieldOrder(D99_ALLOWLIST, [
      "zp-receive-expected-v1",
      "zp-move-internal-expected-v1",
      "zp-send-external-expected-v1",
      "zp-node-event-v1",
      "zp1:",
      "X-ZP-",
      "zupay",
      "zupayments",
      "reservation.*",
      "payment.*",
      "checkout.*",
      "refund.*",
      "apps/node/src/checkout/sdk-route.ts",
    ]);
    expect(D99_ALLOWLIST).toHaveLength(13);
  });

  it("does not flag zupay/zupayments as a payment hit (word-boundary tokenizer)", () => {
    const violations = scanTextForForbiddenTerms(
      "zupayments and zupay are retained compatibility names.",
      "fixture.ts",
    );
    expect(violations).toEqual([]);
  });

  it("exempts a contract-allow marked historical-quote line", () => {
    const violations = scanTextForForbiddenTerms(
      'const RETIRED = "/v1/refunds*"; // contract-allow:retired-route-citation',
      "fixture.ts",
    );
    expect(violations).toEqual([]);
  });

  it("does not exempt an unmarked line merely for sharing a file with a marked one", () => {
    const fixture = [
      'const RETIRED = "/v1/refunds*"; // contract-allow:retired-route-citation',
      'const ACCIDENTAL = "this is a checkout flow";',
    ].join("\n");
    const violations = scanTextForForbiddenTerms(fixture, "fixture.ts");
    expect(violations).toHaveLength(1);
    expect(violations[0]?.term).toBe("checkout");
    expect(violations[0]?.line).toBe(2);
  });

  it("flags the three-generic-operation rule treasury and withdrawal product projections", () => {
    const violations = scanTextForForbiddenTerms(
      ["this line mentions treasury operations.", "this line mentions a withdrawal flow."].join(
        "\n",
      ),
      "fixture.ts",
    );
    const caughtTerms = new Set(violations.map((violation) => violation.term));
    expect(caughtTerms.has("treasury")).toBe(true);
    expect(caughtTerms.has("withdrawal")).toBe(true);
  });

  it("catches plural and inflected forms via conservative suffix stripping", () => {
    const fixture = [
      "this line mentions payments in prose.",
      "this line mentions sweeps and sweeping today.",
      "this line mentions treasuries here.",
      "this line mentions withdrawals here.",
      "this line mentions refunded amounts.",
      // `draining` moved to the AC5 stem allowlist ("draining a queue" is structural), so
      // the `drain` stem is exercised here through the plural instead.
      "this line mentions the pool drains today.",
      "this line mentions orders and payouts.",
    ].join("\n");
    const violations = scanTextForForbiddenTerms(fixture, "fixture.ts");
    const caughtTerms = new Set(violations.map((violation) => violation.term));
    expect(caughtTerms.has("payment")).toBe(true);
    expect(caughtTerms.has("sweep")).toBe(true);
    expect(caughtTerms.has("treasury")).toBe(true);
    expect(caughtTerms.has("withdrawal")).toBe(true);
    expect(caughtTerms.has("refund")).toBe(true);
    expect(caughtTerms.has("drain")).toBe(true);
    expect(caughtTerms.has("order")).toBe(true);
    expect(caughtTerms.has("payout")).toBe(true);
  });

  it("does not decompose zupayments/zupay into a forbidden stem under suffix stripping", () => {
    const violations = scanTextForForbiddenTerms(
      "the zupayments api and zupay sdk ship unchanged; zupayments' rollout continues.",
      "fixture.ts",
    );
    expect(violations).toEqual([]);
  });

  it("the live marked-line count in the frozen scan scope matches FROZEN_EXEMPTION_COUNT", () => {
    // SCAN_SCOPE-wide, not this package alone. FROZEN_EXEMPTION_COUNT's doc says "across the
    // scanned tree", and coupling-exceptions.manifest.test.ts counts the same way; walking only
    // this package's src/ was equivalent while every marker lived here, but SCAN_SCOPE grew to
    // packages/node-core/src and apps/generic-node/src (2026-07-19) and a marker landing there
    // was then invisible to this freeze while still moving the manifest's count — the two gates
    // pinned the same constant to two different populations. src/scan/** stays
    // excluded for the same self-reference reason generic-core.scan-gate.test.ts excludes it.
    // `.md` files are counted alongside `.ts` (the minimum-tripwire concern.2): the scan gate scans them, so their
    // markers must be counted too.
    const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
    const files = SCAN_SCOPE.flatMap((scopePath) => [
      ...globSync(join(repoRoot, scopePath, "**", "*.ts")),
      ...globSync(join(repoRoot, scopePath, "**", "*.md")),
    ]).filter((file) => !file.includes(`${join("src", "scan")}/`));
    const liveCount = files.reduce(
      (total, file) => total + countExemptionMarkers(readFileSync(file, "utf8")),
      0,
    );

    expect(liveCount).toBe(FROZEN_EXEMPTION_COUNT);
  });

  // ---- AC3: contract-allow suppression is per-term and accounted, not a blank line pass.

  it("a legacy whole-line marker no longer hides an adjacent term silently — the hit is counted", () => {
    const line = 'const RETIRED = "/v1/refunds*"; // contract-allow:retired-route-citation';
    expect(scanTextForForbiddenTerms(line, "fixture.ts")).toEqual([]);
    expect(countSuppressedViolations(line)).toBe(1);

    // The evasion the AC names: extend the already-marked line with real product vocabulary. The
    // marked-LINE count cannot see it; the suppressed-hit count does.
    const smuggled = `${line} // and a checkout flow`;
    expect(countExemptionMarkers(smuggled)).toBe(countExemptionMarkers(line));
    expect(countSuppressedViolations(smuggled)).toBe(2);
  });

  it("a token-named marker exempts only the term it names — an adjacent term still FLAGS", () => {
    const line = 'const RETIRED = "/v1/refunds*"; // contract-allow:refund:retired-route-citation';
    expect(scanTextForForbiddenTerms(line, "fixture.ts")).toEqual([]);

    const smuggled = 'const RETIRED = "/v1/refunds*"; const X = "checkout"; // contract-allow:refund:retired-route-citation';
    const violations = scanTextForForbiddenTerms(smuggled, "fixture.ts");
    expect(violations).toHaveLength(1);
    expect(violations[0]?.term).toBe("checkout");
  });

  it("a token-named marker accepts a comma-separated term list and nothing else", () => {
    const both = 'refunds and checkouts // contract-allow:refund,checkout:dual-citation';
    expect(scanTextForForbiddenTerms(both, "fixture.ts")).toEqual([]);

    const onlyOne = 'refunds and checkouts // contract-allow:refund:single-citation';
    expect(scanTextForForbiddenTerms(onlyOne, "fixture.ts").map((v) => v.term)).toEqual(["checkout"]);
  });

  it("a marker's own bytes never count as a violation or as a suppressed hit", () => {
    const line = "// contract-allow:refund:retired-route-citation";
    expect(scanTextForForbiddenTerms(line, "fixture.ts")).toEqual([]);
    expect(countSuppressedViolations(line)).toBe(0);
  });

  it("an unparseable term list falls back to the legacy whole-line form (no silent narrowing)", () => {
    // `not-a-term` is not in FORBIDDEN_TERMS, so this stays a legacy marker: it suppresses the
    // line, and the suppression is counted. A typo must never quietly stop exempting.
    const line = 'const RETIRED = "/v1/refunds*"; // contract-allow:not-a-term:citation';
    expect(scanTextForForbiddenTerms(line, "fixture.ts")).toEqual([]);
    expect(countSuppressedViolations(line)).toBe(1);
  });

  it("the live suppressed-hit count across SCAN_SCOPE matches FROZEN_SUPPRESSED_VIOLATION_COUNT", () => {
    // Same file set and same allowlist the real gate walks (generic-core.scan-gate.test.ts), so
    // this freeze covers every marker the gate honours — not just the contracts package's.
    const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
    const files = SCAN_SCOPE.flatMap((scopePath) => [
      ...globSync(join(repoRoot, scopePath, "**", "*.ts")),
      ...globSync(join(repoRoot, scopePath, "**", "*.md")),
    ]).filter((file) => !file.includes(`${join("src", "scan")}/`));
    expect(files.length).toBeGreaterThan(0);

    const liveSuppressed = files.reduce(
      (total, file) => total + countSuppressedViolations(readFileSync(file, "utf8"), D99_ALLOWLIST),
      0,
    );
    expect(liveSuppressed).toBe(FROZEN_SUPPRESSED_VIOLATION_COUNT);
  });

  // ---- AC5: stemmer allowlist.

  it("does not flag structural ordering/draining usage via the suffix stemmer", () => {
    const fixture = [
      "event ordering is preserved across the batch.",
      "the reordering step runs before dispatch.",
      "results are returned in an ordered, unordered, or reordered sequence.",
      "draining the queue is idempotent.",
    ].join("\n");
    expect(scanTextForForbiddenTerms(fixture, "fixture.ts")).toEqual([]);
  });

  it("the stem allowlist never covers a DIRECT hit — order/orders/drain/drains/drained still flag", () => {
    const fixture = [
      "this line mentions an order.",
      "this line mentions orders.",
      "this line mentions a drain.",
      "this line mentions drains.",
      "this line mentions a drained pool.",
    ].join("\n");
    const violations = scanTextForForbiddenTerms(fixture, "fixture.ts");
    expect(violations.map((violation) => violation.line)).toEqual([1, 2, 3, 4, 5]);
    expect(new Set(violations.map((violation) => violation.term))).toEqual(
      new Set(["order", "drain"]),
    );
  });
});
