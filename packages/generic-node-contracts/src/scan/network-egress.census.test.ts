// Network-egress census (the scan/dependency-boundary gate companion drift tripwire). Global `fetch` (Node 18+)
// and `WebSocket` (Node 21+) need no import, so raw egress evades both existing static
// gates (dependency-boundary.test.ts matches only import/require specifiers;
// forbidden-terms.ts tokenizes vocabulary only). Guards the CONTRACT_FREEZE
// no-network-seam invariant: the generic core issues no outbound network call of its own.
//
// Path list is replicated (not imported) from dependency-boundary.test.ts, same root
// (this package's own src/), same `*.ts` extension, same src/scan/ self-exclusion (this
// file's own fixtures necessarily contain every pattern it hunts).
//
// Six token classes, each a plain per-line regex (no AST parse):
//  - global_fetch_call: bare `fetch(` via negative lookbehind `(?<![.\w])` — property-access
//    forms (`this.fetch(`) and identifier-suffix calls (`refetch(`) are NOT flagged
//    (explicit ticket direction); a namespaced/injected fetch can still evade this class.
//  - websocket_construct: `new WebSocket`.
//  - xhr_construct: `XMLHttpRequest`.
//  - eventsource_construct: `EventSource`, word-bounded (`EventSourceOfTruth` excluded).
//  - http_url_literal: raw `http://`/`https://` substring anywhere, including comments.
//  - ipv4_literal: dotted-quad IPv4 shape, plain substring (not string-literal-only).
// A bare `new URL(` with no http(s) literal argument is never flagged (legitimate
// relative-path parsing via `import.meta.url`, not egress).
//
// NON_EGRESS_ALLOWLIST: nine known-benign hits (no-callback's own destination-class
// contract data, its concern fixtures for a different scanner, one reporting-tuples
// negative fixture). Pinned by exact file + exact trimmed line content, never by line
// number, so it goes stale loudly (via the "every allowlist entry is still live" test)
// the moment a pinned line changes or disappears.
//
// Governing contract: the architecture drift gates (CONTRACT_FREEZE no-network-seam invariant).

import { globSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { EXECUTION_TIMEOUTS } from "../testkit/executionPolicy.ts";
import { readPresentFiles } from "../testkit/realTreeScan.ts";

type EgressTokenClass =
  | "global_fetch_call"
  | "websocket_construct"
  | "xhr_construct"
  | "eventsource_construct"
  | "http_url_literal"
  | "ipv4_literal";

interface EgressTokenPattern {
  readonly tokenClass: EgressTokenClass;
  readonly pattern: RegExp;
}

/**
 * One regex per token class, tested per-line with `.test()` (no `g` flag, so no `lastIndex` state
 * to manage across lines/files). See the file-header comment for the false-positive handling
 * behind each pattern.
 */
const EGRESS_TOKEN_PATTERNS: readonly EgressTokenPattern[] = [
  { tokenClass: "global_fetch_call", pattern: /(?<![.\w])fetch\s*\(/ },
  { tokenClass: "websocket_construct", pattern: /\bnew\s+WebSocket\b/ },
  { tokenClass: "xhr_construct", pattern: /\bXMLHttpRequest\b/ },
  { tokenClass: "eventsource_construct", pattern: /\bEventSource\b/ },
  { tokenClass: "http_url_literal", pattern: /https?:\/\// },
  { tokenClass: "ipv4_literal", pattern: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/ },
];

interface AllowlistEntry {
  readonly relativePath: string;
  readonly content: string;
  readonly reason: string;
}

/**
 * Nine lines the naive scan legitimately hits in the current tree today; none is real egress.
 * Pinned by exact file + exact trimmed line content, never by line number.
 */
const NON_EGRESS_ALLOWLIST: readonly AllowlistEntry[] = [
  {
    relativePath: join("no-callback", "attack-surface.ts"),
    content: `{ class: "dns_rebinding_resolved_ip", exampleHost: "10.0.0.5" },`,
    reason: "NON_GATEWAY_DESTINATION_CLASSES contract data isEgressAllowed must reject; never dialed.",
  },
  {
    relativePath: join("no-callback", "attack-surface.ts"),
    content: `{ class: "loopback", exampleHost: "127.0.0.1" },`,
    reason: "NON_GATEWAY_DESTINATION_CLASSES contract data isEgressAllowed must reject; never dialed.",
  },
  {
    relativePath: join("no-callback", "attack-surface.ts"),
    content: `{ class: "link_local", exampleHost: "169.254.0.1" },`,
    reason: "NON_GATEWAY_DESTINATION_CLASSES contract data isEgressAllowed must reject; never dialed.",
  },
  {
    relativePath: join("no-callback", "attack-surface.ts"),
    content: `{ class: "cloud_metadata", exampleHost: "169.254.169.254" },`,
    reason: "NON_GATEWAY_DESTINATION_CLASSES contract data isEgressAllowed must reject; never dialed.",
  },
  {
    relativePath: join("no-callback", "attack-surface.ts"),
    content: `{ class: "rfc1918_private", exampleHost: "192.168.1.1" },`,
    reason: "NON_GATEWAY_DESTINATION_CLASSES contract data isEgressAllowed must reject; never dialed.",
  },
  {
    relativePath: join("no-callback", "callback-census.defect2.test.ts"),
    content: `const labels = scanForCallbackSurfaces('const leak = "https://operator.example/hook";');`,
    reason: "Synthetic fixture string fed to scanForCallbackSurfaces (a different concern's scanner); never fetched.",
  },
  {
    relativePath: join("no-callback", "callback-census.defect2.test.ts"),
    content: `expect(scanForCallbackSurfaces('fetch("/push/register")')).toContain("push_route");`,
    reason: "Synthetic fixture string fed to scanForCallbackSurfaces (a different concern's scanner); never called.",
  },
  {
    relativePath: join("no-callback", "attack-transport.freeze.test.ts"),
    content: `expect(scanForCallbackSurfaces('const leak = "https://operator.example/hook";')).toContain("outbound_url_literal");`,
    reason: "Synthetic fixture string fed to scanForCallbackSurfaces (a different concern's scanner); never fetched.",
  },
  {
    relativePath: join("reporting-tuples", "manifest.freeze.test.ts"),
    content: `"https://node.example/v1/events",`,
    reason: "Negative-fixture value asserting an invalid report_target is rejected; never fetched.",
  },
];

interface EgressViolation {
  readonly file: string;
  readonly line: number;
  readonly tokenClass: EgressTokenClass;
  readonly excerpt: string;
}

const isAllowlisted = (filePath: string, trimmedLine: string, allowlist: readonly AllowlistEntry[]): boolean =>
  allowlist.some((entry) => filePath.endsWith(entry.relativePath) && trimmedLine === entry.content);

/**
 * Scans `text` line by line for any of the six egress token classes. A line whose trimmed content
 * exactly matches an `allowlist` entry pinned to this `filePath` is exempt from every class on that
 * line (the same whole-line exemption idiom doc-census.freeze.test.ts uses), not only the class
 * that would otherwise fire.
 */
const scanTextForNetworkEgress = (
  text: string,
  filePath: string,
  allowlist: readonly AllowlistEntry[] = [],
): EgressViolation[] => {
  const violations: EgressViolation[] = [];
  const lines = text.split("\n");
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (isAllowlisted(filePath, trimmed, allowlist)) {
      return;
    }
    for (const { tokenClass, pattern } of EGRESS_TOKEN_PATTERNS) {
      if (pattern.test(line)) {
        violations.push({ file: filePath, line: index + 1, tokenClass, excerpt: trimmed });
      }
    }
  });
  return violations;
};

/**
 * Replicated from dependency-boundary.test.ts (not imported — see file-header comment): same root
 * (this package's own `src/`), same extension (`*.ts`), same `src/scan/` self-exclusion.
 */
const srcDir = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Walked at test time, not at collect time: this glob root is a live working tree, so a
 * collect-time list can name a path that is already gone by the time the read runs.
 * readPresentFiles below tolerates that removal; the empty-glob guard keeps a broken walk from
 * passing vacuously.
 */
const walkFiles = (): string[] =>
  globSync(join(srcDir, "**", "*.ts")).filter((file) => !file.includes(`${join("src", "scan")}/`));

// Real-tree walk + read: the realTree class in ../testkit/executionPolicy.ts.
describe("network-egress census", { timeout: EXECUTION_TIMEOUTS.realTree }, () => {
  it("has files to check (guards against an empty/broken glob)", () => {
    expect(walkFiles().length).toBeGreaterThan(0);
  });

  it("the current tree carries zero unallowlisted network-egress hits", () => {
    const violations = readPresentFiles(walkFiles()).flatMap(({ file, text }) =>
      scanTextForNetworkEgress(text, file, NON_EGRESS_ALLOWLIST),
    );
    expect(violations).toEqual([]);
  });

  it("every allowlist entry is still present verbatim in its pinned file (staleness guard)", () => {
    const files = walkFiles();
    for (const entry of NON_EGRESS_ALLOWLIST) {
      const file = files.find((candidate) => candidate.endsWith(entry.relativePath));
      expect(file, `allowlisted file not found in scan scope: ${entry.relativePath}`).toBeDefined();
      const lines = readFileSync(file as string, "utf8")
        .split("\n")
        .map((line) => line.trim());
      expect(lines, `allowlist entry no longer present verbatim: ${entry.relativePath}`).toContain(entry.content);
    }
  });
});

describe("network-egress census: positive controls (not vacuously green)", () => {
  const withTempFixture = (fileName: string, contents: string, run: (filePath: string) => void): void => {
    const tmp = mkdtempSync(join(tmpdir(), "network-egress-egress-census-"));
    try {
      const filePath = join(tmp, fileName);
      writeFileSync(filePath, contents);
      run(filePath);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  };

  it("catches a planted bare fetch( call (with an http(s) literal argument)", () => {
    withTempFixture("planted.ts", 'await fetch("https://evil.example/x");\n', (filePath) => {
      const classes = new Set(
        scanTextForNetworkEgress(readFileSync(filePath, "utf8"), filePath).map((v) => v.tokenClass),
      );
      expect(classes.has("global_fetch_call")).toBe(true);
      expect(classes.has("http_url_literal")).toBe(true);
    });
  });

  it("catches a planted new WebSocket construct", () => {
    withTempFixture("planted.ts", 'const ws = new WebSocket("wss://evil.example");\n', (filePath) => {
      const classes = scanTextForNetworkEgress(readFileSync(filePath, "utf8"), filePath).map((v) => v.tokenClass);
      expect(classes).toContain("websocket_construct");
    });
  });

  it("catches a planted XMLHttpRequest construct", () => {
    withTempFixture("planted.ts", "const xhr = new XMLHttpRequest();\n", (filePath) => {
      const classes = scanTextForNetworkEgress(readFileSync(filePath, "utf8"), filePath).map((v) => v.tokenClass);
      expect(classes).toContain("xhr_construct");
    });
  });

  it("catches a planted EventSource construct", () => {
    withTempFixture("planted.ts", 'const es = new EventSource("https://evil.example/stream");\n', (filePath) => {
      const classes = new Set(
        scanTextForNetworkEgress(readFileSync(filePath, "utf8"), filePath).map((v) => v.tokenClass),
      );
      expect(classes.has("eventsource_construct")).toBe(true);
      expect(classes.has("http_url_literal")).toBe(true);
    });
  });

  it("catches a planted http:// URL literal on its own, outside any call", () => {
    withTempFixture("planted.ts", 'const target = "http://evil.example/callback";\n', (filePath) => {
      const classes = scanTextForNetworkEgress(readFileSync(filePath, "utf8"), filePath).map((v) => v.tokenClass);
      expect(classes).toContain("http_url_literal");
    });
  });

  it("catches a planted raw IPv4 dotted-quad literal", () => {
    withTempFixture("planted.ts", 'const target = "203.0.113.7";\n', (filePath) => {
      const classes = scanTextForNetworkEgress(readFileSync(filePath, "utf8"), filePath).map((v) => v.tokenClass);
      expect(classes).toContain("ipv4_literal");
    });
  });

  it("an allowlisted fixture line is exempt by exact content, not position", () => {
    withTempFixture(
      "planted.ts",
      'const example = "https://operator.example/hook"; // decoy\n',
      (filePath) => {
        const entry: AllowlistEntry = {
          relativePath: "planted.ts",
          content: 'const example = "https://operator.example/hook"; // decoy',
          reason: "fixture-only allowlist proof",
        };
        expect(scanTextForNetworkEgress(readFileSync(filePath, "utf8"), filePath, [entry])).toEqual([]);
      },
    );
  });

  it("does not flag property-access fetch calls (this.fetch(, client.fetch(, globalThis.fetch()", () => {
    const fixture = ["this.fetch(url);", "client.fetch(url);", "globalThis.fetch(url);"].join("\n");
    const classes = scanTextForNetworkEgress(fixture, "fixture.ts").map((v) => v.tokenClass);
    expect(classes).not.toContain("global_fetch_call");
  });

  it("does not flag identifier-suffix calls that merely contain the fetch( substring (refetch()", () => {
    const fixture = ["refetch(id);", "myFetch(id);"].join("\n");
    const classes = scanTextForNetworkEgress(fixture, "fixture.ts").map((v) => v.tokenClass);
    expect(classes).not.toContain("global_fetch_call");
  });

  it("does not flag a bare new URL( call with no http(s) literal (legitimate relative-path parsing)", () => {
    const fixture = 'const p = new URL("./gen/x.json", import.meta.url);';
    expect(scanTextForNetworkEgress(fixture, "fixture.ts")).toEqual([]);
  });

  it("does not flag EventSource as a substring of a longer identifier", () => {
    const fixture = "const EventSourceOfTruth = 1;";
    const classes = scanTextForNetworkEgress(fixture, "fixture.ts").map((v) => v.tokenClass);
    expect(classes).not.toContain("eventsource_construct");
  });

  it("detector mechanism: a multi-class planted fixture yields one violation per class", () => {
    const fixture = [
      'await fetch("https://evil.example/x");',
      'const ws = new WebSocket("wss://evil.example");',
      "const xhr = new XMLHttpRequest();",
      'const es = new EventSource("https://evil.example/stream");',
      'const raw = "203.0.113.7";',
    ].join("\n");
    const classes = new Set(scanTextForNetworkEgress(fixture, "fixture.ts").map((v) => v.tokenClass));
    expect(classes).toEqual(
      new Set<EgressTokenClass>([
        "global_fetch_call",
        "http_url_literal",
        "websocket_construct",
        "xhr_construct",
        "eventsource_construct",
        "ipv4_literal",
      ]),
    );
  });
});
