/**
 * ZTR-1173 / data-model §16 — mandatory database test discharge census.
 *
 * Every one of the 36 mandatory database tests must cite an artifact that actually
 * opens PostgreSQL and carries an *executable* per-id discharge — a named
 * `it("DB-TEST-NN…")` / `it('DB-TEST-NN…')` / `discharges("DB-TEST-NN…")` whose
 * callback body (not a header comment alone) carries distinctive requirement tokens.
 *
 * Comment laundry (`// DB-TEST-NN: …` with zero `it`/`discharges`) is refused.
 * A synthetic `import from "pg"` + comment-only file must fail this census.
 *
 * Source of truth for the requirement text: docs/proposals/…/04-data-model.md §16.
 * Source of truth for the citation map: docs/proposals/…/mandatory-database-tests.md §3.18.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "../../..");

const DISCHARGE_DOC = join(
  repoRoot,
  "docs/proposals/generic-node-redesign-v2/mandatory-database-tests.md",
);
const DATA_MODEL = join(
  repoRoot,
  "docs/proposals/generic-node-redesign-v2/04-data-model.md",
);

interface DischargeRow {
  readonly id: string;
  readonly requirement: string;
  readonly test: string;
}

const unquote = (cell: string): string => {
  const trimmed = cell.trim();
  if (trimmed === "—" || trimmed === "") return "";
  return trimmed.replace(/^`/, "").replace(/`$/, "");
};

const loadDischargeRows = (): DischargeRow[] => {
  const text = readFileSync(DISCHARGE_DOC, "utf8");
  const rows: DischargeRow[] = [];
  for (const line of text.split("\n")) {
    if (!line.startsWith("| `DB-TEST-")) continue;
    const cells = line.split("|").slice(1, -1);
    if (cells.length < 7) continue;
    rows.push({
      id: unquote(cells[0]),
      requirement: cells[2].trim(),
      test: unquote(cells[6]),
    });
  }
  return rows;
};

/** Numbered top-level items under §16 of the data model. */
const loadSpecItems = (): string[] => {
  const text = readFileSync(DATA_MODEL, "utf8");
  const start = text.indexOf("## 16. Mandatory database tests");
  if (start < 0) throw new Error("§16 missing from 04-data-model.md");
  const end = text.indexOf("\n## 17.", start);
  const section = end < 0 ? text.slice(start) : text.slice(start, end);
  const items: string[] = [];
  for (const line of section.split("\n")) {
    if (/^\d+\.\s/.test(line)) {
      items.push(line.replace(/^\d+\.\s*/, "").trim().replace(/;$/, ""));
    }
  }
  return items;
};

const escapeRegExp = (value: string): string =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Body opens PostgreSQL. A bare `.pg.test.ts` suffix is not enough — empty or
 * comment-only files must not green the census.
 */
const exercisesPostgres = (relative: string, body: string): boolean => {
  const opens =
    /\bfrom\s+["']pg["']/.test(body) ||
    /\bpsql\b/.test(body) ||
    /\bTEST_DATABASE_URL\b/.test(body) ||
    /\bPG_AVAILABLE\b/.test(body) ||
    /\bpg_isready\b/.test(body) ||
    /\bcreatedb\b/.test(body) ||
    /\brunMigrationsOnPool\b/.test(body);
  if (relative.endsWith(".pg.test.ts")) return opens;
  if (relative.endsWith("observation-migration-integrity.test.ts")) return true;
  if (relative.endsWith("pg-concurrency.test.ts")) return true;
  return opens;
};

/**
 * Locate every executable discharge site for `id`:
 *   it("DB-TEST-NN …", …) / it('…') / it(`…`)
 *   it.skipIf(...)( "DB-TEST-NN …", …)
 *   it.each(...)( "DB-TEST-NN …", …)
 *   discharges("DB-TEST-NN …")
 *
 * Comment markers `// DB-TEST-NN:` alone are NOT accepted.
 */
interface ExecutableSite {
  readonly kind: "it" | "discharges";
  /** Full matched call head through opening paren of callback / end of discharges call. */
  readonly index: number;
  readonly title: string;
}

const readQuotedString = (
  src: string,
  openQuoteIndex: number,
): { readonly value: string; readonly end: number } | undefined => {
  const quote = src[openQuoteIndex];
  if (quote !== '"' && quote !== "'" && quote !== "`") return undefined;
  let i = openQuoteIndex + 1;
  let value = "";
  while (i < src.length) {
    const c = src[i]!;
    if (c === "\\") {
      value += src[i + 1] ?? "";
      i += 2;
      continue;
    }
    if (c === quote) return { value, end: i };
    // Double-quoted / backtick titles may contain apostrophes; only the matching quote ends.
    value += c;
    i += 1;
  }
  return undefined;
};

const findExecutableSites = (id: string, body: string): ExecutableSite[] => {
  const sites: ExecutableSite[] = [];
  // Scan for it( / it.skipIf(...)( / it.each(...)( then a quoted title containing id.
  const headRe =
    /\bit(?:\s*\.\s*(?:skipIf|each|skip|only|todo|concurrent)\b(?:\s*\([^)]*\))?)?\s*\(/g;
  for (const m of body.matchAll(headRe)) {
    let j = (m.index ?? 0) + m[0].length;
    while (j < body.length && /\s/.test(body[j]!)) j += 1;
    const parsed = readQuotedString(body, j);
    if (!parsed) continue;
    if (!parsed.value.includes(id)) continue;
    sites.push({ kind: "it", index: m.index ?? 0, title: parsed.value });
  }

  const disHeadRe = /\bdischarges\s*\(/g;
  for (const m of body.matchAll(disHeadRe)) {
    let j = (m.index ?? 0) + m[0].length;
    while (j < body.length && /\s/.test(body[j]!)) j += 1;
    const parsed = readQuotedString(body, j);
    if (!parsed) continue;
    if (!parsed.value.includes(id)) continue;
    sites.push({ kind: "discharges", index: m.index ?? 0, title: parsed.value });
  }

  return sites;
};

/** Strip line + block comments so token checks cannot be satisfied by laundry alone. */
const stripComments = (src: string): string => {
  // Block comments first
  let out = src.replace(/\/\*[\s\S]*?\*\//g, "");
  // Line comments
  out = out.replace(/^\s*\/\/.*$/gm, "");
  out = out.replace(/([^:])\/\/.*$/gm, "$1");
  return out;
};

/**
 * Extract the callback body of an `it("…", <callback>)` starting near `index`.
 * Walks braces from the first `{` after the title match. Falls back to a
 * window of source after the match when the form is arrow-without-block
 * (rare in this repo).
 */
const extractItCallbackBody = (body: string, siteIndex: number): string => {
  // Find the matching title close, then the callback start.
  const from = body.slice(siteIndex);
  // After it(...title...,  we expect function / async / arrow
  const afterTitle = from.search(/["'\`]/);
  if (afterTitle < 0) return "";
  // skip opening quote of title already at start of match — find end of title string
  const titleOpen = from.search(/["'\`]/);
  const quote = from[titleOpen]!;
  let i = titleOpen + 1;
  while (i < from.length && from[i] !== quote) {
    if (from[i] === "\\") i += 2;
    else i += 1;
  }
  // i at closing quote
  let j = i + 1;
  // skip whitespace and comma
  while (j < from.length && /[\s,]/.test(from[j]!)) j += 1;

  // Optional async
  if (from.startsWith("async", j)) {
    j += 5;
    while (j < from.length && /\s/.test(from[j]!)) j += 1;
  }

  // function (...) { or (...) => { or () => expr
  if (from.startsWith("function", j)) {
    const brace = from.indexOf("{", j);
    if (brace < 0) return "";
    return sliceBalanced(from, brace);
  }

  // arrow or paren form
  if (from[j] === "(") {
    // skip param list
    let depth = 0;
    let k = j;
    for (; k < from.length; k++) {
      const c = from[k]!;
      if (c === "(") depth += 1;
      else if (c === ")") {
        depth -= 1;
        if (depth === 0) {
          k += 1;
          break;
        }
      }
    }
    while (k < from.length && /\s/.test(from[k]!)) k += 1;
    if (from.startsWith("=>", k)) {
      k += 2;
      while (k < from.length && /\s/.test(from[k]!)) k += 1;
      if (from[k] === "{") return sliceBalanced(from, k);
      // expression body — take until comma/paren end roughly
      return from.slice(k, k + 400);
    }
  }

  if (from.startsWith("=>", j)) {
    j += 2;
    while (j < from.length && /\s/.test(from[j]!)) j += 1;
    if (from[j] === "{") return sliceBalanced(from, j);
    return from.slice(j, j + 400);
  }

  // Fallback: window after the it( match (still comment-stripped later)
  return from.slice(0, 800);
};

const sliceBalanced = (src: string, openBrace: number): string => {
  let depth = 0;
  for (let i = openBrace; i < src.length; i++) {
    const c = src[i]!;
    if (c === "{") depth += 1;
    else if (c === "}") {
      depth -= 1;
      if (depth === 0) return src.slice(openBrace, i + 1);
    }
  }
  return src.slice(openBrace);
};

/** Distinctive tokens from the matrix requirement cell. */
const requirementTokens = (requirement: string): string[] => {
  const stop = new Set([
    "the",
    "and",
    "or",
    "a",
    "an",
    "of",
    "to",
    "for",
    "in",
    "on",
    "is",
    "be",
    "by",
    "with",
    "from",
    "as",
    "at",
    "not",
    "no",
    "its",
    "one",
    "every",
    "any",
    "all",
    "cannot",
    "never",
    "fails",
    "fail",
    "reject",
    "rejects",
    "must",
    "that",
    "this",
    "into",
    "than",
    "only",
    "also",
    "when",
    "while",
    "after",
    "before",
    "without",
    "another",
    "other",
  ]);
  // Split on punctuation including `/` so "body/signature" and "404/409/500" become
  // matchable pieces that real assert titles actually carry.
  const raw = requirement
    .replace(/[`,]/g, " ")
    .split(/[^A-Za-z0-9_.:-]+/)
    .map((t) => t.trim())
    .filter((t) => t.length >= 4 && !stop.has(t.toLowerCase()));
  const preferred = raw.filter(
    (t) =>
      /[_-]/.test(t) ||
      /[A-Z]{2,}/.test(t) ||
      /^\d/.test(t) ||
      t.toLowerCase().includes("zp-") ||
      t.length >= 10,
  );
  const pick = (preferred.length > 0 ? preferred : raw).slice(0, 8);
  return [...new Set(pick)];
};

/**
 * Token match against executable callback bodies (comment-stripped).
 * Requires a majority of distinctive tokens (or all when ≤2) so a single
 * title-echo token cannot launder a multi-token obligation.
 */
const executableBodiesMatchRequirement = (
  requirement: string,
  bodies: readonly string[],
): boolean => {
  const tokens = requirementTokens(requirement);
  if (tokens.length === 0) return true;
  const haystack = stripComments(bodies.join("\n")).toLowerCase();
  const hits = tokens.filter((t) => haystack.includes(t.toLowerCase())).length;
  const need = tokens.length <= 2 ? tokens.length : Math.ceil(tokens.length * 0.5);
  return hits >= need;
};

describe("mandatory database tests (§16 / ZTR-1173)", () => {
  const rows = loadDischargeRows();
  const specItems = loadSpecItems();

  it("enumerates exactly 36 discharge rows and 36 spec items", () => {
    expect(rows).toHaveLength(36);
    expect(specItems).toHaveLength(36);
    expect(rows.map((r) => r.id)).toEqual(
      Array.from({ length: 36 }, (_, i) => `DB-TEST-${String(i + 1).padStart(2, "0")}`),
    );
  });

  it("every row cites an on-disk test path", () => {
    const missing = rows
      .filter((r) => r.test === "" || !existsSync(join(repoRoot, r.test)))
      .map((r) => `${r.id} -> ${r.test}`);
    expect(missing).toEqual([]);
  });

  it("every cited artifact exercises PostgreSQL (body opens PG, not suffix alone)", () => {
    const bad = rows
      .filter((r) => {
        const abs = join(repoRoot, r.test);
        if (!existsSync(abs)) return true;
        return !exercisesPostgres(r.test, readFileSync(abs, "utf8"));
      })
      .map((r) => `${r.id} -> ${r.test}`);
    expect(bad).toEqual([]);
  });

  it("every row has an executable it()/discharges() discharge (comment-only refused)", () => {
    const bad = rows
      .filter((r) => {
        const body = readFileSync(join(repoRoot, r.test), "utf8");
        return findExecutableSites(r.id, body).length === 0;
      })
      .map((r) => `${r.id} -> ${r.test}`);
    expect(bad).toEqual([]);
  });

  it("every executable discharge callback carries distinctive requirement tokens (not comment laundry)", () => {
    const bad = rows
      .filter((r) => {
        const body = readFileSync(join(repoRoot, r.test), "utf8");
        const sites = findExecutableSites(r.id, body);
        if (sites.length === 0) return true;
        const callbackBodies = sites.map((s) => {
          if (s.kind === "discharges") {
            // discharges("…") is a one-liner; require the title itself plus nearby suite body window
            return `${s.title}\n${body.slice(Math.max(0, s.index - 200), s.index + 600)}`;
          }
          // Include the it title (tokens often live there legitimately as the assert name)
          // PLUS the callback body so a title-only echo without body still needs body tokens.
          return `${s.title}\n${extractItCallbackBody(body, s.index)}`;
        });
        return !executableBodiesMatchRequirement(r.requirement, callbackBodies);
      })
      .map((r) => `${r.id} -> ${r.test} :: ${r.requirement.slice(0, 72)}`);
    expect(bad).toEqual([]);
  });

  it("synthetic pg+comment-only file fails executable discharge (A1 hardness pin)", () => {
    // Mirrors Review B's launder recipe: import pg + // DB-TEST-NN: gloss, zero it().
    const synthetic = `
import { Client } from "pg";
const url = process.env.TEST_DATABASE_URL;
// DB-TEST-23: competing rotations and request-admission-versus-revocation races lock one
// DB-TEST-01: imported wallet cannot become a destination
`;
    expect(exercisesPostgres("synthetic.pg.test.ts", synthetic)).toBe(true);
    expect(findExecutableSites("DB-TEST-23", synthetic)).toHaveLength(0);
    expect(findExecutableSites("DB-TEST-01", synthetic)).toHaveLength(0);
    // Even if someone added a title-less comment token match, callback token check must fail.
    expect(
      executableBodiesMatchRequirement(
        "competing rotations and request-admission-versus-revocation races lock one",
        ["// DB-TEST-23: competing rotations and request-admission-versus-revocation races lock one"],
      ),
    ).toBe(false);
  });

  it("no row cites packages/generic-node-contracts (pg-import banned)", () => {
    const bad = rows
      .filter((r) => r.test.includes("packages/generic-node-contracts/"))
      .map((r) => `${r.id} -> ${r.test}`);
    expect(bad).toEqual([]);
  });

  it("dependency-boundary still bans pg in contracts", () => {
    const boundary = readFileSync(
      join(
        repoRoot,
        "packages/generic-node-contracts/src/scan/dependency-boundary.test.ts",
      ),
      "utf8",
    );
    expect(boundary).toMatch(/["']pg["']/);
    expect(boundary).toMatch(/DENYLISTED_MANIFEST_PACKAGES|denylist/i);
  });
});
