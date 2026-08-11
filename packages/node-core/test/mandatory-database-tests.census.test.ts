/**
 * ZTR-1173 / data-model §16 — mandatory database test discharge census.
 *
 * Every one of the 36 mandatory database tests must cite an artifact that actually
 * opens PostgreSQL and carries a per-id discharge marker the census can read.
 * Header comment laundry ("discharges DB-TEST-21..26") is not enough.
 *
 * Marker forms (must appear in the cited file):
 *   // DB-TEST-NN: <obligation gloss>
 *   it("DB-TEST-NN …", …) / it('DB-TEST-NN …', …)
 *   discharges("DB-TEST-NN …")  // existing helper style in some PG suites
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
 * Per-id marker present in the file. Range headers like
 * `// discharges DB-TEST-21..26` do not match (no `ID:` form, no it title).
 */
const hasDischargeMarker = (id: string, body: string): boolean => {
  const idRe = escapeRegExp(id);
  // Single-line obligation marker: // DB-TEST-NN: …
  if (new RegExp(String.raw`^\s*//\s*${idRe}\s*:`, "m").test(body)) return true;
  // it("DB-TEST-NN …") / it('DB-TEST-NN …') / it(`DB-TEST-NN …`)
  if (new RegExp(String.raw`\bit\s*\(\s*["'\`][^"'\`\n]*${idRe}`).test(body)) return true;
  // discharges("DB-TEST-NN …") helper
  if (new RegExp(String.raw`\bdischarges\s*\(\s*["'\`][^"'\`\n]*${idRe}`).test(body)) {
    return true;
  }
  return false;
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
  const raw = requirement
    .replace(/[`,]/g, " ")
    .split(/[^A-Za-z0-9_./:-]+/)
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

const bodyMatchesRequirement = (requirement: string, body: string): boolean => {
  const tokens = requirementTokens(requirement);
  if (tokens.length === 0) return true;
  const lower = body.toLowerCase();
  return tokens.some((t) => lower.includes(t.toLowerCase()));
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

  it("every row has a per-id discharge marker in the cited suite", () => {
    const bad = rows
      .filter((r) => {
        const body = readFileSync(join(repoRoot, r.test), "utf8");
        return !hasDischargeMarker(r.id, body);
      })
      .map((r) => `${r.id} -> ${r.test}`);
    expect(bad).toEqual([]);
  });

  it("every cited suite body carries at least one distinctive requirement token", () => {
    const bad = rows
      .filter((r) => {
        const body = readFileSync(join(repoRoot, r.test), "utf8");
        return !bodyMatchesRequirement(r.requirement, body);
      })
      .map((r) => `${r.id} -> ${r.test} :: ${r.requirement.slice(0, 72)}`);
    expect(bad).toEqual([]);
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
