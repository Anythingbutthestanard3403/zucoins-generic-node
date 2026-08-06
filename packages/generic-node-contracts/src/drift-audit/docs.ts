/**
 * Documentation-citation resolution helpers.
 *
 * Resolves the citation shorthand a concern manifest may carry against the repository's spec
 * files, and provides small markdown-section parsers for cross-document checks. Read-only:
 * every function reads committed files.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "./registry.ts";

const SPEC_DIR = join(repoRoot, "docs", "specs");

/** Citation shorthand — key → file, relative to the spec folder. */
export const SHORTHAND: Readonly<Record<string, string>> = {
  R: "README.md",
  G: "00-foundations.md",
  S1: "01-system-overview.md",
  P: "02-protocol-foundation.md",
  C: "03-node-core.md",
  D: "04-data-model.md",
  API: "05-api-contract.md",
  F: "06-operation-flows.md",
  SEC: "07-signing-custody-security.md",
  OBS: "08-observation-verification.md",
  OPS: "09-operations-recovery.md",
  ZP: "10-zupayments-integration.md",
  BT: "11-build-test-plan.md",
  UC: "12-use-case-framework.md",
  A: "appendices/A-canonical-fields.md",
  B: "appendices/B-state-event-reference.md",
  T: "appendices/C-traceability.md",
  PE: "PLAIN-ENGLISH.md",
  SO: "SYSTEM-OVERVIEW.md",
};

/** `DEC` resolves outside the spec folder to the frozen decision log. */
export const DECISION_LOG_PATH = join(repoRoot, "docs", "decision-log.md");

/** Absolute path for a shorthand key, or `undefined` if the key is not a doc shorthand. */
export const resolveShorthandFile = (key: string): string | undefined => {
  if (key === "DEC") {
    return DECISION_LOG_PATH;
  }
  const relative = SHORTHAND[key];
  return relative === undefined ? undefined : join(SPEC_DIR, relative);
};

const textCache = new Map<string, string>();

/** Cached UTF-8 read of a doc file (many citations touch the same file). */
export const readDoc = (absolutePath: string): string => {
  const cached = textCache.get(absolutePath);
  if (cached !== undefined) {
    return cached;
  }
  const text = readFileSync(absolutePath, "utf8");
  textCache.set(absolutePath, text);
  return text;
};

/** Every decision-log row-ID, parsed from the log's `| <id> |` table rows. */
export const parseDecisionRowIds = (): Set<string> => {
  const text = readFileSync(DECISION_LOG_PATH, "utf8");
  const ids = new Set<string>();
  for (const match of text.matchAll(/^\| (\S+) \|/gm)) {
    ids.add(match[1]);
  }
  return ids;
};

/** Lines from `heading` up to the next markdown heading of any level. Throws if absent. */
export const sectionLines = (docText: string, heading: string): string[] => {
  const lines = docText.split("\n");
  const start = lines.findIndex((line) => line.trim() === heading);
  if (start === -1) {
    throw new Error(`heading not found: ${heading}`);
  }
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (lines[i].startsWith("#")) {
      end = i;
      break;
    }
  }
  return lines.slice(start + 1, end);
};

/**
 * Like `sectionLines`, but keeps the section's own subsections: it stops only at the next heading
 * of the same or a higher level. Use it when a `##` section's whole body lives under `###` children.
 */
export const sectionBlock = (docText: string, heading: string): string[] => {
  const lines = docText.split("\n");
  const start = lines.findIndex((line) => line.trim() === heading);
  if (start === -1) {
    throw new Error(`heading not found: ${heading}`);
  }
  const level = (/^#+/.exec(heading.trim()) as RegExpExecArray)[0].length;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    const match = /^#+/.exec(lines[i]);
    if (match !== null && match[0].length <= level) {
      end = i;
      break;
    }
  }
  return lines.slice(start + 1, end);
};

/** Data rows of the first contiguous pipe table in `lines` (header + separator dropped). */
export const firstPipeTableRows = (lines: readonly string[]): string[][] => {
  const pipeLines: string[] = [];
  let started = false;
  for (const line of lines) {
    if (line.trim().startsWith("|")) {
      started = true;
      pipeLines.push(line);
    } else if (started) {
      break;
    }
  }
  return pipeLines
    .slice(2)
    .map((line) =>
      line
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.replace(/`/g, "").trim()),
    );
};
