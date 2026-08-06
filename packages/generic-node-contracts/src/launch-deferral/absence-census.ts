/**
 * Import/removal absence census. Executable, standing proof
 * that no wallet-key-import or imported-wallet removal surface exists in the three fresh
 * v2 dirs (routes, CLI commands, generated clients, migrations, seeds, signer entry
 * points, deployment scripts). Fails the instant one appears.
 *
 * Scans surface signatures, never the bare word "import": every class requires a
 * route-path, command-name, identifier-compound, origin-write, or file-name context, so
 * `import { x } from "y"` never fires.
 *
 * Surface classes (per walked file, per line unless noted):
 * - route_path: a quoted "/" path literal with an import-/removal-verb segment.
 * - command_name: a quoted, whitespace-free, multi-token string with a verb token
 *   (single-token strings like "import" are vocabulary, not commands, and never fire).
 * - capability_identifier: a code identifier combining a verb token with a
 *   wallet/key/vault token, or an "imported" + removal-verb pair (camelCase evasions).
 * - origin_write: a key_origin write/activation of the reserved 'imported' value
 *   (read-side comparisons and the enum declaration never fire).
 * - surface_file_name: the walked file's own basename carries a verb or "imported"
 *   token (migration/seed/signer/generated-client/deploy surface). Reported at line 0;
 *   applies to test files too.
 *
 * Exemptions: forbidden-terms-marked lines (frozen historical citations, adds no new
 * markers); `*.test.ts` files skip the four content classes (synthetic fixtures, no live
 * surface) but surface_file_name still applies; IDENTIFIER_EXEMPT_FILES exempts only
 * capability_identifier in the existing capability/deferral freeze files; ABSENCE_LINE_ALLOWLIST
 * exempts whole pinned lines, staleness-guarded by the census test.
 *
 * Self-excludes its own module + test. Pure verifiers only — no I/O;
 * absence.census.test.ts walks the tree and feeds (filePath, text) pairs in.
 */

import { join } from "node:path";

import { FORBIDDEN_LAUNCH_CAPABILITY_VERBS } from "./deferral.contract.ts";
import { EXEMPTION_MARKER_PREFIX } from "../scan/forbidden-terms.ts";

export type AbsenceSurfaceClass =
  | "route_path"
  | "command_name"
  | "capability_identifier"
  | "origin_write"
  | "surface_file_name";

export const ABSENCE_SURFACE_CLASSES: readonly AbsenceSurfaceClass[] = [
  "route_path",
  "command_name",
  "capability_identifier",
  "origin_write",
  "surface_file_name",
];

export interface AbsenceViolation {
  readonly file: string;
  readonly line: number;
  readonly surfaceClass: AbsenceSurfaceClass;
  readonly excerpt: string;
}

export interface AbsenceScanInput {
  readonly filePath: string;
  readonly text: string;
}

/**
 * Deployment-script surface (ticket checklist): scanned only once any exist — today every
 * glob over these resolves empty (tolerate-absent), which the census test proves.
 */
export const DEPLOY_SCAN_SCOPE = [
  "apps/generic-node/deploy",
  "apps/generic-node/scripts",
] as const;

/** Extensions walked in the three frozen src dirs: TypeScript modules and SQL schema/migrations. */
export const SCOPE_FILE_EXTENSIONS = ["ts", "sql"] as const;

/** Extensions walked under DEPLOY_SCAN_SCOPE once it exists — deploy/CI config is not TypeScript-only. */
export const DEPLOY_FILE_EXTENSIONS = [
  "ts",
  "js",
  "mjs",
  "cjs",
  "sh",
  "sql",
  "yaml",
  "yml",
  "json",
] as const;

/** The reserved key_origin enum value whose write/activation this census guards. */
export const IMPORTED_KEY_ORIGIN = "imported";

const IMPORT_VERB = FORBIDDEN_LAUNCH_CAPABILITY_VERBS[0];
const REMOVAL_VERB = FORBIDDEN_LAUNCH_CAPABILITY_VERBS[1];

/** Verb token families, derived from the deferral freeze; plural forms catch "/v1/imports"-style surfaces. */
const IMPORT_TOKENS: readonly string[] = [IMPORT_VERB, `${IMPORT_VERB}s`];
const REMOVAL_TOKENS: readonly string[] = [REMOVAL_VERB, `${REMOVAL_VERB}s`];
const VERB_TOKENS: readonly string[] = [...IMPORT_TOKENS, ...REMOVAL_TOKENS];

/** Companion tokens that turn a bare verb into a wallet-key surface signature. */
const WALLET_TOKENS: readonly string[] = ["wallet", "wallets", "key", "keys", "vault"];

/**
 * The existing freeze files whose frozen job is declaring the deferred pair absent — the
 * capability_identifier rule applies only OUTSIDE these. Matched as path suffixes; the census
 * test asserts each entry still resolves to a walked file (staleness guard).
 */
export const IDENTIFIER_EXEMPT_FILES = [
  join("operations", "capabilities.contract.ts"),
  join("launch-deferral", "deferral.contract.ts"),
] as const;

export interface AbsenceAllowlistEntry {
  readonly relativePath: string;
  readonly content: string;
  readonly reason: string;
}

/**
 * Frozen prose lines that legitimately quote the deferred pair or the reserved 'imported'
 * state — plus third-party API identifiers whose spelling this repo does not own — pinned by
 * file + exact trimmed content, exempting every content class on that one line only. Each
 * entry goes stale (and starts failing the census test's liveness guard) the moment its
 * pinned line changes.
 */
export const ABSENCE_LINE_ALLOWLIST: readonly AbsenceAllowlistEntry[] = [
  {
    relativePath: join("launch-deferral", "deferral.contract.ts"),
    content:
      "* feature, greenfield launch ships neither, and `key_origin='imported'` survives only as an",
    reason: "The deferral freeze file's own header comment quoting the reserved inert state.",
  },
  {
    relativePath: join("launch-deferral", "deferral.contract.ts"),
    content: `jointly_deferred: ["WALLET_IMPORT", "IMPORTED_DRAIN"],`,
    reason: "The deferral freeze file's own frozen pair citation inside CUTOVER_GATE.",
  },
  {
    relativePath: join("launch-deferral", "deferral.contract.ts"),
    content: `"send-source-origin exclusion census — reject key_origin='imported' as an external-send source",`,
    reason:
      "The deferral freeze's own frozen cutover prerequisite quoting the rejection rule it mandates; zero authority to write.",
  },
  {
    relativePath: join("push", "vapid-jwt.ts"),
    content: "const key = await webcrypto.subtle.importKey(",
    reason:
      "WebCrypto's own method name (ES256 VAPID signature verification, RFC 8292). Not a " +
      "wallet-key import surface: the material is the push service's public app-server key, " +
      "the usage is 'verify' only, and the spelling belongs to the platform API, not to us.",
  },
];

/** Splits a raw fragment into lowercase tokens on camelCase boundaries and non-alphanumerics. */
const tokenize = (raw: string): string[] =>
  raw
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length > 0);

const intersects = (tokens: readonly string[], needles: readonly string[]): boolean =>
  tokens.some((token) => needles.includes(token));

const QUOTED_STRING = /(["'`])([^"'`\n]*)\1/g;
const IDENTIFIER = /[A-Za-z_$][A-Za-z0-9_$]*/g;
const WHITESPACE = /\s/;

const ORIGIN_ASSIGNMENT = /key_?origin\s*(?::|=(?![=>]))\s*["']imported["']/i;
const ORIGIN_SQL_WRITE = /(?:insert\s+into\s+wallets|update\s+wallets)\b.*\bimported\b/i;

const isCapabilityIdentifier = (identifier: string): boolean => {
  const tokens = tokenize(identifier);
  if (intersects(tokens, IMPORT_TOKENS) && intersects(tokens, WALLET_TOKENS)) {
    return true;
  }
  return (
    intersects(tokens, REMOVAL_TOKENS) &&
    (intersects(tokens, WALLET_TOKENS) || tokens.includes(IMPORTED_KEY_ORIGIN))
  );
};

const isTestFile = (filePath: string): boolean => filePath.endsWith(".test.ts");

const isIdentifierExempt = (filePath: string): boolean =>
  IDENTIFIER_EXEMPT_FILES.some((suffix) => filePath.endsWith(suffix));

const isAllowlistedLine = (filePath: string, trimmedLine: string): boolean =>
  ABSENCE_LINE_ALLOWLIST.some(
    (entry) => filePath.endsWith(entry.relativePath) && trimmedLine === entry.content,
  );

/**
 * Scans one file's text for every absence-surface signature class. Pure: the caller owns the
 * walk and the read. `line` is 1-based, or 0 for the line-less surface_file_name class.
 */
export const scanFileForAbsenceSurfaces = (input: AbsenceScanInput): AbsenceViolation[] => {
  const violations: AbsenceViolation[] = [];
  const baseName = input.filePath.split(/[\\/]/).pop() ?? input.filePath;

  if (intersects(tokenize(baseName), [...VERB_TOKENS, IMPORTED_KEY_ORIGIN])) {
    violations.push({
      file: input.filePath,
      line: 0,
      surfaceClass: "surface_file_name",
      excerpt: baseName,
    });
  }

  if (isTestFile(input.filePath)) {
    return violations;
  }

  input.text.split("\n").forEach((line, index) => {
    if (line.includes(EXEMPTION_MARKER_PREFIX)) {
      return;
    }
    const trimmed = line.trim();
    if (isAllowlistedLine(input.filePath, trimmed)) {
      return;
    }
    const report = (surfaceClass: AbsenceSurfaceClass): void => {
      violations.push({ file: input.filePath, line: index + 1, surfaceClass, excerpt: trimmed });
    };

    for (const match of line.matchAll(QUOTED_STRING)) {
      const content = match[2];
      if (content === undefined) {
        continue;
      }
      const tokens = tokenize(content);
      if (content.startsWith("/") && intersects(tokens, VERB_TOKENS)) {
        report("route_path");
      }
      if (!WHITESPACE.test(content) && tokens.length >= 2 && intersects(tokens, VERB_TOKENS)) {
        report("command_name");
      }
    }

    if (!isIdentifierExempt(input.filePath)) {
      const hit = [...line.matchAll(IDENTIFIER)].find((match) =>
        isCapabilityIdentifier(match[0]),
      );
      if (hit !== undefined) {
        report("capability_identifier");
      }
    }

    if (ORIGIN_ASSIGNMENT.test(line) || ORIGIN_SQL_WRITE.test(line)) {
      report("origin_write");
    }
  });

  return violations;
};

export const SOURCE =
  "launch-capability-deferral; data-model key_origin domain; api launch surface" as const;
