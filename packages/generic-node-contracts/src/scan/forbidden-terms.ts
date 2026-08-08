/**
 * Token-level forbidden-vocabulary scanner (the scan/dependency-boundary gate). Catches legacy product-projection
 * vocabulary leaking into the generic core — e.g. `checkout`, `payment`, `sweep` — including
 * conservative plural/inflected forms (`payments`, `sweeping`, `treasuries`, `refunded`) via
 * whole-word tokenization plus suffix stripping, without false-positiving on compatibility
 * literals like `zupayments` (the compatibility-literal preservation rule): `zupayments` is one unbroken token, so it is compared
 * to the term list as `zupayments`/`zupayment` (post-strip), never as a substring match
 * against `payment`.
 */
export const FORBIDDEN_TERMS = [
  "payment",
  "refund",
  "sweep",
  "treasury",
  "checkout",
  "payout",
  "withdrawal",
  "order",
  "merchant",
  "reservation",
  "outbound",
  "drain",
  "ZUC",
  "finalised",
  "fulfilled",
  "treasury settlement",
] as const;

export type ForbiddenTerm = (typeof FORBIDDEN_TERMS)[number];

export interface ScanViolation {
  readonly file: string;
  readonly line: number;
  readonly term: ForbiddenTerm;
  readonly excerpt: string;
}

/**
 * Frozen path list this scan protects. Grows as later slices add concern directories or
 * packages; see the broad-scope drift-gate decision.
 * `packages/node-core/src` and `apps/generic-node/src` (v2 workspace skeleton)
 * joined 2026-07-19 — they are v2 generic-core surface now, so the scan must cover them from
 * day one. The scanner's own
 * directory (`src/scan/**`) is never itself a scan target: this module's `FORBIDDEN_TERMS`
 * literal and its self-test fixtures necessarily contain every forbidden word, the same way
 * a lint rule's own definition file is not linted against the pattern it forbids.
 */
export const SCAN_SCOPE = [
  "packages/generic-node-contracts/src",
  "packages/node-core/src",
  "apps/generic-node/src",
] as const;

export const EXEMPTION_MARKER_PREFIX = "contract-allow:";

/**
 * `contract-allow:<reason>`-marked lines are historical quotes of retired/forbidden
 * vocabulary with zero authority, or frozen contract bytes (SQL text, a snapshot-synced
 * field name, a concern's own module path) whose exact content a D-numbered freeze governs
 * and a lane cannot reword without changing byte authority. This constant is the exact, live
 * count of those markers across the scanned tree — `forbidden-terms.test.ts`'s "live
 * marked-line count" test fails if it drifts. Any lane adding, removing, or exempting a
 * marker MUST update this count in the same change; a hit with zero test/golden coupling
 * should be reworded meaning-preserving instead of exempted (see CONTRACT.md files for
 * concern-specific frozen vocabulary).
 */
export const FROZEN_EXEMPTION_COUNT = 205 as const;

/**
 *  AC3 — the companion freeze that `FROZEN_EXEMPTION_COUNT` cannot provide. The marked-LINE
 * count above is blind to what a marked line contains: an existing `contract-allow` line extended
 * with genuine product vocabulary keeps the line count at 110 and ships silently. This is the exact,
 * live count of forbidden-term HITS the markers suppress across the whole `SCAN_SCOPE` — the same
 * files, and the same `D99_ALLOWLIST`, the real gate (`generic-core.scan-gate.test.ts`) walks — so
 * that edit moves this number and `forbidden-terms.test.ts` fails. Any lane adding, removing, or
 * widening a marker MUST update this count in the same change, exactly as for the line count.
 */
export const FROZEN_SUPPRESSED_VIOLATION_COUNT = 203 as const;

const FORBIDDEN_TERM_BY_LOWER = new Map<string, ForbiddenTerm>(
  FORBIDDEN_TERMS.map((term) => [term.toLowerCase(), term]),
);

/**
 * Multi-word terms in `FORBIDDEN_TERMS` (currently only `treasury settlement`, per
 * the node-core spec) cannot be caught by single-token matching, so each gets a
 * case-insensitive whole-phrase matcher. A phrase hit suppresses token hits inside its span —
 * the phrase is the more specific classification, and reporting the phrase's head token too
 * would double-count one occurrence.
 */
const FORBIDDEN_PHRASE_MATCHERS = FORBIDDEN_TERMS.filter((term) => term.includes(" ")).map(
  (term) => ({
    term,
    pattern: new RegExp(`\\b${term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "gi"),
  }),
);

/**
 *  AC5 — stemmer allowlist. The suffix stripper turns ordinary technical English into a
 * product-vocabulary hit: `ordering` -> `order`, `draining` -> `drain`. "event ordering",
 * "an ordered list", "draining a queue" are structural descriptions, not the merchant-order or
 * treasury-drain projections the scan/dependency-boundary gate exists to keep out, so they are exempted at the STEM step
 * only. Three deliberate bounds:
 *  - the exemption applies ONLY to a suffix-derived match. A DIRECT hit on a listed term is never
 *    exempt, so `order`, `orders`, `drain`, `drains` still flag — including on these lines.
 *  - it is a closed token list, not a suffix rule: a new inflection is a reviewed addition here.
 *  - `drained`/`drains` are NOT on it. "the pool was drained" is the product projection itself
 *    (cf. the retired `/admin/v1/drains*` route); only the progressive `draining` reads as the
 *    structural sense.
 */
const STEM_EXEMPT_TOKENS = new Set([
  "ordering",
  "orderings",
  "reordering",
  "reorderings",
  "ordered",
  "reordered",
  "unordered",
  "draining",
]);

/**
 * Suffix strips tried against a whole-word token when it has no direct match, longest/most
 * specific first (`ies` before the plain `s` it would otherwise also satisfy). `ies` restores
 * the elided `y` (`treasuries` -> `treasury`); `ing`/`ed`/`es`/`s` are straight truncations.
 * This is deliberately not a full stemmer — irregular forms (e.g. `swept`) are out of scope.
 */
const SUFFIX_STRIPS: ReadonlyArray<{ readonly suffix: string; readonly strip: (token: string) => string }> = [
  { suffix: "ies", strip: (token) => `${token.slice(0, -3)}y` },
  { suffix: "ing", strip: (token) => token.slice(0, -3) },
  { suffix: "ed", strip: (token) => token.slice(0, -2) },
  { suffix: "es", strip: (token) => token.slice(0, -2) },
  { suffix: "s", strip: (token) => token.slice(0, -1) },
];

/**
 * Resolves a whole-word token to the canonical `ForbiddenTerm` it matches, trying the token
 * as-is first and then each suffix-stripped stem. Returns `undefined` for no match, including
 * `zupayments`/`zupay` (the compatibility-literal preservation rule): as single tokens, neither they nor their one-level-stripped
 * stems (`zupayment`, `zupay`) ever equal a listed term.
 */
const matchForbiddenTerm = (token: string): ForbiddenTerm | undefined => {
  const lower = token.toLowerCase();
  const direct = FORBIDDEN_TERM_BY_LOWER.get(lower);
  if (direct !== undefined) {
    return direct;
  }
  if (STEM_EXEMPT_TOKENS.has(lower)) {
    return undefined;
  }
  for (const { suffix, strip } of SUFFIX_STRIPS) {
    if (lower.length > suffix.length && lower.endsWith(suffix)) {
      const stemmed = FORBIDDEN_TERM_BY_LOWER.get(strip(lower));
      if (stemmed !== undefined) {
        return stemmed;
      }
    }
  }
  return undefined;
};

const isWithinAllowlistedSpan = (
  line: string,
  matchIndex: number,
  matchLength: number,
  allowlist: readonly string[],
): boolean => {
  for (const allowed of allowlist) {
    let searchFrom = 0;
    let idx = line.indexOf(allowed, searchFrom);
    while (idx !== -1) {
      if (matchIndex >= idx && matchIndex + matchLength <= idx + allowed.length) {
        return true;
      }
      searchFrom = idx + 1;
      idx = line.indexOf(allowed, searchFrom);
    }
  }
  return false;
};

interface ExemptionMarker {
  readonly start: number;
  readonly end: number;
  /** The terms this marker exempts, or `null` for the legacy whole-line form. */
  readonly terms: readonly ForbiddenTerm[] | null;
}

/**
 *  AC3 — token-named `contract-allow` markers.
 *
 * `contract-allow:<term>[,<term>...]:<reason>` exempts ONLY the named terms on that line; any
 * other forbidden term on the same line still flags. The legacy `contract-allow:<reason>` form —
 * every marker in the tree today, and the only form available to a multi-word term such as
 * `treasury settlement`, whose name cannot survive the whitespace-terminated payload — still
 * suppresses the whole line, but no longer silently: `countSuppressedViolations` counts what each
 * marker actually hides, and `forbidden-terms.test.ts` freezes that number, so extending an
 * already-marked line with fresh product vocabulary now fails the gate instead of riding in under
 * an unchanged marker count.
 *
 * A marker's own bytes are excluded from detection — otherwise `contract-allow:refund:...` would
 * report the `refund` it exists to name.
 */
const parseExemptionMarkers = (line: string): ExemptionMarker[] => {
  const markers: ExemptionMarker[] = [];
  let index = line.indexOf(EXEMPTION_MARKER_PREFIX);
  while (index !== -1) {
    const payloadStart = index + EXEMPTION_MARKER_PREFIX.length;
    let end = payloadStart;
    while (end < line.length && !/[\s`*]/.test(line[end])) {
      end += 1;
    }
    const namedField = line.slice(payloadStart, end).split(":")[0] ?? "";
    const candidates = namedField
      .split(",")
      .map((candidate) => candidate.trim().toLowerCase())
      .filter((candidate) => candidate.length > 0);
    const named =
      candidates.length > 0 && candidates.every((candidate) => FORBIDDEN_TERM_BY_LOWER.has(candidate))
        ? candidates.map((candidate) => FORBIDDEN_TERM_BY_LOWER.get(candidate) as ForbiddenTerm)
        : null;
    markers.push({ start: index, end, terms: named });
    index = line.indexOf(EXEMPTION_MARKER_PREFIX, index + 1);
  }
  return markers;
};

const isSuppressedByMarkers = (
  markers: readonly ExemptionMarker[],
  term: ForbiddenTerm,
): boolean =>
  markers.some((marker) => marker.terms === null || marker.terms.includes(term));

interface ScanResult {
  readonly violations: ScanViolation[];
  /** Hits a `contract-allow` marker suppressed — the accounting half of AC3. */
  readonly suppressed: number;
}

/**
 * Scans `text` line by line for whole-word tokens matching `FORBIDDEN_TERMS` (directly or via
 * a conservative suffix-stripped stem) and for whole-phrase matches of any multi-word term.
 * A match whose span falls entirely within an `allowlist` literal (e.g. the compatibility-literal preservation rule compatibility
 * name) is exempted, defending against a future allowlist literal that happens to contain a
 * forbidden stem. A token inside a phrase match's span is reported as the phrase, not again as
 * its own term. `contract-allow` markers are applied per-term (see `parseExemptionMarkers`), and
 * whatever they hide is counted rather than discarded.
 */
const scanText = (
  text: string,
  filePath: string,
  allowlist: readonly string[],
): ScanResult => {
  const violations: ScanViolation[] = [];
  let suppressed = 0;
  const textLines = text.split("\n");

  textLines.forEach((line, index) => {
    const markers = parseExemptionMarkers(line);
    const isInsideMarker = (start: number, length: number): boolean =>
      markers.some((marker) => start >= marker.start && start + length <= marker.end);
    const record = (term: ForbiddenTerm): void => {
      if (isSuppressedByMarkers(markers, term)) {
        suppressed += 1;
        return;
      }
      violations.push({ file: filePath, line: index + 1, term, excerpt: line.trim() });
    };

    const phraseSpans: Array<{ readonly start: number; readonly end: number }> = [];
    for (const { term, pattern } of FORBIDDEN_PHRASE_MATCHERS) {
      for (const match of line.matchAll(pattern)) {
        if (
          match.index !== undefined &&
          !isInsideMarker(match.index, match[0].length) &&
          !isWithinAllowlistedSpan(line, match.index, match[0].length, allowlist)
        ) {
          record(term);
          phraseSpans.push({ start: match.index, end: match.index + match[0].length });
        }
      }
    }
    for (const token of line.matchAll(/\w+/g)) {
      const term = matchForbiddenTerm(token[0]);
      if (
        term !== undefined &&
        token.index !== undefined &&
        !isInsideMarker(token.index, token[0].length) &&
        !phraseSpans.some(
          (span) => token.index >= span.start && token.index + token[0].length <= span.end,
        ) &&
        !isWithinAllowlistedSpan(line, token.index, token[0].length, allowlist)
      ) {
        record(term);
      }
    }
  });

  return { violations, suppressed };
};

export const scanTextForForbiddenTerms = (
  text: string,
  filePath: string,
  allowlist: readonly string[] = [],
): ScanViolation[] => scanText(text, filePath, allowlist).violations;

/**
 * Counts the forbidden-term hits `contract-allow` markers actually suppress in `text`. Frozen by
 * `forbidden-terms.test.ts` as `FROZEN_SUPPRESSED_VIOLATION_COUNT`: this is the number that moves
 * when a marked line grows a new hit, which the marked-LINE count below cannot see.
 */
export const countSuppressedViolations = (
  text: string,
  allowlist: readonly string[] = [],
): number => scanText(text, "", allowlist).suppressed;

/** Counts `contract-allow:<reason>`-marked lines in `text`. */
export const countExemptionMarkers = (text: string): number =>
  text.split("\n").filter((line) => line.includes(EXEMPTION_MARKER_PREFIX)).length;

export const SOURCE =
  "decision: three-generic-operations; decision: drift-gate-scanner; ../../CONTRACT.md \"Drift-gate scanner (forbidden vocabulary)\"" as const;
