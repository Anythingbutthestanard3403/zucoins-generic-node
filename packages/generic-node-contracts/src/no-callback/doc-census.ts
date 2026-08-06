// Docs anti-reintroduction extension. callback-census.ts's
// CALLBACK_SURFACE_MATRIX is tuned to code: it matches SURFACE SHAPES (callback_url, /webhooks routes,
// registerWebhook(...)) rather than the bare words, precisely so `Array.push(...)` or a verifier named
// `callbackHostForbidden` does not false-positive. Documentation is prose, not executable code — there
// is no `Array.push()` shape to protect against — so a reintroduced callback/webhook/push description
// can read as ordinary sentences with no code-shaped field/route name at all. This module scans for the
// bare callback-term class directly; the doc-census freeze test (doc-census.freeze.test.ts) walks the
// v2 proposal docs tree and applies the frozen line/file allowlist on top.
//
// CONTRACT_FREEZE.
import { deepFreeze } from "./deep-freeze.js";

interface DocTermPattern {
  readonly label: string;
  readonly pattern: RegExp;
}

// Word-boundary bare terms: the callback/webhook/push family a reintroduced callback mechanism would
// be described with in prose, independent of any code-shaped field/route/worker name.
export const DOC_CALLBACK_TERM_CLASS: readonly DocTermPattern[] = deepFreeze([
  { label: "callback_term", pattern: /\bcallbacks?\b/i },
  { label: "webhook_term", pattern: /\bwebhooks?\b/i },
  { label: "push_term", pattern: /\bpush(?:e[sd]|ing)?\b/i },
]);

// True iff `source` contains any callback-term-class match, returning the sorted, de-duplicated set
// of matched labels. No comment/string masking: a doc has no code constructs to mask around.
export function scanForCallbackTerms(source: string): string[] {
  const found = new Set<string>();
  for (const { label, pattern } of DOC_CALLBACK_TERM_CLASS) {
    if (pattern.test(source)) found.add(label);
  }
  return [...found].sort();
}
