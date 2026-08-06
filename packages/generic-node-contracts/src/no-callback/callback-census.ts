// Attack-census audit correction (defect 2 — exemption over-breadth + verb-variant census). The pure
// callback/webhook/push surface census.
//
// This module is the DETECTOR: it names the forbidden surface vocabulary as detection patterns, so
// the freeze-gate census excludes this file (and its test) from its own scan — a detector naming the
// patterns it detects is not "introducing a surface". Everything here is a pure string function
// (no I/O); the freeze test wires it to the real source tree.
//
// CONTRACT_FREEZE.
import { deepFreeze } from "./deep-freeze.js";

interface SurfacePattern {
  readonly label: string;
  readonly pattern: RegExp;
}

// The verb-variant matrix: field, registration/subscription, retry, delivery-worker, dispatch, and
// route surfaces across the callback / webhook / push families, plus a bare send-side-URL literal
// (a pure contracts package has no legitimate send-side URL in live code). Patterns match the SURFACE
// shape, not the bare word, so a verifier named `callbackHostForbidden` or an Array `.push(` is not
// flagged, while `callbackUrl`, `register_webhook`, `push_subscription`, and `/webhooks` are.
export const CALLBACK_SURFACE_MATRIX: readonly SurfacePattern[] = deepFreeze([
  { label: "callback_url_field", pattern: /callback[_-]?url/i },
  { label: "webhook_url_field", pattern: /webhook[_-]?url/i },
  { label: "push_url_field", pattern: /push[_-]?url/i },
  { label: "notify_url_field", pattern: /notify[_-]?url/i },
  { label: "callback_registration", pattern: /callback[_-]?registration/i },
  { label: "register_push_endpoint", pattern: /register[_-]?(?:callback|webhook|push)/i },
  { label: "subscribe_push_endpoint", pattern: /subscribe[_-]?(?:callback|webhook|push)/i },
  { label: "push_subscription", pattern: /(?:callback|webhook|push)[_-]?subscription/i },
  { label: "callback_retry", pattern: /callback[_-]?retry/i },
  { label: "delivery_worker", pattern: /(?:callback|node[_-]?initiated[_-]?delivery|webhook[_-]?delivery)[_-]?worker/i },
  { label: "dispatch_push", pattern: /(?:post|send|emit|fire|dispatch|deliver)[_-]?(?:callback|webhook)/i },
  // Route patterns require a route-segment boundary after the word (not [\w-]), so an import-path
  // fragment like "./callback-census.js" or a hyphenated filename is not mistaken for a route.
  { label: "callback_route", pattern: /\/callbacks?(?![\w-])/i },
  { label: "webhook_route", pattern: /\/webhooks?(?![\w-])/i },
  { label: "push_route", pattern: /\/push(?![\w-])/i },
  { label: "outbound_url_literal", pattern: /https?:\/\//i },
]);

// True iff `source` contains any surface, returning the sorted, de-duplicated set of matched labels.
// Comments are masked first (defect 3) so a comment-only mention is neutral, while a live surface —
// including one built inside a template interpolation — is still detected.
export function scanForCallbackSurfaces(source: string): string[] {
  const scanned = maskComments(source);
  const found = new Set<string>();
  for (const { label, pattern } of CALLBACK_SURFACE_MATRIX) {
    if (pattern.test(scanned)) found.add(label);
  }
  return [...found].sort();
}

// True iff `file` is the concern directory itself or a descendant of it, bounded by a path
// separator — so `no-callback-evil/` (a sibling that shares the string prefix) is NOT exempt.
export function isConcernPathExempt(file: string, concernDir: string): boolean {
  return file === concernDir || file.startsWith(`${concernDir}/`) || file.startsWith(`${concernDir}\\`);
}

// Comment mask (defect 3): blank line (`//`) and block (`/* */`) comments so a mention of a surface
// inside a comment does not count as a live surface, WITHOUT blanking real code. It preserves string
// and template-literal text (a real route is often a string literal), preserves code inside template
// interpolations `${...}` (so an interpolated surface is still detected), and understands regex
// literals (so a `/` inside a regex body or char class is not misread as a comment). Length- and
// newline-preserving: only comment characters become spaces.
export function maskComments(source: string): string {
  const out = source.split("");
  const n = source.length;
  const blank = (i: number): void => {
    if (out[i] !== "\n") out[i] = " ";
  };
  // Consume a template literal's text starting just after an opening/resuming backtick or `${...}`.
  // Returns true if it broke into a `${` interpolation (control returns to the main loop as code).
  const consumeTemplateText = (start: number): { next: number; entered: boolean } => {
    let i = start;
    while (i < n) {
      if (source[i] === "\\") {
        i += 2;
        continue;
      }
      if (source[i] === "`") return { next: i + 1, entered: false };
      if (source[i] === "$" && source[i + 1] === "{") return { next: i + 2, entered: true };
      i++;
    }
    return { next: i, entered: false };
  };
  // Brace depth at which each open `${...}` interpolation began, so its matching `}` resumes text.
  const templateStack: number[] = [];
  let braceDepth = 0;
  let i = 0;
  while (i < n) {
    const c = source[i];
    const d = source[i + 1];
    if (c === "/" && d === "/") {
      while (i < n && source[i] !== "\n") blank(i++);
      continue;
    }
    if (c === "/" && d === "*") {
      blank(i++);
      blank(i++);
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) blank(i++);
      if (i < n) {
        blank(i++);
        blank(i++);
      }
      continue;
    }
    if (c === "'" || c === '"') {
      i++;
      while (i < n && source[i] !== c) {
        if (source[i] === "\\") i++;
        i++;
      }
      i++;
      continue;
    }
    if (c === "`") {
      const r = consumeTemplateText(i + 1);
      i = r.next;
      if (r.entered) {
        templateStack.push(braceDepth);
        braceDepth++;
      }
      continue;
    }
    if (c === "{") {
      braceDepth++;
      i++;
      continue;
    }
    if (c === "}") {
      braceDepth--;
      i++;
      if (templateStack.length > 0 && braceDepth === templateStack[templateStack.length - 1]) {
        templateStack.pop();
        const r = consumeTemplateText(i);
        i = r.next;
        if (r.entered) {
          templateStack.push(braceDepth);
          braceDepth++;
        }
      }
      continue;
    }
    if (c === "/" && regexStartsHere(source, i)) {
      i++;
      let inClass = false;
      while (i < n) {
        const rc = source[i];
        if (rc === "\\") {
          i += 2;
          continue;
        }
        if (rc === "[") inClass = true;
        else if (rc === "]") inClass = false;
        else if (rc === "/" && !inClass) {
          i++;
          break;
        } else if (rc === "\n") break;
        i++;
      }
      continue;
    }
    i++;
  }
  return out.join("");
}

// A `/` begins a regex literal (rather than a division operator) when the previous non-whitespace
// character is not the end of a value — i.e. not an identifier char or a closing `)`/`]`. For
// masking, its only job is to keep an inner `//` from being read as a line comment.
function regexStartsHere(source: string, slashIndex: number): boolean {
  let j = slashIndex - 1;
  while (j >= 0 && (source[j] === " " || source[j] === "\t")) j--;
  if (j < 0) return true;
  return !/[A-Za-z0-9_$)\]]/.test(source[j] ?? "");
}
