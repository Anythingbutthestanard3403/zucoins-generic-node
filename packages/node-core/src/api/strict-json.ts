// Strict JSON intake: rejects duplicate keys, non-UTF-8, oversized bodies,
// and wrong nesting depth AHEAD of any schema check. This is the first gate in the
// validation pipeline — no Zod parse runs until the raw bytes pass this check.

export const DEFAULT_MAX_BODY_BYTES = 1_048_576; // 1 MiB
export const DEFAULT_MAX_NESTING_DEPTH = 16;

export type StrictJsonRejectionCode =
  | "request_too_large"
  | "invalid_utf8"
  | "malformed_json"
  | "duplicate_json_key"
  | "nesting_too_deep";

export interface StrictJsonSuccess {
  readonly ok: true;
  readonly value: unknown;
}

export interface StrictJsonFailure {
  readonly ok: false;
  readonly code: StrictJsonRejectionCode;
}

export type StrictJsonOutcome = StrictJsonSuccess | StrictJsonFailure;

export interface StrictJsonConfig {
  readonly maxBodyBytes: number;
  readonly maxNestingDepth: number;
}

const DEFAULT_CONFIG: StrictJsonConfig = {
  maxBodyBytes: DEFAULT_MAX_BODY_BYTES,
  maxNestingDepth: DEFAULT_MAX_NESTING_DEPTH,
};

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

// Detect duplicate keys by scanning the raw JSON text. A reviver-based parse cannot
// detect duplicates (last-wins silently), so we use a character-level scan that tracks
// keys per object scope.
function hasDuplicateKeys(text: string): boolean {
  const stack: (Set<string> | null)[] = [];
  let inString = false;
  let escaped = false;
  let currentKey = "";
  let collectingKey = false;
  let expectValue = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;

    if (escaped) {
      if (collectingKey) currentKey += ch;
      escaped = false;
      continue;
    }

    if (ch === "\\" && inString) {
      escaped = true;
      if (collectingKey) currentKey += ch;
      continue;
    }

    if (ch === '"') {
      if (!inString) {
        inString = true;
        currentKey = "";
        const scope = stack.length > 0 ? stack[stack.length - 1] : null;
        collectingKey = scope !== null && !expectValue;
      } else {
        inString = false;
        if (collectingKey && stack.length > 0) {
          const scope = stack[stack.length - 1];
          if (scope !== null) {
            if (scope.has(currentKey)) return true;
            scope.add(currentKey);
          }
        }
        collectingKey = false;
        expectValue = false;
      }
      continue;
    }

    if (inString) {
      if (collectingKey) currentKey += ch;
      continue;
    }

    if (ch === "{") {
      stack.push(new Set());
      expectValue = false;
    } else if (ch === "}") {
      stack.pop();
      expectValue = false;
    } else if (ch === "[") {
      stack.push(null);
      expectValue = false;
    } else if (ch === "]") {
      stack.pop();
      expectValue = false;
    } else if (ch === ":") {
      expectValue = true;
    } else if (ch === ",") {
      expectValue = false;
    }
  }
  return false;
}

function measureDepth(text: string): number {
  let maxDepth = 0;
  let current = 0;
  let inStr = false;
  let esc = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (esc) {
      esc = false;
      continue;
    }
    if (ch === "\\" && inStr) {
      esc = true;
      continue;
    }
    if (ch === '"') {
      inStr = !inStr;
      continue;
    }
    if (inStr) continue;
    if (ch === "{" || ch === "[") {
      current++;
      if (current > maxDepth) maxDepth = current;
    } else if (ch === "}" || ch === "]") {
      current--;
    }
  }
  return maxDepth;
}

export function parseStrictJson(
  bodyBytes: Uint8Array,
  config: Partial<StrictJsonConfig> = {},
): StrictJsonOutcome {
  const { maxBodyBytes, maxNestingDepth } = { ...DEFAULT_CONFIG, ...config };

  if (bodyBytes.length > maxBodyBytes) {
    return { ok: false, code: "request_too_large" };
  }

  let text: string;
  try {
    text = UTF8_DECODER.decode(bodyBytes);
  } catch {
    return { ok: false, code: "invalid_utf8" };
  }

  if (measureDepth(text) > maxNestingDepth) {
    return { ok: false, code: "nesting_too_deep" };
  }

  if (hasDuplicateKeys(text)) {
    return { ok: false, code: "duplicate_json_key" };
  }

  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, code: "malformed_json" };
  }

  return { ok: true, value };
}
