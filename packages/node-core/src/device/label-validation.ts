// A.4.3 label validation — enforced against exact received bytes, never a normalized copy.
// 1–80 Unicode scalars, ≤320 UTF-8 bytes, well-formed UTF-8, denylist enforcement.

import type { DeviceEnrolmentRejectionCode } from "./types.js";

const MAX_LABEL_SCALARS = 80;
const MAX_LABEL_UTF8_BYTES = 320;

export type LabelValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: DeviceEnrolmentRejectionCode; readonly detail: string };

export function validateDeviceLabel(label: string): LabelValidationResult {
  if (label.length === 0) {
    return { ok: false, code: "LABEL_EMPTY", detail: "label must not be empty" };
  }

  const scalarCount = countUnicodeScalars(label);
  if (scalarCount > MAX_LABEL_SCALARS) {
    return {
      ok: false,
      code: "LABEL_TOO_LONG_SCALARS",
      detail: `label exceeds ${MAX_LABEL_SCALARS} Unicode scalars (got ${scalarCount})`,
    };
  }

  const utf8Bytes = new TextEncoder().encode(label);
  if (utf8Bytes.length > MAX_LABEL_UTF8_BYTES) {
    return {
      ok: false,
      code: "LABEL_TOO_LONG_BYTES",
      detail: `label exceeds ${MAX_LABEL_UTF8_BYTES} UTF-8 bytes (got ${utf8Bytes.length})`,
    };
  }

  if (!isWellFormedUtf8(label)) {
    return { ok: false, code: "LABEL_MALFORMED_UTF8", detail: "label contains malformed UTF-8" };
  }

  if (label.startsWith(" ") || label.endsWith(" ")) {
    return {
      ok: false,
      code: "LABEL_LEADING_TRAILING_SPACE",
      detail: "label must not have leading or trailing space",
    };
  }

  for (const ch of label) {
    const cp = ch.codePointAt(0)!;
    const rejection = classifyDeniedCodepoint(cp);
    if (rejection !== null) return rejection;
  }

  return { ok: true };
}

function countUnicodeScalars(s: string): number {
  let count = 0;
  for (const _ of s) count++;
  return count;
}

function isWellFormedUtf8(s: string): boolean {
  // JS strings are UTF-16; lone surrogates indicate malformed input
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function classifyDeniedCodepoint(cp: number): { ok: false; code: DeviceEnrolmentRejectionCode; detail: string } | null {
  // C0 controls U+0000–U+001F and U+007F
  if (cp <= 0x001f || cp === 0x007f) {
    return { ok: false, code: "LABEL_CONTROL_CHARS", detail: `label contains C0 control U+${cp.toString(16).toUpperCase().padStart(4, "0")}` };
  }
  // C1 controls U+0080–U+009F
  if (cp >= 0x0080 && cp <= 0x009f) {
    return { ok: false, code: "LABEL_CONTROL_CHARS", detail: `label contains C1 control U+${cp.toString(16).toUpperCase().padStart(4, "0")}` };
  }
  // Surrogates U+D800–U+DFFF
  if (cp >= 0xd800 && cp <= 0xdfff) {
    return { ok: false, code: "LABEL_SURROGATES", detail: `label contains surrogate U+${cp.toString(16).toUpperCase().padStart(4, "0")}` };
  }
  // Noncharacters U+FDD0–U+FDEF
  if (cp >= 0xfdd0 && cp <= 0xfdef) {
    return { ok: false, code: "LABEL_NONCHARACTERS", detail: `label contains noncharacter U+${cp.toString(16).toUpperCase().padStart(4, "0")}` };
  }
  // Noncharacters U+xFFFE, U+xFFFF (and plane-end pairs)
  if ((cp & 0xfffe) === 0xfffe) {
    return { ok: false, code: "LABEL_NONCHARACTERS", detail: `label contains noncharacter U+${cp.toString(16).toUpperCase().padStart(4, "0")}` };
  }
  // Line/paragraph separators U+2028, U+2029
  if (cp === 0x2028 || cp === 0x2029) {
    return { ok: false, code: "LABEL_LINE_SEPARATORS", detail: `label contains line/paragraph separator U+${cp.toString(16).toUpperCase().padStart(4, "0")}` };
  }
  // BOM/ZWNBSP U+FEFF
  if (cp === 0xfeff) {
    return { ok: false, code: "LABEL_BOM", detail: "label contains BOM/ZWNBSP U+FEFF" };
  }
  // Zero-width / BiDi format controls U+200B–U+200D
  if (cp >= 0x200b && cp <= 0x200d) {
    return { ok: false, code: "LABEL_BIDI_CONTROLS", detail: `label contains zero-width format control U+${cp.toString(16).toUpperCase().padStart(4, "0")}` };
  }
  // BiDi controls U+202A–U+202E
  if (cp >= 0x202a && cp <= 0x202e) {
    return { ok: false, code: "LABEL_BIDI_CONTROLS", detail: `label contains BiDi control U+${cp.toString(16).toUpperCase().padStart(4, "0")}` };
  }
  // BiDi isolate controls U+2066–U+2069
  if (cp >= 0x2066 && cp <= 0x2069) {
    return { ok: false, code: "LABEL_BIDI_CONTROLS", detail: `label contains BiDi isolate U+${cp.toString(16).toUpperCase().padStart(4, "0")}` };
  }
  return null;
}
