// Canonical field encoders for the suite-tuple serializer (Appendix).
//
// Each encoder validates ONE trust-boundary value and returns the JSON-ready canonical form the
// single top-level `JSON.stringify` pass will emit (the byte-exact signing rule: byte-exact, never reformatted).
// Scalar encoders reuse the canonical parsers (packages/node-core/src/protocol/scalars.ts,
// amounts.ts) verbatim — this module never re-implements a scalar grammar already froze; it
// only adds the field kinds Appendix A needs that does not expose (canonical RFC3339
// timestamp, anchor, HTTP method/origin-path, label, positive decimal seq, closed enums, and the
// two structured composites AfterLanding / SourceSelector).
//
// Every encoder is a pure function and rejects rather than
// coerces; on rejection it stores only a static reason + field name, never attacker-supplied bytes.

import {
  parseCanonicalVersion,
  parseEd25519Signature,
  parseExpiryUnixTimeSecs,
  parseOpaqueReference,
  parsePreviousStateSignature,
  parseSha256Hex,
  parseUuid,
  parseWalletPublicKey,
} from "../scalars.js";
import { parseObservedZkzBalance, parsePositiveZkzAmount } from "../amounts.js";

// A JSON value the canonical serializer may emit. Suite tuples are objects of scalars plus the two
// structured composites; no suite tuple carries a top-level array, so the array arm is intentionally
// absent (a homogeneous-list encoder is deferred until a tuple that needs one is frozen — minting an
// untested list vector would violate the golden discipline).
export type JsonScalar = string | number | null;
export interface JsonObject {
  readonly [key: string]: JsonScalar | JsonObject;
}
export type CanonicalJson = JsonScalar | JsonObject;

// A canonical encoder validates an unknown boundary value and returns its exact JSON form, throwing
// on any non-canonical input. `null` handling lives in the serializer (the nullable wrapper), never
// in the encoder — an encoder is always called with a non-null value.
export type CanonicalEncoder = (value: unknown) => CanonicalJson;

export type FieldEncodingReason =
  | "wrong_type"
  | "invalid_format"
  | "invalid_enum"
  | "invalid_composite_shape"
  | "disallowed_scalar";

// Trust-boundary rejection for the field kinds this module adds. Mirrors InvalidScalarError
// discipline: it carries a static reason and the schema field/kind name only — never the rejected
// value or a derived excerpt — so logs and error serialization cannot echo signed material.
export class InvalidFieldError extends Error {
  readonly code = "INVALID_FIELD";

  constructor(
    readonly fieldKind: string,
    readonly reason: FieldEncodingReason,
  ) {
    super(`${fieldKind} failed canonical validation (${reason})`);
    this.name = "InvalidFieldError";
  }
}

const RFC3339_MS_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ANCHOR_PATTERN = /^[A-Za-z0-9_-]{1,96}$/;
const UPPERCASE_HTTP_METHOD_PATTERN = /^[A-Z]+$/;
const POSITIVE_DECIMAL_SEQ_PATTERN = /^[1-9][0-9]*$/;
const LABEL_MAX_CODE_POINTS = 80;
// A label is 1–80 code points (A.4.3). Any code point can be up to 4 UTF-8 bytes, so the byte ceiling
// is a loose guard behind the code-point ceiling that actually governs.
const LABEL_MAX_UTF8_BYTES = LABEL_MAX_CODE_POINTS * 4;

function requireString(value: unknown, fieldKind: string): string {
  if (typeof value !== "string") throw new InvalidFieldError(fieldKind, "wrong_type");
  return value;
}

// A canonical UTC RFC3339 timestamp with exactly three fractional digits and a `Z` (A.1.1 rule 3).
// The structural pattern rejects wrong fractional width / missing Z; the round-trip through Date
// additionally rejects an out-of-range calendar value (e.g. month 13) that the pattern alone admits.
export const encodeCanonicalTimestamp: CanonicalEncoder = (value) => {
  const text = requireString(value, "CanonicalTimestamp");
  if (!RFC3339_MS_PATTERN.test(text)) throw new InvalidFieldError("CanonicalTimestamp", "invalid_format");
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== text) {
    throw new InvalidFieldError("CanonicalTimestamp", "invalid_format");
  }
  return text;
};

export const encodeAnchor: CanonicalEncoder = (value) => {
  const text = requireString(value, "Anchor");
  if (!ANCHOR_PATTERN.test(text)) throw new InvalidFieldError("Anchor", "invalid_format");
  return text;
};

export const encodeHttpMethod: CanonicalEncoder = (value) => {
  const text = requireString(value, "HttpMethod");
  if (!UPPERCASE_HTTP_METHOD_PATTERN.test(text)) throw new InvalidFieldError("HttpMethod", "invalid_format");
  return text;
};

// An exact origin-form request target (A.5): begins with `/`, no whitespace, taken verbatim. Query
// canonicalization is the caller's concern before it reaches the signed tuple; the encoder only
// enforces the origin-form shape and rejects control/space characters that would corrupt the byte.
export const encodeOriginPath: CanonicalEncoder = (value) => {
  const text = requireString(value, "OriginPath");
  if (text.length === 0 || text[0] !== "/" || /[\s]/.test(text)) {
    throw new InvalidFieldError("OriginPath", "invalid_format");
  }
  return text;
};

// A.4.3's fail-closed denylist, by Unicode scalar value. Categories are pinned to Unicode 17.0 and
// treated as version-stable (A.4.3 "Unicode version pin"); the ranges are literal so a
// future table change is a reviewed edit here, never an implicit host-ICU behavior change.
function isDisallowedLabelScalar(codePoint: number): boolean {
  if (codePoint <= 0x001f) return true; // C0 controls
  if (codePoint >= 0x007f && codePoint <= 0x009f) return true; // DEL + C1 controls
  if (codePoint >= 0xd800 && codePoint <= 0xdfff) return true; // surrogates
  if (codePoint >= 0xfdd0 && codePoint <= 0xfdef) return true; // noncharacter block
  if ((codePoint & 0xfffe) === 0xfffe) return true; // U+xFFFE / U+xFFFF, every plane
  if (codePoint === 0x2028 || codePoint === 0x2029) return true; // line / paragraph separator
  if (codePoint === 0xfeff) return true; // BOM / ZWNBSP
  if (codePoint >= 0x200b && codePoint <= 0x200d) return true; // zero-width format controls
  if (codePoint >= 0x202a && codePoint <= 0x202e) return true; // BiDi embedding / override
  if (codePoint >= 0x2066 && codePoint <= 0x2069) return true; // BiDi isolates
  return false;
}

// A.4.3 permits "only U+0020 for internal whitespace", so every other space separator is denied.
// U+0009/U+000A/U+000B/U+000C/U+000D are already C0; U+2028/U+2029 are already separators above.
const DISALLOWED_LABEL_SPACES: ReadonlySet<number> = new Set([
  0x00a0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009,
  0x200a, 0x202f, 0x205f, 0x3000,
]);

// A.4.3 device label: 1–80 Unicode scalar values AND ≤320 UTF-8 bytes, well-formed UTF-8, no
// denylisted scalar, no leading/trailing U+0020. `parseOpaqueReference` already enforces the two
// ceilings and rejects lone surrogates; this adds the denylist and the edge-space rule.
//
// The node performs NO normalization: the accepted value is returned as the exact same string that
// arrived, so a well-formed non-NFC label is signed in its original bytes (A.9's NFC-admission gate —
// normalize-then-sign is forbidden, and normalizing here would silently change signed bytes).
export const encodeLabel: CanonicalEncoder = (value) => {
  const text = parseOpaqueReference(value, {
    maxUtf8Bytes: LABEL_MAX_UTF8_BYTES,
    maxCodePoints: LABEL_MAX_CODE_POINTS,
  });

  const scalars = [...text];
  if (scalars.length < 1) throw new InvalidFieldError("Label", "invalid_format");
  if (scalars[0] === " " || scalars[scalars.length - 1] === " ") {
    throw new InvalidFieldError("Label", "disallowed_scalar");
  }

  for (const scalar of scalars) {
    const codePoint = scalar.codePointAt(0);
    if (codePoint === undefined) throw new InvalidFieldError("Label", "invalid_format");
    if (isDisallowedLabelScalar(codePoint) || DISALLOWED_LABEL_SPACES.has(codePoint)) {
      throw new InvalidFieldError("Label", "disallowed_scalar");
    }
  }

  return text;
};

export const encodePositiveDecimalSeq: CanonicalEncoder = (value) => {
  const text = requireString(value, "PositiveDecimalSeq");
  if (!POSITIVE_DECIMAL_SEQ_PATTERN.test(text)) {
    throw new InvalidFieldError("PositiveDecimalSeq", "invalid_format");
  }
  return text;
};

// A value drawn from a closed literal set (event types, state kinds, composite discriminators).
export function closedEnum(fieldKind: string, members: readonly string[]): CanonicalEncoder {
  return (value) => {
    const text = requireString(value, fieldKind);
    if (!members.includes(text)) throw new InvalidFieldError(fieldKind, "invalid_enum");
    return text;
  };
}

// scalar parsers, wrapped as encoders. Named exports keep the registry declarative and let the
// negative tests target each grammar directly.
export const encodeUuid: CanonicalEncoder = (value) => parseUuid(value);
export const encodeWalletPublicKey: CanonicalEncoder = (value) => parseWalletPublicKey(value);
export const encodeEd25519Signature: CanonicalEncoder = (value) => parseEd25519Signature(value);
export const encodeEmptyOrSignature: CanonicalEncoder = (value) => parsePreviousStateSignature(value);
export const encodeSha256Hex: CanonicalEncoder = (value) => parseSha256Hex(value);
export const encodeExpiryUnixTimeSecs: CanonicalEncoder = (value) => parseExpiryUnixTimeSecs(value);
export const encodeCanonicalVersion: CanonicalEncoder = (value) => parseCanonicalVersion(value);
export const encodePositiveZkzAmount: CanonicalEncoder = (value) => parsePositiveZkzAmount(value);
// A.7 `b_amount` binds a role-relative OBSERVED head balance (Byte-exact). Grammar-only —
// never node-authored shortest-form rewrite/reject — so foreign spellings such as "2.50"
// fingerprint byte-identically on write and re-read. Node-authored artifact amounts still
// use encodePositiveZkzAmount → parsePositiveZkzAmount.
export const encodeZkzBalance: CanonicalEncoder = (value) => parseObservedZkzBalance(value);

const AFTER_LANDING_KINDS = ["HOLD", "INTERNAL_MOVE"] as const;
const SOURCE_SELECTOR_KIND = "WALLET_ID" as const;

function requirePlainObject(value: unknown, fieldKind: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new InvalidFieldError(fieldKind, "invalid_composite_shape");
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(
  object: Record<string, unknown>,
  keys: readonly string[],
  fieldKind: string,
): void {
  // Own-property semantics on both halves: `Object.keys` is own-only, so pairing it with a
  // prototype-aware `in` would let a polluted `Object.prototype` supply a required composite key
  // that the caller never provided (the arity check alone still admits a same-length object whose
  // own keys are wrong), and the inherited value would then be encoded into signed bytes.
  const present = Object.keys(object);
  if (
    present.length !== keys.length ||
    !keys.every((key) => Object.prototype.hasOwnProperty.call(object, key))
  ) {
    throw new InvalidFieldError(fieldKind, "invalid_composite_shape");
  }
}

// AfterLanding (A.2): `{"kind":"HOLD","destination_id":null}` or
// `{"kind":"INTERNAL_MOVE","destination_id":"<uuid>"}`. The discriminator fixes destination_id: HOLD
// forces JSON null, INTERNAL_MOVE forces a UUID. The sub-object is rebuilt in a fixed key sequence so
// the nested emission is byte-stable regardless of the caller's input key sequence.
export const encodeAfterLanding: CanonicalEncoder = (value) => {
  const object = requirePlainObject(value, "AfterLanding");
  requireExactKeys(object, ["kind", "destination_id"], "AfterLanding");
  const kind = closedEnum("AfterLanding.kind", AFTER_LANDING_KINDS)(object.kind);
  if (kind === "HOLD") {
    if (object.destination_id !== null) throw new InvalidFieldError("AfterLanding", "invalid_composite_shape");
    return { kind, destination_id: null };
  }
  return { kind, destination_id: parseUuid(object.destination_id) };
};

// SourceSelector (A.2), the resolved wallet form: `{"kind":"WALLET_ID","wallet_id":"<uuid>"}`.
export const encodeSourceSelector: CanonicalEncoder = (value) => {
  const object = requirePlainObject(value, "SourceSelector");
  requireExactKeys(object, ["kind", "wallet_id"], "SourceSelector");
  const kind = closedEnum("SourceSelector.kind", [SOURCE_SELECTOR_KIND])(object.kind);
  return { kind, wallet_id: parseUuid(object.wallet_id) };
};
