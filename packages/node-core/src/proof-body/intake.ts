import { createHash } from "node:crypto";

import { proofBodySchema } from "./schema.js";
import type {
  ProofBodyIntakeRequest,
  ProofBodyIntakeResult,
  ProofBodyRejected,
  ProofBodyRejectionCode,
  ProofBodyRejectionReason,
  ValidatedProofBody,
} from "./types.js";

// the proof-body intake function: the byte-contract surface a caller-
// supplied candidate body crosses before anything else touches it.
//
// Exact-byte rules 4 and 6 bind here: never sign or accept a reconstruction in place of the
// raw preimage; UTF-8 is required, with no BOM, newline, or normalization added. The
// changed-response observation ledger governs what is recorded.
//
// Capture-before-parse (the same discipline that governs the node's own gateway
// reads): the complete exact
// raw bytes are captured and their SHA-256 digest computed BEFORE any UTF-8 decode, JSON
// parse, or schema validation. A decode or parse failure never discards the original bytes —
// they remain the authoritative evidence of what was submitted.
//
// Non-authority (landing-path oracle): a rejected parse produces no projection fields, and no field derived
// from a rejected parse ever reaches a downstream verifier. This function never throws; it
// always returns the discriminated union.

// Budget alignment: a single supplied body is bounded at 64 KiB;
// larger input fails closed as BUDGET_EXCEEDED before any parse work.
export const MAX_PROOF_BODY_BYTES = 65_536;

// Fatal-mode strict UTF-8: an invalid byte
// sequence throws instead of silently substituting U+FFFD. `ignoreBOM: true` keeps a stray
// BOM as a leading U+FEFF character, which the explicit BOM check below then rejects as
// ambiguous encoding — fail closed. Non-streaming decode is stateless, so one shared
// decoder is safe for a pure function.
const STRICT_UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const TEXT_ENCODER = new TextEncoder();

const UTF8_BOM = "\uFEFF";

// Maps each fine-grained code onto its coarse served reason.
const REASON_BY_CODE: Record<ProofBodyRejectionCode, ProofBodyRejectionReason> = {
  AMBIGUOUS_ENCODING: "MALFORMED_ENVELOPE",
  DUPLICATE_JSON_KEY: "MALFORMED_ENVELOPE",
  INVALID_JSON: "MALFORMED_ENVELOPE",
  SCHEMA_VIOLATION: "MALFORMED_ENVELOPE",
  TENANT_MISMATCH: "IDENTITY_MISMATCH",
  OPERATION_MISMATCH: "IDENTITY_MISMATCH",
  ROLE_MISMATCH: "IDENTITY_MISMATCH",
  OVERSIZE: "BUDGET_EXCEEDED",
};

function rejected(
  rawBytes: Uint8Array,
  rawSha256: string,
  code: ProofBodyRejectionCode,
  detail: string,
): ProofBodyRejected {
  return { accepted: false, reason: REASON_BY_CODE[code], code, detail, rawBytes, rawSha256 };
}

// Binds the authenticated request identity to the expected identity BEFORE any parse, so a
// body cannot be reinterpreted under a different tenant, operation, or role after acceptance
// (role/role-relative-state discipline applied at intake; the binding rule is that
// identity is re-derived from the authenticated context,
// never from a client-asserted field alone). Returns the distinct mismatch code, or null
// when the binding holds.
function bindingMismatch(request: ProofBodyIntakeRequest): ProofBodyRejectionCode | null {
  const { authenticated, expected } = request;
  if (authenticated.tenant_id !== expected.tenant_id) return "TENANT_MISMATCH";
  if (authenticated.operation_id !== expected.operation_id) return "OPERATION_MISMATCH";
  if (authenticated.wallet_role !== expected.wallet_role) return "ROLE_MISMATCH";
  return null;
}

// Decodes one raw JSON string token — the exact characters between a string's delimiting
// quotes, with every escape still literal — into the value JSON.parse would produce, by
// delegating to JSON.parse itself. This is the load-bearing choice for the duplicate-key
// scan below: the scanner's notion of "same key" MUST be byte-for-byte identical to what
// JSON.parse collapses, and the only way to guarantee that across every escape the spec
// allows (\uXXXX, surrogate pairs, \n, \", \\, ...) is to reuse the real parser's decode
// rather than hand-roll a second escape decoder that could diverge in the other direction.
// Precondition: the text handed to findDuplicateKey has already parsed successfully via
// JSON.parse, so every extracted token re-wrapped in quotes is itself valid JSON and this
// never throws. The typeof guard yields a `string` return without an `any`-typed assertion;
// a quoted JSON string always decodes to a string, so the fallback branch is unreachable.
function decodeJsonStringToken(token: string): string {
  const decoded: unknown = JSON.parse(`"${token}"`);
  return typeof decoded === "string" ? decoded : token;
}

// Detects a duplicate key within any single JSON object in `text`. A parser that silently
// takes the last (or first) of two duplicate keys is exploitable: the persisted projection
// would disagree with what a byte-level reviewer reads (forgery vector). Keys are
// compared in their DECODED form (decodeJsonStringToken): a plain `"b_amount"` and an escaped
// `"b_amount"` are two distinct raw tokens but ONE key to JSON.parse (last wins), so a
// raw-token comparison would miss the collision and let a forged escape-variant field through
// while a byte-level reviewer reads the first occurrence — the escape-variant vector.
// The scan is string-aware so braces, brackets, and colons inside string literals are never
// mistaken for structure. Returns the first duplicated (decoded) key found, or null when
// every object's keys are unique. Structural validity is JSON.parse's job; this only reports
// repeated object keys.
function findDuplicateKey(text: string): string | null {
  const keyStack: Set<string>[] = [];
  let inString = false;
  let escaped = false;
  let currentString = "";
  let isKeyPosition = false;
  let pendingKey: string | null = null;

  for (const char of text) {
    if (inString) {
      if (escaped) {
        currentString += char;
        escaped = false;
      } else if (char === "\\") {
        currentString += char;
        escaped = true;
      } else if (char === `"`) {
        inString = false;
        // Decode the raw token to the key JSON.parse will build, so escape-variant
        // duplicates collide in the Set exactly as they collapse in the parsed object.
        if (isKeyPosition) pendingKey = decodeJsonStringToken(currentString);
      } else {
        currentString += char;
      }
      continue;
    }

    if (char === `"`) {
      inString = true;
      currentString = "";
      continue;
    }

    if (char === "{") {
      keyStack.push(new Set<string>());
      isKeyPosition = true;
      pendingKey = null;
      continue;
    }

    if (char === "[") {
      isKeyPosition = false;
      pendingKey = null;
      continue;
    }

    if (char === "}" || char === "]") {
      keyStack.pop();
      isKeyPosition = false;
      pendingKey = null;
      continue;
    }

    if (char === ":") {
      const currentKeys = keyStack[keyStack.length - 1];
      if (isKeyPosition && pendingKey !== null && currentKeys !== undefined) {
        if (currentKeys.has(pendingKey)) return pendingKey;
        currentKeys.add(pendingKey);
      }
      isKeyPosition = false;
      pendingKey = null;
      continue;
    }

    if (char === ",") {
      isKeyPosition = keyStack.length > 0;
      pendingKey = null;
    }
  }

  return null;
}

// Intake one authenticated proof-body submission. Pure and side-effect free: raw bytes in,
// typed verdict out. Never throws; always returns the discriminated union.
export function intakeProofBody(request: ProofBodyIntakeRequest): ProofBodyIntakeResult {
  // Defensive copy taken ONCE, up front: every result (accepted or rejected) returns these
  // bytes as the authoritative evidence paired with rawSha256, and that pairing must stay
  // byte-consistent for the lifetime of the result. Copying decouples the returned buffer from
  // the caller's, so a caller mutating its own buffer after this call cannot desync the
  // evidence from its digest. `Uint8Array.from` always allocates fresh backing storage — a
  // plain `.slice` is unsafe here because a Node Buffer's slice aliases shared memory.
  const rawBytes = Uint8Array.from(request.rawBytes);

  // Capture-before-parse: digest the exact captured bytes BEFORE any decode, so even an
  // undecodable body yields the SHA-256 of the authoritative original bytes.
  const rawSha256 = createHash("sha256").update(rawBytes).digest("hex");

  // Budget gate (BUDGET_EXCEEDED) before any parse work.
  if (rawBytes.byteLength > MAX_PROOF_BODY_BYTES) {
    return rejected(
      rawBytes,
      rawSha256,
      "OVERSIZE",
      `body is ${rawBytes.byteLength} bytes; the intake budget is ${MAX_PROOF_BODY_BYTES}`,
    );
  }

  // Identity binding before any parse: a mismatch fails closed with a distinct code and no
  // schema validation ever runs.
  const mismatch = bindingMismatch(request);
  if (mismatch !== null) {
    return rejected(
      rawBytes,
      rawSha256,
      mismatch,
      "authenticated request identity does not bind to the expected tenant/operation/role",
    );
  }

  // Strict UTF-8 decode; an invalid byte sequence is ambiguous encoding (rule 6).
  let text: string;
  try {
    text = STRICT_UTF8_DECODER.decode(rawBytes);
  } catch {
    return rejected(rawBytes, rawSha256, "AMBIGUOUS_ENCODING", "raw bytes are not valid UTF-8");
  }

  // A BOM (or any non-canonical leading marker) is ambiguous encoding — never silently
  // stripped (rule 6: no BOM, newline, or normalization is added or tolerated).
  if (text.startsWith(UTF8_BOM)) {
    return rejected(rawBytes, rawSha256, "AMBIGUOUS_ENCODING", "body carries a UTF-8 BOM");
  }

  // Exactly one JSON value; surrounding non-whitespace fails closed.
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return rejected(rawBytes, rawSha256, "INVALID_JSON", "body is not exactly one JSON value");
  }

  // Duplicate JSON keys fail closed outright (forgery vector: a silent last/first-wins
  // parser would let the persisted projection disagree with the bytes a reviewer reads).
  const duplicateKey = findDuplicateKey(text);
  if (duplicateKey !== null) {
    return rejected(
      rawBytes,
      rawSha256,
      "DUPLICATE_JSON_KEY",
      `object key ${JSON.stringify(duplicateKey)} appears more than once`,
    );
  }

  // Frozen schema validation; .strict rejects unknown keys and missing/invalid fields.
  const result = proofBodySchema.safeParse(parsed);
  if (!result.success) {
    const issue = result.error.issues[0];
    const path = issue === undefined ? "" : issue.path.join(".");
    const message = issue === undefined ? "schema validation failed" : issue.message;
    return rejected(
      rawBytes,
      rawSha256,
      "SCHEMA_VIOLATION",
      path === "" ? message : `${path}: ${message}`,
    );
  }

  const body = result.data as ValidatedProofBody;

  // The storage CHECK (octet_length(completed_transaction_text) =
  // completed_transaction_octets): the supplied octet count must equal the exact byte length
  // of the supplied text, or the body is internally inconsistent and fails closed.
  const completedOctets = TEXT_ENCODER.encode(body.completed_transaction_text).byteLength;
  if (completedOctets !== body.completed_transaction_octets) {
    return rejected(
      rawBytes,
      rawSha256,
      "SCHEMA_VIOLATION",
      `completed_transaction_octets: expected ${completedOctets}, got ${body.completed_transaction_octets}`,
    );
  }

  // Deliberate asymmetry (landing-path oracle): intake enforces the storage CHECK
  // constraints on body content — the octet equality above, plus octet_length(inner_preimage_
  // text) > 0 which the schema's .min(1) already guarantees — but does NOT cross-check any of
  // the three supplied digests (completed_transaction_sha256, inner_sha256,
  // verification_manifest_sha256) against their texts. The schema defines NO such CHECK; each
  // digest is an index column, and "digest indexes are not equality
  // authority" — the landing-path oracle verifier recomputes every digest and byte-compares against the
  // fresh-head-anchored body. A digest self-check here would (a) invent a constraint absent
  // from the frozen data model, (b) encroach on the verifier's exclusive non-authority
  // boundary, (c) be inconsistent unless all three were checked, and (d) add zero forgery
  // resistance — a forger trivially supplies a self-consistent text+digest pair — while
  // manufacturing the false confidence landing-path oracle exists to prevent. The octet check is a
  // storability mirror; digest verification is the verifier's job, not the envelope's.

  return { accepted: true, body, rawBytes, rawSha256 };
}
