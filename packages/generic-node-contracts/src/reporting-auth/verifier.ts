// the reporting-auth register tuple — Pure structural verifiers over the reporting-auth contract. These enforce the
// A.9 required-negative-vector classes that do not need signature crypto (byte layout, purpose
// match, canonical_version type, UUID/key/timestamp form) plus the lifecycle, tenant-binding, and
// cross-purpose rules. Signature/proof-of-possession crypto is exercised in the freeze test via
// node:crypto, keeping this package a zero-runtime-dep leaf. the reporting node-event purpose/.3 consume these verifiers.
//
// Governing contract: the canonical suite serializer and negative vectors; signed reporting; the pull-cursor authority decision.

import {
  REGISTER_FIELD_ORDER,
  REPORTING_KEY_ENROL_WINDOW_SECS,
  REPORTING_REGISTER_CANONICAL_VERSION,
  REPORTING_REGISTER_PURPOSE,
  buildRegisterPreimage,
  type ReportingRegisterPayload,
} from "./register-tuple.js";
import {
  REPORTING_KEY_ALLOWED_PURPOSES,
  ALLOWED_CREDENTIAL_MECHANISMS,
  ED25519_SMALL_ORDER_ENCODINGS_HEX,
} from "./keys.js";
import {
  REPORTING_KEY_TRANSITIONS,
  type ReportingKeyBinding,
  type ReportingKeyState,
} from "./lifecycle.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PADDED_B64URL_KEY = /^[A-Za-z0-9\-_]{43}=$/;
const PADDED_B64URL_SIGNATURE = /^[A-Za-z0-9\-_]{86}==$/;
const RFC3339_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export interface VerifyResult {
  readonly ok: boolean;
  readonly reason: string | null;
}

const pass = (): VerifyResult => ({ ok: true, reason: null });
const fail = (reason: string): VerifyResult => ({ ok: false, reason });

export const REGISTER_PROOF_VERIFICATION_STAGES = Object.freeze([
  "structural_register_preimage",
  "public_key_padded_base64url_decode_32_byte_length_exact_reencode",
  "public_key_canonical_compressed_encoding_y_less_than_p_and_negative_zero_reject",
  "public_key_exact_eight_torsion_reject",
  "signature_padded_base64url_decode_64_byte_length_exact_reencode",
  "injected_full_public_key_point_validation",
  "proof_of_possession_detached_verification",
] as const);

const SMALL_ORDER_ENCODINGS = new Set<string>(ED25519_SMALL_ORDER_ENCODINGS_HEX);
const ED25519_FIELD_PRIME = Uint8Array.from([
  0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0x7f,
]);

function encodePaddedBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url") + (bytes.length === 32 ? "=" : "==");
}

function decodeExactPaddedBase64Url(
  encoded: string,
  expectedLength: 32 | 64,
): Uint8Array | null {
  const form = expectedLength === 32 ? PADDED_B64URL_KEY : PADDED_B64URL_SIGNATURE;
  if (!form.test(encoded)) return null;
  let decoded: Buffer;
  try {
    decoded = Buffer.from(encoded.slice(0, encoded.indexOf("=")), "base64url");
  } catch {
    return null;
  }
  if (decoded.length !== expectedLength) return null;
  const bytes = Uint8Array.from(decoded);
  return encodePaddedBase64Url(bytes) === encoded ? bytes : null;
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function hasCanonicalEd25519Encoding(bytes: Uint8Array): boolean {
  const y = Uint8Array.from(bytes);
  const sign = y[31]! >>> 7;
  y[31]! &= 0x7f;

  // Canonical compressed Ed25519 requires y < 2^255 - 19.
  let comparison = 0;
  for (let i = 31; i >= 0; i -= 1) {
    if (y[i]! !== ED25519_FIELD_PRIME[i]!) {
      comparison = y[i]! < ED25519_FIELD_PRIME[i]! ? -1 : 1;
      break;
    }
  }
  if (comparison >= 0) return false;

  // RFC 8032 decoding also rejects a set sign bit when the recovered x is zero. The only such
  // canonical-y encodings are y=1 and y=p-1; enumerate them without implementing curve math.
  if (sign === 1) {
    const yHex = bytesToHex(y);
    if (
      yHex === "0100000000000000000000000000000000000000000000000000000000000000" ||
      yHex === "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ) {
      return false;
    }
  }
  return true;
}

export function decodeCanonicalReportingPublicKey(encoded: string): Uint8Array | null {
  const bytes = decodeExactPaddedBase64Url(encoded, 32);
  if (
    bytes === null ||
    !hasCanonicalEd25519Encoding(bytes) ||
    SMALL_ORDER_ENCODINGS.has(bytesToHex(bytes))
  ) {
    return null;
  }
  return Uint8Array.from(bytes);
}

export function decodeCanonicalEd25519Signature(encoded: string): Uint8Array | null {
  const bytes = decodeExactPaddedBase64Url(encoded, 64);
  return bytes === null ? null : Uint8Array.from(bytes);
}

export interface RegisterProofCallbacks {
  readonly validatePublicKeyPoint: (publicKey: Uint8Array) => unknown;
  readonly verifyDetached: (input: {
    readonly publicKey: Uint8Array;
    readonly preimage: Uint8Array;
    readonly signature: Uint8Array;
  }) => unknown;
}

// Enforces the security-relevant sequence: structural/canonical bytes, runtime point validation,
// then (and only then) proof-of-possession. This contract deliberately makes no runtime-complete
// point-validation claim: the injected validator owns full curve/subgroup validation.
export function verifyRegisterProofOfPossession(
  preimage: string,
  signature: string,
  callbacks: RegisterProofCallbacks,
): VerifyResult {
  const structural = verifyRegisterPreimage(preimage);
  if (!structural.ok) return structural;

  const payload = JSON.parse(preimage.slice(preimage.indexOf("\n") + 1)) as ReportingRegisterPayload;
  const publicKey = decodeCanonicalReportingPublicKey(payload.new_reporting_public_key);
  if (publicKey === null) {
    return fail("new_reporting_public_key is not canonical/prevalidated Ed25519 bytes");
  }
  const signatureBytes = decodeCanonicalEd25519Signature(signature);
  if (signatureBytes === null) return fail("proof-of-possession signature is not canonical padded base64url");

  try {
    if (callbacks.validatePublicKeyPoint(Uint8Array.from(publicKey)) !== true) {
      return fail("reporting public key point validation failed");
    }
  } catch {
    return fail("reporting public key point validation failed");
  }

  try {
    const verified = callbacks.verifyDetached({
      publicKey: Uint8Array.from(publicKey),
      preimage: Uint8Array.from(Buffer.from(preimage, "utf8")),
      signature: Uint8Array.from(signatureBytes),
    });
    return verified === true ? pass() : fail("proof-of-possession signature verification failed");
  } catch {
    return fail("proof-of-possession signature verification failed");
  }
}

// Structurally verify a `zp-reporting-register-v1` preimage against A.1.1/A.9. Does NOT check the
// Ed25519 signature (that is proof-of-possession crypto, exercised in the freeze test).
export function verifyRegisterPreimage(preimage: string): VerifyResult {
  const lf = preimage.indexOf("\n");
  if (lf < 0) return fail("no purpose/payload separator");
  const prefix = preimage.slice(0, lf);
  if (prefix !== REPORTING_REGISTER_PURPOSE) return fail("prefix purpose mismatch");

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(preimage.slice(lf + 1)) as Record<string, unknown>;
  } catch {
    return fail("payload is not valid JSON");
  }

  if (payload.purpose !== REPORTING_REGISTER_PURPOSE) return fail("payload purpose mismatch");
  if (
    payload.canonical_version !== REPORTING_REGISTER_CANONICAL_VERSION ||
    typeof payload.canonical_version !== "number"
  ) {
    return fail("canonical_version must be the number 1");
  }
  for (const field of REGISTER_FIELD_ORDER) {
    if (payload[field] === undefined) return fail(`missing field ${field}`);
  }
  for (const field of ["node_id", "implementer_id", "new_reporting_key_id", "nonce"] as const) {
    if (typeof payload[field] !== "string" || !UUID.test(payload[field] as string)) {
      return fail(`field ${field} is not a canonical lowercase UUID`);
    }
  }
  // supersedes_key_id is nullable: `null` at bootstrap or a canonical UUID on rotation. It is
  // always present (the field loop above rejects omission — A.9 register: omitted instead of null).
  if (
    payload.supersedes_key_id !== null &&
    (typeof payload.supersedes_key_id !== "string" || !UUID.test(payload.supersedes_key_id))
  ) {
    return fail("supersedes_key_id must be null or a canonical lowercase UUID");
  }
  if (
    typeof payload.new_reporting_public_key !== "string" ||
    decodeCanonicalReportingPublicKey(payload.new_reporting_public_key) === null
  ) {
    return fail("new_reporting_public_key is not canonical/prevalidated Ed25519 bytes");
  }
  for (const field of ["issued_at", "expires_at"] as const) {
    if (typeof payload[field] !== "string" || !RFC3339_MS.test(payload[field] as string)) {
      return fail(`field ${field} is not an RFC3339 timestamp with three fractional digits`);
    }
  }
  if ((payload.expires_at as string) <= (payload.issued_at as string)) {
    return fail("expires_at must be later than issued_at");
  }
  // Enrolment ceremony window (the reporting-key enrolment rule / A.5.1): expires_at at most REPORTING_KEY_ENROL_WINDOW_SECS
  // after the SIGNED issued_at (A.9 register: an enrolment window over 300 s is rejected). Both
  // operands are in-tuple signed timestamps, so this is a signed-issued_at check, never receipt
  // time.
  if (
    Date.parse(payload.expires_at as string) - Date.parse(payload.issued_at as string) >
    REPORTING_KEY_ENROL_WINDOW_SECS * 1000
  ) {
    return fail("enrolment window exceeds 300 seconds");
  }
  // Reconstruct in the canonical sequence and compare byte-exact — catches field reorder, extra
  // field, or appended whitespace (A.9 #1/#8) that the checks above do not individually cover.
  if (buildRegisterPreimage(payload as unknown as ReportingRegisterPayload) !== preimage) {
    return fail("non-canonical byte layout (reorder / extra field / whitespace)");
  }
  return pass();
}

// True iff a reporting key is permitted to sign this purpose (cross-purpose guard, A.9 #10).
export function reportingKeyMaySign(purpose: string): boolean {
  return (REPORTING_KEY_ALLOWED_PURPOSES as readonly string[]).includes(purpose);
}

// True iff a per-key_id state transition is legal (no reactivation of a terminal key).
export function isLegalReportingKeyTransition(from: ReportingKeyState, to: ReportingKeyState): boolean {
  return REPORTING_KEY_TRANSITIONS.some((t) => t.from === from && t.to === to);
}

// Tenant binding (the pull-cursor authority rule point 1): a request tuple is authorized only when its node_id AND
// implementer_id EQUAL the registration binding for its key_id.
export function requestTupleMatchesBinding(
  binding: ReportingKeyBinding,
  tuple: { readonly node_id: string; readonly implementer_id: string },
): boolean {
  return tuple.node_id === binding.node_id && tuple.implementer_id === binding.implementer_id;
}

// True iff a credential mechanism is permitted on the signed reporting channel (Ed25519 only).
export function credentialMechanismAllowed(mechanism: string): boolean {
  return (ALLOWED_CREDENTIAL_MECHANISMS as readonly string[]).includes(mechanism);
}
