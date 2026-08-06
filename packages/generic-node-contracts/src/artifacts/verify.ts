/**
 * Expected-artifact verifier (A.1.1, A.3.1-A.3.4, A.9 negative vectors; artifacts freeze).
 *
 * A pure, stateless verifier for the three expected-action artifacts. It performs the exact
 * A.3.4 procedure — parse the envelope preimage, enforce the frozen field sequence, types, and
 * literal purpose/version, recompute the digest, resolve the active node identity key, and
 * verify the Ed25519 signature over the exact bytes — returning a typed verdict. It creates no
 * retry authority and touches no wallet key (node-signature verification only;
 * the chain-observable economic predicate is a separate half, out of this module's scope).
 *
 * hardened: byte-canonical JSON enforcement (the byte-exact signing rule, A.1.1). The verifier
 * rebuilds the canonical payload from validated scalars in the frozen field sequence and
 * compares byte-for-byte against the original payload_json. It also enforces key_id binding,
 * rejects BOM/trailing whitespace, and rejects unknown/extra fields.
 */
import { validateOperationAmount } from "../amounts/validators.ts";
import {
  EXPECTED_ARTIFACTS,
  type ArtifactFieldType,
  type ExpectedArtifactPurpose,
  type ExpectedArtifactManifest,
} from "./expected-artifacts.contract.ts";
import { isKeyAcceptedForVerification, type NodeIdentityKeyRecord } from "./signing-contract.ts";

/**
 *  CONTRACT_FREEZE amendment: the Ed25519 + SHA-256 crypto `verifyExpectedArtifact` needs
 * DEPENDENCY-INJECTED via an in-package callback interface (the frozen `RegisterProofCallbacks`
 * pattern, `reporting-auth/verifier.ts`). Declaring it HERE — inside the contract package — keeps
 * the generic-core scan concern intact: the concern that OWNS the verifier owns the interface, and the CALLER injects a
 * concrete implementation. It must never be declared in node-core and imported (that would invert
 * the dependency and re-violate the generic-core scan concern). The injected default (`testkit/suiteVerificationCrypto.ts`)
 * MUST stay the wallet's `libsodium-wrappers` family so bytes/accept-set are identical to Appendix A.
 */
export interface ArtifactVerificationCrypto {
  /** Resolves when the underlying crypto (e.g. libsodium) is initialised. */
  readonly ready: () => Promise<void>;
  /** Lowercase 64-char hex SHA-256 of the exact UTF-8 bytes of `preimageText` (A.1.1 rule 6). */
  readonly digestPreimage: (preimageText: string) => string;
  /**
   * Verify a padded URL-safe base64 detached Ed25519 signature over the exact UTF-8 bytes of
   * `preimageText`, under the padded URL-safe base64 public key. The implementation owns full
   * point/subgroup validation and canonical-S enforcement (it MUST reject malleated/non-canonical-S
   * signatures and small-subgroup/torsion keys — the wallet libsodium accept-set). It may throw on malformed
   * base64, exactly as the pre-DI direct decode did.
   */
  readonly verifyPreimageSignature: (input: {
    readonly preimageText: string;
    readonly signatureB64Url: string;
    readonly publicKeyB64Url: string;
  }) => boolean;
}

/** The unsigned API/storage envelope frozen in A.3.4. */
export interface ArtifactEnvelope {
  readonly key_id: string;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly signature: string;
}

export interface VerifyInput {
  readonly envelope: ArtifactEnvelope;
  readonly key: NodeIdentityKeyRecord;
  readonly signedAtUnixMs: number;
  /** Cross-purpose guard: if set, the artifact's purpose MUST equal this (A.9 vector 10). */
  readonly expectedPurpose?: ExpectedArtifactPurpose;
  /** Independent pin (instruction-origin identity pin): if set, the resolved key's public key MUST equal this.*/
  readonly pinnedPublicKeyB64?: string;
}

export const VERIFY_REJECT_REASONS = [
  "malformed_preimage",
  "unknown_purpose",
  "cross_purpose_expected_mismatch",
  "payload_purpose_mismatch",
  "field_sequence_mismatch",
  "canonical_version_invalid",
  "field_value_invalid",
  "noncanonical_payload",
  "digest_mismatch",
  "key_id_mismatch",
  "key_not_accepted",
  "key_pubkey_mismatch",
  "signature_invalid",
] as const;
export type VerifyRejectReason = (typeof VERIFY_REJECT_REASONS)[number];

export type VerifyResult =
  | { readonly ok: true; readonly purpose: ExpectedArtifactPurpose; readonly digest: string }
  | { readonly ok: false; readonly reason: VerifyRejectReason; readonly detail?: string };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PADDED_KEY_RE = /^[A-Za-z0-9\-_]{43}=$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const ANCHOR_RE = /^[A-Za-z0-9_-]{1,96}$/;
const INTEGER_STRING_RE = /^(0|[1-9][0-9]*)$/;

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isValidAfterLanding = (value: unknown): boolean => {
  if (!isPlainObject(value)) return false;
  const keys = Object.keys(value);
  if (keys.length !== 2 || keys[0] !== "kind" || keys[1] !== "destination_id") return false;
  if (value.kind === "HOLD") return value.destination_id === null;
  if (value.kind === "INTERNAL_MOVE") {
    return typeof value.destination_id === "string" && UUID_RE.test(value.destination_id);
  }
  return false;
};

const isValidSourceSelector = (value: unknown): boolean => {
  if (!isPlainObject(value)) return false;
  const keys = Object.keys(value);
  if (keys.length !== 2 || keys[0] !== "kind" || keys[1] !== "wallet_id") return false;
  return value.kind === "WALLET_ID" && typeof value.wallet_id === "string" && UUID_RE.test(value.wallet_id);
};

/**
 * Rebuild a structured value (after_landing or source_selector) with keys in the exact
 * canonical insertion sequence, so JSON.stringify produces byte-identical output.
 */
const rebuildStructuredValue = (value: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> => {
  const rebuilt: Record<string, unknown> = {};
  for (const k of keys) {
    rebuilt[k] = value[k];
  }
  return rebuilt;
};

/**
 * Rebuild the canonical payload from validated field values using the frozen field sequence
 * from expected-artifacts.contract.ts. JSON.stringify(rebuilt) must be byte-identical to the
 * original payload_json — this is the core of the canonical enforcement (the byte-exact signing rule).
 */
const rebuildCanonicalPayload = (
  payload: Record<string, unknown>,
  manifest: ExpectedArtifactManifest,
): Record<string, unknown> => {
  const rebuilt: Record<string, unknown> = {};
  for (const field of manifest.fields) {
    const value = payload[field.name];
    if (field.type === "after_landing_object" && isPlainObject(value)) {
      rebuilt[field.name] = rebuildStructuredValue(value, ["kind", "destination_id"]);
    } else if (field.type === "source_selector_object" && isPlainObject(value)) {
      rebuilt[field.name] = rebuildStructuredValue(value, ["kind", "wallet_id"]);
    } else {
      rebuilt[field.name] = value;
    }
  }
  return rebuilt;
};

const isValueValidForType = (type: ArtifactFieldType, value: unknown, purpose: string): boolean => {
  switch (type) {
    case "purpose_literal":
      return value === purpose;
    case "canonical_version_literal":
      return value === 1;
    case "uuid":
    case "operation_uuid":
      return typeof value === "string" && UUID_RE.test(value);
    case "uuid_nullable":
      return value === null || (typeof value === "string" && UUID_RE.test(value));
    case "ed25519_pubkey_padded":
    case "external_address_padded":
      return typeof value === "string" && PADDED_KEY_RE.test(value);
    case "zkz_amount_positive":
      // the amounts-grammar freeze: positivity is a NUMERIC predicate, never a bare literal-string equality test
      // delegated to the shared the amounts concern operation-amount validator so this concern carries no
      // second amount parser. Rejects every mathematical representation of zero (a zero integer,
      // zero with trailing fractional digits, a maximally-padded zero decimal) plus
      // non-canonical grammar-legal forms, out-of-range magnitude, and excess decimal places.
      return typeof value === "string" && validateOperationAmount(value).ok;
    case "anchor":
      return typeof value === "string" && ANCHOR_RE.test(value);
    case "sha256_hex":
      return typeof value === "string" && SHA256_HEX_RE.test(value);
    case "integer_string_nullable":
      return value === null || (typeof value === "string" && INTEGER_STRING_RE.test(value));
    case "after_landing_object":
      return isValidAfterLanding(value);
    case "source_selector_object":
      return isValidSourceSelector(value);
    default:
      return false;
  }
};

const manifestByPurpose = (purpose: string): ExpectedArtifactManifest | undefined =>
  EXPECTED_ARTIFACTS.find((m) => m.purpose === purpose);

const reject = (reason: VerifyRejectReason, detail?: string): VerifyResult => ({ ok: false, reason, detail });

/**
 * Verify one expected artifact against its frozen schema, the recomputed digest, and the
 * resolved node identity key. Pure and fail-closed: the FIRST failing check returns its reason.
 *
 * hardened: enforces byte-canonical JSON by rebuilding the canonical payload from
 * validated scalars in the frozen field sequence and comparing byte-for-byte. Also enforces
 * key_id binding, BOM rejection, and trailing whitespace rejection.
 */
export const verifyExpectedArtifact = async (
  input: VerifyInput,
  crypto: ArtifactVerificationCrypto,
): Promise<VerifyResult> => {
  await crypto.ready();
  const { envelope, key, signedAtUnixMs, expectedPurpose, pinnedPublicKeyB64 } = input;

  // byte-level preimage checks — BOM prefix (A.1.1 rule 1)
  if (envelope.preimage_text.charCodeAt(0) === 0xfeff) {
    return reject("malformed_preimage", "BOM prefix detected");
  }
  // trailing whitespace/newline (A.1.1 rule 1, A.9 vector 8)
  if (/\s$/.test(envelope.preimage_text)) {
    return reject("malformed_preimage", "trailing whitespace");
  }

  const newlineIndex = envelope.preimage_text.indexOf("\n");
  if (newlineIndex === -1) {
    return reject("malformed_preimage", "no domain-separation prefix");
  }
  const prefix = envelope.preimage_text.slice(0, newlineIndex);
  const payloadJson = envelope.preimage_text.slice(newlineIndex + 1);

  const manifest = manifestByPurpose(prefix);
  if (!manifest) {
    return reject("unknown_purpose", prefix);
  }
  if (expectedPurpose !== undefined && prefix !== expectedPurpose) {
    return reject("cross_purpose_expected_mismatch", `${prefix} != ${expectedPurpose}`);
  }

  let payload: unknown;
  try {
    payload = JSON.parse(payloadJson);
  } catch {
    return reject("malformed_preimage", "payload is not valid JSON");
  }
  if (!isPlainObject(payload)) {
    return reject("malformed_preimage", "payload is not a JSON object");
  }

  if (payload.purpose !== prefix) {
    return reject("payload_purpose_mismatch", "prefix purpose != payload purpose");
  }

  // reject unknown/extra fields not in the frozen schema
  const frozenFieldNames = new Set<string>(manifest.fields.map((f) => f.name));
  for (const key of Object.keys(payload)) {
    if (!frozenFieldNames.has(key)) {
      return reject("field_value_invalid", `unknown field: ${key}`);
    }
  }

  const actualFieldSequence = Object.keys(payload);
  const frozenFieldSequence = manifest.fields.map((f) => f.name);
  if (
    actualFieldSequence.length !== frozenFieldSequence.length ||
    actualFieldSequence.some((name, i) => name !== frozenFieldSequence[i])
  ) {
    return reject("field_sequence_mismatch", actualFieldSequence.join(","));
  }

  if (payload.canonical_version !== 1) {
    return reject("canonical_version_invalid", String(payload.canonical_version));
  }

  // nullable fields must be present as null, not omitted (A.1.1 rule 7)
  for (const field of manifest.fields) {
    if (field.nullable && payload[field.name] === undefined) {
      return reject("field_value_invalid", `${field.name} is undefined (must be null)`);
    }
  }

  for (const field of manifest.fields) {
    if (!isValueValidForType(field.type, payload[field.name], manifest.purpose)) {
      return reject("field_value_invalid", field.name);
    }
  }

  // byte-canonical enforcement (the byte-exact signing rule, A.1.1). Rebuild the canonical payload
  // from validated scalars in the frozen field sequence and compare byte-for-byte against the
  // original payload_json. This rejects: whitespace variants, alternate number spellings (1.0,
  // \u0031), duplicate fields (JSON.parse silently takes last), escape aliases, and reordered fields.
  const rebuilt = rebuildCanonicalPayload(payload, manifest);
  const canonicalJson = JSON.stringify(rebuilt);
  if (canonicalJson !== payloadJson) {
    return reject("noncanonical_payload", "payload is not byte-canonical JSON");
  }

  if (crypto.digestPreimage(envelope.preimage_text) !== envelope.preimage_sha256) {
    return reject("digest_mismatch");
  }

  // key_id binding — the envelope's key_id must match the resolved key record's keyId
  if (envelope.key_id !== key.keyId) {
    return reject("key_id_mismatch", `${envelope.key_id} != ${key.keyId}`);
  }

  const keyVerdict = isKeyAcceptedForVerification(key, signedAtUnixMs);
  if (!keyVerdict.accepted) {
    return reject("key_not_accepted", keyVerdict.reason);
  }
  if (pinnedPublicKeyB64 !== undefined && pinnedPublicKeyB64 !== key.publicKeyB64) {
    return reject("key_pubkey_mismatch");
  }

  const signatureValid = crypto.verifyPreimageSignature({
    preimageText: envelope.preimage_text,
    signatureB64Url: envelope.signature,
    publicKeyB64Url: key.publicKeyB64,
  });
  if (!signatureValid) {
    return reject("signature_invalid");
  }

  return { ok: true, purpose: manifest.purpose, digest: envelope.preimage_sha256 };
};

export const SOURCE = "expected-artifact verifier A.1.1, A.3, A.9; artifacts freeze" as const;
