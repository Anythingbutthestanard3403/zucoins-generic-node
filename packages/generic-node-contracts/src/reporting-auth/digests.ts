// the reporting-auth register tuple — Digest and proof-of-possession pins for the `zp-reporting-register-v1` golden.
//
// The digest is SHA-256 over the exact UTF-8 preimage bytes (A.1.1); the signature is the golden
// preimage signed by the A.8 seed-0x04 reporting key — the implementer's proof of possession of
// `new_reporting_public_key`. The freeze test recomputes both from the fixture seed with
// node:crypto and asserts they match (and that the derived pubkey equals the A.8 reporting key), so
// any drift in the frozen byte layout fails the test. These values are the frozen
// reporting-key enrolment / A.8
// golden (verified vector: the pipeline first reproduces the existing zp-report-request-v1 and
// zp-device-enrol-v1 goldens byte-for-byte). Regenerating is a deliberate paired change.

// SHA-256 of REGISTER_GOLDEN_PREIMAGE (477 bytes) and of gen/zp-reporting-register-v1.preimage.txt.
export const REGISTER_GOLDEN_PREIMAGE_SHA256 =
  "98fba788ad4ba2141dc400f1cd0f58db3a03b34a00b5a04ecdcfe239e9912e7e" as const;

// Padded base64url Ed25519 proof-of-possession signature over the golden preimage (A.8 seed 0x04).
export const REGISTER_GOLDEN_POP_SIGNATURE =
  "mSzq0luyM9AubD8PrVDBeoSwljM8SGXmUTsXVhVaLJiX0bPQgHKzFwBwIDkGTpm-2CdsINIQObzjOvHvCMCuDA==" as const;

// The A.8 reporting public key (seed 0x04) — the verify key for the proof-of-possession signature.
export const REGISTER_GOLDEN_REPORTING_PUBKEY =
  "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=" as const;
