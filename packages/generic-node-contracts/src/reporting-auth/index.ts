// the reporting-auth register tuple — Public surface of the reporting-auth concern. Concern-local barrel owned by the
// the reporting-auth register tuple slice; NOT the package index (src/index.ts, owned by the concern-manifest registry). the reporting node-event purpose (signed request
// and event bytes) and the reporting bootstrap enrolment (replay/rotation tests) consume this.

export {
  type ReportingRegisterPayload,
  REPORTING_REGISTER_PURPOSE,
  REPORTING_REGISTER_CANONICAL_VERSION,
  REPORTING_KEY_ENROL_WINDOW_SECS,
  REGISTER_FIELD_ORDER,
  buildRegisterPreimage,
  REGISTER_GOLDEN_PAYLOAD,
  REGISTER_GOLDEN_PREIMAGE,
} from "./register-tuple.js";

export {
  type ReportingKeyClass,
  REPORTING_KEY_CLASSES,
  REPORTING_KEY_ALLOWED_PURPOSES,
  NODE_EVENT_KEY_ALLOWED_PURPOSES,
  REPORTING_CROSS_PURPOSE_FORBIDDEN,
  ALLOWED_CREDENTIAL_MECHANISMS,
  FORBIDDEN_CREDENTIAL_MECHANISMS,
  V2_REPORTING_PURPOSES,
  LEGACY_PUSH_PURPOSES,
  ED25519_SMALL_ORDER_ENCODINGS_HEX,
} from "./keys.js";

export {
  type ReportingKeyBinding,
  type ReportingKeyState,
  type KeyStateTransition,
  REPORTING_KEY_STATES,
  REPORTING_KEY_TRANSITIONS,
  TERMINAL_KEY_STATES,
  REPORTING_VERIFIER_ORDER,
  ROTATION_MODEL,
  RESTORE_GUARD,
  BOOTSTRAP_TRUST_ROOT,
} from "./lifecycle.js";

export {
  type VerifyResult,
  type RegisterProofCallbacks,
  REGISTER_PROOF_VERIFICATION_STAGES,
  decodeCanonicalReportingPublicKey,
  decodeCanonicalEd25519Signature,
  verifyRegisterProofOfPossession,
  verifyRegisterPreimage,
  reportingKeyMaySign,
  isLegalReportingKeyTransition,
  requestTupleMatchesBinding,
  credentialMechanismAllowed,
} from "./verifier.js";

export {
  REGISTER_GOLDEN_PREIMAGE_SHA256,
  REGISTER_GOLDEN_POP_SIGNATURE,
  REGISTER_GOLDEN_REPORTING_PUBKEY,
} from "./digests.js";

export {
  type ReportingAuthManifest,
  reportingAuthConcernManifest,
  buildReportingAuthManifest,
} from "./manifest.js";
