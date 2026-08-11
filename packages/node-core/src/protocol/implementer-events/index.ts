// Public surface for implementer-scoped continuity tuple verification.
// GET /v1/events serves zp-implementer-event-v1 and zp-implementer-checkpoint-v1;
// zp-implementer-keyrotation-v1 is verified by the same key class but not yet routed.

export {
  IMPLEMENTER_CONTINUITY_KEY_CLASS,
  ImplementerParseError,
  keyClassForImplementerPurpose,
  mayKeyClassSignImplementerPurpose,
  SuiteVerifyError,
  verifyImplementerCheckpoint,
  verifyImplementerEvent,
  verifyImplementerKeyRotation,
  type ImplementerContinuityPurpose,
  type ImplementerParseReason,
  type ParsedImplementerTuple,
  type SuiteVerifyReason,
} from "./verify.js";
