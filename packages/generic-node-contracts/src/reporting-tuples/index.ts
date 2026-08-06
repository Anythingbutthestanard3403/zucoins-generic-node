// the reporting node-event purpose — Public surface of the reporting-tuples concern. Concern-local barrel owned by the
// the reporting node-event purpose slice; NOT the package index (src/index.ts, owned by the concern-manifest registry). the reporting bootstrap enrolment consumes this.

export {
  type ReportRequestPayload,
  REPORT_REQUEST_PURPOSE,
  REPORT_REQUEST_CANONICAL_VERSION,
  REPORT_REQUEST_FIELD_ORDER,
  REPORT_REQUEST_MAX_WINDOW_SECONDS,
  REPORTING_REQUEST_HEADERS,
  // the guard-free money-path request-payload signing serializer is deliberately NOT
  // re-exported here. It is confined to the `./testkit` subpath (src/testkit/index.ts) so it
  // stays off this public concern barrel and off the root `.` barrel. The honest,
  // window-enforcing buildReportRequestPreimage below remains the public serializer. The
  // confinement is enforced by src/scan/reporting-serializer-confinement.census.test.ts.
  buildReportRequestPreimage,
  REPORT_REQUEST_GOLDEN_PAYLOAD,
  REPORT_REQUEST_GOLDEN_PREIMAGE,
  REPORT_REQUEST_QUERY_GOLDEN_PAYLOAD,
  REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE,
} from "./request-tuple.js";

export {
  type CanonicalTargetResult,
  REPORT_REQUEST_CLOCK_SKEW_MS,
  parseCanonicalRfc3339Ms,
  validateReportingRequestTarget,
} from "./request-target.js";

export {
  type NodeEventPayload,
  NODE_EVENT_PURPOSE,
  NODE_EVENT_CANONICAL_VERSION,
  NODE_EVENT_FIELD_ORDER,
  NEUTRAL_EVENT_TYPES,
  SEQUENCE_MODEL,
  buildNodeEventPreimage,
  NODE_EVENT_GOLDEN_A,
  NODE_EVENT_GOLDEN_B,
  NODE_EVENT_GOLDEN_A_PREIMAGE,
  NODE_EVENT_GOLDEN_B_PREIMAGE,
} from "./event-tuple.js";

export {
  type VerifyResult,
  verifyReportRequestPreimage,
  verifyNodeEventPreimage,
  eventChainLinks,
} from "./verifier.js";

export {
  REPORT_REQUEST_GOLDEN_SHA256,
  REPORT_REQUEST_GOLDEN_SIGNATURE,
  REPORT_REQUEST_QUERY_GOLDEN_SHA256,
  REPORT_REQUEST_QUERY_GOLDEN_SIGNATURE,
  REPORTING_KEY_PUBKEY,
  NODE_EVENT_A_SHA256,
  NODE_EVENT_A_SIGNATURE,
  NODE_EVENT_A_EVENT_HASH,
  NODE_EVENT_B_SHA256,
  NODE_EVENT_B_SIGNATURE,
  NODE_EVENT_B_EVENT_HASH,
  NODE_EVENT_KEY_PUBKEY,
} from "./digests.js";

export {
  type ReportingTuplesManifest,
  reportingTuplesConcernManifest,
  buildReportingTuplesManifest,
  EVENT_HASH_RULE,
} from "./manifest.js";
