// the reporting bootstrap enrolment — Public surface of the reporting-behavior concern. Concern-local barrel owned by the
// the reporting bootstrap enrolment slice; NOT the package index (src/index.ts, owned by the concern-manifest registry).

export {
  type RequestOutcome,
  type RequestContext,
  type KeyUseOutcome,
  type KeySlot,
  type KeyRegistry,
  type TenantSeqOutcome,
  type ChainAppendOutcome,
  type RestoreOutcome,
  type RestoreState,
  type BootstrapEnrolmentOutcome,
  type BootstrapEnrolmentContext,
  REQUEST_MAX_WINDOW_MS,
  REQUEST_CLOCK_SKEW_MS,
  evaluateReportRequest,
  evaluateKeyUse,
  cutoverNeverGoesDark,
  evaluateTenantSeq,
  evaluateChainAppend,
  evaluateRestoreIngest,
  evaluateBootstrapEnrolment,
} from "./decisions.js";

export { type MatrixCell, buildReplayMatrix } from "./matrix.js";

export {
  type ReportingBehaviorManifest,
  reportingBehaviorConcernManifest,
  BEHAVIOUR_DIMENSIONS,
  buildReportingBehaviorManifest,
} from "./manifest.js";
