// the events concern.2 — Public surface of the event-commit concern. Concern-local barrel owned by the events concern.2
// slice; NOT the package index (src/index.ts, owned by the concern-manifest registry). the events concern.3 consumes this.

export {
  COMMIT_STEP_ORDER,
  COMMIT_UNIT,
  ATOMICITY,
  SIGN_STEP,
  INSERT_EVENT_STEP,
} from "./commit.js";

export { OUTBOX_DECOUPLING, IDEMPOTENT_REDELIVERY } from "./outbox.js";

export { CONCURRENCY } from "./concurrency.js";

export { RESTART_COMMIT, KEY_ROTATION } from "./recovery.js";

export { DDL_CONSTRAINTS } from "./ddl.js";

export {
  type AtomicityShape,
  type OutboxShape,
  type RedeliveryShape,
  type ConcurrencyShape,
  type RestartCommitShape,
  type KeyRotationShape,
  type DdlConstraintShape,
  allocationPrefixValid,
  noUnsignedGap,
  rollbackBurnsNoSeq,
  outboxVisibleOnlyPostCommit,
  deliveryFailureImmutable,
  redeliveryIsIdempotent,
  concurrentWritersOneWinnerGapless,
  restartResumesGaplessAndRedelivers,
  keyRotationPreservesChain,
  ddlEnforcesAtomicCommit,
  unitBindsStateTransition,
  preimageBindsCurrentHead,
} from "./verifier.js";

export {
  type EventCommitManifest,
  eventCommitConcernManifest,
  buildEventCommitManifest,
} from "./manifest.js";
