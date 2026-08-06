// The endpoint-disagreement anomaly seam. When two
// independently configured gateway endpoints disagree on a wallet's semantic state across
// a failover, the node must record the disagreement as a permanent anomaly and fail
// closed ("two independent gateway endpoints disagree → halt affected
// wallet/operation → INDETERMINATE; oracle incident";: "every
// relationship anomaly inserts a permanent observation row plus a permanent anomaly
// row").
//
// The concrete, DDL-backed recorder that writes an `observation_anomalies` row is
// DEFERRED to. That table is deliberately NOT transcribed in
// packages/node-core/src/schema/observation-ledger.sql yet — see that file's header:
// "the remainder of the observation ledger (wallet_observation_cursors, observation_anomalies,
// operation_landing_proofs, lineage_path_proofs, lineage_path_bodies,
// observation_relationship_adjudications) belongs to the observation-verification and
// landing-oracle lanes and is deliberately not transcribed here." Until
// lands the schema and its persistence adapter, the disagreement/halt safety logic in
// failover.ts is exercised against this injected port with an in-memory recorder in
// tests; production wiring of a DDL-backed AnomalyRecorder is a BLOCKING dependency on
// and must not be satisfied by minting a stand-in table here.

// One endpoint-disagreement anomaly. Plain data (no database coupling) so the halt
// logic is testable now without minting frozen observation_anomalies DDL.
// Fields are the minimum an oracle-incident row needs: the observer, the two disagreeing
// endpoints' fingerprints (copied at detection time so later reconfiguration cannot
// rewrite provenance, mirroring endpoint_fingerprint), and the two conflicting
// semantic states carried opaquely from the semantic reducer.
export interface EndpointDisagreementAnomaly {
  readonly observerId: string;
  readonly acceptedEndpointFingerprint: string;
  readonly servingEndpointFingerprint: string;
  readonly acceptedSemanticState: string;
  readonly servingSemanticState: string;
  readonly detectedAt: string;
}

// Injected persistence seam for anomalies. The disagreement path CALLS this port; its
// real backing (an observation_anomalies INSERT in the same transaction as the
// gateway_observations rows) is deliverable. Recorder failures propagate
// (fail-closed): an anomaly that cannot be persisted aborts the operation rather than
// silently vanishing, mirroring ObservationRecorder / SubmitAttemptRecorder in
// records.ts.
export interface AnomalyRecorder {
  recordDisagreement(anomaly: EndpointDisagreementAnomaly): Promise<void>;
}
