// the tenant_and_key_binding and lifecycle_eligibility pre-burn stages
// of the signed reporting request pipeline (PRE_BURN_CHECKS, positions after bounded_rate):
// the registration selected by the (unsigned) key-id selector and scoped to this node, holds
// plus lifecycle admission of the presented key against the current head snapshot at the
// ingress instant, then tenant equality before anything object-scoped. Split out of
// request-verifier.ts for the file-size budget — no logic change.

import { requestTupleMatchesBinding } from "@zucoins/generic-node-contracts";

import type { ReportingRejectionCode } from "./errors.js";
import {
  reportingKeyAdmissionEligible,
  type ReportingAdmissionSnapshot,
  type ReportingRegistration,
  type ReportingRequestStore,
} from "./store.js";

export interface ReportingAdmissionGranted {
  readonly ok: true;
  readonly binding: ReportingRegistration;
  readonly snapshot: ReportingAdmissionSnapshot;
}

export interface ReportingAdmissionDenied {
  readonly ok: false;
  readonly code: ReportingRejectionCode;
}

export type ReportingAdmissionOutcome = ReportingAdmissionGranted | ReportingAdmissionDenied;

const deny = (code: ReportingRejectionCode): ReportingAdmissionDenied => ({ ok: false, code });

export async function admitReportingKey(
  store: ReportingRequestStore,
  nodeId: string,
  keyId: string,
  receivedAtMs: number,
): Promise<ReportingAdmissionOutcome> {
  // tenant_and_key_binding: the registration selected by the (unsigned) key-id selector,
  // scoped to this node. The tuple's tenant fields are built from this binding only.
  const binding = await store.findRegistration(nodeId, keyId);
  if (binding === null) return deny("unknown_reporting_key");

  // key_status before any crypto (REPORTING_VERIFIER_ORDER): holds, then lifecycle admission
  // of the presented key against the current head snapshot at the ingress instant.
  const snapshot = await store.readAdmissionSnapshot(nodeId, binding.implementerId, keyId);
  if (snapshot === null) return deny("reporting_key_not_active");
  if (snapshot.restoreHold || snapshot.authHold) return deny("reporting_auth_hold");
  const admitted = reportingKeyAdmissionEligible({
    presentedKeyId: keyId,
    currentKeyId: snapshot.currentKeyId,
    priorKeyId: snapshot.priorKeyId,
    overlapExpiresAtMs: snapshot.overlapExpiresAtMs,
    successorCommittedAtMs: snapshot.successorCommittedAtMs,
    presentedKeyState: snapshot.presentedKeyState,
    presentedKeyRevokedAtMs: snapshot.presentedKeyRevokedAtMs,
    receivedAtMs,
  });
  if (!admitted) return deny("reporting_key_not_active");

  // tenant_equality before anything object-scoped: the tuple fields equal the binding by
  // construction; this assert closes the store-corruption case (and a binding registered for
  // a different node) without an existence oracle.
  if (
    binding.nodeId !== nodeId ||
    !requestTupleMatchesBinding(
      {
        reporting_key_id: binding.reportingKeyId,
        node_id: binding.nodeId,
        implementer_id: binding.implementerId,
      },
      { node_id: binding.nodeId, implementer_id: binding.implementerId },
    )
  ) {
    return deny("tenant_binding_mismatch");
  }

  return { ok: true, binding, snapshot };
}
