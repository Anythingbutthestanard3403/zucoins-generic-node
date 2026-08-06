// assembly of the BurnNonceEvidence row for a fully verified signed
// reporting request: the frozen-purpose nonce evidence carrying the exact request preimage
// text, its sha256, the verbatim signature, and the logical fingerprint over the
// actual-inputs triple (method, raw target, body digest). Split out of request-verifier.ts
// for the file-size budget — no logic change.

import { REPORT_REQUEST_PURPOSE } from "@zucoins/generic-node-contracts";

import { computeReportingLogicalFingerprint, sha256HexUtf8 } from "./ed25519.js";
import type { ReportingRouteClassification } from "./route-table.js";
import type { BurnNonceEvidence, ReportingRegistration } from "./store.js";

export interface BurnEvidenceInput {
  readonly nodeId: string;
  readonly binding: ReportingRegistration;
  readonly route: ReportingRouteClassification;
  readonly lifecycleEpoch: bigint;
  readonly keyId: string;
  readonly nonce: string;
  readonly signature: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly method: string;
  readonly rawTarget: string;
  readonly bodySha256: string;
  readonly preimageText: string;
  readonly receivedAtMs: number;
  readonly consumedAtMs: number;
}

export function buildBurnNonceEvidence(input: BurnEvidenceInput): BurnNonceEvidence {
  return {
    nodeId: input.nodeId,
    implementerId: input.binding.implementerId,
    nonce: input.nonce,
    purpose: REPORT_REQUEST_PURPOSE,
    routeId: input.route.routeId,
    requestClass: input.route.requestClass,
    reportingKeyId: input.keyId,
    lifecycleEpoch: input.lifecycleEpoch,
    requestPreimageText: input.preimageText,
    requestPreimageSha256: sha256HexUtf8(input.preimageText),
    requestSignature: input.signature,
    method: input.method,
    rawTarget: input.rawTarget,
    bodySha256: input.bodySha256,
    logicalFingerprint: computeReportingLogicalFingerprint(
      input.method,
      input.rawTarget,
      input.bodySha256,
    ),
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    receivedAtMs: input.receivedAtMs,
    consumedAtMs: input.consumedAtMs,
    retentionClass: input.route.retentionClass,
  };
}
