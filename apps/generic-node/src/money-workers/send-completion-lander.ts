// SEND_EXTERNAL observe-only completion lander.
//
// Invariants: one approval, one partial; the landing-proof rule as applicable
// to source observe; never blind-retry (the never-blind-retry rule). Replaces the offline stub
// `tickSendCompletionMonitorOffline` with a real observe-and-land worker.
//
// The node NEVER submits the recipient's completion (correct — the recipient owns step-2).
// This worker OBSERVES the source wallet's head: if the gateway shows the SEND's source
// balance decreased by the exact amount with the correct step-2 signature present, the landing-proof rule
// landing oracle verifies the proof and the landing DB-TX commits EXTERNAL_SEND_LANDED +
// the exact settled body + the terminal observation. The source lease is NOT released here
// (the verification-complete acknowledgement releases it).
//
// Head classification (B4): only an unchanged genesis/T0 head may stay WAITING. A head that
// is a different transaction (changed), malformed, or anomalous is parked NEEDS_ATTENTION
// with a closed reason + event. A head that IS our send (exact step-1 signature match) is
// driven through the landing oracle and the nine-predicate verifier; every non-VERIFIED oracle
// outcome is INDETERMINATE (never a false landing, never a rebuild — No-blind-retry).
//
// `readFreshHead` and `store` are injected ports so the whole flow runs offline against a real
// PostgreSQL with a scripted gateway exchange (test/send-completion-lander.pg.test.ts).

import { randomUUID } from "node:crypto";

import type { Pool } from "pg";

import {
  GENESIS_PROJECTION,
  OPERATION_NEEDS_ATTENTION_EVENT,
  SEND_EXPIRY_ATTENTION_REASON,
  SEND_EXPIRY_ATTENTION_SQL,
  commitExternalSendLanding,
  createSqlRetainedPathBodySource,
  fetchRetainedBodyByObservationId,
  fetchRetainedBodyByStepOneSignature,
  parseGatewayEnvelope,
  proveSendLanding,
  sha256HexUtf8,
  verifyDetachedEd25519,
  verifyDeviceSignature,
  verifyExternalSendLanding,
  verifySettledTransaction,
  walkAncestryPath,
  InMemoryLineagePathProofStore,
  type CommitExternalSendLandingOutcome,
  type DeviceKeyStore,
  type ExternalSendLandingStore,
  type FreshHeadRead,
  type MetricsHooks,
  type ParsedSettledTransaction,
  type ReadFreshHead,
  type SendLandingEvidence,
  type SendLandingVerdict,
  type WalletStateProjection,
} from "@zucoins/node-core";

export interface SendCompletionLogger {
  info(message: string): void;
  error(message: string, err?: unknown): void;
}

// a candidate-query PostgreSQL fault (connection loss, permission revocation,
// schema drift/missing table) must never be laundered into "zero candidates" (healthy idle,
// No-blind-retry). Thrown out of loadSendLandingCandidates and left unswallowed so it propagates out of
// tickSendCompletionLander to the tick-loop error boundary (start-money-workers.ts) instead of
// returning a false-idle result. `kind` distinguishes a structural fault (missing table /
// permission denied — SQLSTATE 42P01 / 42501, likely durable until an operator fixes schema or
// grants) from a transient one (everything else, e.g. connection refused/timeout — may clear on
// its own); both are still faults, never idle.
const PG_STRUCTURAL_SQLSTATES = new Set(["42P01", "42501"]);

export class SendLandingCandidateQueryError extends Error {
  readonly kind: "STRUCTURAL" | "TRANSIENT";
  readonly sqlstate: string | undefined;

  constructor(cause: unknown) {
    const sqlstate =
      typeof (cause as { code?: unknown } | null)?.code === "string"
        ? (cause as { code: string }).code
        : undefined;
    const kind: "STRUCTURAL" | "TRANSIENT" =
      sqlstate !== undefined && PG_STRUCTURAL_SQLSTATES.has(sqlstate) ? "STRUCTURAL" : "TRANSIENT";
    const causeMessage = cause instanceof Error ? cause.message : String(cause);
    super(
      `money-workers: SEND completion candidate query failed (${kind}${sqlstate !== undefined ? `, sqlstate ${sqlstate}` : ""}): ${causeMessage}`,
      { cause },
    );
    this.name = "SendLandingCandidateQueryError";
    this.kind = kind;
    this.sqlstate = sqlstate;
  }
}

export interface SendObserveLanderDeps {
  readonly pool: Pool;
  readonly logger: SendCompletionLogger;
  /** The durable source-head confirm-read (sql-fresh-head-reader.ts). */
  readonly readFreshHead: ReadFreshHead;
  /** The landing DB-TX (createSqlExternalSendLandingStore — operations mirror). */
  readonly store: ExternalSendLandingStore;
  /** Node id — for device signature verification (B5) + node identity key lookup. */
  readonly nodeId: string;
  /** Device key store — for approval device-signature verification (B5). */
  readonly deviceKeyStore: DeviceKeyStore;
  /** Lifecycle metrics fire only after the landing CAS is APPLIED. */
  readonly metricsHooks?: MetricsHooks;
  readonly batchSize?: number;
}

const DEFAULT_BATCH = 25;
const ENTRY_STATUS = "AWAITING_REDEMPTION" as const;

/** The one attention reason this lander parks on (UNEXPECTED_HEAD_CHANGE). */
const HEAD_ANOMALY_REASON = SEND_EXPIRY_ATTENTION_REASON;

interface SendLandingCandidate {
  readonly operationId: string;
  readonly rowVersion: number;
  readonly sourceWalletId: string;
  readonly sourcePubkey: string;
  readonly destinationAddress: string;
  readonly amountZkz: string;
  readonly referencesOperationId: string | null;
  readonly nodeId: string;
  // Sign intent (null when absent — verifier predicate 3 rejects).
  readonly intentApprovalId: string | null;
  readonly sourceT0ObservationId: string | null;
  readonly destinationT0ObservationId: string | null;
  readonly innerPreimageText: string | null;
  readonly innerSha256: string | null;
  // Partial (always present — INNER JOIN).
  readonly partialInnerSha256: string;
  readonly step1Signature: string;
  readonly transferCodeSha256: string;
  readonly firstDeliveredAt: Date | string | null;
  // Approval (null when absent — verifier predicate 2 rejects).
  readonly approvalId: string | null;
  readonly approvalMethod: string | null;
  readonly deviceKeyId: string | null;
  readonly deviceSignature: string | null;
  readonly approvalPreimageText: string | null;
  // Expected artifact (null when absent — verifier predicate 1 rejects).
  readonly artifactPreimageText: string | null;
  readonly artifactPreimageSha256: string | null;
  readonly artifactSignature: string | null;
  // Node identity public key (for artifact signature verification — B5).
  readonly nodeIdentityPublicKey: string | null;
  // T0 observation bodies (null = genesis).
  readonly sourceT0BodyText: string | null;
  readonly destT0BodyText: string | null;
  // Lease active (One-in-flight).
  readonly sourceLeaseActive: boolean;
}

/**
 * The result of classifying + gathering evidence for one candidate.
 *
 * EVIDENCE — the head is our send; the full nine-predicate evidence is assembled and the
 * landing path proof is built; the caller verifies + commits.
 * INDETERMINATE — the gateway read or path proof failed; the row stays AWAITING_REDEMPTION
 *   and the next tick retries the OBSERVATION, never the transaction (No-blind-retry).
 * PARK_ATTENTION — the head is changed, malformed, or anomalous (B4); the row is parked to
 *   NEEDS_ATTENTION with a closed reason + event.
 * WAITING — the source head is still genesis/T0 (unchanged); the row stays AWAITING_REDEMPTION.
 */
type GatherResult =
  | { readonly kind: "EVIDENCE"; readonly evidence: SendLandingEvidence }
  | { readonly kind: "INDETERMINATE"; readonly detail: string }
  | { readonly kind: "PARK_ATTENTION"; readonly reason: string; readonly detail: string }
  | { readonly kind: "WAITING"; readonly detail: string };

/**
 * Load AWAITING_REDEMPTION sends with a persisted partial plus all the durable material the
 * nine-predicate verifier needs: sign intent, approval, expected artifact, T0 observation
 * bodies, and the source lease presence. A landed operation advances to EXTERNAL_SEND_LANDED
 * and no longer matches this query — that is the crash-resume property.
 */
async function loadSendLandingCandidates(
  pool: Pool,
  batchSize: number,
): Promise<readonly SendLandingCandidate[]> {
  let result: { rows: Record<string, unknown>[] };
  try {
    result = await pool.query<Record<string, unknown>>(
      `SELECT s.operation_id::text AS operation_id,
              s.row_version::bigint AS row_version,
              s.source_wallet_id::text AS source_wallet_id,
              w.public_key AS source_pubkey,
              s.destination_address AS destination_address,
              s.amount_zkz::text AS amount_zkz,
              s.references_operation_id::text AS references_operation_id,
              s.node_id::text AS node_id,
              si.approval_id::text AS intent_approval_id,
              si.source_t0_observation_id::text AS source_t0_observation_id,
              si.destination_t0_observation_id::text AS destination_t0_observation_id,
              si.inner_preimage_text AS inner_preimage_text,
              si.inner_sha256 AS inner_sha256,
              p.inner_sha256 AS partial_inner_sha256,
              p.step_1_signature AS step_1_signature,
              p.transfer_code_sha256 AS transfer_code_sha256,
              p.first_delivered_at AS first_delivered_at,
              ap.id::text AS approval_id,
              ap.method::text AS approval_method,
              ap.device_key_id::text AS device_key_id,
              ap.device_signature AS device_signature,
              ap.preimage_text AS approval_preimage_text,
              a.preimage_text AS artifact_preimage_text,
              a.preimage_sha256 AS artifact_preimage_sha256,
              a.signature AS artifact_signature,
              (SELECT n.identity_public_key FROM nodes n WHERE n.id = s.node_id)
                AS node_identity_public_key,
              st0.completed_transaction_text AS source_t0_body_text,
              dt0.completed_transaction_text AS dest_t0_body_text,
              EXISTS (SELECT 1 FROM wallet_active_leases l
                       WHERE l.wallet_id = s.source_wallet_id
                         AND l.lease_group_id = si.lease_group_id
                         AND l.lease_epoch = si.lease_epoch) AS source_lease_active
         FROM send_operations s
         INNER JOIN wallets w ON w.id = s.source_wallet_id
         INNER JOIN external_send_partials p ON p.operation_id = s.operation_id
         LEFT JOIN external_send_sign_intents si ON si.operation_id = s.operation_id
         LEFT JOIN operation_approvals ap ON ap.operation_id = s.operation_id
         LEFT JOIN send_operation_expected_artifacts a ON a.operation_id = s.operation_id
         LEFT JOIN gateway_observations st0 ON st0.id = si.source_t0_observation_id
         LEFT JOIN gateway_observations dt0 ON dt0.id = si.destination_t0_observation_id
        WHERE s.status = 'AWAITING_REDEMPTION'
        ORDER BY s.created_at ASC -- contract-allow:order:frozen structural vocabulary
        LIMIT $1`,
      [batchSize],
    );
  } catch (err) {
    // Never launder a query fault into an empty (healthy-idle) candidate set —
    // propagate typed so the caller's tick fails loudly instead of reporting zero work.
    throw new SendLandingCandidateQueryError(err);
  }
  return result.rows.map((r): SendLandingCandidate => ({
    operationId: r.operation_id as string,
    rowVersion: Number(r.row_version),
    sourceWalletId: r.source_wallet_id as string,
    sourcePubkey: r.source_pubkey as string,
    destinationAddress: r.destination_address as string,
    amountZkz: r.amount_zkz as string,
    referencesOperationId: (r.references_operation_id as string | null) ?? null,
    nodeId: r.node_id as string,
    intentApprovalId: (r.intent_approval_id as string | null) ?? null,
    sourceT0ObservationId: (r.source_t0_observation_id as string | null) ?? null,
    destinationT0ObservationId: (r.destination_t0_observation_id as string | null) ?? null,
    innerPreimageText: (r.inner_preimage_text as string | null) ?? null,
    innerSha256: (r.inner_sha256 as string | null) ?? null,
    partialInnerSha256: r.partial_inner_sha256 as string,
    step1Signature: r.step_1_signature as string,
    transferCodeSha256: r.transfer_code_sha256 as string,
    firstDeliveredAt: (r.first_delivered_at as Date | string | null) ?? null,
    approvalId: (r.approval_id as string | null) ?? null,
    approvalMethod: (r.approval_method as string | null) ?? null,
    deviceKeyId: (r.device_key_id as string | null) ?? null,
    deviceSignature: (r.device_signature as string | null) ?? null,
    approvalPreimageText: (r.approval_preimage_text as string | null) ?? null,
    artifactPreimageText: (r.artifact_preimage_text as string | null) ?? null,
    artifactPreimageSha256: (r.artifact_preimage_sha256 as string | null) ?? null,
    artifactSignature: (r.artifact_signature as string | null) ?? null,
    nodeIdentityPublicKey: (r.node_identity_public_key as string | null) ?? null,
    sourceT0BodyText: (r.source_t0_body_text as string | null) ?? null,
    destT0BodyText: (r.dest_t0_body_text as string | null) ?? null,
    sourceLeaseActive: r.source_lease_active as boolean,
  }));
}

/**
 * Re-read a durably persisted `completed_transaction_text` as a parsed settled transaction,
 * through the exact observation envelope stage the gateway path uses — same key-sequence and
 * scalar exactness, no bespoke parser and no JSON.parse here (mirrors receive-landing-step's
 * `parseStoredSettledBody`).
 *
 * The round trip is byte-compared (the byte-exact signing rule): if re-serializing the
 * parse does not reproduce the stored bytes, the stored body has been normalized and is
 * refused rather than used as a T0 baseline.
 */
function parseStoredSettledBody(text: string): ParsedSettledTransaction | null {
  const envelope = parseGatewayEnvelope(
    Buffer.from(`{"status":true,"code":"ok","message":"","data":[${text}]}`, "utf8"),
  );
  if (envelope.classification !== "HEAD") return null;
  return JSON.stringify(envelope.parsed) === text ? envelope.parsed : null;
}

/** Decode a padded base64url string (with = padding) to a Uint8Array. */
function decodePaddedBase64Url(value: string): Uint8Array | null {
  try {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/**
 * Build a BaselineObservation from a stored T0 body. Genesis (null text) yields
 * GENESIS_PROJECTION. A non-null body is parsed, verified under the wallet pubkey, and the
 * role-relative projection is extracted. Returns null when the body is not byte-exact or
 * does not verify — the caller treats that as INDETERMINATE.
 */
function buildBaselineObservation(
  bodyText: string | null,
  walletPubkey: string,
  observationId: string,
): { observation: { observationId: string; projection: WalletStateProjection }; body: ParsedSettledTransaction | null } | null {
  if (bodyText === null) {
    return { observation: { observationId, projection: GENESIS_PROJECTION }, body: null };
  }
  const parsed = parseStoredSettledBody(bodyText);
  if (parsed === null) return null;
  const verified = verifySettledTransaction(parsed, walletPubkey);
  if (verified.verdict !== "VERIFIED") return null;
  return { observation: { observationId, projection: verified.projection }, body: parsed };
}

/**
 * B5 — cryptographically verify the expected artifact signature against the recorded node
 * identity key. Returns true only when sha256(preimage) === preimage_sha256 AND the Ed25519
 * signature verifies under the node identity public key.
 */
function verifyArtifactSignature(input: {
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly signature: string;
  readonly nodeIdentityPublicKey: string;
}): boolean {
  if (sha256HexUtf8(input.preimageText) !== input.preimageSha256) return false;
  const publicKeyBytes = decodePaddedBase64Url(input.nodeIdentityPublicKey);
  const signatureBytes = decodePaddedBase64Url(input.signature);
  if (publicKeyBytes === null || signatureBytes === null) return false;
  return verifyDetachedEd25519({
    publicKeyBytes,
    preimageText: input.preimageText,
    signatureBytes,
  });
}

/**
 * B5 — cryptographically verify the device approval signature against the active, non-revoked
 * device key. Returns { required, verified }. When the approval method is TOTP_ONLY, no
 * device signature is required. When TOTP_AND_DEVICE, the device key is resolved from the
 * store and the signature is verified over the approval preimage.
 */
function verifyDeviceApproval(input: {
  readonly method: string;
  readonly deviceKeyId: string | null;
  readonly deviceSignature: string | null;
  readonly approvalPreimageText: string | null;
  readonly nodeId: string;
  readonly deviceKeyStore: DeviceKeyStore;
}): { readonly required: boolean; readonly verified: boolean } {
  if (input.method !== "TOTP_AND_DEVICE") {
    return { required: false, verified: false };
  }
  if (input.deviceKeyId === null || input.deviceSignature === null || input.approvalPreimageText === null) {
    return { required: true, verified: false };
  }
  const deviceKey = input.deviceKeyStore.findById(input.deviceKeyId);
  if (deviceKey === null) return { required: true, verified: false };
  const signatureBytes = decodePaddedBase64Url(input.deviceSignature);
  if (signatureBytes === null) return { required: true, verified: false };
  const result = verifyDeviceSignature(input.deviceKeyStore, {
    nodeId: input.nodeId,
    publicKey: deviceKey.publicKey,
    preimageText: input.approvalPreimageText,
    signatureBytes,
  });
  return { required: true, verified: result.ok };
}

/**
 * Gather the SendLandingEvidence for one candidate by reading the source wallet's fresh head
 * from the gateway and the persisted sign intent / partial / approval from the DB (B1), then
 * building the landing path proof and verifying the artifact + device signatures (B5). Classifies
 * the head state per B4.
 */
async function gatherSendLandingEvidence(
  candidate: SendLandingCandidate,
  deps: SendObserveLanderDeps,
): Promise<GatherResult> {
  // The sign intent and approval are required to build evidence. Their absence is a durable
  // inconsistency — INDETERMINATE, not a park (the row is not anomalous, the material is missing).
  if (
    candidate.intentApprovalId === null ||
    candidate.sourceT0ObservationId === null ||
    candidate.destinationT0ObservationId === null ||
    candidate.innerPreimageText === null ||
    candidate.innerSha256 === null
  ) {
    return { kind: "INDETERMINATE", detail: "sign intent is absent or incomplete" };
  }
  if (candidate.approvalId === null || candidate.approvalMethod === null) {
    return { kind: "INDETERMINATE", detail: "approval is absent" };
  }

  // Step 1 — read the source wallet's fresh head (the durable confirm-read).
  let headRead: FreshHeadRead;
  try {
    headRead = await deps.readFreshHead(candidate.sourcePubkey);
  } catch (err) {
    return {
      kind: "INDETERMINATE",
      detail: err instanceof Error ? err.message : "source head read failed",
    };
  }

  const envelope = headRead.envelope;

  // B4 — classify the head state.
  if (envelope.classification === "GENESIS") {
    // Source wallet is still at genesis — the SEND has not landed yet. WAITING.
    return { kind: "WAITING", detail: "source head is genesis (no transaction landed)" };
  }
  if (envelope.classification === "MALFORMED_ENVELOPE") {
    // Malformed gateway response — park NEEDS_ATTENTION (B4 anomalous).
    return {
      kind: "PARK_ATTENTION",
      reason: HEAD_ANOMALY_REASON,
      detail: `malformed source head envelope: ${envelope.reason}`,
    };
  }

  // envelope.classification === "HEAD" — a settled transaction is present.
  const headTx: ParsedSettledTransaction = envelope.parsed;
  const headVerified = verifySettledTransaction(headTx, candidate.sourcePubkey);
  if (headVerified.verdict !== "VERIFIED") {
    // The head does not verify under the source key — anomalous/malformed (B4).
    return {
      kind: "PARK_ATTENTION",
      reason: HEAD_ANOMALY_REASON,
      detail: `source head does not verify under source key: ${headVerified.verdict}`,
    };
  }

  // B1 — verify the head binds to the persisted partial: byte-exact step-1 signature match.
  // But first: if the head IS the source T0 (unchanged), the send has not landed yet — WAITING
  // (B4: only unchanged T0/genesis may stay WAITING). Compare the head's body sha to the T0's.
  if (
    candidate.sourceT0BodyText !== null &&
    headVerified.completedTransactionSha256 === sha256HexUtf8(candidate.sourceT0BodyText)
  ) {
    return { kind: "WAITING", detail: "source head is unchanged T0 (send has not landed yet)" };
  }

  // Exact-head (depth 0) vs buried (depth ≥ 1, under later hops): both are
  // legitimate landing shapes for our own send, never a park by themselves. A step-1 mismatch
  // with NO retained row for our own send at all (fetchRetainedBodyByStepOneSignature ⇒ NONE,
  // below) remains the real B4 anomaly — the source wallet changed under the lease.
  const isExactHeadMatch = headTx.step_1_signature === candidate.step1Signature;

  // Build the source T0 baseline observation.
  const sourceT0 = buildBaselineObservation(
    candidate.sourceT0BodyText,
    candidate.sourcePubkey,
    candidate.sourceT0ObservationId,
  );
  if (sourceT0 === null) {
    return { kind: "INDETERMINATE", detail: "source T0 body is not byte-exact or does not verify" };
  }

  // Build the destination T0 baseline observation.
  const destT0 = buildBaselineObservation(
    candidate.destT0BodyText,
    candidate.destinationAddress,
    candidate.destinationT0ObservationId,
  );
  if (destT0 === null) {
    return { kind: "INDETERMINATE", detail: "destination T0 body is not byte-exact or does not verify" };
  }

  // B5 — verify the expected artifact signature against the recorded node identity key.
  const expectedArtifactVerified =
    candidate.artifactPreimageText !== null &&
    candidate.artifactPreimageSha256 !== null &&
    candidate.artifactSignature !== null &&
    candidate.nodeIdentityPublicKey !== null &&
    verifyArtifactSignature({
      preimageText: candidate.artifactPreimageText,
      preimageSha256: candidate.artifactPreimageSha256,
      signature: candidate.artifactSignature,
      nodeIdentityPublicKey: candidate.nodeIdentityPublicKey,
    });

  // B5 — verify the device approval signature against the active non-revoked device key.
  const deviceResult = verifyDeviceApproval({
    method: candidate.approvalMethod,
    deviceKeyId: candidate.deviceKeyId,
    deviceSignature: candidate.deviceSignature,
    approvalPreimageText: candidate.approvalPreimageText,
    nodeId: candidate.nodeId,
    deviceKeyStore: deps.deviceKeyStore,
  });

  // Build the landing path proof for the SOURCE wallet. Exact head match, depth 0
  // (proveSendLanding). Buried under later hops, depth ≥ 1 (walkAncestryPath, reusing
  // the retained-body forward walk rather than depth-0 equality alone).
  let candidateEvidence;
  let pathProof;
  let pathProofIncomplete = false;

  if (isExactHeadMatch) {
    // `headVerified.transaction` is the narrowed SettledSplitChainTransaction (the verified
    // form of the ParsedSettledTransaction); `completedTransactionText` is its byte-exact
    // JSON.stringify, re-derived here so the settled-body triple is self-consistent.
    const completedTransaction = headVerified.transaction;
    const completedTransactionText = JSON.stringify(completedTransaction);
    const completedTransactionSha256 = sha256HexUtf8(completedTransactionText);
    const step1PreimageText = headVerified.innerPreimageText;

    candidateEvidence = {
      completedTransaction,
      completedTransactionText,
      completedTransactionSha256,
      step1PreimageText,
      step1Signature: headTx.step_1_signature,
      step2Signature: headTx.step_2_signature,
      step2SignatureVerified: true,
    };

    try {
      const oracleOutcome = await proveSendLanding(
        {
          walletPubkeyBase64Urlsafe: candidate.sourcePubkey,
          t0Body: sourceT0.body,
          expectedBody: headTx,
          successorBodies: [],
          operation: {
            amountZkz: candidate.amountZkz,
            sourcePubkey: candidate.sourcePubkey,
            destinationAddress: candidate.destinationAddress,
          },
        },
        deps.readFreshHead,
      );
      if (oracleOutcome.kind === "PROOF_INCOMPLETE") {
        pathProof = null;
        pathProofIncomplete = true;
      } else {
        pathProof = oracleOutcome;
      }
    } catch (err) {
      return {
        kind: "INDETERMINATE",
        detail: err instanceof Error ? err.message : "proveSendLanding threw",
      };
    }
  } else {
    // Buried: the current head is neither T0 nor our send. Find our own send's completed
    // body wherever it now sits, by the one identifier that survives regardless of chain
    // position — (sourcePubkey, step1Signature). NONE here (not merely a mismatched head) is
    // the real B4 anomaly: the source wallet changed under the lease with no trace of our send.
    const ownBodyResolution = await fetchRetainedBodyByStepOneSignature(
      { sql: deps.pool },
      candidate.sourcePubkey,
      candidate.step1Signature,
    );
    if (ownBodyResolution.kind === "NONE") {
      return {
        kind: "PARK_ATTENTION",
        reason: HEAD_ANOMALY_REASON,
        detail: "source head step_1_signature does not match the persisted partial (head changed)",
      };
    }
    if (ownBodyResolution.kind === "AMBIGUOUS") {
      return {
        kind: "INDETERMINATE",
        detail: "own send's completed body is ambiguous across retained rows",
      };
    }

    const ownBody = ownBodyResolution.body;
    const ownParsed = parseStoredSettledBody(ownBody.completed_transaction_text);
    const ownVerified =
      ownParsed === null ? null : verifySettledTransaction(ownParsed, candidate.sourcePubkey);
    if (ownParsed === null || ownVerified === null || ownVerified.verdict !== "VERIFIED") {
      return {
        kind: "INDETERMINATE",
        detail: "own send's retained body is not byte-exact or does not verify",
      };
    }

    candidateEvidence = {
      completedTransaction: ownVerified.transaction,
      completedTransactionText: ownVerified.completedTransactionText,
      completedTransactionSha256: ownVerified.completedTransactionSha256,
      step1PreimageText: ownVerified.innerPreimageText,
      step1Signature: ownParsed.step_1_signature,
      step2Signature: ownParsed.step_2_signature,
      step2SignatureVerified: true,
    };

    // Baseline for the walk: reuse the source T0 retained body already resolved above when it
    // carried one, otherwise anchor at genesis by observation id (same shape as sourceT0.body).
    let walkBaseline;
    if (candidate.sourceT0BodyText === null) {
      walkBaseline = { kind: "GENESIS" as const, observation_id: candidate.sourceT0ObservationId };
    } else {
      const t0Retained = await fetchRetainedBodyByObservationId(
        { sql: deps.pool },
        candidate.sourceT0ObservationId,
      );
      if (t0Retained === null) {
        return {
          kind: "INDETERMINATE",
          detail: "source T0 retained body not found for buried walk",
        };
      }
      walkBaseline = { kind: "HEAD" as const, body: t0Retained };
    }

    try {
      const walkOutcome = await walkAncestryPath(
        {
          pathProofId: randomUUID(),
          landingProofId: randomUUID(),
          walletId: candidate.sourceWalletId,
          walletPublicKey: candidate.sourcePubkey,
          operation: {
            kind: "SEND_EXTERNAL",
            amountZkz: candidate.amountZkz,
            sourcePubkey: candidate.sourcePubkey,
            destinationAddress: candidate.destinationAddress,
          },
          expectedBody: ownBody,
          baseline: walkBaseline,
        },
        createSqlRetainedPathBodySource({ sql: deps.pool }),
        deps.readFreshHead,
        new InMemoryLineagePathProofStore(),
      );
      if (walkOutcome.kind === "PATH_PROVEN") {
        pathProof = walkOutcome.proof;
      } else {
        // Fail-closed (No-blind-retry): unprovable buried path never lands and never launders as a
        // park — it stays INDETERMINATE, same disposition as any other unverifiable oracle
        // outcome, so the row remains WAITING rather than a false LANDED.
        return {
          kind: "INDETERMINATE",
          detail: `buried send path unprovable: ${walkOutcome.fault}`,
        };
      }
    } catch (err) {
      return {
        kind: "INDETERMINATE",
        detail: err instanceof Error ? err.message : "walkAncestryPath threw",
      };
    }
  }

  // Assemble the full nine-predicate evidence.
  const evidence: SendLandingEvidence = {
    operationId: candidate.operationId,
    entryStatus: ENTRY_STATUS,
    economic: {
      operationId: candidate.operationId,
      sourceWalletId: candidate.sourceWalletId,
      sourcePubkey: candidate.sourcePubkey,
      destinationAddress: candidate.destinationAddress,
      amountZkz: candidate.amountZkz,
      referencesOperationId: candidate.referencesOperationId,
    },
    expectedArtifactVerified,
    expectedArtifact: {
      sourcePubkey: candidate.sourcePubkey,
      destinationAddress: candidate.destinationAddress,
      amountZkz: candidate.amountZkz,
      referencesOperationId: candidate.referencesOperationId,
    },
    approval: {
      approvalId: candidate.approvalId,
      totpConsumed: true,
      deviceSignatureRequired: deviceResult.required,
      deviceSignatureVerified: deviceResult.verified,
      sourcePubkey: candidate.sourcePubkey,
      destinationAddress: candidate.destinationAddress,
      amountZkz: candidate.amountZkz,
      referencesOperationId: candidate.referencesOperationId,
    },
    signIntent: {
      approvalId: candidate.intentApprovalId,
      sourceT0ObservationId: candidate.sourceT0ObservationId,
      destinationT0ObservationId: candidate.destinationT0ObservationId,
      innerPreimageText: candidate.innerPreimageText,
      innerSha256: candidate.innerSha256,
    },
    signIntentRowCount: 1,
    partial: {
      innerSha256: candidate.partialInnerSha256,
      step1Signature: candidate.step1Signature,
      transferCodeSha256: candidate.transferCodeSha256,
      deliveredTransferCodeSha256:
        candidate.firstDeliveredAt === null ? null : candidate.transferCodeSha256,
      otherDeliveredPartialSha256: [],
    },
    sourceT0: sourceT0.observation,
    destinationT0: destT0.observation,
    candidate: candidateEvidence,
    sourcePathProof: pathProof,
    sourcePathProofIncomplete: pathProofIncomplete,
    sourceLeaseActive: candidate.sourceLeaseActive,
  };

  return { kind: "EVIDENCE", evidence };
}

/**
 * B4 — park an AWAITING_REDEMPTION send to NEEDS_ATTENTION with a closed reason + event in
 * one DB-TX (CAS_AWAITING_TO_NEEDS_ATTENTION), then sync the operations mirror. Returns true
 * when the park was applied. A row that already advanced (landed, or already attention) is a
 * no-op.
 */
async function parkSendOnHeadAnomaly(
  pool: Pool,
  operationId: string,
  reason: string,
): Promise<boolean> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const cas = await client.query<{ operation_id: string; row_version: string }>(
      SEND_EXPIRY_ATTENTION_SQL.CAS_AWAITING_TO_NEEDS_ATTENTION,
      [operationId, reason, OPERATION_NEEDS_ATTENTION_EVENT],
    );
    if (cas.rows.length === 0) {
      await client.query("ROLLBACK");
      return false;
    }
    // Sync the operations mirror (lockstep) in the same TX.
    await client.query(
      `UPDATE operations o
          SET status = s.status::operation_status,
              formation_state = s.formation_state::external_formation_state,
              attention_required = s.attention_required,
              attention_reason = s.attention_reason,
              row_version = s.row_version,
              updated_at = now()
         FROM send_operations s
        WHERE s.operation_id = $1::uuid
          AND o.id = s.operation_id
          AND o.kind = 'SEND_EXTERNAL'`,
      [operationId],
    );
    await client.query("COMMIT");
    return true;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* keep the original failure */
    }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * The production SEND completion observe-lander. Replaces
 * `tickSendCompletionMonitorOffline`. For each AWAITING_REDEMPTION send with a persisted
 * partial, observes the source wallet's head, classifies the head state (B4), verifies the
 * landing proof + nine predicates, and commits EXTERNAL_SEND_LANDED + the exact settled
 * body. Never invents landing without a gateway OBSERVE (AC3). Never submits the recipient's
 * completion (AC4).
 */
export async function tickSendCompletionLander(
  deps: SendObserveLanderDeps,
): Promise<{ readonly landed: readonly string[]; readonly indeterminate: number; readonly parked: number }> {
  const batchSize = deps.batchSize ?? DEFAULT_BATCH;
  const candidates = await loadSendLandingCandidates(deps.pool, batchSize);

  if (candidates.length === 0) {
    return { landed: [], indeterminate: 0, parked: 0 };
  }

  deps.logger.info(`money-workers: SEND completion lander scanning ${candidates.length} AWAITING_REDEMPTION op(s)`);

  const landed: string[] = [];
  let indeterminate = 0;
  let parked = 0;

  for (const candidate of candidates) {
    let gather: GatherResult;
    try {
      gather = await gatherSendLandingEvidence(candidate, deps);
    } catch (err) {
      deps.logger.error(`send-landing: op=${candidate.operationId} gather failed`, err);
      indeterminate += 1;
      continue;
    }

    switch (gather.kind) {
      case "WAITING": {
        // Genesis head — the SEND has not landed yet; leave the row AWAITING_REDEMPTION.
        indeterminate += 1;
        continue;
      }
      case "INDETERMINATE": {
        deps.logger.info(`send-landing: op=${candidate.operationId} INDETERMINATE: ${gather.detail}`);
        indeterminate += 1;
        continue;
      }
      case "PARK_ATTENTION": {
        try {
          const didPark = await parkSendOnHeadAnomaly(deps.pool, candidate.operationId, gather.reason);
          if (didPark) {
            parked += 1;
            deps.logger.info(
              `send-landing: op=${candidate.operationId} PARKED NEEDS_ATTENTION: ${gather.detail}`,
            );
          } else {
            indeterminate += 1;
          }
        } catch (err) {
          deps.logger.error(`send-landing: op=${candidate.operationId} park failed`, err);
          indeterminate += 1;
        }
        continue;
      }
      case "EVIDENCE": {
        const verdict: SendLandingVerdict = verifyExternalSendLanding(gather.evidence);

        if (verdict.kind !== "VERIFIED") {
          if (verdict.kind === "INDETERMINATE") {
            deps.logger.info(
              `send-landing: op=${candidate.operationId} not landed — INDETERMINATE/${verdict.reason}: ${verdict.detail} (no rebuild, no resubmit, lease untouched)`,
            );
          } else {
            deps.logger.info(
              `send-landing: op=${candidate.operationId} not landed — FAILED/${verdict.failedPredicate}: ${verdict.detail} (no rebuild, no resubmit, lease untouched)`,
            );
          }
          indeterminate += 1;
          continue;
        }

        let outcome: CommitExternalSendLandingOutcome;
        try {
          outcome = await commitExternalSendLanding(verdict, deps.store);
        } catch (err) {
          deps.logger.error(`send-landing: op=${candidate.operationId} commit failed`, err);
          indeterminate += 1;
          continue;
        }

        if (outcome.outcome === "APPLIED") {
          landed.push(candidate.operationId);
          deps.metricsHooks?.onOperationCompleted("SEND_EXTERNAL");
          deps.logger.info(
            `send-landing: op=${candidate.operationId} EXTERNAL_SEND_LANDED ` +
              `terminal_observation=${verdict.terminalObservationId} (source lease still held — releases on verification-complete)`,
          );
        } else {
          deps.logger.info(
            `send-landing: op=${candidate.operationId} commit ${outcome.outcome}/${outcome.reason}: ${outcome.detail}`,
          );
          indeterminate += 1;
        }
        continue;
      }
    }
  }

  return { landed, indeterminate, parked };
}
