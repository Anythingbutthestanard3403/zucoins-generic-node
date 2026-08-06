// SQL adapter for VerificationMaterialTablePort.
//
// Driver-free: statements go through an injected SqlQueryFn (same pattern as
// core/transaction-material-store.ts). Byte columns (raw_response_bytes) cross
// the seam as base64 text via encode(..., 'base64') so no driver-specific Buffer
// handling is required at this layer.
//
// Cross-tenant collapse: loadOperation filters on implementer_id.

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

// Local SqlQueryFn — observation cannot import core/ (boundary: protocol only).
export type SqlQueryFn = (
  sql: string,
  params?: readonly unknown[],
) => Promise<ReadonlyArray<Record<string, unknown>>>;
import type {
  DurableAttemptRow,
  DurableExpectedArtifactRow,
  DurableLineageBodyRow,
  DurableLineagePathRow,
  DurableObservationEvidenceRow,
  DurableObservationRow,
  DurableOperationHeader,
  VerificationMaterialTablePort,
} from "./source.js";
import type { EvidenceRole } from "./material.js";

const ISO_MS = `(extract(epoch FROM verification_material_available_until) * 1000)::bigint`;

const OP_SELECT = `
  SELECT id::text AS id,
         implementer_id::text AS implementer_id,
         kind::text AS kind,
         status::text AS status,
         ${ISO_MS} AS verification_material_available_until_ms,
         (
           SELECT olp.expected_transaction_attempt_no
           FROM operation_landing_proofs olp
           WHERE olp.operation_id = o.id
             AND olp.verdict IN ('LANDED_EXACT', 'LANDED_COMPLETE_PATH')
           ORDER BY olp.created_at DESC -- contract-allow:order:frozen-sql-text
           LIMIT 1
         ) AS landed_attempt_no
  FROM operations o
  WHERE o.id = $1::uuid AND o.implementer_id = $2::uuid
`;

const ARTIFACT_SELECT = `
  SELECT signing_key_id::text AS signing_key_id,
         preimage_text,
         preimage_sha256,
         signature
  FROM operation_expected_artifacts
  WHERE operation_id = $1::uuid
`;

// Attempt recovery classification is NEVER derived from attempt_phase alone.
// attempt_phase is internal persistence state; LANDED_VERIFIED requires a
// durable landing oracle fact — operation_landing_proofs with LANDED_EXACT /
// LANDED_COMPLETE_PATH for that attempt (landing-path oracle). Settled body persistence alone is
// not landing verification.
const ATTEMPTS_SELECT = `
  SELECT ot.attempt_no,
         ot.inner_preimage_text,
         ot.inner_sha256,
         ot.step_1_signature,
         ot.step_2_preimage_text,
         ot.step_2_signature,
         ot.completed_transaction_text,
         (
           SELECT olp.verdict::text
           FROM operation_landing_proofs olp
           WHERE olp.operation_id = ot.operation_id
             AND olp.expected_transaction_attempt_no = ot.attempt_no
             AND olp.verdict IN ('LANDED_EXACT', 'LANDED_COMPLETE_PATH')
           ORDER BY olp.created_at DESC -- contract-allow:order:frozen-sql-text
           LIMIT 1
         ) AS landing_proof_verdict
  FROM operation_transactions ot
  WHERE ot.operation_id = $1::uuid
  ORDER BY ot.attempt_no ASC -- contract-allow:order:frozen-sql-text
`;

// Lineage paths joined through the landing proof for this operation.
const PATHS_SELECT = `
  SELECT lpp.id::text AS path_id,
         lpp.path_role,
         lpp.wallet_public_key,
         lpp.verdict::text AS verdict,
         lpp.fresh_head_completed_transaction_sha256,
         -- expected step_2 from body 0; fresh head step_2 from last body
         (
           SELECT b0.step_2_signature FROM lineage_path_bodies b0
           WHERE b0.path_proof_id = lpp.id AND b0.path_index = 0
         ) AS expected_step_2_signature,
         (
           SELECT bl.step_2_signature FROM lineage_path_bodies bl
           WHERE bl.path_proof_id = lpp.id
           ORDER BY bl.path_index DESC LIMIT 1 -- contract-allow:order:frozen-sql-text
         ) AS fresh_head_step_2_signature
  FROM lineage_path_proofs lpp
  INNER JOIN operation_landing_proofs olp ON olp.id = lpp.landing_proof_id
  WHERE olp.operation_id = $1::uuid
  ORDER BY lpp.path_role ASC -- contract-allow:order:frozen-sql-text
`;

const BODIES_SELECT = `
  SELECT path_index,
         step_2_signature,
         p_signature,
         completed_transaction_sha256,
         completed_transaction_text
  FROM lineage_path_bodies
  WHERE path_proof_id = $1::uuid
  ORDER BY path_index ASC -- contract-allow:order:frozen-sql-text
`;

// Observation loaders per kind. Move uses move_observation_evidence; receive/send use
// operation_observation_bindings roles.
const MOVE_EVIDENCE_SELECT = `
  SELECT source_t0_observation_id::text AS source_t0,
         destination_t0_observation_id::text AS dest_t0,
         source_terminal_observation_id::text AS source_term,
         destination_terminal_observation_id::text AS dest_term
  FROM move_observation_evidence
  WHERE operation_id = $1::uuid
`;

const OBS_SELECT = `
  SELECT id::text AS id,
         wallet_id::text AS wallet_id,
         wallet_public_key,
         COALESCE(s_signature, '') AS s_signature,
         COALESCE(p_signature, '') AS p_signature,
         COALESCE(b_amount, '0') AS b_amount,
         encode(raw_response_bytes, 'base64') AS raw_response_body_base64
  FROM gateway_observations
  WHERE id = $1::uuid
`;

const BINDINGS_SELECT = `
  SELECT evidence_role,
         observation_id::text AS observation_id,
         wallet_public_key
  FROM operation_observation_bindings
  WHERE operation_id = $1::uuid
`;

/**
 * Map durable attempt + landing-proof facts → recovery classification for.1
 * `attempts[].classification`.
 *
 * Rules (DurableAttemptRow contract):
 * - `LANDED_VERIFIED` only when a complete-path landing proof exists for this attempt.
 * - Never map `attempt_phase = SETTLED_BODY_PERSISTED` (or settled body text) alone to
 * `LANDED_VERIFIED` — settled body is not the landing oracle.
 * No generic `PROVEN_NOT_LANDED` inference (landing-path oracle).
 * - Signer boundary never crossed → `PROVEN_NOT_STARTED`; otherwise fail closed to
 * `INDETERMINATE` until a determinate recovery/landing writer stores a fact.
 */
export function classifyAttemptFromLandingFacts(facts: {
  readonly landing_proof_verdict: string | null;
  readonly step_1_signature: string | null;
}): string {
  const verdict = facts.landing_proof_verdict;
  if (verdict === "LANDED_EXACT" || verdict === "LANDED_COMPLETE_PATH") {
    return "LANDED_VERIFIED";
  }
  const step1 = facts.step_1_signature;
  if (step1 === null || step1 === undefined || step1.length === 0) {
    return "PROVEN_NOT_STARTED";
  }
  return "INDETERMINATE";
}

function asString(v: unknown, fallback = ""): string {
  if (v === null || v === undefined) return fallback;
  return String(v);
}

function asNumberOrNull(v: unknown): number | null {
  if (v === null || v === undefined) return null;
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : null;
}

function asKind(v: unknown): OperationKind {
  const s = String(v);
  if (s === "RECEIVE_EXTERNAL" || s === "MOVE_INTERNAL" || s === "SEND_EXTERNAL") {
    return s;
  }
  throw new Error(`unexpected operation kind: ${s}`);
}

async function loadObservation(
  query: SqlQueryFn,
  id: string | null,
): Promise<DurableObservationRow | null> {
  if (id === null || id.length === 0) return null;
  const rows = await query(OBS_SELECT, [id]);
  const row = rows[0];
  if (row === undefined) return null;
  return {
    id: asString(row.id),
    wallet_id: row.wallet_id === null || row.wallet_id === undefined ? null : asString(row.wallet_id),
    wallet_public_key: asString(row.wallet_public_key),
    s_signature: asString(row.s_signature),
    p_signature: asString(row.p_signature),
    b_amount: asString(row.b_amount, "0"),
    raw_response_body_base64: asString(row.raw_response_body_base64),
  };
}

/**
 * Map operation_observation_bindings evidence_role pairs into evidence_role
 * groups (RECEIVER / SOURCE / DESTINATION). Formation-only EXTERNAL_* roles are not
 * stored on the bindings table — they come from dedicated send preflight rows when
 * present; this adapter surfaces only the three path roles from bindings.
 */
function bindingRoleToEvidenceRole(
  role: string,
): { group: "RECEIVER" | "SOURCE" | "DESTINATION"; half: "t0" | "terminal" } | null {
  switch (role) {
    case "RECEIVER_T0":
      return { group: "RECEIVER", half: "t0" };
    case "RECEIVER_TERMINAL":
      return { group: "RECEIVER", half: "terminal" };
    case "SOURCE_T0":
      return { group: "SOURCE", half: "t0" };
    case "SOURCE_TERMINAL":
      return { group: "SOURCE", half: "terminal" };
    case "DESTINATION_T0":
      return { group: "DESTINATION", half: "t0" };
    case "DESTINATION_TERMINAL":
      return { group: "DESTINATION", half: "terminal" };
    default:
      return null;
  }
}

export function createSqlVerificationMaterialTablePort(
  query: SqlQueryFn,
  options: {
    readonly loadProofBodies?: (pathProofId: string) => Promise<readonly DurableLineageBodyRow[]>;
  } = {},
): VerificationMaterialTablePort {
  return {
    async loadOperation(operationId, implementerId) {
      const rows = await query(OP_SELECT, [operationId, implementerId]);
      const row = rows[0];
      if (row === undefined) return null;
      return {
        id: asString(row.id),
        implementer_id: asString(row.implementer_id),
        kind: asKind(row.kind),
        status: asString(row.status),
        verification_material_available_until_ms: asNumberOrNull(
          row.verification_material_available_until_ms,
        ),
        landed_attempt_no: asNumberOrNull(row.landed_attempt_no),
      } satisfies DurableOperationHeader;
    },

    async loadExpectedArtifact(operationId) {
      const rows = await query(ARTIFACT_SELECT, [operationId]);
      const row = rows[0];
      if (row === undefined) return null;
      return {
        signing_key_id: asString(row.signing_key_id),
        preimage_text: asString(row.preimage_text),
        preimage_sha256: asString(row.preimage_sha256),
        signature: asString(row.signature),
      } satisfies DurableExpectedArtifactRow;
    },

    async loadAttempts(operationId) {
      const rows = await query(ATTEMPTS_SELECT, [operationId]);
      return rows.map((row): DurableAttemptRow => {
        const step1Raw =
          row.step_1_signature === null || row.step_1_signature === undefined
            ? null
            : asString(row.step_1_signature);
        const landingVerdict =
          row.landing_proof_verdict === null || row.landing_proof_verdict === undefined
            ? null
            : asString(row.landing_proof_verdict);
        return {
          attempt_no: Number(row.attempt_no),
          classification: classifyAttemptFromLandingFacts({
            landing_proof_verdict: landingVerdict === "" ? null : landingVerdict,
            step_1_signature: step1Raw === "" ? null : step1Raw,
          }),
          inner_preimage_text: asString(row.inner_preimage_text),
          inner_sha256: asString(row.inner_sha256),
          step_1_signature: step1Raw ?? "",
          step_2_preimage_text: asString(row.step_2_preimage_text),
          step_2_signature: asString(row.step_2_signature),
          settled_transaction_text: asString(row.completed_transaction_text),
        };
      });
    },

    async loadAncestorPaths(operationId) {
      const pathRows = await query(PATHS_SELECT, [operationId]);
      const out: DurableLineagePathRow[] = [];
      for (const prow of pathRows) {
        const pathId = asString(prow.path_id);
        const bodies: readonly DurableLineageBodyRow[] = options.loadProofBodies === undefined
          ? (await query(BODIES_SELECT, [pathId])).map((b) => ({
              path_index: Number(b.path_index),
              step_2_signature: asString(b.step_2_signature),
              p_signature: asString(b.p_signature),
              completed_transaction_sha256: asString(b.completed_transaction_sha256),
              completed_transaction_text: asString(b.completed_transaction_text),
            }))
          : await options.loadProofBodies(pathId);
        const role = asString(prow.path_role);
        if (role !== "RECEIVER" && role !== "SOURCE" && role !== "DESTINATION") {
          continue;
        }
        out.push({
          path_role: role,
          wallet_public_key: asString(prow.wallet_public_key),
          verdict: asString(prow.verdict),
          expected_step_2_signature: asString(prow.expected_step_2_signature),
          fresh_head_step_2_signature: asString(prow.fresh_head_step_2_signature),
          fresh_head_transaction_sha256: asString(prow.fresh_head_completed_transaction_sha256),
          bodies,
          indeterminate_reason: null,
        });
      }
      return out;
    },

    async loadObservationEvidence(operationId, kind) {
      if (kind === "MOVE_INTERNAL") {
        return loadMoveObservationEvidence(query, operationId);
      }
      return loadBoundObservationEvidence(query, operationId);
    },
  };
}

async function loadMoveObservationEvidence(
  query: SqlQueryFn,
  operationId: string,
): Promise<readonly DurableObservationEvidenceRow[]> {
  const rows = await query(MOVE_EVIDENCE_SELECT, [operationId]);
  const row = rows[0];
  if (row === undefined) return [];

  const sourceT0 = await loadObservation(query, asString(row.source_t0) || null);
  const destT0 = await loadObservation(query, asString(row.dest_t0) || null);
  const sourceTerm = await loadObservation(query, asString(row.source_term) || null);
  const destTerm = await loadObservation(query, asString(row.dest_term) || null);

  const out: DurableObservationEvidenceRow[] = [];
  if (sourceT0 !== null) {
    out.push({
      evidence_role: "SOURCE",
      wallet_id: sourceT0.wallet_id,
      wallet_public_key: sourceT0.wallet_public_key,
      t0: sourceT0,
      terminal: sourceTerm,
    });
  }
  if (destT0 !== null) {
    out.push({
      evidence_role: "DESTINATION",
      wallet_id: destT0.wallet_id,
      wallet_public_key: destT0.wallet_public_key,
      t0: destT0,
      terminal: destTerm,
    });
  }
  return out;
}

async function loadBoundObservationEvidence(
  query: SqlQueryFn,
  operationId: string,
): Promise<readonly DurableObservationEvidenceRow[]> {
  const bindings = await query(BINDINGS_SELECT, [operationId]);
  type Acc = {
    role: EvidenceRole;
    wallet_public_key: string;
    t0Id: string | null;
    terminalId: string | null;
  };
  const groups = new Map<string, Acc>();

  for (const b of bindings) {
    const mapped = bindingRoleToEvidenceRole(asString(b.evidence_role));
    if (mapped === null) continue;
    let acc = groups.get(mapped.group);
    if (acc === undefined) {
      acc = {
        role: mapped.group,
        wallet_public_key: asString(b.wallet_public_key),
        t0Id: null,
        terminalId: null,
      };
      groups.set(mapped.group, acc);
    }
    if (mapped.half === "t0") acc.t0Id = asString(b.observation_id);
    else acc.terminalId = asString(b.observation_id);
  }

  const out: DurableObservationEvidenceRow[] = [];
  for (const acc of groups.values()) {
    if (acc.t0Id === null) continue;
    const t0 = await loadObservation(query, acc.t0Id);
    if (t0 === null) continue;
    const terminal =
      acc.terminalId === null ? null : await loadObservation(query, acc.terminalId);
    out.push({
      evidence_role: acc.role,
      wallet_id: t0.wallet_id,
      wallet_public_key: acc.wallet_public_key || t0.wallet_public_key,
      t0,
      terminal,
    });
  }
  return out;
}
