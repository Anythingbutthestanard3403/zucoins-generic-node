// verification-material assembly surface.
// durable-table load + map into that surface.

export {
  ANCESTOR_CLASSIFICATIONS,
  EVIDENCE_ROLES,
  FORBIDDEN_MATERIAL_MARKERS,
  INDETERMINATE_REASONS,
  asVerificationMaterialFields,
  assembleVerificationMaterial,
  assessAncestorProofCompleteness,
  computePathManifestSha256,
  containsForbiddenMaterial,
  serializePathManifest,
  transactionBodySha256,
  type AncestorClassification,
  type AncestorProofInput,
  type AncestorProofMaterial,
  type AttemptMaterial,
  type AttemptTransactionMaterial,
  type EvidenceRole,
  type ExpectedArtifactMaterial,
  type IndeterminateReason,
  type ObservationEvidenceMaterial,
  type ObservationProjection,
  type PathManifestEntry,
  type StateProjection,
  type TransactionBodyMaterial,
  type VerificationMaterialInput,
  type VerificationMaterialPayload,
} from "./material.js";

export {
  assembleVerificationMaterialFromTables,
  createInMemoryVerificationMaterialTables,
  mapLineageBodiesToManifest,
  mapLineagePath,
  mapLineageVerdictToClassification,
  type AssembleFromTablesResult,
  type AssembledVerificationMaterial,
  type DurableAttemptRow,
  type DurableExpectedArtifactRow,
  type DurableLineageBodyRow,
  type DurableLineagePathRow,
  type DurableObservationEvidenceRow,
  type DurableObservationRow,
  type DurableOperationHeader,
  type InMemoryVerificationMaterialTables,
  type VerificationMaterialTablePort,
} from "./source.js";

export {
  classifyAttemptFromLandingFacts,
  createSqlVerificationMaterialTablePort,
  type SqlQueryFn as VerificationMaterialSqlQueryFn,
} from "./source-sql.js";
