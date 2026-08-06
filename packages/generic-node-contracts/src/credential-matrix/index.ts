// the auth-errors/route-policy concern.3 — Public surface of the credential-matrix concern. Concern-local barrel owned by the
// the auth-errors/route-policy concern.3 slice; NOT the package index (src/index.ts, owned by the concern-manifest registry).

export {
  type MatrixCell,
  MATRIX_STATES,
  STATE_DIMENSION,
  STATE_RESOLVING_STAGE,
  MATRIX_AUTH_CLASSES,
  REPRESENTATIVE_ROUTES,
  buildCredentialMatrix,
  renderCellResponse,
} from "./matrix.js";

export {
  type CredentialMatrixManifest,
  credentialMatrixConcernManifest,
  buildCredentialMatrixManifest,
} from "./manifest.js";
