// Concern barrel for the two-instance handoff proof matrix (the named concern). Public frozen surface for
// the concern-manifest registry assembly. This is NOT the package index (src/index.ts, the concern-manifest registry-owned) — it is
// the src/handoff-proof/ concern's own export sequence. Drives the named concern readiness predicates
// and the named concern takeover verifier; the group's final slice.

export * from "./scenario-matrix.contract.ts";
export * from "./proof.ts";
export { HANDOFF_PROOF_CONTRACT, HANDOFF_PROOF_CONCERN_MANIFEST } from "./manifest.ts";
