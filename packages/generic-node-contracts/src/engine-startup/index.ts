// Concern barrel for the leader-gated engine-startup contract (the named concern). Public frozen surface
// for the concern-manifest registry assembly and the downstream the named concern (two-instance handoff proof) slice.
// This is NOT the package index (src/index.ts, the concern-manifest registry-owned) — it is the src/engine-startup
// concern's own export sequence. Consumes the named concern readiness predicates and vocabulary.

export * from "./engines.contract.ts";
export * from "./startup-sequence.contract.ts";
export * from "./split-brain.contract.ts";
export * from "./predicates.ts";
export * from "./verifiers.ts";
export { ENGINE_STARTUP_CONTRACT, ENGINE_STARTUP_CONCERN_MANIFEST } from "./manifest.ts";
