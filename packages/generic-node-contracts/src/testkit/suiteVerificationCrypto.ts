/**
 * : the DEFAULT suite verification crypto wired for injection into the DI'd contract
 * verifiers (`artifacts/verify.ts` `verifyExpectedArtifact`, `approval/verify.ts`
 * `verifyApprovalDeviceSignature`). It is built ENTIRELY from `independentCrypto.ts`, i.e. from the
 * exact `libsodium-wrappers` family the wallet/splitchain uses — so the injected Ed25519 accept-set
 * (canonical-S enforcement, small-subgroup/torsion rejection, non-canonical point rejection) and the
 * SHA-256 digest are byte/semantics identical to the frozen Appendix A goldens. Injecting anything
 * more permissive than libsodium would be caught by `artifacts/ed25519-accept-set.test.ts`.
 *
 * This lives in `testkit/` (never shipped to a runtime): the artifacts/approval verification island
 * has no runtime consumer today (node-core imports none of these symbols), so tests are the only
 * caller. A future runtime consumer wires its OWN libsodium-family implementation of the same
 * per-concern callback interface; nothing in a frozen contract module imports this default.
 */
import { ready, digestPreimage, decodeBase64Url, verifyPreimageSignature } from "./independentCrypto.ts";

/**
 * Structurally satisfies both `ArtifactVerificationCrypto` (artifacts/verify.ts) and
 * `ApprovalDeviceVerificationCrypto` (approval/verify.ts) — the interfaces are declared in-package
 * by each concern (never in node-core), so this default is injected by the caller and inverts no
 * dependency. `verifyPreimageSignature` decodes both the signature and the public key with the same
 * padded-URL-safe base64 the wallet uses and can throw on malformed base64 EXACTLY where the prior
 * direct calls did, preserving each caller's own throw/try-catch behaviour.
 */
export const defaultSuiteVerificationCrypto = {
  ready,
  digestPreimage,
  verifyPreimageSignature: (input: {
    readonly preimageText: string;
    readonly signatureB64Url: string;
    readonly publicKeyB64Url: string;
  }): boolean =>
    verifyPreimageSignature(input.preimageText, input.signatureB64Url, decodeBase64Url(input.publicKeyB64Url)),
} as const;
