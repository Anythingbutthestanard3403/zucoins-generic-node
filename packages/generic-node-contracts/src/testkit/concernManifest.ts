/**
 * the concern-manifest registry leave-behind shape (../../CONTRACT.md "ConcernManifest schema (the concern-manifest registry
 * leave-behind)"): every concern directory self-registers one of these so the eventual
 * registry assembly (the concern-manifest registry) can iterate, count, and verify disposition without archaeology.
 */
export interface ConcernManifest {
  readonly concernId: string;
  readonly decisionRefs: readonly string[];
  readonly frozenValues: Readonly<Record<string, unknown>>;
  readonly goldenRefs: readonly { readonly path: string; readonly sha256: string }[];
  readonly scanRules: readonly string[];
  readonly sourceDocCitations: readonly string[];
}

export const defineConcernManifest = (manifest: ConcernManifest): ConcernManifest => manifest;
