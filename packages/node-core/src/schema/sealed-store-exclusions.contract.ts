/**
 * Secret classes the generic node deliberately does not seal.
 *
 * The reporting private key is implementer-side: the node stores the public key only. The
 * generic node exposes no node-initiated callback or webhook surface, so it holds no
 * webhook signing secret to seal. The wallet-vault AAD and HKDF-info binding conditions
 * name cross-store HKDF labels as a *principle*, illustrated with v1 examples -- not as a
 * requirement that the v2 generic node hold those stores. A webhook signing secret
 * encrypted at rest is a product-layer concern on the v1 node path.
 *
 * Residual: the HKDF-label binding condition names "webhook secret encrypted at rest" among
 * root-sharing stores that need a unique HKDF label, and the v1 node seals webhook /
 * reporting-signing / push-receiver material under VAULT_MASTER_KEY. Push delivery and
 * destination binding add the product-neutral receive-crypto primitive to node-core, so
 * PUSH_RECEIVER_SECRETS is admitted to the registry and rotation path; this exclusion set
 * retains only the classes the generic node still does not hold:
 *
 * - REPORTING_PRIVATE_KEY -- implementer-side private store; the node holds the public key
 *   only and uses it for registration and request auth, never a node-side sealed reporting
 *   private key.
 * - WEBHOOK_SIGNING_SECRET -- the generic node has no node-initiated callback or webhook
 *   surface. Webhooks stay a product-layer projection (v1 product scope; HMAC-SHA256 signed
 *   webhooks; webhook secret encrypted at rest) on the v1 platform path, censused there
 *   rather than by the v2 generic-node register.
 *
 * This file is the closed admission gate for those two classes. They MUST NOT be
 * added to a future v2 `SEALED_STORES` / `REGISTERED_SEAL_SITES` set while
 * their disposition remains EXCLUDED_BY_CANON. If the no-callback rule is reversed (or a
 * reporting private key is put on the node), flip the disposition here and
 * register the new seal site in the same change -- the census below will fail closed
 * the moment a `createCipheriv` site appears under a marker path without admission.
 */

/** Secret classes the generic node still does not seal. */
export type NonNodeSealedSecretClass =
  | "REPORTING_PRIVATE_KEY"
  | "WEBHOOK_SIGNING_SECRET";

/**
 * Why the class is absent from the v2 SEALED_STORES set.
 * EXCLUDED_BY_CANON is permanent under current decisions; a future reversal
 * would re-open admission (and require a seal-site registration in the same PR).
 */
export type NonNodeSealedDisposition = "EXCLUDED_BY_CANON";

export interface NonNodeSealedSecretDescriptor {
  readonly id: NonNodeSealedSecretClass;
  readonly disposition: NonNodeSealedDisposition;
  /** Why the exclusion holds, in one line. */
  readonly authority: string;
  /**
   * Path substrings that would indicate a seal site for this class if a module under
   * `packages/**` began calling `createCipheriv`/`createDecipheriv`. Matched against
   * repo-relative paths from the structural seal-site scan. Case-sensitive path
   * segments only — never prose or identifier tokens in unrelated modules.
   */
  readonly sealSitePathMarkers: readonly string[];
  /**
   * Reconciles the vault HKDF-label binding condition's mention of the class (or its
   * nearest sibling) with the v2 generic-node store set: the condition is a *shared-root
   * HKDF label uniqueness* rule for stores the node *does* seal, illustrated with
   * v1 examples — not a mandate that every v1 store reappear in v2.
   */
  readonly sharedRootHkdfReconciliation: string;
  readonly note: string;
}

/**
 * Closed set. The sequence is stable for census snapshots: reporting → webhook → push
 * (mirrors the v1 rotate-master-key-stores cost sequence, not a rotation claim).
 */
export const NON_NODE_SEALED_SECRETS: readonly NonNodeSealedSecretDescriptor[] = [
  {
    id: "REPORTING_PRIVATE_KEY",
    disposition: "EXCLUDED_BY_CANON",
    authority:
      "signing custody: the reporting key is an implementer-side private store and the " +
      "node holds only the public key; reporting is a signed pull stream with public-key " +
      "enrolment, and registration plus signed-request auth are public-key only",
    sealSitePathMarkers: [
      "reporting-signing-key",
      "reporting_signing_key",
      "reporting-key-store",
      "reporting_key_store",
      "reporting-private",
      "reporting_private",
    ],
    sharedRootHkdfReconciliation:
      "The HKDF-label binding condition enumerates stores that share the VAULT_MASTER_KEY " +
      "root *when present*. The v2 reporting private key is not node-resident, so it " +
      "shares no root and needs no HKDF label in the generic-node sealed-store census.",
    note:
      "Node holds implementer_reporting_keys public rows only. A sealed reporting " +
      "private key on the node would reverse the key inventory and the custody scope " +
      "that the key-custody rule rests on; do not invent one to clear a census.",
  },
  {
    id: "WEBHOOK_SIGNING_SECRET",
    disposition: "EXCLUDED_BY_CANON",
    authority:
      "the generic node exposes no node-initiated callback or webhook surface; webhooks " +
      "are a product-layer concern on the v1 platform path; the signed pull stream is the " +
      "sole authoritative reporting channel",
    sealSitePathMarkers: [
      "webhook/secret",
      "webhooks/secret",
      "webhook_endpoints",
      "webhook-secret",
      "webhook_secret",
    ],
    sharedRootHkdfReconciliation:
      "The binding condition cites the webhook secret as a *v1* root-sharing example that " +
      "needs its own HKDF label. The generic node has no such store; the product-layer v1 " +
      "census still covers the platform's webhook_endpoints.secret_ciphertext. No v2 " +
      "SEALED_STORES entry.",
    note:
      "Generic-node index.ts already documents the outbox/callback absence. " +
      "A new packages/** webhook seal site would reopen the reporting-auth and SSRF " +
      "surface and must not land under an EXCLUDED_BY_CANON disposition.",
  },
] as const;

export const NON_NODE_SEALED_SECRET_IDS: readonly NonNodeSealedSecretClass[] =
  NON_NODE_SEALED_SECRETS.map((entry) => entry.id);

export const SEALED_STORE_EXCLUSIONS_SOURCE =
  "signing-custody: key inventory; no node-initiated callback surface; vault HKDF-label reconciliation; product-layer webhooks; sealed-store census residual" as const;

/**
 * Admission check for a candidate SEALED_STORES id (or a path that would become a
 * seal site). EXCLUDED_BY_CANON classes always refuse. Used by the census and by
 * any future register so an accidental add cannot ship silently.
 */
export function admitNonNodeSealedSecret(
  id: string,
): { readonly admitted: false; readonly reason: string } | { readonly admitted: true } {
  const entry = NON_NODE_SEALED_SECRETS.find((row) => row.id === id);
  if (entry === undefined) {
    return { admitted: true };
  }
  return {
    admitted: false,
    reason:
      `${entry.id} is ${entry.disposition} (${entry.authority.split(";")[0]?.trim() ?? entry.authority})`,
  };
}

/**
 * Pure: which excluded classes have a structural seal-site hit under `foundPaths`?
 * A non-empty result means a `createCipheriv`/`createDecipheriv` module appeared
 * under a marker path while the class is still EXCLUDED_BY_CANON — fail closed
 * until disposition flips and the site is registered in SEALED_STORES.
 */
export function excludedSealSiteHits(
  foundPaths: readonly string[],
): readonly { readonly id: NonNodeSealedSecretClass; readonly path: string; readonly marker: string }[] {
  const hits: { id: NonNodeSealedSecretClass; path: string; marker: string }[] = [];
  for (const entry of NON_NODE_SEALED_SECRETS) {
    for (const path of foundPaths) {
      for (const marker of entry.sealSitePathMarkers) {
        if (path.includes(marker)) {
          hits.push({ id: entry.id, path, marker });
        }
      }
    }
  }
  return hits;
}
