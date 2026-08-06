/**
 * The repository-wide construction census `compat-literals.contract.ts` itself does not carry:
 * freezes the CONSTRUCTION RULE for each retained-literal family as data — never as a second
 * implementation. Every rule here is a citation of the owning concern's byte contract
 * (`inventory.contract.ts`'s `machineFrozenAt` says who owns it); this module centralizes the
 * *rule text* so no edit can silently reserialize, re-derive, or emit an alias for a retained
 * literal without visibly contradicting a frozen row here.
 */
import { REPLACEMENT_POLICY_RULE, REPLACEMENT_POLICY_FORBIDDEN } from "./replacement-policy.ts";

export interface LiteralConstructionSite {
  readonly family: string;
  /** The frozen construction rule, quoted/paraphrased from its defining contract. */
  readonly rule: string;
  readonly appliesTo: readonly string[];
  readonly owningConcern: string;
  readonly sourceDocCitation: string;
}

export const LITERAL_CONSTRUCTION_SITES: readonly LiteralConstructionSite[] = [
  {
    family: "suite-signed-tuple (zp-*-v1 purposes)",
    rule:
      'preimage_text = purpose + "\\n" + JSON.stringify(payload_object); preimage_bytes = ' +
      "UTF8(preimage_text); digest = lowercase_hex(SHA256(preimage_bytes)); signature = " +
      "padded_base64url(Ed25519.sign(preimage_bytes, signing_key)). `purpose` appears twice by " +
      "design — once as the domain-separation prefix, once as payload field 1 — and a verifier " +
      "requires both copies to equal the expected literal before checking the signature.",
    appliesTo: [
      "zp-receive-expected-v1",
      "zp-move-internal-expected-v1",
      "zp-send-external-expected-v1",
      "zp-send-external-approval-v1",
      "zp-destination-bless-v1",
      "zp-device-enrol-v1",
      "zp-report-request-v1",
      "zp-node-event-v1",
      "zp-reporting-register-v1",
    ],
    owningConcern:
      "artifacts (three expected artifacts); " +
      "reporting-tuples (report-request, node-event); reporting-auth (reporting-register); " +
      "unassigned (approval, bless, device-enrol — see inventory.contract.ts gaps)",
    sourceDocCitation: "canonical suite-tuple serialization rule",
  },
  {
    family: "wallet-head semantic fingerprint (zp-wallet-head-fingerprint-v1)",
    rule:
      "Same suite serializer and SHA-256 digest as the signed-tuple family above, but the result " +
      "is NOT Ed25519-signed — it is a fingerprint used for equality comparison, never a signature.",
    appliesTo: ["zp-wallet-head-fingerprint-v1"],
    owningConcern: "unassigned (future proof concern)",
    sourceDocCitation: "wallet-head fingerprint rule",
  },
  {
    family: "SplitChain receive-message prefix (zp1:)",
    rule:
      '"zp1:" + discriminator + ":" + anchor. `discriminator` is the operation UUID (fixed width); ' +
      "`anchor` matches ^[A-Za-z0-9_-]{1,96}$. The fixed-width UUID and constrained anchor alphabet " +
      "make the split unambiguous. No whitespace or normalization is added.",
    appliesTo: ["zp1:"],
    owningConcern: "transfer-code (packages/generic-node-contracts/src/transfer-code)",
    sourceDocCitation: "receive-message construction rule",
  },
  {
    family: "transfer-code digest",
    rule:
      "transfer_code_sha256 = lowercase_hex(SHA256(UTF8(exact_transfer_code_string))). No newline, " +
      "URL-decode, base64-decode, padding repair, or JSON parse occurs before hashing.",
    appliesTo: [],
    owningConcern: "transfer-code (packages/generic-node-contracts/src/transfer-code)",
    sourceDocCitation: "transfer-code digest rule",
  },
  {
    family: "vault AAD (zp-wallet-secret-v1)",
    rule:
      'Exact UTF-8 associated data: "zp-wallet-secret-v1\\n" + node_id + "\\n" + wallet_id + "\\n" + ' +
      "key_version + \"\\n\" + public_key + \"\\n\" + key_origin. Decryption rejects any AAD " +
      "mismatch.",
    appliesTo: ["zp-wallet-secret-v1"],
    owningConcern: "vault (packages/generic-node-contracts/src/vault)",
    sourceDocCitation: "vault AAD rule",
  },
  {
    family: "reporting-request header set (X-ZP-Reporting-*)",
    rule:
      "Five mandatory headers map onto the zp-report-request-v1 signed tuple's fields; the " +
      "signature covers method, canonical path/query, request-body SHA-256, nonce, issued_at, and " +
      "expires_at. Key-Id is a registration SELECTOR, not itself a signed field.",
    appliesTo: [
      "X-ZP-Reporting-Key-Id",
      "X-ZP-Reporting-Timestamp",
      "X-ZP-Reporting-Expires-At",
      "X-ZP-Reporting-Nonce",
      "X-ZP-Reporting-Signature",
    ],
    owningConcern: "reporting-tuples (packages/generic-node-contracts/src/reporting-tuples)",
    sourceDocCitation: "reporting request-tuple rule",
  },
  {
    family: "legacy reporting-ingest signed domain prefixes + X-ZuPay-* transport headers",
    rule:
      "Pre-existing v1 platform-ingest push path: per-event, transport, and " +
      "handshake domain-separated Ed25519 signatures over their respective canonical strings. " +
      "Disjoint from and unchanged by the v2 generic-node reporting contract (explicit no-" +
      "repurpose) — v2 code must never fold these into or re-derive them from the new zp-*-v1 family.",
    appliesTo: [
      "zupay-reporting-v1",
      "zupay-reporting-transport-v1",
      "zupay-reporting-handshake-v1",
      "X-ZuPay-Node",
      "X-ZuPay-Timestamp",
      "X-ZuPay-Signature",
    ],
    owningConcern: "legacy v1 (apps/node/src/reporting/*, apps/platform/src/{nodes,server/ingest}/*)",
    sourceDocCitation: "legacy v1 ingest signatures (disjoint from v2 reporting)",
  },
  {
    family: "discovery/API route paths + package scope (zupay/zupayments names)",
    rule:
      "Established v1 route and npm-scope literals. The v2 generic core introduces net-new paths " +
      "and an entirely separate npm scope (@zucoins/*), so there is no collision and no rename to " +
      "perform — the legacy literal is retained unmodified because nothing requires it to change. " +
      "`/.well-known/zupay-node` is additionally re-frozen, unmodified, as a v2 public route by " +
      "the operations concern — the same literal path in two owning concerns by design, not a drift.",
    appliesTo: ["/.well-known/zupay-node", "/sdk/zupayments.js", "@zupayments/"],
    owningConcern:
      "legacy v1; /.well-known/zupay-node ALSO operations (" +
      "packages/generic-node-contracts/src/operations/routes.contract.ts PUBLIC_ROUTES)",
    sourceDocCitation: "retained v1 routes and package scope",
  },
] as const;

export { REPLACEMENT_POLICY_RULE, REPLACEMENT_POLICY_FORBIDDEN };
