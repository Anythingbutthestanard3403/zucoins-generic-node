import { CONCERN_REGISTRY } from "../registry.ts";
import { AUDIT_RESIDUALS, AUTOMATED_AXES } from "./audit-residuals.ts";
import { AXIS_DISPOSITIONS } from "./dispositions.ts";

/**
 * Cross-document contract-drift manifest — a frozen, in-package projection of three
 * already-committed registers (the package concern registry, the drift-audit residuals
 * ledger, and the foundational rule/freeze rows) into one shape a downstream freeze verdict
 * can read without re-deriving any of them. This module invents no disposition: every field
 * below traces to a committed source.
 */

export interface Disposition {
  readonly decisionLayer: "canonical" | "delegated" | "package-freeze";
  readonly decisionRefs: readonly string[];
  readonly driftAuditStatus: "automated-clean" | "residual-open";
  readonly sourceDoc: string;
  readonly note?: string;
}

export interface DriftItem {
  readonly item: string;
  readonly disposition: Disposition;
}

export interface RegisterItem {
  readonly id: string;
  readonly disposition: Disposition;
}

export interface ConcernRow {
  readonly concernDir: string;
  readonly concernId: string;
  readonly decisionRefs: readonly string[];
  readonly sourceDocCitations: readonly string[];
  readonly goldenRefs: readonly { readonly path: string; readonly sha256: string }[];
}

export interface ContractDriftManifest {
  readonly schemaVersion: string;
  readonly driftItems: readonly DriftItem[];
  readonly canonicalItems: readonly RegisterItem[];
  readonly blockerItems: readonly RegisterItem[];
  readonly concerns: readonly ConcernRow[];
}

const FOUNDATION_SOURCE_DOC = "foundational rule register";

/**
 * The 15 scope-line drift axes (as opposed to the 4 sub-split "deferred" pointers that
 * `AUTOMATED_AXES` entries name, and the separate cross-cutting
 * `provisional-manifest-migration` residual). All fifteen started in `AUDIT_RESIDUALS`; the
 * cross-document diffs were then automated one by one, so all fifteen now sit in
 * `AUTOMATED_AXES`. The mapping below asserts each axis's actual placement against the real
 * data rather than trusting this comment.
 */
export const SCOPE_LINE_AXES: readonly string[] = [
  "destination-label",
  "terminal-timestamps",
  "evidence-role-names",
  "proof-windows",
  "settled-body-phases",
  "idempotency-length",
  "discovery",
  "subscription-handles",
  "signer-audit",
  "callbacks",
  "pool-membership",
  "bearer-admin-storage",
  "totp-burns",
  "canonical-ledger",
  "candidate-intake",
];

/**
 * Each scope-line axis projects its disposition (`dispositions.ts`): the rules that govern
 * it, whether its cross-document diff is automated and clean, and the closure line.
 * `decisionLayer` stays `package-freeze` — it names *where* the disposition was recorded
 * (this package's freeze), not the layer of the rules it cites.
 *
 * The axis's own honesty-ledger placement is asserted here rather than assumed: a closed
 * axis must be in `AUTOMATED_AXES` and absent from `AUDIT_RESIDUALS`, and an open one the
 * reverse. That is what stops a status string in `dispositions.ts` from silently outranking
 * the residual ledger.
 */
const driftItems: readonly DriftItem[] = SCOPE_LINE_AXES.map((axis) => {
  const disposition = AXIS_DISPOSITIONS.find((entry) => entry.axis === axis);
  if (disposition === undefined) {
    throw new Error(`scope-line axis "${axis}" has no disposition`);
  }
  const closed = disposition.status === "CLOSED_AUTOMATED";
  const inAutomated = AUTOMATED_AXES.some((entry) => entry.axis === axis);
  const inResiduals = AUDIT_RESIDUALS.some((entry) => entry.axis === axis);
  if (closed !== inAutomated || closed === inResiduals) {
    throw new Error(
      `scope-line axis "${axis}" is ${disposition.status} but sits in the wrong honesty ledger`,
    );
  }
  return {
    item: axis,
    disposition: {
      decisionLayer: "package-freeze",
      decisionRefs: disposition.decisionRefs,
      driftAuditStatus: closed ? "automated-clean" : "residual-open",
      sourceDoc: disposition.docCitations.join("; "),
      note:
        disposition.escalation === undefined
          ? disposition.closure
          : `${disposition.closure} Escalated as ${disposition.escalation}.`,
    },
  };
});

/** The nine canonical foundational rules, in their fixed sequence. */
const CANONICAL_RULES: readonly { readonly id: string; readonly note?: string }[] = [
  { id: "three-generic-operations" },
  { id: "expected-artifact-surfaces-freeze" },
  { id: "custody-and-sink-eligibility-rule" },
  { id: "launch-capability-deferral" },
  { id: "observation-dedup" },
  {
    id: "complete-path-adjudication",
    note: "The narrower tx16 single-direct-successor linkage remains open/deferred per the operation-flows spec.",
  },
  { id: "operator-approval-surface-rule" },
  { id: "single-approval-single-sign-rule" },
  { id: "compatibility-literals" },
];

const canonicalItems: readonly RegisterItem[] = CANONICAL_RULES.map(({ id, note }) => ({
  id,
  disposition: {
    decisionLayer: "canonical",
    decisionRefs: [id],
    driftAuditStatus: "residual-open",
    sourceDoc: FOUNDATION_SOURCE_DOC,
    ...(note === undefined ? {} : { note }),
  },
}));

const DELEGATED_RULE_NOTE =
  "Supersedable delegated rule — issued under a standing delegation, not first-party canonical law.";

/** The eight delegated foundational contract freezes, in their fixed sequence. */
const DELEGATED_FREEZES: readonly { readonly id: string; readonly refs: readonly string[] }[] = [
  { id: "amount-contract", refs: ["zkz-amount-grammar"] },
  { id: "vault-contract", refs: ["vault-storage-model"] },
  {
    id: "reporting-credential",
    refs: [
      "reporting-channel",
      "reporting-key-enrolment",
      "bootstrap-enrolment-trust-root",
    ],
  },
  { id: "receive-pool", refs: ["receive-pool-sizing-freeze"] },
  { id: "send-expiry", refs: ["send-expiry-single-source-rule"] },
  { id: "receive-expiry", refs: ["receive-expiry-prevention-rule"] },
  { id: "no-callback", refs: ["no-network-egress"] },
  { id: "recovery-gate", refs: ["recovery-gate-rule"] },
];

const blockerItems: readonly RegisterItem[] = DELEGATED_FREEZES.map(({ id, refs }) => ({
  id,
  disposition: {
    decisionLayer: "delegated",
    decisionRefs: refs,
    driftAuditStatus: "residual-open",
    sourceDoc: FOUNDATION_SOURCE_DOC,
    note: DELEGATED_RULE_NOTE,
  },
}));

/** Verbatim projection of the package concern registry, in registry sequence. */
const concerns: readonly ConcernRow[] = CONCERN_REGISTRY.map((registered) => ({
  concernDir: registered.concernDir,
  concernId: registered.manifest.concernId,
  decisionRefs: registered.manifest.decisionRefs,
  sourceDocCitations: registered.manifest.sourceDocCitations,
  goldenRefs: registered.manifest.goldenRefs.map((ref) => ({
    path: ref.path,
    sha256: ref.sha256,
  })),
}));

export const CONTRACT_DRIFT_MANIFEST: ContractDriftManifest = {
  schemaVersion: "contract-drift-manifest/1",
  driftItems,
  canonicalItems,
  blockerItems,
  concerns,
};
