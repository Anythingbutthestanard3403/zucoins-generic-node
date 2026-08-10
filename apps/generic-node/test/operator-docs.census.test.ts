// Operator-documentation census (ZTR-1131).
//
// Converts "the docs rotted" into a test failure:
//
//   * every SAFETY_ALERT_SIGNALS entry has an incident section and an alert-reference
//     section, and an explicit statement of whether its reading is actually fed;
//   * every ATTENTION_REASONS value has a triage section;
//   * the two generated documents still match a fresh render from safety-alerts.ts, so
//     a hand edit to either markdown file fails rather than silently diverging;
//   * the committed Prometheus rules load as YAML, only use severities and signal ids that
//     exist, and cover every signal whose reading is live.
//
// The renderers come from scripts/gen-operator-alert-docs.mjs, which takes the module
// namespace as an argument and imports nothing itself. The generator CLI renders from
// packages/node-core/dist; this test renders from TypeScript source through the vitest
// alias. Both must produce the committed bytes.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import yaml from "js-yaml";
import { describe, expect, it } from "vitest";

import * as nodeCore from "@zucoins/node-core";
import { ATTENTION_REASONS } from "@zucoins/generic-node-contracts/api-schema";

import {
  ALERT_REFERENCE_PATH,
  ESCALATION_MATRIX_PATH,
  SIGNAL_WIRING,
  renderAlertReference,
  renderEscalationMatrix,
} from "../../../scripts/gen-operator-alert-docs.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

const OPERATOR_DOCS = {
  readme: "docs/operations/README.md",
  restore: "docs/operations/restore.md",
  incidents: "docs/operations/incidents.md",
  triage: "docs/operations/attention-triage.md",
  ceremony: "docs/operations/recovery-ceremony.md",
  alertReference: ALERT_REFERENCE_PATH,
  escalationMatrix: ESCALATION_MATRIX_PATH,
  rules: "docs/operations/alerts/generic-node.rules.yml",
} as const;

function read(relPath: string): string {
  return readFileSync(resolve(repoRoot, relPath), "utf8");
}

/** `## <heading>` at the start of a line, exact match on the rest of the line. */
function hasSection(markdown: string, heading: string): boolean {
  return new RegExp(`^## ${heading}\\s*$`, "m").test(markdown);
}

describe("operator documentation set", () => {
  it("every document named by ZTR-1131 exists and is non-trivial", () => {
    for (const [name, relPath] of Object.entries(OPERATOR_DOCS)) {
      const body = read(relPath);
      expect(body.length, `${name} (${relPath}) is empty`).toBeGreaterThan(500);
    }
  });
});

describe("SAFETY_ALERT_SIGNALS census", () => {
  const incidents = read(OPERATOR_DOCS.incidents);
  const alertReference = read(OPERATOR_DOCS.alertReference);

  it.each([...nodeCore.SAFETY_ALERT_SIGNALS])(
    "%s has an incident section and an alert-reference section",
    (signal) => {
      expect(hasSection(incidents, signal), `${OPERATOR_DOCS.incidents} lacks "## ${signal}"`).toBe(
        true,
      );
      expect(
        hasSection(alertReference, signal),
        `${OPERATOR_DOCS.alertReference} lacks "## ${signal}"`,
      ).toBe(true);
    },
  );

  it("every signal states whether its reading is actually fed", () => {
    // A new rule cannot ship without an explicit bound/unbound statement: documenting a
    // threshold for an alert that can never fire is worse than documenting nothing.
    expect(Object.keys(SIGNAL_WIRING).sort()).toEqual([...nodeCore.SAFETY_ALERT_SIGNALS].sort());
  });

  it("the rule catalogue and the signal list agree", () => {
    expect(nodeCore.SAFETY_ALERT_RULES.map((rule) => rule.signal)).toEqual([
      ...nodeCore.SAFETY_ALERT_SIGNALS,
    ]);
  });
});

describe("ATTENTION_REASONS census", () => {
  const triage = read(OPERATOR_DOCS.triage);

  it.each([...ATTENTION_REASONS])("%s has a triage section", (reason) => {
    expect(hasSection(triage, reason), `${OPERATOR_DOCS.triage} lacks "## ${reason}"`).toBe(true);
  });
});

describe("generated documents", () => {
  it("alert-reference.md matches a fresh render from safety-alerts.ts", () => {
    expect(read(OPERATOR_DOCS.alertReference)).toBe(renderAlertReference(nodeCore));
  });

  it("escalation-matrix.md matches a fresh render from safety-alerts.ts", () => {
    expect(read(OPERATOR_DOCS.escalationMatrix)).toBe(renderEscalationMatrix(nodeCore));
  });
});

describe("committed Prometheus rules", () => {
  // Typed parse, not a text scan: a rules file Prometheus cannot load is an operator
  // document that silently does nothing, and a regex over the raw bytes would pass on it.
  // js-yaml also rejects duplicated mapping keys on its own.
  interface PrometheusRule {
    readonly alert?: string;
    readonly expr?: string;
    readonly labels?: Record<string, string>;
  }
  const document = yaml.load(read(OPERATOR_DOCS.rules)) as {
    groups?: { rules?: PrometheusRule[] }[];
  };
  const alertRules = (document.groups ?? []).flatMap((group) => group.rules ?? []);
  const labelValues = (label: string): string[] =>
    alertRules.flatMap((rule) => {
      const value = rule.labels?.[label];
      return value === undefined ? [] : [value];
    });

  it("loads as YAML and every rule carries an alert name and an expression", () => {
    expect(alertRules.length).toBeGreaterThan(0);
    for (const rule of alertRules) {
      expect(typeof rule.alert, `a rule in ${OPERATOR_DOCS.rules} has no alert name`).toBe("string");
      expect(typeof rule.expr, `${rule.alert ?? "<unnamed>"} has no expr`).toBe("string");
    }
  });

  it("uses only severities that exist in the ladder", () => {
    const severities = labelValues("severity");
    expect(severities.length).toBeGreaterThan(0);
    for (const severity of severities) {
      expect(nodeCore.ALERT_SEVERITIES).toContain(severity);
    }
  });

  it("uses only signal ids that exist", () => {
    const signals = labelValues("signal");
    expect(signals.length).toBeGreaterThan(0);
    for (const signal of signals) {
      expect(nodeCore.SAFETY_ALERT_SIGNALS).toContain(signal);
    }
  });

  it("carries a rule for every signal whose reading is live", () => {
    const signals = new Set(labelValues("signal"));
    for (const [signal, wiring] of Object.entries(SIGNAL_WIRING)) {
      if (!wiring.bound) continue;
      expect(signals, `no committed alert rule for live signal ${signal}`).toContain(signal);
    }
  });
});
