// Generator for the two code-derived operator documents:
//
//   docs/operations/alert-reference.md    — one section per SAFETY_ALERT_SIGNALS entry
//   docs/operations/escalation-matrix.md  — severity -> channels -> signals -> posture
//
// Both are rendered from `packages/node-core/src/operator/safety-alerts.ts`, never
// hand-copied: severity, citation, posture, diagnostic-only flag, numeric threshold
// bands and the escalation path all come from that module. Editing the markdown by
// hand is a drift bug, and `apps/generic-node/test/operator-docs.census.test.ts`
// fails when the committed bytes stop matching a fresh render.
//
//   node scripts/gen-operator-alert-docs.mjs           # write both files
//   node scripts/gen-operator-alert-docs.mjs --check   # exit 2 on drift, write nothing
//
// The CLI reads the COMPILED module (`pnpm build` first). The render functions take
// the module namespace as an argument and import nothing themselves, so the census
// test can render from TypeScript source through vitest and compare byte-for-byte
// against what this script wrote from `dist`.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");

export const ALERT_REFERENCE_PATH = "docs/operations/alert-reference.md";
export const ESCALATION_MATRIX_PATH = "docs/operations/escalation-matrix.md";

/**
 * Whether each signal's reading is actually fed on a live node.
 *
 * Source of truth for this column is `apps/generic-node/src/metrics/custody-alerts.ts`
 * (`custodyAlertInputFromSnapshot`), which spreads `emptySafetyAlertMetricInput()` and
 * overrides snapshot-backed inputs and process counters from NodeMetrics (ZTR-1144).
 *
 * A signal missing from this map fails the census test — a new rule cannot ship without
 * an explicit statement of whether it can fire.
 */
export const SIGNAL_WIRING = {
  invariant_breach: { bound: true, note: "`gn_invariant_breach_total` from applyMoveInvariantBreachQuarantine / receive-expiry breach sites" },
  duplicate_submit_attempt: { bound: true, note: "`gn_duplicate_submit_rejection_total` on submit_decisions mint loser (move + receive claim paths)" },
  lease_age: { bound: true, note: "`gn_oldest_lease_age_seconds`, suppressed while `gn_database_truth_available` is 0" },
  path_gap: { bound: true, note: "`gn_proof_budget_exhaustion_total` (INDETERMINATE-by-budget path gaps)" },
  regression: { bound: true, note: "`gn_observation_anomalies_total{kind=\"REGRESSION\"}`" },
  endpoint_disagreement: { bound: true, note: "`gn_observation_anomalies_total{kind=\"ENDPOINT_DISAGREEMENT\"}` from GATEWAY_ENDPOINT_DISAGREEMENT quarantine" },
  storage_pressure: { bound: true, note: "`gn_storage_pressure` — a 0/1 band flag, not a utilization fraction" },
  queue_caps: { bound: true, note: "queue depth, pool-cap utilization, pinned ratio, and `gn_receive_queue_full_503_total` (normalized)" },
  signer_loss: { bound: true, note: "`gn_signer_leadership_held` + `gn_signer_in_flight_ambiguous` (raises P0 when both)" },
  backup_age: { bound: true, note: "`gn_backup_last_success_age_seconds`, suppressed while `gn_backup_last_success_available` is 0; threshold only exists when `backupMaxAgeMs` is passed" },
  push_no_transfer_code_streak: {
    bound: true,
    note: "`gn_push_no_transfer_code_streak` process-local gauge; in-process SAFETY_ALERT_SIGNALS fire on threshold via composePush + custodyAlertEvaluator",
  },
  attention_backlog: { bound: true, note: "`gn_operations_attention_required` COUNT(*), suppressed while `gn_database_truth_available` is 0" },
  gateway_read_failure: { bound: true, note: "`gn_t0_read_failures_total` process counter at the observation seam" },
  queue_oldest_age: { bound: true, note: "`gn_receive_queue_oldest_age_seconds`, band = RECEIVE_QUEUE_MAX_WAIT; suppressed while DB-truth unavailable" },
};

/**
 * Escalation roles. The node is self-hosted, so the repository cannot know who is on
 * call — it can only fix which role each severity reaches and what that role is
 * expected to do. Names and contact channels belong in the deployment's own on-call
 * record, not in this repository.
 */
export const ESCALATION_ROLES = [
  {
    severity: "P0",
    role: "Custody escalation",
    responsibility:
      "Authorized to stop money engines and quarantine wallets. Reached immediately, day or night. Cannot be the same person who is mid-incident on the node unless the deployment runs single-operator.",
  },
  {
    severity: "P1",
    role: "Primary operator",
    responsibility:
      "Holds the admin session, TOTP device and enrolled device key. Works the incident runbook; escalates to custody escalation on any P0 trigger.",
  },
  {
    severity: "P2",
    role: "Primary operator (next business day)",
    responsibility: "Reviews the log channel. No paging obligation.",
  },
];

const GENERATED_BANNER = (script) =>
  `<!-- GENERATED FILE — do not edit by hand.\n     Source: packages/node-core/src/operator/safety-alerts.ts\n     Regenerate: node ${script}\n     Gate: apps/generic-node/test/operator-docs.census.test.ts -->`;

function thresholdsFor(core, signal) {
  return core.DEFAULT_ALERT_THRESHOLDS.filter((t) => t.signal === signal).sort(
    (a, b) => core.SEVERITY_RANK[a.severity] - core.SEVERITY_RANK[b.severity],
  );
}

function thresholdCell(core, signal) {
  const bands = thresholdsFor(core, signal);
  if (bands.length === 0) {
    return `none by default — supplied at construction (source: \`${core.BACKUP_AGE_THRESHOLD_SOURCE}\`)`;
  }
  return bands.map((t) => `${t.severity} when reading ${t.direction === "above" ? "≥" : "≤"} ${t.value}`).join("; ");
}

function wiringFor(signal) {
  const entry = SIGNAL_WIRING[signal];
  if (entry === undefined) {
    throw new Error(`SIGNAL_WIRING has no entry for signal ${signal}`);
  }
  return entry;
}

export function renderAlertReference(core, script = "scripts/gen-operator-alert-docs.mjs") {
  const lines = [
    GENERATED_BANNER(script),
    "",
    "# Alert reference",
    "",
    "One section per entry in `SAFETY_ALERT_SIGNALS`. Severity, citation, posture, the",
    "diagnostic-only flag and the numeric bands are the values the running evaluator uses.",
    "",
    "A **fire is advisory**. No alert advances a cursor, infers chain truth, releases a lease",
    "or changes money state — the operator does, through the actions in",
    "[`incidents.md`](incidents.md).",
    "",
    "`Feeds` states whether the reading is actually produced on a live node. A signal marked",
    "*unbound* has a correct rule and a permanently zero input: it will never fire, and you",
    "must not treat its silence as an all-clear. Prometheus rules that watch the exposed",
    "metrics directly are in [`alerts/generic-node.rules.yml`](alerts/generic-node.rules.yml).",
    "",
    "## Summary",
    "",
    "| Signal | Severity | Diagnostic only | Feeds |",
    "| --- | --- | --- | --- |",
  ];

  for (const rule of core.SAFETY_ALERT_RULES) {
    const wiring = wiringFor(rule.signal);
    lines.push(
      `| [\`${rule.signal}\`](#${rule.signal}) | ${rule.severity} | ${rule.diagnosticOnly ? "yes" : "no"} | ${wiring.bound ? "live" : "**unbound**"} |`,
    );
  }

  lines.push("");

  for (const rule of core.SAFETY_ALERT_RULES) {
    const wiring = wiringFor(rule.signal);
    lines.push(
      `## ${rule.signal}`,
      "",
      `- **Severity:** ${rule.severity}`,
      `- **Thresholds:** ${thresholdCell(core, rule.signal)}`,
      `- **Diagnostic only:** ${rule.diagnosticOnly ? "yes — this signal must never drive an automatic lease release or money-state change" : "no"}`,
      `- **Feeds:** ${wiring.bound ? "live — " : "**unbound — this rule cannot fire today.** "}${wiring.note}`,
      "",
      "**Rule.**",
      "",
      `> ${rule.citation}`,
      "",
      "**Required posture.**",
      "",
      `> ${rule.posture}`,
      "",
    );
  }

  lines.push(
    "## Invariants asserted by the source module",
    "",
    `- \`LEASE_AGE_AUTOMATIC_RELEASE\` = \`${String(core.LEASE_AGE_AUTOMATIC_RELEASE)}\` — a lease heartbeat expiring is not a lease release.`,
    `- \`BACKUP_AGE_THRESHOLD_SOURCE\` = \`${core.BACKUP_AGE_THRESHOLD_SOURCE}\` — the backup-age number comes from the configured cadence and is never invented locally.`,
    "- Every notification carries `automaticRelease: false`, so no sink can promote a fire into a release.",
    "- A non-finite reading fails closed: it is treated as crossing the threshold.",
    "",
  );

  return `${lines.join("\n").trimEnd()}\n`;
}

export function renderEscalationMatrix(core, script = "scripts/gen-operator-alert-docs.mjs") {
  const bySeverity = new Map();
  for (const rule of core.SAFETY_ALERT_RULES) {
    const bucket = bySeverity.get(rule.severity) ?? [];
    bucket.push(rule);
    bySeverity.set(rule.severity, bucket);
  }
  // Any signal with a higher-severity band escalates into that severity too.
  for (const threshold of core.DEFAULT_ALERT_THRESHOLDS) {
    const bucket = bySeverity.get(threshold.severity) ?? [];
    if (!bucket.some((r) => r.signal === threshold.signal)) {
      bucket.push(core.SAFETY_ALERT_RULE_BY_SIGNAL[threshold.signal]);
      bySeverity.set(threshold.severity, bucket);
    }
  }

  const descending = [...core.ALERT_SEVERITIES].sort(
    (a, b) => core.SEVERITY_RANK[b] - core.SEVERITY_RANK[a],
  );

  const lines = [
    GENERATED_BANNER(script),
    "",
    "# Escalation matrix",
    "",
    "Severity → who → how. The severity ladder, the channel routing and the posture text are",
    "rendered from `packages/node-core/src/operator/safety-alerts.ts`; the roles are fixed by",
    "this repository, and the humans behind them belong in your deployment's on-call record.",
    "",
    "Channels widen monotonically: a higher severity never drops a channel a lower one uses",
    "(`validateEscalationPath` refuses a configuration that narrows).",
    "",
    "## Severity → role",
    "",
    "| Severity | Role reached | What that role is expected to do |",
    "| --- | --- | --- |",
  ];

  for (const role of ESCALATION_ROLES) {
    lines.push(`| ${role.severity} | ${role.role} | ${role.responsibility} |`);
  }

  lines.push("", "## Severity → channels → signals", "");
  lines.push("| Severity | Channels | Signals that reach this severity |");
  lines.push("| --- | --- | --- |");

  for (const severity of descending) {
    const step = core.DEFAULT_ESCALATION_PATH.find((s) => s.severity === severity);
    const channels = step === undefined ? "—" : step.channels.map((c) => `\`${c}\``).join(", ");
    const signals = (bySeverity.get(severity) ?? [])
      .map((r) => `\`${r.signal}\``)
      .sort()
      .join(", ");
    lines.push(`| ${severity} | ${channels} | ${signals === "" ? "—" : signals} |`);
  }

  lines.push(
    "",
    "## P0 signals and their required posture",
    "",
    "These are the only signals that reach custody escalation. Each posture below is the",
    "verbatim `posture` field of its rule.",
    "",
  );

  for (const rule of core.SAFETY_ALERT_RULES) {
    const bands = thresholdsFor(core, rule.signal);
    const reachesP0 = rule.severity === "P0" || bands.some((b) => b.severity === "P0");
    if (!reachesP0) continue;
    const wiring = wiringFor(rule.signal);
    lines.push(
      `### \`${rule.signal}\``,
      "",
      `${wiring.bound ? "" : "**Unbound — cannot fire today.** "}${wiring.note}`,
      "",
      `> ${rule.posture}`,
      "",
    );
  }

  lines.push(
    "## Delivery",
    "",
    "| Channel | Meaning |",
    "| --- | --- |",
    "| `log` | Written to the node's stdout logger. Always available. |",
    "| `webhook` | Configured `AlertChannel` of kind `webhook`. |",
    "",
    "**Nothing pages today.** The composition root registers a `log` channel only, and no",
    "webhook URL is configurable — so every P1/P0 above is delivered to stdout and to nobody",
    "else. Configure OPERATOR_ALERT_WEBHOOK_URL (https, no credentials) for P1/P0 paging; absent keeps log-only",
    "the metrics endpoint with the rules in",
    "[`alerts/generic-node.rules.yml`](alerts/generic-node.rules.yml), not on this escalation",
    "path.",
    "",
  );

  return `${lines.join("\n").trimEnd()}\n`;
}

async function main(argv) {
  const check = argv.includes("--check");
  const distPath = resolve(repoRoot, "packages/node-core/dist/operator/safety-alerts.js");
  let core;
  try {
    core = await import(distPath);
  } catch (err) {
    process.stderr.write(
      `cannot load ${distPath} — run \`pnpm build\` first.\n${err instanceof Error ? err.message : String(err)}\n`,
    );
    return 1;
  }

  const outputs = [
    [ALERT_REFERENCE_PATH, renderAlertReference(core)],
    [ESCALATION_MATRIX_PATH, renderEscalationMatrix(core)],
  ];

  let drifted = false;
  for (const [relPath, content] of outputs) {
    const absolute = resolve(repoRoot, relPath);
    if (check) {
      const existing = await readFile(absolute, "utf8").catch(() => null);
      if (existing !== content) {
        drifted = true;
        process.stderr.write(`DRIFT: ${relPath} does not match a fresh render\n`);
      }
      continue;
    }
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    process.stdout.write(`wrote ${relPath}\n`);
  }

  if (drifted) return 2;
  if (check) process.stdout.write("operator alert docs are up to date\n");
  return 0;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
