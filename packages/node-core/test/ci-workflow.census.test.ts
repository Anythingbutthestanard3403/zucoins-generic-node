import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const REPO_ROOT = fileURLToPath(new URL("../../..", import.meta.url));
const readRepoFile = (path: string): string => readFileSync(`${REPO_ROOT}/${path}`, "utf8");

/** Doc-11 command gates that must appear as active `run:` steps (not comments / || true). */
const REQUIRED_RUN_COMMANDS = [
  "pnpm build",
  "pnpm lint",
  "pnpm --filter @zucoins/generic-node-contracts test",
  "pnpm test",
  "pnpm test:boundaries",
  "node scripts/check-schema-census.mjs",
  "pnpm --filter @zucoins/generic-node-ui test",
  "pnpm --filter @zucoins/generic-node-ui test:e2e",
] as const;

type WorkflowStep = {
  readonly name?: string;
  readonly uses?: string;
  readonly run?: string;
  readonly continueOnError: boolean;
  /** Raw `if:` expression when present (after unquote); undefined = always runs. */
  readonly ifExpr?: string;
  /** Absolute start line (1-based) of this step mapping in the source file. */
  readonly startLine: number;
};

type WorkflowJob = {
  readonly id: string;
  readonly continueOnError: boolean;
  /** Raw job-level `if:` expression when present. */
  readonly ifExpr?: string;
  readonly steps: WorkflowStep[];
};

export type ParsedWorkflow = {
  readonly raw: string;
  /** Source with full-line `#` comments blanked (keeps line numbers stable). */
  readonly activeSource: string;
  readonly jobs: WorkflowJob[];
};

/**
 * Blank full-line YAML comments and strip end-of-line `# ...` comments outside quotes.
 * Does not attempt general YAML string fidelity — GHA workflow steps use plain scalars.
 */
export function blankYamlComments(source: string): string {
  return source
    .split("\n")
    .map((line) => {
      const trimmed = line.trimStart();
      if (trimmed.startsWith("#")) {
        return "";
      }
      // Strip unquoted trailing comments: walk chars, track single/double quotes.
      let out = "";
      let quote: "'" | '"' | null = null;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i]!;
        if (quote) {
          out += ch;
          if (ch === quote && line[i - 1] !== "\\") quote = null;
          continue;
        }
        if (ch === "'" || ch === '"') {
          quote = ch;
          out += ch;
          continue;
        }
        if (ch === "#") {
          // drop rest of line
          break;
        }
        out += ch;
      }
      return out.replace(/\s+$/, "");
    })
    .join("\n");
}

function indentOf(line: string): number {
  const m = /^ */.exec(line);
  return m ? m[0].length : 0;
}

function unquote(val: string): string {
  const t = val.trim();
  if (
    (t.startsWith('"') && t.endsWith('"')) ||
    (t.startsWith("'") && t.endsWith("'"))
  ) {
    return t.slice(1, -1);
  }
  return t;
}

/**
 * YAML / GHA truthy scalars that enable continue-on-error.
 * GHA coerces these; matching only bare `true` left yes/"true"/True/1 green while
 * the step still continues on failure.
 */
export function isYamlTruthy(raw: string): boolean {
  const t = unquote(raw).trim().toLowerCase();
  return t === "true" || t === "yes" || t === "on" || t === "y" || t === "1";
}

/**
 * Expressions that always evaluate true under GHA (or are absent).
 * Anything else on a required gate job/step is treated as a skip-neuter.
 */
export function isAlwaysTrueIf(expr: string | undefined): boolean {
  if (expr === undefined) return true;
  const t = expr.trim().toLowerCase();
  if (t === "") return true;
  if (t === "true" || t === "${{ true }}" || t === "${{true}}") return true;
  // Bare always-true literals only — any actor/ref/event condition is a skip risk.
  return false;
}

/** Soft-exit / success-masking anywhere in a run body (not first line only). */
const SUCCESS_MASK =
  /(?:\|\||&&)\s*(?:true|:)\b|^\s*(?:true|:)\s*$|;\s*(?:true|:)\s*$|set\s+\+e\b|set\s+-[a-zA-Z]*e[a-zA-Z]*\s+\+e|exit\s+0\b/m;

/**
 * Parse jobs.*.steps from workflow YAML with line-oriented structure.
 * Fail-closed: only `run:` / `run: |` / `run: >` bodies that survive comment blanking count.
 */
export function parseWorkflowJobs(source: string): ParsedWorkflow {
  const activeSource = blankYamlComments(source);
  const lines = activeSource.split("\n");
  const jobs: WorkflowJob[] = [];

  let i = 0;
  // Find top-level `jobs:`
  while (i < lines.length && !/^jobs:\s*$/.test(lines[i]!)) i++;
  if (i >= lines.length) {
    return { raw: source, activeSource, jobs };
  }
  i++;

  while (i < lines.length) {
    const line = lines[i]!;
    if (line.trim() === "") {
      i++;
      continue;
    }
    const ind = indentOf(line);
    // Next top-level key ends jobs
    if (ind === 0 && line.trim() !== "") break;
    // Job id at indent 2: `  quality-and-tests:`
    const jobMatch = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (!jobMatch) {
      i++;
      continue;
    }
    const jobId = jobMatch[1]!;
    const jobIndent = 2;
    i++;
    let jobContinue = false;
    let jobIf: string | undefined;
    const steps: WorkflowStep[] = [];

    while (i < lines.length) {
      const jl = lines[i]!;
      if (jl.trim() === "") {
        i++;
        continue;
      }
      const ji = indentOf(jl);
      if (ji <= jobIndent && jl.trim() !== "") break;

      // Job-level keys at indent 4 (before or around steps)
      const jobKey = /^ {4}([A-Za-z0-9_-]+):\s*(.*)$/.exec(jl);
      if (jobKey && jobKey[1] !== "steps") {
        const key = jobKey[1]!;
        const val = jobKey[2]!;
        if (key === "continue-on-error") {
          jobContinue = isYamlTruthy(val);
        } else if (key === "if") {
          jobIf = unquote(val);
        }
        i++;
        continue;
      }

      if (!/^ {4}steps:\s*$/.test(jl)) {
        i++;
        continue;
      }
      // parse steps sequence
      i++;
      while (i < lines.length) {
        const sl = lines[i]!;
        if (sl.trim() === "") {
          i++;
          continue;
        }
        const si = indentOf(sl);
        if (si <= 4 && sl.trim() !== "") break;

        // Step starts with `      - ` at indent 6
        const stepStart = /^( {6})-\s+(.*)$/.exec(sl);
        if (!stepStart) {
          i++;
          continue;
        }
        const stepIndent = 6;
        const startLine = i + 1;
        let name: string | undefined;
        let uses: string | undefined;
        let run: string | undefined;
        let continueOnError = false;
        let ifExpr: string | undefined;

        type BlockState = { pendingBlock?: string[]; pendingBlockIndent?: number };
        const blockState: BlockState = {};

        const consumeKey = (rawKeyLine: string): void => {
          const kv = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(rawKeyLine);
          if (!kv) return;
          const key = kv[1]!;
          const val = kv[2]!;
          if (key === "name") {
            name = unquote(val);
            return;
          }
          if (key === "uses") {
            uses = unquote(val);
            return;
          }
          if (key === "continue-on-error") {
            continueOnError = isYamlTruthy(val);
            return;
          }
          if (key === "if") {
            ifExpr = unquote(val);
            return;
          }
          if (key === "run") {
            const t = val.trim();
            if (t === "|" || t === "|-" || t === ">" || t === ">-" || t === "") {
              const block: string[] = [];
              blockState.pendingBlock = block;
              blockState.pendingBlockIndent = 8;
              run = "";
            } else {
              run = unquote(val);
            }
          }
        };

        consumeKey(stepStart[2]!);
        i++;
        while (i < lines.length) {
          const bl = lines[i]!;
          if (bl.trim() === "") {
            if (blockState.pendingBlock) {
              blockState.pendingBlock.push("");
              i++;
              continue;
            }
            i++;
            continue;
          }
          const bi = indentOf(bl);
          // next step or leave steps
          if (bi <= stepIndent) break;
          // content under step at indent >= 8
          if (blockState.pendingBlock && bi > 8) {
            blockState.pendingBlock.push(bl.slice(8));
            i++;
            continue;
          }
          if (blockState.pendingBlock && bi <= 8) {
            // close block
            run = blockState.pendingBlock.join("\n").replace(/^\n+|\n+$/g, "");
            delete blockState.pendingBlock;
            // fall through to parse this line as key if still in step
          }
          if (bi === 8) {
            const content = bl.slice(8);
            if (/^[A-Za-z0-9_-]+:/.test(content)) {
              consumeKey(content);
              i++;
              continue;
            }
          }
          // deeper nested (with:/env:) — skip
          i++;
        }
        // close any open block
        if (blockState.pendingBlock) {
          run = blockState.pendingBlock.join("\n").replace(/^\n+|\n+$/g, "");
          delete blockState.pendingBlock;
        }

        steps.push({ name, uses, run, continueOnError, ifExpr, startLine });
      }
    }

    jobs.push({ id: jobId, continueOnError: jobContinue, ifExpr: jobIf, steps });
  }

  return { raw: source, activeSource, jobs };
}

/** Shell success-masking that would keep a step green when the command fails. */
export function hasSuccessMask(runBody: string): boolean {
  // Evaluate per non-empty line AND whole body so multi-line soft-exits are caught.
  if (SUCCESS_MASK.test(runBody)) return true;
  for (const line of runBody.split(/\n/)) {
    const t = line.trim();
    if (!t) continue;
    if (SUCCESS_MASK.test(t)) return true;
  }
  return false;
}

/**
 * A gate is "active" only when the entire run body is exactly the command
 * (single-line or multi-line with only that command after trim). First-line-only
 * matching allowed `run: |\n  pnpm build\n  exit 0` to count as the build gate.
 */
function runBodyIsExactCommand(run: string, command: string): boolean {
  const trimmed = run.replace(/^\n+|\n+$/g, "").trimEnd();
  if (trimmed === command) return true;
  // Multi-line: every non-empty line must equal the command (no trailing soft-exit).
  const nonEmpty = trimmed
    .split(/\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  return nonEmpty.length === 1 && nonEmpty[0] === command;
}

function findActiveGate(
  wf: ParsedWorkflow,
  command: string,
): { job: WorkflowJob; step: WorkflowStep } | undefined {
  for (const job of wf.jobs) {
    for (const step of job.steps) {
      if (typeof step.run !== "string") continue;
      if (runBodyIsExactCommand(step.run, command)) {
        return { job, step };
      }
    }
  }
  return undefined;
}

function activeRunCommands(wf: ParsedWorkflow): string[] {
  const out: string[] = [];
  for (const job of wf.jobs) {
    for (const step of job.steps) {
      if (typeof step.run === "string" && step.run.length > 0) {
        out.push(step.run);
      }
    }
  }
  return out;
}

describe("required CI gates", () => {
  const workflowSource = readRepoFile(".github/workflows/ci.yml");
  const wf = parseWorkflowJobs(workflowSource);

  it("runs on pull requests and pushes to main", () => {
    // Triggers must be active (not comment-only).
    const active = wf.activeSource;
    expect(active).toMatch(/push:\s*\n\s*branches:\s*\[main\]/);
    expect(active).toMatch(/pull_request:\s*\n\s*branches:\s*\[main\]/);
  });

  it("fails closed around every doc-11 command gate", () => {
    expect(wf.jobs.length, "workflow must define at least one job").toBeGreaterThan(0);

    for (const command of REQUIRED_RUN_COMMANDS) {
      const hit = findActiveGate(wf, command);
      expect(hit, `${command} must be an active run: step (not comment-only)`).toBeDefined();
      const { job, step } = hit!;
      expect(
        job.continueOnError,
        `job ${job.id} must not set continue-on-error`,
      ).toBe(false);
      expect(
        step.continueOnError,
        `step for ${command} must not set continue-on-error`,
      ).toBe(false);
      expect(
        isAlwaysTrueIf(job.ifExpr),
        `job ${job.id} must not set a skippable if: (got ${JSON.stringify(job.ifExpr)})`,
      ).toBe(true);
      expect(
        isAlwaysTrueIf(step.ifExpr),
        `step for ${command} must not set a skippable if: (got ${JSON.stringify(step.ifExpr)})`,
      ).toBe(true);
      expect(
        hasSuccessMask(step.run ?? ""),
        `${command} must not mask failures (|| true / exit 0 / bare true / set +e)`,
      ).toBe(false);
      // Whole body must be exactly the gate command — no trailing soft-exit lines.
      expect(
        runBodyIsExactCommand(step.run ?? "", command),
        `${command} run body must be exactly the command (full body, not first line only)`,
      ).toBe(true);
    }

    // No job/step anywhere may enable continue-on-error or skippable if (delivery fail-closed).
    for (const job of wf.jobs) {
      expect(job.continueOnError, `job ${job.id} continue-on-error`).toBe(false);
      expect(
        isAlwaysTrueIf(job.ifExpr),
        `job ${job.id} if: ${JSON.stringify(job.ifExpr)}`,
      ).toBe(true);
      for (const step of job.steps) {
        expect(step.continueOnError, `step@${step.startLine} continue-on-error`).toBe(false);
        expect(
          isAlwaysTrueIf(step.ifExpr),
          `step@${step.startLine} if: ${JSON.stringify(step.ifExpr)}`,
        ).toBe(true);
        if (step.run) {
          expect(hasSuccessMask(step.run), `run@${step.startLine} success-mask`).toBe(false);
        }
      }
    }

    // Comment-only residue must not satisfy the gate: active runs list is the authority.
    const runs = activeRunCommands(wf);
    for (const command of REQUIRED_RUN_COMMANDS) {
      expect(
        runs.some((r) => runBodyIsExactCommand(r, command)),
        `${command} missing from active exact-command run list: ${JSON.stringify(runs)}`,
      ).toBe(true);
    }
  });

  it("requires a healthy PostgreSQL service rather than permitting DB skips", () => {
    const active = wf.activeSource;
    // Hosted path uses `services.postgres` (image: postgres:16). Self-hosted path
    // cannot use GHA service containers; both must still set PG_REQUIRED=1, pin
    // PGHOST, and run pg_isready so a skipped DB suite fails the build.
    const hasHostedService = /image:\s*postgres:16/.test(active);
    const hasSelfHostedRunner = /runs-on:\s*\[\s*self-hosted/.test(active);
    expect(
      hasHostedService || hasSelfHostedRunner,
      "CI must provision PostgreSQL via hosted service image OR self-hosted runner with local PG",
    ).toBe(true);
    expect(active).toMatch(/PG_REQUIRED:\s*["']?1["']?/);
    expect(active).toContain("PGHOST: 127.0.0.1");
    expect(active).toContain("pg_isready");
  });

  it("runs the real admin browser suite in Chromium", () => {
    const active = wf.activeSource;
    expect(active).toMatch(/admin-playwright:/);
    // Hosted ubuntu uses --with-deps; self-hosted macOS installs the browser binary only.
    expect(active).toMatch(/playwright install(?: --with-deps)? chromium/);
    const hit = findActiveGate(wf, "pnpm --filter @zucoins/generic-node-ui test:e2e");
    expect(hit).toBeDefined();
  });

  it("keeps both consumer projects on guarded source aliases", () => {
    const consumer = readRepoFile("packages/generic-node-consumer/vitest.config.ts");
    const example = readRepoFile("packages/consumer-example/vitest.config.ts");

    for (const config of [consumer, example]) {
      expect(config).toContain("setup-network-guard.ts");
      expect(config).toContain("packageSourceAliases");
      expect(config).toContain('new URL("../node-core/", import.meta.url)');
    }
  });

  it("pins third-party actions to immutable commit SHAs", () => {
    const uses = wf.jobs.flatMap((j) => j.steps.map((s) => s.uses).filter(Boolean)) as string[];
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) {
      // owner/name@<40-hex> or owner/name/path@<40-hex>
      expect(u, `action not SHA-pinned: ${u}`).toMatch(
        /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$/,
      );
    }
  });
});
