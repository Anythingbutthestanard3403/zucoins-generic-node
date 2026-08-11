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
  /** Absolute start line (1-based) of this step mapping in the source file. */
  readonly startLine: number;
};

type WorkflowJob = {
  readonly id: string;
  readonly continueOnError: boolean;
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
    const steps: WorkflowStep[] = [];

    while (i < lines.length) {
      const jl = lines[i]!;
      if (jl.trim() === "") {
        i++;
        continue;
      }
      const ji = indentOf(jl);
      if (ji <= jobIndent && jl.trim() !== "") break;

      if (/^ {4}continue-on-error:\s*true\s*$/.test(jl)) {
        jobContinue = true;
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

        // First line may hold inline key after `- `
        const firstRest = stepStart[2]!;
        // Use a cleaner block collector
        // Reset and parse properly:
        name = undefined;
        uses = undefined;
        run = undefined;
        continueOnError = false;

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
            continueOnError = /^true\s*$/.test(val.trim());
            return;
          }
          if (key === "run") {
            const t = val.trim();
            if (t === "|" || t === "|-" || t === ">" || t === ">-" || t === "") {
              // block or empty then block — collect subsequent lines indented deeper than key
              const block: string[] = [];
              // keys under step are indent 8
              const keyIndent = 8;
              // advance happens in outer loop — we'll use a side channel
              (consumeKey as { pendingBlock?: string[] }).pendingBlock = block;
              (consumeKey as { pendingBlockIndent?: number }).pendingBlockIndent = keyIndent;
              run = ""; // filled after
            } else {
              run = unquote(val);
            }
          }
        };

        consumeKey(firstRest);
        i++;
        while (i < lines.length) {
          const bl = lines[i]!;
          if (bl.trim() === "") {
            // blank inside step — keep if collecting block
            const pending = (consumeKey as { pendingBlock?: string[] }).pendingBlock;
            if (pending) {
              pending.push("");
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
          const pending = (consumeKey as { pendingBlock?: string[] }).pendingBlock;
          if (pending && bi > 8) {
            pending.push(bl.slice(8)); // dedent one step-key level
            i++;
            continue;
          }
          if (pending && bi <= 8) {
            // close block
            run = pending.join("\n").replace(/^\n+|\n+$/g, "");
            delete (consumeKey as { pendingBlock?: string[] }).pendingBlock;
            // fall through to parse this line as key if still in step
          }
          if (bi === 8) {
            const content = bl.slice(8);
            // If this starts a new key
            if (/^[A-Za-z0-9_-]+:/.test(content)) {
              consumeKey(content);
              // if consumeKey opened a new block, continue
              i++;
              continue;
            }
          }
          // deeper nested (with:/env:) — skip
          i++;
        }
        // close any open block
        const pending = (consumeKey as { pendingBlock?: string[] }).pendingBlock;
        if (pending) {
          run = pending.join("\n").replace(/^\n+|\n+$/g, "");
          delete (consumeKey as { pendingBlock?: string[] }).pendingBlock;
        }

        steps.push({ name, uses, run, continueOnError, startLine });
      }
    }

    jobs.push({ id: jobId, continueOnError: jobContinue, steps });
  }

  return { raw: source, activeSource, jobs };
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

/** Shell success-masking that would keep a step green when the command fails. */
const SUCCESS_MASK = /(?:\|\||&&)\s*(?:true|:)\b|set\s+\+e\b|set\s+-[a-zA-Z]*e[a-zA-Z]*\s+\+e/;

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

function findActiveGate(
  wf: ParsedWorkflow,
  command: string,
): { job: WorkflowJob; step: WorkflowStep } | undefined {
  for (const job of wf.jobs) {
    for (const step of job.steps) {
      if (typeof step.run !== "string") continue;
      // Exact match or first line / whole script equals command.
      const run = step.run.trim();
      const firstLine = run.split(/\n/)[0]!.trim();
      if (run === command || firstLine === command) {
        return { job, step };
      }
      // Allow trailing args only when command is a strict prefix as a whole argv[0..] —
      // not substring smuggling inside a larger script. Require the run body to be exactly
      // the command, or the command alone on the first non-empty line of a block with no
      // masking operators on that line.
    }
  }
  return undefined;
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
        `job ${job.id} must not set continue-on-error: true`,
      ).toBe(false);
      expect(
        step.continueOnError,
        `step for ${command} must not set continue-on-error: true`,
      ).toBe(false);
      expect(
        SUCCESS_MASK.test(step.run ?? ""),
        `${command} must not mask failures (|| true / set +e)`,
      ).toBe(false);
    }

    // No job/step anywhere may enable continue-on-error (delivery gates are fail-closed).
    for (const job of wf.jobs) {
      expect(job.continueOnError, `job ${job.id}`).toBe(false);
      for (const step of job.steps) {
        expect(step.continueOnError, `step@${step.startLine}`).toBe(false);
        if (step.run) {
          expect(SUCCESS_MASK.test(step.run), `run@${step.startLine}`).toBe(false);
        }
      }
    }

    // Comment-only residue must not satisfy the gate: active runs list is the authority.
    const runs = activeRunCommands(wf);
    for (const command of REQUIRED_RUN_COMMANDS) {
      expect(
        runs.some((r) => r.trim() === command || r.trim().split(/\n/)[0]!.trim() === command),
        `${command} missing from active run list: ${JSON.stringify(runs)}`,
      ).toBe(true);
    }
  });

  it("requires a healthy PostgreSQL service rather than permitting DB skips", () => {
    const active = wf.activeSource;
    expect(active).toContain("image: postgres:16");
    expect(active).toMatch(/PG_REQUIRED:\s*["']?1["']?/);
    expect(active).toContain("PGHOST: 127.0.0.1");
    expect(active).toContain("pg_isready");
  });

  it("runs the real admin browser suite in Chromium", () => {
    const active = wf.activeSource;
    expect(active).toMatch(/admin-playwright:/);
    expect(active).toContain("playwright install --with-deps chromium");
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
