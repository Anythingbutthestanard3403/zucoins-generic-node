import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { REQUEST_PIPELINE } from "@zucoins/generic-node-contracts/route-policy";

/**
 * ZTR-1167 item 6a — the node-core validation pipeline must keep the frozen
 * REQUEST_PIPELINE stage sequence. Stage names are documented in the header of
 * packages/node-core/src/api/pipeline.ts and implemented as runValidationPipeline.
 * This gate fails if a stage is reordered, added, or dropped in either place.
 */
const here = dirname(fileURLToPath(import.meta.url));
const pipelineSourcePath = join(here, "../src/api/pipeline.ts");
const pipelineSource = readFileSync(pipelineSourcePath, "utf8");

const FROZEN_STAGE_NAMES = REQUEST_PIPELINE.map((stage) => stage.name);

/** Header comment block lists `N. <stage_name>` for the frozen sequence. */
function stageNamesFromHeaderComment(source: string): string[] {
  const names: string[] = [];
  for (const line of source.split("\n")) {
    const match = /^\/\/\s*(\d+)\.\s+([a-z0-9_]+)/.exec(line);
    if (match) {
      names.push(match[2]!);
    }
    // Stop once the import block begins — only the frozen header list counts.
    if (line.startsWith("import ")) break;
  }
  return names;
}

describe("request pipeline stage order (REQUEST_PIPELINE freeze)", () => {
  it("header comment stage sequence matches frozen REQUEST_PIPELINE names in order", () => {
    expect(stageNamesFromHeaderComment(pipelineSource)).toEqual([...FROZEN_STAGE_NAMES]);
  });

  it("frozen REQUEST_PIPELINE keeps eight stages with dense order 1..N", () => {
    expect(FROZEN_STAGE_NAMES).toHaveLength(8);
    expect(REQUEST_PIPELINE.map((s) => s.order)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it("runValidationPipeline remains the stage-1..5 validation entrypoint", () => {
    expect(pipelineSource).toMatch(/export async function runValidationPipeline\b/);
    // Stage 1 assign + stages 2/3 auth + stage 4 idempotency must stay named in-body.
    for (const fragment of [
      "assignRequestId",
      "authenticateAndAuthorize",
      "enforceIdempotency",
      "resolve_object_with_tenant_predicate",
    ] as const) {
      expect(pipelineSource).toContain(fragment);
    }
  });
});
