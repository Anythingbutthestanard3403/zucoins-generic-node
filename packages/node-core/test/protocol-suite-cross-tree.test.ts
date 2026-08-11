// Cross-tree suite preimage parity + external-serialization scan (ZTR-1174 / doc 02 §4 item 8).
//
// Production builders live in packages/node-core/src/protocol/suite/.
// Contracts carries a second frozen family under reporting-tuples/ (and peers).
// Digests must agree; the anti-drift scan must cover BOTH trees.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  buildNodeEvent,
  buildReportRequest,
  EXTERNAL_SUITE_SERIALIZATION_PROHIBITED,
} from "../src/protocol/suite/index.js";
import {
  buildNodeEventPreimage,
  NODE_EVENT_GOLDEN_A,
  NODE_EVENT_GOLDEN_A_PREIMAGE,
  NODE_EVENT_GOLDEN_B,
  NODE_EVENT_GOLDEN_B_PREIMAGE,
} from "../../generic-node-contracts/src/reporting-tuples/event-tuple.ts";
import {
  buildReportRequestPreimage,
  REPORT_REQUEST_GOLDEN_PAYLOAD,
  REPORT_REQUEST_GOLDEN_PREIMAGE,
} from "../../generic-node-contracts/src/reporting-tuples/request-tuple.ts";
import { parseSha256Hex, parseUuid } from "../src/protocol/scalars.js";
import type { NodeEventType } from "../src/protocol/suite/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "../..");
const NODE_SUITE_DIR = join(HERE, "../src/protocol/suite");
const CONTRACTS_SRC = join(HERE, "../../generic-node-contracts/src");

function walkTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === "gen" || name === "dist" || name === "node_modules") continue;
    const abs = join(dir, name);
    const st = statSync(abs);
    if (st.isDirectory()) out.push(...walkTsFiles(abs));
    else if (name.endsWith(".ts") && !name.endsWith(".test.ts") && !name.endsWith(".census.test.ts")) {
      out.push(abs);
    }
  }
  return out;
}

describe("cross-tree suite preimage byte equality", () => {
  it("holds EXTERNAL_SUITE_SERIALIZATION_PROHIBITED", () => {
    expect(EXTERNAL_SUITE_SERIALIZATION_PROHIBITED).toBe(true);
  });

  it("report-request: node-core serializeSuiteTuple === contracts buildReportRequestPreimage", () => {
    const contracts = buildReportRequestPreimage(REPORT_REQUEST_GOLDEN_PAYLOAD);
    expect(contracts).toBe(REPORT_REQUEST_GOLDEN_PREIMAGE);

    const core = buildReportRequest({
      node_id: parseUuid(REPORT_REQUEST_GOLDEN_PAYLOAD.node_id),
      implementer_id: parseUuid(REPORT_REQUEST_GOLDEN_PAYLOAD.implementer_id),
      method: REPORT_REQUEST_GOLDEN_PAYLOAD.method,
      path: REPORT_REQUEST_GOLDEN_PAYLOAD.path,
      body_sha256: parseSha256Hex(REPORT_REQUEST_GOLDEN_PAYLOAD.body_sha256),
      nonce: parseUuid(REPORT_REQUEST_GOLDEN_PAYLOAD.nonce),
      issued_at: REPORT_REQUEST_GOLDEN_PAYLOAD.issued_at,
      expires_at: REPORT_REQUEST_GOLDEN_PAYLOAD.expires_at,
    });
    expect(core.preimageText).toBe(contracts);
    expect(core.preimageText).toBe(REPORT_REQUEST_GOLDEN_PREIMAGE);
  });

  it("node-event golden A/B: node-core === contracts preimage bytes", () => {
    for (const [payload, frozen] of [
      [NODE_EVENT_GOLDEN_A, NODE_EVENT_GOLDEN_A_PREIMAGE],
      [NODE_EVENT_GOLDEN_B, NODE_EVENT_GOLDEN_B_PREIMAGE],
    ] as const) {
      const contracts = buildNodeEventPreimage(payload);
      expect(contracts).toBe(frozen);
      const core = buildNodeEvent({
        node_id: parseUuid(payload.node_id),
        event_id: parseUuid(payload.event_id),
        seq: payload.seq,
        operation_id: payload.operation_id === null ? null : parseUuid(payload.operation_id),
        wallet_id: payload.wallet_id === null ? null : parseUuid(payload.wallet_id),
        event_type: payload.event_type as NodeEventType,
        data_sha256: parseSha256Hex(payload.data_sha256),
        previous_event_hash:
          payload.previous_event_hash === null
            ? null
            : parseSha256Hex(payload.previous_event_hash),
        created_at: payload.created_at,
      });
      expect(core.preimageText).toBe(contracts);
    }
  });
});

describe("external-serialization scan covers node-core suite AND contracts builder trees", () => {
  it("node-core suite: exactly one JSON.stringify, only in serialize.ts", () => {
    const files = readdirSync(NODE_SUITE_DIR).filter((n) => n.endsWith(".ts"));
    const withStringify: string[] = [];
    let total = 0;
    for (const name of files) {
      const src = readFileSync(join(NODE_SUITE_DIR, name), "utf8");
      const matches = src.match(/JSON\.stringify\s*\(/g) ?? [];
      if (matches.length > 0) withStringify.push(name);
      total += matches.length;
    }
    expect(withStringify).toEqual(["serialize.ts"]);
    expect(total).toBe(1);
  });

  it("contracts reporting-tuples: stringify confined to the known builder entry files", () => {
    // Contracts is the frozen artifact family — builders may stringify, but only inside the
    // dedicated tuple modules (not scattered across unrelated contracts sources).
    const reportingTuples = join(CONTRACTS_SRC, "reporting-tuples");
    const files = readdirSync(reportingTuples).filter(
      (n) => n.endsWith(".ts") && !n.includes(".test.") && !n.includes(".census."),
    );
    const withStringify: string[] = [];
    for (const name of files) {
      const src = readFileSync(join(reportingTuples, name), "utf8");
      if (/JSON\.stringify\s*\(/.test(src)) withStringify.push(name);
    }
    // request-tuple + event-tuple are the sanctioned contracts-side builders.
    expect(withStringify.sort()).toEqual(["event-tuple.ts", "request-tuple.ts"].sort());
  });

  it("contracts approval/landing-proof production sources do not grow ad-hoc suite stringify sites", () => {
    const watched = ["approval", "landing-proof", "reporting-auth"];
    const offenders: string[] = [];
    for (const dir of watched) {
      const abs = join(CONTRACTS_SRC, dir);
      for (const file of walkTsFiles(abs)) {
        const rel = file.slice(REPO_ROOT.length + 1);
        const src = readFileSync(file, "utf8");
        // Allow manifest snapshots / gen-sync (indent pretty JSON) and test-only files already filtered.
        if (rel.endsWith("manifest.ts") || rel.includes("/gen/")) continue;
        // approval-digest and verify may hash but should not invent suite preimages via stringify of purpose payloads.
        const matches = src.match(/JSON\.stringify\s*\(/g) ?? [];
        if (matches.length === 0) continue;
        // Flag only if the file also mentions a suite purpose string — likely a rogue builder.
        if (/zp-[a-z0-9-]+-v1/.test(src) && /JSON\.stringify\s*\(\s*\{/.test(src)) {
          offenders.push(rel);
        }
      }
    }
    expect(offenders, `unexpected suite-purpose JSON.stringify sites: ${offenders.join(", ")}`).toEqual([]);
  });
});
