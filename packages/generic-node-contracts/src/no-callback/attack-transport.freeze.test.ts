// Attack callback transport and replay census. With callbacks
// removed there is no transport to attack, so this suite proves the removal holds by construction:
//
//  (1) EGRESS-ABSENCE — every operation's egress census grants only the configured gateway;
//      isEgressAllowed rejects every non-gateway destination class (operator http/https URLs,
//      DNS-rebinding IPs, redirect targets, loopback, link-local, cloud-metadata, RFC1918); and no
//      callback field / route / worker identifier exists anywhere in the contract package outside
//      the frozen REJECTED_SURFACES data (a package-source census with a positive control).
//  (2) CURSOR-AUTHORITY — the authoritative pull cursor + node-global hash chain is complete and authoritative
//      (consuming reporting-behavior's tenant-seq / chain-append rules and event-sequencing's gap-detection facts);
//      SSE is a wake accelerator that never advances a cursor and is never authoritative.
//
// One negative per dimension: an egress-allowing model is rejected; an SSE-advances-cursor model is
// rejected.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import golden from "./gen/attack-surface.json" with { type: "json" };
import { NODE_EVENT_A_EVENT_HASH, NODE_EVENT_PURPOSE } from "../reporting-tuples/index.js";
import { evaluateChainAppend } from "../reporting-behavior/index.js";
import {
  ALLOWED_EGRESS_KIND,
  AUTHORITATIVE_CHANNELS,
  AUTHORITATIVE_CURSOR_ROLE,
  AUTHORITATIVE_EVENT_PURPOSE,
  NEUTRALIZED_BY_EGRESS_ABSENCE,
  NEUTRALIZED_BY_PULL_CURSOR,
  NEUTRALIZED_REPLAY_ATTACKS,
  NEUTRALIZED_TRANSPORT_ATTACKS,
  NON_GATEWAY_DESTINATION_CLASSES,
  OPERATION_EGRESS,
  SSE_ACCELERATOR_ROLE,
  attackIsNeutralized,
  buildAttackSurfaceManifest,
  buildNoCallbackManifest,
  egressCensusIsClean,
  egressRowIsClean,
  gapDetectorIsChainNotContiguity,
  isConcernPathExempt,
  isEgressAllowed,
  pullIsSoleCursorAuthority,
  scanForCallbackSurfaces,
  sparseTenantViewIsComplete,
  sseModelKeepsCursorAuthority,
} from "./index.js";

const GATEWAY_HOSTS = ["gateway.splitchain.test"] as const;
const ZERO_HASH = "0".repeat(64);

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = resolve(THIS_DIR, "..");

// callback-census.ts is the DETECTOR module — it names the forbidden vocabulary as its patterns, so
// scanning it would be self-defeating (same principle as a neutrality gate keeping its word
// list outside the scanned tree). Test files are detector exercises / bad-input fixtures, not the
// shipped contract surface, so they are likewise not part of the census.
const DETECTOR_MODULE = resolve(THIS_DIR, "callback-census.ts");

function collectSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "dist") continue;
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectSourceFiles(full));
    } else if (entry.name.endsWith(".ts") || entry.name.endsWith(".json")) {
      out.push(full);
    }
  }
  return out;
}

// The shipped contract source the census scans: every .ts/.json under src/ except the detector
// module and the *.test.ts detector exercises.
function scannableSourceFiles(): string[] {
  return collectSourceFiles(SRC_ROOT).filter((f) => f !== DETECTOR_MODULE && !f.endsWith(".test.ts"));
}

// The surface labels the no-callback concern is permitted to declare — the "known metadata
// contexts", derived from its two FROZEN goldens so the allowlist cannot drift silently: a newly
// declared surface must change a golden (and its freeze test) to be admitted.
const CONCERN_ALLOWED_LABELS = new Set([
  ...scanForCallbackSurfaces(readFileSync(resolve(THIS_DIR, "gen/no-callback.json"), "utf8")),
  ...scanForCallbackSurfaces(readFileSync(resolve(THIS_DIR, "gen/attack-surface.json"), "utf8")),
]);

function surfaceOffenders(files: readonly string[], allowed: ReadonlySet<string>): Array<{ file: string; labels: string[] }> {
  return files
    .map((file) => ({ file, labels: scanForCallbackSurfaces(readFileSync(file, "utf8")).filter((l) => !allowed.has(l)) }))
    .filter((r) => r.labels.length > 0);
}

describe("attack-surface manifest freeze", () => {
  it("serialized attack-surface manifest matches the committed golden snapshot", () => {
    expect(buildAttackSurfaceManifest()).toEqual(golden);
  });
});

describe("egress-absence: every transport attack is neutralized by construction", () => {
  it("all three operations grant zero non-gateway egress (only the configured gateway)", () => {
    expect(ALLOWED_EGRESS_KIND).toBe("configured_splitchain_gateway_only");
    expect(egressCensusIsClean()).toBe(true);
    for (const row of OPERATION_EGRESS) {
      expect(egressRowIsClean(row)).toBe(true);
    }
  });

  it("isEgressAllowed rejects every non-gateway destination class (SSRF / rebind / redirect / private)", () => {
    for (const dest of NON_GATEWAY_DESTINATION_CLASSES) {
      expect(isEgressAllowed(dest.exampleHost, GATEWAY_HOSTS)).toBe(false);
    }
    expect(isEgressAllowed(GATEWAY_HOSTS[0], GATEWAY_HOSTS)).toBe(true);
  });

  it("every transport attack neutralizes by egress-absence; every replay attack by the pull cursor", () => {
    for (const a of NEUTRALIZED_TRANSPORT_ATTACKS) {
      expect(attackIsNeutralized(a)).toBe(true);
      expect(a.neutralizedBy).toBe(NEUTRALIZED_BY_EGRESS_ABSENCE);
    }
    for (const a of NEUTRALIZED_REPLAY_ATTACKS) {
      expect(attackIsNeutralized(a)).toBe(true);
      expect(a.neutralizedBy).toBe(NEUTRALIZED_BY_PULL_CURSOR);
    }
  });
});

describe("package census: no callback/webhook/push surface outside declared metadata", () => {
  it("no non-concern contract source declares any callback/webhook/push surface", () => {
    const nonConcern = scannableSourceFiles().filter((f) => !isConcernPathExempt(f, THIS_DIR));
    // Non-concern files get no metadata allowance at all — the empty allowlist.
    expect(surfaceOffenders(nonConcern, new Set())).toEqual([]);
  });

  it("concern contract source declares surfaces only in known metadata contexts (frozen goldens)", () => {
    const concern = scannableSourceFiles().filter((f) => isConcernPathExempt(f, THIS_DIR));
    expect(surfaceOffenders(concern, CONCERN_ALLOWED_LABELS)).toEqual([]);
  });

  it("positive control: the census detects a real callback/webhook/push surface (not vacuously green)", () => {
    expect(CONCERN_ALLOWED_LABELS.size).toBeGreaterThan(0);
    expect(scanForCallbackSurfaces('router.post("/callbacks", handler);')).toContain("callback_route");
    expect(scanForCallbackSurfaces("registerWebhook(cfg)")).toContain("register_push_endpoint");
    expect(scanForCallbackSurfaces('const leak = "https://operator.example/hook";')).toContain("outbound_url_literal");
  });

  it("the live no-callback contract (minus REJECTED_SURFACES) carries no surface", () => {
    const live = { ...buildNoCallbackManifest(), rejectedSurfaces: [] };
    expect(scanForCallbackSurfaces(JSON.stringify(live))).toEqual([]);
    // Positive control: the full manifest (with rejected data) does contain surfaces.
    expect(scanForCallbackSurfaces(JSON.stringify(buildNoCallbackManifest())).length).toBeGreaterThan(0);
  });
});

describe("cursor-authority: the pull cursor + hash chain is complete and authoritative", () => {
  it("exactly the pull channel is authoritative; SSE holds only the accelerator role", () => {
    expect(pullIsSoleCursorAuthority(AUTHORITATIVE_CHANNELS)).toBe(true);
    const pull = AUTHORITATIVE_CHANNELS.find((c) => c.channel === "pull_events");
    const sse = AUTHORITATIVE_CHANNELS.find((c) => c.channel === "sse_stream");
    // Bind the role markers to the frozen channel roles by value (earlier slice wins).
    expect(pull?.role).toBe(AUTHORITATIVE_CURSOR_ROLE);
    expect(sse?.role).toBe(SSE_ACCELERATOR_ROLE);
    expect(AUTHORITATIVE_EVENT_PURPOSE).toBe(NODE_EVENT_PURPOSE);
  });

  it("a sparse tenant view is complete (tenant-seq + gap-detection)", () => {
    // Cursor at 5; next visible tenant event is seq 9 — the skipped 6,7,8 are other tenants' events,
    // not gaps, so the view is complete under the node-global hash chain.
    expect(sparseTenantViewIsComplete(5n, 9n)).toBe(true);
  });

  it("gaps are chain-detected, never seq-contiguity-detected (chain-append rule)", () => {
    expect(gapDetectorIsChainNotContiguity()).toBe(true);
    expect(evaluateChainAppend(NODE_EVENT_A_EVENT_HASH, NODE_EVENT_A_EVENT_HASH)).toBe("ACCEPT_CHAIN");
    expect(evaluateChainAppend(NODE_EVENT_A_EVENT_HASH, ZERO_HASH)).toBe("HARD_STOP_CHAIN_BREAK");
  });

  it("SSE never advances a cursor and is never authoritative", () => {
    expect(sseModelKeepsCursorAuthority({ channel: "sse_stream", advancesCursor: false })).toBe(true);
  });
});

describe("attack-census negative path (one per dimension)", () => {
  it("egress dimension: an egress-allowing model is rejected", () => {
    expect(isEgressAllowed("operator.example.com", GATEWAY_HOSTS)).toBe(false);
    expect(egressRowIsClean({ operation: "RECEIVE_EXTERNAL", nonGatewayEgress: "operator_url" })).toBe(false);
  });

  it("cursor dimension: an SSE-advances-cursor model is rejected", () => {
    expect(sseModelKeepsCursorAuthority({ channel: "sse_stream", advancesCursor: true })).toBe(false);
    expect(
      pullIsSoleCursorAuthority([
        { channel: "pull_events", role: AUTHORITATIVE_CURSOR_ROLE },
        { channel: "sse_stream", role: AUTHORITATIVE_CURSOR_ROLE },
      ]),
    ).toBe(false);
  });
});
