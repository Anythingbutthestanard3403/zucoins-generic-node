// Census gate (ZTR-1146): every DURABLE_EVENTS value must have a production emitter
// that reaches the implementer stream (dual-chain appender or implementer leg).
//
// The existing events.census.test.ts only proves the vocabulary is closed at nine.
// This file proves each of the nine is reachable on the tenant stream — the hole
// that let six of nine stay slice-local / unwritten.
//
// Detection: a production `.ts` file (excluding tests, goldens, contracts packages)
// must reference the event literal in the same file as one of:
//   - createDualChainEventAppender
//   - appendDurableDualChainEvent
//   - appendTerminalLandedEvent
//   - appendImplementerEventLeg
// Composition-root wiring in apps/generic-node counts (that is where several
// dual-chain ports are bound).

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { DURABLE_EVENTS } from "../../generic-node-contracts/src/operations/events.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");

const DUAL_CHAIN_MARKERS = [
  "createDualChainEventAppender",
  "appendDurableDualChainEvent",
  "appendTerminalLandedEvent",
  "appendImplementerEventLeg",
] as const;

const SCAN_ROOTS = [
  resolve(repoRoot, "packages/node-core/src"),
  resolve(repoRoot, "apps/generic-node/src"),
] as const;

function walkTsFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "dist" || name === "gen") continue;
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      walkTsFiles(full, out);
      continue;
    }
    if (!name.endsWith(".ts")) continue;
    if (name.endsWith(".test.ts") || name.endsWith(".pg.test.ts")) continue;
    if (name.includes(".census.")) continue;
    out.push(full);
  }
  return out;
}

/** Known production constants that hold a DURABLE_EVENTS literal. */
const EVENT_CONST_ALIASES: Readonly<Record<string, readonly string[]>> = {
  "receive.ready": ["RECEIVE_READY_EVENT"],
  "receive.landed": ["RECEIVE_LANDED_EVENT"],
  "internal_move.created": [],
  "internal_move.landed": [],
  "external_send.created": [],
  "external_send.awaiting_redemption": ["EXTERNAL_SEND_AWAITING_REDEMPTION_EVENT"],
  "external_send.landed": ["EXTERNAL_SEND_LANDED_EVENT"],
  "operation.needs_attention": [
    "OPERATION_NEEDS_ATTENTION_EVENT",
    "RECEIVE_NEEDS_ATTENTION_EVENT",
  ],
  "operation.expired": ["RECEIVE_EXPIRED_EVENT"],
};

function sourceNamesEvent(source: string, eventType: string): boolean {
  // String / template / comment mentions of the closed literal.
  if (
    source.includes(`"${eventType}"`) ||
    source.includes(`'${eventType}'`) ||
    source.includes(`\`${eventType}\``) ||
    source.includes(eventType)
  ) {
    // Bare substring is enough when paired with a dual-chain marker below — the
    // closed nine-value set has no overlapping prefixes.
    return true;
  }
  const aliases = EVENT_CONST_ALIASES[eventType] ?? [];
  return aliases.some((alias) => source.includes(alias));
}

function fileReachesImplementerStream(source: string, eventType: string): boolean {
  if (!sourceNamesEvent(source, eventType)) return false;
  return DUAL_CHAIN_MARKERS.some((marker) => source.includes(marker));
}

describe("durable events implementer-stream emitter census (ZTR-1146)", () => {
  const files = SCAN_ROOTS.flatMap((root) => walkTsFiles(root));
  const sources = files.map((path) => ({
    path: relative(repoRoot, path),
    text: readFileSync(path, "utf8"),
  }));

  it("scans production source trees (not vacuously empty)", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  it("every DURABLE_EVENTS value has a production emitter reaching the implementer stream", () => {
    const missing: string[] = [];
    const found: Record<string, string[]> = {};
    for (const eventType of DURABLE_EVENTS) {
      const hits = sources
        .filter((s) => fileReachesImplementerStream(s.text, eventType))
        .map((s) => s.path);
      found[eventType] = hits;
      if (hits.length === 0) missing.push(eventType);
    }
    expect(missing, `missing implementer-stream emitters: ${JSON.stringify(found, null, 2)}`).toEqual(
      [],
    );
  });

  it("mutation negative: dropping external_send.created dual-chain marker fails the census", () => {
    const mutated = sources.map((s) => ({
      ...s,
      text:
        s.path.includes("main.ts") || s.path.includes("sql-store.ts")
          ? s.text
              .replaceAll('"external_send.created"', '"external_send.CREATED_MUTATED"')
              .replaceAll("'external_send.created'", "'external_send.CREATED_MUTATED'")
          : s.text,
    }));
    const hits = mutated.filter((s) =>
      fileReachesImplementerStream(s.text, "external_send.created"),
    );
    expect(hits).toEqual([]);
  });

  /**
   * Path-complete gate for SEND park (ZTR-1146 rework): production sites that run
   * CAS_AWAITING_TO_NEEDS_ATTENTION must co-locate a dual-chain marker (or the library
   * dualChain emitter port). A single receive hit must not green
   * `operation.needs_attention` while the live SEND lander park stays slice-local.
   */
  it("every CAS_AWAITING_TO_NEEDS_ATTENTION production site co-locates a dual-chain marker", () => {
    const casSites = sources.filter((s) => s.text.includes("CAS_AWAITING_TO_NEEDS_ATTENTION"));
    expect(
      casSites.map((s) => s.path),
      "expected production CAS_AWAITING_TO_NEEDS_ATTENTION call sites",
    ).not.toEqual([]);

    const bare: string[] = [];
    for (const site of casSites) {
      const hasDual = DUAL_CHAIN_MARKERS.some((marker) => site.text.includes(marker));
      // Library helper may bind dual-chain via SendExpiryDualChainEmitter rather than
      // importing the appender by name — still counts as a dual-chain neighbor.
      const hasLibraryPort =
        site.text.includes("SendExpiryDualChainEmitter") ||
        site.text.includes("input.dualChain");
      if (!hasDual && !hasLibraryPort) bare.push(site.path);
    }
    expect(
      bare,
      `CAS_AWAITING_TO_NEEDS_ATTENTION without dual-chain marker (SEND park must project operation.needs_attention): ${bare.join(", ")}`,
    ).toEqual([]);
  });

  it("send-completion-lander parks with dual-chain operation.needs_attention", () => {
    const lander = sources.find((s) =>
      s.path.replaceAll("\\", "/").endsWith("money-workers/send-completion-lander.ts"),
    );
    expect(lander, "send-completion-lander.ts must be in the production scan").toBeDefined();
    expect(fileReachesImplementerStream(lander!.text, "operation.needs_attention")).toBe(true);
    expect(lander!.text.includes("CAS_AWAITING_TO_NEEDS_ATTENTION")).toBe(true);
    // Live production park path must call the appender directly (not only a dead library port).
    expect(lander!.text.includes("appendDurableDualChainEvent")).toBe(true);
  });
});
