/**
 * REGRESSION CORPUS REPLAY (amendment 9 / JC5).
 *
 * Seed-independent: each saved counterexample is executed DIRECTLY (not via fast-check
 * sampling), so a shrunk regression stays pinned regardless of generator/seed drift. The guard
 * asserts the corpus is non-empty AND that every entry is actually executed.
 *
 * TEST-ONLY.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  MOVE_INTERNAL_TRANSITIONS,
  SEND_EXTERNAL_TRANSITIONS,
} from "../../generic-node-contracts/src/operations/states.contract.ts";
import {
  classifyReceiveReconcile,
  classifyMoveReconcile,
  classifySendReconcile,
  type MoveReconcileInput,
  type ReceiveReconcileInput,
  type SendReconcileInput,
} from "../src/protocol/reconcile/index.js";
import { classifyObservedTransition, type ObservedTransition } from "./lifecycle-fuzz-oracles.ts";

interface CorpusEntry {
  readonly id: string;
  readonly kind: string;
  readonly input?: unknown;
  readonly observed?: ObservedTransition;
  readonly expected: { readonly kind?: string; readonly reasonSource?: string; readonly verdict?: string };
}

const corpusPath = fileURLToPath(
  new URL("./__fuzz-corpus__/lifecycle/regressions.json", import.meta.url),
);
const corpus = JSON.parse(readFileSync(corpusPath, "utf8")) as { readonly entries: CorpusEntry[] };

describe("regression corpus replays deterministically", () => {
  it("corpus is non-empty", () => {
    expect(corpus.entries.length).toBeGreaterThan(0);
  });

  let executed = 0;
  it.each(corpus.entries)("$id replays to its recorded outcome", (entry) => {
    switch (entry.kind) {
      case "reconcile-receive": {
        const out = classifyReceiveReconcile(entry.input as ReceiveReconcileInput);
        expect(out.kind).toBe(entry.expected.kind);
        break;
      }
      case "reconcile-move": {
        const out = classifyMoveReconcile(entry.input as MoveReconcileInput);
        expect(out.kind).toBe(entry.expected.kind);
        break;
      }
      case "reconcile-send": {
        const out = classifySendReconcile(entry.input as SendReconcileInput);
        expect(out.kind).toBe(entry.expected.kind);
        if (entry.expected.reasonSource !== undefined && out.kind === "INVARIANT_BREACH") {
          expect(out.reason.source).toBe(entry.expected.reasonSource);
        }
        break;
      }
      case "transition-send":
        expect(classifyObservedTransition(SEND_EXTERNAL_TRANSITIONS, entry.observed!).verdict).toBe(
          entry.expected.verdict,
        );
        break;
      case "transition-move":
        expect(classifyObservedTransition(MOVE_INTERNAL_TRANSITIONS, entry.observed!).verdict).toBe(
          entry.expected.verdict,
        );
        break;
      default:
        throw new Error(`unknown corpus entry kind: ${entry.kind}`);
    }
    executed += 1;
  });

  it("every corpus entry was executed", () => {
    expect(executed).toBe(corpus.entries.length);
  });
});
