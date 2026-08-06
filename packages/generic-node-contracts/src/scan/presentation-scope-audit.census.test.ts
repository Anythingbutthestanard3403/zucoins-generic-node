// the presentation scope audit scope audit — the runnable half of "product presentation stays out of the core".
//
// The frozen use-case framework names five things a hosted product may NOT push
// down into the generic node (frozen verbatim in SCOPE_AUDIT below). A prose note saying
// "we complied" is exactly the defect class this
// repo keeps producing: an artifact that ASSERTS a safety property nothing enforces. This census
// makes the claim executable in two layers, each of which goes RED on a different kind of drift:
//
//  1. GATE COVERAGE. Every frozen item maps to exactly one named gate, and each gate's rejection
//     is actually EXECUTED against the forbidden literal — the gate must reject it now, not
//     merely be cited.
//  2. SOURCE RATCHET. Each item may be named in source only inside the concern directory that
//     DECLARES it forbidden. A new file anywhere else in the package that names `PAID`, a webhook,
//     or the finality vocabulary is a reintroduction and fails, even though the declaring gate
//     itself is untouched.
//
// Lives in `src/scan/` because it must quote every forbidden literal it hunts; `src/scan/**` is the
// one directory `generic-core.scan-gate.test.ts` excludes from the forbidden-vocabulary scan, for
// exactly this reason (same arrangement as `forbidden-terms.ts` and `network-egress.census.test.ts`).
//
// Stated limit — item 5 ("product-finality claims based only on a node assertion") is a SEMANTIC
// property; no static probe decides it. Its gate is a VOCABULARY PROXY: the finality words a
// finality claim would have to be written in (`FINALISED`, `finalised`, `fulfilled`) are themselves
// rejected, so the claim cannot be stated in the core's own vocabulary. That is a real control and
// a strictly weaker one than the other four; it is labelled `vocabulary_proxy` in the table rather
// than dressed up as a decision procedure.
//
// Canonical: the instruction-origin identity rule. CONTRACT_FREEZE.

import { existsSync, globSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { FORBIDDEN_EVENT_GLOBS } from "../compat-literals/forbidden-aliases.contract.ts";
import { scanForCallbackSurfaces } from "../no-callback/callback-census.ts";
import { FORBIDDEN_EVENT_ALIASES } from "../operations/events.contract.ts";
import { OPERATION_KINDS } from "../operations/operations.contract.ts";
import { FORBIDDEN_STATE_ALIASES, OPERATION_STATES } from "../operations/states.contract.ts";
import { scanTextForForbiddenTerms } from "./forbidden-terms.ts";

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = resolve(THIS_DIR, "..");
type GateKind = "closed_enum" | "reject_list" | "surface_census" | "vocabulary_proxy";

interface ScopeAuditRow {
  /** Verbatim frozen forbidden-core-addition bullet text, backticks stripped. */
  readonly item: string;
  /** The gate that actually rejects it, named so a reader can go execute it. */
  readonly gate: string;
  readonly kind: GateKind;
  /** How the CODE literal is spotted in package source. */
  readonly sourceProbe: RegExp;
  /** How the PROSE form is spotted in a spec section (a literal can be described, not typed). */
  readonly docProbe: RegExp;
  /**
   * Concern directories under `src/` permitted to name the literal, because their job is to
   * DECLARE it rejected. Empty = the literal may not appear in package source at all.
   */
  readonly enforcedIn: readonly string[];
}

/**
 * One row per forbidden core addition. Frozen; `enforcedIn` is the drift ratchet.
 * `src/scan/**` is implicitly exempt everywhere — it is this census's own home.
 */
const SCOPE_AUDIT: readonly ScopeAuditRow[] = [
  {
    item: "CREATE_CHECKOUT",
    gate: "OPERATION_KINDS (closed 3-kind enum) + `checkout` in FORBIDDEN_TERMS",
    kind: "closed_enum",
    sourceProbe: /CREATE_CHECKOUT/,
    docProbe: /CREATE_CHECKOUT/,
    enforcedIn: [],
  },
  {
    item: "payment.succeeded",
    gate: "FORBIDDEN_EVENT_GLOBS `payment.*` + `payment` in FORBIDDEN_TERMS",
    kind: "reject_list",
    sourceProbe: /payment\.succeeded/,
    docProbe: /payment\.succeeded/,
    enforcedIn: [],
  },
  {
    item: "PAID",
    gate: "FORBIDDEN_STATE_ALIASES (state-event reference reject-list)",
    kind: "reject_list",
    sourceProbe: /\bPAID\b/,
    docProbe: /\bPAID\b/,
    enforcedIn: ["operations"],
  },
  {
    item: "merchant webhook delivery",
    gate: "scanForCallbackSurfaces + `merchant` in FORBIDDEN_TERMS",
    kind: "surface_census",
    sourceProbe: /\bwebhooks?\b/i,
    docProbe: /\bwebhooks?\b/i,
    // no-callback owns the surface census; drift-audit re-asserts the same forbid against
    // numbered core specs (dispositions.test.ts). Both declare the ban, neither implement it.
    enforcedIn: ["no-callback", "drift-audit"],
  },
  {
    item: "product-finality claims based only on a node assertion",
    gate: "FORBIDDEN_EVENT_ALIASES `transfer.finalised` + `finalised`/`fulfilled` in FORBIDDEN_TERMS",
    kind: "vocabulary_proxy",
    sourceProbe: /\b(?:FINALISED|finalised|fulfilled)\b/,
    docProbe: /\bfinalit(?:y|ies)\b|\bfulfil/i,
    enforcedIn: ["operations"],
  },
] as const;

describe("the presentation scope audit scope audit — 2. every forbidden addition has a gate that rejects it today", () => {
  it("the frozen item list is exactly the five frozen additions, each named once", () => {
    expect(SCOPE_AUDIT.map((r) => r.item)).toEqual([
      "CREATE_CHECKOUT",
      "payment.succeeded",
      "PAID",
      "merchant webhook delivery",
      "product-finality claims based only on a node assertion",
    ]);
    expect(new Set(SCOPE_AUDIT.map((r) => r.item)).size).toBe(SCOPE_AUDIT.length);
  });

  it("CREATE_CHECKOUT: the operation-kind enum is closed and does not admit it", () => {
    // Do not restate the three frozen kind literals here — that is an OperationKind
    // re-declaration and fails the operations drift gate (the scan/dependency-boundary gate). Length + absence is enough.
    expect(OPERATION_KINDS).toHaveLength(3);
    expect((OPERATION_KINDS as readonly string[]).includes("CREATE_CHECKOUT")).toBe(false);
    expect(scanTextForForbiddenTerms("const kind = CREATE_CHECKOUT; // checkout", "x.ts")).not.toEqual([]);
  });

  it("payment.succeeded: the event-name glob reject-list covers it", () => {
    expect(FORBIDDEN_EVENT_GLOBS).toContain("payment.*");
    const covered = FORBIDDEN_EVENT_GLOBS.some(
      (glob) => glob.endsWith(".*") && "payment.succeeded".startsWith(glob.slice(0, -1)),
    );
    expect(covered).toBe(true);
    expect(scanTextForForbiddenTerms('emit("payment.succeeded");', "x.ts")).not.toEqual([]);
  });

  it("PAID: it is on the state reject-list and in no operation's state set", () => {
    expect(FORBIDDEN_STATE_ALIASES).toContain("PAID");
    for (const [kind, states] of Object.entries(OPERATION_STATES)) {
      expect({ kind, hasPaid: (states as readonly string[]).includes("PAID") }).toEqual({ kind, hasPaid: false });
    }
  });

  it("merchant webhook delivery: the callback-surface census flags it and the term scan rejects it", () => {
    expect(scanForCallbackSurfaces('app.post("/webhooks/merchant", handler);')).not.toEqual([]);
    expect(scanTextForForbiddenTerms("deliver to the merchant endpoint", "x.ts")).not.toEqual([]);
  });

  it("product-finality: the finality vocabulary is rejected as event name and as bare term", () => {
    // vocabulary_proxy — see the file header. The claim cannot be STATED in core vocabulary.
    expect(FORBIDDEN_EVENT_ALIASES).toContain("transfer.finalised");
    expect(scanTextForForbiddenTerms("the transfer is finalised", "x.ts")).not.toEqual([]);
    expect(scanTextForForbiddenTerms("the order was fulfilled", "x.ts")).not.toEqual([]);
  });

  it("negative control: an ordinary generic-core line trips none of the term gates", () => {
    expect(scanTextForForbiddenTerms("export const OPERATION_KINDS = [] as const;", "x.ts")).toEqual([]);
    expect(scanForCallbackSurfaces("const rows = [];\nrows.push(1);")).toEqual([]);
  });
});

describe("the presentation scope audit scope audit — 4. source ratchet: only the declaring concern may name it", () => {
  const sourceFiles = globSync(join(SRC_ROOT, "**", "*.ts")).filter(
    (f) => !relative(SRC_ROOT, f).startsWith("scan" + "/"),
  );

  it("the walk found the package source (not an empty glob reporting a vacuous pass)", () => {
    expect(sourceFiles.length).toBeGreaterThan(50);
  });

  for (const row of SCOPE_AUDIT) {
    it(`"${row.item}" appears only under ${row.enforcedIn.length > 0 ? row.enforcedIn.join(", ") : "(nowhere)"}`, () => {
      const offenders = sourceFiles
        .filter((f) => row.sourceProbe.test(readFileSync(f, "utf8")))
        .map((f) => relative(SRC_ROOT, f))
        .filter((rel) => !row.enforcedIn.includes(rel.split("/")[0] ?? ""))
        .sort();
      expect(offenders).toEqual([]);
    });
  }

  it("positive control: the ratchet flags a literal placed outside its declaring concern", () => {
    const row = SCOPE_AUDIT.find((r) => r.item === "PAID");
    expect(row).toBeDefined();
    const reintroduced = relative(SRC_ROOT, join(SRC_ROOT, "instruction-origin", "invented.ts"));
    expect(row?.sourceProbe.test('const state = "PAID";')).toBe(true);
    expect(row?.enforcedIn.includes(reintroduced.split("/")[0] ?? "")).toBe(false);
  });
});

describe("the presentation scope audit scope audit — 5. the exercised consumer path carries no product vocabulary", () => {
  /**
   * Transitive relative-import closure of the reference consumer, within this package. The tree
   * mixes `.ts` and NodeNext `.js` specifiers for the same on-disk `.ts` file (compare
   * `instruction-origin/index.ts` with `no-callback/index.ts`), so a `.js` specifier is resolved
   * back to its `.ts` source; anything still unresolvable is a broken import and fails loudly.
   */
  function importClosure(entry: string): string[] {
    const seen = new Set<string>();
    const queue = [entry];
    while (queue.length > 0) {
      const file = queue.pop() as string;
      if (seen.has(file)) continue;
      seen.add(file);
      const source = readFileSync(file, "utf8");
      for (const [, spec] of source.matchAll(/from\s+"(\.[^"]+)"/g)) {
        const target = resolve(dirname(file), spec);
        const onDisk = existsSync(target) ? target : target.replace(/\.js$/, ".ts");
        if (!existsSync(onDisk)) throw new Error(`unresolvable import "${spec}" in ${relative(SRC_ROOT, file)}`);
        queue.push(onDisk);
      }
    }
    return [...seen].sort();
  }

  const exercised = importClosure(join(SRC_ROOT, "instruction-origin", "consumer-boundary.ts"));

  it("the closure resolved the real module graph", () => {
    const rels = exercised.map((f) => relative(SRC_ROOT, f));
    expect(rels).toContain(join("instruction-origin", "consumer-boundary.ts"));
    expect(rels).toContain(join("instruction-origin", "identity-pin.contract.ts"));
    expect(rels).toContain(join("artifacts", "verify.ts"));
    expect(exercised.length).toBeGreaterThan(3);
  });

  it("zero checkout / widget / merchant / payment-session symbols anywhere in it", () => {
    const productVocabulary = /\bcheckouts?\b|\bwidgets?\b|\bmerchants?\b|\bpayment[_ -]?sessions?\b/i;
    const offenders = exercised
      .filter((f) => productVocabulary.test(readFileSync(f, "utf8")))
      .map((f) => relative(SRC_ROOT, f));
    expect(offenders).toEqual([]);
  });

  it("positive control: that probe does detect product vocabulary when present", () => {
    expect(/\bcheckouts?\b|\bwidgets?\b|\bmerchants?\b|\bpayment[_ -]?sessions?\b/i.test("const paymentSession = 1;")).toBe(
      true,
    );
  });
});
