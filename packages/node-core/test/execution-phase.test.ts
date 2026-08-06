// The public `execution_phase` derivation.
//
// Two proofs live here. The docs-artifact half extracts BOTH canon tables from the live
// markdown — state/event's phase vocabulary and the data model's precedence/required-fact
// table — and binds the module's literals and evaluation order to them, so an unreviewed doc edit
// or a drift in this module is a red test rather than a silent divergence. The behavioural half
// walks every phase for every operation kind, including the cases where two kinds read the SAME
// attempt_phase as different public phases, which is the whole reason the mapping is not a copy
// of attempt_phase.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { OPERATION_KINDS } from "../../generic-node-contracts/src/operations/operations.contract.ts";
import {
  ATTEMPT_PHASE_LADDER,
  EXECUTION_PHASES,
  EXECUTION_PHASE_APPLIES_TO,
  EXECUTION_PHASE_PRECEDENCE,
  deriveExecutionPhase,
  type AttemptPhase,
  type DurableExecutionFacts,
  type ExecutionPhase,
} from "../src/core/execution-phase.ts";
import { TRANSACTION_MATERIAL_PHASE_VOCABULARY } from "../src/schema/transaction-material.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const appendixB = readFileSync(resolve(here, "state-event-reference.fixture.md"), "utf8");
const dataModel = readFileSync(resolve(here, "data-model.fixture.md"), "utf8");

/** Rows of the single pipe table inside `[startHeading, endHeading)`, header/rule dropped. */
const tableRows = (doc: string, startHeading: string, endHeading: string): string[][] => {
  const start = doc.indexOf(startHeading);
  if (start === -1) throw new Error(`heading not found: ${startHeading}`);
  const end = doc.indexOf(endHeading, start);
  if (end === -1) throw new Error(`heading not found after ${startHeading}: ${endHeading}`);
  return doc
    .slice(start, end)
    .split("\n")
    .filter((line) => line.trim().startsWith("|"))
    .map((line) =>
      line
        .trim()
        .replace(/^\|/, "")
        .replace(/\|$/, "")
        .split("|")
        .map((cell) => cell.trim()),
    )
    .filter((cells) => !cells[0]!.startsWith("---") && cells[0] !== "Phase")
    .filter((cells) => cells[0] !== "Public `execution_phase`");
};

const unbacktick = (cell: string): string => cell.replaceAll("`", "");

// The kinds named in a canon "Applies to" cell, mapped onto frozen OperationKind values.
const kindsIn = (cell: string): string[] => {
  if (cell === "all") return [...OPERATION_KINDS];
  const named: string[] = [];
  if (/\breceive\b/.test(cell)) named.push("RECEIVE_EXTERNAL");
  if (/\bmove\b/.test(cell)) named.push("MOVE_INTERNAL");
  if (/\bsend\b/.test(cell)) named.push("SEND_EXTERNAL");
  return named;
};

describe("execution_phase vocabulary is bound to canon, not minted here", () => {
  it("state/event's table supplies the seven phases, in that order", () => {
    const rows = tableRows(appendixB, "## 3. Orthogonal execution phase", "## 4. Attention reasons");
    expect(rows.map((cells) => unbacktick(cells[0]!))).toEqual([...EXECUTION_PHASES]);
  });

  it("state/event's `Applies to` column supplies the per-kind applicability", () => {
    const rows = tableRows(appendixB, "## 3. Orthogonal execution phase", "## 4. Attention reasons");
    for (const cells of rows) {
      const phase = unbacktick(cells[0]!) as ExecutionPhase;
      // Canon orders receive/move/send; the module carries the frozen OPERATION_KINDS order.
      expect([...EXECUTION_PHASE_APPLIES_TO[phase]].sort(), phase).toEqual(
        kindsIn(cells[1]!).sort(),
      );
    }
    // DELIVERED is send-only and the submit phases exclude send (mandatory DB test 11). Asserted
    // explicitly so a canon table that ever widened them could not pass unnoticed.
    expect(EXECUTION_PHASE_APPLIES_TO.DELIVERED).toEqual(["SEND_EXTERNAL"]);
    expect(EXECUTION_PHASE_APPLIES_TO.SUBMIT_STARTED).not.toContain("SEND_EXTERNAL");
    expect(EXECUTION_PHASE_APPLIES_TO.SUBMIT_RETURNED).not.toContain("SEND_EXTERNAL");
  });

  it("data-model's derivation table supplies the precedence order, the reverse of advance order", () => {
    const rows = tableRows(dataModel, "| Public `execution_phase` | Required durable fact |", "## 10.");
    expect(rows.map((cells) => unbacktick(cells[0]!))).toEqual([...EXECUTION_PHASE_PRECEDENCE]);
    expect([...EXECUTION_PHASE_PRECEDENCE].reverse()).toEqual([...EXECUTION_PHASES]);
    // Same set, two orders — neither list may gain or lose a member.
    expect([...EXECUTION_PHASE_PRECEDENCE].sort()).toEqual([...EXECUTION_PHASES].sort());
  });

  // The ladder is declared in src/core/execution-phase.ts rather than imported from
  // src/schema, because node-core's dependency fence forbids a `core` file importing `schema`
  // (test/boundaries.test.ts). This assertion is what keeps the two from drifting: it is the
  // reason the declaration is safe, so deleting it removes the only link to the frozen SQL
  // contract. Member sequence is asserted too — the ladder's sequence is load-bearing for
  // advance and precedence.
  it("the attempt-phase ladder matches the frozen SQL-contract inventory exactly", () => {
    expect([...ATTEMPT_PHASE_LADDER]).toEqual([
      ...TRANSACTION_MATERIAL_PHASE_VOCABULARY.attemptPhaseLiterals,
    ]);
    // The two vocabularies are disjoint and neither derives from the other.
    const shared = (ATTEMPT_PHASE_LADDER as readonly string[]).filter((phase) =>
      (EXECUTION_PHASES as readonly string[]).includes(phase),
    );
    expect(shared).toEqual([]);
  });
});

const NOTHING: Omit<DurableExecutionFacts, "operationKind"> = {
  attemptPhase: null,
  signIntentPersisted: false,
  partialPersisted: false,
  partialFirstDelivered: false,
  submitStarted: false,
  submitReturned: false,
  verificationAccepted: false,
  terminalObservationsPresent: false,
};

const facts = (
  operationKind: DurableExecutionFacts["operationKind"],
  overrides: Partial<DurableExecutionFacts> = {},
): DurableExecutionFacts => ({ ...NOTHING, operationKind, ...overrides });

describe("deriveExecutionPhase — data-model precedence over durable facts", () => {
  it("NOT_STARTED when no subrecord exists, for every kind", () => {
    for (const kind of OPERATION_KINDS) {
      expect(deriveExecutionPhase(facts(kind)), kind).toBe("NOT_STARTED");
    }
  });

  it("MOVE: INNER_PREIMAGE_PERSISTED is PREIMAGE_PERSISTED; every later phase is SIGNED_PERSISTED", () => {
    expect(deriveExecutionPhase(facts("MOVE_INTERNAL", { attemptPhase: "INNER_PREIMAGE_PERSISTED" }))).toBe(
      "PREIMAGE_PERSISTED",
    );
    for (const phase of ATTEMPT_PHASE_LADDER.slice(1)) {
      expect(deriveExecutionPhase(facts("MOVE_INTERNAL", { attemptPhase: phase })), phase).toBe(
        "SIGNED_PERSISTED",
      );
    }
  });

  it("RECEIVE: only STEP2_PREIMAGE_PERSISTED is PREIMAGE_PERSISTED; step-2 signature onward is SIGNED_PERSISTED", () => {
    const expected: Record<AttemptPhase, ExecutionPhase> = {
      // The payer's step-1 signature is not a NODE signature and the node's own next-signing
      // preimage is not persisted yet, so no row of data-model's table applies to either of these.
      INNER_PREIMAGE_PERSISTED: "NOT_STARTED",
      STEP1_SIGNATURE_PERSISTED: "NOT_STARTED",
      STEP2_PREIMAGE_PERSISTED: "PREIMAGE_PERSISTED",
      STEP2_SIGNATURE_PERSISTED: "SIGNED_PERSISTED",
      SETTLED_BODY_PERSISTED: "SIGNED_PERSISTED",
    };
    for (const phase of ATTEMPT_PHASE_LADDER) {
      expect(deriveExecutionPhase(facts("RECEIVE_EXTERNAL", { attemptPhase: phase })), phase).toBe(
        expected[phase],
      );
    }
  });

  it("the same attempt_phase derives DIFFERENT public phases per kind — the mapping is not a copy", () => {
    const step1 = { attemptPhase: "STEP1_SIGNATURE_PERSISTED" } as const;
    expect(deriveExecutionPhase(facts("MOVE_INTERNAL", step1))).toBe("SIGNED_PERSISTED");
    expect(deriveExecutionPhase(facts("RECEIVE_EXTERNAL", step1))).toBe("NOT_STARTED");
    const step2Preimage = { attemptPhase: "STEP2_PREIMAGE_PERSISTED" } as const;
    expect(deriveExecutionPhase(facts("MOVE_INTERNAL", step2Preimage))).toBe("SIGNED_PERSISTED");
    expect(deriveExecutionPhase(facts("RECEIVE_EXTERNAL", step2Preimage))).toBe("PREIMAGE_PERSISTED");
  });

  it("SEND: sign intent alone is PREIMAGE_PERSISTED; the partial or node step 1 is SIGNED_PERSISTED", () => {
    expect(deriveExecutionPhase(facts("SEND_EXTERNAL", { signIntentPersisted: true }))).toBe(
      "PREIMAGE_PERSISTED",
    );
    expect(
      deriveExecutionPhase(
        facts("SEND_EXTERNAL", {
          signIntentPersisted: true,
          attemptPhase: "INNER_PREIMAGE_PERSISTED",
        }),
      ),
    ).toBe("PREIMAGE_PERSISTED");
    expect(
      deriveExecutionPhase(
        facts("SEND_EXTERNAL", { signIntentPersisted: true, partialPersisted: true }),
      ),
    ).toBe("SIGNED_PERSISTED");
    expect(
      deriveExecutionPhase(
        facts("SEND_EXTERNAL", {
          signIntentPersisted: true,
          attemptPhase: "STEP1_SIGNATURE_PERSISTED",
        }),
      ),
    ).toBe("SIGNED_PERSISTED");
  });

  it("SEND: DELIVERED once first_delivered_at is set, and it outranks SIGNED_PERSISTED", () => {
    expect(
      deriveExecutionPhase(
        facts("SEND_EXTERNAL", {
          signIntentPersisted: true,
          partialPersisted: true,
          partialFirstDelivered: true,
        }),
      ),
    ).toBe("DELIVERED");
  });

  it("submit facts outrank formation facts, and a returned submit outranks a started one", () => {
    const formed = { attemptPhase: "STEP2_SIGNATURE_PERSISTED" } as const;
    expect(deriveExecutionPhase(facts("MOVE_INTERNAL", { ...formed, submitStarted: true }))).toBe(
      "SUBMIT_STARTED",
    );
    expect(
      deriveExecutionPhase(
        facts("MOVE_INTERNAL", { ...formed, submitStarted: true, submitReturned: true }),
      ),
    ).toBe("SUBMIT_RETURNED");
  });

  it("LANDED_VERIFIED needs an accepted verification AND terminal observations — settlement alone is not landing", () => {
    // SETTLED_BODY_PERSISTED is a persistence phase, not a landing verdict (data-model: settled_at
    // waits for independently verified landing).
    expect(
      deriveExecutionPhase(facts("MOVE_INTERNAL", { attemptPhase: "SETTLED_BODY_PERSISTED" })),
    ).toBe("SIGNED_PERSISTED");
    expect(
      deriveExecutionPhase(
        facts("MOVE_INTERNAL", {
          attemptPhase: "SETTLED_BODY_PERSISTED",
          verificationAccepted: true,
        }),
      ),
    ).toBe("SIGNED_PERSISTED");
    expect(
      deriveExecutionPhase(
        facts("MOVE_INTERNAL", {
          attemptPhase: "SETTLED_BODY_PERSISTED",
          terminalObservationsPresent: true,
        }),
      ),
    ).toBe("SIGNED_PERSISTED");
    expect(
      deriveExecutionPhase(
        facts("MOVE_INTERNAL", {
          attemptPhase: "SETTLED_BODY_PERSISTED",
          verificationAccepted: true,
          terminalObservationsPresent: true,
        }),
      ),
    ).toBe("LANDED_VERIFIED");
  });

  it("LANDED_VERIFIED outranks every other fact, for every kind", () => {
    const landed = { verificationAccepted: true, terminalObservationsPresent: true } as const;
    expect(
      deriveExecutionPhase(facts("MOVE_INTERNAL", { ...landed, submitReturned: true, submitStarted: true })),
    ).toBe("LANDED_VERIFIED");
    expect(
      deriveExecutionPhase(
        facts("SEND_EXTERNAL", {
          ...landed,
          signIntentPersisted: true,
          partialPersisted: true,
          partialFirstDelivered: true,
        }),
      ),
    ).toBe("LANDED_VERIFIED");
    expect(
      deriveExecutionPhase(facts("RECEIVE_EXTERNAL", { ...landed, submitReturned: true, submitStarted: true })),
    ).toBe("LANDED_VERIFIED");
  });

  it("every phase is reachable, and every derived phase applies to the kind that derived it", () => {
    const reachable = new Set<ExecutionPhase>();
    const boolKeys = [
      "signIntentPersisted",
      "partialPersisted",
      "partialFirstDelivered",
      "submitStarted",
      "submitReturned",
      "verificationAccepted",
      "terminalObservationsPresent",
    ] as const;
    const phases: readonly (AttemptPhase | null)[] = [null, ...ATTEMPT_PHASE_LADDER];

    // Exhaustive: 3 kinds x 6 attempt phases x every combination of the seven boolean facts.
    for (const kind of OPERATION_KINDS) {
      for (const attemptPhase of phases) {
        for (let mask = 0; mask < 1 << boolKeys.length; mask += 1) {
          const overrides: Record<string, boolean> = {};
          boolKeys.forEach((key, bit) => {
            overrides[key] = (mask & (1 << bit)) !== 0;
          });
          let derived: ExecutionPhase;
          try {
            derived = deriveExecutionPhase(facts(kind, { attemptPhase, ...overrides }));
          } catch {
            continue; // an unrepresentable tuple; covered by the negative test below
          }
          reachable.add(derived);
          expect(
            EXECUTION_PHASE_APPLIES_TO[derived],
            `${kind} at ${attemptPhase} mask ${mask} derived ${derived}`,
          ).toContain(kind);
        }
      }
    }
    expect([...reachable].sort()).toEqual([...EXECUTION_PHASES].sort());
  });
});

describe("deriveExecutionPhase fails closed on fact tuples canon makes unrepresentable", () => {
  it("a submit attempt on an external send is rejected, never reported as a submit phase", () => {
    expect(() => deriveExecutionPhase(facts("SEND_EXTERNAL", { submitStarted: true }))).toThrow(
      /a submit attempt exists for an external send/,
    );
    expect(() =>
      deriveExecutionPhase(facts("SEND_EXTERNAL", { submitStarted: true, submitReturned: true })),
    ).toThrow(/a submit attempt exists for an external send/);
  });

  it("sign-intent or partial material outside an external send is rejected", () => {
    for (const kind of ["RECEIVE_EXTERNAL", "MOVE_INTERNAL"] as const) {
      expect(() => deriveExecutionPhase(facts(kind, { signIntentPersisted: true })), kind).toThrow(
        /outside an external send/,
      );
      expect(() => deriveExecutionPhase(facts(kind, { partialPersisted: true })), kind).toThrow(
        /outside an external send/,
      );
    }
  });

  it("delivery before the partial row commits is rejected", () => {
    expect(() =>
      deriveExecutionPhase(facts("SEND_EXTERNAL", { partialFirstDelivered: true })),
    ).toThrow(/delivered before its row committed/);
  });

  it("a submit that returned without starting is rejected", () => {
    expect(() => deriveExecutionPhase(facts("MOVE_INTERNAL", { submitReturned: true }))).toThrow(
      /returned that never started/,
    );
  });

  it("the derivation writes nothing: it is a pure function of its argument", () => {
    const input = facts("SEND_EXTERNAL", { signIntentPersisted: true });
    const snapshot = JSON.stringify(input);
    expect(deriveExecutionPhase(input)).toBe("PREIMAGE_PERSISTED");
    expect(deriveExecutionPhase(input)).toBe("PREIMAGE_PERSISTED");
    expect(JSON.stringify(input)).toBe(snapshot);
  });
});
