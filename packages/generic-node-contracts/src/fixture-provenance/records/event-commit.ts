import type { FixtureProvenanceRecord } from "../types.ts";

/**
 * Event-commit vectors (the event-commit concern) — executable model vectors in the unsigned-evidence class
 * (unsigned frozen JSON authenticated by digest). Each vector's model is fed to the class
 * verifier; `expect` is the required verdict.
 */
export const EVENT_COMMIT_FIXTURE_RECORDS: readonly FixtureProvenanceRecord[] = [
  {
    fixtureId: "event-commit/commit.vectors",
    byteClass: "unsigned-evidence",
    indexPath: "src/event-commit/__vectors__/commit.vectors.json",
    files: [
      { path: "src/event-commit/__vectors__/commit.vectors.json", sha256: "dabdf2183684043ba3072cf0482f839c574d58bad047eb51e55763781bcd44de" },
    ],
    provenance: {
      originKind: "canonical-constructor",
      captureMethod:
        "Hand-authored executable rollback/concurrency/restart/rotation model vectors, frozen; " +
        "each vector's model is fed to the class verifier and `expect` is the required verdict",
      captureDate: "2026-07-19",
      walletVersion: "n/a — frozen vector table; no wallet capture",
      source: "packages/generic-node-contracts/src/event-commit (the event-commit class verifiers)",
      keyMaterial: "none — pure model vectors",
      specCitations: [
        "data model: durable event commit rules",
        "canonical-fields reference: node-event tuple fields",
        "state-event reference: durable public events",
        "api contract: event stream",
      ],
      decisionRefs: [
        "signed-event-log",
        "sealed-store",
        "reporting-channel",
      ],
    },
  },
];
