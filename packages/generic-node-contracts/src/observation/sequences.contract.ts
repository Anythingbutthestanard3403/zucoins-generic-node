/**
 * SOURCE: the observation-verification contract (mandatory raw-capture and dedup golden
 * tests, and the capture examples table), the permanent-retention requirement, the
 * integration observation feed, and the canonical observation-dedup decision.
 *
 * The frozen end-to-end outcome of each frozen golden observation sequence, driven through
 * the observation dedup freeze primitive and the observation concern.2 classifier by sequence-driver.ts. `relationships` is the
 * per-appended-row classification in capture sequence; suppressed sightings never add a row.
 */

import { type ObservationRelationship } from "./enums.contract.ts";

export interface GoldenSequenceExpectation {
  readonly name: string;
  readonly description: string;
  readonly appendedRows: number;
  readonly anomalyRows: number;
  readonly suppressedSightings: number;
  readonly relationships: readonly ObservationRelationship[];
}

export const GOLDEN_SEQUENCES = [
  {
    name: "AA_BYTE_IDENTICAL",
    description: "byte-identical verified A,A appends once and increments the sighting counter",
    appendedRows: 1,
    anomalyRows: 0,
    suppressedSightings: 1,
    relationships: ["FIRST"],
  },
  {
    name: "AA_PRIME_WRAPPER",
    description: "same verified head with a byte-different envelope A,A' appends twice",
    appendedRows: 2,
    anomalyRows: 0,
    suppressedSightings: 0,
    relationships: ["FIRST", "EQUIVALENT_STATE_DIFFERENT_ENVELOPE"],
  },
  {
    name: "ABCA_REGRESSION",
    description: "A,B,C,A appends four; the final A is a REGRESSION and quarantines",
    appendedRows: 4,
    anomalyRows: 1,
    suppressedSightings: 0,
    relationships: ["FIRST", "SUCCESSOR", "SUCCESSOR", "REGRESSION"],
  },
  {
    name: "MALFORMED_XX",
    description: "identical malformed bytes twice appends twice with two anomalies",
    appendedRows: 2,
    anomalyRows: 2,
    suppressedSightings: 0,
    relationships: ["NOT_APPLICABLE", "NOT_APPLICABLE"],
  },
  {
    name: "DIGEST_COLLISION",
    description:
      "two verified bodies with a forced-equal digest and length but different bytes still append",
    appendedRows: 2,
    anomalyRows: 0,
    suppressedSightings: 0,
    relationships: ["FIRST", "EQUIVALENT_STATE_DIFFERENT_ENVELOPE"],
  },
] as const satisfies readonly GoldenSequenceExpectation[];

export type GoldenSequenceName = (typeof GOLDEN_SEQUENCES)[number]["name"];

/** Properties proven over sequences rather than by a single fixed transcript. */
export const SEQUENCE_PROPERTIES = [
  "restart: resuming from a returned cursor yields the identical continuation transcript",
  "concurrent: each read stream folds an independent cursor with its own contiguous wallet_seq",
  "append-only: a row count never decreases and a suppressed sighting never removes a row",
] as const;
