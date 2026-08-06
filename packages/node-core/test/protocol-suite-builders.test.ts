// Proves the typed builders reproduce all 11 canonical fields
// goldens byte-exact THROUGH this module's own code path (not just through
// `serializeSuiteTuple`, which own test already covers), and that each builder's output
// is independent of the caller's input key insertion order (cross-purpose byte-determinism
// item (a)). Reuses `SUITE_GOLDENS` fixture (already reproduced byte-exact against the
// live A.8.2 doc by own golden test) rather than re-transcribing a second copy.
import { describe, expect, it } from "vitest";

import {
  buildDestinationBless,
  buildDeviceEnrol,
  buildMoveInternalExpectedArtifact,
  buildNodeEvent,
  buildReceiveExpectedArtifact,
  buildReportRequest,
  buildReportingRegister,
  buildSendExternalApproval,
  buildSendExternalExpectedArtifact,
  buildWalletHeadFingerprint,
} from "../src/protocol/suite/builders.js";
import { SUITE_GOLDENS } from "./__vectors__/suite-appendix-a.js";

type Builder = (input: Record<string, unknown>) => { readonly preimageText: string; readonly sha256: string };

const BUILDER_BY_ID: Record<string, Builder> = {
  "receive-expected": buildReceiveExpectedArtifact as Builder,
  "move-internal-expected": buildMoveInternalExpectedArtifact as Builder,
  "send-external-expected": buildSendExternalExpectedArtifact as Builder,
  "send-external-approval": buildSendExternalApproval as Builder,
  "destination-bless": buildDestinationBless as Builder,
  "device-enrol": buildDeviceEnrol as Builder,
  "report-request": buildReportRequest as Builder,
  "reporting-register": buildReportingRegister as Builder,
  "node-event-a": buildNodeEvent as Builder,
  "node-event-b": buildNodeEvent as Builder,
  "wallet-head-fingerprint": buildWalletHeadFingerprint as Builder,
  // One builder serves both A.7 state_kind variants; GENESIS differs only in field values.
  "wallet-head-fingerprint-genesis": buildWalletHeadFingerprint as Builder,
};

// Every golden's `values` includes the `purpose`/`canonical_version` header fields the builder
// itself supplies — strip them to get the builder's own input shape.
function builderInput(values: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const { purpose: _purpose, canonical_version: _canonicalVersion, ...rest } = values;
  return rest;
}

describe("builders reproduce every A.8.2 golden byte-exact", () => {
  it("covers all 12 goldens across 10 builders", () => {
    expect(Object.keys(BUILDER_BY_ID).sort()).toEqual([...new Set(SUITE_GOLDENS.map((g) => g.id))].sort());
  });

  for (const golden of SUITE_GOLDENS) {
    it(`${golden.id}: builder output equals the pinned preimage and SHA-256`, () => {
      const builder = BUILDER_BY_ID[golden.id];
      expect(builder, `no builder registered for ${golden.id}`).toBeDefined();
      const produced = (builder as Builder)(builderInput(golden.values));
      expect(produced.preimageText).toBe(golden.preimageText);
      expect(produced.sha256).toBe(golden.sha256);
    });
  }
});

describe("cross-purpose byte-determinism: builder output ignores caller key order", () => {
  for (const golden of SUITE_GOLDENS) {
    it(`${golden.id}: reversed-insertion-order input still reproduces the exact golden bytes`, () => {
      const input = builderInput(golden.values);
      const reversed: Record<string, unknown> = {};
      for (const key of Object.keys(input).reverse()) reversed[key] = input[key];
      const builder = BUILDER_BY_ID[golden.id] as Builder;
      expect(builder(reversed).preimageText).toBe(golden.preimageText);
    });
  }

  it("building the same purpose twice from the same input yields identical bytes (pure/idempotent)", () => {
    const golden = SUITE_GOLDENS.find((g) => g.id === "receive-expected");
    if (golden === undefined) throw new Error("missing receive-expected golden");
    const input = builderInput(golden.values);
    const first = buildReceiveExpectedArtifact(input as Parameters<typeof buildReceiveExpectedArtifact>[0]);
    const second = buildReceiveExpectedArtifact(input as Parameters<typeof buildReceiveExpectedArtifact>[0]);
    expect(first.preimageText).toBe(second.preimageText);
    expect(first.sha256).toBe(second.sha256);
    expect(Buffer.from(first.preimageBytes).equals(Buffer.from(second.preimageBytes))).toBe(true);
  });
});
