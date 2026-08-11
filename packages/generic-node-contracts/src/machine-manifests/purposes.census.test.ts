import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  DEFERRED_SUITE_PURPOSE_CENSUS,
  IMPLEMENTER_SUITE_PURPOSE_CENSUS,
  LEGACY_PUSH_PURPOSES_REFERENCE,
  PURPOSES_CONTRACT_VERSION,
  SUITE_PURPOSE_CENSUS,
  SUITE_PURPOSE_DISPOSITIONS,
  SUITE_PURPOSE_SUFFIX,
  SUITE_SIGNING_KEY_ROLES,
} from "./purposes.contract.ts";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const FROZEN_PURPOSES = SUITE_PURPOSE_CENSUS.map((entry) => entry.purpose);
const DEFERRED_PURPOSES = DEFERRED_SUITE_PURPOSE_CENSUS.map((entry) => entry.purpose);
const IMPLEMENTER_PURPOSES = IMPLEMENTER_SUITE_PURPOSE_CENSUS.map((entry) => entry.purpose);

describe("purposes census (the fixture-provenance purposes census, Appendix A.3-A.7)", () => {
  it("freezes the ten live suite purposes, in Appendix A declaration sequence", () => {
    assertFieldOrder(FROZEN_PURPOSES, [
      "zp-receive-expected-v1",
      "zp-move-internal-expected-v1",
      "zp-send-external-expected-v1",
      "zp-send-external-approval-v1",
      "zp-destination-bless-v1",
      "zp-device-enrol-v1",
      "zp-report-request-v1",
      "zp-reporting-register-v1",
      "zp-node-event-v1",
      "zp-wallet-head-fingerprint-v1",
    ]);
  });

  it("freezes the three implementer continuity tuples (C4 discharged)", () => {
    expect(DEFERRED_PURPOSES).toEqual([]);
    assertFieldOrder(IMPLEMENTER_PURPOSES, [
      "zp-implementer-event-v1",
      "zp-implementer-checkpoint-v1",
      "zp-implementer-keyrotation-v1",
    ]);
    for (const entry of IMPLEMENTER_SUITE_PURPOSE_CENSUS) {
      expect(entry.disposition).toBe("frozen");
      expect(existsSync(join(packageRoot, entry.fieldSequenceOwner)), entry.purpose).toBe(true);
    }
  });

  it("carries the -v1 suffix on every live and implementer purpose (compatibility-literal preservation)", () => {
    for (const purpose of [...FROZEN_PURPOSES, ...IMPLEMENTER_PURPOSES]) {
      expect(purpose.endsWith(SUITE_PURPOSE_SUFFIX)).toBe(true);
    }
  });

  it("freezes the signing-key role per purpose", () => {
    const roleByPurpose = new Map(SUITE_PURPOSE_CENSUS.map((entry) => [entry.purpose, entry.signingKeyRole]));
    expect(roleByPurpose.get("zp-receive-expected-v1")).toBe("node_identity");
    expect(roleByPurpose.get("zp-move-internal-expected-v1")).toBe("node_identity");
    expect(roleByPurpose.get("zp-send-external-expected-v1")).toBe("node_identity");
    expect(roleByPurpose.get("zp-send-external-approval-v1")).toBe("device");
    expect(roleByPurpose.get("zp-destination-bless-v1")).toBe("device");
    expect(roleByPurpose.get("zp-device-enrol-v1")).toBe("device");
    expect(roleByPurpose.get("zp-report-request-v1")).toBe("reporting");
    expect(roleByPurpose.get("zp-reporting-register-v1")).toBe("reporting");
    expect(roleByPurpose.get("zp-node-event-v1")).toBe("node_event");
    expect(roleByPurpose.get("zp-wallet-head-fingerprint-v1")).toBe("none");
    const implRoles = new Map(IMPLEMENTER_SUITE_PURPOSE_CENSUS.map((e) => [e.purpose, e.signingKeyRole]));
    expect(implRoles.get("zp-implementer-event-v1")).toBe("node_event");
    expect(implRoles.get("zp-implementer-checkpoint-v1")).toBe("node_event");
    expect(implRoles.get("zp-implementer-keyrotation-v1")).toBe("node_event");
  });

  it("marks only the wallet-head fingerprint unsigned (A.7)", () => {
    const unsigned = SUITE_PURPOSE_CENSUS.filter((entry) => !entry.signed);
    expect(unsigned.map((entry) => entry.purpose)).toEqual(["zp-wallet-head-fingerprint-v1"]);
  });

  it("freezes the closed role/disposition vocabularies", () => {
    assertFieldOrder(SUITE_SIGNING_KEY_ROLES, [
      "node_identity",
      "device",
      "reporting",
      "node_event",
      "none",
    ]);
    assertFieldOrder(SUITE_PURPOSE_DISPOSITIONS, ["frozen", "deferred-c4"]);
  });

  it("every frozen purpose's field-sequence owner module exists on disk", () => {
    for (const entry of SUITE_PURPOSE_CENSUS) {
      expect(existsSync(join(packageRoot, entry.fieldSequenceOwner)), entry.purpose).toBe(true);
    }
  });

  it("excludes the implementer and legacy-push purposes from the suite-serializer census", () => {
    for (const purpose of [...IMPLEMENTER_PURPOSES, ...LEGACY_PUSH_PURPOSES_REFERENCE.purposes]) {
      expect(FROZEN_PURPOSES).not.toContain(purpose);
    }
  });

  it("rejects a reordered census (negative path)", () => {
    expectRejects(
      () => [...FROZEN_PURPOSES].reverse(),
      (mutated) => assertFieldOrder(mutated, FROZEN_PURPOSES),
    );
  });

  it("rejects an unknown purpose injected into the census (negative path)", () => {
    expectRejects(
      () => [...FROZEN_PURPOSES, "zp-extra-thing-v1"],
      (mutated) => assertClosedSet(mutated, FROZEN_PURPOSES),
    );
  });

  it("rejects an implementer purpose admitted into the suite-serializer census (negative path)", () => {
    expectRejects(
      () => [...FROZEN_PURPOSES, "zp-implementer-event-v1"],
      (mutated) => assertClosedSet(mutated, FROZEN_PURPOSES),
    );
  });

  it("pins the manifest version", () => {
    expect(PURPOSES_CONTRACT_VERSION).toBe(1);
  });
});
