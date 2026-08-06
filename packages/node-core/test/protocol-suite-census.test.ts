// Census + external-serialization prohibition. Proves: (a) the machine census matches the
// byte authority — every purpose's declared field order equals the actual key order of its A.8 golden
// JSON; (b) the prohibition datum holds and the module funnels through a single JSON.stringify
// (signing custody: "Calling JSON.stringify for these tuples outside that module is forbidden"); and
// (c) the serializer's reporting/event/key-class facts align with the frozen contract
// (the two must never drift — cross-checked by importing the frozen source directly).
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  EXTERNAL_SUITE_SERIALIZATION_PROHIBITED,
  NEUTRAL_EVENT_TYPES,
  SUITE_PURPOSES,
  SUITE_SERIALIZER_ENTRYPOINT,
  buildSuiteSerializerManifest,
  keyClassForPurpose,
} from "../src/protocol/suite/index.js";
import { SUITE_GOLDENS } from "./__vectors__/suite-appendix-a.js";
import {
  NODE_EVENT_KEY_ALLOWED_PURPOSES,
  REPORTING_KEY_ALLOWED_PURPOSES,
  V2_REPORTING_PURPOSES,
} from "../../generic-node-contracts/src/reporting-auth/index.ts";
import { NEUTRAL_EVENT_TYPES as CONTRACT_NEUTRAL_EVENT_TYPES } from "../../generic-node-contracts/src/reporting-tuples/event-tuple.ts";

const here = dirname(fileURLToPath(import.meta.url));
const SUITE_SRC_DIR = join(here, "..", "src", "protocol", "suite");

function jsonKeyOrder(preimageText: string): readonly string[] {
  return Object.keys(JSON.parse(preimageText.slice(preimageText.indexOf("\n") + 1)) as Record<string, unknown>);
}

describe("census — the manifest matches the byte authority", () => {
  const manifest = buildSuiteSerializerManifest();

  it("registers exactly the ten closed suite purposes in order", () => {
    expect(SUITE_PURPOSES).toEqual([
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
    expect(manifest.purposeCount).toBe(10);
    expect(manifest.domainSeparator).toBe("\n");
  });

  it("declares each purpose's field order equal to its A.8 golden's actual JSON key order", () => {
    for (const entry of manifest.purposes) {
      const golden = SUITE_GOLDENS.find((g) => g.purpose === entry.purpose);
      expect(golden, `golden for ${entry.purpose}`).toBeDefined();
      expect(entry.fieldOrder).toEqual(jsonKeyOrder((golden as { preimageText: string }).preimageText));
      expect(entry.fieldOrder.slice(0, 2)).toEqual(["purpose", "canonical_version"]);
    }
  });

  it("declares each purpose's signing key class", () => {
    const byPurpose = Object.fromEntries(manifest.purposes.map((p) => [p.purpose, p.keyClass]));
    expect(byPurpose).toEqual({
      "zp-receive-expected-v1": "node_identity",
      "zp-move-internal-expected-v1": "node_identity",
      "zp-send-external-expected-v1": "node_identity",
      "zp-send-external-approval-v1": "device",
      "zp-destination-bless-v1": "device",
      "zp-device-enrol-v1": "device",
      "zp-report-request-v1": "reporting",
      "zp-reporting-register-v1": "reporting",
      "zp-node-event-v1": "node_event",
      "zp-wallet-head-fingerprint-v1": "unsigned",
    });
  });
});

describe("external-serialization prohibition", () => {
  it("asserts the prohibition datum and the single sanctioned entrypoint", () => {
    expect(EXTERNAL_SUITE_SERIALIZATION_PROHIBITED).toBe(true);
    expect(SUITE_SERIALIZER_ENTRYPOINT).toBe("serializeSuiteTuple");
  });

  it("funnels all suite serialization through exactly one JSON.stringify, only in serialize.ts", () => {
    const files = readdirSync(SUITE_SRC_DIR).filter((name) => name.endsWith(".ts"));
    let totalStringifyCalls = 0;
    const filesWithStringify: string[] = [];
    for (const name of files) {
      const source = readFileSync(join(SUITE_SRC_DIR, name), "utf8");
      const matches = source.match(/JSON\.stringify\s*\(/g) ?? [];
      if (matches.length > 0) filesWithStringify.push(name);
      totalStringifyCalls += matches.length;
    }
    expect(filesWithStringify).toEqual(["serialize.ts"]);
    expect(totalStringifyCalls).toBe(1);
  });
});

describe("alignment with the frozen reporting contract", () => {
  it("reporting-key purposes match the registry's reporting-class purposes", () => {
    const reportingPurposes = SUITE_PURPOSES.filter((p) => keyClassForPurpose(p) === "reporting");
    expect(reportingPurposes.sort()).toEqual([...REPORTING_KEY_ALLOWED_PURPOSES].sort());
    for (const purpose of reportingPurposes) expect(V2_REPORTING_PURPOSES).toContain(purpose);
  });

  it("the node-event purpose matches the frozen node-event key purpose", () => {
    const eventPurposes = SUITE_PURPOSES.filter((p) => keyClassForPurpose(p) === "node_event");
    expect(eventPurposes).toEqual([...NODE_EVENT_KEY_ALLOWED_PURPOSES]);
  });

  it("the registry-owned neutral event set equals the frozen closed set", () => {
    expect([...NEUTRAL_EVENT_TYPES]).toEqual([...CONTRACT_NEUTRAL_EVENT_TYPES]);
  });
});
