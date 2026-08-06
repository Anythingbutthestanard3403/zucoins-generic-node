// split-brain reconciliation. `packages/generic-node-contracts/src/
// reporting-tuples/` and `reporting-auth/` freeze `zp-report-request-v1`,
// `zp-node-event-v1`, and `zp-reporting-register-v1` with their own hand-rolled
// `purpose + "\n" + JSON.stringify(payload)` builders, predating single-serializer module
// and this module's typed builders over it. DO NOT move or edit those frozen contracts (they are
// CONTRACT_FREEZE-gated byte authorities in their own right — see their CONTRACT.md files).
// Reconciliation instead means: this module's builders
// route through the one canonical serializer (`serializeSuiteTuple`, proven in
// protocol-suite-goldens.test.ts / protocol-suite-builders.test.ts to reproduce the same A.8 bytes),
// and — proven here — produce preimages BYTE-IDENTICAL to the frozen contract's own output
// for the same logical fields. census test already cross-checks the two modules'
// structural facts (field order, key-class purposes, neutral event set); this file adds the byte
// identity check those structural facts imply but do not themselves prove.
//
// Canonical-constructor note: going forward, runtime code that needs to CONSTRUCT one
// of these three preimages should call this module's typed builder
// (`buildReportRequest`/`buildReportingRegister`/`buildNodeEvent`), not hand-roll a fourth copy of
// the `purpose + "\n" + JSON.stringify(...)` pattern. The contracts remain the frozen byte
// authority for their goldens; this module is the sanctioned runtime constructor that reproduces them.
import { describe, expect, it } from "vitest";

import { buildNodeEvent, buildReportRequest, buildReportingRegister } from "../src/protocol/suite/builders.js";
import {
  NODE_EVENT_GOLDEN_A,
  NODE_EVENT_GOLDEN_A_PREIMAGE,
  NODE_EVENT_GOLDEN_B,
  NODE_EVENT_GOLDEN_B_PREIMAGE,
} from "../../generic-node-contracts/src/reporting-tuples/event-tuple.ts";
import {
  REPORT_REQUEST_GOLDEN_PAYLOAD,
  REPORT_REQUEST_GOLDEN_PREIMAGE,
} from "../../generic-node-contracts/src/reporting-tuples/request-tuple.ts";
import {
  REGISTER_GOLDEN_PAYLOAD,
  REGISTER_GOLDEN_PREIMAGE,
} from "../../generic-node-contracts/src/reporting-auth/register-tuple.ts";

describe("<-> cross-package byte parity", () => {
  it("buildReportRequest reproduces the frozen zp-report-request-v1 preimage byte-identical", () => {
    const { purpose: _purpose, canonical_version: _version, ...input } = REPORT_REQUEST_GOLDEN_PAYLOAD;
    const produced = buildReportRequest(input);
    expect(produced.preimageText).toBe(REPORT_REQUEST_GOLDEN_PREIMAGE);
  });

  it("buildReportingRegister reproduces the frozen zp-reporting-register-v1 preimage byte-identical", () => {
    const { purpose: _purpose, canonical_version: _version, ...input } = REGISTER_GOLDEN_PAYLOAD;
    const produced = buildReportingRegister(input);
    expect(produced.preimageText).toBe(REGISTER_GOLDEN_PREIMAGE);
  });

  it("buildNodeEvent reproduces the frozen zp-node-event-v1 golden A preimage byte-identical", () => {
    const { purpose: _purpose, canonical_version: _version, ...input } = NODE_EVENT_GOLDEN_A;
    const produced = buildNodeEvent(input);
    expect(produced.preimageText).toBe(NODE_EVENT_GOLDEN_A_PREIMAGE);
  });

  it("buildNodeEvent reproduces the frozen zp-node-event-v1 golden B (null wallet_id) preimage byte-identical", () => {
    const { purpose: _purpose, canonical_version: _version, ...input } = NODE_EVENT_GOLDEN_B;
    const produced = buildNodeEvent(input);
    expect(produced.preimageText).toBe(NODE_EVENT_GOLDEN_B_PREIMAGE);
  });
});
