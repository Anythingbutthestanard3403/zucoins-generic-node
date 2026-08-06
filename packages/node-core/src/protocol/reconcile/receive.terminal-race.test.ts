// complete-path fault vectors for RECEIVE terminal races.
//
// Complements packages/node-core/test/receive-terminal-race.pg.test.ts (real PG) and
// packages/node-core/test/receive-terminal-race.test.ts (crash + ACK). This file keeps the
// buried-landing / missing-intermediate oracle on the production path:
// proveReceiveLanding → landingProofToPathObservation → classifyReceiveReconcile.
//
// Fixed seed (shared with PG suite): receive-terminal-race-fault-seed.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { parseGatewayEnvelope, type ParsedSettledTransaction } from "../../verifier/gateway-envelope.js";
import {
  landingProofToPathObservation,
  proveReceiveLanding,
  type FreshHeadRead,
  type ReadFreshHead,
} from "../../verifier/landing-path-oracle.js";
import { classifyReceiveReconcile } from "./receive.js";

export const FAULT_SEED = "receive-terminal-race-fault-seed";

const GEN_DIR = new URL(
  "../../../../generic-node-contracts/src/receive-golden/gen/",
  import.meta.url,
);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
};
const RECEIVER_KEY = MANIFEST.public_keys.seed_02 as string;
const PREDECESSOR_TEXT = fixtureText("predecessor.settled.json");
const TARGET_TEXT = fixtureText("target.settled.json");

function headEnvelope(settledText: string): FreshHeadRead {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
  );
  return { observationId: `obs-${settledText.length}`, envelope: parseGatewayEnvelope(bytes) };
}

function parsedBody(settledText: string): ParsedSettledTransaction {
  const verdict = headEnvelope(settledText).envelope;
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD");
  return verdict.parsed;
}

const PREDECESSOR = parsedBody(PREDECESSOR_TEXT);
const TARGET = parsedBody(TARGET_TEXT);

function staticReader(settledText: string): ReadFreshHead {
  return async () => headEnvelope(settledText);
}

describe("landing-path oracle complete-path oracle (missing intermediate head)", () => {
  it("buried expected attempt + no intervening body → PROOF_INCOMPLETE/MISSING_BODY", async () => {
    const outcome = await proveReceiveLanding(
      {
        walletPubkeyBase64Urlsafe: RECEIVER_KEY,
        t0Body: null,
        expectedBody: PREDECESSOR,
        successorBodies: [],
        operation: { amountZkz: "10", receiverPubkey: RECEIVER_KEY },
      },
      staticReader(TARGET_TEXT),
    );
    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "MISSING_BODY" });
  });

  it("PROOF_INCOMPLETE folds to INDETERMINATE via receive reconcile — never landing/non-landing", async () => {
    const incomplete = await proveReceiveLanding(
      {
        walletPubkeyBase64Urlsafe: RECEIVER_KEY,
        t0Body: null,
        expectedBody: PREDECESSOR,
        successorBodies: [],
        operation: { amountZkz: "10", receiverPubkey: RECEIVER_KEY },
      },
      staticReader(TARGET_TEXT),
    );
    expect(incomplete.kind).toBe("PROOF_INCOMPLETE");
    const classified = classifyReceiveReconcile({
      boundary: "POST_SUBMIT",
      receiveAttemptId: `${FAULT_SEED}-attempt`,
      receiverWalletId: `${FAULT_SEED}-wallet`,
      receiverLeaseState: "ACTIVE",
      receiverObservation: landingProofToPathObservation(incomplete),
    });
    expect(classified.kind).toBe("INDETERMINATE");
  });

  it("positive complete-path land at depth 1 still yields LANDED_VERIFIED", async () => {
    const proof = await proveReceiveLanding(
      {
        walletPubkeyBase64Urlsafe: RECEIVER_KEY,
        t0Body: null,
        expectedBody: PREDECESSOR,
        successorBodies: [TARGET],
        operation: { amountZkz: "10", receiverPubkey: RECEIVER_KEY },
      },
      staticReader(TARGET_TEXT),
    );
    expect(proof.kind).toBe("LANDED_COMPLETE_PATH");
    const classified = classifyReceiveReconcile({
      boundary: "POST_SUBMIT",
      receiveAttemptId: `${FAULT_SEED}-land`,
      receiverWalletId: `${FAULT_SEED}-wallet`,
      receiverLeaseState: "ACTIVE",
      receiverObservation: landingProofToPathObservation(proof),
    });
    expect(classified.kind).toBe("LANDED_VERIFIED");
  });

  it("pins the shared fixed seed constant", () => {
    expect(FAULT_SEED).toBe("receive-terminal-race-fault-seed");
  });
});
