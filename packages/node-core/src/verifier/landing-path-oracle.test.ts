// vectors for the landing-path oracle any-depth complete-path landing oracle, driven by the
// frozen A.8.1 golden pair. For wallet seed_02 those two fixtures are a real adjacent
// chain segment: `predecessor` credits seed_02 with 10 ZKZ from genesis, `target` then
// spends 2.25 of it, so `target.P(seed_02) == predecessor.S(seed_02)`. Every signature
// here is a real Ed25519 signature over real signed bytes — no body is hand-assembled.
//
// The load-bearing case is "phantom settle": the head has moved past the expected attempt
// and the caller supplies no intervening bodies. Nothing the caller can pass makes that a
// landing.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  classifyReceiveReconcile,
  type ReceiveObservationEvidence,
} from "../protocol/reconcile/index.js";
import { parseGatewayEnvelope, type ParsedSettledTransaction } from "./gateway-envelope.js";
import {
  DEFAULT_MAX_PATH_DEPTH,
  landingProofToPathObservation,
  proveReceiveLanding,
  type FreshHeadRead,
  type ReadFreshHead,
} from "./landing-path-oracle.js";

const GEN_DIR = new URL("../../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
};
const RECEIVER_KEY = MANIFEST.public_keys.seed_02 as string;
const UNRELATED_KEY = MANIFEST.public_keys.seed_03 as string;

// The pipeline seam: settled text -> gateway envelope bytes -> HEAD verdict.
function headEnvelope(settledText: string): FreshHeadRead {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
  );
  return { observationId: `obs-${settledText.length}`, envelope: parseGatewayEnvelope(bytes) };
}

function parsedBody(settledText: string): ParsedSettledTransaction {
  const verdict = headEnvelope(settledText).envelope;
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD envelope verdict");
  return verdict.parsed;
}

const PREDECESSOR_TEXT = fixtureText("predecessor.settled.json");
const TARGET_TEXT = fixtureText("target.settled.json");
const PREDECESSOR = parsedBody(PREDECESSOR_TEXT);
const TARGET = parsedBody(TARGET_TEXT);

// seed_02 is the step-2 receiver of `predecessor`, crediting it 10 ZKZ from a genesis
// baseline (manifest: seed_02_receiver P="", B="10").
const RECEIVE_OPERATION = { amountZkz: "10", receiverPubkey: RECEIVER_KEY };

function baseInput(successorBodies: readonly ParsedSettledTransaction[] = []) {
  return {
    walletPubkeyBase64Urlsafe: RECEIVER_KEY,
    t0Body: null,
    expectedBody: PREDECESSOR,
    successorBodies,
    operation: RECEIVE_OPERATION,
  };
}

// A reader that answers every call with the same head; `calls` proves the oracle really
// reads twice rather than trusting its anchor.
function staticReader(settledText: string): ReadFreshHead & { calls: () => number } {
  let calls = 0;
  const read: ReadFreshHead = async () => {
    calls += 1;
    return headEnvelope(settledText);
  };
  return Object.assign(read, { calls: () => calls });
}

// A reader whose head moves between the anchor read and the confirm read.
function movingReader(first: string, rest: string): ReadFreshHead {
  let calls = 0;
  return async () => {
    calls += 1;
    return headEnvelope(calls === 1 ? first : rest);
  };
}

function genesisReader(): ReadFreshHead {
  return async () => ({
    observationId: "obs-genesis",
    envelope: parseGatewayEnvelope(
      new TextEncoder().encode(
        `{"status":false,"code":"account_not_found","message":"no account","data":null}`,
      ),
    ),
  });
}

// Replace one signature field in the settled text with another valid-format signature:
// the shape and scalars still pass, only the Ed25519 check fails.
function withForeignStepTwoSignature(settledText: string, donorText: string): string {
  const marker = ',"step_2_signature":"';
  const donorStart = donorText.indexOf(marker) + marker.length;
  const donorSignature = donorText.slice(donorStart, donorText.indexOf('"', donorStart));
  const start = settledText.indexOf(marker) + marker.length;
  const end = settledText.indexOf('"', start);
  return settledText.slice(0, start) + donorSignature + settledText.slice(end);
}

describe("landing oracle — positive proofs", () => {
  it("mints LANDED_EXACT when the confirm-read head is the expected body itself", async () => {
    const reader = staticReader(PREDECESSOR_TEXT);
    const outcome = await proveReceiveLanding(baseInput(), reader);

    expect(outcome.kind).toBe("LANDED_EXACT");
    if (outcome.kind === "PROOF_INCOMPLETE") return;
    expect(outcome.depth).toBe(0);
    expect(outcome.walletPubkeyBase64Urlsafe).toBe(RECEIVER_KEY);
    // Recomputed from the exact signed text, never supplied: the golden settled digest.
    expect(outcome.expectedBodySha256).toBe(
      "51dd611df7564d3cac3bdf8a3415ce9326ee29b920daa1338447c57a4c78505b",
    );
    // Anchor read plus confirm read — the head is observed twice, not assumed.
    expect(reader.calls()).toBe(2);
  });

  it("mints LANDED_COMPLETE_PATH at depth 1 across a verified backlink", async () => {
    const outcome = await proveReceiveLanding(baseInput([TARGET]), staticReader(TARGET_TEXT));

    expect(outcome.kind).toBe("LANDED_COMPLETE_PATH");
    if (outcome.kind === "PROOF_INCOMPLETE") return;
    expect(outcome.depth).toBe(1);
    // Still the EXPECTED body's digest, not the head's — the proof identifies the attempt.
    expect(outcome.expectedBodySha256).toBe(
      "51dd611df7564d3cac3bdf8a3415ce9326ee29b920daa1338447c57a4c78505b",
    );
  });
});

describe("landing oracle — landing is never inferred from a supplied value", () => {
  // The phantom-settle case this ticket exists to prevent: the head moved past the
  // expected attempt and the caller supplied nothing to bridge the distance.
  it("refuses to land a buried attempt when no intervening body is supplied", async () => {
    const outcome = await proveReceiveLanding(baseInput(), staticReader(TARGET_TEXT));

    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "MISSING_BODY" });
  });

  it("refuses a supplied path that stops short of the fresh head", async () => {
    // Bodies verify and link, but the head is not the one they terminate at.
    const outcome = await proveReceiveLanding(baseInput([TARGET]), staticReader(PREDECESSOR_TEXT));

    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "GAP" });
  });

  it("refuses a supplied body whose backlink does not hold", async () => {
    const outcome = await proveReceiveLanding(
      {
        ...baseInput([PREDECESSOR]),
        expectedBody: TARGET,
        operation: { amountZkz: "2.25", receiverPubkey: UNRELATED_KEY },
      },
      staticReader(PREDECESSOR_TEXT),
    );

    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "GAP" });
  });

  it("refuses a repeated body in the supplied sequence", async () => {
    const outcome = await proveReceiveLanding(baseInput([PREDECESSOR]), staticReader(TARGET_TEXT));

    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "DUPLICATE" });
  });

  it("refuses a body whose signature does not verify", async () => {
    const forged = parsedBody(withForeignStepTwoSignature(TARGET_TEXT, PREDECESSOR_TEXT));
    const outcome = await proveReceiveLanding(baseInput([forged]), staticReader(TARGET_TEXT));

    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "ANOMALOUS_OR_CONTRADICTORY" });
  });

  it("refuses when the economic predicate does not hold against T0", async () => {
    const outcome = await proveReceiveLanding(
      { ...baseInput(), operation: { amountZkz: "9", receiverPubkey: RECEIVER_KEY } },
      staticReader(PREDECESSOR_TEXT),
    );

    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "ANOMALOUS_OR_CONTRADICTORY" });
  });

  it("refuses when the queried wallet has no role in the fresh head", async () => {
    const outcome = await proveReceiveLanding(
      { ...baseInput(), walletPubkeyBase64Urlsafe: UNRELATED_KEY },
      staticReader(PREDECESSOR_TEXT),
    );

    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "ANOMALOUS_OR_CONTRADICTORY" });
  });

  it("refuses when the fresh read is genesis", async () => {
    const outcome = await proveReceiveLanding(baseInput(), genesisReader());

    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "MISSING_BODY" });
  });

  it("refuses a supplied sequence past the verification budget", async () => {
    const outcome = await proveReceiveLanding(
      { ...baseInput([TARGET]), maxDepth: 0 },
      staticReader(TARGET_TEXT),
    );

    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "BUDGET_EXHAUSTED" });
    expect(DEFAULT_MAX_PATH_DEPTH).toBeGreaterThan(0);
  });
});

describe("landing oracle — current-exact-head rule", () => {
  it("refuses a head that moved between the anchor read and the confirm read", async () => {
    const outcome = await proveReceiveLanding(
      baseInput(),
      movingReader(PREDECESSOR_TEXT, TARGET_TEXT),
    );

    // Would have been LANDED_EXACT against the anchor alone; the confirm-read contradicts it.
    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "CONFLICT" });
  });
});

describe("landing oracle — reconcile wiring", () => {
  function receiveEvidence(observation: ReceiveObservationEvidence["receiverObservation"]) {
    return {
      boundary: "POST_SUBMIT",
      receiveAttemptId: "attempt-1",
      receiverWalletId: "wallet-1",
      receiverLeaseState: "ACTIVE",
      receiverObservation: observation,
    } as const satisfies ReceiveObservationEvidence;
  }

  it("carries a proof through to LANDED_VERIFIED", async () => {
    const outcome = await proveReceiveLanding(baseInput([TARGET]), staticReader(TARGET_TEXT));
    const classified = classifyReceiveReconcile(
      receiveEvidence(landingProofToPathObservation(outcome)),
    );

    expect(classified.kind).toBe("LANDED_VERIFIED");
  });

  it("carries every fault through to INDETERMINATE, never to a non-landing verdict", async () => {
    const outcome = await proveReceiveLanding(baseInput(), staticReader(TARGET_TEXT));
    const classified = classifyReceiveReconcile(
      receiveEvidence(landingProofToPathObservation(outcome)),
    );

    expect(classified).toEqual({
      kind: "INDETERMINATE",
      receiveAttemptId: "attempt-1",
      reason: { source: "LANDING_PROOF_INCOMPLETE", fault: "MISSING_BODY" },
    });
  });
});
