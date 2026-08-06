// (parent) — the state-promotion seam.
//
// The three children each prove a STAGE-LOCAL verdict and stop there: that
// the envelope parser rejects (gateway-envelope.test.ts).2 that the transaction
// verifier rejects (transaction-verify.test.ts).3 that the frozen 17-vector
// adversarial corpus draws the exact typed verdict at the correct stage
// (attack-vectors.test.ts). None of them carries a malformed input ACROSS the stage seam to
// the point where state is actually promoted, which is what this parent's exit criterion
// requires: "unknown or malformed authoritative fields fail before state promotion".
//
// The only object in this system that authorizes promotion is a positive LandingPathProof
// from proveReceiveLanding, which
// classifyReceiveReconcile folds to LANDED_VERIFIED. So this file drives the same frozen
// corpus through the full committed composition —
//
// parseGatewayEnvelope -> verifySettledTransaction -> proveReceiveLanding
// -> landingProofToPathObservation -> classifyReceiveReconcile
//
// — substituted into EVERY position of the oracle input a caller can influence (t0 body,
// expected body, a supplied successor, and the freshly read head), and asserts that not one
// of them reaches a proof. The control is the unmutated A.8.1 pair in the same positions
// minting LANDED_COMPLETE_PATH, so a uniformly dead pipeline cannot pass this file: a
// fail-open at any single position would surface as that positive verdict surviving the
// substitution.
//
// Pure test slice: no production logic is added, every input is offline committed bytes, no
// live submit or live-chain path is reachable, and no signing payload is reformatted.
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  classifyReceiveReconcile,
  type ReceiveObservationEvidence,
} from "../protocol/reconcile/index.js";
import { type LandingProofFault } from "../protocol/reconcile/landing-proof.js";
import { parseGatewayEnvelope, type ParsedSettledTransaction } from "./gateway-envelope.js";
import {
  landingProofToPathObservation,
  proveReceiveLanding,
  type FreshHeadRead,
  type ReadFreshHead,
  type ReceiveLandingOracleInput,
} from "./landing-path-oracle.js";

const ATTACK_DIR = new URL(
  "../../../generic-node-contracts/src/receive-golden/attack-vectors/",
  import.meta.url,
);
const GEN_DIR = new URL("../../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function attackBytes(file: string): Uint8Array {
  return readFileSync(fileURLToPath(new URL(file, ATTACK_DIR)));
}
function attackText(file: string): string {
  return Buffer.from(attackBytes(file)).toString("utf8");
}
function genText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}
function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

interface AttackVector {
  readonly name: string;
  readonly file: string;
  readonly stage: "envelope" | "verifier";
  readonly expected: { readonly verdict?: string; readonly classification?: string };
  readonly sha256: string;
}
const MANIFEST = JSON.parse(attackText("manifest.json")) as {
  readonly baseline_settled_sha256: string;
  readonly public_keys: Readonly<Record<string, string>>;
  readonly vectors: readonly AttackVector[];
};

// seed_02 is the step-2 receiver of `predecessor` (credited 10 ZKZ from a genesis baseline)
// and the step-1 sender of `target`, so the pair is a real adjacent chain segment for it.
const WALLET = MANIFEST.public_keys.seed_02;
const ABSENT_WALLET = MANIFEST.public_keys.seed_05;

const PREDECESSOR_TEXT = genText("predecessor.settled.json");
const TARGET_TEXT = genText("target.settled.json");

// The pipeline seam, byte-for-byte as the live gateway delivers it: settled text spliced
// into a success envelope, parsed by the real envelope parser. Fixture bytes ride through
// verbatim — never re-serialized.
function headEnvelopeBytes(settledText: string): Uint8Array {
  return new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
  );
}
function headRead(settledText: string): FreshHeadRead {
  return {
    observationId: `obs-${sha256Hex(new TextEncoder().encode(settledText)).slice(0, 12)}`,
    envelope: parseGatewayEnvelope(headEnvelopeBytes(settledText)),
  };
}
function parsedBody(settledText: string): ParsedSettledTransaction {
  const verdict = parseGatewayEnvelope(headEnvelopeBytes(settledText));
  if (verdict.classification !== "HEAD") {
    throw new Error(`expected HEAD envelope verdict, got ${verdict.classification}`);
  }
  return verdict.parsed;
}
function staticReader(read: FreshHeadRead): ReadFreshHead {
  return async () => read;
}

const PREDECESSOR = parsedBody(PREDECESSOR_TEXT);
const TARGET = parsedBody(TARGET_TEXT);

// The proven-positive depth-1 configuration every substitution below is made against: the
// receive of 10 ZKZ into seed_02, with `target` supplied as the one intervening body that
// bridges it to the freshly read head.
const CONTROL_INPUT: ReceiveLandingOracleInput = {
  walletPubkeyBase64Urlsafe: WALLET,
  t0Body: null,
  expectedBody: PREDECESSOR,
  successorBodies: [TARGET],
  operation: { amountZkz: "10", receiverPubkey: WALLET },
};
const CONTROL_HEAD = headRead(TARGET_TEXT);

// The four caller-influenced positions in one oracle invocation. `head` is the authoritative
// read; the other three are the supplied evidence landing-path oracle calls untrusted until verified.
type Position = "t0Body" | "expectedBody" | "successorBody" | "head";
const POSITIONS: readonly Position[] = ["t0Body", "expectedBody", "successorBody", "head"];

// Substitute one settled text into one position of the control configuration. Only that
// position changes; everything else stays the configuration proven to mint a proof.
function substitute(
  position: Position,
  settledText: string,
): { readonly input: ReceiveLandingOracleInput; readonly reader: ReadFreshHead } {
  if (position === "head") {
    return { input: CONTROL_INPUT, reader: staticReader(headRead(settledText)) };
  }
  const body = parsedBody(settledText);
  const input: ReceiveLandingOracleInput =
    position === "t0Body"
      ? { ...CONTROL_INPUT, t0Body: body }
      : position === "expectedBody"
        ? { ...CONTROL_INPUT, expectedBody: body }
        : { ...CONTROL_INPUT, successorBodies: [body] };
  return { input, reader: staticReader(CONTROL_HEAD) };
}

// The landing-path oracle fault the oracle owes for a body that failed verification, derived from the
// frozen manifest's own (different) verdict vocabulary rather than restated: a shape or
// scalar defect is a MALFORMED_BODY; a signature or role that does not hold is a
// contradiction between the supplied evidence and the chain.
function expectedFault(vector: AttackVector): LandingProofFault {
  return vector.expected.verdict === "MALFORMED_TRANSACTION"
    ? "MALFORMED_BODY"
    : "ANOMALOUS_OR_CONTRADICTORY";
}

const envelopeVectors = MANIFEST.vectors.filter((vector) => vector.stage === "envelope");
// `absent-wallet` carries the pristine golden bytes — its defect is the querying key, not
// the body — so it is driven separately below rather than as a malformed substitution.
const bodyVectors = MANIFEST.vectors.filter(
  (vector) => vector.stage === "verifier" && vector.file !== "../gen/target.settled.json",
);

const cases = POSITIONS.flatMap((position) =>
  bodyVectors.map((vector) => ({ position, vector, name: `${vector.name} @ ${position}` })),
);

function receiveEvidence(
  observation: ReceiveObservationEvidence["receiverObservation"],
): ReceiveObservationEvidence {
  return {
    boundary: "POST_SUBMIT",
    receiveAttemptId: "attempt-1",
    receiverWalletId: "wallet-1",
    receiverLeaseState: "ACTIVE",
    receiverObservation: observation,
  } as const satisfies ReceiveObservationEvidence;
}

describe("state-promotion seam — the control that makes the matrix meaningful", () => {
  it("drives the frozen corpus from committed bytes whose digests match the manifest", () => {
    expect(envelopeVectors).toHaveLength(6);
    expect(bodyVectors).toHaveLength(10);
    for (const vector of MANIFEST.vectors) {
      expect(sha256Hex(attackBytes(vector.file))).toBe(vector.sha256);
    }
    expect(sha256Hex(new TextEncoder().encode(TARGET_TEXT))).toBe(MANIFEST.baseline_settled_sha256);
    // Every position is exercised against every mutated body.
    expect(cases).toHaveLength(40);
  });

  it("the unmutated A.8.1 pair reaches state promotion through the full composition", async () => {
    const outcome = await proveReceiveLanding(CONTROL_INPUT, staticReader(CONTROL_HEAD));

    expect(outcome.kind).toBe("LANDED_COMPLETE_PATH");
    if (outcome.kind === "PROOF_INCOMPLETE") return;
    expect(outcome.depth).toBe(1);
    // Recomputed from exact signed text, never supplied: the published A.8.1 predecessor
    // settled digest.
    expect(outcome.expectedBodySha256).toBe(
      "51dd611df7564d3cac3bdf8a3415ce9326ee29b920daa1338447c57a4c78505b",
    );

    const observation = landingProofToPathObservation(outcome);
    expect(observation.result).toBe("PROOF");
    expect(classifyReceiveReconcile(receiveEvidence(observation)).kind).toBe("LANDED_VERIFIED");
  });
});

describe("state-promotion seam — no malformed body promotes state from any position", () => {
  it.each(cases)("$name yields no proof", async ({ position, vector }) => {
    const { input, reader } = substitute(position, attackText(vector.file));
    const outcome = await proveReceiveLanding(input, reader);

    // Not merely "not LANDED": the exact fault the taxonomy owes, so a guard that fired for
    // the wrong reason (or a position whose verification never ran) fails here.
    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: expectedFault(vector) });
    // The promotion boundary itself: the observation mapper cannot emit a PROOF, and the
    // reconcile fold cannot reach a landed verdict.
    const observation = landingProofToPathObservation(outcome);
    expect(observation.result).toBe("PROOF_INCOMPLETE");
    expect(classifyReceiveReconcile(receiveEvidence(observation)).kind).toBe("INDETERMINATE");
  });

  it("the pristine golden queried by a wallet with no role in it promotes nothing", async () => {
    const outcome = await proveReceiveLanding(
      { ...CONTROL_INPUT, walletPubkeyBase64Urlsafe: ABSENT_WALLET },
      staticReader(CONTROL_HEAD),
    );

    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "ANOMALOUS_OR_CONTRADICTORY" });
    expect(
      classifyReceiveReconcile(receiveEvidence(landingProofToPathObservation(outcome))).kind,
    ).toBe("INDETERMINATE");
  });
});

describe("state-promotion seam — envelope-stage rejects yield no body to promote with", () => {
  it.each(envelopeVectors)("$name produces no ParsedSettledTransaction at all", (vector) => {
    const verdict = parseGatewayEnvelope(attackBytes(vector.file));

    expect(verdict.classification).toBe("MALFORMED_ENVELOPE");
    // `parsed` is the only channel by which bytes become oracle input; null here means an
    // envelope-stage reject is unconstructible as evidence, not merely rejected later.
    expect(verdict.parsed).toBeNull();
  });

  it.each(envelopeVectors)(
    "$name in the authoritative head position yields no proof",
    async (vector) => {
      const outcome = await proveReceiveLanding(CONTROL_INPUT, async () => ({
        observationId: `obs-${vector.name}`,
        envelope: parseGatewayEnvelope(attackBytes(vector.file)),
      }));

      expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "MALFORMED_BODY" });
      expect(
        classifyReceiveReconcile(receiveEvidence(landingProofToPathObservation(outcome))).kind,
      ).toBe("INDETERMINATE");
    },
  );
});
