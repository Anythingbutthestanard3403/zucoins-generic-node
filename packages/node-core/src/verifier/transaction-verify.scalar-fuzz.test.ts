// shape and scalar grammar fail-closed batteries for the
// pre-signature stage: inner literal deviations, state-object shape deviations, and the
// branded-scalar violation matrix (each vector asserts the exact rejection code and the
// validator's own scalar vocabulary). Every vector mutates a clone of a frozen
// fixture — adversarial inputs only, expected bytes never regenerated. Signature-level
// and role-level negatives live in transaction-verify.fuzz.test.ts.
import { Buffer } from "node:buffer";
import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { parseGatewayEnvelope, type ParsedSettledTransaction } from "./gateway-envelope.js";
import {
  verifySettledTransaction,
  type MalformedTransactionVerdict,
} from "./transaction-verify.js";

const GEN_DIR = new URL("../../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function headParsed(name: string): ParsedSettledTransaction {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${fixtureText(name)}]}`,
  );
  const verdict = parseGatewayEnvelope(bytes);
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD envelope verdict");
  return verdict.parsed;
}

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
};
const RECEIVER_KEY = MANIFEST.public_keys.seed_03;
const SENDER_KEY = MANIFEST.public_keys.seed_02;

function cloneTx(tx: ParsedSettledTransaction): ParsedSettledTransaction {
  return JSON.parse(JSON.stringify(tx)) as ParsedSettledTransaction;
}

function target(): ParsedSettledTransaction {
  return headParsed("target.settled.json");
}

function innerOf(tx: ParsedSettledTransaction): Record<string, unknown> {
  return tx.inner as Record<string, unknown>;
}

function expectMalformed(tx: ParsedSettledTransaction): MalformedTransactionVerdict {
  const verdict = verifySettledTransaction(tx, RECEIVER_KEY);
  expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
  if (verdict.verdict !== "MALFORMED_TRANSACTION") throw new Error("expected MALFORMED_TRANSACTION");
  return verdict;
}

function expectShapeRejection(mutate: (inner: Record<string, unknown>) => void): void {
  const tx = cloneTx(target());
  mutate(innerOf(tx));
  expect(expectMalformed(tx).rejection.reason).toBe("unexpected_inner_shape");
}

// Test-only re-signing over a MUTATED inner, using the seeds the manifest itself declares
// ("test-only 32-byte filled Ed25519 seeds 02, 03, and 05"): seed 02 signs step 1 as sender,
// seed 03 signs step 2 as receiver. Both preimages are taken with JSON.stringify directly on
// the insertion-sequenced object — the exact construction transaction-verify.ts performs — so
// a vector that VERIFIES here proves the verifier read the mutated bytes verbatim, and a
// vector that is rejected was rejected on its own merits, not on a stale signature.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function signAsSeed(preimageText: string, seed: number): string {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.alloc(32, seed)]),
    format: "der",
    type: "pkcs8",
  });
  return `${sign(null, Buffer.from(preimageText, "utf8"), privateKey).toString("base64url")}==`;
}

function resigned(mutate: (inner: Record<string, unknown>) => void): ParsedSettledTransaction {
  const tx = cloneTx(target());
  const inner = innerOf(tx);
  mutate(inner);
  const step1Signature = signAsSeed(JSON.stringify(inner), 2);
  const step2Signature = signAsSeed(
    JSON.stringify({ inner, step_1_signature: step1Signature }),
    3,
  );
  return { ...tx, step_1_signature: step1Signature, step_2_signature: step2Signature };
}

function expectScalarRejection(
  mutate: (inner: Record<string, unknown>) => void,
  scalarKind: string,
  scalarReason: string,
): void {
  const tx = cloneTx(target());
  mutate(innerOf(tx));
  expect(expectMalformed(tx).rejection).toMatchObject({
    reason: "invalid_scalar",
    scalarKind,
    scalarReason,
  });
}

describe("inner literals and field set — unexpected_inner_shape", () => {
  it("rejects a wrong type literal", () => {
    expectShapeRejection((inner) => {
      inner.type = "combinable";
    });
  });

  it("rejects a wrong version literal", () => {
    expectShapeRejection((inner) => {
      inner.version = "1";
    });
  });

  it("rejects signer_steps as the string \"2\" (must be the number 2)", () => {
    expectShapeRejection((inner) => {
      inner.signer_steps = "2";
    });
  });

  it("rejects signer_steps as the number 3", () => {
    expectShapeRejection((inner) => {
      inner.signer_steps = 3;
    });
  });

  it("rejects a swapped signer literal", () => {
    expectShapeRejection((inner) => {
      inner.step_1_signer = "receiver";
    });
  });

  it("rejects an unknown extra inner field", () => {
    expectShapeRejection((inner) => {
      inner.routed_via = "elsewhere";
    });
  });

  it("rejects a missing required field (unix_time_secs deleted)", () => {
    expectShapeRejection((inner) => {
      delete inner.unix_time_secs;
    });
  });

  it("rejects the optionals in the wrong trailing position (message before expiry)", () => {
    const tx = cloneTx(target()); // carries expiry then message
    const inner = innerOf(tx);
    const expiry = inner.expiry__unix_time_secs;
    const message = inner.message;
    delete inner.expiry__unix_time_secs;
    delete inner.message;
    inner.message = message;
    inner.expiry__unix_time_secs = expiry;
    expect(expectMalformed(tx).rejection.reason).toBe("unexpected_inner_shape");
  });
});

describe("state-object shape — unexpected_inner_shape", () => {
  it("rejects a state object with an extra field", () => {
    expectShapeRejection((inner) => {
      inner.step_1_state = { amount: "7.75", extra: true };
    });
  });

  it("rejects a state array", () => {
    expectShapeRejection((inner) => {
      inner.step_2_state = ["2.25"];
    });
  });

  it("rejects a null state", () => {
    expectShapeRejection((inner) => {
      inner.step_1_state = null;
    });
  });

  it("rejects metadata sequenced before amount", () => {
    expectShapeRejection((inner) => {
      inner.step_1_state = { metadata: null, amount: "7.75" };
    });
  });
});

describe("branded scalar matrix — invalid_scalar with the validator's own vocabulary", () => {
  it("rejects a numeric unix_time_secs (stays a SECONDS string)", () => {
    expectScalarRejection((inner) => {
      inner.unix_time_secs = 1784332800;
    }, "UnixTimeSecsV2", "wrong_type");
  });

  it("rejects an empty unix_time_secs", () => {
    expectScalarRejection((inner) => {
      inner.unix_time_secs = "";
    }, "UnixTimeSecsV2", "invalid_format");
  });

  it("rejects a numeric amount (string-only per)", () => {
    expectScalarRejection((inner) => {
      inner.step_2_state = { amount: 2.25 };
    }, "ZkzBalance", "wrong_type");
  });

  it("rejects an amount with a leading zero", () => {
    expectScalarRejection((inner) => {
      inner.step_1_state = { amount: "07.75" };
    }, "ZkzBalance", "invalid_format");
  });

  it("rejects a negative amount", () => {
    expectScalarRejection((inner) => {
      inner.step_1_state = { amount: "-1" };
    }, "ZkzBalance", "invalid_format");
  });

  it("rejects exponential notation", () => {
    expectScalarRejection((inner) => {
      inner.step_1_state = { amount: "1e3" };
    }, "ZkzBalance", "invalid_format");
  });

  it("rejects an amount at the exclusive protocol bound (grammar width caps it first)", () => {
    expectScalarRejection((inner) => {
      inner.step_1_state = { amount: "100000000" };
    }, "ZkzBalance", "invalid_format");
  });

  it("rejects an empty amount", () => {
    expectScalarRejection((inner) => {
      inner.step_1_state = { amount: "" };
    }, "ZkzBalance", "invalid_format");
  });

  it("rejects an unpadded wallet public key", () => {
    expectScalarRejection((inner) => {
      inner.step_1_key_public__base64urlsafe = SENDER_KEY.slice(0, -1);
    }, "WalletPublicKey", "invalid_format");
  });

  it("rejects standard-base64 alphabet in a wallet public key", () => {
    expectScalarRejection((inner) => {
      inner.step_1_key_public__base64urlsafe = SENDER_KEY.replace("-", "+");
    }, "WalletPublicKey", "invalid_format");
  });

  it("rejects a garbage previous-state signature", () => {
    expectScalarRejection((inner) => {
      inner.previous_step_1_state_signature = "not-a-signature";
    }, "PreviousStateSignature", "invalid_format");
  });

  it("rejects an unpadded previous-state signature", () => {
    expectScalarRejection((inner) => {
      inner.previous_step_1_state_signature = String(
        inner.previous_step_1_state_signature,
      ).slice(0, -2);
    }, "PreviousStateSignature", "invalid_format");
  });

  it("rejects a fractional expiry", () => {
    expectScalarRejection((inner) => {
      inner.expiry__unix_time_secs = "1784336400.5";
    }, "ExpiryUnixTimeSecs", "invalid_format");
  });

  it("rejects a negative expiry", () => {
    expectScalarRejection((inner) => {
      inner.expiry__unix_time_secs = "-1";
    }, "ExpiryUnixTimeSecs", "invalid_format");
  });

  it("rejects a message over the 256-scalar limit", () => {
    expectScalarRejection((inner) => {
      inner.message = "x".repeat(257);
    }, "OpaqueReference", "limit_exceeded");
  });

  it("rejects a message carrying a lone surrogate", () => {
    expectScalarRejection((inner) => {
      inner.message = "\ud800";
    }, "OpaqueReference", "invalid_utf16");
  });
});

// Canonical ZKZ amount contract: fields 9–10 are FOREIGN-signed absolute balances, judged by the ZkzAmount
// grammar alone. The grammar prohibits sign, exponent, separators, leading zeros and a
// trailing decimal point — but NOT trailing fractional zeros, so "7.50" is a valid
// ZkzAmount. Re-judging it against the node's construction format is a false reject, and on
// the money path a false reject is a stuck settlement (FAIL class). These
// vectors carry genuine dual signatures over the exact mutated preimage, so nothing here
// weakens the fail-closed posture — the last case proves the grammar still bites when the
// signatures are real.
describe("foreign-signed amounts — grammar only, never re-canonicalized", () => {
  it("VERIFIES the re-signing harness itself against an unmutated inner", () => {
    // Control: without this, a VERIFIED below could be an artifact of the harness rather
    // than evidence about the amount rule.
    const verdict = verifySettledTransaction(resigned(() => {}), RECEIVER_KEY);
    expect(verdict.verdict).toBe("VERIFIED");
  });

  it("VERIFIES trailing-zero fractional amounts and keeps the signed text verbatim", () => {
    const verdict = verifySettledTransaction(
      resigned((inner) => {
        inner.step_1_state = { amount: "7.50" };
        inner.step_2_state = { amount: "2.50" };
      }),
      RECEIVER_KEY,
    );
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict !== "VERIFIED") return;

    // The byte-exact signing rule: the reconstructed preimage carries "7.50"/"2.50" byte-for-byte — never
    // rewritten to the node's canonical "7.5"/"2.5".
    expect(verdict.innerPreimageText).toContain('"step_1_state":{"amount":"7.50"}');
    expect(verdict.innerPreimageText).toContain('"step_2_state":{"amount":"2.50"}');
    expect(verdict.innerPreimageText).not.toContain('"7.5"');
    // The receiver's role-relative B is the verbatim signed balance.
    expect(verdict.projection.B).toBe("2.50");
  });

  it("VERIFIES for the sender with the verbatim sender-side balance", () => {
    const verdict = verifySettledTransaction(
      resigned((inner) => {
        inner.step_1_state = { amount: "7.50" };
        inner.step_2_state = { amount: "2.50" };
      }),
      SENDER_KEY,
    );
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict !== "VERIFIED") return;
    expect(verdict.projection.B).toBe("7.50");
  });

  it('VERIFIES a swept payer signing the legal "0" balance (canonical ZKZ amount contract)', () => {
    const verdict = verifySettledTransaction(
      resigned((inner) => {
        inner.step_1_state = { amount: "0" };
      }),
      SENDER_KEY,
    );
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict !== "VERIFIED") return;
    expect(verdict.projection.B).toBe("0");
  });

  it("VERIFIES a maximally long fractional amount inside the 32-dp grammar", () => {
    const amount = `7.${"0".repeat(31)}5`;
    const verdict = verifySettledTransaction(
      resigned((inner) => {
        inner.step_1_state = { amount };
      }),
      SENDER_KEY,
    );
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict !== "VERIFIED") return;
    expect(verdict.projection.B).toBe(amount);
  });

  it("still rejects a grammar violation even with genuine dual signatures over it", () => {
    const tx = resigned((inner) => {
      inner.step_1_state = { amount: "7.5.0" };
    });
    const verdict = verifySettledTransaction(tx, RECEIVER_KEY);
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    if (verdict.verdict !== "MALFORMED_TRANSACTION") return;
    expect(verdict.rejection).toMatchObject({
      reason: "invalid_scalar",
      scalarKind: "ZkzBalance",
      scalarReason: "invalid_format",
    });
  });

  it("still rejects a 33-dp amount even with genuine dual signatures over it", () => {
    const tx = resigned((inner) => {
      inner.step_1_state = { amount: `7.${"0".repeat(32)}5` };
    });
    const verdict = verifySettledTransaction(tx, RECEIVER_KEY);
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    if (verdict.verdict !== "MALFORMED_TRANSACTION") return;
    expect(verdict.rejection).toMatchObject({
      reason: "invalid_scalar",
      scalarKind: "ZkzBalance",
      scalarReason: "invalid_format",
    });
  });
});

// Canonical ZKZ amount contract (the same foreign-signed grammar-vs-canonical layer boundary fixed for the
// step amounts): field 3 (unix_time_secs) is a FOREIGN-signed SECONDS string judged by the
// acceptance grammar alone. A foreign wallet may legitimately sign a grammar-valid but non-canonical
// spelling with trailing fractional zeros such as "1784332800.50"; that text must not be rejected
// before the signature check (the byte-exact signing rule — the node never rewrites signed bytes to its own
// shortest form). These vectors carry genuine dual signatures over the exact mutated preimage, so
// nothing here weakens the fail-closed posture — the last cases prove the grammar (1–3 fractional
// digits, no bare decimal point) still bites when the signatures are real.
describe("foreign-signed unix_time_secs — grammar only, never re-canonicalized", () => {
  it("VERIFIES a trailing-zero fractional unix_time_secs and keeps the signed text verbatim", () => {
    const verdict = verifySettledTransaction(
      resigned((inner) => {
        inner.unix_time_secs = "1784332800.50";
      }),
      RECEIVER_KEY,
    );
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict !== "VERIFIED") return;

    // The byte-exact signing rule: the reconstructed preimage carries "1784332800.50" byte-for-byte —
    // never rewritten to the node's canonical "1784332800.5".
    expect(verdict.innerPreimageText).toContain('"unix_time_secs":"1784332800.50"');
    expect(verdict.innerPreimageText).not.toContain('"unix_time_secs":"1784332800.5"');
  });

  it("VERIFIES a 3-digit fractional unix_time_secs with a trailing zero", () => {
    const verdict = verifySettledTransaction(
      resigned((inner) => {
        inner.unix_time_secs = "1784332800.500";
      }),
      RECEIVER_KEY,
    );
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict !== "VERIFIED") return;
    expect(verdict.innerPreimageText).toContain('"unix_time_secs":"1784332800.500"');
  });

  it("VERIFIES a 1-digit fractional unix_time_secs (accepted before the relax too)", () => {
    const verdict = verifySettledTransaction(
      resigned((inner) => {
        inner.unix_time_secs = "1784332800.5";
      }),
      RECEIVER_KEY,
    );
    expect(verdict.verdict).toBe("VERIFIED");
  });

  it("VERIFIES an integer unix_time_secs (no fractional part)", () => {
    const verdict = verifySettledTransaction(
      resigned((inner) => {
        inner.unix_time_secs = "1784332800";
      }),
      RECEIVER_KEY,
    );
    expect(verdict.verdict).toBe("VERIFIED");
  });

  it("still rejects a 4-digit fractional unix_time_secs even with genuine dual signatures over it", () => {
    const tx = resigned((inner) => {
      inner.unix_time_secs = "1784332800.1234";
    });
    const verdict = verifySettledTransaction(tx, RECEIVER_KEY);
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    if (verdict.verdict !== "MALFORMED_TRANSACTION") return;
    expect(verdict.rejection).toMatchObject({
      reason: "invalid_scalar",
      scalarKind: "UnixTimeSecsV2",
      scalarReason: "invalid_format",
    });
  });

  it("still rejects a bare decimal point (no fractional digits) even with genuine dual signatures over it", () => {
    const tx = resigned((inner) => {
      inner.unix_time_secs = "1784332800.";
    });
    const verdict = verifySettledTransaction(tx, RECEIVER_KEY);
    expect(verdict.verdict).toBe("MALFORMED_TRANSACTION");
    if (verdict.verdict !== "MALFORMED_TRANSACTION") return;
    expect(verdict.rejection).toMatchObject({
      reason: "invalid_scalar",
      scalarKind: "UnixTimeSecsV2",
      scalarReason: "invalid_format",
    });
  });
});
