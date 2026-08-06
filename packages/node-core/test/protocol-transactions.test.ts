import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  TransactionConstructionError,
  buildSettledSplitChainTransactionV2,
  buildSplitChainInnerV2,
  buildSplitChainPartialV2,
  issueCoherentWalletBaselineV2ForVerifiedHead,
  type BuildSplitChainInnerV2Input,
  type SplitChainInnerV2Capability,
  type SplitChainPartialV2Capability,
  type WalletBaselineV2Capability,
  type WalletBaselineV2Input,
} from "../src/protocol/transactions.js";
import {
  InvalidScalarError,
  parseEd25519Signature,
  parseExpiryUnixTimeSecs,
  parseObservedZkzBalance,
  parsePositiveZkzAmount,
  parsePreviousStateSignature,
  parseUnixTimeSecsV2,
  parseWalletPublicKey,
  parseZkzBalance,
} from "../src/protocol/index.js";
import {
  A8_INNER_PREIMAGE_LENGTH,
  A8_INNER_PREIMAGE_SHA256,
  A8_INNER_PREIMAGE_TEXT,
  CANONICAL_INNER_FIELD_ORDER,
  WALLET_INNER_PREIMAGE_LENGTH,
  WALLET_INNER_PREIMAGE_SHA256,
  WALLET_INNER_PREIMAGE_TEXT,
  WALLET_RECEIVER_PUBLIC_KEY,
  WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
  WALLET_SENDER_PUBLIC_KEY,
  WALLET_SETTLED_TRANSACTION_LENGTH,
  WALLET_SETTLED_TRANSACTION_SHA256,
  WALLET_SETTLED_TRANSACTION_TEXT,
  WALLET_STEP_1_SIGNATURE,
  WALLET_STEP_2_PREIMAGE_LENGTH,
  WALLET_STEP_2_PREIMAGE_SHA256,
  WALLET_STEP_2_PREIMAGE_TEXT,
  WALLET_STEP_2_SIGNATURE,
} from "./fixtures/splitchain-v2-byte-evidence.js";

const ABSENT = Symbol("absent optional test value");

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function senderBaselineInput(): WalletBaselineV2Input {
  return {
    kind: "HEAD",
    publicKey: parseWalletPublicKey(WALLET_SENDER_PUBLIC_KEY),
    balance: parseObservedZkzBalance("10"),
    previousSettledStep2Signature: parsePreviousStateSignature(
      WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
    ),
  };
}

function receiverBaselineInput(): WalletBaselineV2Input {
  return {
    kind: "GENESIS",
    publicKey: parseWalletPublicKey(WALLET_RECEIVER_PUBLIC_KEY),
    balance: parseObservedZkzBalance("0"),
    previousSettledStep2Signature: parsePreviousStateSignature(""),
  };
}

function validInput(
  expiry: string | typeof ABSENT = "1718000300",
  message: string | typeof ABSENT = "zup_sess_3f9a1c00d24b48e7",
): BuildSplitChainInnerV2Input {
  const input = {
    unixTimeSecs: parseUnixTimeSecsV2("1718000000.123"),
    sender: issueCoherentWalletBaselineV2ForVerifiedHead(senderBaselineInput()),
    receiver: issueCoherentWalletBaselineV2ForVerifiedHead(receiverBaselineInput()),
    transferAmount: parsePositiveZkzAmount("2.5"),
  } as BuildSplitChainInnerV2Input;

  if (expiry !== ABSENT) {
    (input as { expiryUnixTimeSecs?: unknown }).expiryUnixTimeSecs =
      parseExpiryUnixTimeSecs(expiry);
  }
  if (message !== ABSENT) {
    (input as { message?: unknown }).message = message;
  }
  return input;
}

function buildUnsafe(value: unknown): SplitChainInnerV2Capability {
  return buildSplitChainInnerV2(value as BuildSplitChainInnerV2Input);
}

function issueBaselineUnsafe(value: unknown): WalletBaselineV2Capability {
  return issueCoherentWalletBaselineV2ForVerifiedHead(value as WalletBaselineV2Input);
}

function expectConstructionReason(operation: () => unknown, reason: string): void {
  try {
    operation();
    throw new Error("expected construction rejection");
  } catch (error) {
    expect(error).toBeInstanceOf(TransactionConstructionError);
    expect((error as TransactionConstructionError).reason).toBe(reason);
  }
}

describe("independent byte evidence", () => {
  it("pins Appendix A.8 as immutable field-order and digest evidence", () => {
    expect(Buffer.byteLength(A8_INNER_PREIMAGE_TEXT, "utf8")).toBe(A8_INNER_PREIMAGE_LENGTH);
    expect(sha256(A8_INNER_PREIMAGE_TEXT)).toBe(A8_INNER_PREIMAGE_SHA256);
    expect(Object.keys(JSON.parse(A8_INNER_PREIMAGE_TEXT))).toEqual(CANONICAL_INNER_FIELD_ORDER);
  });

  it("matches the full wallet-captured inner before checking its length and digest", () => {
    const capability = buildSplitChainInnerV2(validInput());
    expect(capability.innerPreimageText).toBe(WALLET_INNER_PREIMAGE_TEXT);
    expect(Buffer.byteLength(capability.innerPreimageText, "utf8")).toBe(
      WALLET_INNER_PREIMAGE_LENGTH,
    );
    expect(capability.innerPreimageSha256).toBe(WALLET_INNER_PREIMAGE_SHA256);
  });

  it("matches the full wallet-captured step-2 preimage and settled container", () => {
    const inner = buildSplitChainInnerV2(validInput());
    const partial = buildSplitChainPartialV2(
      inner,
      parseEd25519Signature(WALLET_STEP_1_SIGNATURE),
    );
    expect(partial.step2PreimageText).toBe(WALLET_STEP_2_PREIMAGE_TEXT);
    expect(partial.partialText).toBe(WALLET_STEP_2_PREIMAGE_TEXT);
    expect(Buffer.byteLength(partial.step2PreimageText, "utf8")).toBe(
      WALLET_STEP_2_PREIMAGE_LENGTH,
    );
    expect(partial.step2PreimageSha256).toBe(WALLET_STEP_2_PREIMAGE_SHA256);

    const settled = buildSettledSplitChainTransactionV2(
      partial,
      parseEd25519Signature(WALLET_STEP_2_SIGNATURE),
    );
    expect(settled.transactionText).toBe(WALLET_SETTLED_TRANSACTION_TEXT);
    expect(Buffer.byteLength(settled.transactionText, "utf8")).toBe(
      WALLET_SETTLED_TRANSACTION_LENGTH,
    );
    expect(settled.transactionSha256).toBe(WALLET_SETTLED_TRANSACTION_SHA256);
  });
});

describe("ordered node-authored inner projection", () => {
  it("uses null prototypes, direct fixed roles, absolute balances, and deep freezing", () => {
    const capability = buildSplitChainInnerV2(validInput());
    expect(Object.getPrototypeOf(capability.inner)).toBe(null);
    expect(Object.getPrototypeOf(capability.inner.step_1_state)).toBe(null);
    expect(Object.getPrototypeOf(capability.inner.step_2_state)).toBe(null);
    expect(Object.keys(capability.inner)).toEqual(CANONICAL_INNER_FIELD_ORDER);
    expect(Object.keys(capability.inner.step_1_state)).toEqual(["amount"]);
    expect(Object.keys(capability.inner.step_2_state)).toEqual(["amount"]);
    expect(capability.inner.type).toBe("unique_combinable");
    expect(capability.inner.version).toBe("2");
    expect(capability.inner.signer_steps).toBe(2);
    expect(capability.inner.step_1_signer).toBe("sender");
    expect(capability.inner.step_2_signer).toBe("receiver");
    expect(capability.inner.step_1_state.amount).toBe("7.5");
    expect(capability.inner.step_2_state.amount).toBe("2.5");
    expect(Object.isFrozen(capability)).toBe(true);
    expect(Object.isFrozen(capability.inner)).toBe(true);
    expect(Object.isFrozen(capability.inner.step_1_state)).toBe(true);
    expect(Object.isFrozen(capability.inner.step_2_state)).toBe(true);
    expect(Reflect.set(capability.inner, "message", "mutated")).toBe(false);
  });

  it("emits all four optional permutations in the one permitted order", () => {
    const none = buildSplitChainInnerV2(validInput(ABSENT, ABSENT));
    const expiryOnly = buildSplitChainInnerV2(validInput("1718000300", ABSENT));
    const messageOnly = buildSplitChainInnerV2(validInput(ABSENT, "message"));
    const both = buildSplitChainInnerV2(validInput("1718000300", "message"));

    expect(Object.keys(none.inner)).toEqual(CANONICAL_INNER_FIELD_ORDER.slice(0, 12));
    expect(Object.keys(expiryOnly.inner)).toEqual([
      ...CANONICAL_INNER_FIELD_ORDER.slice(0, 12),
      "expiry__unix_time_secs",
    ]);
    expect(Object.keys(messageOnly.inner)).toEqual([
      ...CANONICAL_INNER_FIELD_ORDER.slice(0, 12),
      "message",
    ]);
    expect(Object.keys(both.inner)).toEqual(CANONICAL_INNER_FIELD_ORDER);
  });

  it("treats own undefined optionals as absent and ignores caller property order", () => {
    const canonical = validInput(ABSENT, ABSENT);
    const reordered = {
      receiver: canonical.receiver,
      message: undefined,
      transferAmount: canonical.transferAmount,
      sender: canonical.sender,
      expiryUnixTimeSecs: undefined,
      unixTimeSecs: canonical.unixTimeSecs,
    };
    const actual = buildUnsafe(reordered);
    expect(Object.keys(actual.inner)).toEqual(CANONICAL_INNER_FIELD_ORDER.slice(0, 12));
    expect(actual.innerPreimageText).toBe(
      buildSplitChainInnerV2(validInput(ABSENT, ABSENT)).innerPreimageText,
    );
  });

  it("makes adjacent-order, missing-field, extra-field, and whitespace mutations byte-distinct", () => {
    const exact = buildSplitChainInnerV2(validInput()).innerPreimageText;
    const swapped = exact.replace(
      '{"type":"unique_combinable","version":"2"',
      '{"version":"2","type":"unique_combinable"',
    );
    const missing = exact.replace(',"step_2_signer":"receiver"', "");
    const extra = exact.replace('{"type":', '{"unexpected":true,"type":');
    const whitespace = exact.replace('"version":"2"', '"version": "2"');
    for (const mutation of [swapped, missing, extra, whitespace]) {
      expect(mutation).not.toBe(exact);
      expect(sha256(mutation)).not.toBe(sha256(exact));
    }
  });
});

describe("strict descriptor-snapshot input boundary", () => {
  it("accepts exact null-prototype parameter and baseline objects", () => {
    const source = validInput();
    const sender = Object.create(null) as { [key: string]: unknown };
    const senderSource = senderBaselineInput();
    sender.kind = senderSource.kind;
    sender.publicKey = senderSource.publicKey;
    sender.balance = senderSource.balance;
    sender.previousSettledStep2Signature = senderSource.previousSettledStep2Signature;
    const receiver = Object.create(null) as { [key: string]: unknown };
    const receiverSource = receiverBaselineInput();
    receiver.kind = receiverSource.kind;
    receiver.publicKey = receiverSource.publicKey;
    receiver.balance = receiverSource.balance;
    receiver.previousSettledStep2Signature = receiverSource.previousSettledStep2Signature;
    const input = Object.create(null) as { [key: string]: unknown };
    input.unixTimeSecs = source.unixTimeSecs;
    input.sender = issueBaselineUnsafe(sender);
    input.receiver = issueBaselineUnsafe(receiver);
    input.transferAmount = source.transferAmount;
    input.expiryUnixTimeSecs = source.expiryUnixTimeSecs;
    input.message = source.message;
    expect(buildUnsafe(input).innerPreimageText).toBe(WALLET_INNER_PREIMAGE_TEXT);
  });

  it("rejects arrays, boxed primitives, custom prototypes, missing, and extra keys", () => {
    expectConstructionReason(() => buildUnsafe([]), "invalid_object");
    expectConstructionReason(() => buildUnsafe(new String("unsafe")), "unsafe_prototype");
    const missing = validInput() as unknown as { transferAmount?: unknown };
    delete missing.transferAmount;
    expectConstructionReason(() => buildUnsafe(missing), "invalid_properties");
    expectConstructionReason(
      () => buildUnsafe({ ...validInput(), unexpected: true }),
      "invalid_properties",
    );
    expectConstructionReason(
      () => buildUnsafe(Object.create({ inherited: true })),
      "unsafe_prototype",
    );
  });

  it("rejects accessors without invoking getters that change values", () => {
    let topReads = 0;
    const top = validInput();
    Object.defineProperty(top, "unixTimeSecs", {
      enumerable: true,
      get() {
        topReads += 1;
        return topReads === 1 ? "1718000000.123" : "1718000001.123";
      },
    });
    expectConstructionReason(() => buildUnsafe(top), "accessor_property");
    expect(topReads).toBe(0);

    let nestedReads = 0;
    const nested = senderBaselineInput();
    Object.defineProperty(nested, "balance", {
      enumerable: true,
      get() {
        nestedReads += 1;
        return "10";
      },
    });
    expectConstructionReason(() => issueBaselineUnsafe(nested), "accessor_property");
    expect(nestedReads).toBe(0);
  });

  it("snapshots data descriptors without direct property gets", () => {
    let gets = 0;
    const proxied = new Proxy(validInput(), {
      get(target, property, receiver) {
        gets += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    expect(buildUnsafe(proxied).innerPreimageText).toBe(WALLET_INNER_PREIMAGE_TEXT);
    expect(gets).toBe(0);
  });

  it("rejects symbols and dangerous own property names", () => {
    const symbolInput = validInput() as unknown as { [key: symbol]: unknown };
    symbolInput[Symbol("hidden")] = true;
    expectConstructionReason(() => buildUnsafe(symbolInput), "invalid_properties");

    for (const dangerous of ["constructor", "prototype", "__proto__"] as const) {
      const input = Object.create(null) as { [key: string]: unknown };
      const source = validInput();
      input.unixTimeSecs = source.unixTimeSecs;
      input.sender = source.sender;
      input.receiver = source.receiver;
      input.transferAmount = source.transferAmount;
      input[dangerous] = true;
      expectConstructionReason(() => buildUnsafe(input), "invalid_properties");
    }
  });

  it("rejects own, inherited, and polluted Object.prototype toJSON hazards", () => {
    expectConstructionReason(
      () => buildUnsafe({ ...validInput(), toJSON: () => ({}) }),
      "unsafe_to_json",
    );

    const inherited = Object.create({ toJSON: () => ({}) }) as { [key: string]: unknown };
    expectConstructionReason(() => buildUnsafe(inherited), "unsafe_prototype");

    Object.defineProperty(Object.prototype, "toJSON", {
      configurable: true,
      value: () => ({}),
    });
    try {
      expectConstructionReason(() => buildSplitChainInnerV2(validInput()), "unsafe_to_json");
    } finally {
      delete (Object.prototype as { toJSON?: unknown }).toJSON;
    }
  });
});

describe("runtime scalar, balance, role, and link validation", () => {
  it("revalidates forged brands, numeric amounts, spellings, keys, and links", () => {
    const topLevelMutations: unknown[] = [
      { ...validInput(), transferAmount: 2.5 },
      { ...validInput(), transferAmount: "2.50" },
      { ...validInput(), transferAmount: "2.5e0" },
      { ...validInput(), unixTimeSecs: 1718000000.123 },
      { ...validInput(), unixTimeSecs: "1718000000.1230" },
    ];
    for (const mutation of topLevelMutations) expect(() => buildUnsafe(mutation)).toThrow();

    expect(() =>
      issueBaselineUnsafe({
        ...senderBaselineInput(),
        publicKey: WALLET_SENDER_PUBLIC_KEY.slice(0, -1),
      }),
    ).toThrow();
    expect(() =>
      issueBaselineUnsafe({
        ...senderBaselineInput(),
        previousSettledStep2Signature: WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE.slice(0, -2),
      }),
    ).toThrow();
  });

  it("rejects self-transfer and arithmetic underflow or overflow", () => {
    expectConstructionReason(
      () =>
        buildUnsafe({
          ...validInput(),
          receiver: issueCoherentWalletBaselineV2ForVerifiedHead({
            ...receiverBaselineInput(),
            publicKey: validInput().sender.publicKey,
          }),
        }),
      "same_wallet",
    );
    expect(() =>
      buildUnsafe({ ...validInput(), transferAmount: parsePositiveZkzAmount("10.1") }),
    ).toThrow();
    expect(() =>
      buildUnsafe({
        ...validInput(),
        receiver: issueCoherentWalletBaselineV2ForVerifiedHead({
          ...receiverBaselineInput(),
          kind: "HEAD",
          balance: parseObservedZkzBalance("99999999.9"),
          previousSettledStep2Signature: parsePreviousStateSignature(WALLET_STEP_2_SIGNATURE),
        }),
      }),
    ).toThrow();
  });

  it("enforces the closed GENESIS and HEAD baseline variant matrix", () => {
    const genesis = issueCoherentWalletBaselineV2ForVerifiedHead(receiverBaselineInput());
    const zeroHead = issueCoherentWalletBaselineV2ForVerifiedHead({
      ...receiverBaselineInput(),
      kind: "HEAD",
      previousSettledStep2Signature: parsePreviousStateSignature(WALLET_STEP_2_SIGNATURE),
    });
    const positiveHead = issueCoherentWalletBaselineV2ForVerifiedHead(senderBaselineInput());

    expect(genesis.kind).toBe("GENESIS");
    expect(genesis.balance).toBe("0");
    expect(genesis.previousSettledStep2Signature).toBe("");
    expect(zeroHead.kind).toBe("HEAD");
    expect(zeroHead.balance).toBe("0");
    expect(zeroHead.previousSettledStep2Signature).toBe(WALLET_STEP_2_SIGNATURE);
    expect(positiveHead.kind).toBe("HEAD");
    expect(positiveHead.balance).toBe("10");

    for (const invalid of [
      { ...receiverBaselineInput(), balance: parseObservedZkzBalance("1") },
      {
        ...receiverBaselineInput(),
        previousSettledStep2Signature: parsePreviousStateSignature(WALLET_STEP_2_SIGNATURE),
      },
      { ...receiverBaselineInput(), kind: "HEAD" },
      {
        ...senderBaselineInput(),
        previousSettledStep2Signature: parsePreviousStateSignature(""),
      },
    ]) {
      expectConstructionReason(() => issueBaselineUnsafe(invalid), "invalid_genesis_link");
    }
  });

  it("retains the issued variant while emitting the role-correct predecessor link", () => {
    const input = validInput();
    expect(input.sender.kind).toBe("HEAD");
    expect(input.receiver.kind).toBe("GENESIS");
    const inner = buildSplitChainInnerV2(input).inner;
    expect(inner.previous_step_1_state_signature).toBe(
      WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE,
    );
    expect(inner.previous_step_2_state_signature).toBe("");
  });

  it("keeps A.8 as raw bytes but rejects its invalid nonzero empty-link lineage", () => {
    const a8 = JSON.parse(A8_INNER_PREIMAGE_TEXT) as {
      step_1_state: { amount: string };
      previous_step_1_state_signature: string;
    };
    expect(a8.step_1_state.amount).toBe("7.75");
    expect(a8.previous_step_1_state_signature).toBe("");
    expect(A8_INNER_PREIMAGE_SHA256).toBe(sha256(A8_INNER_PREIMAGE_TEXT));
    expectConstructionReason(
      () =>
        issueBaselineUnsafe({
          kind: "HEAD",
          publicKey: parseWalletPublicKey(WALLET_SENDER_PUBLIC_KEY),
          balance: parseObservedZkzBalance("10"),
          previousSettledStep2Signature: parsePreviousStateSignature(""),
        }),
      "invalid_genesis_link",
    );
  });
});

// the observation/baseline boundary is the FOREIGN-signed layer: an observed
// wallet-head balance is validated by the ZkzAmount grammar alone and preserved verbatim, so a
// legitimately non-canonical head spelling such as "2.50" is accepted instead of being
// false-rejected into a stuck settlement (the foreign-signed grammar pattern). Node-authored construction
// stays strict: it only ever emits canonical shortest form.
describe("observation-boundary grammar-only balance", () => {
  it("accepts a non-canonical observed balance '2.50' at the verified-head boundary (previously threw non_canonical)", () => {
    const capability = issueCoherentWalletBaselineV2ForVerifiedHead({
      ...senderBaselineInput(),
      balance: parseObservedZkzBalance("2.50"),
    });
    // Exact observed bytes preserved on the capability — never re-canonicalized to "2.5".
    expect(capability.balance).toBe("2.50");
    expect(capability.kind).toBe("HEAD");
  });

  it("accepts the foreign-signed '7.50' balance that previously broke the observation boundary", () => {
    const capability = issueCoherentWalletBaselineV2ForVerifiedHead({
      ...senderBaselineInput(),
      balance: parseObservedZkzBalance("7.50"),
    });
    expect(capability.balance).toBe("7.50");
  });

  it("still rejects grammar-invalid observed balances at the boundary", () => {
    for (const bad of ["1e5", "-1", "01", ".5", "1.", ""]) {
      expect(() => issueBaselineUnsafe({ ...senderBaselineInput(), balance: bad })).toThrow(
        InvalidScalarError,
      );
    }
  });

  it("keeps node-authored construction strict: canonical parsers still reject '2.50'", () => {
    expect(() => parseZkzBalance("2.50")).toThrow(InvalidScalarError);
    expect(() => parsePositiveZkzAmount("2.50")).toThrow(InvalidScalarError);
  });

  it("canonicalizes a non-canonical observed baseline for node-authored arithmetic (never emits '2.50')", () => {
    const nonCanonicalSender = issueCoherentWalletBaselineV2ForVerifiedHead({
      ...senderBaselineInput(),
      balance: parseObservedZkzBalance("2.50"),
    });
    expect(nonCanonicalSender.balance).toBe("2.50");
    const source = validInput();
    const inner = buildSplitChainInnerV2({
      unixTimeSecs: source.unixTimeSecs,
      sender: nonCanonicalSender,
      receiver: source.receiver,
      transferAmount: parsePositiveZkzAmount("1"),
      expiryUnixTimeSecs: source.expiryUnixTimeSecs,
      message: source.message,
    } as BuildSplitChainInnerV2Input).inner;
    // Node-authored post-balances are canonical shortest form, never the observed "2.50" spelling.
    expect(inner.step_1_state.amount).toBe("1.5");
    expect(inner.step_2_state.amount).toBe("1");
  });
});

describe("time, expiry, and exact message validation", () => {
  it("requires a positive canonical wallet clock without numeric conversion", () => {
    expectConstructionReason(
      () => buildUnsafe({ ...validInput(), unixTimeSecs: "0" }),
      "invalid_unix_time",
    );
    expect(buildUnsafe({ ...validInput(), unixTimeSecs: "0.001", expiryUnixTimeSecs: "1" }).inner)
      .toHaveProperty("unix_time_secs", "0.001");
    for (const invalid of ["1e3", "+1", " 1", "1.230", "1.1234", "9".repeat(10_000)]) {
      expect(() => buildUnsafe({ ...validInput(), unixTimeSecs: invalid })).toThrow();
    }
  });

  it("uses exact scaled expiry arithmetic with the inclusive maximum-ahead boundary", () => {
    expect(
      buildUnsafe({ ...validInput(), unixTimeSecs: "1.125", expiryUnixTimeSecs: "59999881" })
        .inner.expiry__unix_time_secs,
    ).toBe("59999881");
    for (const invalid of ["1", "0", "1.5", "01", "59999882", "9".repeat(10_000)]) {
      expectConstructionReason(
        () => buildUnsafe({ ...validInput(), unixTimeSecs: "1.125", expiryUnixTimeSecs: invalid }),
        "invalid_expiry",
      );
    }
  });

  it("preserves NFC and NFD as distinct exact bytes", () => {
    const nfc = "prefix-é-suffix";
    const nfd = "prefix-e\u0301-suffix";
    const builtNfc = buildUnsafe({ ...validInput(), message: nfc });
    const builtNfd = buildUnsafe({ ...validInput(), message: nfd });
    expect(builtNfc.inner.message).toBe(nfc);
    expect(builtNfd.inner.message).toBe(nfd);
    expect(builtNfc.innerPreimageText).not.toBe(builtNfd.innerPreimageText);
    expect(builtNfc.innerPreimageSha256).not.toBe(builtNfd.innerPreimageSha256);
  });

  it("preserves controls, quotes, backslashes, U+2028/U+2029, and astral text", () => {
    const message = "prefix\u0000\"\\\t\u2028\u2029😀suffix";
    const capability = buildUnsafe({ ...validInput(), message });
    expect(capability.inner.message).toBe(message);
    expect((JSON.parse(capability.innerPreimageText) as { message: string }).message).toBe(message);
  });

  it("rejects blank text, lone surrogates, and either message length overflow", () => {
    for (const invalid of ["", " ", "\n\t", "\ud800", "x\udc00", "a".repeat(257), "😀".repeat(129)]) {
      expectConstructionReason(
        () => buildUnsafe({ ...validInput(), message: invalid }),
        "invalid_message",
      );
    }
    expect(buildUnsafe({ ...validInput(), message: "a".repeat(256) }).inner.message).toHaveLength(
      256,
    );
    expect(buildUnsafe({ ...validInput(), message: "😀".repeat(128) }).inner.message).toHaveLength(
      256,
    );
  });
});

describe("module-issued capability chain", () => {
  it("rejects forged, copied, JSON-round-tripped, and proxy-wrapped wallet baselines", () => {
    const baseline = validInput().sender;
    expect(Object.getPrototypeOf(baseline)).toBe(null);
    expect(Object.isFrozen(baseline)).toBe(true);

    const forged = {
      kind: baseline.kind,
      publicKey: baseline.publicKey,
      balance: baseline.balance,
      previousSettledStep2Signature: baseline.previousSettledStep2Signature,
    } as unknown as WalletBaselineV2Capability;
    const copied = { ...baseline } as unknown as WalletBaselineV2Capability;
    const roundTripped = JSON.parse(JSON.stringify(baseline)) as WalletBaselineV2Capability;
    const proxied = new Proxy(baseline, {});

    for (const invalid of [forged, copied, roundTripped, proxied]) {
      expectConstructionReason(
        () => buildSplitChainInnerV2({ ...validInput(), sender: invalid }),
        "invalid_capability",
      );
    }
  });

  it("rejects forged and proxy-wrapped inner or partial capabilities", () => {
    const inner = buildSplitChainInnerV2(validInput());
    const forgedInner = {
      inner: inner.inner,
      innerPreimageText: inner.innerPreimageText,
      innerPreimageSha256: inner.innerPreimageSha256,
    } as unknown as SplitChainInnerV2Capability;
    expectConstructionReason(
      () => buildSplitChainPartialV2(forgedInner, parseEd25519Signature(WALLET_STEP_1_SIGNATURE)),
      "invalid_capability",
    );
    expectConstructionReason(
      () =>
        buildSplitChainPartialV2(
          new Proxy(inner, {}),
          parseEd25519Signature(WALLET_STEP_1_SIGNATURE),
        ),
      "invalid_capability",
    );

    const partial = buildSplitChainPartialV2(
      inner,
      parseEd25519Signature(WALLET_STEP_1_SIGNATURE),
    );
    const forgedPartial = { ...partial } as unknown as SplitChainPartialV2Capability;
    expectConstructionReason(
      () =>
        buildSettledSplitChainTransactionV2(
          forgedPartial,
          parseEd25519Signature(WALLET_STEP_2_SIGNATURE),
        ),
      "invalid_capability",
    );
  });

  it("revalidates both signatures and never adds step_2_signature to a partial", () => {
    const inner = buildSplitChainInnerV2(validInput());
    expect(() =>
      buildSplitChainPartialV2(
        inner,
        WALLET_STEP_1_SIGNATURE.slice(0, -2) as ReturnType<typeof parseEd25519Signature>,
      ),
    ).toThrow();
    const partial = buildSplitChainPartialV2(
      inner,
      parseEd25519Signature(WALLET_STEP_1_SIGNATURE),
    );
    expect(Object.keys(partial.partial)).toEqual(["inner", "step_1_signature"]);
    expect(partial.partialText).not.toContain("step_2_signature");
    expect(() =>
      buildSettledSplitChainTransactionV2(
        partial,
        WALLET_STEP_2_SIGNATURE.slice(0, -2) as ReturnType<typeof parseEd25519Signature>,
      ),
    ).toThrow();
  });

  it("reuses exact inner text and fixes partial/full top-level order", () => {
    const inner = buildSplitChainInnerV2(validInput());
    const partial = buildSplitChainPartialV2(
      inner,
      parseEd25519Signature(WALLET_STEP_1_SIGNATURE),
    );
    const settled = buildSettledSplitChainTransactionV2(
      partial,
      parseEd25519Signature(WALLET_STEP_2_SIGNATURE),
    );
    expect(partial.step2PreimageText).toContain(`{"inner":${inner.innerPreimageText},`);
    expect(settled.transactionText).toContain(`{"inner":${inner.innerPreimageText},`);
    expect(Object.keys(JSON.parse(partial.partialText))).toEqual(["inner", "step_1_signature"]);
    expect(Object.keys(JSON.parse(settled.transactionText))).toEqual([
      "inner",
      "step_1_signature",
      "step_2_signature",
    ]);
    expect(Object.isFrozen(partial)).toBe(true);
    expect(Object.isFrozen(partial.partial)).toBe(true);
    expect(Object.isFrozen(settled)).toBe(true);
    expect(Object.isFrozen(settled.transaction)).toBe(true);
  });

  it("makes canonical signature mutations byte- and digest-distinct", () => {
    const inner = buildSplitChainInnerV2(validInput());
    const first = buildSplitChainPartialV2(
      inner,
      parseEd25519Signature(WALLET_STEP_1_SIGNATURE),
    );
    const second = buildSplitChainPartialV2(
      inner,
      parseEd25519Signature(WALLET_STEP_2_SIGNATURE),
    );
    expect(second.partialText).not.toBe(first.partialText);
    expect(second.step2PreimageSha256).not.toBe(first.step2PreimageSha256);
  });
});

// the construction/signing path must stay STRICT (the byte-exact signing rule): buildSplitChainInnerV2
// only ever authors canonical shortest-form unix_time_secs and rejects a caller-supplied trailing-
// zero spelling outright, so it can never sign a non-canonical clock. This is the exact proof the
// qa-reviewer dual-run demanded and that no prior test covered — the pre-existing negative vectors
// were masked by the expiry-delta check (a tiny epoch time made the real-world expiry invalid
// first) or by a 4-digit fractional length, never isolating the trailing-zero unix_time_secs gate.
// The FOREIGN-signed VERIFY path accepts those same spellings (transaction-verify.scalar-fuzz.test
// .ts and protocol-scalars.test.ts) — the construction and verify layers are deliberately distinct.
describe("construction rejects non-canonical unix_time_secs and never emits one", () => {
  it("rejects a caller-supplied trailing-zero fractional unix_time_secs at buildSplitChainInnerV2", () => {
    // No expiry/message: ONLY the unix_time_secs gate can reject here, isolating it from the
    // expiry-delta masking that let the pre-existing negatives pass for the wrong reason.
    for (const nonCanonical of [
      "1784332800.50",
      "1784332800.500",
      "1784332800.120",
      "0.0",
      "1.000",
      "1.230",
    ]) {
      try {
        buildUnsafe({ ...validInput(ABSENT, ABSENT), unixTimeSecs: nonCanonical });
        throw new Error(`expected rejection of non-canonical unix_time_secs ${nonCanonical}`);
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidScalarError);
        expect((error as InvalidScalarError).scalarKind).toBe("UnixTimeSecsV2");
        expect((error as InvalidScalarError).reason).toBe("invalid_format");
      }
    }
  });

  it("emits canonical shortest form verbatim and never the trailing-zero spelling", () => {
    const built = buildUnsafe({ ...validInput(ABSENT, ABSENT), unixTimeSecs: "1784332800.5" });
    expect(built.inner.unix_time_secs).toBe("1784332800.5");
    expect(built.innerPreimageText).toContain('"unix_time_secs":"1784332800.5"');
    expect(built.innerPreimageText).not.toContain('"unix_time_secs":"1784332800.50"');
  });
});
