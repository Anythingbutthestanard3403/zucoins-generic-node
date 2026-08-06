// byte-exact receive transfer-code construction + A.2 digest.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  RECEIVE_MESSAGE_PREFIX,
  RECEIVE_TRANSFER_CODE_TYPE,
  RECEIVE_TRANSFER_CODE_WIRE_VERSION,
  ReceiveTransferCodeError,
  buildReceiveMessage,
  buildReceiveTransferCode,
  hashTransferCodeText,
} from "./receive-transfer-code.js";

const GOLDEN_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../generic-node-contracts/goldens/transfer-code",
);

const FIXTURE_PUBKEY = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const FIXTURE_AMOUNT = "2.25";
const FIXTURE_DISCRIMINATOR = "33333333-3333-4333-8333-333333333333";
const FIXTURE_ANCHOR = "ord_7YQ3";
const FIXTURE_EXPIRY = "1784336400";
const FIXTURE_B64_SHA256 = "104eb00c3bda958b82b7ce5a24e582dd9efa3e63d2192838fe26b5b23dcb2bab";

describe("buildReceiveMessage", () => {
  it("is exactly zp1:discriminator:anchor with no whitespace", () => {
    expect(buildReceiveMessage(FIXTURE_DISCRIMINATOR, FIXTURE_ANCHOR)).toBe(
      `${RECEIVE_MESSAGE_PREFIX}${FIXTURE_DISCRIMINATOR}:${FIXTURE_ANCHOR}`,
    );
  });

  it("rejects a non-canonical anchor", () => {
    expect(() => buildReceiveMessage(FIXTURE_DISCRIMINATOR, "bad anchor!")).toThrow(
      ReceiveTransferCodeError,
    );
  });
});

describe("buildReceiveTransferCode", () => {
  it("matches the receive-code golden byte-for-byte at genesis B0", () => {
    const built = buildReceiveTransferCode({
      receiverPubkey: FIXTURE_PUBKEY,
      amountZkz: FIXTURE_AMOUNT,
      b0: "0",
      discriminator: FIXTURE_DISCRIMINATOR,
      anchor: FIXTURE_ANCHOR,
      expiryUnixTimeSecs: FIXTURE_EXPIRY,
    });
    const golden = readFileSync(join(GOLDEN_DIR, "receive-code.v1.b64url.txt"), "utf8");
    expect(built.transferCodeText).toBe(golden);
    expect(built.transferCodeSha256).toBe(FIXTURE_B64_SHA256);
    expect(built.innerStateAmount).toBe(FIXTURE_AMOUNT);
    expect(built.receiveMessage).toBe(
      `zp1:${FIXTURE_DISCRIMINATOR}:${FIXTURE_ANCHOR}`,
    );
  });

  it("emits the frozen envelope type and wire version", () => {
    const built = buildReceiveTransferCode({
      receiverPubkey: FIXTURE_PUBKEY,
      amountZkz: FIXTURE_AMOUNT,
      b0: "0",
      discriminator: FIXTURE_DISCRIMINATOR,
      anchor: FIXTURE_ANCHOR,
      expiryUnixTimeSecs: FIXTURE_EXPIRY,
    });
    // Decode without repair: reverse transfer-code encode/decode.
    const json = decodeURIComponent(
      Buffer.from(built.transferCodeText, "base64url").toString("utf8"),
    );
    const envelope = JSON.parse(json) as {
      version: string;
      type: string;
      incoming_data: Record<string, string>;
    };
    expect(envelope.version).toBe(RECEIVE_TRANSFER_CODE_WIRE_VERSION);
    expect(envelope.type).toBe(RECEIVE_TRANSFER_CODE_TYPE);
    expect(Object.keys(envelope)).toEqual(["version", "type", "incoming_data"]);
    expect(Object.keys(envelope.incoming_data)).toEqual([
      "receiver_key_public__base64urlsafe",
      "inner_state_amount",
      "expiry__unix_time_secs",
      "message",
    ]);
  });

  it("is deterministic: same inputs yield identical bytes", () => {
    const a = buildReceiveTransferCode({
      receiverPubkey: FIXTURE_PUBKEY,
      amountZkz: FIXTURE_AMOUNT,
      b0: "0",
      discriminator: FIXTURE_DISCRIMINATOR,
      anchor: FIXTURE_ANCHOR,
      expiryUnixTimeSecs: FIXTURE_EXPIRY,
    });
    const b = buildReceiveTransferCode({
      receiverPubkey: FIXTURE_PUBKEY,
      amountZkz: FIXTURE_AMOUNT,
      b0: "0",
      discriminator: FIXTURE_DISCRIMINATOR,
      anchor: FIXTURE_ANCHOR,
      expiryUnixTimeSecs: FIXTURE_EXPIRY,
    });
    expect(a.transferCodeText).toBe(b.transferCodeText);
    expect(a.transferCodeSha256).toBe(b.transferCodeSha256);
  });

  it("sets inner_state_amount = B0 + amount (non-genesis)", () => {
    const built = buildReceiveTransferCode({
      receiverPubkey: FIXTURE_PUBKEY,
      amountZkz: "1.5",
      b0: "2.25",
      discriminator: FIXTURE_DISCRIMINATOR,
      anchor: FIXTURE_ANCHOR,
      expiryUnixTimeSecs: FIXTURE_EXPIRY,
    });
    expect(built.innerStateAmount).toBe("3.75");
    expect(built.transferCodeSha256).not.toBe(FIXTURE_B64_SHA256);
  });

  it("A.2 digest rejects decode/repair variants (negative vectors)", () => {
    const built = buildReceiveTransferCode({
      receiverPubkey: FIXTURE_PUBKEY,
      amountZkz: FIXTURE_AMOUNT,
      b0: "0",
      discriminator: FIXTURE_DISCRIMINATOR,
      anchor: FIXTURE_ANCHOR,
      expiryUnixTimeSecs: FIXTURE_EXPIRY,
    });
    const exact = built.transferCodeSha256;
    expect(hashTransferCodeText(built.transferCodeText)).toBe(exact);

    // base64url-decoded bytes
    const decoded = Buffer.from(built.transferCodeText, "base64url");
    expect(createHash("sha256").update(decoded).digest("hex")).not.toBe(exact);

    // padding repair
    const pad = (4 - (built.transferCodeText.length % 4)) % 4;
    const repaired = built.transferCodeText + "=".repeat(pad);
    expect(repaired).not.toBe(built.transferCodeText);
    expect(hashTransferCodeText(repaired)).not.toBe(exact);

    // trailing newline
    expect(hashTransferCodeText(built.transferCodeText + "\n")).not.toBe(exact);
  });

  it("rejects zero / non-canonical amount via validateOperationAmount", () => {
    expect(() =>
      buildReceiveTransferCode({
        receiverPubkey: FIXTURE_PUBKEY,
        amountZkz: "0",
        b0: "0",
        discriminator: FIXTURE_DISCRIMINATOR,
        anchor: FIXTURE_ANCHOR,
        expiryUnixTimeSecs: FIXTURE_EXPIRY,
      }),
    ).toThrow();
    expect(() =>
      buildReceiveTransferCode({
        receiverPubkey: FIXTURE_PUBKEY,
        amountZkz: "0.0",
        b0: "0",
        discriminator: FIXTURE_DISCRIMINATOR,
        anchor: FIXTURE_ANCHOR,
        expiryUnixTimeSecs: FIXTURE_EXPIRY,
      }),
    ).toThrow();
    expect(() =>
      buildReceiveTransferCode({
        receiverPubkey: FIXTURE_PUBKEY,
        amountZkz: "999999999999.5",
        b0: "0",
        discriminator: FIXTURE_DISCRIMINATOR,
        anchor: FIXTURE_ANCHOR,
        expiryUnixTimeSecs: FIXTURE_EXPIRY,
      }),
    ).toThrow();
  });
});
