// A.8.3 SEND_EXTERNAL redemption golden pin (ZTR-1174 / GN-016.3).
//
// Tier-3 raw bytes live under packages/generic-node-contracts/goldens/send-redemption/
// (no trailing newline). The sha256 constant below is hard-coded; no test writes a golden.
//
// Governing: Appendix A §A.8.3; SEND_REDEMPTION_WINDOW_SECS=300; Q8 byte-identical redelivery.
import { createHash, createPrivateKey, sign as nodeSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { SEND_REDEMPTION_WINDOW_SECS } from "../src/protocol/send-redemption.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDEN_DIR = join(
  HERE,
  "../../generic-node-contracts/goldens/send-redemption",
);

/** Hard-pinned A.8.3 step_1_sha256 (Appendix A §A.8.3). */
const A83_STEP_1_SHA256 =
  "46ba7528a9a757bd2bf50e2950256663aae9d20a51b485b71d511ac74b38662d" as const;
/** Hard-pinned A.8.3 step_1_signature (seed-02 sender). */
const A83_STEP_1_SIGNATURE =
  "KKyZRQpHR7Xt3QhUXe0eki2iJC9sGYJ13tDzMN5lpQXA3ets0_7PPHZgOmbxDq2R9Hd7TPN_8Su-QVkuLcFyBA==" as const;

const PREIMAGE_REL = "a83-send-external-redemption.step1.preimage.txt";
const SIG_REL = "a83-send-external-redemption.step1.sig.b64";

function sha256Hex(bytes: Buffer | string): string {
  return createHash("sha256")
    .update(typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes)
    .digest("hex");
}

function paddedB64Url(bytes: Buffer): string {
  return bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

function keyFromSeed(byte: number) {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, byte),
  ]);
  return createPrivateKey({ key: der, type: "pkcs8", format: "der" });
}

describe("A.8.3 SEND_EXTERNAL redemption golden", () => {
  const preimageBytes = readFileSync(join(GOLDEN_DIR, PREIMAGE_REL));
  const sigBytes = readFileSync(join(GOLDEN_DIR, SIG_REL));
  const preimageText = preimageBytes.toString("utf8");
  const sigText = sigBytes.toString("utf8");

  it("on-disk golden has no trailing newline and matches the pinned sha256", () => {
    expect(preimageBytes.includes(0x0a)).toBe(false);
    expect(preimageBytes[preimageBytes.length - 1]).not.toBe(0x0a);
    expect(sha256Hex(preimageBytes)).toBe(A83_STEP_1_SHA256);
    expect(sha256Hex(preimageBytes)).toBe(
      "46ba7528a9a757bd2bf50e2950256663aae9d20a51b485b71d511ac74b38662d",
    );
  });

  it("matches the A.8.3 spec digest prefix and signature prefix", () => {
    expect(A83_STEP_1_SHA256.startsWith("46ba7528")).toBe(true);
    expect(A83_STEP_1_SIGNATURE.startsWith("KKyZRQ")).toBe(true);
    expect(sigText).toBe(A83_STEP_1_SIGNATURE);
  });

  it("carries the D9.14 redemption expiry (formation + 300s), not the A.8.0 3600s fixture", () => {
    expect(SEND_REDEMPTION_WINDOW_SECS).toBe(300);
    expect(preimageText).toContain('"expiry__unix_time_secs":"1784333100"');
    expect(preimageText).not.toContain('"expiry__unix_time_secs":"1784336400"');
    // 1784333100 = 1784332800 + 300
    expect(1_784_332_800 + SEND_REDEMPTION_WINDOW_SECS).toBe(1_784_333_100);
  });

  it("reproduces the step-1 signature from seed-02 over the exact on-disk bytes", () => {
    const sender = keyFromSeed(0x02);
    const produced = paddedB64Url(Buffer.from(nodeSign(null, preimageBytes, sender)));
    expect(produced).toBe(A83_STEP_1_SIGNATURE);
  });

  it("changing the SEND inner emission (expiry field) fails the golden digest", () => {
    const mutated = preimageText.replace(
      '"expiry__unix_time_secs":"1784333100"',
      '"expiry__unix_time_secs":"1784333101"',
    );
    expect(sha256Hex(mutated)).not.toBe(A83_STEP_1_SHA256);
  });
});
