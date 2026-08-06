import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const argv = new Set(process.argv.slice(2));
const allowedArgs = new Set(["--check"]);
for (const arg of argv) {
  if (!allowedArgs.has(arg)) {
    throw new Error(`unknown argument: ${arg}`);
  }
}

const checkOnly = argv.has("--check");
const here = dirname(fileURLToPath(import.meta.url));
const outputDir = join(here, "..", "src", "receive-golden", "gen");
const negativeOutputDir = join(here, "..", "src", "receive-golden", "negative-vectors");

const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
const sha256 = (bytes: Buffer | string): string =>
  createHash("sha256")
    .update(typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes)
    .digest("hex");
const keyFromSeed = (byte: number) => {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, byte),
  ]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
};
const publicKey = (privateKey: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(-32));
const signText = (text: string, privateKey: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(sign(null, Buffer.from(text, "utf8"), privateKey));

const seed02 = keyFromSeed(0x02);
const seed03 = keyFromSeed(0x03);
const seed05 = keyFromSeed(0x05);
const seed02Public = publicKey(seed02);
const seed03Public = publicKey(seed03);
const seed05Public = publicKey(seed05);

// This is an explicit finite-fixture boundary, not a generated transaction or a claim of
// genesis-to-positive ancestry. It is a canonical padded-base64url encoding of 64 opaque bytes.
const seed05BoundaryS =
  "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ==";

const predecessorInner = {
  type: "unique_combinable",
  version: "2",
  unix_time_secs: "1784332700",
  signer_steps: 2,
  step_1_signer: "sender",
  step_2_signer: "receiver",
  step_1_key_public__base64urlsafe: seed05Public,
  step_2_key_public__base64urlsafe: seed02Public,
  step_1_state: { amount: "0" },
  step_2_state: { amount: "10" },
  previous_step_1_state_signature: seed05BoundaryS,
  previous_step_2_state_signature: "",
};
const predecessorStep1 = JSON.stringify(predecessorInner);
const predecessorStep1Signature = signText(predecessorStep1, seed05);
const predecessorStep2 = JSON.stringify({
  inner: predecessorInner,
  step_1_signature: predecessorStep1Signature,
});
const predecessorStep2Signature = signText(predecessorStep2, seed02);
const predecessorSettled = JSON.stringify({
  inner: predecessorInner,
  step_1_signature: predecessorStep1Signature,
  step_2_signature: predecessorStep2Signature,
});

const targetInner = {
  type: "unique_combinable",
  version: "2",
  unix_time_secs: "1784332800.125",
  signer_steps: 2,
  step_1_signer: "sender",
  step_2_signer: "receiver",
  step_1_key_public__base64urlsafe: seed02Public,
  step_2_key_public__base64urlsafe: seed03Public,
  step_1_state: { amount: "7.75" },
  step_2_state: { amount: "2.25" },
  previous_step_1_state_signature: predecessorStep2Signature,
  previous_step_2_state_signature: "",
  expiry__unix_time_secs: "1784336400",
  message: "zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3",
};
const targetStep1 = JSON.stringify(targetInner);
const targetStep1Signature = signText(targetStep1, seed02);
const targetStep2 = JSON.stringify({ inner: targetInner, step_1_signature: targetStep1Signature });
const targetStep2Signature = signText(targetStep2, seed03);
const targetSettled = JSON.stringify({
  inner: targetInner,
  step_1_signature: targetStep1Signature,
  step_2_signature: targetStep2Signature,
});

const receiverHeadPayload = {
  purpose: "zp-wallet-head-fingerprint-v1",
  canonical_version: 1,
  wallet_public_key: seed03Public,
  state_kind: "HEAD",
  s_signature: targetStep2Signature,
  p_signature: "",
  b_amount: "2.25",
  inner_sha256: sha256(targetStep1),
  step_1_signature: targetStep1Signature,
  step_2_signature: targetStep2Signature,
};
const receiverHeadPreimage = `${receiverHeadPayload.purpose}\n${JSON.stringify(receiverHeadPayload)}`;

// the transfer-code byte-binding rule: transfer_code_sha256 binds the SHA-256 of the EXACT stored bytes of the receive-golden transfer-code concern
// encoded receive-code fixture — no base64url decode, padding repair, newline insertion, NFC/NFD
// normalization, JSON wrapper, or reserialization (A.9 rules 9, 11). This supersedes the retired
// illustrative placeholder sha256("golden-transfer-code-v1") (digest 4b3e384d…), whose receive
// tuple (57253b75…) is VOID and MUST NOT be accepted.
const receiveCodeFixtureBytes = readFileSync(
  join(here, "..", "goldens", "transfer-code", "receive-code.v1.b64url.txt"),
);
const receiveExpectedPayload = {
  purpose: "zp-receive-expected-v1",
  canonical_version: 1,
  node_id: "11111111-1111-4111-8111-111111111111",
  implementer_id: "22222222-2222-4222-8222-222222222222",
  operation_id: "33333333-3333-4333-8333-333333333333",
  receiver_wallet_id: "55555555-5555-4555-8555-555555555555",
  receiver_pubkey: seed03Public,
  amount_zkz: "2.25",
  discriminator: "33333333-3333-4333-8333-333333333333",
  anchor: "ord_7YQ3",
  receiver_t0_fingerprint: "0".repeat(64),
  expiry_unix_time_secs: "1784336400",
  after_landing: { kind: "HOLD", destination_id: null },
  transfer_code_sha256: sha256(receiveCodeFixtureBytes),
};
const moveExpectedPayload = {
  purpose: "zp-move-internal-expected-v1",
  canonical_version: 1,
  node_id: "11111111-1111-4111-8111-111111111111",
  implementer_id: "22222222-2222-4222-8222-222222222222",
  operation_id: "33333333-3333-4333-8333-333333333333",
  source_wallet_id: "55555555-5555-4555-8555-555555555555",
  source_pubkey: seed02Public,
  destination_id: "66666666-6666-4666-8666-666666666666",
  destination_wallet_id: "44444444-4444-4444-8444-444444444444",
  destination_pubkey: seed03Public,
  amount_zkz: "2.25",
  spawned_from_operation_id: null,
  references_operation_id: null,
};
const sourceSelector = {
  kind: "WALLET_ID",
  wallet_id: "55555555-5555-4555-8555-555555555555",
};
const sendExpectedPayload = {
  purpose: "zp-send-external-expected-v1",
  canonical_version: 1,
  node_id: "11111111-1111-4111-8111-111111111111",
  implementer_id: "22222222-2222-4222-8222-222222222222",
  operation_id: "33333333-3333-4333-8333-333333333333",
  source_selector: sourceSelector,
  source_pubkey: seed02Public,
  destination_address: seed03Public,
  amount_zkz: "2.25",
  references_operation_id: null,
};
const sendApprovalPayload = {
  purpose: "zp-send-external-approval-v1",
  canonical_version: 1,
  node_id: "11111111-1111-4111-8111-111111111111",
  operation_id: "33333333-3333-4333-8333-333333333333",
  source_selector: sourceSelector,
  source_pubkey: seed02Public,
  destination_address: seed03Public,
  amount_zkz: "2.25",
  references_operation_id: null,
  nonce: "99999999-9999-4999-8999-999999999999",
  issued_at: "2026-07-18T00:00:00.000Z",
  expires_at: "2026-07-18T00:05:00.000Z",
};
const suiteDigest = (payload: { purpose: string }): string =>
  sha256(`${payload.purpose}\n${JSON.stringify(payload)}`);
const d92Pins = {
  receive: suiteDigest(receiveExpectedPayload),
  move: suiteDigest(moveExpectedPayload),
  send: suiteDigest(sendExpectedPayload),
  approval: suiteDigest(sendApprovalPayload),
  transfer_code_sha256: receiveExpectedPayload.transfer_code_sha256,
};
const expectedD92Pins = {
  receive: "f49635f02d8de86c5b4324f13520cc38c094d79ee2c0df5df60547c590ede498",
  move: "ad964723e07ca2aef3356f1e02990e07b90be49b5387a7095091398a10944a14",
  send: "f094f981f833c908fae1fa661cb6d9f6c3cdf29bab792f2660b866c588f22cb5",
  approval: "d7c03561bd9bc87e302c533f03741c34d44058fc0aaf1b59b17a4f28f8022146",
  transfer_code_sha256: "104eb00c3bda958b82b7ce5a24e582dd9efa3e63d2192838fe26b5b23dcb2bab",
};
if (JSON.stringify(d92Pins) !== JSON.stringify(expectedD92Pins)) {
  throw new Error(`artifacts-freeze pin drift: ${JSON.stringify(d92Pins)}`);
}

// A.8.1's SplitChain golden keeps its OWN illustrative transfer_code_sha256 — the SHA-256 of the
// A.8 fixture-identifier string, NOT a real transfer-code binding. The transfer-code byte-binding rule deliberately did
// NOT rebind this line (its open flag): the real binding lives only in the A.8.2 suite tuple above
// (d92Pins.transfer_code_sha256 = 104eb00c…). These two surfaces MUST stay decoupled.
const a81IllustrativeTransferCodeSha256 = sha256("golden-transfer-code-v1");

const manifest = JSON.stringify(
  {
    schema_version: 1,
    provenance: {
      generator: "packages/generic-node-contracts/scripts/emit-receive-golden.ts",
      construction: "insertion-ordered objects serialized only with JSON.stringify",
      key_material: "test-only 32-byte filled Ed25519 seeds 02, 03, and 05",
      source: "offline canonical constructor; no gateway capture, import, or submission",
    },
    boundary: {
      wallet_seed: "05",
      preflight_balance: "10",
      prior_head_s: seed05BoundaryS,
      limitation:
        "pre-existing funded fixture boundary; earlier ancestry is outside this finite vector and no genesis-to-positive lineage is claimed",
    },
    public_keys: {
      seed_02: seed02Public,
      seed_03: seed03Public,
      seed_05: seed05Public,
    },
    predecessor: {
      step_1_sha256: sha256(predecessorStep1),
      step_1_signature: predecessorStep1Signature,
      step_2_sha256: sha256(predecessorStep2),
      step_2_signature: predecessorStep2Signature,
      settled_sha256: sha256(predecessorSettled),
      role_relative_projection: {
        seed_05_sender: { S: predecessorStep2Signature, P: seed05BoundaryS, B: "0" },
        seed_02_receiver: { S: predecessorStep2Signature, P: "", B: "10" },
      },
    },
    target: {
      step_1_sha256: sha256(targetStep1),
      step_1_signature: targetStep1Signature,
      step_2_sha256: sha256(targetStep2),
      step_2_signature: targetStep2Signature,
      settled_sha256: sha256(targetSettled),
      role_relative_projection: {
        seed_02_sender: { S: targetStep2Signature, P: predecessorStep2Signature, B: "7.75" },
        seed_03_receiver: { S: targetStep2Signature, P: "", B: "2.25" },
      },
      receiver_terminal_head: {
        preimage_sha256: sha256(receiverHeadPreimage),
        fingerprint: sha256(receiverHeadPreimage),
      },
    },
    preserved_d9_2: d92Pins,
  },
  null,
  2,
);

const artifacts: Readonly<Record<string, string>> = {
  "predecessor.step-1.json": predecessorStep1,
  "predecessor.step-2.json": predecessorStep2,
  "predecessor.settled.json": predecessorSettled,
  "target.step-1.json": targetStep1,
  "target.step-2.json": targetStep2,
  "target.settled.json": targetSettled,
  "receiver-head-fingerprint.txt": receiverHeadPreimage,
  "manifest.json": manifest,
};

// ---------------------------------------------------------------------------
// A.9 negative vectors — static adversarial RECEIVE candidates.
//
// Each candidate is the exact positive target inner with ONE field mutated so that it is a
// *validly re-signed* (seed-02 step-1 signature verifies) but structurally/economically
// invalid RECEIVE target. These are captured as committed fixtures — NOT runtime rejection
// proof. No reusable pre-sign semantic validator exists in @zucoins/node-core yet (the v2
// node runtime is skeleton-only) and this package's dependency-boundary/CONTRACT_FREEZE gate
// forbids the fresh-read sender preflight such a validator needs. Runtime rejection of every
// candidate is owned by the external-intake concern (external partial intake, co-sign, and single submit; its
// acceptance is "every invalid or indeterminate candidate fails before co-sign"). The external-intake concern
// build MUST feed these fixtures through the real validator once it lands. Field order below
// mirrors the positive `targetInner` exactly, because the byte serialization is the signed
// preimage. `receive-golden.freeze.test.ts` reconstructs and byte-compares each candidate, so
// any drift from the positive construction fails there.
const buildTargetVariantInner = (
  senderPredecessorSignature: string,
  senderPostAmount: string,
  receiverPostAmount: string,
) => ({
  type: "unique_combinable",
  version: "2",
  unix_time_secs: "1784332800.125",
  signer_steps: 2,
  step_1_signer: "sender",
  step_2_signer: "receiver",
  step_1_key_public__base64urlsafe: seed02Public,
  step_2_key_public__base64urlsafe: seed03Public,
  step_1_state: { amount: senderPostAmount },
  step_2_state: { amount: receiverPostAmount },
  previous_step_1_state_signature: senderPredecessorSignature,
  previous_step_2_state_signature: "",
  expiry__unix_time_secs: "1784336400",
  message: "zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3",
});

type NegativeVectorSpec = Readonly<{
  name: string;
  senderPredecessorSignature: string;
  senderPostAmount: string;
  receiverPostAmount: string;
  defect: string;
  expectedRejection: string;
  canonicalSource: string;
}>;

const negativeVectorSpecs: readonly NegativeVectorSpec[] = [
  {
    name: "funded-sender-genesis-predecessor",
    senderPredecessorSignature: "",
    senderPostAmount: "7.75",
    receiverPostAmount: "2.25",
    defect:
      "funded sender (preflight balance 10) presents an empty genesis previous_step_1_state_signature",
    expectedRejection: "funded-sender/genesis-predecessor",
    canonicalSource: "canonical negative vector 17 (canonical classification)",
  },
  {
    name: "wrong-sender-balance",
    senderPredecessorSignature: predecessorStep2Signature,
    senderPostAmount: "7.74",
    receiverPostAmount: "2.25",
    defect: "sender post-state 7.74 implies a 2.26 debit from preflight balance 10, not the 2.25 receive amount",
    expectedRejection: "sender-amount-mismatch",
    canonicalSource: "economic conservation; delta check (reason code provisional until the runtime intake validator lands)",
  },
  {
    name: "wrong-receiver-balance",
    senderPredecessorSignature: predecessorStep2Signature,
    senderPostAmount: "7.75",
    receiverPostAmount: "2.24",
    defect: "receiver post-state 2.24 implies a 2.24 credit over T0 balance 0, not the 2.25 receive amount",
    expectedRejection: "receiver-amount-mismatch",
    canonicalSource: "economic conservation; delta check (reason code provisional until the runtime intake validator lands)",
  },
];

const negativeVectors = negativeVectorSpecs.map((spec) => {
  const innerText = JSON.stringify(
    buildTargetVariantInner(spec.senderPredecessorSignature, spec.senderPostAmount, spec.receiverPostAmount),
  );
  return {
    ...spec,
    innerText,
    innerFile: `${spec.name}.inner.json`,
    step1SignatureFile: `${spec.name}.step-1-signature.txt`,
    innerSha256: sha256(innerText),
    step1Signature: signText(innerText, seed02),
  };
});

const negativeManifest = JSON.stringify(
  {
    schema_version: 1,
    provenance: {
      generator: "packages/generic-node-contracts/scripts/emit-receive-golden.ts",
      construction: "insertion-ordered objects serialized only with JSON.stringify",
      key_material: "test-only 32-byte filled Ed25519 seeds 02, 03, and 05",
      source: "offline canonical constructor; no gateway capture, import, or submission",
    },
    runtime_enforcement: {
      status: "DEFERRED",
      owner: "external-partial-intake",
      owner_title: "Implement external partial intake, co-sign, and single submit",
      boundary: "receive external partial intake sender preflight, before receiver co-sign or submit",
      statement:
        "Static adversarial fixtures only. Each candidate is a validly re-signed but invalid RECEIVE " +
        "target. No reusable pre-sign semantic validator exists in this package or in @zucoins/node-core " +
        "yet, so runtime rejection is NOT asserted here. The external-partial-intake concern owns feeding each candidate through the " +
        "real validator and asserting rejection before receiver co-sign or submit.",
      sources: [
        "canonical-fields negative vector 17 (funded sender with genesis predecessor)",
        "operation-flows economic-conservation rule",
      ],
    },
    preflight: {
      sender_balance_zkz: "10",
      receiver_t0_balance_zkz: "0",
      expected_amount_zkz: "2.25",
    },
    positive_target_step_1_sha256: sha256(targetStep1),
    vectors: negativeVectors.map((vector) => ({
      name: vector.name,
      inner_file: vector.innerFile,
      step_1_signature_file: vector.step1SignatureFile,
      inner_sha256: vector.innerSha256,
      step_1_signer_seed: "02",
      step_1_signature: vector.step1Signature,
      defect: vector.defect,
      expected_rejection: vector.expectedRejection,
      canonical_source: vector.canonicalSource,
    })),
  },
  null,
  2,
);

const negativeArtifacts: Readonly<Record<string, string>> = {
  ...Object.fromEntries(
    negativeVectors.flatMap((vector) => [
      [vector.innerFile, vector.innerText],
      [vector.step1SignatureFile, vector.step1Signature],
    ]),
  ),
  "manifest.json": negativeManifest,
};

const extractSection = (doc: string, startHeading: string, endHeading: string): string => {
  const start = doc.indexOf(startHeading);
  const end = doc.indexOf(endHeading, start + startHeading.length);
  if (start === -1 || end === -1) throw new Error(`Appendix A section not found: ${startHeading}`);
  return doc.slice(start, end);
};
const extractCodeBlocks = (section: string, language: "json" | "text"): string[] =>
  [...section.matchAll(new RegExp("```" + language + "\\n([\\s\\S]*?)\\n```", "g"))].map((match) => match[1]);

const appendixDrift = (): string[] => {
  const appendixPath = join(
    here,
    "..",
    "..",
    "..",
    "docs",
    "proposals",
    "generic-node-redesign-v2",
    "appendices",
    "A-canonical-fields.md",
  );
  const doc = readFileSync(appendixPath, "utf8");
  const a81 = extractSection(doc, "### A.8.1 SplitChain golden", "### A.8.2 Suite tuple goldens");
  const a82 = extractSection(doc, "### A.8.2 Suite tuple goldens", "## A.9 Required negative vectors");
  const drift: string[] = [];

  const expectedJsonBlocks = [
    predecessorStep1,
    predecessorStep2,
    predecessorSettled,
    targetStep1,
    targetStep2,
    targetSettled,
  ];
  if (JSON.stringify(extractCodeBlocks(a81, "json")) !== JSON.stringify(expectedJsonBlocks)) {
    drift.push("Appendix A.8.1 ordered JSON blocks");
  }

  const expectedPinBlocks = [
    [
      `predecessor_step_1_sha256    = ${sha256(predecessorStep1)}`,
      `predecessor_step_1_signature = ${predecessorStep1Signature}`,
      `predecessor_step_2_sha256    = ${sha256(predecessorStep2)}`,
      `predecessor_step_2_signature = ${predecessorStep2Signature}`,
      `predecessor_settled_sha256   = ${sha256(predecessorSettled)}`,
    ].join("\n"),
    [
      `target_step_1_sha256    = ${sha256(targetStep1)}`,
      `target_step_1_signature = ${targetStep1Signature}`,
      `target_step_2_sha256    = ${sha256(targetStep2)}`,
      `target_step_2_signature = ${targetStep2Signature}`,
      `target_settled_sha256   = ${sha256(targetSettled)}`,
      `transfer_code_sha256    = ${a81IllustrativeTransferCodeSha256}`,
    ].join("\n"),
  ];
  if (JSON.stringify(extractCodeBlocks(a81, "text")) !== JSON.stringify(expectedPinBlocks)) {
    drift.push("Appendix A.8.1 hash/signature blocks");
  }

  const expectedHeadBlock = receiverHeadPreimage.replace("\n", "\\n");
  const actualHeadBlock = extractCodeBlocks(a82, "text").find((block) =>
    block.startsWith("zp-wallet-head-fingerprint-v1\\n"),
  );
  if (actualHeadBlock !== expectedHeadBlock) {
    drift.push("Appendix A.8.2 receiver-head preimage");
  }

  const expectedRows = [
    `| \`zp-receive-expected-v1\` | \`${d92Pins.receive}\` |`,
    `| \`zp-move-internal-expected-v1\` | \`${d92Pins.move}\` |`,
    `| \`zp-send-external-expected-v1\` | \`${d92Pins.send}\` |`,
    `| \`zp-send-external-approval-v1\` | \`${d92Pins.approval}\` |`,
    `| \`zp-wallet-head-fingerprint-v1\` | \`${sha256(receiverHeadPreimage)}\` |`,
  ];
  for (const rowPrefix of expectedRows) {
    if (!a82.split("\n").some((line) => line.startsWith(rowPrefix))) {
      drift.push(`Appendix A.8.2 machine-output row: ${rowPrefix}`);
    }
  }
  return drift;
};

const checkArtifacts = (dir: string, expectedArtifacts: Readonly<Record<string, string>>): string[] => {
  const drift: string[] = [];
  for (const [name, expected] of Object.entries(expectedArtifacts)) {
    const path = join(dir, name);
    if (!existsSync(path)) {
      drift.push(`${name}: missing`);
      continue;
    }
    const actual = readFileSync(path, "utf8");
    if (actual !== expected) {
      drift.push(`${name}: byte drift`);
    }
    if (actual.endsWith("\n")) {
      drift.push(`${name}: trailing LF`);
    }
  }
  return drift;
};

if (checkOnly) {
  const drift = [
    ...checkArtifacts(outputDir, artifacts),
    ...checkArtifacts(negativeOutputDir, negativeArtifacts).map((entry) => `negative-vectors/${entry}`),
    ...appendixDrift(),
  ];
  if (drift.length > 0) {
    throw new Error(`receive golden check failed:\n${drift.join("\n")}`);
  }
} else {
  for (const [dir, contents] of [
    [outputDir, artifacts],
    [negativeOutputDir, negativeArtifacts],
  ] as const) {
    mkdirSync(dir, { recursive: true });
    for (const [name, body] of Object.entries(contents)) {
      writeFileSync(join(dir, name), body, "utf8");
    }
  }
}
