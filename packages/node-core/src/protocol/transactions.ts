import { createHash } from "node:crypto";

import {
  addZkz,
  parseObservedZkzBalance,
  parsePositiveZkzAmount,
  parseZkzBalance,
  reemitObservedZkzCanonical,
  subtractZkz,
  type ObservedZkzBalance,
  type PositiveZkzAmount,
  type ZkzBalance,
} from "./amounts.js";
import {
  parseEd25519Signature,
  parseExpiryUnixTimeSecs,
  parseOpaqueReference,
  parsePreviousStateSignature,
  parseSha256Hex,
  parseUnixTimeSecsV2,
  parseWalletPublicKey,
  type Ed25519Signature,
  type ExpiryUnixTimeSecs,
  type PreviousStateSignature,
  type Sha256Hex,
  type UnixTimeSecsV2,
  type WalletPublicKey,
} from "./scalars.js";

declare const INNER_CAPABILITY_BRAND: unique symbol;
declare const PARTIAL_CAPABILITY_BRAND: unique symbol;
declare const WALLET_BASELINE_CAPABILITY_BRAND: unique symbol;

export type TransactionConstructionFailureReason =
  | "invalid_object"
  | "unsafe_prototype"
  | "invalid_properties"
  | "accessor_property"
  | "unsafe_to_json"
  | "same_wallet"
  | "invalid_genesis_link"
  | "invalid_unix_time"
  | "invalid_expiry"
  | "invalid_message"
  | "invalid_capability";

export class TransactionConstructionError extends Error {
  readonly code = "TRANSACTION_CONSTRUCTION_REJECTED";

  constructor(readonly reason: TransactionConstructionFailureReason) {
    super(`SplitChain v2 construction rejected (${reason})`);
    this.name = "TransactionConstructionError";
  }
}

export interface GenesisWalletBaselineV2Input {
  readonly kind: "GENESIS";
  readonly publicKey: WalletPublicKey;
  // OBSERVED wallet-head balance (foreign-signed layer): grammar-valid but not
  // necessarily canonical shortest form — a head may legitimately carry "2.50".
  readonly balance: ObservedZkzBalance;
  readonly previousSettledStep2Signature: PreviousStateSignature;
}

export interface HeadWalletBaselineV2Input {
  readonly kind: "HEAD";
  readonly publicKey: WalletPublicKey;
  readonly balance: ObservedZkzBalance;
  readonly previousSettledStep2Signature: PreviousStateSignature;
}

export type WalletBaselineV2Input =
  | GenesisWalletBaselineV2Input
  | HeadWalletBaselineV2Input;

interface WalletBaselineV2CapabilityFields {
  readonly publicKey: WalletPublicKey;
  readonly balance: ObservedZkzBalance;
  readonly previousSettledStep2Signature: PreviousStateSignature;
  readonly [WALLET_BASELINE_CAPABILITY_BRAND]: true;
}

export interface GenesisWalletBaselineV2Capability
  extends WalletBaselineV2CapabilityFields {
  readonly kind: "GENESIS";
}

export interface HeadWalletBaselineV2Capability extends WalletBaselineV2CapabilityFields {
  readonly kind: "HEAD";
}

export type WalletBaselineV2Capability =
  | GenesisWalletBaselineV2Capability
  | HeadWalletBaselineV2Capability;

export interface BuildSplitChainInnerV2Input {
  readonly unixTimeSecs: UnixTimeSecsV2;
  readonly sender: WalletBaselineV2Capability;
  readonly receiver: WalletBaselineV2Capability;
  readonly transferAmount: PositiveZkzAmount;
  readonly expiryUnixTimeSecs?: ExpiryUnixTimeSecs;
  readonly message?: string;
}

export interface SplitChainStateV2Projection {
  readonly amount: ZkzBalance;
}

export interface SplitChainInnerV2Projection {
  readonly type: "unique_combinable";
  readonly version: "2";
  readonly unix_time_secs: UnixTimeSecsV2;
  readonly signer_steps: 2;
  readonly step_1_signer: "sender";
  readonly step_2_signer: "receiver";
  readonly step_1_key_public__base64urlsafe: WalletPublicKey;
  readonly step_2_key_public__base64urlsafe: WalletPublicKey;
  readonly step_1_state: SplitChainStateV2Projection;
  readonly step_2_state: SplitChainStateV2Projection;
  readonly previous_step_1_state_signature: PreviousStateSignature;
  readonly previous_step_2_state_signature: PreviousStateSignature;
  readonly expiry__unix_time_secs?: ExpiryUnixTimeSecs;
  readonly message?: string;
}

export interface SplitChainInnerV2Capability {
  readonly inner: SplitChainInnerV2Projection;
  readonly innerPreimageText: string;
  readonly innerPreimageSha256: Sha256Hex;
  readonly [INNER_CAPABILITY_BRAND]: true;
}

export interface SplitChainPartialV2Projection {
  readonly inner: SplitChainInnerV2Projection;
  readonly step_1_signature: Ed25519Signature;
}

export interface SplitChainPartialV2Capability {
  readonly partial: SplitChainPartialV2Projection;
  readonly partialText: string;
  readonly step2PreimageText: string;
  readonly step2PreimageSha256: Sha256Hex;
  readonly [PARTIAL_CAPABILITY_BRAND]: true;
}

export interface SettledSplitChainTransactionV2Projection {
  readonly inner: SplitChainInnerV2Projection;
  readonly step_1_signature: Ed25519Signature;
  readonly step_2_signature: Ed25519Signature;
}

export interface SettledSplitChainTransactionV2 {
  readonly transaction: SettledSplitChainTransactionV2Projection;
  readonly transactionText: string;
  readonly transactionSha256: Sha256Hex;
}

interface MutableState {
  amount: ZkzBalance;
}

interface MutableInner {
  type: "unique_combinable";
  version: "2";
  unix_time_secs: UnixTimeSecsV2;
  signer_steps: 2;
  step_1_signer: "sender";
  step_2_signer: "receiver";
  step_1_key_public__base64urlsafe: WalletPublicKey;
  step_2_key_public__base64urlsafe: WalletPublicKey;
  step_1_state: SplitChainStateV2Projection;
  step_2_state: SplitChainStateV2Projection;
  previous_step_1_state_signature: PreviousStateSignature;
  previous_step_2_state_signature: PreviousStateSignature;
  expiry__unix_time_secs?: ExpiryUnixTimeSecs;
  message?: string;
}

interface MutableInnerCapability {
  inner: SplitChainInnerV2Projection;
  innerPreimageText: string;
  innerPreimageSha256: Sha256Hex;
}

interface MutablePartialProjection {
  inner: SplitChainInnerV2Projection;
  step_1_signature: Ed25519Signature;
}

interface MutablePartialCapability {
  partial: SplitChainPartialV2Projection;
  partialText: string;
  step2PreimageText: string;
  step2PreimageSha256: Sha256Hex;
  innerPreimageText: string;
  step1SignatureJson: string;
}

interface MutableSettledProjection {
  inner: SplitChainInnerV2Projection;
  step_1_signature: Ed25519Signature;
  step_2_signature: Ed25519Signature;
}

interface MutableSettledResult {
  transaction: SettledSplitChainTransactionV2Projection;
  transactionText: string;
  transactionSha256: Sha256Hex;
}

interface MutableWalletBaselineCapability {
  kind: "GENESIS" | "HEAD";
  publicKey: WalletPublicKey;
  balance: ObservedZkzBalance;
  previousSettledStep2Signature: PreviousStateSignature;
}

const TOP_LEVEL_REQUIRED_KEYS = ["unixTimeSecs", "sender", "receiver", "transferAmount"] as const;
const TOP_LEVEL_OPTIONAL_KEYS = ["expiryUnixTimeSecs", "message"] as const;
const BASELINE_REQUIRED_KEYS = [
  "kind",
  "publicKey",
  "balance",
  "previousSettledStep2Signature",
] as const;
const EMPTY_KEYS: readonly string[] = [];
const MAX_EXPIRY_TEXT_LENGTH = 14;
const MAX_MESSAGE_UTF16_CODE_UNITS = 256;
const MAX_MESSAGE_UNICODE_SCALARS = 256;
const MAX_MESSAGE_UTF8_BYTES = MAX_MESSAGE_UNICODE_SCALARS * 4;
const MAX_EXPIRY_AHEAD_MILLISECONDS = 59_999_880_000n;
const BLANK_MESSAGE_PATTERN = /^\s*$/u;
const DANGEROUS_PROPERTY_NAMES = new Set(["__proto__", "constructor", "prototype", "toJSON"]);

const issuedInnerCapabilities = new WeakSet<object>();
const issuedPartialCapabilities = new WeakSet<object>();
const issuedWalletBaselineCapabilities = new WeakSet<object>();

function reject(reason: TransactionConstructionFailureReason): never {
  throw new TransactionConstructionError(reason);
}

function snapshotExactObject(
  value: unknown,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
): readonly unknown[] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return reject("invalid_object");
  }

  if (Object.getOwnPropertyDescriptor(Object.prototype, "toJSON") !== undefined) {
    return reject("unsafe_to_json");
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return reject("unsafe_prototype");
  }

  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key === "symbol")) {
    return reject("invalid_properties");
  }

  const stringKeys = ownKeys as string[];
  if (stringKeys.some((key) => DANGEROUS_PROPERTY_NAMES.has(key))) {
    return reject(keyIsToJson(stringKeys) ? "unsafe_to_json" : "invalid_properties");
  }

  const expectedKeyCount = requiredKeys.length + optionalKeys.filter((key) => stringKeys.includes(key)).length;
  if (
    stringKeys.length !== expectedKeyCount ||
    requiredKeys.some((key) => !stringKeys.includes(key)) ||
    stringKeys.some((key) => !requiredKeys.includes(key) && !optionalKeys.includes(key))
  ) {
    return reject("invalid_properties");
  }

  const values: unknown[] = [];
  for (const key of requiredKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      return reject(descriptor !== undefined && !("value" in descriptor) ? "accessor_property" : "invalid_properties");
    }
    values.push(descriptor.value);
  }
  for (const key of optionalKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) {
      values.push(undefined);
    } else if (!("value" in descriptor) || !descriptor.enumerable) {
      return reject(!("value" in descriptor) ? "accessor_property" : "invalid_properties");
    } else {
      values.push(descriptor.value);
    }
  }
  return values;
}

function keyIsToJson(keys: readonly string[]): boolean {
  return keys.includes("toJSON");
}

/**
 * In-package observation boundary. Callers must first prove that this coherent
 * triple came from an authoritative wallet head; structural validation here
 * does not prove observation authenticity. Deliberately omitted from barrels.
 */
export function issueCoherentWalletBaselineV2ForVerifiedHead(
  value: WalletBaselineV2Input,
): WalletBaselineV2Capability {
  const [kindValue, publicKeyValue, balanceValue, previousSignatureValue] = snapshotExactObject(
    value,
    BASELINE_REQUIRED_KEYS,
    EMPTY_KEYS,
  );
  if (kindValue !== "GENESIS" && kindValue !== "HEAD") {
    return reject("invalid_genesis_link");
  }
  const publicKey = parseWalletPublicKey(publicKeyValue);
  // OBSERVATION boundary, not construction (pattern; the byte-exact signing rule):
  // the balance is an OBSERVED foreign-signed wallet-head value, so it is validated by the
  // ZkzAmount GRAMMAR alone and preserved verbatim. A legitimately non-canonical head spelling
  // such as "2.50" is accepted here — rejecting it with node-authored canonical strictness
  // (parseZkzBalance) would be a false reject at the observation boundary, i.e. the latent
  // stuck-settlement gap. Node-authored construction below stays strict.
  const balance = parseObservedZkzBalance(balanceValue);
  let previousSettledStep2Signature: PreviousStateSignature;
  if (kindValue === "GENESIS") {
    previousSettledStep2Signature = parsePreviousStateSignature(previousSignatureValue);
    if (balance !== "0" || previousSettledStep2Signature !== "") {
      return reject("invalid_genesis_link");
    }
  } else {
    if (previousSignatureValue === "") return reject("invalid_genesis_link");
    const settledSignature = parseEd25519Signature(previousSignatureValue);
    previousSettledStep2Signature = parsePreviousStateSignature(settledSignature);
  }

  const capability = Object.create(null) as MutableWalletBaselineCapability;
  capability.kind = kindValue;
  capability.publicKey = publicKey;
  capability.balance = balance;
  capability.previousSettledStep2Signature = previousSettledStep2Signature;
  Object.freeze(capability);
  issuedWalletBaselineCapabilities.add(capability);
  return capability as WalletBaselineV2Capability;
}

function unixTimeToMilliseconds(value: UnixTimeSecsV2): bigint {
  const separatorIndex = value.indexOf(".");
  if (separatorIndex === -1) return BigInt(value) * 1000n;

  const integerPart = value.slice(0, separatorIndex);
  const fractionalPart = value.slice(separatorIndex + 1);
  let fractionalMilliseconds = BigInt(fractionalPart);
  if (fractionalPart.length === 1) fractionalMilliseconds *= 100n;
  if (fractionalPart.length === 2) fractionalMilliseconds *= 10n;
  return BigInt(integerPart) * 1000n + fractionalMilliseconds;
}

function validateUnixTime(value: unknown): { readonly text: UnixTimeSecsV2; readonly milliseconds: bigint } {
  const text = parseUnixTimeSecsV2(value);
  const milliseconds = unixTimeToMilliseconds(text);
  if (milliseconds <= 0n) return reject("invalid_unix_time");
  return { text, milliseconds };
}

function validateExpiry(value: unknown, unixTimeMilliseconds: bigint): ExpiryUnixTimeSecs {
  if (typeof value !== "string" || value.length > MAX_EXPIRY_TEXT_LENGTH) {
    return reject("invalid_expiry");
  }
  let text: ExpiryUnixTimeSecs;
  try {
    text = parseExpiryUnixTimeSecs(value);
  } catch {
    return reject("invalid_expiry");
  }
  const expiryMilliseconds = BigInt(text) * 1000n;
  const delta = expiryMilliseconds - unixTimeMilliseconds;
  if (delta <= 0n || delta > MAX_EXPIRY_AHEAD_MILLISECONDS) {
    return reject("invalid_expiry");
  }
  return text;
}

function validateMessage(value: unknown): string {
  if (typeof value !== "string") return reject("invalid_message");
  if (
    value.length === 0 ||
    value.length > MAX_MESSAGE_UTF16_CODE_UNITS ||
    BLANK_MESSAGE_PATTERN.test(value)
  ) {
    return reject("invalid_message");
  }
  try {
    parseOpaqueReference(value, {
      maxUtf8Bytes: MAX_MESSAGE_UTF8_BYTES,
      maxCodePoints: MAX_MESSAGE_UNICODE_SCALARS,
    });
  } catch {
    return reject("invalid_message");
  }
  return value;
}

function sha256Utf8(value: string): Sha256Hex {
  return parseSha256Hex(createHash("sha256").update(value, "utf8").digest("hex"));
}

function assertIssuedInnerCapability(value: unknown): asserts value is SplitChainInnerV2Capability {
  if (typeof value !== "object" || value === null || !issuedInnerCapabilities.has(value)) {
    return reject("invalid_capability");
  }
}

function assertIssuedWalletBaselineCapability(
  value: unknown,
): asserts value is WalletBaselineV2Capability {
  if (
    typeof value !== "object" ||
    value === null ||
    !issuedWalletBaselineCapabilities.has(value)
  ) {
    return reject("invalid_capability");
  }
}

function assertIssuedPartialCapability(value: unknown): asserts value is SplitChainPartialV2Capability {
  if (typeof value !== "object" || value === null || !issuedPartialCapabilities.has(value)) {
    return reject("invalid_capability");
  }
}

export function buildSplitChainInnerV2(value: BuildSplitChainInnerV2Input): SplitChainInnerV2Capability {
  const [unixTimeValue, senderValue, receiverValue, transferAmountValue, expiryValue, messageValue] =
    snapshotExactObject(value, TOP_LEVEL_REQUIRED_KEYS, TOP_LEVEL_OPTIONAL_KEYS);

  const unixTime = validateUnixTime(unixTimeValue);
  assertIssuedWalletBaselineCapability(senderValue);
  assertIssuedWalletBaselineCapability(receiverValue);
  const sender = senderValue;
  const receiver = receiverValue;
  const transferAmount = parsePositiveZkzAmount(transferAmountValue);
  if (sender.publicKey === receiver.publicKey) return reject("same_wallet");

  const senderPostBalance = parseZkzBalance(
    subtractZkz(reemitObservedZkzCanonical(sender.balance), transferAmount),
  );
  const receiverPostBalance = parseZkzBalance(
    addZkz(reemitObservedZkzCanonical(receiver.balance), transferAmount),
  );
  const expiry = expiryValue === undefined ? undefined : validateExpiry(expiryValue, unixTime.milliseconds);
  const message = messageValue === undefined ? undefined : validateMessage(messageValue);

  const senderState = Object.create(null) as MutableState;
  senderState.amount = senderPostBalance;
  Object.freeze(senderState);

  const receiverState = Object.create(null) as MutableState;
  receiverState.amount = receiverPostBalance;
  Object.freeze(receiverState);

  const inner = Object.create(null) as MutableInner;
  inner.type = "unique_combinable";
  inner.version = "2";
  inner.unix_time_secs = unixTime.text;
  inner.signer_steps = 2;
  inner.step_1_signer = "sender";
  inner.step_2_signer = "receiver";
  inner.step_1_key_public__base64urlsafe = sender.publicKey;
  inner.step_2_key_public__base64urlsafe = receiver.publicKey;
  inner.step_1_state = senderState;
  inner.step_2_state = receiverState;
  inner.previous_step_1_state_signature = sender.previousSettledStep2Signature;
  inner.previous_step_2_state_signature = receiver.previousSettledStep2Signature;
  if (expiry !== undefined) inner.expiry__unix_time_secs = expiry;
  if (message !== undefined) inner.message = message;
  Object.freeze(inner);

  const innerPreimageText = JSON.stringify(inner);
  const capability = Object.create(null) as MutableInnerCapability;
  capability.inner = inner;
  capability.innerPreimageText = innerPreimageText;
  capability.innerPreimageSha256 = sha256Utf8(innerPreimageText);
  Object.freeze(capability);
  issuedInnerCapabilities.add(capability);
  return capability as SplitChainInnerV2Capability;
}

export function buildSplitChainPartialV2(
  capability: SplitChainInnerV2Capability,
  step1SignatureValue: Ed25519Signature,
): SplitChainPartialV2Capability {
  assertIssuedInnerCapability(capability);
  const step1Signature = parseEd25519Signature(step1SignatureValue);
  const step1SignatureJson = JSON.stringify(step1Signature);
  const step2PreimageText =
    '{"inner":' +
    capability.innerPreimageText +
    ',"step_1_signature":' +
    step1SignatureJson +
    "}";

  const partial = Object.create(null) as MutablePartialProjection;
  partial.inner = capability.inner;
  partial.step_1_signature = step1Signature;
  Object.freeze(partial);

  const partialCapability = Object.create(null) as MutablePartialCapability;
  partialCapability.partial = partial;
  partialCapability.partialText = step2PreimageText;
  partialCapability.step2PreimageText = step2PreimageText;
  partialCapability.step2PreimageSha256 = sha256Utf8(step2PreimageText);
  partialCapability.innerPreimageText = capability.innerPreimageText;
  partialCapability.step1SignatureJson = step1SignatureJson;
  Object.freeze(partialCapability);
  issuedPartialCapabilities.add(partialCapability);
  return partialCapability as unknown as SplitChainPartialV2Capability;
}

export function buildSettledSplitChainTransactionV2(
  capability: SplitChainPartialV2Capability,
  step2SignatureValue: Ed25519Signature,
): SettledSplitChainTransactionV2 {
  assertIssuedPartialCapability(capability);
  const internalCapability = capability as SplitChainPartialV2Capability & MutablePartialCapability;
  const step2Signature = parseEd25519Signature(step2SignatureValue);
  const transactionText =
    '{"inner":' +
    internalCapability.innerPreimageText +
    ',"step_1_signature":' +
    internalCapability.step1SignatureJson +
    ',"step_2_signature":' +
    JSON.stringify(step2Signature) +
    "}";

  const transaction = Object.create(null) as MutableSettledProjection;
  transaction.inner = capability.partial.inner;
  transaction.step_1_signature = capability.partial.step_1_signature;
  transaction.step_2_signature = step2Signature;
  Object.freeze(transaction);

  const result = Object.create(null) as MutableSettledResult;
  result.transaction = transaction;
  result.transactionText = transactionText;
  result.transactionSha256 = sha256Utf8(transactionText);
  Object.freeze(result);
  return result;
}
