// Strict parsers for every Appendix – suite-tuple purpose. Each
// parser takes untrusted wire bytes (`string | Uint8Array`), decodes strictly, and re-derives the
// canonical bytes through `serializeSuiteTuple` (the same constructor the builders
// use) so every field-level rejection (missing/unexpected field, wrong type, non-canonical scalar,
// wrong purpose/version, invalid composite shape) is enforced exactly once, in exactly one place.
//
// This module adds only what the wire-decode step needs and the registry cannot check on its own,
// since it never sees raw bytes: (1) strict UTF-8 decoding — a lone surrogate or invalid byte
// sequence in the source must be rejected before it can silently mangle into U+FFFD replacement
// bytes under a lossy decode (via the shared
// `strictDecodeTupleSource`); (2) an exact `purpose + "\n"` prefix check (also rejects a prepended
// BOM or a `\r\n` separator, since neither can match the literal prefix); (3) a byte-for-byte
// round-trip comparison between the decoded source and the rebuilt canonical preimage, which is the
// general-purpose test for every non-canonical framing the registry's field-by-field checks cannot
// see on their own — key reorder, appended/surrounding whitespace, a numeric literal that
// re-stringifies differently (e.g. `1.0` vs `1`), or any other byte the source and the rebuild
// disagree on.
import { Buffer } from "node:buffer";

import type {
  DestinationBlessInput,
  DeviceEnrolInput,
  MoveInternalExpectedInput,
  NodeEventInput,
  ReceiveExpectedInput,
  ReportRequestInput,
  ReportingRegisterInput,
  SendExternalApprovalInput,
  SendExternalExpectedInput,
  WalletHeadFingerprintInput,
} from "./builders.js";
import { serializeSuiteTuple, type SuiteTupleValues } from "./serialize.js";

export type SuiteParseReason = "invalid_utf8" | "purpose_mismatch" | "invalid_json" | "non_canonical_bytes";

// Parse-direction rejection only. Field-level rejections surface as-is from `serializeSuiteTuple`
// (`SuiteSerializeError`, `InvalidFieldError`, `InvalidScalarError`) — this module never re-wraps
// them, so a caller distinguishing "malformed wire framing" from "a signed field failed validation"
// can do so by error type alone, matching this codebase's per-layer error convention.
export class SuiteParseError extends Error {
  readonly code = "SUITE_PARSE";

  constructor(readonly reason: SuiteParseReason) {
    super(`suite parse rejected (${reason})`);
    this.name = "SuiteParseError";
  }
}

export interface ParsedSuiteTuple<TPayload> {
  readonly payload: TPayload;
  readonly preimageText: string;
  readonly preimageBytes: Uint8Array;
  readonly sha256: string;
}

// Mirrors the private helper in scalars.ts (not exported there) so this module does not need to
// widen that frozen file's surface for a ten-line utility.
function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function decodeStrict(source: string | Uint8Array): { readonly text: string; readonly bytes: Uint8Array } {
  if (typeof source === "string") {
    if (hasLoneSurrogate(source)) throw new SuiteParseError("invalid_utf8");
    return { text: source, bytes: Buffer.from(source, "utf8") };
  }
  if (!(source instanceof Uint8Array)) throw new SuiteParseError("invalid_utf8");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(source);
  } catch {
    throw new SuiteParseError("invalid_utf8");
  }
  return { text, bytes: Uint8Array.from(source) };
}

function parseSuitePurpose(purpose: string, source: string | Uint8Array): ParsedSuiteTuple<SuiteTupleValues> {
  const decoded = decodeStrict(source);
  const prefix = `${purpose}\n`;
  if (!decoded.text.startsWith(prefix)) throw new SuiteParseError("purpose_mismatch");

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded.text.slice(prefix.length));
  } catch {
    throw new SuiteParseError("invalid_json");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new SuiteParseError("invalid_json");
  }

  const rebuilt = serializeSuiteTuple(purpose, parsed as SuiteTupleValues);
  const rebuiltBytes = Buffer.from(rebuilt.preimageBytes);
  if (!rebuiltBytes.equals(Buffer.from(decoded.bytes))) {
    throw new SuiteParseError("non_canonical_bytes");
  }

  return { payload: parsed as SuiteTupleValues, preimageText: rebuilt.preimageText, preimageBytes: rebuilt.preimageBytes, sha256: rebuilt.sha256 };
}

export type ReceiveExpectedPayload = { readonly purpose: "zp-receive-expected-v1"; readonly canonical_version: 1 } & ReceiveExpectedInput;
export function parseReceiveExpectedArtifact(source: string | Uint8Array): ParsedSuiteTuple<ReceiveExpectedPayload> {
  const result = parseSuitePurpose("zp-receive-expected-v1", source);
  return { ...result, payload: result.payload as unknown as ReceiveExpectedPayload };
}

export type MoveInternalExpectedPayload = { readonly purpose: "zp-move-internal-expected-v1"; readonly canonical_version: 1 } & MoveInternalExpectedInput;
export function parseMoveInternalExpectedArtifact(source: string | Uint8Array): ParsedSuiteTuple<MoveInternalExpectedPayload> {
  const result = parseSuitePurpose("zp-move-internal-expected-v1", source);
  return { ...result, payload: result.payload as unknown as MoveInternalExpectedPayload };
}

export type SendExternalExpectedPayload = { readonly purpose: "zp-send-external-expected-v1"; readonly canonical_version: 1 } & SendExternalExpectedInput;
export function parseSendExternalExpectedArtifact(source: string | Uint8Array): ParsedSuiteTuple<SendExternalExpectedPayload> {
  const result = parseSuitePurpose("zp-send-external-expected-v1", source);
  return { ...result, payload: result.payload as unknown as SendExternalExpectedPayload };
}

export type SendExternalApprovalPayload = { readonly purpose: "zp-send-external-approval-v1"; readonly canonical_version: 1 } & SendExternalApprovalInput;
export function parseSendExternalApproval(source: string | Uint8Array): ParsedSuiteTuple<SendExternalApprovalPayload> {
  const result = parseSuitePurpose("zp-send-external-approval-v1", source);
  return { ...result, payload: result.payload as unknown as SendExternalApprovalPayload };
}

export type DestinationBlessPayload = { readonly purpose: "zp-destination-bless-v1"; readonly canonical_version: 1 } & DestinationBlessInput;
export function parseDestinationBless(source: string | Uint8Array): ParsedSuiteTuple<DestinationBlessPayload> {
  const result = parseSuitePurpose("zp-destination-bless-v1", source);
  return { ...result, payload: result.payload as unknown as DestinationBlessPayload };
}

export type DeviceEnrolPayload = { readonly purpose: "zp-device-enrol-v1"; readonly canonical_version: 1 } & DeviceEnrolInput;
export function parseDeviceEnrol(source: string | Uint8Array): ParsedSuiteTuple<DeviceEnrolPayload> {
  const result = parseSuitePurpose("zp-device-enrol-v1", source);
  return { ...result, payload: result.payload as unknown as DeviceEnrolPayload };
}

export type ReportRequestPayload = { readonly purpose: "zp-report-request-v1"; readonly canonical_version: 1 } & ReportRequestInput;
export function parseReportRequest(source: string | Uint8Array): ParsedSuiteTuple<ReportRequestPayload> {
  const result = parseSuitePurpose("zp-report-request-v1", source);
  return { ...result, payload: result.payload as unknown as ReportRequestPayload };
}

export type ReportingRegisterPayload = { readonly purpose: "zp-reporting-register-v1"; readonly canonical_version: 1 } & ReportingRegisterInput;
export function parseReportingRegister(source: string | Uint8Array): ParsedSuiteTuple<ReportingRegisterPayload> {
  const result = parseSuitePurpose("zp-reporting-register-v1", source);
  return { ...result, payload: result.payload as unknown as ReportingRegisterPayload };
}

export type NodeEventPayload = { readonly purpose: "zp-node-event-v1"; readonly canonical_version: 1 } & NodeEventInput;
export function parseNodeEvent(source: string | Uint8Array): ParsedSuiteTuple<NodeEventPayload> {
  const result = parseSuitePurpose("zp-node-event-v1", source);
  return { ...result, payload: result.payload as unknown as NodeEventPayload };
}

export type WalletHeadFingerprintPayload = { readonly purpose: "zp-wallet-head-fingerprint-v1"; readonly canonical_version: 1 } & WalletHeadFingerprintInput;
export function parseWalletHeadFingerprint(source: string | Uint8Array): ParsedSuiteTuple<WalletHeadFingerprintPayload> {
  const result = parseSuitePurpose("zp-wallet-head-fingerprint-v1", source);
  return { ...result, payload: result.payload as unknown as WalletHeadFingerprintPayload };
}
