// The call-count audit harness for the signer and submitter boundaries.
//
// Two halves, deliberately separate:
//
//   1. A STATIC enumeration of the *literal-token* call-site class, produced by scanning
//      the production source tree for the tokens listed below. The catalogues are the
//      *expected result* of that scan, never its input: submit-signing-call-audit.test.ts
//      asserts scan == catalogue, so a new call written with one of those tokens fails the
//      audit until it is listed here together with the runtime test that counts it.
//      Coverage is judged against the source, not against the test's own list.
//
//      What this static half enforces (and what it does not):
//        - ENFORCED: every occurrence of the listed submit/sign tokens under src/ is
//          catalogued with an exact occurrence count.
//        - ENFORCED: no production src/ file imports the low-level network modules
//          (node:http|https|net|tls|dgram|http2), so raw socket egress cannot be added
//          without tripping the audit (mirrors setup-network-guard's module list).
//        - NOT ENFORCED statically: identifier aliasing / rebinding of a catalogued
//          function (e.g. `const aliased = submitGatewayRequestOnce; aliased(...)`).
//          Runtime counting spies at the choke points cover that class.
//        - Live network is also denied for every test body by setup-network-guard.ts;
//          that is independent of this catalogue.
//
//   2. Counting spies at the two boundaries, so every runtime case asserts an exact
//      invocation count rather than "it returned something".
//
// All fixture naming is ZKZ; no test here moves coins or opens a socket (the package's
// setup-network-guard denies every transport before a test body runs).

import { readdirSync, statSync } from "node:fs";
import { extname, join, relative, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { readFileSync } from "node:fs";
import { expect } from "vitest";

import type { VaultSigner, SignerAuditEntry } from "../src/core/signer-boundary.js";
import {
  sha256Hex,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
} from "../src/gateway/capture.js";
import { fingerprintEndpoint } from "../src/gateway/client.js";
import type { GatewaySubmitAttemptRecord } from "../src/gateway/records.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = resolve(HERE, "../src");

// ---------------------------------------------------------------------------
// 1. Static call-site class enumeration
// ---------------------------------------------------------------------------

// The literal tokens this package uses for a submit to cross a boundary: the process-wide
// HTTP egress, the single-shot exchange, the two exported single-shot entry points, and
// the injected GatewaySubmitTransport seam. `.exchange(` deliberately also catches the
// READ path so the audit has to classify it rather than silently ignore it.
// Raw `https.request` / `net.connect` style egress is closed separately by
// FORBIDDEN_NETWORK_MODULES below — not by these tokens.
export const SUBMIT_CALL_SITE_TOKENS = [
  "fetch(",
  ".exchange(",
  "submitGatewayActionOnce(",
  "submitGatewayRequestOnce(",
  ".submit(",
] as const;

// The literal token by which a signature is produced in this package: bare `sign(` covers
// method-form calls (`.sign(`), interface/method declarations (`sign(` / `async sign(`),
// and the node:crypto function form (`sign(null, …)`). Every hit is catalogued — including
// type seams and test-fixture helpers — so the class named by this token is complete.
export const SIGN_CALL_SITE_TOKENS = ["sign("] as const;

// Low-level network modules that must never appear as a production import under src/.
// Mirrors the module list patched by test/setup-network-guard.ts. A new raw egress path
// written with https.request / net.connect / etc. therefore fails this audit even when it
// avoids the SUBMIT_CALL_SITE_TOKENS list above.
export const FORBIDDEN_NETWORK_MODULES = [
  "node:http",
  "node:https",
  "node:net",
  "node:tls",
  "node:dgram",
  "node:http2",
  "http",
  "https",
  "net",
  "tls",
  "dgram",
  "http2",
] as const;

export interface CallSiteScanHit {
  readonly file: string;
  readonly token: string;
  readonly occurrences: number;
}

const BLOCK_COMMENT = /\/\*[\s\S]*?\*\//g;

// Only WHOLE-LINE `//` comments are stripped. A trailing comment is left in place, because
// stripping from the first `//` would truncate any line holding a URL literal and could
// hide a real call that follows it. The residual risk is a false POSITIVE (a token named
// inside a trailing comment), which fails toward cataloguing an extra call site — never
// toward hiding one.
export function scannableText(source: string): string {
  return source
    .replace(BLOCK_COMMENT, "")
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("//"))
    .join("\n");
}

// Production source only: `*.test.ts` is excluded because a test may legitimately call a
// submit entry point, and `src/testkit/` is excluded because it ships fakes, not money
// paths (forbids production src importing it).
export function productionSourceFiles(): string[] {
  return (readdirSync(SRC_ROOT, { recursive: true }) as string[])
    .map((entry) => join(SRC_ROOT, entry))
    .filter(
      (file) =>
        extname(file) === ".ts" &&
        !file.endsWith(".test.ts") &&
        !relative(SRC_ROOT, file).split(/[\\/]/).includes("testkit") &&
        statSync(file).isFile(),
    );
}

export function scanProductionCallSites(tokens: readonly string[]): CallSiteScanHit[] {
  const hits: CallSiteScanHit[] = [];
  for (const file of productionSourceFiles()) {
    const text = scannableText(readFileSync(file, "utf8"));
    for (const token of tokens) {
      const occurrences = text.split(token).length - 1;
      if (occurrences > 0) {
        hits.push({
          file: relative(SRC_ROOT, file).split(/[\\/]/).join("/"),
          token,
          occurrences,
        });
      }
    }
  }
  return hits.sort((a, b) => a.file.localeCompare(b.file) || a.token.localeCompare(b.token));
}

// Return every production src/ import of a forbidden network module. Any raw egress
// beyond NETWORK_IMPORT_EXCEPTION_CATALOGUE below lands here and fails the audit.
// Covers: `import … from "mod"`, side-effect `import "mod"`, dynamic `import("mod")`,
// and `require("mod")`.
//
// Pure classification exports (no socket, no connect) may be named-imported from these
// modules without counting as egress. Default / namespace / side-effect / dynamic /
// require imports of the whole module still fail — mirrors setup-network-guard.ts which
// only patches connect/createConnection/request, not isIP.
const MODULE_SPECIFIER_PATTERNS = [
  // Capture binding form when present: `import X from "mod"`, `import { a } from "mod"`,
  // `import * as ns from "mod"`. Group 1 = binding clause (may be empty for side-effect),
  // group 2 = module specifier on from-form.
  /\bimport\s+([\s\S]*?)\s+from\s+["']([^"']+)["']/g,
  /\bimport\s+["']([^"']+)["']/g,
  /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
  /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
];

// Named-only pure utilities allowed from otherwise-forbidden modules.
const PURE_NAMED_NETWORK_EXPORTS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ["node:net", new Set(["isIP"])],
  ["net", new Set(["isIP"])],
]);

function isPureNamedNetworkImport(binding: string, mod: string): boolean {
  const allowed = PURE_NAMED_NETWORK_EXPORTS.get(mod);
  if (!allowed) return false;
  const trimmed = binding.trim();
  // Only `{ a, b as c }` form — not default, not namespace.
  if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return false;
  const names = trimmed
    .slice(1, -1)
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      // `isIP` or `isIP as isIp`
      const beforeAs = part.split(/\s+as\s+/i)[0]!.trim();
      return beforeAs;
    });
  return names.length > 0 && names.every((n) => allowed.has(n));
}

export function productionForbiddenNetworkImports(): readonly {
  readonly file: string;
  readonly module: string;
}[] {
  const forbidden = new Set<string>(FORBIDDEN_NETWORK_MODULES);
  const hits: { file: string; module: string }[] = [];
  for (const file of productionSourceFiles()) {
    const text = scannableText(readFileSync(file, "utf8"));
    const rel = relative(SRC_ROOT, file).split(/[\\/]/).join("/");
    for (const pattern of MODULE_SPECIFIER_PATTERNS) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null) {
        // from-form has (binding, mod); side-effect/dynamic/require have (mod) only.
        const hasBinding = match.length >= 3 && match[2] !== undefined;
        const binding = hasBinding ? match[1]! : "";
        const mod = hasBinding ? match[2]! : match[1]!;
        if (!forbidden.has(mod)) continue;
        if (hasBinding && isPureNamedNetworkImport(binding, mod)) continue;
        hits.push({ file: rel, module: mod });
      }
    }
  }
  return hits.sort(
    (a, b) => a.file.localeCompare(b.file) || a.module.localeCompare(b.module),
  );
}

// The sole, deliberate, exact-count exception to FORBIDDEN_NETWORK_MODULES: TLS
// certificate pin comparison needs checkServerIdentity's cert
// argument, which fetch() has no way to expose. Every entry here must be load-bearing
// for that one purpose — the "no production src/ file imports a low-level network
// module" assertion checks the scan against this catalogue exactly (mirrors
// SUBMIT_CALL_SITE_CATALOGUE), so a NEW raw-network import anywhere else, or a THIRD
// import added to capture.ts, still fails the audit loudly.
export const NETWORK_IMPORT_EXCEPTION_CATALOGUE: ReadonlyArray<{
  readonly file: string;
  readonly module: string;
}> = [
  { file: "gateway/capture.ts", module: "node:https" },
  { file: "gateway/capture.ts", module: "node:tls" },
];

export type CallSiteRole =
  // the one process-wide HTTP egress every gateway exchange funnels into
  | "NETWORK_EGRESS"
  // the single shot: the only place a submit request leaves the node
  | "SUBMIT_EGRESS"
  // the read/failover path — iterates endpoints by design and must never reach submit
  | "READ_NOT_SUBMIT"
  // the request-level core every submit entry point routes through
  | "SUBMIT_CHOKE_POINT"
  // an exported entry point that reaches the choke point exactly once
  | "SUBMIT_ENTRY"
  // the injected GatewaySubmitTransport seam dispatched by the gateway client
  | "SUBMIT_SEAM"
  // SplitChain step-1 / step-2 signing of an already-persisted exact preimage
  | "TRANSACTION_SIGNER"
  // a wrapper that gates a signer and delegates at most once
  | "SIGNER_WRAPPER"
  // signing that is not a SplitChain transaction preimage (backup manifests)
  | "NON_TRANSACTION_SIGNER"
  // an interface/type seam that declares `sign(` without producing a signature
  | "SIGNER_SEAM_TYPE"
  // a test-fixture helper that produces a real signature for colocated unit tests only
  | "TEST_FIXTURE_SIGNER";

export interface CallSiteRecord extends CallSiteScanHit {
  readonly role: CallSiteRole;
  readonly countedBy: string;
}

// The expected scan result for the submitter class. Occurrence counts are exact: adding a
// second `.exchange(` to submit.ts, or a fourth `submitGatewayRequestOnce(` mention, breaks
// the audit even though the file was already catalogued.
export const SUBMIT_CALL_SITE_CATALOGUE: readonly CallSiteRecord[] = [
  {
    file: "core/move-submit-claim.ts",
    token: "submitGatewayActionOnce(",
    occurrences: 1,
    role: "SUBMIT_ENTRY",
    countedBy: "crash matrix — MOVE_INTERNAL",
  },
  {
    file: "core/receive-submit-once.ts",
    token: "submitGatewayRequestOnce(",
    occurrences: 1,
    role: "SUBMIT_ENTRY",
    countedBy: "crash matrix — RECEIVE_EXTERNAL",
  },
  {
    file: "gateway/capture.ts",
    token: "fetch(",
    occurrences: 1,
    role: "NETWORK_EGRESS",
    countedBy: "single production HTTP egress; denied outright by setup-network-guard",
  },
  {
    file: "gateway/client.ts",
    token: ".submit(",
    occurrences: 1,
    role: "SUBMIT_SEAM",
    countedBy: "gateway client dispatches the injected transport exactly once",
  },
  {
    file: "gateway/read.ts",
    token: ".exchange(",
    occurrences: 1,
    role: "READ_NOT_SUBMIT",
    countedBy: "read path — asserted never reachable from submit.ts",
  },
  {
    file: "gateway/submit.ts",
    token: ".exchange(",
    occurrences: 1,
    role: "SUBMIT_EGRESS",
    countedBy: "one exchange per authorized attempt, every transport outcome",
  },
  {
    file: "gateway/submit.ts",
    token: "submitGatewayActionOnce(",
    occurrences: 1,
    role: "SUBMIT_ENTRY",
    countedBy: "one exchange per authorized attempt, every transport outcome",
  },
  {
    // 3 = the `export async function` declaration plus its two in-module callers
    // (submitGatewayActionOnce and createSingleShotSubmitTransport).
    file: "gateway/submit.ts",
    token: "submitGatewayRequestOnce(",
    occurrences: 3,
    role: "SUBMIT_CHOKE_POINT",
    countedBy: "one exchange per authorized attempt, every transport outcome",
  },
] as const;

// The expected scan result for the signer class under token `sign(`. Includes:
//   - transaction signing (signer-boundary)
//   - gated wrapper (halt-gate)
//   - non-transaction backup signing (export) plus its interface seam (types)
//   - the reporting test-fixture helper that calls node:crypto `sign(null, …)` —
//     production never imports it (file header), but it is under src/ and produces a real
//     Ed25519 signature, so the class is incomplete without it.
// Occurrence counts are exact against bare `sign(` (method form, declarations, and the
// crypto function form all match the same token).
export const SIGN_CALL_SITE_CATALOGUE: readonly CallSiteRecord[] = [
  {
    file: "core/backup/export.ts",
    token: "sign(",
    occurrences: 2,
    role: "NON_TRANSACTION_SIGNER",
    countedBy: "backup manifest / identity signing — asserted to sign no SplitChain preimage",
  },
  {
    file: "core/backup/types.ts",
    token: "sign(",
    occurrences: 1,
    role: "SIGNER_SEAM_TYPE",
    countedBy: "BackupSigner interface declaration — no runtime call",
  },
  {
    file: "core/signer-boundary.ts",
    token: "sign(",
    // VaultSigner.sign decl + LeaseSignerBoundary.sign method + this.vaultSigner.sign call
    occurrences: 3,
    role: "TRANSACTION_SIGNER",
    countedBy: "one signer call per persisted preimage per role",
  },
  {
    file: "event-log/dual-chain-appender.ts",
    token: "sign(",
    // NodeEventSigner.sign decl + one EVENT_SIGNING signature per chain
    // (zp-node-event-v1, then zp-implementer-event-v1). Never a SplitChain transaction.
    occurrences: 3,
    role: "NON_TRANSACTION_SIGNER",
    countedBy: "one EVENT_SIGNING signature per durable event per chain",
  },
  {
    file: "operator/halt-gate.ts",
    token: "sign(",
    // SignRequest seam decl + delegate.sign call
    occurrences: 2,
    role: "SIGNER_WRAPPER",
    countedBy: "gated signer delegates at most once, zero while halted",
  },
  {
    file: "proof/policies/test-transactions.ts",
    token: "sign(",
    occurrences: 1,
    role: "TEST_FIXTURE_SIGNER",
    countedBy: "node:crypto sign(null, …) policy-test fixture — production never imports this file",
  },
  {
    // The push subscribe id-proof — the single params.sign call that signs the
    // timestamp. This is a WALLET-key signature proving key ownership to the push service;
    // it never produces or touches a SplitChain transaction preimage, so it is not a
    // transaction signer.
    file: "push/id-proof.ts",
    token: "sign(",
    occurrences: 1,
    role: "NON_TRANSACTION_SIGNER",
    countedBy: "one id-proof signature per subscribe attempt (timestamp preimage only)",
  },
  {
    // Declaration-only probe port. Candidate intake MUST NEVER invoke the
    // signer — CandidateIntakeSignerProbe.sign exists so tests can assert zero calls. Same
    // SIGNER_SEAM_TYPE class as BackupSigner: a type seam, not a runtime producer.
    file: "receive/candidate-intake.ts",
    token: "sign(",
    occurrences: 1,
    role: "SIGNER_SEAM_TYPE",
    countedBy:
      "CandidateIntakeSignerProbe interface declaration — no runtime call (intake asserts zero invocations)",
  },
  {
    file: "receive/code-formation.ts",
    token: "sign(",
    // NodeIdentitySigner.sign seam + resume-path sign + first-formation sign
    occurrences: 3,
    role: "TRANSACTION_SIGNER",
    countedBy:
      "RECEIVE_EXTERNAL formation — one sign per persisted artifact preimage (code-formation.test.ts)",
  },
  {
    file: "reporting/test-fixtures.ts",
    token: "sign(",
    occurrences: 1,
    role: "TEST_FIXTURE_SIGNER",
    countedBy: "node:crypto sign(null, …) fixture helper — production never imports this file",
  },
  {
    file: "send/create.ts",
    token: "sign(",
    // ExternalSendSigner.sign seam + one production call with already-persisted preimage bytes
    occurrences: 2,
    role: "TRANSACTION_SIGNER",
    countedBy: "SEND_EXTERNAL formation — one sign per approved/persisted preimage",
  },
  {
    // NODE_IDENTITY / EVENT_SIGNING artifact signer seam + method body.
    // Opens sealed seed per call; signs zp-*-expected-v1 / backup manifests — never
    // SplitChain step-1/2 transaction perimaes (those stay on VaultSigner).
    file: "signing-keys/ensure.ts",
    token: "sign(",
    occurrences: 2,
    role: "NON_TRANSACTION_SIGNER",
    countedBy:
      "NODE_IDENTITY sealed-store artifact signer — expected-artifact / identity only; vault holds wallet secrets",
  },
] as const;

// Packages that ship request retry (or an HTTP client that retries by default).
// "Submits are not placed inside generic HTTP retry
// middleware." The audit asserts none of these is reachable as a node-core dependency.
export const RETRY_CAPABLE_PACKAGES = [
  "axios",
  "got",
  "superagent",
  "request",
  "request-promise",
  "node-fetch-retry",
  "fetch-retry",
  "p-retry",
  "async-retry",
  "retry",
  "retry-axios",
  "exponential-backoff",
  "backoff",
  "cockatiel",
  "opossum",
  "ky",
  "wretch",
] as const;

// ---------------------------------------------------------------------------
// 2. Counting spies at the two boundaries
// ---------------------------------------------------------------------------

export type ScriptedExchangeOutcome =
  | { readonly status: number; readonly body: Uint8Array }
  | Error;

export interface CountedExchangeCall {
  readonly endpoint: string;
  readonly requestSha256: string;
}

export interface CountingExchange extends GatewayExchangeTransport {
  readonly calls: readonly CountedExchangeCall[];
}

// The submitter-boundary spy. One entry per exchange the node actually attempted, with the
// endpoint and the exact request digest, so "how many times did we submit" is a length and
// "did we resend the same bytes" is a digest comparison.
export function createCountingExchange(outcome: ScriptedExchangeOutcome): CountingExchange {
  const calls: CountedExchangeCall[] = [];
  return {
    get calls(): readonly CountedExchangeCall[] {
      return [...calls];
    },
    exchange: async (endpoint, request): Promise<GatewayExchangeCapture> => {
      const requestSha256 = sha256Hex(request.bodyBytes);
      calls.push({ endpoint, requestSha256 });
      if (outcome instanceof Error) {
        throw outcome;
      }
      return {
        endpoint,
        endpointFingerprint: fingerprintEndpoint(endpoint),
        requestBytes: request.bodyBytes,
        requestSha256,
        responseBytes: outcome.body,
        responseSha256: sha256Hex(outcome.body),
        statusCode: outcome.status,
      };
    },
  };
}

export interface CountedSignCall {
  readonly walletId: string;
  readonly preimageSha256: string;
}

export interface CountingVaultSigner extends VaultSigner {
  readonly calls: readonly CountedSignCall[];
}

// The signer-boundary spy. Records the wallet and the digest of the exact bytes handed to
// the vault, so "one signature per persisted preimage" is checkable without trusting the
// boundary's own audit log.
export function createCountingVaultSigner(
  signature = "emlnbmF0dXJlLXpreg",
): CountingVaultSigner {
  const calls: CountedSignCall[] = [];
  return {
    get calls(): readonly CountedSignCall[] {
      return [...calls];
    },
    sign: async (walletId, preimageBytes) => {
      calls.push({ walletId, preimageSha256: sha256Hex(preimageBytes) });
      return signature;
    },
  };
}

// ---------------------------------------------------------------------------
// 3. Assertion helpers
// ---------------------------------------------------------------------------

// At most one gateway call for the one immutable transaction attempt.
// Asserts the runtime spy and the persisted evidence agree, then re-checks the schema's own
// uniqueness shape against the rows — so the proof survives a spy that missed a code path.
// `expectedRecords` diverges from `expectedExchanges` only where the crash under test IS
// the lost evidence write: an exchange with no surviving row is exactly's "after
// gateway acceptance, before local acknowledgement" point, and is why that outcome is
// INDETERMINATE rather than a claimed success.
export function assertOneSubmitPerAuthorization(
  exchange: CountingExchange,
  records: readonly GatewaySubmitAttemptRecord[],
  expectedExchanges: number,
  expectedRecords: number = expectedExchanges,
): void {
  expect(exchange.calls).toHaveLength(expectedExchanges);
  expect(records).toHaveLength(expectedRecords);

  const decisionIds = records.map((record) => record.decisionId);
  expect(new Set(decisionIds).size).toBe(decisionIds.length);

  const attemptSlots = records.map((record) => `${record.operationId}#${record.attemptNo}`);
  expect(new Set(attemptSlots).size).toBe(attemptSlots.length);

  const transactionSlots = records.map(
    (record) => `${record.operationId}#${record.transactionAttemptNo}`,
  );
  expect(new Set(transactionSlots).size).toBe(transactionSlots.length);

  for (const record of records) {
    expect(record.attemptNo).toBe(1);
    expect(record.transactionAttemptNo).toBe(1);
  }
}

// The signer signs an already-persisted exact preimage. One vault call
// per SIGNED audit entry, each over the digest that entry recorded — a second signature for
// the same preimage, or a signature with no audit entry, fails here.
export function assertOneSignPerPersistedPreimage(
  signer: CountingVaultSigner,
  auditEntries: readonly SignerAuditEntry[],
): void {
  const signed = auditEntries.filter((entry) => entry.outcome === "SIGNED");
  expect(signer.calls).toHaveLength(signed.length);
  expect(signer.calls.map((call) => call.preimageSha256)).toEqual(
    signed.map((entry) => entry.preimageSha256),
  );
  const perPreimage = new Map<string, number>();
  for (const call of signer.calls) {
    perPreimage.set(call.preimageSha256, (perPreimage.get(call.preimageSha256) ?? 0) + 1);
  }
  for (const [preimageSha256, count] of perPreimage) {
    expect(`${preimageSha256}:${count}`).toBe(`${preimageSha256}:1`);
  }
}
