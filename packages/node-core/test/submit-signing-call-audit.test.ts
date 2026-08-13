// The submit and signing CALL-COUNT audit. Governing:
// the test plan (Submit and reconciliation); node-core (signer /
// submitter boundary duties); signing custody; the data model
// the one-in-flight-per-wallet and never-blind-retry rules.
//
// This file is the mechanical form of the never-blind-retry rule. It fails if any code path submits
// twice, or signs twice, for one logical operation.
//
// How the call-site CLASS is enumerated (not from this file's own catalogue):
// call-count-audit.ts scans every production `.ts` under src/ for the listed literal
// submit/sign tokens, and the first describe block asserts that scan equals
// SUBMIT_CALL_SITE_CATALOGUE / SIGN_CALL_SITE_CATALOGUE exactly, occurrence counts
// included. A new call site written with one of those tokens therefore fails this audit
// until it is catalogued with the runtime test that counts it. Raw low-level network
// egress is closed by a separate assertion (no production import of node:http|https|net|
// tls|dgram|http2 beyond NETWORK_IMPORT_EXCEPTION_CATALOGUE's one TLS-pin exception).
// Identifier aliasing of a catalogued function is out of static scope
// and is covered by the runtime counting spies at the choke points. Live sockets are also
// denied for every test body by setup-network-guard.ts — independent of this catalogue.
//
// Everything here is offline: the package's setup-network-guard denies fetch/http/net
// before any test body runs, and no ZKZ moves.

import { createHash } from "node:crypto";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  NETWORK_IMPORT_EXCEPTION_CATALOGUE,
  SIGN_CALL_SITE_CATALOGUE,
  SIGN_CALL_SITE_TOKENS,
  SUBMIT_CALL_SITE_CATALOGUE,
  SUBMIT_CALL_SITE_TOKENS,
  RETRY_CAPABLE_PACKAGES,
  assertOneSignPerPersistedPreimage,
  assertOneSubmitPerAuthorization,
  createCountingExchange,
  createCountingVaultSigner,
  productionForbiddenNetworkImports,
  productionSourceFiles,
  scanProductionCallSites,
  scannableText,
} from "./call-count-audit.ts";
import { PARTIALS_TABLE, SIGN_INTENTS_TABLE } from "./crash-replay-surfaces.ts";
import {
  executeMoveSubmitClaim,
  MoveSubmitAmbiguousError,
  type MoveSubmitClaim,
  type MoveSubmitClaimStore,
} from "../src/core/move-submit-claim.js";
import {
  receiveSubmitOnce,
  type SubmitClaimStore,
} from "../src/core/receive-submit-once.js";
import {
  LeaseSignerBoundary,
  type ActiveLeaseRecord,
  type SignerAuditEntry,
  type SigningPurpose,
  type WalletSigningCapability,
} from "../src/core/signer-boundary.js";
import { GatewayTransportAmbiguityError } from "../src/gateway/capture.js";
import {
  SubmitIndeterminateError,
  createSingleShotSubmitTransport,
  submitGatewayRequestOnce,
  type SubmitAuthorization,
  type SubmitGatewayActionOptions,
} from "../src/gateway/submit.js";
import { createGatewaySubmitCredentials } from "../src/gateway/client.js";
import type {
  GatewaySubmitAttemptRecord,
  SubmitAttemptRecorder,
} from "../src/gateway/records.js";
import type { GatewayLimits } from "../src/gateway/types.js";
import type { GatewayRequest } from "../src/protocol/index.js";
import { classifyMoveReconcile } from "../src/protocol/reconcile/move.js";
import { classifyReceiveReconcile } from "../src/protocol/reconcile/receive.js";
import { classifySendReconcile } from "../src/protocol/reconcile/send.js";

const HERE = dirname(fileURLToPath(import.meta.url));

const PRIMARY = "https://gateway-zkz-a.invalid/";
const SECONDARY = "https://gateway-zkz-b.invalid/";
const FIXED_TIME = "2026-07-25T00:00:00.000Z";

const LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 4_096,
  maxResponseBytes: 4_096,
};

const ACK_BODY = new TextEncoder().encode('{"status":true}');

const RECEIVE_AUTHORIZATION: SubmitAuthorization = {
  submitDecisionId: "11111111-1111-4111-8111-111111111111",
  operationId: "22222222-2222-4222-8222-222222222222",
  transactionAttemptNo: 1,
};

const MOVE_AUTHORIZATION: SubmitAuthorization = {
  submitDecisionId: "33333333-3333-4333-8333-333333333333",
  operationId: "44444444-4444-4444-8444-444444444444",
  transactionAttemptNo: 1,
};

const SIGNED_REQUEST: GatewayRequest = {
  rpc: "submit_transaction__v1",
  bodyBytes: new TextEncoder().encode('{"amount":"0.01000000000000000000000000000000"}'),
};

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// The evidence recorder, with the "after gateway acceptance, before local
// acknowledgement" injection point. `failing` is mutable so a row can lose the evidence
// write on the first drive and re-drive against a healthy restarted node.
function countingRecorder(failing = false): SubmitAttemptRecorder & {
  readonly records: readonly GatewaySubmitAttemptRecord[];
  failing: boolean;
} {
  const records: GatewaySubmitAttemptRecord[] = [];
  let failNow = failing;
  return {
    get failing(): boolean {
      return failNow;
    },
    set failing(next: boolean) {
      failNow = next;
    },
    get records(): readonly GatewaySubmitAttemptRecord[] {
      return [...records];
    },
    recordSubmitAttempt: async (record) => {
      if (failNow) {
        throw new Error("evidence write lost");
      }
      records.push(record);
    },
  };
}

type StoreCrash = "BEFORE_PERSIST" | "AFTER_PERSIST" | null;

// A submit-claim store with the two persist-phase injection points needs: a claim
// that never lands (crash before persist) and a claim that lands and then the process dies
// (crash after persist, before submit). `crash` is mutable so a row can crash the first
// drive and then re-drive against a healthy restarted store. The seam is a single
// arbitrated claimSubmitOnce (no separate read-then-write) — same discipline as MOVE.
function claimStore(): SubmitClaimStore & {
  readonly persisted: ReadonlySet<string>;
  crash: StoreCrash;
} {
  const claims = new Map<string, { attemptId: string; claimedAt: string; operationId: string; transactionAttemptNo: number }>();
  const persisted = new Set<string>();
  let crash: StoreCrash = null;
  return {
    get crash(): StoreCrash {
      return crash;
    },
    set crash(next: StoreCrash) {
      crash = next;
    },
    get persisted(): ReadonlySet<string> {
      return persisted;
    },
    claimSubmitOnce: async (claim) => {
      if (crash === "BEFORE_PERSIST") {
        throw new Error("crash before the submit claim is durable");
      }
      const key = `${claim.operationId}#${claim.transactionAttemptNo}`;
      const existing = claims.get(key);
      if (existing !== undefined) {
        return { claim: existing, minted: false };
      }
      claims.set(key, claim);
      persisted.add(claim.attemptId);
      if (crash === "AFTER_PERSIST") {
        // Claim is durable; process dies before the function returns to the submit path.
        throw new Error("crash after the submit claim is durable, before submit");
      }
      return { claim, minted: true };
    },
  };
}

function submitOptions(
  exchange: ReturnType<typeof createCountingExchange>,
  recorder: SubmitAttemptRecorder,
): SubmitGatewayActionOptions {
  return {
    endpoint: PRIMARY,
    limits: LIMITS,
    recorder,
    exchange,
    nowIso: () => FIXED_TIME,
  };
}

// ---------------------------------------------------------------------------

describe("the submit/sign call-site class is enumerated from source", () => {
  it("the submitter class in src/ is exactly the catalogued set", () => {
    expect(scanProductionCallSites(SUBMIT_CALL_SITE_TOKENS)).toEqual(
      SUBMIT_CALL_SITE_CATALOGUE.map(({ file, token, occurrences }) => ({
        file,
        token,
        occurrences,
      })),
    );
  });

  it("the signer class in src/ is exactly the catalogued set", () => {
    expect(scanProductionCallSites(SIGN_CALL_SITE_TOKENS)).toEqual(
      SIGN_CALL_SITE_CATALOGUE.map(({ file, token, occurrences }) => ({
        file,
        token,
        occurrences,
      })),
    );
  });

  // mutation proof: cataloguing a declaration-only seam must not blind
  // the scanner to a genuine new production sign( surface. A fix that greens the census by
  // no longer detecting new sites is the defect, not the fix.
  it("mutation negative: a new production sign( call site still fails the census", () => {
    const srcRoot = resolve(HERE, "../src");
    const probeRel = "_sign_census_mutation_probe.ts";
    const probePath = resolve(srcRoot, probeRel);
    const catalogued = SIGN_CALL_SITE_CATALOGUE.map(({ file, token, occurrences }) => ({
      file,
      token,
      occurrences,
    }));
    try {
      writeFileSync(
        probePath,
        // Genuine runtime call form — not a type seam. Must trip scan ≠ catalogue.
        "export function submit_signing_callMutationProbe(signer: { sign(p: string): string }, p: string) {\n" +
          "  return signer.sign(p);\n" +
          "}\n",
        "utf8",
      );
      const scanned = scanProductionCallSites(SIGN_CALL_SITE_TOKENS);
      expect(scanned).not.toEqual(catalogued);
      expect(scanned.some((hit) => hit.file === probeRel && hit.token === "sign(")).toBe(true);
    } finally {
      try {
        unlinkSync(probePath);
      } catch {
        // probe may already be gone
      }
    }
  });

  it("no production src/ file imports a low-level network module beyond the catalogued TLS-pin egress", () => {
    // Closes the raw https.request / net.connect / … egress class that the token scan
    // alone cannot see. Mirrors the module list setup-network-guard.ts patches at runtime.
    // Pure named `isIP` from node:net is allowed (ssrf-guard classification; no socket).
    // gateway/capture.ts's node:https/node:tls pair is the sole catalogued exception
    // (checkServerIdentity is unreachable through fetch()) — anything beyond that
    // exact set still fails this assertion.
    expect(productionForbiddenNetworkImports()).toEqual(NETWORK_IMPORT_EXCEPTION_CATALOGUE);
  });

  it("network-import audit still has teeth on default/side-effect node:net", () => {
    const srcRoot = resolve(HERE, "../src");
    const probeRel = "_net_import_probe.ts";
    const probePath = resolve(srcRoot, probeRel);
    try {
      writeFileSync(probePath, 'import net from "node:net";\nexport const c = net;\n', "utf8");
      const hits = productionForbiddenNetworkImports().filter((h) => h.file === probeRel);
      expect(hits).toEqual([{ file: probeRel, module: "node:net" }]);
    } finally {
      try {
        unlinkSync(probePath);
      } catch {
        // probe may already be gone
      }
    }
  });

  it("exactly one production HTTP egress exists, and it is the gateway exchange", () => {
    const egress = SUBMIT_CALL_SITE_CATALOGUE.filter((site) => site.role === "NETWORK_EGRESS");
    expect(egress.map((site) => `${site.file}#${site.occurrences}`)).toEqual([
      "gateway/capture.ts#1",
    ]);
  });

  it("submit egresses are the single-shot path plus identical-byte redelivery; read is classified apart", () => {
    expect(
      SUBMIT_CALL_SITE_CATALOGUE.filter((site) => site.role === "SUBMIT_EGRESS").map(
        (site) => site.file,
      ),
    ).toEqual(["gateway/identical-byte-redelivery.ts", "gateway/submit.ts"]);
    expect(
      SUBMIT_CALL_SITE_CATALOGUE.filter((site) => site.role === "READ_NOT_SUBMIT").map(
        (site) => site.file,
      ),
    ).toEqual(["gateway/read.ts"]);
  });

  it("the submit module never imports the read/failover path", () => {
    const submitSource = scannableText(
      readFileSync(resolve(HERE, "../src/gateway/submit.ts"), "utf8"),
    );
    expect(submitSource).not.toContain("./read.js");
    expect(submitSource).not.toContain("./failover.js");
  });

  it("transaction signers are the lease boundary plus SEND/RECEIVE formation; backup is separate", () => {
    expect(
      SIGN_CALL_SITE_CATALOGUE.filter((site) => site.role === "TRANSACTION_SIGNER").map(
        (site) => site.file,
      ),
    ).toEqual([
      "core/signer-boundary.ts",
      "receive/code-formation.ts",
      "send/create.ts",
    ]);
    const backupSource = scannableText(
      readFileSync(resolve(HERE, "../src/core/backup/export.ts"), "utf8"),
    );
    expect(backupSource).not.toContain("SPLITCHAIN_STEP_1");
    expect(backupSource).not.toContain("SPLITCHAIN_STEP_2");
  });

  it("signer type seams are declaration-only (backup + candidate-intake probe)", () => {
    expect(
      SIGN_CALL_SITE_CATALOGUE.filter((site) => site.role === "SIGNER_SEAM_TYPE").map(
        (site) => site.file,
      ),
    ).toEqual(["core/backup/types.ts", "receive/candidate-intake.ts"]);
    // Intake composition may carry the probe, but production source must never call it.
    const intakeSource = scannableText(
      readFileSync(resolve(HERE, "../src/receive/candidate-intake.ts"), "utf8"),
    );
    // Only the interface method declaration — no `.sign(` runtime dispatch.
    expect(intakeSource).toContain("sign(");
    expect(intakeSource).not.toContain(".sign(");
  });
});

describe("submitter: exactly one call per authorized attempt", () => {
  const outcomes = [
    { label: "ACK (2xx)", outcome: { status: 200, body: ACK_BODY } },
    { label: "REJECT (4xx)", outcome: { status: 400, body: ACK_BODY } },
    { label: "INDETERMINATE (5xx)", outcome: { status: 503, body: ACK_BODY } },
  ] as const;

  it.each(outcomes)(
    "submitGatewayRequestOnce makes exactly one exchange on $label",
    async ({ outcome }) => {
      const exchange = createCountingExchange(outcome);
      const recorder = countingRecorder();
      await submitGatewayRequestOnce(
        SIGNED_REQUEST,
        RECEIVE_AUTHORIZATION,
        submitOptions(exchange, recorder),
      );
      assertOneSubmitPerAuthorization(exchange, recorder.records, 1);
    },
  );

  it("makes exactly one exchange when the transport outcome is ambiguous", async () => {
    const exchange = createCountingExchange(
      new GatewayTransportAmbiguityError("no response", new Error("socket hang up")),
    );
    const recorder = countingRecorder();
    const result = await submitGatewayRequestOnce(
      SIGNED_REQUEST,
      RECEIVE_AUTHORIZATION,
      submitOptions(exchange, recorder),
    );
    expect(result.transportOutcome).toBe("INDETERMINATE");
    assertOneSubmitPerAuthorization(exchange, recorder.records, 1);
  });

  it("the single-shot transport calls one endpoint once even when several are configured", async () => {
    const exchange = createCountingExchange({ status: 200, body: ACK_BODY });
    const recorder = countingRecorder();
    const transport = createSingleShotSubmitTransport({
      credentials: createGatewaySubmitCredentials(),
      limits: LIMITS,
      recorder,
      authorization: RECEIVE_AUTHORIZATION,
      exchange,
      nowIso: () => FIXED_TIME,
    });
    await transport.submit([PRIMARY, SECONDARY], SIGNED_REQUEST);
    assertOneSubmitPerAuthorization(exchange, recorder.records, 1);
    expect(exchange.calls.map((call) => call.endpoint)).toEqual([PRIMARY]);
  });
});

// the test plan: the seven crash points, each followed by a real re-drive of
// the production RECEIVE_EXTERNAL submit orchestrator. The assertion in every row is the
// CUMULATIVE exchange count across crash + re-drive — a blind retry shows up as 2.
describe("crash matrix: RECEIVE_EXTERNAL", () => {
  const ATTEMPT_ID = "receive-attempt-zkz-1";

  interface CrashRow {
    readonly point: string;
    // Where the first drive dies. The three axes are exactly the durable stages a submit
    // passes through: the claim write, the exchange itself, and the evidence write.
    readonly storeCrash: StoreCrash;
    readonly outcome: ScriptedExchangeOutcome;
    readonly recorderFails: boolean;
    readonly reconcileDuringCrash: boolean;
    readonly redrives: number;
    // Cumulative exchanges across the crash AND every re-drive. A blind retry shows as 2.
    readonly cumulativeExchanges: number;
    // Attempt rows that survived. Equal to cumulativeExchanges except where the crash IS
    // the lost evidence write — an exchange with no row is exactly what 's
    // "after gateway acceptance, before local acknowledgement" point produces.
    readonly cumulativeRecords: number;
  }

  const rows: readonly CrashRow[] = [
    {
      // Nothing durable exists, so the restarted node legitimately forms and submits once.
      point: "before signed bytes persist",
      storeCrash: "BEFORE_PERSIST",
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: false,
      reconcileDuringCrash: false,
      redrives: 1,
      cumulativeExchanges: 1,
      cumulativeRecords: 1,
    },
    {
      // The claim is durable, so the outcome is unknowable: reconcile only, never submit.
      point: "after persist, before submit",
      storeCrash: "AFTER_PERSIST",
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: false,
      reconcileDuringCrash: false,
      redrives: 1,
      cumulativeExchanges: 0,
      cumulativeRecords: 0,
    },
    {
      point: "during submit with no response",
      storeCrash: null,
      outcome: new GatewayTransportAmbiguityError("no response", new Error("ETIMEDOUT")),
      recorderFails: false,
      reconcileDuringCrash: false,
      redrives: 1,
      cumulativeExchanges: 1,
      cumulativeRecords: 1,
    },
    {
      point: "after gateway acceptance, before local acknowledgement",
      storeCrash: null,
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: true,
      reconcileDuringCrash: false,
      redrives: 1,
      cumulativeExchanges: 1,
      cumulativeRecords: 0,
    },
    {
      point: "after local acknowledgement, before event emission",
      storeCrash: null,
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: false,
      reconcileDuringCrash: false,
      redrives: 1,
      cumulativeExchanges: 1,
      cumulativeRecords: 1,
    },
    {
      point: "during reconciliation",
      storeCrash: null,
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: false,
      reconcileDuringCrash: true,
      redrives: 1,
      cumulativeExchanges: 1,
      cumulativeRecords: 1,
    },
    {
      // Outbox delivery and re-delivery each re-enter the operation; neither may submit.
      point: "before and after outbox delivery",
      storeCrash: null,
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: false,
      reconcileDuringCrash: false,
      redrives: 2,
      cumulativeExchanges: 1,
      cumulativeRecords: 1,
    },
  ];

  it.each(rows)(
    "crash $point: $cumulativeExchanges cumulative exchange(s) across the crash and $redrives re-drive(s)",
    async (row) => {
      const store = claimStore();
      const exchange = createCountingExchange(row.outcome);
      const recorder = countingRecorder(row.recorderFails);

      async function drive(): Promise<void> {
        await receiveSubmitOnce({
          receiveAttemptId: ATTEMPT_ID,
          signedRequest: SIGNED_REQUEST,
          authorization: RECEIVE_AUTHORIZATION,
          submitOptions: submitOptions(exchange, recorder),
          claimStore: store,
          nowIso: () => FIXED_TIME,
        });
      }

      store.crash = row.storeCrash;
      try {
        await drive();
      } catch (error) {
        // Only the two persist-phase rows crash out of the orchestrator; every other row's
        // failure is absorbed into the reconcile-only AMBIGUOUS result.
        expect(row.storeCrash).not.toBeNull();
        expect((error as Error).message).toContain("crash");
      }
      if (row.reconcileDuringCrash) {
        // The reconcile classifier is pure — it can never reach a transport.
        classifyReceiveReconcile({
          boundary: "PRE_SUBMIT",
          receiveOperationId: RECEIVE_AUTHORIZATION.operationId,
          formationComplete: true,
          step2SignaturePersisted: true,
          signerAuditIndicatesUse: true,
        });
      }

      // The node restarts healthy; only the durable state carries across.
      store.crash = null;
      recorder.failing = false;
      const afterCrash = exchange.calls.length;

      for (let redrive = 0; redrive < row.redrives; redrive += 1) {
        await drive();
      }

      if (store.persisted.has(ATTEMPT_ID) && afterCrash > 0) {
        // A durable claim makes every re-drive a no-op at the submitter boundary.
        expect(exchange.calls).toHaveLength(afterCrash);
      }
      expect(exchange.calls.length).toBeLessThanOrEqual(1);
      expect(exchange.calls).toHaveLength(row.cumulativeExchanges);
      // The never-blind-retry rule: whatever went out, it went out once, under one authorization.
      assertOneSubmitPerAuthorization(
        exchange,
        recorder.records,
        row.cumulativeExchanges,
        row.cumulativeRecords,
      );
    },
  );

  it("a re-drive under a durable claim resends nothing — identical bytes never go out twice", async () => {
    const store = claimStore();
    const exchange = createCountingExchange({ status: 200, body: ACK_BODY });
    const recorder = countingRecorder();
    const input = {
      receiveAttemptId: ATTEMPT_ID,
      signedRequest: SIGNED_REQUEST,
      authorization: RECEIVE_AUTHORIZATION,
      submitOptions: submitOptions(exchange, recorder),
      claimStore: store,
      nowIso: () => FIXED_TIME,
    };
    await receiveSubmitOnce(input);
    await receiveSubmitOnce(input);
    await receiveSubmitOnce(input);
    expect(exchange.calls).toHaveLength(1);
    assertOneSubmitPerAuthorization(exchange, recorder.records, 1);
  });
});

// MOVE_INTERNAL is the second node-submit operation. Its submit orchestrator is
// core/move-submit-claim.ts (`executeMoveSubmitClaim`), which routes through
// submitGatewayActionOnce → the shared choke point. The claim seam is a single arbitrated
// claimSubmitOnce (no separate read-then-write), so the persist-phase crash points are
// injected by throwing from that seam before/after the durable mint.
describe("crash matrix: MOVE_INTERNAL", () => {
  const MOVE_SIGNED_TX = { inner: "move-inner-zkz", step_1_signature: "sig-zkz" };

  const attemptKey = (claim: MoveSubmitClaim): string =>
    `${claim.operationId}#${claim.transactionAttemptNo}`;

  function moveClaimStore(): MoveSubmitClaimStore & {
    readonly claims: ReadonlyMap<string, MoveSubmitClaim>;
    crash: StoreCrash;
  } {
    const claims = new Map<string, MoveSubmitClaim>();
    let crash: StoreCrash = null;
    return {
      get crash(): StoreCrash {
        return crash;
      },
      set crash(next: StoreCrash) {
        crash = next;
      },
      get claims(): ReadonlyMap<string, MoveSubmitClaim> {
        return claims;
      },
      claimSubmitOnce: async (claim) => {
        if (crash === "BEFORE_PERSIST") {
          throw new Error("crash before the move submit claim is durable");
        }
        const key = attemptKey(claim);
        const existing = claims.get(key);
        if (existing !== undefined) {
          return { claim: existing, minted: false };
        }
        claims.set(key, claim);
        if (crash === "AFTER_PERSIST") {
          // Claim is durable; process dies before the function returns to the submit path.
          throw new Error("crash after the move submit claim is durable, before submit");
        }
        return { claim, minted: true };
      },
    };
  }

  interface CrashRow {
    readonly point: string;
    readonly storeCrash: StoreCrash;
    readonly outcome: ScriptedExchangeOutcome;
    readonly recorderFails: boolean;
    readonly reconcileDuringCrash: boolean;
    readonly redrives: number;
    readonly cumulativeExchanges: number;
    readonly cumulativeRecords: number;
  }

  const rows: readonly CrashRow[] = [
    {
      point: "before signed bytes persist",
      storeCrash: "BEFORE_PERSIST",
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: false,
      reconcileDuringCrash: false,
      redrives: 1,
      cumulativeExchanges: 1,
      cumulativeRecords: 1,
    },
    {
      // Durable mint with no exchange: restart loses the mint → reconcile only.
      point: "after persist, before submit",
      storeCrash: "AFTER_PERSIST",
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: false,
      reconcileDuringCrash: false,
      redrives: 1,
      cumulativeExchanges: 0,
      cumulativeRecords: 0,
    },
    {
      point: "during submit with no response",
      storeCrash: null,
      outcome: new GatewayTransportAmbiguityError("no response", new Error("ECONNRESET")),
      recorderFails: false,
      reconcileDuringCrash: false,
      redrives: 1,
      cumulativeExchanges: 1,
      cumulativeRecords: 1,
    },
    {
      point: "after gateway acceptance, before local acknowledgement",
      storeCrash: null,
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: true,
      reconcileDuringCrash: false,
      redrives: 1,
      cumulativeExchanges: 1,
      cumulativeRecords: 0,
    },
    {
      point: "after local acknowledgement, before event emission",
      storeCrash: null,
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: false,
      reconcileDuringCrash: false,
      redrives: 1,
      cumulativeExchanges: 1,
      cumulativeRecords: 1,
    },
    {
      point: "during reconciliation",
      storeCrash: null,
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: false,
      reconcileDuringCrash: true,
      redrives: 1,
      cumulativeExchanges: 1,
      cumulativeRecords: 1,
    },
    {
      point: "before and after outbox delivery",
      storeCrash: null,
      outcome: { status: 200, body: ACK_BODY },
      recorderFails: false,
      reconcileDuringCrash: false,
      redrives: 2,
      cumulativeExchanges: 1,
      cumulativeRecords: 1,
    },
  ];

  it("the MOVE_INTERNAL submit entry point is catalogued", () => {
    expect(
      SUBMIT_CALL_SITE_CATALOGUE.filter((site) => site.role === "SUBMIT_ENTRY").map(
        (site) => site.file,
      ),
    ).toEqual([
      "core/move-submit-claim.ts",
      "core/receive-submit-once.ts",
      "gateway/submit.ts",
    ]);
  });

  it.each(rows)(
    "crash $point: $cumulativeExchanges cumulative exchange(s) across the crash and $redrives re-drive(s)",
    async (row) => {
      const store = moveClaimStore();
      const exchange = createCountingExchange(row.outcome);
      const recorder = countingRecorder(row.recorderFails);

      async function drive(): Promise<void> {
        await executeMoveSubmitClaim({
          authorization: MOVE_AUTHORIZATION,
          signedTransaction: MOVE_SIGNED_TX,
          claimStore: store,
          submit: submitOptions(exchange, recorder),
        });
      }

      store.crash = row.storeCrash;
      try {
        await drive();
      } catch (error) {
        if (error instanceof MoveSubmitAmbiguousError) {
          // Recorder lost the evidence write after the exchange — exchange may have landed.
          expect(row.recorderFails).toBe(true);
        } else {
          expect(row.storeCrash).not.toBeNull();
          expect((error as Error).message).toContain("crash");
        }
      }
      if (row.reconcileDuringCrash) {
        classifyMoveReconcile({
          boundary: "PRE_SUBMIT",
          moveAttemptId: "move-attempt-zkz-1",
          preimagePersisted: true,
          signaturesComplete: true,
          signerAuditIndicatesCall: true,
        });
      }

      store.crash = null;
      recorder.failing = false;
      const afterCrash = exchange.calls.length;

      for (let redrive = 0; redrive < row.redrives; redrive += 1) {
        await drive();
      }

      if (store.claims.size > 0 && afterCrash > 0) {
        // A durable claim makes every re-drive a no-op at the submitter boundary.
        expect(exchange.calls).toHaveLength(afterCrash);
      }
      expect(exchange.calls.length).toBeLessThanOrEqual(1);
      expect(exchange.calls).toHaveLength(row.cumulativeExchanges);
      assertOneSubmitPerAuthorization(
        exchange,
        recorder.records,
        row.cumulativeExchanges,
        row.cumulativeRecords,
      );
    },
  );

  it("a re-drive under a durable claim resends nothing — identical bytes never go out twice", async () => {
    const store = moveClaimStore();
    const exchange = createCountingExchange({ status: 200, body: ACK_BODY });
    const recorder = countingRecorder();
    const input = {
      authorization: MOVE_AUTHORIZATION,
      signedTransaction: MOVE_SIGNED_TX,
      claimStore: store,
      submit: submitOptions(exchange, recorder),
    };
    await executeMoveSubmitClaim(input);
    await executeMoveSubmitClaim(input);
    await executeMoveSubmitClaim(input);
    expect(exchange.calls).toHaveLength(1);
    assertOneSubmitPerAuthorization(exchange, recorder.records, 1);
  });

  it("the reconcile classifier adds no exchange and never authorizes a second submit", () => {
    const exchange = createCountingExchange({ status: 200, body: ACK_BODY });
    for (const preimagePersisted of [false, true]) {
      for (const signaturesComplete of [false, true]) {
        for (const signerAuditIndicatesCall of [false, true]) {
          classifyMoveReconcile({
            boundary: "PRE_SUBMIT",
            moveAttemptId: "move-attempt-zkz-1",
            preimagePersisted,
            signaturesComplete,
            signerAuditIndicatesCall,
          });
        }
      }
    }
    expect(exchange.calls).toHaveLength(0);
  });
});

// operation flows and signing custody: the node never submits
// SEND_EXTERNAL. Proven three ways, so no single missed code path defeats it.
describe("SEND_EXTERNAL: zero submitter calls, ever", () => {
  it("structurally: the send tables carry no submit-decision or submit-attempt reference", () => {
    for (const table of [SIGN_INTENTS_TABLE, PARTIALS_TABLE]) {
      const referenced = table.columns
        .filter(
          (column) =>
            column.raw.includes("submit_decisions") ||
            column.raw.includes("gateway_submit_attempts"),
        )
        .map((column) => `${table.name}.${column.name}`);
      expect(referenced).toEqual([]);
      expect(table.raw).not.toContain("submit_decisions");
      expect(table.raw).not.toContain("gateway_submit_attempts");
    }
  });

  it("statically: no production file that mentions SEND_EXTERNAL holds a submit call site", () => {
    const submitFiles = new Set(SUBMIT_CALL_SITE_CATALOGUE.map((site) => site.file));
    const sendMentionFiles = productionSourceFiles().filter((file) =>
      scannableText(readFileSync(file, "utf8")).includes("SEND_EXTERNAL"),
    );
    // Non-vacuity: the scan must actually see SEND_EXTERNAL somewhere under src/,
    // otherwise "no overlap with submit sites" is true for the wrong reason.
    expect(sendMentionFiles.length).toBeGreaterThan(0);
    const offenders = sendMentionFiles
      .map((file) => file.slice(file.indexOf("/src/") + 5))
      .filter((file) => submitFiles.has(file));
    expect(offenders).toEqual([]);
  });

  it("at runtime: the send reconcile classifier never emits a submit action", () => {
    const exchange = createCountingExchange({ status: 200, body: ACK_BODY });
    const signer = createCountingVaultSigner();
    const actions: string[] = [];
    for (const signIntentPersisted of [false, true]) {
      for (const step1SignaturePersisted of [false, true]) {
        for (const signerAuditIndicatesCall of [false, true]) {
          const outcome = classifySendReconcile({
            boundary: "PRE_DELIVERY",
            sendOperationId: "send-operation-zkz-1",
            signIntentPersisted,
            step1SignaturePersisted,
            signerAuditIndicatesCall,
          });
          if (outcome.kind === "PROVEN_NOT_STARTED") {
            actions.push(outcome.resumeAction);
          }
        }
      }
    }
    expect(actions.length).toBeGreaterThan(0);
    expect(actions.filter((action) => action.includes("SUBMIT"))).toEqual([]);
    expect(exchange.calls).toHaveLength(0);
    expect(signer.calls).toHaveLength(0);
  });

  it("the SUBMIT-free send vocabulary is not vacuous: the node-submit kinds do emit it", () => {
    const receive = classifyReceiveReconcile({
      boundary: "PRE_SUBMIT",
      receiveOperationId: RECEIVE_AUTHORIZATION.operationId,
      formationComplete: true,
      step2SignaturePersisted: true,
      signerAuditIndicatesUse: true,
    });
    const move = classifyMoveReconcile({
      boundary: "PRE_SUBMIT",
      moveAttemptId: "move-attempt-zkz-1",
      preimagePersisted: true,
      signaturesComplete: true,
      signerAuditIndicatesCall: true,
    });
    expect(receive.kind === "PROVEN_NOT_STARTED" ? receive.resumeAction : null).toBe(
      "SUBMIT_ONCE",
    );
    expect(move.kind === "PROVEN_NOT_STARTED" ? move.resumeAction : null).toBe("SUBMIT_ONCE");
  });
});

// signing custody: "Submits are not placed inside generic HTTP retry
// middleware."
describe("no HTTP retry middleware and no hidden SDK retry", () => {
  it("node-core depends on no retry-capable HTTP package", () => {
    const manifest = JSON.parse(
      readFileSync(resolve(HERE, "../package.json"), "utf8"),
    ) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const declared = [
      ...Object.keys(manifest.dependencies ?? {}),
      ...Object.keys(manifest.devDependencies ?? {}),
    ];
    expect(declared.filter((name) => RETRY_CAPABLE_PACKAGES.includes(name))).toEqual([]);
  });

  it("the submit module contains no iteration construct around the exchange", () => {
    const submitSource = scannableText(
      readFileSync(resolve(HERE, "../src/gateway/submit.ts"), "utf8"),
    );
    for (const construct of ["for (", "for(", "while (", "while(", ".forEach(", ".reduce("]) {
      expect(submitSource).not.toContain(construct);
    }
  });

  it("the exchange transport is invoked directly, never through a wrapper the caller injects twice", async () => {
    // A recorder that fails is the only post-exchange failure mode; it must NOT re-enter
    // the exchange while converting the failure into the reconcile-only signal.
    const exchange = createCountingExchange({ status: 200, body: ACK_BODY });
    const recorder = countingRecorder(true);
    await expect(
      submitGatewayRequestOnce(
        SIGNED_REQUEST,
        RECEIVE_AUTHORIZATION,
        submitOptions(exchange, recorder),
      ),
    ).rejects.toBeInstanceOf(SubmitIndeterminateError);
    expect(exchange.calls).toHaveLength(1);
  });
});

// node-core: "signer — sign an already-persisted exact preimage". One call per
// persisted preimage per role — receiver step-2 for RECEIVE_EXTERNAL; source step-1 plus
// destination step-2 for MOVE_INTERNAL.
describe("signer: exactly one call per persisted preimage per role", () => {
  function boundary(lease: ActiveLeaseRecord | null): {
    readonly boundary: LeaseSignerBoundary;
    readonly signer: ReturnType<typeof createCountingVaultSigner>;
    readonly auditEntries: readonly SignerAuditEntry[];
  } {
    const entries: SignerAuditEntry[] = [];
    const signer = createCountingVaultSigner();
    return {
      boundary: new LeaseSignerBoundary({
        // Process-wide leadership is required on every money-path sign.
        leadership: { held: true },
        leaseReader: { readActiveLease: async () => lease },
        vaultSigner: signer,
        auditLog: {
          append: async (entry) => {
            entries.push(entry);
          },
        },
        now: () => FIXED_TIME,
        assertMoneyAdmitted: () => {},
        assertCanOperate: () => {},
        assertWalletMaySign: async () => {},
      }),
      signer,
      get auditEntries(): readonly SignerAuditEntry[] {
        return [...entries];
      },
    };
  }

  function capability(
    walletId: string,
    purpose: SigningPurpose,
    preimageText: string,
  ): WalletSigningCapability {
    return {
      walletId,
      operationId: "operation-zkz-1",
      leaseEpoch: 1n,
      purpose,
      preimageText,
      expectedPreimageSha256: sha256Hex(preimageText),
    };
  }

  it("RECEIVE_EXTERNAL: one signer call for the receiver's step-2 preimage", async () => {
    const harness = boundary({
      walletId: "receiver-zkz",
      operationId: "operation-zkz-1",
      epoch: 1n,
      role: "RECEIVE_WINDOW",
      lifecycle: "ACTIVE",
    });
    await harness.boundary.sign(
      capability("receiver-zkz", "SPLITCHAIN_STEP_2", '{"step":"2","amount":"0.01"}'),
    );
    expect(harness.signer.calls).toHaveLength(1);
    assertOneSignPerPersistedPreimage(harness.signer, harness.auditEntries);
  });

  it("MOVE_INTERNAL: one signer call for source step-1 and one for destination step-2", async () => {
    const source = boundary({
      walletId: "move-source-zkz",
      operationId: "operation-zkz-1",
      epoch: 1n,
      role: "MOVE_SOURCE",
      lifecycle: "ACTIVE",
    });
    await source.boundary.sign(
      capability("move-source-zkz", "SPLITCHAIN_STEP_1", '{"step":"1","amount":"0.01"}'),
    );

    const destination = boundary({
      walletId: "move-destination-zkz",
      operationId: "operation-zkz-1",
      epoch: 1n,
      role: "RECEIVE_WINDOW",
      lifecycle: "ACTIVE",
    });
    await destination.boundary.sign(
      capability("move-destination-zkz", "SPLITCHAIN_STEP_2", '{"step":"2","amount":"0.00"}'),
    );

    expect(source.signer.calls).toHaveLength(1);
    expect(destination.signer.calls).toHaveLength(1);
    assertOneSignPerPersistedPreimage(source.signer, source.auditEntries);
    assertOneSignPerPersistedPreimage(destination.signer, destination.auditEntries);
    // One preimage per role, never the same bytes signed twice.
    expect(source.signer.calls[0].preimageSha256).not.toBe(
      destination.signer.calls[0].preimageSha256,
    );
  });

  const rejections: readonly {
    readonly label: string;
    readonly lease: ActiveLeaseRecord | null;
    readonly capability: WalletSigningCapability;
  }[] = [
    {
      label: "no active lease",
      lease: null,
      capability: capability("receiver-zkz", "SPLITCHAIN_STEP_2", '{"step":"2"}'),
    },
    {
      label: "lease released",
      lease: {
        walletId: "receiver-zkz",
        operationId: "operation-zkz-1",
        epoch: 1n,
        role: "RECEIVE_WINDOW",
        lifecycle: "RELEASED",
      },
      capability: capability("receiver-zkz", "SPLITCHAIN_STEP_2", '{"step":"2"}'),
    },
    {
      label: "operation mismatch",
      lease: {
        walletId: "receiver-zkz",
        operationId: "operation-zkz-other",
        epoch: 1n,
        role: "RECEIVE_WINDOW",
        lifecycle: "ACTIVE",
      },
      capability: capability("receiver-zkz", "SPLITCHAIN_STEP_2", '{"step":"2"}'),
    },
    {
      label: "lease epoch mismatch",
      lease: {
        walletId: "receiver-zkz",
        operationId: "operation-zkz-1",
        epoch: 2n,
        role: "RECEIVE_WINDOW",
        lifecycle: "ACTIVE",
      },
      capability: capability("receiver-zkz", "SPLITCHAIN_STEP_2", '{"step":"2"}'),
    },
    {
      label: "role not permitted",
      lease: {
        walletId: "receiver-zkz",
        operationId: "operation-zkz-1",
        epoch: 1n,
        role: "OBSERVATION",
        lifecycle: "ACTIVE",
      },
      capability: capability("receiver-zkz", "SPLITCHAIN_STEP_2", '{"step":"2"}'),
    },
    {
      label: "preimage digest mismatch",
      lease: {
        walletId: "receiver-zkz",
        operationId: "operation-zkz-1",
        epoch: 1n,
        role: "RECEIVE_WINDOW",
        lifecycle: "ACTIVE",
      },
      capability: {
        ...capability("receiver-zkz", "SPLITCHAIN_STEP_2", '{"step":"2"}'),
        expectedPreimageSha256: sha256Hex("a different preimage"),
      },
    },
  ];

  it.each(rejections)("zero signer calls when $label", async ({ lease, capability: cap }) => {
    const harness = boundary(lease);
    await expect(harness.boundary.sign(cap)).rejects.toThrow();
    expect(harness.signer.calls).toHaveLength(0);
    assertOneSignPerPersistedPreimage(harness.signer, harness.auditEntries);
  });

  it("the one-sign-per-preimage assertion has teeth: a double sign fails it", async () => {
    const harness = boundary({
      walletId: "receiver-zkz",
      operationId: "operation-zkz-1",
      epoch: 1n,
      role: "RECEIVE_WINDOW",
      lifecycle: "ACTIVE",
    });
    const cap = capability("receiver-zkz", "SPLITCHAIN_STEP_2", '{"step":"2","amount":"0.01"}');
    await harness.boundary.sign(cap);
    await harness.boundary.sign(cap);
    expect(harness.signer.calls).toHaveLength(2);
    expect(() =>
      assertOneSignPerPersistedPreimage(harness.signer, harness.auditEntries),
    ).toThrow();
  });

  it("the one-submit-per-authorization assertion has teeth: a double submit fails it", async () => {
    const exchange = createCountingExchange({ status: 200, body: ACK_BODY });
    const recorder = countingRecorder();
    const options = submitOptions(exchange, recorder);
    await submitGatewayRequestOnce(SIGNED_REQUEST, RECEIVE_AUTHORIZATION, options);
    await submitGatewayRequestOnce(SIGNED_REQUEST, RECEIVE_AUTHORIZATION, options);
    expect(exchange.calls).toHaveLength(2);
    // Two exchanges under one authorization: duplicate decision id, duplicate attempt slot.
    expect(() => assertOneSubmitPerAuthorization(exchange, recorder.records, 2)).toThrow();
  });
});
