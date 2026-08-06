// Lab receive tool — operator-only capped RECEIVE_EXTERNAL for seeing a
// transfer_code/QR without a consumer app. Real chain rules; no gate bypass.
//
// Cap ≤ 0.01 ZKZ enforced server-side (the external transaction cap).
// recovery_verified + reporting + implementer gates checked via readiness signals —
// never skip recovery verification. Wake ≠ proof; no false "paid".

import { createHash, createPrivateKey, randomUUID, sign as cryptoSign } from "node:crypto";

import {
  buildReportRequestPreimage,
  REPORT_REQUEST_CANONICAL_VERSION,
  REPORT_REQUEST_PURPOSE,
} from "@zucoins/generic-node-contracts";
import {
  compareZkz,
  formatZkz,
  parsePositiveZkzAmount,
  parseZkzBalance,
  sha256HexUtf8,
  toBase64UrlPadded,
  type OperationRouteStore,
  type ReceiveResponse,
} from "@zucoins/node-core";

import {
  buildReadinessChecklist,
  type ReadinessChecklist,
  type ReadinessRow,
  type ReadinessSignals,
} from "./admin-readiness.js";

/** External transaction cap — lab is not looser. */
export const LAB_RECEIVE_MAX_ZKZ = "0.01" as const;

export const LAB_RECEIVE_ANCHOR_PREFIX = "lab" as const;

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export type LabReceiveBlockedCode =
  | "lab_amount_exceeds_cap"
  | "lab_amount_invalid"
  | "lab_gates_blocked"
  | "lab_implementer_missing"
  | "lab_not_ready"
  | "lab_arm_failed"
  | "lab_reporting_seed_invalid"
  | "lab_create_failed";

export interface LabReceiveGateLink {
  readonly id: string;
  readonly href: string;
  readonly title: string;
  readonly detail: string;
  readonly status: string;
}

export type LabReceiveResult =
  | {
      readonly ok: true;
      readonly body: LabReceiveSuccessBody;
    }
  | {
      readonly ok: false;
      readonly status: 400 | 409 | 422 | 503;
      readonly code: LabReceiveBlockedCode;
      readonly message: string;
      readonly checklist_links?: readonly LabReceiveGateLink[];
      readonly operation_id?: string;
    };

export interface LabReceiveSuccessBody {
  readonly object: "lab_receive";
  readonly lab: true;
  readonly non_production_label: "lab/non-production";
  readonly amount_zkz: string;
  readonly operation_id: string;
  readonly state: string;
  readonly code_status: string;
  readonly transfer_code: string;
  readonly transfer_code_sha256: string;
  readonly expires_at: string | null;
  readonly receiver_pubkey: string | null;
  readonly discriminator: string | null;
  readonly reminders: {
    readonly wake_is_not_proof: true;
    readonly independent_verify_required: true;
    readonly verification_complete_required: true;
    readonly no_false_paid: true;
  };
}

export interface LabReceiveCreateInput {
  readonly amount_zkz: unknown;
  readonly reporting_key_id: unknown;
  readonly reporting_private_seed_hex: unknown;
  readonly idempotency_key?: unknown;
}

export interface LabReceivePorts {
  readonly nodeId: string;
  readonly resolveImplementerId: () => Promise<string | null>;
  readonly operationStore: OperationRouteStore;
  /** Invoke the live reporting request handler (ARM path). */
  readonly reportingHandle: (captured: {
    readonly method: string;
    readonly rawTarget: string;
    readonly rawHeaders: readonly string[];
    readonly bodyBytes: Uint8Array;
    readonly receivedAtMs: number;
  }) => Promise<{
    readonly status: number;
    readonly headers: Readonly<Record<string, string>>;
    readonly bodyBytes: Uint8Array;
  }>;
  readonly collectSignals: () => Promise<ReadinessSignals>;
  readonly nowMs: () => number;
  /** Max wait for CREATED→READY before returning lab_not_ready. */
  readonly readyWaitMs?: number;
  readonly readyPollMs?: number;
}

/** Pure: reject amounts above the external cap (byte-canonical compare). */
export function assertLabReceiveAmount(
  amountRaw: unknown,
):
  | { readonly ok: true; readonly amount_zkz: string }
  | { readonly ok: false; readonly code: "lab_amount_invalid" | "lab_amount_exceeds_cap"; readonly message: string } {
  let amount: ReturnType<typeof parsePositiveZkzAmount>;
  try {
    amount = parsePositiveZkzAmount(amountRaw);
  } catch {
    return {
      ok: false,
      code: "lab_amount_invalid",
      message: "amount_zkz must be a positive canonical ZKZ decimal string",
    };
  }
  const amountText = formatZkz(amount);
  const cap = parseZkzBalance(LAB_RECEIVE_MAX_ZKZ);
  if (compareZkz(amount, cap) > 0) {
    return {
      ok: false,
      code: "lab_amount_exceeds_cap",
      message: `Lab receive amount must be ≤ ${LAB_RECEIVE_MAX_ZKZ} ZKZ (external-amount cap)`,
    };
  }
  return { ok: true, amount_zkz: amountText };
}

/** Gates that block RECEIVE_EXTERNAL — lab must not bypass. */
export function receiveBlockingRows(checklist: ReadinessChecklist): readonly ReadinessRow[] {
  return checklist.rows.filter(
    (r) =>
      (r.status === "blocked" || r.status === "amber") &&
      (r.blocks_ops?.includes("RECEIVE_EXTERNAL") === true ||
        r.id === "recovery_verified_wallet" ||
        r.id === "reporting_key_active" ||
        r.id === "implementer_key" ||
        r.id === "node_healthy"),
  );
}

export function checklistLinksFromRows(rows: readonly ReadinessRow[]): readonly LabReceiveGateLink[] {
  return rows.map((r) => ({
    id: r.id,
    href: r.href,
    title: r.title,
    detail: r.detail,
    status: r.status,
  }));
}

function parseReportingSeed(
  raw: unknown,
):
  | { readonly ok: true; readonly seed: Buffer }
  | { readonly ok: false; readonly message: string } {
  if (typeof raw !== "string" || raw.trim().length === 0) {
    return { ok: false, message: "reporting_private_seed_hex is required (32-byte hex Ed25519 seed)" };
  }
  const hex = raw.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    return { ok: false, message: "reporting_private_seed_hex must be 64 lowercase hex chars (32 bytes)" };
  }
  return { ok: true, seed: Buffer.from(hex, "hex") };
}

function parseKeyId(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const t = raw.trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(t)) {
    return null;
  }
  return t.toLowerCase();
}

function seedToPrivateKey(seed: Buffer) {
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

function signPadded(preimageText: string, privateKey: ReturnType<typeof createPrivateKey>): string {
  const sig = cryptoSign(null, Buffer.from(preimageText, "utf8"), privateKey);
  return toBase64UrlPadded(sig);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForArmable(
  store: OperationRouteStore,
  operationId: string,
  implementerId: string,
  opts: { readonly waitMs: number; readonly pollMs: number; readonly nowMs: () => number },
): Promise<ReceiveResponse | null> {
  const deadline = opts.nowMs() + opts.waitMs;
  let last: ReceiveResponse | null = null;
  while (opts.nowMs() < deadline) {
    last = await store.getReceive(operationId, implementerId);
    if (
      last !== null &&
      last.operation.state === "READY" &&
      last.t0 !== null &&
      last.code_status === "AWAITING_ARM"
    ) {
      return last;
    }
    // Terminal failure states — stop early.
    if (
      last !== null &&
      (last.operation.state === "FAILED" ||
        last.operation.state === "EXPIRED" ||
        last.operation.state === "CANCELLED")
    ) {
      return last;
    }
    await sleep(opts.pollMs);
  }
  return last;
}

/**
 * Create a capped lab receive, wait for READY, ARM with operator-supplied reporting seed.
 * Seed is used only for this request — never logged, never returned, never stored.
 */
export async function runLabReceive(
  ports: LabReceivePorts,
  input: LabReceiveCreateInput,
): Promise<LabReceiveResult> {
  const amountCheck = assertLabReceiveAmount(input.amount_zkz);
  if (!amountCheck.ok) {
    return {
      ok: false,
      status: 400,
      code: amountCheck.code,
      message: amountCheck.message,
    };
  }

  const keyId = parseKeyId(input.reporting_key_id);
  if (keyId === null) {
    return {
      ok: false,
      status: 400,
      code: "lab_reporting_seed_invalid",
      message: "reporting_key_id must be a UUID",
    };
  }
  const seedParsed = parseReportingSeed(input.reporting_private_seed_hex);
  if (!seedParsed.ok) {
    return {
      ok: false,
      status: 400,
      code: "lab_reporting_seed_invalid",
      message: seedParsed.message,
    };
  }

  const signals = await ports.collectSignals();
  const checklist = buildReadinessChecklist(signals, new Date(ports.nowMs()).toISOString());
  const blocking = receiveBlockingRows(checklist);
  if (blocking.length > 0) {
    return {
      ok: false,
      status: 409,
      code: "lab_gates_blocked",
      message:
        "Lab receive blocked — checklist items still red. Fix setup first (no gate bypass).",
      checklist_links: checklistLinksFromRows(blocking),
    };
  }

  const implementerId = await ports.resolveImplementerId();
  if (implementerId === null) {
    return {
      ok: false,
      status: 409,
      code: "lab_implementer_missing",
      message: "No implementer registered — issue a server API key first.",
      checklist_links: [
        {
          id: "implementer_key",
          href: "/api-keys",
          title: "Server API key",
          detail: "Issue an implementer API key before lab receive.",
          status: "blocked",
        },
      ],
    };
  }

  const idem =
    typeof input.idempotency_key === "string" && input.idempotency_key.trim().length > 0
      ? input.idempotency_key.trim().slice(0, 128)
      : randomUUID();

  const anchor = `${LAB_RECEIVE_ANCHOR_PREFIX}-${ports.nowMs().toString(36)}-${randomUUID().slice(0, 8)}`;

  let created: { status: 201 | 202; body: ReceiveResponse };
  try {
    created = await ports.operationStore.createReceive({
      amount_zkz: amountCheck.amount_zkz,
      anchor,
      expires_in_seconds: 300,
      after_landing: { kind: "HOLD", destination_id: null },
      idempotencyKey: idem,
      implementerId,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "receive create failed";
    return {
      ok: false,
      status: 503,
      code: "lab_create_failed",
      message: msg.slice(0, 200),
    };
  }

  const operationId = created.body.operation.operation_id;
  const waitMs = ports.readyWaitMs ?? 20_000;
  const pollMs = ports.readyPollMs ?? 500;

  const ready = await waitForArmable(ports.operationStore, operationId, implementerId, {
    waitMs,
    pollMs,
    nowMs: ports.nowMs,
  });

  if (
    ready === null ||
    ready.operation.state !== "READY" ||
    ready.t0 === null ||
    ready.code_status !== "AWAITING_ARM"
  ) {
    return {
      ok: false,
      status: 503,
      code: "lab_not_ready",
      message:
        "Receive created but not yet READY/AWAITING_ARM (T0 or pool not ready). Retry arm later or check money workers.",
      operation_id: operationId,
      checklist_links: [
        {
          id: "node_healthy",
          href: "/",
          title: "Node health",
          detail: "Wait for READY then re-run lab receive, or open Operations for the op id.",
          status: "amber",
        },
      ],
    };
  }

  const armBody = JSON.stringify({
    expected_row_version: ready.operation.row_version,
    t0: {
      observation_id: ready.t0.observation_id,
      projection: {
        s: ready.t0.projection.s,
        p: ready.t0.projection.p,
        b_zkz: ready.t0.projection.b_zkz,
      },
    },
    opened_cursor: "0",
  });

  const rawTarget = `/v1/operations/${operationId}/armed`;
  const issuedAtMs = ports.nowMs();
  const expiresAtMs = issuedAtMs + 30_000;
  const issuedAt = new Date(issuedAtMs).toISOString();
  const expiresAt = new Date(expiresAtMs).toISOString();
  const bodySha = sha256HexUtf8(armBody);
  const nonce = toBase64UrlPadded(createHash("sha256").update(randomUUID()).digest().subarray(0, 16));

  const preimage = buildReportRequestPreimage({
    purpose: REPORT_REQUEST_PURPOSE,
    canonical_version: REPORT_REQUEST_CANONICAL_VERSION,
    node_id: ports.nodeId,
    implementer_id: implementerId,
    method: "POST",
    path: rawTarget,
    body_sha256: bodySha,
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
  });

  let signature: string;
  try {
    signature = signPadded(preimage, seedToPrivateKey(seedParsed.seed));
  } catch {
    return {
      ok: false,
      status: 400,
      code: "lab_reporting_seed_invalid",
      message: "reporting_private_seed_hex is not a valid Ed25519 seed",
    };
  }

  const armIdem = randomUUID();
  const armResponse = await ports.reportingHandle({
    method: "POST",
    rawTarget,
    rawHeaders: [
      "X-ZP-Reporting-Key-Id",
      keyId,
      "X-ZP-Reporting-Timestamp",
      issuedAt,
      "X-ZP-Reporting-Expires-At",
      expiresAt,
      "X-ZP-Reporting-Nonce",
      nonce,
      "X-ZP-Reporting-Signature",
      signature,
      "Idempotency-Key",
      armIdem,
      "Content-Type",
      "application/json",
    ],
    bodyBytes: new TextEncoder().encode(armBody),
    receivedAtMs: issuedAtMs + 1,
  });

  if (armResponse.status < 200 || armResponse.status >= 300) {
    let detail = `ARM failed HTTP ${armResponse.status}`;
    try {
      const parsed = JSON.parse(new TextDecoder().decode(armResponse.bodyBytes)) as {
        error?: { message?: string; code?: string };
      };
      if (parsed.error?.message) detail = parsed.error.message;
      else if (parsed.error?.code) detail = parsed.error.code;
    } catch {
      /* keep */
    }
    return {
      ok: false,
      status: 503,
      code: "lab_arm_failed",
      message: detail.slice(0, 240),
      operation_id: operationId,
    };
  }

  let armParsed: {
    transfer_code?: string;
    transfer_code_sha256?: string;
    expires_at?: string;
    code_status?: string;
    state?: string;
  };
  try {
    armParsed = JSON.parse(new TextDecoder().decode(armResponse.bodyBytes)) as typeof armParsed;
  } catch {
    return {
      ok: false,
      status: 503,
      code: "lab_arm_failed",
      message: "ARM response was not JSON",
      operation_id: operationId,
    };
  }

  const transferCode = armParsed.transfer_code;
  if (typeof transferCode !== "string" || transferCode.length === 0) {
    return {
      ok: false,
      status: 503,
      code: "lab_arm_failed",
      message: "ARM succeeded without transfer_code",
      operation_id: operationId,
    };
  }

  // Success body is secret-scoped: transfer_code only; no reporting seed, no ik_, no sh_.
  return {
    ok: true,
    body: {
      object: "lab_receive",
      lab: true,
      non_production_label: "lab/non-production",
      amount_zkz: amountCheck.amount_zkz,
      operation_id: operationId,
      state: armParsed.state ?? "READY",
      code_status: armParsed.code_status ?? "RELEASED",
      transfer_code: transferCode,
      transfer_code_sha256:
        typeof armParsed.transfer_code_sha256 === "string"
          ? armParsed.transfer_code_sha256
          : createHash("sha256").update(transferCode).digest("hex"),
      expires_at: armParsed.expires_at ?? ready.expires_at,
      receiver_pubkey: ready.receiver_pubkey,
      discriminator: ready.discriminator,
      reminders: {
        wake_is_not_proof: true,
        independent_verify_required: true,
        verification_complete_required: true,
        no_false_paid: true,
      },
    },
  };
}

/** Assert lab success JSON never carries secret-shaped keys. */
export function assertLabPayloadSecretFree(body: unknown): void {
  const json = JSON.stringify(body);
  const forbidden = [
    "raw_private",
    "private_seed",
    "reporting_private",
    "ik_",
    "master_key",
    "VAULT_",
    "BACKUP_MASTER",
    "password",
  ];
  for (const f of forbidden) {
    if (json.toLowerCase().includes(f.toLowerCase()) && f !== "ik_") {
      // ik_ prefix check is stricter
      if (f === "password" && !/"password"/i.test(json)) continue;
      if (json.toLowerCase().includes(f.toLowerCase())) {
        throw new Error(`lab payload leaked secret-shaped content: ${f}`);
      }
    }
  }
  if (/(?:^|[^a-z])ik_[a-z0-9_-]{8,}/i.test(json)) {
    throw new Error("lab payload leaked ik_ material");
  }
  if (/(?:^|[^a-z])sh_[a-z0-9_-]{8,}/i.test(json)) {
    throw new Error("lab payload leaked sh_ material");
  }
}
