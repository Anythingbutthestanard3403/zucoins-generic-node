// Optional operator Web Push for pending SEND / needs_attention.
//
// Hard separations from wallet receiver push (push_subscriptions):
// - Audience: admin operators / approver phones — never wallets/payers.
// - Store: operator_push_subscriptions (separate table / in-memory store).
// - Must NOT gate RECEIVE or any money path.
// - Opt-in only; deny/skip still full manual inbox.
// - Fail soft: push infra errors never block approve/inbox.
// - Payload: attention type + deep link + non-sensitive summary — no keys/TOTP/codes.

export const OPERATOR_PUSH_FORBIDDEN_PAYLOAD_KEYS = [
  "private_key",
  "privateKey",
  "secret",
  "seed",
  "totp",
  "totp_code",
  "transfer_code",
  "transfer_code_encoded",
  "master_key",
  "masterKey",
  "device_signature",
  "authorizing_signature",
  "preimage_text",
  "wallet_private_key",
  "auth_secret",
  "receiver_auth_secret",
  "receiver_ecdh_private",
] as const;

export type OperatorPushAttentionType =
  | "send_pending_approval"
  | "needs_attention";

export interface OperatorPushPayload {
  readonly attention_type: OperatorPushAttentionType;
  /** Node-origin path only, e.g. /transfers/<id> or /operations?filter=attention */
  readonly deep_link_path: string;
  /** Non-sensitive one-line summary (amount class, kind) — never secrets. */
  readonly summary: string;
  readonly operation_id?: string;
}

export interface OperatorPushSubscription {
  readonly id: string;
  readonly nodeId: string;
  readonly operatorId: string;
  /** Web Push endpoint URL (browser PushSubscription.endpoint). */
  readonly endpoint: string;
  /** p256dh public key (non-secret). */
  readonly p256dh: string;
  /**
   * Auth secret is retained only sealed / opaque at rest in SQL adapters.
   * In-memory tests may hold a placeholder token — never log it.
   */
  readonly authSealed: string;
  readonly createdAt: string;
  readonly userAgent: string | null;
}


/**
 * Web Push p256dh is an uncompressed P-256 public point (65 bytes: 0x04||X||Y)
 * encoded base64url (or standard base64). Auth is a 16-byte secret, same encoding.
 * Reject placeholder / fabricated material before it reaches the store (ZTR-1168).
 */
export function isValidOperatorPushP256dh(value: string): boolean {
  if (typeof value !== "string" || value.length < 40 || value.length > 200) return false;
  if (/pending|placeholder|example|test-only/i.test(value)) return false;
  const bytes = tryDecodeWebPushKey(value);
  return bytes !== null && bytes.length === 65 && bytes[0] === 0x04;
}

export function isValidOperatorPushAuth(value: string): boolean {
  if (typeof value !== "string" || value.length < 10 || value.length > 64) return false;
  if (/pending|placeholder|example|test-only/i.test(value)) return false;
  const bytes = tryDecodeWebPushKey(value);
  return bytes !== null && bytes.length === 16;
}

function tryDecodeWebPushKey(value: string): Buffer | null {
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
    const buf = Buffer.from(normalized + pad, "base64");
    return buf.length > 0 ? buf : null;
  } catch {
    return null;
  }
}

/** Stable short fingerprint of a full endpoint (matches list API truncation). */
export function operatorPushEndpointFingerprint(endpoint: string): string {
  return endpoint.slice(0, 48);
}

export interface OperatorPushSubscriptionStore {
  listByOperator(nodeId: string, operatorId: string): readonly OperatorPushSubscription[];
  listActiveByNode(nodeId: string): readonly OperatorPushSubscription[];
  upsert(row: OperatorPushSubscription): void;
  deleteByEndpoint(nodeId: string, operatorId: string, endpoint: string): boolean;
  /** Delete by the same fingerprint the list API returns (full endpoint is not listed). */
  deleteByEndpointFingerprint(nodeId: string, operatorId: string, fingerprint: string): boolean;
}

export class InMemoryOperatorPushSubscriptionStore implements OperatorPushSubscriptionStore {
  private readonly rows: OperatorPushSubscription[] = [];

  listByOperator(nodeId: string, operatorId: string): readonly OperatorPushSubscription[] {
    return this.rows.filter((r) => r.nodeId === nodeId && r.operatorId === operatorId);
  }

  listActiveByNode(nodeId: string): readonly OperatorPushSubscription[] {
    return this.rows.filter((r) => r.nodeId === nodeId);
  }

  upsert(row: OperatorPushSubscription): void {
    const idx = this.rows.findIndex(
      (r) => r.nodeId === row.nodeId && r.endpoint === row.endpoint,
    );
    if (idx >= 0) {
      this.rows[idx] = row;
    } else {
      this.rows.push(row);
    }
  }

  deleteByEndpoint(nodeId: string, operatorId: string, endpoint: string): boolean {
    const idx = this.rows.findIndex(
      (r) => r.nodeId === nodeId && r.operatorId === operatorId && r.endpoint === endpoint,
    );
    if (idx < 0) return false;
    this.rows.splice(idx, 1);
    return true;
  }

  deleteByEndpointFingerprint(nodeId: string, operatorId: string, fingerprint: string): boolean {
    const idx = this.rows.findIndex(
      (r) =>
        r.nodeId === nodeId &&
        r.operatorId === operatorId &&
        operatorPushEndpointFingerprint(r.endpoint) === fingerprint,
    );
    if (idx < 0) return false;
    this.rows.splice(idx, 1);
    return true;
  }
}

export function buildOperatorPushPayload(input: {
  readonly attentionType: OperatorPushAttentionType;
  readonly deepLinkPath: string;
  readonly summary: string;
  readonly operationId?: string;
}): OperatorPushPayload {
  const raw = input.deepLinkPath.trim();
  if (!raw.startsWith("/") || raw.startsWith("//") || /^https?:/i.test(raw)) {
    throw new Error("deep_link_path must be a root-relative path");
  }
  const payload: OperatorPushPayload = {
    attention_type: input.attentionType,
    deep_link_path: raw,
    summary: input.summary.slice(0, 200),
    ...(input.operationId !== undefined ? { operation_id: input.operationId } : {}),
  };
  assertOperatorPushPayloadSafe(payload);
  return payload;
}

/** Schema test target: rejects any secret-bearing field. */
export function assertOperatorPushPayloadSafe(payload: unknown): void {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new Error("operator push payload must be a plain object");
  }
  const obj = payload as Record<string, unknown>;
  const allowed = new Set(["attention_type", "deep_link_path", "summary", "operation_id"]);
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      throw new Error(`operator push payload forbids key: ${key}`);
    }
  }
  for (const forbidden of OPERATOR_PUSH_FORBIDDEN_PAYLOAD_KEYS) {
    if (forbidden in obj) {
      throw new Error(`operator push payload forbids secret field: ${forbidden}`);
    }
  }
  const blob = JSON.stringify(obj);
  for (const forbidden of OPERATOR_PUSH_FORBIDDEN_PAYLOAD_KEYS) {
    if (blob.toLowerCase().includes(forbidden.toLowerCase()) && forbidden !== "secret") {
      // "secret" substring is too broad; only exact keys above.
      continue;
    }
  }
  // Explicit secret-ish value patterns.
  if (/"totp"\s*:/i.test(blob) || /"transfer_code/i.test(blob) || /"private_key/i.test(blob)) {
    throw new Error("operator push payload must not embed secret material");
  }
  if (typeof obj.attention_type !== "string") {
    throw new Error("attention_type required");
  }
  if (typeof obj.deep_link_path !== "string" || !obj.deep_link_path.startsWith("/")) {
    throw new Error("deep_link_path must be a root-relative path");
  }
  if (typeof obj.summary !== "string") {
    throw new Error("summary required");
  }
}

export type OperatorPushDeliveryResult =
  | { readonly ok: true; readonly delivered: number; readonly failed: number }
  | { readonly ok: false; readonly soft: true; readonly detail: string };

export interface OperatorPushSender {
  /**
   * Deliver to one subscription. Must never throw into money paths —
   * implementors catch and return false.
   */
  send(sub: OperatorPushSubscription, payload: OperatorPushPayload): Promise<boolean>;
}

/** No-op sender — inbox remains source of truth. */
export const noopOperatorPushSender: OperatorPushSender = {
  async send() {
    return false;
  },
};

/**
 * Fan-out pending attention to all operator subscriptions on the node.
 * Fail-soft: errors become soft failures; callers must not block approve/inbox.
 */
export async function notifyOperatorsPendingAttention(
  deps: {
    readonly store: OperatorPushSubscriptionStore;
    readonly sender: OperatorPushSender;
    readonly nodeId: string;
  },
  payload: OperatorPushPayload,
): Promise<OperatorPushDeliveryResult> {
  try {
    assertOperatorPushPayloadSafe(payload);
    const subs = deps.store.listActiveByNode(deps.nodeId);
    let delivered = 0;
    let failed = 0;
    for (const sub of subs) {
      try {
        const ok = await deps.sender.send(sub, payload);
        if (ok) delivered += 1;
        else failed += 1;
      } catch {
        failed += 1;
      }
    }
    return { ok: true, delivered, failed };
  } catch (err) {
    return {
      ok: false,
      soft: true,
      detail: err instanceof Error ? err.message : "operator push failed",
    };
  }
}
