// The three push-API calls, over the frozen gateway form-body codec.
//
// Deliberately NOT routed through node-core's `readGatewayAction`: that path records every
// exchange into `gateway_observations`, which is the money-path observation ledger used to
// verify chain state. The push API is a different host (wallet.zucoins.com) and its
// responses are not chain evidence — writing them into that ledger would pollute the very
// record settlement reasons over. The request BYTES still come from the frozen codec
// (`v=<encodeURIComponent(JSON.stringify({action_name, action_data}))>`), so
// the wire format cannot drift from every other producer.
//
// Bounded retry with jitter + exponential backoff per the push retry policy. All three actions are typed as
// `GatewayReadActionName` (node-core's read-safe union) and re-checked at runtime via
// `assertReadSafeActionName` before the request is built — the same primary type-level
// guarantee plus the same fail-closed backstop `packages/node-core/src/gateway/read.ts`
// uses, so a submit action can never reach this path even via a future refactor that
// widens `call`'s parameter (the never-blind-retry rule).

import {
  assertReadSafeActionName,
  buildGatewayActionRequest,
  decodeTolerantBase64,
  type GatewayReadActionName,
  type PushGatewayActions,
} from "@zucoins/node-core";

/** Envelope every push-API action returns. */
interface PushEnvelope {
  readonly status?: boolean;
  readonly code?: string;
  readonly message?: string;
  readonly data?: unknown;
}

export class PushGatewayRejectedError extends Error {
  readonly code = "push_gateway_rejected";
  constructor(action: string, readonly gatewayCode: string) {
    // Only the envelope code — never the id-proof, subscription keys or a transfer code.
    super(`push action ${action} rejected by gateway (code=${gatewayCode})`);
    this.name = "PushGatewayRejectedError";
  }
}

export class PushGatewayUnavailableError extends Error {
  readonly code = "push_gateway_unavailable";
  constructor(action: string, attempts: number, lastError: string) {
    super(`push action ${action} failed after ${attempts} attempts: ${lastError}`);
    this.name = "PushGatewayUnavailableError";
  }
}

// The push host dispatches on exact suffixed action names (opaque per-action tokens
// transcribed from the wallet bundle — see READ_SAFE_ACTION_NAMES). When a wallet
// release rotates them, the host answers an UNKNOWN name with HTTP 200 and
// {"status":false,"code":"oysinkh3cy","message":'…Unsupported "action_name"…'} — the
// same 200/status:false shape as a legitimate negative answer (live probe 2026-08-08,
// ZTR-1152). Without this classification that rejection degrades into `false` on
// hasSubscriptionForPublicKey (a re-subscribe storm) or a generic transport-flavoured
// error, and the operator debugs the network while the defect is the vocabulary. This
// error is DISTINCT and never folded into PushGatewayUnavailableError.
export class PushActionVocabularyRejectedError extends Error {
  readonly code = "push_action_vocabulary_rejected";
  constructor(action: string, readonly gatewayCode: string) {
    super(
      `push action ${action} is not in the push host's dispatch vocabulary ` +
        `(code=${gatewayCode}) — wallet-release action-name drift, not an outage; ` +
        `re-transcribe the suffixed literals from the current wallet bundle`,
    );
    this.name = "PushActionVocabularyRejectedError";
  }
}

// Vocabulary rejection is recognised by the host's message text (semantic, stable
// phrasing) with the observed envelope code as a secondary signal — the code looks like
// another opaque token and may itself rotate. Transcribed from the live probe
// 2026-08-08 (ZTR-1152 evidence comment).
function isActionVocabularyRejection(envelope: PushEnvelope): boolean {
  if (envelope.status === true) return false;
  const message = envelope.message ?? "";
  return message.includes('Unsupported "action_name"') || envelope.code === "oysinkh3cy";
}

export interface PushGatewayOptions {
  /** Push API base, e.g. `https://wallet.zucoins.com/api__v1/`. */
  readonly pushApiBase: string;
  readonly maxAttempts?: number;
  readonly baseDelayMs?: number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly jitter?: () => number;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_BASE_DELAY_MS = 200;
const DEFAULT_TIMEOUT_MS = 10_000;

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

export function createPushGatewayActions(options: PushGatewayOptions): PushGatewayActions {
  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const baseDelayMs = options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
  const sleep = options.sleep ?? defaultSleep;
  const jitter = options.jitter ?? Math.random;
  const doFetch = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const base = options.pushApiBase.replace(/\/+$/u, "");

  // Cache: the app-server VAPID public key is stable gateway-side; re-fetching it on
  // every provision/reconcile pass would be a retry-storm-sized waste for a value that
  // only changes on a gateway key rotation (rare, and any node holding a stale copy just
  // fails VAPID verification downstream until the next boot reconcile refreshes it).
  let cachedAppServerKey: string | null = null;

  async function call(actionName: GatewayReadActionName, actionData: unknown): Promise<PushEnvelope> {
    // Defence in depth: the primary guarantee is that only the three literals below are
    // ever passed in (this function is not exported), matching node-core's own read.ts,
    // which runs the identical guard before touching any endpoint.
    assertReadSafeActionName(actionName);

    // Frozen codec — identical bytes to every other gateway action producer.
    const request = buildGatewayActionRequest(actionName, actionData);
    let lastError = "unknown";

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await doFetch(base, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: Buffer.from(request.bodyBytes),
          signal: controller.signal,
        });
        const text = await res.text();
        if (!res.ok) {
          lastError = `http ${res.status}`;
        } else {
          let envelope: PushEnvelope | undefined;
          try {
            envelope = JSON.parse(text) as PushEnvelope;
          } catch {
            lastError = "malformed envelope";
          }
          if (envelope !== undefined) {
            // A vocabulary rejection is deterministic — the same name gets the same
            // refusal on every attempt — so it must escape the retry loop as its own
            // named error, never burn attempts, and never fold into
            // PushGatewayUnavailableError.
            if (isActionVocabularyRejection(envelope)) {
              throw new PushActionVocabularyRejectedError(actionName, envelope.code ?? "unknown");
            }
            return envelope;
          }
        }
      } catch (err) {
        if (err instanceof PushActionVocabularyRejectedError) {
          throw err;
        }
        lastError = err instanceof Error ? err.message : String(err);
      } finally {
        clearTimeout(timer);
      }

      if (attempt < maxAttempts) {
        const backoff = baseDelayMs * 2 ** (attempt - 1);
        await sleep(Math.floor(backoff * (0.5 + jitter() * 0.5)));
      }
    }
    throw new PushGatewayUnavailableError(actionName, maxAttempts, lastError);
  }

  return {
    async subscribe(input) {
      // Wallet 200.6 app.js:4841 — suffixed literal transcribed verbatim (ZTR-1152).
      const res = await call("push_notification__subscribe__v1__tos2d5b5md", {
        id_proof__url_query: input.idProofQuery,
        subscription: {
          endpoint: input.endpoint,
          key_p256dh: input.keyP256dh,
          key_auth: input.keyAuth,
        },
      });
      // A `status:false` envelope is an application-layer REJECTION delivered over a 200.
      // Without this check a rejected subscribe would resolve as success and the row would
      // be marked ACTIVE with no remote subscription — fail-open, exactly what the
      // external-operation gate must never be told.
      if (res.status !== true) {
        throw new PushGatewayRejectedError("subscribe", res.code ?? "unknown");
      }
    },

    async hasSubscriptionForPublicKey(walletPublicKey) {
      // The SUBSCRIBED signal is the envelope `status` boolean, NOT any `data` field:
      // `data` is an empty array both when subscribed and when not, so reading
      // `data.has_subscription` yields undefined → always false → a re-subscribe storm
      // against the push rate limiter on every pass.
      // Wallet 200.6 main.js:8866 — suffixed literal transcribed verbatim (ZTR-1152).
      const res = await call(
        "push_notification__has_subscription_for_public_key_base64urlsafe__v1__jxqlqcj5zv",
        { wallet_key_public__base64urlsafe: walletPublicKey },
      );
      return res.status === true;
    },

    async getAppServerPublicKey() {
      if (cachedAppServerKey !== null) {
        return cachedAppServerKey;
      }

      // Wallet 200.6 app.js:4222 — suffixed literal transcribed verbatim (ZTR-1152).
      const res = await call("push_notification__get_app_server_public_key__v1__nozleh4wul", {});
      const data = res.data;
      if (typeof data !== "object" || data === null) {
        throw new PushGatewayRejectedError("get_app_server_public_key", res.code ?? "unknown");
      }
      // The field is `key_public__base64urlsafenopad` and is base64 but NOT
      // actually urlsafe despite the name. Validated tolerantly here so a corrupt or
      // truncated gateway response fails closed now rather than at whatever eventually
      // consumes the cached key; the raw string is what's returned/cached/stored, since
      // VAPID verification decodes it again itself (RFC 8292, `PushGatewayActions` returns
      // `Promise<string>`).
      const key = (data as Record<string, unknown>).key_public__base64urlsafenopad;
      if (typeof key !== "string" || key.length === 0) {
        throw new PushGatewayRejectedError("get_app_server_public_key", res.code ?? "unknown");
      }
      if (decodeTolerantBase64(key).length === 0) {
        throw new PushGatewayRejectedError("get_app_server_public_key", res.code ?? "unknown");
      }

      cachedAppServerKey = key;
      return key;
    },
  };
}

// Fixed valid-shape probe key: 32 zero bytes, padded base64url (44 chars). The host
// treats an unknown wallet key as a legitimate query ("No active subscriptions found"),
// so the probe is a pure read that binds to nothing.
export const PUSH_VOCABULARY_PROBE_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/**
 * One smoke call proving the push host still dispatches our (wallet-transcribed,
 * opaque-suffixed) action names — ZTR-1152 Option B. Called from the boot lane's
 * gateway-read region, NEVER from `createPushGatewayActions` (the factory stays
 * side-effect-free).
 *
 * Only vocabulary drift propagates (`PushActionVocabularyRejectedError`, deterministic,
 * named, actionable). Plain unavailability logs and returns: push-host availability has
 * never gated boot — the boot reconcile and periodic pass repair an outage later.
 */
export async function probePushActionVocabulary(
  gateway: Pick<PushGatewayActions, "hasSubscriptionForPublicKey">,
  logger: { info(message: string): void; error(message: string, err?: unknown): void },
): Promise<void> {
  try {
    await gateway.hasSubscriptionForPublicKey(PUSH_VOCABULARY_PROBE_KEY);
    logger.info("push: action-vocabulary probe accepted by the push host");
  } catch (err) {
    if (err instanceof PushActionVocabularyRejectedError) {
      throw err;
    }
    logger.error(
      "push: action-vocabulary probe could not reach the push host — proceeding (availability, not vocabulary)",
      err,
    );
  }
}
