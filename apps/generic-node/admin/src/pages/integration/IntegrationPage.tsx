// issue-time, copy-paste Connect handoff for the full RECEIVE_EXTERNAL path.
// The ik_ secret is consumed once from an in-memory handoff into volatile React state.
// No URL/history state, Web Storage, logging, network call, or later key lookup is used.
// Reporting private seeds never enter this page or the kit generator.

import { useCallback, useMemo, useState } from "react";
import { Link } from "react-router";
import { consumeIssuedIntegrationKey } from "../../lib/integration-handoff.js";
import {
  THREE_OPS_COMPOSITION_COPY,
  buildPackGuideText,
  isPackEnabled,
  kitSlotsForPacks,
  loadEnabledPacks,
  packDefinition,
  saveEnabledPacks,
  togglePack,
  type TogglePackId,
  PACK_DEFINITIONS,
  type KitGeneratorId,
} from "../../lib/packs.js";

export function safeNodeBaseUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Enter a valid node URL.");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Node URL must use HTTP or HTTPS.");
  }
  return url.origin;
}

function jsString(value: string): string {
  // Keep generated source inert even if a surprising origin/key is pasted into HTML later.
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

/**
 * Build the downloadable Connect kit.
 *
 * Secrets: only the one-time implementer bearer (`ik_…`) may appear, and only inside the
 * merchant-server receive.mjs section. Reporting private seeds are never accepted as
 * arguments and must never be serialized here (operators copy them from Reporting once).
 */
export function buildIntegrationKit(nodeBaseUrl: string, implementerKey: string): string {
  const base = safeNodeBaseUrl(nodeBaseUrl);
  if (!/^ik_[A-Za-z0-9_-]+$/.test(implementerKey)) {
    throw new Error("The one-time implementer key is not valid.");
  }

  return `ZU NODE CONNECT KIT — FULL RECEIVE PATH
========================================

GIVE THIS TO YOUR WEB DEVELOPER
-------------------------------
This kit walks the complete Incoming (RECEIVE_EXTERNAL) path end-to-end. Keep IMPLEMENTER_API_KEY
and the reporting private seed in server environment/config only.
NEVER ship IMPLEMENTER_API_KEY to browser code, HTML, analytics, logs, source control,
or a client-side environment variable. Same rule for reporting private seeds and sh_
handles.

WAKE ≠ PROOF (read this twice)
------------------------------
A node lifecycle SSE event, webhook, or status poll is a WAKE-UP SIGNAL only. It is
NOT proof of payment, NOT permission to fulfil an order, and NOT a substitute for
independent chain observation. Fulfil only after your own verifier reaches a terminal
verdict, then call verification-complete so the node can unpin the receiver wallet.
Skip verification-complete and the wallet pool drains (receiver stays PINNED).

PREREQUISITES (operator UI — do these once before coding)
---------------------------------------------------------
1. Keys page (/api-keys): issue an implementer bearer (ik_…). You are holding one now.
2. Reporting page (/reporting-keys): issue an ACTIVE reporting credential. Copy the
   private seed ONCE into server-only secret storage. The node keeps only the public half.
3. Recovery ceremony must have stamped recovery_verified_at on pool wallets or
   receives stay CREATED with NO_ELIGIBLE_WALLET.
4. Pin node identity independently of any hosted platform (see DISCOVERY PIN below).

FULL RECEIVE PATH (8 steps)
---------------------------
1. POST /v1/receives with implementer bearer (ik_…) — SERVER-SIDE ONLY.
2. Wait until operation state is READY and code_status is AWAITING_ARM
   (poll GET /v1/receives/:id or same-origin SSE wake — wake ≠ proof).
3. ARM with a reporting-signed POST /v1/operations/:id/armed (zp-report-request-v1
   five headers). Success releases transfer_code and sets code_status=RELEASED.
4. Handle transfer_code on the trusted server only. Customer instruction UI is yours:
   show amount, receiver pubkey, transfer code, and expiry from verified material —
   never embed spend authority or ik_/reporting seeds in the browser.
5. Discovery pin checklist + GET /.well-known/zupay-node (below).
6. Optional SSE/wake for UX only — wake ≠ proof.
7. Independent verify via in-repo consumer packages (below).
8. POST /v1/operations/:id/verification-complete (proof-backed, reporting-signed)
   → unpins the receiver wallet. Failure modes below.

NODE BASE URL
-------------
${base}

IN-REPO PACKAGES (do not reinvent signing or verification)
----------------------------------------------------------
- @zucoins/generic-node-consumer
    createReceive / getReceive (implementer bearer)
    buildSignedReportingHeaders (five X-ZP-Reporting-* headers, byte-exact)
    getVerificationMaterial / postVerificationComplete
    observation pipeline helpers (verify independently, then ack)
- @zucoins/consumer-example
    worked end-to-end composition + lying-node fixtures
    verifyReceiveInstructionOrigin (merchant-controlled instruction surface)
- @zucoins/merchant-adapter
    merchant-facing adapter patterns over the same contracts

MERCHANT SERVER FILE — receive.mjs (Node 22+)
---------------------------------------------
// STEP 1 — POST /v1/receives must run on your server, never in customer browser code.
const NODE_BASE_URL = ${jsString(base)};
const IMPLEMENTER_API_KEY = ${jsString(implementerKey)}; // move to server secret storage now

export async function createReceive({
  amountZkz,
  orderId,
  idempotencyKey,
  saveSubscriptionHandle,
}) {
  const response = await fetch(\`\${NODE_BASE_URL}/v1/receives\`, {
    method: "POST",
    headers: {
      Authorization: \`Bearer \${IMPLEMENTER_API_KEY}\`,
      "Content-Type": "application/json; charset=utf-8",
      "Idempotency-Key": idempotencyKey, // persist and reuse for this logical receive
    },
    body: JSON.stringify({
      amount_zkz: amountZkz,       // canonical positive decimal string (ZKZ)
      anchor: orderId,             // 1–96 chars: A-Z, a-z, 0-9, _ or -
      expires_in_seconds: 300,
      after_landing: { kind: "HOLD", destination_id: null },
    }),
  });

  if (!response.ok) throw new Error(\`Node receive failed (\${response.status})\`);
  const created = await response.json(); // 201 ready-ish or 202 queued
  const operationId = created.operation.operation_id;

  // Persist encrypted/server-side and bind lookup to this merchant order/customer.
  await saveSubscriptionHandle(operationId, created.subscription_handle);
  return { operationId }; // the browser never receives the sh_ handle
}

// STEP 2 — Wait READY + AWAITING_ARM (transfer_code is withheld until ARM).
// Prefer GET /v1/receives/:id with the implementer bearer. SSE is optional UX only.
export async function waitUntilArmable(operationId, { pollMs = 1000, maxMs = 120_000 } = {}) {
  const started = Date.now();
  for (;;) {
    const response = await fetch(\`\${NODE_BASE_URL}/v1/receives/\${operationId}\`, {
      headers: { Authorization: \`Bearer \${IMPLEMENTER_API_KEY}\` },
    });
    if (!response.ok) throw new Error(\`receive read failed (\${response.status})\`);
    const body = await response.json();
    const state = body.operation?.state;
    const codeStatus = body.code_status;
    // GET never returns plaintext transfer_code — only ARM does.
    if (state === "READY" && codeStatus === "AWAITING_ARM" && body.t0) {
      return {
        operationId,
        rowVersion: body.operation.row_version,
        t0: body.t0,
        receiverPubkey: body.receiver_pubkey,
        amountZkz: body.operation.amount_zkz,
        expiresAt: body.expires_at,
        expectedArtifact: body.expected_artifact,
      };
    }
    if (Date.now() - started > maxMs) {
      throw new Error(\`timeout waiting READY/AWAITING_ARM (state=\${state} code=\${codeStatus})\`);
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

MERCHANT SERVER FILE — arm-and-code.mjs (Node 22+)
-------------------------------------------------
// STEP 3 — ARM is REPORTING-SIGNED (not the implementer bearer).
// Use @zucoins/generic-node-consumer buildSignedReportingHeaders so zp-report-request-v1
// preimage bytes stay byte-exact. Never paste a reporting private seed
// into this kit, a browser bundle, or source control.
//
// Required reporting headers:
//   X-ZP-Reporting-Key-Id
//   X-ZP-Reporting-Timestamp
//   X-ZP-Reporting-Expires-At   (or window implied by timestamp pair — use the consumer helper)
//   X-ZP-Reporting-Nonce
//   X-ZP-Reporting-Signature
// Companion: Idempotency-Key (required on ARM), Content-Type application/json.
//
// ArmBody (strict):
// {
//   "expected_row_version": <number from READY read>,
//   "t0": {
//     "observation_id": "<uuid from READY.t0>",
//     "projection": { "s": "...", "p": "...", "b_zkz": "..." }
//   },
//   "opened_cursor": "<decimal implementer event cursor your consumer has opened through>"
// }
//
// opened_cursor is YOUR consumer watermark (from GET /v1/events), not invented.
// Prefer the consumer package rather than hand-rolling headers.

import { buildSignedReportingHeaders } from "@zucoins/generic-node-consumer";
// credential = { nodeId, implementerId, keyId, signer } — seed stays in your KMS/HSM.
const NODE_BASE_URL = ${jsString(base)};

export async function armReceive({
  operationId,
  expectedRowVersion,
  t0,
  openedCursor,
  idempotencyKey,
  credential,
  nodeBaseUrl = NODE_BASE_URL,
}) {
  const rawTarget = \`/v1/operations/\${operationId}/armed\`;
  const bodyObject = {
    expected_row_version: expectedRowVersion,
    t0,
    opened_cursor: openedCursor,
  };
  // Byte-exact JSON.stringify — do not reorder keys after hashing/signing.
  const bodyText = JSON.stringify(bodyObject);
  const bodyBytes = new TextEncoder().encode(bodyText);
  const headers = await buildSignedReportingHeaders({
    credential,
    method: "POST",
    rawTarget,
    bodyBytes,
  });
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("idempotency-key", idempotencyKey);

  const response = await fetch(\`\${nodeBaseUrl}\${rawTarget}\`, {
    method: "POST",
    headers,
    body: bodyText,
  });
  if (!response.ok) throw new Error(\`ARM failed (\${response.status})\`);
  const armed = await response.json();
  // armed.code_status === "RELEASED"
  // armed.transfer_code — PLAINTEXT, one-time release. Handle server-side only.
  // armed.transfer_code_sha256 — safe for logs/evidence; never log plaintext code.
  return armed;
}

// STEP 4 — transfer_code handling (trusted server only).
// Customer instruction UI is implementer-owned. Show:
//   - exact amount (ZKZ)
//   - receiver public key
//   - transfer_code
//   - expiry
// Prefer verifyReceiveInstructionOrigin (@zucoins/consumer-example) so a compromised
// relay cannot substitute amount/receiver. Never put transfer_code into a CDN-hosted
// JS bundle as a constant; serve it from your origin after session auth.

export async function presentPayInstruction({ armed, armable, customerSession }) {
  assertCustomerMaySee(customerSession, armable.operationId);
  return {
    amount_zkz: armable.amountZkz,
    receiver_pubkey: armable.receiverPubkey,
    transfer_code: armed.transfer_code,
    expires_at: armed.expires_at ?? armable.expiresAt,
    // Do NOT include ik_, reporting seed, sh_, or node admin cookies.
  };
}

MERCHANT SERVER FILE — status-proxy.mjs (Node 22+)
-------------------------------------------------
// STEP 6 — Optional UX wake. WAKE ≠ PROOF.
const NODE_BASE_URL = ${jsString(base)};

// Mount this handler at GET /api/receive-status/:operationId on the merchant origin.
// Authenticate the customer and authorize access to the operation before calling it.
export async function proxyReceiveStatus({
  request,
  response,
  operationId,
  loadSubscriptionHandle,
}) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(operationId)) {
    response.writeHead(400).end();
    return;
  }

  // Server-only lookup; never accept sh_ from a query string, cookie, or browser body.
  const subscriptionHandle = await loadSubscriptionHandle(operationId);
  if (!subscriptionHandle) {
    response.writeHead(404).end();
    return;
  }

  const abort = new AbortController();
  response.once("close", () => abort.abort());
  const upstream = await fetch(
    \`\${NODE_BASE_URL}/v1/operations/\${operationId}/subscribe\`,
    {
      headers: {
        Accept: "text/event-stream",
        Authorization: \`Bearer \${subscriptionHandle}\`,
      },
      signal: abort.signal,
    },
  );

  if (!upstream.ok || !upstream.body) {
    response.writeHead(502).end(); // do not relay node auth details to the customer
    return;
  }

  response.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });

  try {
    for await (const chunk of upstream.body) response.write(chunk);
  } finally {
    response.end();
  }
}

CUSTOMER BROWSER FILE — customer-status.js
------------------------------------------
// Same-origin EventSource: no node origin, CORS preflight, Authorization header, or sh_.
// On lifecycle events: refresh YOUR server-side verification job. Do not fulfil here.
export function subscribeToReceiveStatus({ operationId, onStatus, onError }) {
  const source = new EventSource(
    \`/api/receive-status/\${encodeURIComponent(operationId)}\`,
  );

  source.addEventListener("operation.lifecycle", (event) => {
    onStatus(JSON.parse(event.data)); // apply idempotently by row_version — wake only
  });
  source.addEventListener("error", (event) => onError?.(event));

  // EventSource reconnects automatically and sends Last-Event-ID to this merchant endpoint.
  // Section 8.4 has no durable cursor: the proxy intentionally opens a fresh node stream,
  // whose fresh upstream stream replays current state. Duplicate row_version is harmless.
  return () => source.close();
}

DISCOVERY PIN CHECKLIST
-----------------------
GET ${base}/.well-known/zupay-node  (public)

1. Fetch discovery over a channel the hosted platform cannot replace (operator export,
   signed release artifact, or a pin you control). Do not trust platform-relayed pins alone.
2. Record and pin: node_id, template_version, and the node identity public key material
   the document advertises.
3. Re-check the pin on every deploy / key rotation. A rotated identity without an
   intentional pin update is a hard fail — do not silently accept a new key.
4. Before showing pay instructions, verify the node-signed expected artifact against
   YOUR pin (see verifyReceiveInstructionOrigin in @zucoins/consumer-example).
5. Hosted ZuPayments may relay data; it must never be the only code that establishes
   or replaces the pin.

INDEPENDENT VERIFY (step 7) — then VERIFICATION-COMPLETE (step 8)
-----------------------------------------------------------------
Server-side only. Prefer the installable pipeline:

  import {
    getVerificationMaterial,
    postVerificationComplete,
    buildSignedReportingHeaders,
  } from "@zucoins/generic-node-consumer";
  // plus observation pipeline helpers from the same package / @zucoins/consumer-example

Flow:
  a. On wake (SSE or poll), do NOT fulfil.
  b. GET /v1/operations/:id/verification-material (reporting-signed).
  c. Observe the chain yourself (configured gateway) — never trust node claims alone.
  d. Run the consumer verifier to a terminal verdict (VERIFIED | REJECTED | INDETERMINATE).
  e. POST /v1/operations/:id/verification-complete with:
       {
         "expected_row_version": <number>,
         "consumed_cursor": "<your decimal watermark>",
         "verdict": "VERIFIED" | "REJECTED" | "INDETERMINATE",
         "wallet_evidence": [ /* proof-backed rows from material + your observation */ ]
       }
     + reporting five headers + Idempotency-Key.
  f. Success unpins the receiver wallet. Skip this and the pool drains.

Failure modes (do not invent success):
  - 401 unknown_reporting_key / missing headers → enrol ACTIVE reporting key first.
  - 409 verification_material_not_ready → wait; do not forge evidence.
  - 410 verification_material_expired → reopen / escalate; do not retry blind money.
  - 409 t0_mismatch / row_version conflict → re-read, never blind-retry with new body
    until you reconcile.
  - INDETERMINATE verdict → do not fulfil; keep evidence; operator attention.
  - Network timeout on verification-complete → reconcile via GET / read before re-POST
    with the SAME Idempotency-Key (never mint a second key for the same logical ack).

SECURITY HANDOFF CHECKLIST
--------------------------
1. Move the ik_ value into server-only secret storage, then close this page.
2. Issue/store an ACTIVE reporting private seed from /reporting-keys (never in this kit).
3. Never expose ik_, reporting private seeds, or sh_ in browser bundles, public env vars,
   URLs, logs, or analytics.
4. Send POST /v1/receives from the server with a stable per-request Idempotency-Key.
5. ARM and verification-complete are reporting-signed server routes — not browser calls.
6. Store sh_ server-side, authorize its operation lookup, and expose only same-origin SSE.
7. Give customer browser code only operation_id; never a node URL or Authorization header.
8. Pin the node identity independently of the hosted platform before trusting artifacts.
9. Treat node lifecycle status as a wake-up signal; verify settlement independently.
10. Always call verification-complete after a terminal independent verdict so wallets unpin.
11. Currency is ZKZ only — never "ZUC".
12. Never blind-retry a money or ack submit; reconcile first (get_transaction / point read).
`;
}

function downloadText(filename: string, text: string): void {
  const objectUrl = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(objectUrl);
}

export function IntegrationPage() {
  const [issuedKey] = useState(consumeIssuedIntegrationKey);
  const [copyStatus, setCopyStatus] = useState("");
  const [guideStatus, setGuideStatus] = useState("");
  const [enabledPacks, setEnabledPacks] = useState(() => {
    const stored = [...loadEnabledPacks()];
    // Keys → "Build Connect kit" handoff: enable Pack M so the kit is not gated away.
    if (issuedKey !== null && !stored.includes("M")) {
      const next = [...stored, "M" as const];
      saveEnabledPacks(next);
      return next;
    }
    return stored;
  });
  const nodeBaseUrl = useMemo(() => safeNodeBaseUrl(window.location.origin), []);
  const kit = useMemo(
    () => (issuedKey === null ? null : buildIntegrationKit(nodeBaseUrl, issuedKey)),
    [issuedKey, nodeBaseUrl],
  );
  const kitSlots = useMemo(() => kitSlotsForPacks(enabledPacks), [enabledPacks]);
  const packMOn = isPackEnabled(enabledPacks, "M");

  const onTogglePack = useCallback((id: TogglePackId, on: boolean) => {
    setEnabledPacks((prev) => {
      const next = [...togglePack(prev, id, on)];
      saveEnabledPacks(next);
      return next;
    });
  }, []);

  const copyGuide = useCallback(
    (slotId: KitGeneratorId) => {
      const body = buildPackGuideText(slotId, nodeBaseUrl);
      if (!body) {
        setGuideStatus("This slot uses the Connect kit below (issue an implementer key first).");
        return;
      }
      void navigator.clipboard.writeText(body).then(
        () => setGuideStatus("Guide copied"),
        () => {
          downloadText(`zu-node-pack-${slotId}.txt`, body);
          setGuideStatus("Download started");
        },
      );
    },
    [nodeBaseUrl],
  );

  return (
    <div className="page integration-page">
      <div className="page-title-row">
        <div>
          <h1>Connect</h1>
          <p className="muted">
            Enablement packs, checklists, and kit slots — compositions of the same three money ops.
            Pack M also drives the full Incoming (RECEIVE) handoff kit.
          </p>
        </div>
      </div>

      <section
        className="card integration-handoff"
        aria-labelledby="connect-packs-heading"
        data-testid="connect-packs"
      >
        <h2 id="connect-packs-heading">Packs</h2>
        <p className="muted" data-testid="three-ops-composition">
          {THREE_OPS_COMPOSITION_COPY}
        </p>
        <ul className="pack-card-list" style={{ listStyle: "none", margin: "12px 0 0", padding: 0, display: "grid", gap: 12 }}>
          {PACK_DEFINITIONS.map((pack) => {
            const on = isPackEnabled(enabledPacks, pack.id);
            const def = packDefinition(pack.id);
            return (
              <li
                key={pack.id}
                className="pack-card"
                data-testid={`pack-card-${pack.id}`}
                data-enabled={on ? "true" : "false"}
                style={{
                  border: "1px solid var(--border, #333)",
                  borderRadius: 8,
                  padding: 12,
                  display: "grid",
                  gap: 6,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
                  <strong>
                    Pack {pack.id} — {def.title}
                  </strong>
                  {pack.toggleable ? (
                    <label style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 13 }}>
                      <input
                        type="checkbox"
                        checked={on}
                        data-testid={`pack-toggle-${pack.id}`}
                        onChange={(e) => onTogglePack(pack.id as TogglePackId, e.target.checked)}
                      />
                      {on ? "On" : "Off"}
                    </label>
                  ) : (
                    <span className="tag muted" data-testid="pack-x-always-on">
                      Always on
                    </span>
                  )}
                </div>
                <p className="muted" style={{ margin: 0, fontSize: 13 }}>
                  {def.purpose}
                </p>
                {def.ops.length > 0 ? (
                  <p className="muted" style={{ margin: 0, fontSize: 12 }}>
                    Ops: {def.ops.join(" · ")}
                  </p>
                ) : (
                  <p className="muted" style={{ margin: 0, fontSize: 12 }}>
                    Ops: none forced — headless API / pin / verifier
                  </p>
                )}
              </li>
            );
          })}
        </ul>
        {enabledPacks.length === 0 ? (
          <p className="muted" style={{ marginTop: 12 }} data-testid="packs-x-default">
            No M/T/P packs enabled — headless (X) semantics only. Home gains pack checklist rows when you turn a pack on.
          </p>
        ) : null}
      </section>

      <section
        className="card integration-handoff"
        aria-labelledby="kit-slots-heading"
        data-testid="kit-generator-slots"
        style={{ marginTop: 16 }}
      >
        <h2 id="kit-slots-heading">Kit generators</h2>
        <p className="muted">
          Extension point for pack kits. Pack M reuses the issue-time Connect kit; other packs
          ship plain-language guides (no new money verbs).
        </p>
        <ul style={{ listStyle: "none", margin: "12px 0 0", padding: 0, display: "grid", gap: 10 }}>
          {kitSlots.map((slot) => (
            <li
              key={slot.id}
              data-testid={`kit-slot-${slot.id}`}
              style={{
                border: "1px solid var(--border, #333)",
                borderRadius: 8,
                padding: 12,
                display: "grid",
                gap: 6,
              }}
            >
              <strong>{slot.title}</strong>
              <p className="muted" style={{ margin: 0, fontSize: 13 }}>
                {slot.description}
              </p>
              {slot.usesConnectKit ? (
                <p className="muted" style={{ margin: 0, fontSize: 12 }}>
                  {packMOn
                    ? issuedKey
                      ? "Connect kit ready below (one-time ik_ in hand)."
                      : "Issue an implementer key on Keys, then Build Connect kit."
                    : "Enable Pack M to use this slot."}
                  {" "}
                  <Link to="/api-keys">Keys</Link>
                </p>
              ) : (
                <div className="integration-actions">
                  <button
                    type="button"
                    className="pill"
                    data-testid={`kit-copy-${slot.id}`}
                    onClick={() => copyGuide(slot.id)}
                  >
                    Copy guide
                  </button>
                  <button
                    type="button"
                    className="pill"
                    onClick={() => {
                      const body = buildPackGuideText(slot.id, nodeBaseUrl);
                      if (body) downloadText(`zu-node-pack-${slot.id}.txt`, body);
                    }}
                  >
                    Download
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
        {guideStatus ? (
          <p className="muted" role="status" style={{ marginTop: 8 }}>
            {guideStatus}
          </p>
        ) : null}
      </section>

      {packMOn ? (
      <section className="card integration-handoff" aria-labelledby="developer-handoff" style={{ marginTop: 16 }}>
        <h2 id="developer-handoff">Pack M — Give this to your web developer</h2>
        <p>
          The bundle covers server-side receive, reporting-signed ARM, server-side
          <code> transfer_code </code> handling, discovery pin, same-origin SSE wake, independent
          verify via <code>@zucoins/generic-node-consumer</code>, and proof-backed
          verification-complete so receiver wallets unpin. Wording fits any receiver accepting
          external value — not only storefronts.
        </p>
        <p className="callout wake-not-proof" role="note" data-testid="wake-not-proof">
          <strong>Wake ≠ proof.</strong> Node lifecycle events only wake your verification.
          They do not prove settlement or authorize fulfilment. Fulfil only after independent
          chain observation, then call verification-complete.
        </p>
      </section>
      ) : (
        <section className="card integration-handoff" style={{ marginTop: 16 }} data-testid="pack-m-kit-gated">
          <h2>Incoming Connect kit</h2>
          <p className="muted">
            Enable <strong>Pack M</strong> above to unlock the full Incoming (RECEIVE) kit path
            and Home checklist rows. Independent verify + verification-complete stay required
            whenever you accept external value.
          </p>
          <p className="callout wake-not-proof" role="note" data-testid="wake-not-proof">
            <strong>Wake ≠ proof.</strong> Node lifecycle events only wake your verification.
          </p>
        </section>
      )}

      {packMOn && kit === null ? (
        <div className="banner banner-error" role="alert" data-testid="connect-empty-funnel">
          <p>
            The plaintext implementer API key is only available immediately after issuing it. It
            cannot be recovered or rebuilt later.
          </p>
          <p>
            To generate a Connect kit you need both credentials:
          </p>
          <ol>
            <li>
              <Link to="/api-keys">Issue an implementer key</Link> on the Keys page, then choose
              &ldquo;Build Connect kit&rdquo; while the one-time secret is still on screen.
            </li>
            <li>
              <Link to="/reporting-keys">Issue an ACTIVE reporting key</Link> on the Reporting
              page and store its private seed in server-only secret storage (ARM and
              verification-complete require it). The seed is never embedded in this kit.
            </li>
          </ol>
        </div>
      ) : packMOn && kit !== null ? (
        <>
          <div className="banner" role="note">
            <strong>One-time secret:</strong> copy or download this now, move the <code>ik_</code>
            value to server-only secret storage, then close this page. The key is not saved in
            browser storage or history. Reporting private seeds are issued separately on{" "}
            <Link to="/reporting-keys">Reporting</Link> and never appear in this bundle.
          </div>
          <div className="integration-actions">
            <button
              type="button"
              className="pill primary"
              onClick={() => {
                void navigator.clipboard.writeText(kit).then(
                  () => setCopyStatus("Bundle copied"),
                  () => setCopyStatus("Copy failed — use Download bundle"),
                );
              }}
            >
              Copy bundle
            </button>
            <button
              type="button"
              className="pill"
              onClick={() => downloadText("zu-node-connect-kit.txt", kit)}
            >
              Download bundle
            </button>
            <span className="muted" role="status" aria-live="polite">
              {copyStatus}
            </span>
          </div>
          <pre className="integration-kit" data-testid="integration-kit" tabIndex={0}>
            <code>{kit}</code>
          </pre>
        </>
      ) : null}
    </div>
  );
}

export default IntegrationPage;
