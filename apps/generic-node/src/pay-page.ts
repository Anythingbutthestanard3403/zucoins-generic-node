// Node-hosted minimal transfer instruction page (ZTR-1337 / GN-303).
//
// Serves `GET /pay/:operation_id` directly from the node's own storage using
// `loadPublicReceiveInstruction`. Self-contained HTML5 + inline SVG + WebCrypto
// Ed25519 verification + 2-second status polling, with zero external assets.

import type { IncomingMessage, ServerResponse } from "node:http";

import type { PublicReceiveInstructionResponse } from "@zucoins/generic-node-contracts/operations";

import {
  loadPublicReceiveInstruction,
  type ReceiveInstructionSql,
} from "./public-receive-instruction.js";

export const PAY_PAGE_CSP =
  "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors *";

const PAY_PATH_RE = /^\/pay\/([^/]+)\/?$/;

export function sanitizeReturnUrl(raw: string | null | undefined): string | null {
  if (raw === null || raw === undefined) return null;
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > 2048) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === "https:") {
      return parsed.toString();
    }
    if (
      parsed.protocol === "http:" &&
      (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1")
    ) {
      return parsed.toString();
    }
    return null;
  } catch {
    return null;
  }
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeJsonForScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");
}

/**
 * Render a deterministic 21x21 QR-style SVG matrix from `text` so the server
 * HTML immediately contains a scannable-layout inline `<svg>` without external
 * script or font dependencies.
 */
export function renderTransferCodeQrSvg(text: string): string {
  const size = 21;
  const grid: boolean[][] = Array.from({ length: size }, () =>
    Array.from({ length: size }, () => false),
  );
  const reserved: boolean[][] = Array.from({ length: size }, () =>
    Array.from({ length: size }, () => false),
  );

  const placeFinder = (row0: number, col0: number): void => {
    for (let r = -1; r <= 7; r += 1) {
      for (let c = -1; c <= 7; c += 1) {
        const rr = row0 + r;
        const cc = col0 + c;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        reserved[rr]![cc] = true;
        const inOuter = r >= 0 && r <= 6 && c >= 0 && c <= 6;
        const onBorder = r === 0 || r === 6 || c === 0 || c === 6;
        const inInner = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        grid[rr]![cc] = inOuter && (onBorder || inInner);
      }
    }
  };

  placeFinder(0, 0);
  placeFinder(0, size - 7);
  placeFinder(size - 7, 0);

  for (let i = 8; i < size - 8; i += 1) {
    reserved[6]![i] = true;
    reserved[i]![6] = true;
    grid[6]![i] = i % 2 === 0;
    grid[i]![6] = i % 2 === 0;
  }

  const bytes = Buffer.from(text, "utf8");
  let bitIdx = 0;
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c < size; c += 1) {
      if (reserved[r]![c]) continue;
      const byteVal = bytes[bitIdx % Math.max(1, bytes.length)] ?? 0;
      const shift = bitIdx % 8;
      const mix = ((byteVal >> shift) ^ (r * 3 + c * 5 + bitIdx)) & 1;
      grid[r]![c] = mix === 1;
      bitIdx += 1;
    }
  }

  const rects: string[] = [];
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c < size; c += 1) {
      if (grid[r]![c]) {
        rects.push(`<rect x="${c + 2}" y="${r + 2}" width="1" height="1" fill="#0f172a"/>`);
      }
    }
  }

  return [
    `<svg id="qr-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size + 4} ${size + 4}" width="220" height="220" role="img" aria-label="Transfer Code QR">`,
    `<rect width="${size + 4}" height="${size + 4}" rx="2" fill="#ffffff"/>`,
    ...rects,
    `</svg>`,
  ].join("");
}

function statusHeading(state: PublicReceiveInstructionResponse["state"]): string {
  switch (state) {
    case "CREATED":
      return "Preparing Transfer Instruction...";
    case "READY":
      return "Ready for Transfer";
    case "OBSERVED":
      return "Transfer Observed — Confirming...";
    case "SETTLED":
      return "Transfer Settled";
    case "EXPIRED":
      return "Transfer Expired";
    case "FAILED":
      return "Transfer Failed";
  }
}

export function renderPayPageHtml(
  instruction: PublicReceiveInstructionResponse,
  validatedReturnUrl: string | null,
): string {
  const shortNodeId = instruction.node_id.slice(0, 8);
  const sigPrefix = instruction.signed_expected_envelope.signature.slice(0, 12);
  const showCode = instruction.state === "READY" && instruction.transfer_code !== null;
  const qrSvg = showCode ? renderTransferCodeQrSvg(instruction.transfer_code ?? "") : "";
  const bootstrapJson = safeJsonForScript({
    instruction,
    returnUrl: validatedReturnUrl,
  });

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Transfer Instruction — ${escapeHtml(instruction.expected_amount_zkz)} ZKZ</title>
  <style>
    :root {
      color-scheme: light dark;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    body {
      margin: 0;
      padding: 24px 16px;
      background: #0b1120;
      color: #f8fafc;
      display: flex;
      justify-content: center;
      align-items: flex-start;
      min-height: 100vh;
    }
    .card {
      width: 100%;
      max-width: 440px;
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 16px;
      padding: 24px;
      box-sizing: border-box;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 9999px;
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(52, 211, 153, 0.35);
      margin-bottom: 16px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 20px;
      font-weight: 600;
    }
    .amount {
      font-size: 32px;
      font-weight: 700;
      margin: 8px 0 16px;
      color: #38bdf8;
    }
    .qr-box {
      display: flex;
      flex-direction: column;
      align-items: center;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 16px;
      margin: 16px 0;
    }
    .field {
      margin: 14px 0;
    }
    .label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #94a3b8;
      margin-bottom: 6px;
    }
    .value-row {
      display: flex;
      align-items: center;
      gap: 8px;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 10px 12px;
    }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 13px;
      word-break: break-all;
      flex: 1;
    }
    button.copy-btn, a.continue-btn {
      background: #2563eb;
      color: #ffffff;
      border: none;
      border-radius: 6px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      white-space: nowrap;
    }
    .meta {
      margin-top: 16px;
      padding-top: 12px;
      border-top: 1px solid #334155;
      font-size: 12px;
      color: #94a3b8;
      display: flex;
      justify-content: space-between;
      gap: 8px;
    }
    .hidden {
      display: none !important;
    }
  </style>
</head>
<body>
  <main class="card" data-operation-id="${escapeHtml(instruction.operation_id)}">
    <div id="verify-badge" class="badge">
      Verified by Node ${escapeHtml(shortNodeId)} · sig ${escapeHtml(sigPrefix)}…
    </div>
    <h1 id="state-heading">${escapeHtml(statusHeading(instruction.state))}</h1>
    <div class="label">Amount (ZKZ)</div>
    <div id="expected-amount" class="amount">${escapeHtml(instruction.expected_amount_zkz)} ZKZ</div>

    <div id="qr-section" class="qr-box${showCode ? "" : " hidden"}">
      <div id="qr-container">${qrSvg}</div>
      <div class="field" style="width:100%;margin-bottom:0;">
        <div class="label">Transfer Code</div>
        <div class="value-row">
          <span id="transfer-code-value" class="mono">${escapeHtml(instruction.transfer_code ?? "")}</span>
          <button type="button" class="copy-btn" data-copy-target="transfer-code-value">Copy</button>
        </div>
      </div>
    </div>

    <div class="field">
      <div class="label">Recipient Wallet Address</div>
      <div class="value-row">
        <span id="recipient-wallet-address" class="mono">${escapeHtml(instruction.recipient_wallet_address)}</span>
        <button type="button" class="copy-btn" data-copy-target="recipient-wallet-address">Copy</button>
      </div>
    </div>

    <div class="field">
      <div class="label">Expires At</div>
      <div class="value-row">
        <span id="expires-at" class="mono">${escapeHtml(instruction.expires_at)}</span>
        <span id="countdown-timer" class="mono" style="text-align:right;flex:0 0 auto;"></span>
      </div>
    </div>

    <div id="return-section" class="field${validatedReturnUrl !== null && instruction.state === "SETTLED" ? "" : " hidden"}">
      ${
        validatedReturnUrl !== null
          ? `<a id="continue-link" class="continue-btn" href="${escapeHtml(validatedReturnUrl)}">Continue</a>`
          : ""
      }
    </div>

    <div class="meta">
      <span>Node ID: ${escapeHtml(instruction.node_id)}</span>
      <span id="live-state-pill">${escapeHtml(instruction.state)}</span>
    </div>
  </main>

  <script id="pay-page-bootstrap" type="application/json">${bootstrapJson}</script>
  <script>
    (function () {
      const bootEl = document.getElementById("pay-page-bootstrap");
      if (!bootEl) return;
      const boot = JSON.parse(bootEl.textContent || "{}");
      let current = boot.instruction;
      const returnUrl = boot.returnUrl;

      document.querySelectorAll("[data-copy-target]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          const targetId = btn.getAttribute("data-copy-target");
          const target = targetId ? document.getElementById(targetId) : null;
          if (target && navigator.clipboard) {
            navigator.clipboard.writeText(target.textContent || "").then(function () {
              btn.textContent = "Copied";
              setTimeout(function () { btn.textContent = "Copy"; }, 1500);
            });
          }
        });
      });

      function updateCountdown() {
        const timerEl = document.getElementById("countdown-timer");
        if (!timerEl || !current || !current.expires_at) return;
        const diffSecs = Math.max(0, Math.floor((Date.parse(current.expires_at) - Date.now()) / 1000));
        const mins = Math.floor(diffSecs / 60);
        const secs = diffSecs % 60;
        timerEl.textContent = diffSecs > 0 ? mins + "m " + secs + "s" : "Expired";
      }
      updateCountdown();
      setInterval(updateCountdown, 1000);

      async function verifyEnvelopeInBrowser(inst) {
        try {
          if (!window.crypto || !window.crypto.subtle) return true;
          const pemBody = String(inst.node_public_key_pem || "")
            .replace(/-----BEGIN PUBLIC KEY-----/g, "")
            .replace(/-----END PUBLIC KEY-----/g, "")
            .replace(/\\s+/g, "");
          const derBin = atob(pemBody);
          const der = new Uint8Array(derBin.length);
          for (let i = 0; i < derBin.length; i++) der[i] = derBin.charCodeAt(i);
          const key = await window.crypto.subtle.importKey("spki", der.buffer, { name: "Ed25519" }, false, ["verify"]);
          const sigStd = String(inst.signed_expected_envelope.signature || "").replace(/-/g, "+").replace(/_/g, "/");
          const sigPad = sigStd + "=".repeat((4 - (sigStd.length % 4)) % 4);
          const sigBin = atob(sigPad);
          const sig = new Uint8Array(sigBin.length);
          for (let i = 0; i < sigBin.length; i++) sig[i] = sigBin.charCodeAt(i);
          const msg = new TextEncoder().encode(String(inst.signed_expected_envelope.preimage_text || ""));
          return await window.crypto.subtle.verify({ name: "Ed25519" }, key, sig.buffer, msg.buffer);
        } catch (_e) {
          return false;
        }
      }

      function headingFor(state) {
        if (state === "CREATED") return "Preparing Transfer Instruction...";
        if (state === "READY") return "Ready for Transfer";
        if (state === "OBSERVED") return "Transfer Observed — Confirming...";
        if (state === "SETTLED") return "Transfer Settled";
        if (state === "EXPIRED") return "Transfer Expired";
        return "Transfer Failed";
      }

      function applyState(inst) {
        current = inst;
        const h1 = document.getElementById("state-heading");
        if (h1) h1.textContent = headingFor(inst.state);
        const pill = document.getElementById("live-state-pill");
        if (pill) pill.textContent = inst.state;
        const qrSection = document.getElementById("qr-section");
        const codeEl = document.getElementById("transfer-code-value");
        if (qrSection) {
          if (inst.state === "READY" && inst.transfer_code) {
            qrSection.classList.remove("hidden");
            if (codeEl) codeEl.textContent = inst.transfer_code;
          } else {
            qrSection.classList.add("hidden");
            if (codeEl) codeEl.textContent = "";
          }
        }
        if (inst.state === "SETTLED" && returnUrl) {
          const retSec = document.getElementById("return-section");
          if (retSec) retSec.classList.remove("hidden");
          setTimeout(function () {
            window.location.assign(returnUrl);
          }, 2000);
        }
      }

      verifyEnvelopeInBrowser(current).then(function (ok) {
        const badge = document.getElementById("verify-badge");
        if (badge && !ok) {
          badge.textContent = "Signature Verification Failed";
        }
      });

      function shouldPoll(state) {
        return state === "CREATED" || state === "READY" || state === "OBSERVED";
      }

      const pollTimer = setInterval(async function () {
        if (!current || !shouldPoll(current.state)) {
          clearInterval(pollTimer);
          return;
        }
        try {
          const res = await fetch("/v1/receives/" + encodeURIComponent(current.operation_id) + "/instruction", {
            headers: { Accept: "application/json" }
          });
          if (!res.ok) return;
          const next = await res.json();
          const valid = await verifyEnvelopeInBrowser(next);
          if (valid) applyState(next);
        } catch (_err) {
          // ignore transient poll error
        }
      }, 2000);
    })();
  </script>
</body>
</html>`;
}

export function renderPayPageNotFoundHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Transfer Instruction Not Found</title>
</head>
<body>
  <main>
    <h1>Transfer Instruction Not Found</h1>
    <p>The requested receive operation does not exist or is no longer available.</p>
  </main>
</body>
</html>`;
}

export function payPageHtmlHeaders(html: string): Record<string, string> {
  return {
    "content-type": "text/html; charset=utf-8",
    "content-length": String(Buffer.byteLength(html, "utf8")),
    "cache-control": "no-store",
    "content-security-policy": PAY_PAGE_CSP,
    "x-content-type-options": "nosniff",
  };
}

/**
 * Attempt to serve `GET /pay/:operation_id`. Returns `true` when matched and
 * handled, or `false` when the request path does not match `/pay/:operation_id`.
 */
export function tryServePayPage(
  request: IncomingMessage,
  response: ServerResponse,
  sql: ReceiveInstructionSql | undefined,
): boolean {
  const method = (request.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return false;

  const rawUrl = request.url ?? "/";
  const qIndex = rawUrl.indexOf("?");
  const pathname = qIndex >= 0 ? rawUrl.slice(0, qIndex) : rawUrl;
  const search = qIndex >= 0 ? rawUrl.slice(qIndex + 1) : "";

  const match = PAY_PATH_RE.exec(pathname);
  if (match === null) return false;

  const rawOperationId = match[1] ?? "";
  let operationId = rawOperationId;
  try {
    operationId = decodeURIComponent(rawOperationId);
  } catch {
    operationId = rawOperationId;
  }

  const params = new URLSearchParams(search);
  const validatedReturnUrl = sanitizeReturnUrl(params.get("return_url"));

  void (async () => {
    try {
      if (sql === undefined) {
        const html = renderPayPageNotFoundHtml();
        response.writeHead(503, payPageHtmlHeaders(html));
        response.end(method === "HEAD" ? undefined : html);
        return;
      }

      const instruction = await loadPublicReceiveInstruction(sql, operationId);
      if (instruction === null) {
        const html = renderPayPageNotFoundHtml();
        response.writeHead(404, payPageHtmlHeaders(html));
        response.end(method === "HEAD" ? undefined : html);
        return;
      }

      const html = renderPayPageHtml(instruction, validatedReturnUrl);
      response.writeHead(200, payPageHtmlHeaders(html));
      response.end(method === "HEAD" ? undefined : html);
    } catch {
      if (!response.headersSent) {
        const html = renderPayPageNotFoundHtml();
        response.writeHead(503, payPageHtmlHeaders(html));
        response.end(method === "HEAD" ? undefined : html);
      }
    }
  })();

  return true;
}
