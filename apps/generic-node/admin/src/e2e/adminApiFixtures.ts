// Real-browser fixtures for the generic-node admin `/admin/v1/*` API.
// Every request is matched by method + exact pathname and receives the production wire
// shape consumed by the page. Unknown requests are recorded and fail the test instead of
// quietly becoming a 404/empty-state that could mask an uncovered workflow dependency.
import type { Page } from "@playwright/test";
import {
  OPERATION_INVENTORY_DETAIL_FIELDS,
  OPERATION_INVENTORY_LIST_FIELDS,
  type WalletInventoryItem,
} from "@zucoins/generic-node-contracts/admin-inventory";
import type { WalletKeyOrigin, WalletState } from "@zucoins/generic-node-contracts/custody";

export const E2E_WALLET_PUBKEY =
  "zkz1qe2emobilewalletpublickey0000000000000000000001";
export const E2E_OPERATION_ID = "operation-e2e-0000000000000001";
export const E2E_DESTINATION_ADDRESS = "zkz1qe2edestination00000000000000000000000001";

type SessionMode = "authenticated" | "anonymous" | "setup";

const SESSION = {
  userId: "u1",
  username: "operator",
  role: "admin",
  mustEnrolTotp: false,
  mustChangePassword: false,
  csrfToken: "csrf-e2e",
};

const SETUP_SESSION = {
  ...SESSION,
  mustChangePassword: true,
  mustEnrolTotp: true,
};

const NEEDS_ATTENTION = {
  operations: [],
  summary: { total: 0, by_classification: {}, p0_invariant_breach: 0 },
  has_more: false,
  next_cursor: null,
};

const KEY_ORIGIN_NODE: WalletKeyOrigin = "node_generated";

function walletFixture(
  partial: Partial<WalletInventoryItem> &
    Pick<WalletInventoryItem, "wallet_id" | "public_key" | "state">,
): WalletInventoryItem {
  return {
    node_id: "node-e2e-0000000000000000000001",
    key_origin: KEY_ORIGIN_NODE,
    created_at: "2026-07-30T00:00:00.000Z",
    retired_at: null,
    quarantine_reason: null,
    recovery_verified: true,
    recovery_verified_at: "2026-07-30T00:00:00.000Z",
    recovery_verification: null,
    observed_balance_zkz: "0.0000",
    holding_operation_id: null,
    holding_operation_status: null,
    holding_operation_expiry_unix_time_secs: null,
    holding_operation_attention_required: false,
    holding_operation_terminal_at: null,
    holding_lease_role: null,
    holding_operation_type: null,
    money_mode: "FULL",
    allow_external_receive: true,
    allow_external_send: true,
    allow_internal_move: true,
    row_version: 1,
    ...partial,
  };
}

/** AVAILABLE — idle free pool wallet (not busy). */
const WALLET: WalletInventoryItem = walletFixture({
  wallet_id: "wallet-e2e-0000000000000000000001",
  public_key: E2E_WALLET_PUBKEY,
  state: "AVAILABLE" satisfies WalletState,
  observed_balance_zkz: "1248.4200",
});

/** PINNED with active lease — hold cause must surface. */
const WALLET_PINNED: WalletInventoryItem = walletFixture({
  wallet_id: "wallet-e2e-pinned-0000000000000001",
  public_key: `${E2E_WALLET_PUBKEY.slice(0, -1)}3`,
  state: "PINNED" satisfies WalletState,
  observed_balance_zkz: "10.0000",
  holding_operation_id: "operation-e2e-hold-000000000001",
  holding_operation_status: "AWAITING_REDEMPTION",
  holding_operation_expiry_unix_time_secs: "9999999999",
  holding_operation_attention_required: false,
  holding_operation_terminal_at: null,
  holding_lease_role: "RECEIVE_WINDOW",
  holding_operation_type: "RECEIVE_EXTERNAL",
});

/** QUARANTINED — danger severity + reason text (ZTR-1255). */
const WALLET_QUARANTINED: WalletInventoryItem = walletFixture({
  wallet_id: "wallet-e2e-quarantined-0000000000001",
  public_key: `${E2E_WALLET_PUBKEY.slice(0, -1)}2`,
  state: "QUARANTINED" satisfies WalletState,
  quarantine_reason: "REGRESSION",
  observed_balance_zkz: "0.0000",
});

/** RETIRED — terminal custody standing. */
const WALLET_RETIRED: WalletInventoryItem = walletFixture({
  wallet_id: "wallet-e2e-retired-0000000000000001",
  public_key: `${E2E_WALLET_PUBKEY.slice(0, -1)}4`,
  state: "RETIRED" satisfies WalletState,
  retired_at: "2026-07-31T00:00:00.000Z",
  recovery_verified: false,
  recovery_verified_at: null,
  observed_balance_zkz: null,
});

const WALLETS_LIST = {
  object: "list",
  data: [WALLET, WALLET_PINNED, WALLET_QUARANTINED, WALLET_RETIRED],
  has_more: false,
  next_cursor: null,
};

/** Everything the node knows about the e2e operation, in wire vocabulary. */
const OPERATION_RECORD: Readonly<Record<string, unknown>> = {
  operation_id: E2E_OPERATION_ID,
  operation_type: "SEND_EXTERNAL",
  status: "CREATED",
  amount_zkz: "0.0100",
  row_version: 1,
  attention_required: false,
  attention_reason: null,
  created_at: "2026-07-30T00:00:00.000Z",
  updated_at: "2026-07-30T00:00:00.000Z",
  terminal_at: null,
  expiry_unix_time_secs: null,
  destination_address: E2E_DESTINATION_ADDRESS,
  source_wallet_id: "wallet-e2e-0000000000000000000001",
  receiver_wallet_id: null,
  destination_id: "destination-e2e-1",
  after_landing: null,
  after_landing_destination_id: null,
  formation_state: "NOT_REQUIRED",
  verification_verdict: "PENDING",
  implementer_id: "implementer-e2e-1",
  client_reference: null,
  verification_mode: "INDEPENDENT",
};

/**
 * Rows are projected through the node's own field allowlists rather than hand-listed here. A
 * field a projection stops carrying disappears from this payload too, so a screen reading it
 * goes red — a hand-written row is how a column the server never populated stayed green through
 * an entire e2e suite.
 */
function project(
  fields: readonly string[],
  record: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  const row: Record<string, unknown> = {};
  for (const field of fields) {
    if (!(field in record)) {
      throw new Error(`e2e operation fixture has no value for projected field "${field}"`);
    }
    row[field] = record[field];
  }
  return row;
}

const OPERATION = project(OPERATION_INVENTORY_LIST_FIELDS, OPERATION_RECORD);
const OPERATION_DETAIL = project(OPERATION_INVENTORY_DETAIL_FIELDS, OPERATION_RECORD);

const OPERATIONS_LIST = {
  object: "list",
  data: [OPERATION],
  has_more: false,
  next_cursor: null,
};

/** Pending CREATED send for Approve inbox — same row as OPERATION. */
const PENDING_SENDS_LIST = OPERATIONS_LIST;

const APPROVAL_CHALLENGE = {
  operation_id: E2E_OPERATION_ID,
  row_version: 1,
  purpose: "approve_external_send",
  canonical_version: 1,
  nonce: "nonce-e2e",
  preimage_text: "e2e approval preimage",
  preimage_sha256: "a".repeat(64),
  issued_at: "2026-07-30T00:00:00.000Z",
  expires_at: "2026-07-30T00:10:00.000Z",
  source_selector: { kind: "wallet_id", wallet_id: WALLET.wallet_id },
  source_pubkey: E2E_WALLET_PUBKEY,
  destination_address: E2E_DESTINATION_ADDRESS,
  amount_zkz: OPERATION_RECORD.amount_zkz,
  references_operation_id: null,
};

const RECOVERY = {
  operation_id: E2E_OPERATION_ID,
  operation_type: "SEND_EXTERNAL",
  status: "CREATED",
  attention_required: false,
  attention_reason: null,
  verification_mode: "INDEPENDENT",
  classification: "NONE",
  classification_rationale: "No recovery action required.",
  permitted_actions: [],
  held_leases: [],
  row_version: 1,
  lease_epoch: null,
  recovery_nonce: "recovery-nonce-e2e",
  recovery_nonce_issued_at: "2026-07-30T00:00:00.000Z",
  recovery_nonce_expires_at: "2026-07-30T00:10:00.000Z",
};

const DESTINATIONS_LIST = {
  object: "list",
  data: [
    {
      destination_id: "destination-e2e-1",
      wallet_id: WALLET.wallet_id,
      wallet_public_key: "zkz1qe2edestination00000000000000000000000001",
      state: "BLESSED",
      label: "E2E destination",
      blessed_at: "2026-07-30T00:00:00.000Z",
      retired_at: null,
      created_at: "2026-07-30T00:00:00.000Z",
      move_eligible: true,
      ineligibility_reason: null,
    },
  ],
  has_more: false,
  next_cursor: null,
};

const AUDIT_LIST = {
  object: "list",
  data: [
    {
      id: "audit-e2e-1",
      actor_kind: "ADMIN",
      actor_id: "u1",
      action: "LOGIN",
      operation_id: null,
      wallet_id: null,
      details: {},
      details_sha256: "b".repeat(64),
      created_at: "2026-07-30T00:00:00.000Z",
    },
  ],
  has_more: false,
  next_cursor: null,
};

const API_KEYS_LIST = {
  keys: [
    {
      id: "k1",
      implementer_id: "11111111-1111-4111-8111-111111111111",
      prefix: "ik_e2emobilekeyprefix",
      scopes: ["receive:create", "receive:read"],
      status: "ACTIVE",
      key_version: 1,
      issued_at: "2026-07-30T00:00:00Z",
      expires_at: null,
      revoked_at: null,
      last_used_at: null,
    },
  ],
};

const IMPLEMENTERS_LIST = {
  implementers: [
    {
      id: "11111111-1111-4111-8111-111111111111",
      name: "genesis",
      created_at: "2026-01-01T00:00:00Z",
      retired_at: null,
      funding_wallet_id: null,
      funding_wallet_public_key: null,
    },
  ],
};

const DEFAULT_FUNDING_WALLET = {
  wallet_id: null,
  public_key: null,
  row_version: 0,
};

const HALT_STATE = { engaged: false, reason: null, updated_at: null, updated_by: null };

/** Empty list — App shell badge (`useApproveInboxBadgeCount`) soft-reads PENDING IRs on every route. */
const INTEGRATION_REQUESTS_LIST = {
  object: "list",
  data: [] as const,
  has_more: false,
  next_cursor: null,
};

/** Empty keys — Approve/Destinations device-sign paths and listDeviceKeys consumers. */
const DEVICE_KEYS_LIST = {
  keys: [] as const,
};

const READINESS = {
  object: "readiness_checklist",
  generated_at: "2026-07-30T00:00:00.000Z",
  rows: [
    {
      id: "node_healthy",
      status: "ok",
      title: "Node healthy",
      detail: "Health and readiness probes are green.",
      href: null,
      blocks_ops: [],
    },
  ],
};

const AUTO_APPROVE_POLICY = {
  status: "disabled",
  disabledReason: "absent",
  rules: [],
  server_time: "2026-01-01T00:00:00.000Z",
};

const DUAL_CONTROL_POLICY = {
  mode: "single_operator",
  short: "Single operator",
  long: "One operator approves with TOTP and a device signature.",
  approve_hint: "Approve with your enrolled device.",
};

const VAULT_MASTER = {
  phase: "ready",
  can_generate: false,
  plaintext_pending_ack: false,
  offline_backup_acked: true,
};

/**
 * Day-0 gate (`RequireAuth` in main.tsx) — every authenticated route reads this before it
 * paints. An authenticated fixture session is a finished node; the `setup` session is not.
 */
const SETUP_STATE_COMPLETE = {
  object: "setup_state",
  current_step: "home",
  complete: true,
  next_step: "home",
  ceremony_master_key_blocked: false,
  pwa_installed: true,
  password_ok: true,
  totp_ok: true,
  device_enrolled: true,
  recovery_proven: true,
  vault_ready: true,
  flags: {},
  steps: [],
};

const SETUP_STATE_PENDING = {
  ...SETUP_STATE_COMPLETE,
  current_step: "password",
  complete: false,
  next_step: "password",
  password_ok: false,
  totp_ok: false,
  device_enrolled: false,
  recovery_proven: false,
  vault_ready: false,
};

export interface AdminFixtureGuard {
  assertNoUnhandledRequests(): void;
}

export async function registerAdminApiRoutes(
  page: Page,
  options: {
    session?: SessionMode;
    responseStatusOverrides?: Readonly<Record<string, number>>;
  } = {},
): Promise<AdminFixtureGuard> {
  const unexpected: string[] = [];
  const unexpectedNon2xx = new Set<string>();
  const session = options.session ?? "authenticated";

  await page.route("**/admin/v1/**", (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = decodeURIComponent(url.pathname);
    const method = request.method();
    const key = `${method} ${path}`;

    const json = (body: unknown, status = 200, allowNon2xx = false) => {
      const effectiveStatus = options.responseStatusOverrides?.[key] ?? status;
      if (!allowNon2xx && (effectiveStatus < 200 || effectiveStatus >= 300)) {
        unexpectedNon2xx.add(`${key} -> ${effectiveStatus}`);
      }
      return route.fulfill({
        status: effectiveStatus,
        contentType: "application/json",
        body: JSON.stringify(body),
      });
    };

    if (key === "GET /admin/v1/me") {
      if (session === "anonymous") {
        return json({ error: { code: "unauthorized", message: "Sign in required" } }, 401, true);
      }
      return json(session === "setup" ? SETUP_SESSION : SESSION);
    }
    if (key === "GET /admin/v1/setup-state" || key === "PATCH /admin/v1/setup-state") {
      return json(session === "setup" ? SETUP_STATE_PENDING : SETUP_STATE_COMPLETE);
    }
    if (key === "GET /admin/v1/operations/needs-attention") return json(NEEDS_ATTENTION);
    if (key === "GET /admin/v1/wallets") return json(WALLETS_LIST);
    if (key === `GET /admin/v1/wallets/${E2E_WALLET_PUBKEY}`) return json(WALLET);
    // Approve inbox + transfers inventory both hit GET /operations (optional kind/status query).
    if (key === "GET /admin/v1/operations") {
      const kind = url.searchParams.get("kind");
      const status = url.searchParams.get("status");
      if (kind === "SEND_EXTERNAL" || status === "CREATED") return json(PENDING_SENDS_LIST);
      return json(OPERATIONS_LIST);
    }
    if (key === `GET /admin/v1/external-sends/${E2E_OPERATION_ID}/approval-challenge`) {
      return json(APPROVAL_CHALLENGE);
    }
    if (key === `GET /admin/v1/operations/${E2E_OPERATION_ID}`) return json(OPERATION_DETAIL);
    if (key === `GET /admin/v1/operations/${E2E_OPERATION_ID}/recovery`) return json(RECOVERY);
    if (key === "GET /admin/v1/readiness") return json(READINESS);
    if (key === "GET /admin/v1/auto-approve-policy") return json(AUTO_APPROVE_POLICY);
    if (key === "GET /admin/v1/allow-node-verified-policy") {
      return json({
        status: "disabled",
        disabledReason: "absent",
        implementers: [],
        server_time: "2026-07-30T00:00:00.000Z",
      });
    }
    if (key === "GET /admin/v1/dual-control-policy") return json(DUAL_CONTROL_POLICY);
    if (key === "GET /admin/v1/vault-master") return json(VAULT_MASTER);
    if (key === "GET /admin/v1/destinations") return json(DESTINATIONS_LIST);
    // Shell badge always soft-reads PENDING integration requests; query string is not part of `key`.
    if (key === "GET /admin/v1/integration-requests") return json(INTEGRATION_REQUESTS_LIST);
    if (key === "GET /admin/v1/device-keys") return json(DEVICE_KEYS_LIST);
    if (key === "GET /admin/v1/audit") return json(AUDIT_LIST);
    if (key === "GET /admin/v1/api-keys") return json(API_KEYS_LIST);
    if (key === "GET /admin/v1/implementers") return json(IMPLEMENTERS_LIST);
    if (key === "GET /admin/v1/default-funding-wallet") return json(DEFAULT_FUNDING_WALLET);
    if (key === "GET /admin/v1/halt") return json(HALT_STATE);
    if (key === "GET /admin/v1/settings")
      return json({
        public_base_url: "https://e2e-node.example",
        node_id: "11111111-1111-4111-8111-111111111111",
        gateway_hosts: ["gw.e2e.example"],
        version: "e2e",
        backup_schedule_enabled: false,
        push_configured: true,
      });

    unexpected.push(`${key}${url.search}`);
    return json(
      { error: { code: "unhandled_e2e_fixture", message: `No fixture for ${key}` } },
      599,
    );
  });

  return {
    assertNoUnhandledRequests() {
      if (unexpected.length > 0) {
        throw new Error(`Unhandled admin API fixture request(s): ${unexpected.join(", ")}`);
      }
      if (unexpectedNon2xx.size > 0) {
        throw new Error(
          `Matched admin API fixture returned unexpected non-2xx response(s): ${[...unexpectedNon2xx].join(", ")}`,
        );
      }
    },
  };
}
