// Unified API Connectors page (GN-403 / ZTR-1341).
// Consolidates connector pairing approvals, spend rule request approvals,
// connected platform creation, reserve wallet routing, lifetime & rolling window
// spend caps with visual progress bars, API key management, and signed hook settings.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, apiSoftRead } from "../../lib/api.js";
import { truncatePubkey } from "../../lib/format.js";
import {
  fetchAutoApprovePolicy,
  formatMoneyError,
  isCancelled,
  listIntegrationRequests,
  listWalletsInventory,
  newIdempotencyKey,
  parseProposedIntegrationRule,
  postAutoApprovePolicy,
  postIntegrationRequestDecline,
  type AutoApprovePolicyWriteBody,
  type IntegrationRequestItem,
  type WalletInventoryItem,
} from "../../lib/money.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

export type ConnectorScope =
  | "receives:write"
  | "sends:write"
  | "wallets:read_linked"
  | "ledger:read_all";

export const ALL_CONNECTOR_SCOPES: readonly {
  readonly scope: ConnectorScope;
  readonly label: string;
}[] = [
  { scope: "receives:write", label: "Create Receive Operations (receives:write)" },
  { scope: "sends:write", label: "Create Send Operations (sends:write)" },
  { scope: "wallets:read_linked", label: "Read Linked Reserves (wallets:read_linked)" },
  { scope: "ledger:read_all", label: "Read Full Node Ledger (ledger:read_all)" },
] as const;

export interface ConnectorReserveView {
  readonly wallet_id: string;
  readonly display_name: string | null;
  readonly is_default: boolean;
  readonly allow_custom_routing: boolean;
}

export interface ConnectorKeyView {
  readonly key_id: string;
  readonly key_prefix: string;
  readonly created_at: string;
  readonly last_used_at: string | null;
}

export interface ConnectorSpendRuleView {
  readonly rule_id: string;
  readonly implementer_id: string;
  readonly label?: string | null;
  readonly reserve_wallet_id?: string | null;
  readonly total_cap_zkz?: string | null;
  readonly per_send_max_zkz: string;
  readonly per_send_min_zkz: string | null;
  readonly window_hours: number;
  readonly window_cap_zkz: string;
  readonly expires_at: string | null;
  readonly enabled: boolean;
  readonly current_window_spend_zkz: string;
  readonly cumulative_total_spend_zkz?: string;
}

export interface ConnectorView {
  readonly implementer_id: string;
  readonly display_name: string;
  readonly policy_mode: "NODE_VERIFIED" | "LEGACY";
  readonly scopes: readonly ConnectorScope[];
  readonly linked_reserves: readonly ConnectorReserveView[];
  readonly api_keys: readonly ConnectorKeyView[];
  readonly spend_rules: readonly ConnectorSpendRuleView[];
  readonly webhook_url: string | null;
  readonly webhook_enabled: boolean;
}

export interface ConnectorCreateResult extends ConnectorView {
  readonly api_key: string;
}

export interface ConnectorRuleRequestItem {
  readonly request_id: string;
  readonly implementer_id: string;
  readonly rule_id: string;
  readonly label: string | null;
  readonly reserve_wallet_id: string | null;
  readonly total_cap_zkz: string | null;
  readonly per_send_max_zkz: string;
  readonly per_send_min_zkz: string | null;
  readonly window_hours: number;
  readonly window_cap_zkz: string;
  readonly expires_at: string | null;
  readonly status: "PENDING" | "APPROVED" | "REJECTED";
  readonly webhook_enabled: boolean;
  readonly created_at: string;
  readonly decided_at: string | null;
  readonly decided_by: string | null;
}

const CONNECTORS_KEY = ["connectors-list"] as const;
const PAIRING_REQ_KEY = ["connectors-pairing-requests"] as const;
const RULE_REQ_KEY = ["connectors-rule-requests"] as const;
const WALLETS_KEY = ["connectors-wallets"] as const;
const AUTO_APPROVE_KEY = ["auto-approve-policy"] as const;

export async function fetchConnectors(): Promise<{
  readonly connectors: readonly ConnectorView[];
  readonly live: boolean;
}> {
  const res = await apiSoftRead<{ readonly connectors?: readonly ConnectorView[] }>(
    "/connectors",
    { connectors: [] },
  );
  return {
    connectors: res.data.connectors ?? [],
    live: res.live,
  };
}

export async function fetchPendingRuleRequests(): Promise<{
  readonly requests: readonly ConnectorRuleRequestItem[];
  readonly live: boolean;
}> {
  const res = await apiSoftRead<{ readonly requests?: readonly ConnectorRuleRequestItem[] }>(
    "/connector-rules/requests?status=PENDING",
    { requests: [] },
  );
  return {
    requests: res.data.requests ?? [],
    live: res.live,
  };
}

export function computeCapProgressPercent(
  usedZkz: string | null | undefined,
  capZkz: string | null | undefined,
): number {
  if (!capZkz) return 0;
  const parseUnits = (val: string | null | undefined): bigint => {
    if (!val) return 0n;
    const m = /^(\d+)(?:\.(\d{1,8}))?$/.exec(val.trim());
    if (!m) return 0n;
    const whole = BigInt(m[1] ?? "0");
    const frac = BigInt((m[2] ?? "").padEnd(8, "0").slice(0, 8));
    return whole * 100_000_000n + frac;
  };
  const used = parseUnits(usedZkz);
  const cap = parseUnits(capZkz);
  if (cap <= 0n) return 0;
  if (used >= cap) return 100;
  return Number((used * 100n) / cap);
}

function walletOptionLabel(w: WalletInventoryItem): string {
  const rec = w as unknown as { display_label?: string | null };
  const label = rec.display_label?.trim();
  if (label && label.length > 0) {
    return `${label} (${truncatePubkey(w.public_key, 6, 4)})`;
  }
  return `${w.wallet_id.slice(0, 8)}… (${truncatePubkey(w.public_key, 6, 4)})`;
}

export function ConnectorsPage() {
  const qc = useQueryClient();

  const [selectedConnectorId, setSelectedConnectorId] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [mintedConnectorKey, setMintedConnectorKey] = useState<{
    readonly displayName: string;
    readonly implementerId: string;
    readonly rawKey: string;
  } | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Pairing request reserve selection by request id
  const [pairingReserveById, setPairingReserveById] = useState<Record<string, string>>({});

  // New Connector form state
  const [newDisplayName, setNewDisplayName] = useState("");
  const [newScopes, setNewScopes] = useState<ConnectorScope[]>([
    "receives:write",
    "sends:write",
    "wallets:read_linked",
  ]);
  const [newDefaultReserveId, setNewDefaultReserveId] = useState("");
  const [newAdditionalReserveIds, setNewAdditionalReserveIds] = useState<string[]>([]);
  const [newAllowCustomRouting, setNewAllowCustomRouting] = useState(false);
  const [newWebhookUrl, setNewWebhookUrl] = useState("");
  const [newIncludeInitialRule, setNewIncludeInitialRule] = useState(false);
  const [newRuleId, setNewRuleId] = useState("default-spend-rule");
  const [newRuleLabel, setNewRuleLabel] = useState("Default Spend Rule");
  const [newRuleTotalCap, setNewRuleTotalCap] = useState("1000");
  const [newRulePerSendMax, setNewRulePerSendMax] = useState("100");
  const [newRuleWindowCap, setNewRuleWindowCap] = useState("500");
  const [newRuleWindowHours, setNewRuleWindowHours] = useState("24");

  // Add Spend Rule form state inside Connector Detail
  const [showAddRuleModal, setShowAddRuleModal] = useState(false);
  const [addRuleId, setAddRuleId] = useState("");
  const [addRuleLabel, setAddRuleLabel] = useState("");
  const [addRuleTotalCap, setAddRuleTotalCap] = useState("");
  const [addRulePerSendMax, setAddRulePerSendMax] = useState("");
  const [addRuleWindowCap, setAddRuleWindowCap] = useState("");
  const [addRuleWindowHours, setAddRuleWindowHours] = useState("24");

  // Detail Hook edit state
  const [hookUrlDraft, setHookUrlDraft] = useState<string | null>(null);
  const [hookEnabledDraft, setHookEnabledDraft] = useState<boolean | null>(null);

  const connectorsQ = useQuery({
    queryKey: [...CONNECTORS_KEY],
    queryFn: fetchConnectors,
  });

  const pairingReqsQ = useQuery({
    queryKey: [...PAIRING_REQ_KEY],
    queryFn: () => listIntegrationRequests({ status: "PENDING" }),
  });

  const ruleReqsQ = useQuery({
    queryKey: [...RULE_REQ_KEY],
    queryFn: fetchPendingRuleRequests,
  });

  const walletsQ = useQuery({
    queryKey: [...WALLETS_KEY],
    queryFn: () => listWalletsInventory(),
  });

  const reserveWallets = useMemo(() => {
    const items = walletsQ.data?.data ?? [];
    const active = items.filter((w) => w.retired_at === null && w.state !== "RETIRED");
    const reserves = active.filter(
      (w) => w.money_mode === "INTERNAL_ONLY" || w.money_mode === "FULL",
    );
    return reserves.length > 0 ? reserves : active;
  }, [walletsQ.data]);

  const defaultReserveWalletId = useMemo(() => {
    const main = reserveWallets.find((w) => {
      const rec = w as unknown as { display_label?: string | null };
      return rec.display_label === "Main Reserve";
    });
    return main?.wallet_id ?? reserveWallets[0]?.wallet_id ?? "";
  }, [reserveWallets]);

  function refreshAll() {
    void qc.invalidateQueries({ queryKey: CONNECTORS_KEY });
    void qc.invalidateQueries({ queryKey: PAIRING_REQ_KEY });
    void qc.invalidateQueries({ queryKey: RULE_REQ_KEY });
    void qc.invalidateQueries({ queryKey: AUTO_APPROVE_KEY });
  }

  const approvePairingMut = useTotpGatedMutation<
    unknown,
    { readonly req: IntegrationRequestItem; readonly reserveWalletId: string }
  >(
    ({ req, reserveWalletId }, totp) => {
      const parsed = parseProposedIntegrationRule(req.proposed_rule_json);
      const ruleBody = {
        rule_id: parsed.rule_id || "default-rule",
        per_send_max_zkz: parsed.per_send_max_zkz || "100",
        per_send_min_zkz: parsed.per_send_min_zkz.trim() === "" ? null : parsed.per_send_min_zkz,
        window_hours: Number.parseInt(parsed.window_hours || "24", 10) || 24,
        window_cap_zkz: parsed.window_cap_zkz || "500",
        expires_at: parsed.expires_at.trim() === "" ? null : parsed.expires_at,
        enabled: parsed.enabled,
      };
      return api(`/integration-requests/${encodeURIComponent(req.id)}/approve`, {
        method: "POST",
        body: JSON.stringify({
          expected_row_version: req.row_version,
          rule: ruleBody,
          ...(reserveWalletId
            ? {
                default_reserve_wallet_id: reserveWalletId,
                linked_reserve_wallet_ids: [reserveWalletId],
              }
            : {}),
        }),
        totp,
        idempotencyKey: newIdempotencyKey(),
      });
    },
    {
      title: "Approve & Connect Platform",
      detail: "Enter a fresh TOTP code to approve this connector pairing request.",
      onSuccess: () => {
        setActionError(null);
        setActionSuccess("Connector pairing request approved and connected.");
        refreshAll();
      },
      onError: (err) => {
        if (isCancelled(err)) return;
        setActionError(formatMoneyError(err, "Failed to approve pairing request."));
      },
    },
  );

  const declinePairingMut = useTotpGatedMutation<unknown, IntegrationRequestItem>(
    (req, totp) =>
      postIntegrationRequestDecline(req.id, { expected_row_version: req.row_version }, totp),
    {
      title: "Decline Pairing Request",
      detail: "Enter a fresh TOTP code to decline this connector pairing request.",
      onSuccess: () => {
        setActionError(null);
        setActionSuccess("Connector pairing request declined.");
        refreshAll();
      },
      onError: (err) => {
        if (isCancelled(err)) return;
        setActionError(formatMoneyError(err, "Failed to decline pairing request."));
      },
    },
  );

  const approveRuleReqMut = useTotpGatedMutation<unknown, ConnectorRuleRequestItem>(
    (req, totp) =>
      api(`/connector-rules/requests/${encodeURIComponent(req.request_id)}/approve`, {
        method: "POST",
        body: JSON.stringify({}),
        totp,
        idempotencyKey: newIdempotencyKey(),
      }),
    {
      title: "Approve Spend Rule",
      detail: "Enter a fresh TOTP code to activate this connector spend rule.",
      onSuccess: () => {
        setActionError(null);
        setActionSuccess("Spend rule request approved.");
        refreshAll();
      },
      onError: (err) => {
        if (isCancelled(err)) return;
        setActionError(formatMoneyError(err, "Failed to approve spend rule request."));
      },
    },
  );

  const rejectRuleReqMut = useTotpGatedMutation<unknown, ConnectorRuleRequestItem>(
    (req, totp) =>
      api(`/connector-rules/requests/${encodeURIComponent(req.request_id)}/reject`, {
        method: "POST",
        body: JSON.stringify({}),
        totp,
        idempotencyKey: newIdempotencyKey(),
      }),
    {
      title: "Decline Spend Rule",
      detail: "Enter a fresh TOTP code to decline this connector spend rule request.",
      onSuccess: () => {
        setActionError(null);
        setActionSuccess("Spend rule request declined.");
        refreshAll();
      },
      onError: (err) => {
        if (isCancelled(err)) return;
        setActionError(formatMoneyError(err, "Failed to decline spend rule request."));
      },
    },
  );

  const createConnectorMut = useTotpGatedMutation<ConnectorCreateResult, void>(
    (_v, totp) => {
      const chosenDefault = newDefaultReserveId || defaultReserveWalletId || null;
      const linkedSet = new Set<string>();
      if (chosenDefault) linkedSet.add(chosenDefault);
      for (const id of newAdditionalReserveIds) {
        if (id) linkedSet.add(id);
      }
      const linkedIds = [...linkedSet];
      const rules = newIncludeInitialRule
        ? [
            {
              rule_id: newRuleId.trim() || "default-spend-rule",
              label: newRuleLabel.trim() || null,
              total_cap_zkz: newRuleTotalCap.trim() || null,
              per_send_max_zkz: newRulePerSendMax.trim() || "100",
              per_send_min_zkz: null,
              window_hours: Number.parseInt(newRuleWindowHours, 10) || 24,
              window_cap_zkz: newRuleWindowCap.trim() || "500",
              expires_at: null,
              enabled: true,
            },
          ]
        : [];
      return api<ConnectorCreateResult>("/connectors", {
        method: "POST",
        body: JSON.stringify({
          display_name: newDisplayName.trim(),
          scopes: newScopes,
          ...(linkedIds.length > 0 ? { linked_reserve_wallet_ids: linkedIds } : {}),
          ...(chosenDefault ? { default_reserve_wallet_id: chosenDefault } : {}),
          allow_custom_routing: newAllowCustomRouting,
          rules,
          webhook_url: newWebhookUrl.trim() ? newWebhookUrl.trim() : null,
          webhook_enabled: newWebhookUrl.trim().length > 0,
          policy_mode: "NODE_VERIFIED",
        }),
        totp,
        idempotencyKey: newIdempotencyKey(),
      });
    },
    {
      title: "Create API Connector",
      detail: "Enter a fresh TOTP code to register this connector and mint its bearer API key.",
      onSuccess: (created) => {
        setShowCreateModal(false);
        setMintedConnectorKey({
          displayName: created.display_name,
          implementerId: created.implementer_id,
          rawKey: created.api_key,
        });
        setCopiedKey(false);
        setSelectedConnectorId(created.implementer_id);
        setNewDisplayName("");
        setActionError(null);
        setActionSuccess(`Connector "${created.display_name}" created.`);
        refreshAll();
      },
      onError: (err) => {
        if (isCancelled(err)) return;
        setActionError(formatMoneyError(err, "Failed to create connector."));
      },
    },
  );

  const patchConnectorMut = useTotpGatedMutation<
    ConnectorView,
    {
      readonly implementerId: string;
      readonly patch: {
        readonly linked_reserve_wallet_ids?: readonly string[];
        readonly default_reserve_wallet_id?: string | null;
        readonly allow_custom_routing?: boolean;
        readonly webhook_url?: string | null;
        readonly webhook_enabled?: boolean;
        readonly policy_mode?: "NODE_VERIFIED" | "LEGACY";
      };
    }
  >(
    ({ implementerId, patch }, totp) =>
      api<ConnectorView>(`/connectors/${encodeURIComponent(implementerId)}`, {
        method: "PATCH",
        body: JSON.stringify(patch),
        totp,
        idempotencyKey: newIdempotencyKey(),
      }),
    {
      title: "Update Connector Settings",
      detail: "Enter a fresh TOTP code to update connector routing or hook settings.",
      onSuccess: () => {
        setActionError(null);
        setActionSuccess("Connector settings saved.");
        refreshAll();
      },
      onError: (err) => {
        if (isCancelled(err)) return;
        setActionError(formatMoneyError(err, "Failed to update connector settings."));
      },
    },
  );

  const mintKeyMut = useTotpGatedMutation<
    { readonly raw_key: string; readonly prefix: string; readonly implementer_id: string },
    { readonly implementerId: string; readonly displayName: string }
  >(
    ({ implementerId }, totp) =>
      api(`/api-keys`, {
        method: "POST",
        body: JSON.stringify({
          implementer_id: implementerId,
          scopes: ["receives:write", "operations:read", "external_sends:write"],
        }),
        totp,
        idempotencyKey: newIdempotencyKey(),
      }),
    {
      title: "Mint Connector API Key",
      detail: "Enter a fresh TOTP code to issue an additional API key for this connector.",
      onSuccess: (res, vars) => {
        setMintedConnectorKey({
          displayName: vars.displayName,
          implementerId: vars.implementerId,
          rawKey: res.raw_key,
        });
        setCopiedKey(false);
        setActionError(null);
        setActionSuccess("New API key issued.");
        refreshAll();
      },
      onError: (err) => {
        if (isCancelled(err)) return;
        setActionError(formatMoneyError(err, "Failed to issue API key."));
      },
    },
  );

  const revokeKeyMut = useTotpGatedMutation<unknown, string>(
    (keyId, totp) =>
      api(`/api-keys/${encodeURIComponent(keyId)}/revoke`, {
        method: "POST",
        body: JSON.stringify({}),
        totp,
        idempotencyKey: newIdempotencyKey(),
      }),
    {
      title: "Revoke API Key",
      detail: "Enter a fresh TOTP code to permanently revoke this API key.",
      onSuccess: () => {
        setActionError(null);
        setActionSuccess("API key revoked.");
        refreshAll();
      },
      onError: (err) => {
        if (isCancelled(err)) return;
        setActionError(formatMoneyError(err, "Failed to revoke API key."));
      },
    },
  );

  const addSpendRuleMut = useTotpGatedMutation<
    unknown,
    {
      readonly implementerId: string;
      readonly rule_id: string;
      readonly label: string | null;
      readonly total_cap_zkz: string | null;
      readonly per_send_max_zkz: string;
      readonly window_cap_zkz: string;
      readonly window_hours: number;
    }
  >(
    async (newRule, totp) => {
      const current = await fetchAutoApprovePolicy();
      const existingRules = current.rules.filter((r) => r.rule_id !== newRule.rule_id);
      const body: AutoApprovePolicyWriteBody & {
        readonly rules: readonly Record<string, unknown>[];
      } = {
        enabled: true,
        rules: [
          ...existingRules.map((r) => ({
            rule_id: r.rule_id,
            implementer_id: r.implementer_id,
            per_send_max_zkz: r.per_send_max_zkz,
            per_send_min_zkz: r.per_send_min_zkz,
            window_hours: r.window_hours,
            window_cap_zkz: r.window_cap_zkz,
            expires_at: r.expires_at,
            enabled: r.enabled,
          })),
          {
            rule_id: newRule.rule_id,
            implementer_id: newRule.implementerId,
            ...(newRule.label ? { label: newRule.label } : {}),
            ...(newRule.total_cap_zkz ? { total_cap_zkz: newRule.total_cap_zkz } : {}),
            per_send_max_zkz: newRule.per_send_max_zkz,
            per_send_min_zkz: null,
            window_hours: newRule.window_hours,
            window_cap_zkz: newRule.window_cap_zkz,
            expires_at: null,
            enabled: true,
          },
        ],
      };
      return postAutoApprovePolicy(body as AutoApprovePolicyWriteBody, totp);
    },
    {
      title: "Add Spend Rule",
      detail: "Enter a fresh TOTP code to save this spend rule.",
      onSuccess: () => {
        setShowAddRuleModal(false);
        setAddRuleId("");
        setAddRuleLabel("");
        setAddRuleTotalCap("");
        setAddRulePerSendMax("");
        setAddRuleWindowCap("");
        setActionError(null);
        setActionSuccess("Spend rule added.");
        refreshAll();
      },
      onError: (err) => {
        if (isCancelled(err)) return;
        setActionError(formatMoneyError(err, "Failed to add spend rule."));
      },
    },
  );

  const connectors = connectorsQ.data?.connectors ?? [];
  const pendingPairings = pairingReqsQ.data?.data ?? [];
  const pendingRules = ruleReqsQ.data?.requests ?? [];

  const selectedConnector = useMemo(() => {
    if (selectedConnectorId) {
      return connectors.find((c) => c.implementer_id === selectedConnectorId) ?? connectors[0] ?? null;
    }
    return connectors[0] ?? null;
  }, [connectors, selectedConnectorId]);

  function toggleNewScope(scope: ConnectorScope) {
    setNewScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope],
    );
  }

  return (
    <div className="page" data-testid="connectors-page">
      <div
        className="page-title-row"
        style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}
      >
        <div>
          <h1>API Connectors</h1>
          <p className="muted" style={{ fontSize: 13, marginTop: 4 }}>
            Connect external platforms, bind Reserve Wallets, manage API keys, and enforce Lifetime
            and Rolling Window Spend Rules.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          data-testid="open-new-connector-modal"
          onClick={() => {
            setNewDefaultReserveId(defaultReserveWalletId);
            setShowCreateModal(true);
          }}
        >
          + New Connector
        </button>
      </div>

      {actionError ? (
        <div className="banner banner-error" role="alert" style={{ marginBottom: 12 }}>
          {actionError}
        </div>
      ) : null}

      {actionSuccess ? (
        <div
          className="banner"
          role="status"
          data-testid="connectors-action-success"
          style={{ marginBottom: 12 }}
        >
          {actionSuccess}
        </div>
      ) : null}

      {mintedConnectorKey ? (
        <div
          className="card"
          data-testid="minted-connector-key-banner"
          style={{ marginBottom: 16, border: "1px solid var(--accent, #2563eb)" }}
        >
          <h2>One-Time Connector API Key — {mintedConnectorKey.displayName}</h2>
          <p className="muted" style={{ fontSize: 12.5 }}>
            Copy this bearer secret now. The node stores only a one-way digest and will never
            display the full secret again.
          </p>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 8 }}>
            <code
              data-testid="minted-raw-key"
              style={{
                padding: "6px 10px",
                background: "var(--surface-2, #1e293b)",
                borderRadius: 4,
                fontFamily: "var(--mono)",
                fontSize: 13,
              }}
            >
              {mintedConnectorKey.rawKey}
            </code>
            <button
              type="button"
              className="btn"
              onClick={() => {
                void navigator.clipboard?.writeText(mintedConnectorKey.rawKey);
                setCopiedKey(true);
              }}
            >
              {copiedKey ? "Copied" : "Copy Key"}
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => setMintedConnectorKey(null)}
            >
              Dismiss
            </button>
          </div>
        </div>
      ) : null}

      {/* Top Section: Pending Pairing Requests & Pending Spend Rule Requests */}
      {pendingPairings.length > 0 || pendingRules.length > 0 ? (
        <div
          className="card"
          data-testid="pending-connector-requests-banner"
          style={{ marginBottom: 20 }}
        >
          <h2>Pending Connector Requests</h2>

          {pendingPairings.length > 0 ? (
            <div style={{ marginTop: 12 }} data-testid="pending-pairing-requests-section">
              <h3 style={{ fontSize: 14, marginBottom: 8 }}>
                Connector Pairing Requests ({pendingPairings.length})
              </h3>
              <table className="table">
                <thead>
                  <tr>
                    <th>Platform</th>
                    <th>Requested Scopes</th>
                    <th>Proposed Spend Rule</th>
                    <th>Reserve Wallet</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {pendingPairings.map((req) => {
                    const rule = parseProposedIntegrationRule(req.proposed_rule_json);
                    const pickedReserve =
                      pairingReserveById[req.id] ?? defaultReserveWalletId;
                    return (
                      <tr key={req.id} data-testid={`pairing-request-row-${req.id}`}>
                        <td>
                          <strong>{req.display_name}</strong>
                          <div className="muted" style={{ fontSize: 11.5 }}>
                            <code>{req.id.slice(0, 8)}…</code>
                          </div>
                        </td>
                        <td>
                          <code>{(req.requested_scopes ?? []).join(", ") || "default"}</code>
                        </td>
                        <td style={{ fontSize: 12.5 }}>
                          <code>{rule.rule_id}</code> — max{" "}
                          <strong>{rule.per_send_max_zkz || "0"} ZKZ</strong> / send,{" "}
                          <strong>{rule.window_cap_zkz || "0"} ZKZ</strong> / {rule.window_hours}h
                        </td>
                        <td>
                          <select
                            aria-label={`Reserve wallet for ${req.display_name}`}
                            value={pickedReserve}
                            onChange={(e) =>
                              setPairingReserveById((prev) => ({
                                ...prev,
                                [req.id]: e.target.value,
                              }))
                            }
                          >
                            <option value="">Main Reserve (Default)</option>
                            {reserveWallets.map((w) => (
                              <option key={w.wallet_id} value={w.wallet_id}>
                                {walletOptionLabel(w)}
                              </option>
                            ))}
                          </select>
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <button
                            type="button"
                            className="btn btn-primary"
                            data-testid={`approve-pairing-${req.id}`}
                            onClick={() =>
                              void approvePairingMut.mutateAsync({
                                req,
                                reserveWalletId: pickedReserve,
                              })
                            }
                          >
                            Approve &amp; Connect
                          </button>{" "}
                          <button
                            type="button"
                            className="btn"
                            data-testid={`decline-pairing-${req.id}`}
                            onClick={() => void declinePairingMut.mutateAsync(req)}
                          >
                            Decline
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}

          {pendingRules.length > 0 ? (
            <div style={{ marginTop: 16 }} data-testid="pending-rule-requests-section">
              <h3 style={{ fontSize: 14, marginBottom: 8 }}>
                Spend Rule Requests ({pendingRules.length})
              </h3>
              <table className="table">
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Connector</th>
                    <th>Lifetime Cap</th>
                    <th>Per-Send Max</th>
                    <th>Rolling Window Cap</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {pendingRules.map((req) => (
                    <tr key={req.request_id} data-testid={`rule-request-row-${req.request_id}`}>
                      <td>
                        <strong>{req.label ?? req.rule_id}</strong>
                        <div className="muted" style={{ fontSize: 11.5 }}>
                          <code>{req.rule_id}</code>
                        </div>
                      </td>
                      <td>
                        <code>{req.implementer_id.slice(0, 8)}…</code>
                      </td>
                      <td>{req.total_cap_zkz ? `${req.total_cap_zkz} ZKZ` : "Unlimited"}</td>
                      <td>{req.per_send_max_zkz} ZKZ</td>
                      <td>
                        {req.window_cap_zkz} ZKZ / {req.window_hours}h
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <button
                          type="button"
                          className="btn btn-primary"
                          data-testid={`approve-rule-req-${req.request_id}`}
                          onClick={() => void approveRuleReqMut.mutateAsync(req)}
                        >
                          Approve Rule
                        </button>{" "}
                        <button
                          type="button"
                          className="btn"
                          data-testid={`reject-rule-req-${req.request_id}`}
                          onClick={() => void rejectRuleReqMut.mutateAsync(req)}
                        >
                          Decline
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      ) : null}

      {/* New Connector Modal */}
      {showCreateModal ? (
        <div
          className="card"
          role="dialog"
          aria-label="New API Connector"
          data-testid="new-connector-modal"
          style={{ marginBottom: 20 }}
        >
          <h2>Create API Connector</h2>
          <div style={{ display: "grid", gap: 12, marginTop: 12 }}>
            <label>
              Display Name
              <input
                type="text"
                aria-label="Connector display name"
                value={newDisplayName}
                onChange={(e) => setNewDisplayName(e.target.value)}
                placeholder="e.g. Promotional Campaign Engine"
              />
            </label>

            <div>
              <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 6 }}>Access Scopes</div>
              <div style={{ display: "grid", gap: 6 }}>
                {ALL_CONNECTOR_SCOPES.map((item) => (
                  <label key={item.scope} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <input
                      type="checkbox"
                      checked={newScopes.includes(item.scope)}
                      onChange={() => toggleNewScope(item.scope)}
                    />
                    <span>{item.label}</span>
                  </label>
                ))}
              </div>
            </div>

            <label>
              Default Reserve Wallet
              <select
                aria-label="Default Reserve Wallet"
                value={newDefaultReserveId}
                onChange={(e) => setNewDefaultReserveId(e.target.value)}
              >
                <option value="">Main Reserve (Node Default)</option>
                {reserveWallets.map((w) => (
                  <option key={w.wallet_id} value={w.wallet_id}>
                    {walletOptionLabel(w)}
                  </option>
                ))}
              </select>
            </label>

            {reserveWallets.length > 1 ? (
              <div>
                <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 6 }}>
                  Additional Linked Reserve Wallets
                </div>
                <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                  {reserveWallets.map((w) => (
                    <label
                      key={w.wallet_id}
                      style={{ display: "flex", gap: 6, alignItems: "center" }}
                    >
                      <input
                        type="checkbox"
                        checked={newAdditionalReserveIds.includes(w.wallet_id)}
                        onChange={(e) => {
                          setNewAdditionalReserveIds((prev) =>
                            e.target.checked
                              ? [...prev, w.wallet_id]
                              : prev.filter((id) => id !== w.wallet_id),
                          );
                        }}
                      />
                      <span>{walletOptionLabel(w)}</span>
                    </label>
                  ))}
                </div>
              </div>
            ) : null}

            <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input
                type="checkbox"
                checked={newAllowCustomRouting}
                onChange={(e) => setNewAllowCustomRouting(e.target.checked)}
              />
              <span>Allow custom per-operation Reserve routing (`allow_custom_routing`)</span>
            </label>

            <label>
              Signed Event Hook URL (Optional, HTTPS)
              <input
                type="url"
                aria-label="Signed Event Hook URL"
                value={newWebhookUrl}
                onChange={(e) => setNewWebhookUrl(e.target.value)}
                placeholder="https://example.com/hooks/zucoins"
              />
            </label>

            <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input
                type="checkbox"
                checked={newIncludeInitialRule}
                onChange={(e) => setNewIncludeInitialRule(e.target.checked)}
              />
              <span>Configure initial Spend Rule</span>
            </label>

            {newIncludeInitialRule ? (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
                  gap: 10,
                  padding: 12,
                  borderRadius: 6,
                  border: "1px solid var(--border, #334155)",
                }}
              >
                <label>
                  Rule ID
                  <input
                    type="text"
                    aria-label="Initial Rule ID"
                    value={newRuleId}
                    onChange={(e) => setNewRuleId(e.target.value)}
                  />
                </label>
                <label>
                  Label
                  <input
                    type="text"
                    aria-label="Initial Rule Label"
                    value={newRuleLabel}
                    onChange={(e) => setNewRuleLabel(e.target.value)}
                  />
                </label>
                <label>
                  Lifetime Cap (ZKZ)
                  <input
                    type="text"
                    aria-label="Initial Lifetime Cap ZKZ"
                    value={newRuleTotalCap}
                    onChange={(e) => setNewRuleTotalCap(e.target.value)}
                  />
                </label>
                <label>
                  Per-Send Max (ZKZ)
                  <input
                    type="text"
                    aria-label="Initial Per-Send Max ZKZ"
                    value={newRulePerSendMax}
                    onChange={(e) => setNewRulePerSendMax(e.target.value)}
                  />
                </label>
                <label>
                  Rolling Window Cap (ZKZ)
                  <input
                    type="text"
                    aria-label="Initial Window Cap ZKZ"
                    value={newRuleWindowCap}
                    onChange={(e) => setNewRuleWindowCap(e.target.value)}
                  />
                </label>
                <label>
                  Window Hours
                  <input
                    type="number"
                    aria-label="Initial Window Hours"
                    value={newRuleWindowHours}
                    onChange={(e) => setNewRuleWindowHours(e.target.value)}
                  />
                </label>
              </div>
            ) : null}

            <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
              <button
                type="button"
                className="btn btn-primary"
                data-testid="submit-create-connector"
                disabled={newDisplayName.trim().length === 0 || newScopes.length === 0}
                onClick={() => void createConnectorMut.mutateAsync(undefined)}
              >
                Create Connector &amp; Mint Key
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => setShowCreateModal(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {/* Main Section: Connected Platforms List & Detail View */}
      {connectorsQ.isPending ? <p className="muted">Loading connectors…</p> : null}

      {connectorsQ.isSuccess && connectors.length === 0 ? (
        <div className="card" data-testid="connectors-empty-state">
          <h2>No Connected Platforms Yet</h2>
          <p className="muted" style={{ fontSize: 13 }}>
            Click <strong>+ New Connector</strong> above or approve a pending pairing request to
            connect an external service to your node.
          </p>
        </div>
      ) : null}

      {connectors.length > 0 ? (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "minmax(260px, 1fr) minmax(420px, 2fr)",
            gap: 16,
            alignItems: "start",
          }}
        >
          {/* Left: Connected Platforms List */}
          <div className="card" data-testid="connectors-list-card">
            <h2>Connected Platforms ({connectors.length})</h2>
            <div style={{ display: "grid", gap: 8, marginTop: 10 }}>
              {connectors.map((c) => {
                const isSelected = selectedConnector?.implementer_id === c.implementer_id;
                const defaultReserve =
                  c.linked_reserves.find((r) => r.is_default) ?? c.linked_reserves[0];
                return (
                  <button
                    key={c.implementer_id}
                    type="button"
                    data-testid={`connector-card-${c.implementer_id}`}
                    onClick={() => {
                      setSelectedConnectorId(c.implementer_id);
                      setHookUrlDraft(null);
                      setHookEnabledDraft(null);
                    }}
                    style={{
                      textAlign: "left",
                      padding: 12,
                      borderRadius: 6,
                      border: isSelected
                        ? "2px solid var(--accent, #2563eb)"
                        : "1px solid var(--border, #334155)",
                      background: "transparent",
                      color: "inherit",
                      cursor: "pointer",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                    >
                      <strong>{c.display_name}</strong>
                      <span className="pill pill-ok">{c.policy_mode}</span>
                    </div>
                    <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                      Reserve: <strong>{defaultReserve?.display_name ?? "Main Reserve"}</strong> ·{" "}
                      {c.spend_rules.length} Spend Rule(s) · {c.api_keys.length} Key(s)
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right: Connector Detail View */}
          {selectedConnector ? (
            <div style={{ display: "grid", gap: 16 }} data-testid="connector-detail-view">
              {/* 1. Reserve Wallets & Routing Card */}
              <div className="card" data-testid="connector-reserves-card">
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <h2>{selectedConnector.display_name} — Reserve Wallets &amp; Routing</h2>
                  <code>{selectedConnector.implementer_id}</code>
                </div>
                <p className="muted" style={{ fontSize: 12.5, marginTop: 4 }}>
                  Operations initiated by this connector default to its Default Reserve Wallet.
                </p>
                <div style={{ marginTop: 10 }}>
                  <strong>Linked Reserve Wallets:</strong>{" "}
                  {selectedConnector.linked_reserves.length === 0 ? (
                    <span>Main Reserve (Node Default)</span>
                  ) : (
                    selectedConnector.linked_reserves.map((r) => (
                      <span
                        key={r.wallet_id}
                        className="pill"
                        style={{ marginRight: 6 }}
                        data-testid={`linked-reserve-pill-${r.wallet_id}`}
                      >
                        {r.display_name ?? `${r.wallet_id.slice(0, 8)}…`}
                        {r.is_default ? " (Default)" : ""}
                      </span>
                    ))
                  )}
                </div>
                <div style={{ marginTop: 10, fontSize: 13 }}>
                  Custom Per-Operation Routing:{" "}
                  <strong>
                    {selectedConnector.linked_reserves.some((r) => r.allow_custom_routing)
                      ? "Enabled"
                      : "Disabled"}
                  </strong>
                </div>
                <div style={{ marginTop: 10 }}>
                  <div className="muted" style={{ fontSize: 12 }}>
                    Authorized Scopes: <code>{selectedConnector.scopes.join(", ")}</code>
                  </div>
                </div>
              </div>

              {/* 2. Spend Rules & Caps Card */}
              <div className="card" data-testid="connector-spend-rules-card">
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <h2>Spend Rules &amp; Caps</h2>
                  <button
                    type="button"
                    className="btn"
                    data-testid="open-add-spend-rule"
                    onClick={() => setShowAddRuleModal((prev) => !prev)}
                  >
                    + Add Spend Rule
                  </button>
                </div>

                {showAddRuleModal ? (
                  <div
                    data-testid="add-spend-rule-form"
                    style={{
                      marginTop: 12,
                      padding: 12,
                      borderRadius: 6,
                      border: "1px solid var(--border, #334155)",
                      display: "grid",
                      gap: 10,
                    }}
                  >
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
                        gap: 8,
                      }}
                    >
                      <label>
                        Rule ID
                        <input
                          type="text"
                          aria-label="New Spend Rule ID"
                          value={addRuleId}
                          onChange={(e) => setAddRuleId(e.target.value)}
                          placeholder="campaign-2026"
                        />
                      </label>
                      <label>
                        Label
                        <input
                          type="text"
                          aria-label="New Spend Rule Label"
                          value={addRuleLabel}
                          onChange={(e) => setAddRuleLabel(e.target.value)}
                          placeholder="Spring Promo"
                        />
                      </label>
                      <label>
                        Lifetime Cap (ZKZ)
                        <input
                          type="text"
                          aria-label="New Spend Rule Lifetime Cap"
                          value={addRuleTotalCap}
                          onChange={(e) => setAddRuleTotalCap(e.target.value)}
                          placeholder="1000"
                        />
                      </label>
                      <label>
                        Per-Send Max (ZKZ)
                        <input
                          type="text"
                          aria-label="New Spend Rule Per-Send Max"
                          value={addRulePerSendMax}
                          onChange={(e) => setAddRulePerSendMax(e.target.value)}
                          placeholder="50"
                        />
                      </label>
                      <label>
                        Window Cap (ZKZ)
                        <input
                          type="text"
                          aria-label="New Spend Rule Window Cap"
                          value={addRuleWindowCap}
                          onChange={(e) => setAddRuleWindowCap(e.target.value)}
                          placeholder="250"
                        />
                      </label>
                      <label>
                        Window Hours
                        <input
                          type="number"
                          aria-label="New Spend Rule Window Hours"
                          value={addRuleWindowHours}
                          onChange={(e) => setAddRuleWindowHours(e.target.value)}
                        />
                      </label>
                    </div>
                    <div>
                      <button
                        type="button"
                        className="btn btn-primary"
                        data-testid="submit-add-spend-rule"
                        disabled={!addRuleId.trim() || !addRulePerSendMax.trim() || !addRuleWindowCap.trim()}
                        onClick={() =>
                          void addSpendRuleMut.mutateAsync({
                            implementerId: selectedConnector.implementer_id,
                            rule_id: addRuleId.trim(),
                            label: addRuleLabel.trim() || null,
                            total_cap_zkz: addRuleTotalCap.trim() || null,
                            per_send_max_zkz: addRulePerSendMax.trim(),
                            window_cap_zkz: addRuleWindowCap.trim(),
                            window_hours: Number.parseInt(addRuleWindowHours, 10) || 24,
                          })
                        }
                      >
                        Save Spend Rule
                      </button>
                    </div>
                  </div>
                ) : null}

                {selectedConnector.spend_rules.length === 0 ? (
                  <p className="muted" style={{ fontSize: 13, marginTop: 10 }}>
                    No automated spend rules configured. External sends from this connector require
                    manual operator approval.
                  </p>
                ) : (
                  <div style={{ display: "grid", gap: 12, marginTop: 12 }}>
                    {selectedConnector.spend_rules.map((rule) => {
                      const lifetimeUsed = rule.cumulative_total_spend_zkz ?? "0";
                      const lifetimeCap = rule.total_cap_zkz ?? null;
                      const lifetimePct = computeCapProgressPercent(lifetimeUsed, lifetimeCap);
                      const windowUsed = rule.current_window_spend_zkz ?? "0";
                      const windowCap = rule.window_cap_zkz;
                      const windowPct = computeCapProgressPercent(windowUsed, windowCap);

                      return (
                        <div
                          key={rule.rule_id}
                          data-testid={`spend-rule-card-${rule.rule_id}`}
                          style={{
                            padding: 12,
                            borderRadius: 6,
                            border: "1px solid var(--border, #334155)",
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              alignItems: "center",
                            }}
                          >
                            <div>
                              <strong>{rule.label ?? rule.rule_id}</strong>{" "}
                              <code style={{ fontSize: 12 }}>({rule.rule_id})</code>
                            </div>
                            <span className={rule.enabled ? "pill pill-ok" : "pill"}>
                              {rule.enabled ? "ACTIVE" : "PAUSED"}
                            </span>
                          </div>
                          <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                            Per-Send Max: <strong>{rule.per_send_max_zkz} ZKZ</strong>
                            {rule.per_send_min_zkz ? ` · Min: ${rule.per_send_min_zkz} ZKZ` : ""}
                            {rule.expires_at ? ` · Expires: ${rule.expires_at}` : ""}
                          </div>

                          {/* Rolling Window Cap Progress Bar */}
                          <div style={{ marginTop: 10 }}>
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                fontSize: 12,
                              }}
                            >
                              <span>Rolling Window Cap ({rule.window_hours}h)</span>
                              <span data-testid={`window-spend-text-${rule.rule_id}`}>
                                {windowUsed} / {windowCap} ZKZ ({windowPct}%)
                              </span>
                            </div>
                            <div
                              role="progressbar"
                              aria-label={`Rolling Window Cap for ${rule.rule_id}`}
                              aria-valuenow={windowPct}
                              aria-valuemin={0}
                              aria-valuemax={100}
                              style={{
                                height: 8,
                                background: "var(--surface-2, #1e293b)",
                                borderRadius: 4,
                                overflow: "hidden",
                                marginTop: 4,
                              }}
                            >
                              <div
                                style={{
                                  width: `${windowPct}%`,
                                  height: "100%",
                                  background: "var(--accent, #2563eb)",
                                }}
                              />
                            </div>
                          </div>

                          {/* Lifetime Cap Progress Bar */}
                          <div style={{ marginTop: 10 }}>
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                fontSize: 12,
                              }}
                            >
                              <span>Lifetime Cap</span>
                              <span data-testid={`lifetime-spend-text-${rule.rule_id}`}>
                                {lifetimeCap
                                  ? `${lifetimeUsed} / ${lifetimeCap} ZKZ (${lifetimePct}%)`
                                  : `${lifetimeUsed} ZKZ used (No lifetime cap)`}
                              </span>
                            </div>
                            {lifetimeCap ? (
                              <div
                                role="progressbar"
                                aria-label={`Lifetime Cap for ${rule.rule_id}`}
                                aria-valuenow={lifetimePct}
                                aria-valuemin={0}
                                aria-valuemax={100}
                                style={{
                                  height: 8,
                                  background: "var(--surface-2, #1e293b)",
                                  borderRadius: 4,
                                  overflow: "hidden",
                                  marginTop: 4,
                                }}
                              >
                                <div
                                  style={{
                                    width: `${lifetimePct}%`,
                                    height: "100%",
                                    background:
                                      lifetimePct >= 100
                                        ? "var(--danger, #dc2626)"
                                        : "var(--ok, #16a34a)",
                                  }}
                                />
                              </div>
                            ) : null}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* 3. API Keys Card */}
              <div className="card" data-testid="connector-api-keys-card">
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <h2>API Keys</h2>
                  <button
                    type="button"
                    className="btn"
                    data-testid="mint-additional-key-btn"
                    onClick={() =>
                      void mintKeyMut.mutateAsync({
                        implementerId: selectedConnector.implementer_id,
                        displayName: selectedConnector.display_name,
                      })
                    }
                  >
                    + Mint Key
                  </button>
                </div>
                {selectedConnector.api_keys.length === 0 ? (
                  <p className="muted" style={{ fontSize: 13, marginTop: 8 }}>
                    No active API keys for this connector.
                  </p>
                ) : (
                  <table className="table" style={{ marginTop: 10 }}>
                    <thead>
                      <tr>
                        <th>Prefix</th>
                        <th>Issued At</th>
                        <th>Last Used</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {selectedConnector.api_keys.map((k) => (
                        <tr key={k.key_id} data-testid={`connector-key-row-${k.key_id}`}>
                          <td>
                            <code>{k.key_prefix}…</code>
                          </td>
                          <td>{k.created_at}</td>
                          <td>{k.last_used_at ?? "Never"}</td>
                          <td style={{ textAlign: "right" }}>
                            <button
                              type="button"
                              className="btn"
                              data-testid={`revoke-key-${k.key_id}`}
                              onClick={() => void revokeKeyMut.mutateAsync(k.key_id)}
                            >
                              Revoke
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {/* 4. Signed Event Hooks & Verification Mode Card */}
              <div className="card" data-testid="connector-hooks-card">
                <h2>Signed Event Hooks &amp; Verification Mode</h2>
                <p className="muted" style={{ fontSize: 12.5, marginTop: 4 }}>
                  When enabled, the node signs and delivers{" "}
                  <code>zp-webhook-event-v1</code> notifications to the configured HTTPS endpoint.
                </p>
                <div style={{ display: "grid", gap: 10, marginTop: 10 }}>
                  <label>
                    Hook Endpoint URL
                    <input
                      type="url"
                      aria-label="Connector Hook Endpoint URL"
                      value={hookUrlDraft ?? selectedConnector.webhook_url ?? ""}
                      onChange={(e) => setHookUrlDraft(e.target.value)}
                      placeholder="https://example.com/hooks/zucoins"
                    />
                  </label>
                  <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <input
                      type="checkbox"
                      checked={hookEnabledDraft ?? selectedConnector.webhook_enabled}
                      onChange={(e) => setHookEnabledDraft(e.target.checked)}
                    />
                    <span>Enable signed event hook deliveries</span>
                  </label>
                  <div>
                    <button
                      type="button"
                      className="btn"
                      data-testid="save-connector-hook-btn"
                      onClick={() => {
                        const nextUrl = (hookUrlDraft ?? selectedConnector.webhook_url ?? "").trim();
                        const nextEnabled = hookEnabledDraft ?? selectedConnector.webhook_enabled;
                        void patchConnectorMut.mutateAsync({
                          implementerId: selectedConnector.implementer_id,
                          patch: {
                            webhook_url: nextUrl.length > 0 ? nextUrl : null,
                            webhook_enabled: nextEnabled,
                          },
                        });
                      }}
                    >
                      Save Hook Settings
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
