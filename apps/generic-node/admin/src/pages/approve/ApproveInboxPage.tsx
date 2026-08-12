/**
 * Mobile-first Approve inbox.
 * Surfaces pending SEND_EXTERNAL approvals, destination bless requests, and
 * implemented recovery-action attentions without hunting Activity.
 *
 * Normative honesty:
 * - Approve ≠ redeemed ≠ paid; node never submits SEND_EXTERNAL on-chain.
 * - Post-approve: forming → waiting for recipient to finish → landed/attention.
 * - Only live (non-reserved) recovery effect kinds are actionable.
 * - TOTP is required for every money mutation; device signature is additive only.
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useRef, useState } from "react";
import { Link } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { RecoveryActions } from "../../components/RecoveryActions.js";
import { StatusTag } from "../../components/StatusTag.js";
import { countApproveInboxItems } from "../../lib/approve-inbox-count.js";
import {
  formatApproveFailure,
  getLocalApproveDeviceAvailability,
  signApproveChallengePreimage,
} from "../../lib/approve-device-sign.js";
import {
  buildDestinationBlessPreimage,
  ceremonyWindowFromNow,
  getDeviceRecord,
  randomUuid,
  signPreimage,
} from "../../lib/device-crypto.js";
import { truncatePubkey } from "../../lib/format.js";
import { operationKindLabel, statusLabel } from "../../lib/labels.js";
import {
  formatMoneyError,
  getApprovalChallenge,
  isCancelled,
  isLiveRecoveryAction,
  listDestinationsInventory,
  listDeviceKeys,
  listIntegrationRequests,
  listSendOperationsInventory,
  operationDetailPath,
  parseProposedIntegrationRule,
  pollSendState,
  postApprove,
  postBless,
  postIntegrationRequestApprove,
  postIntegrationRequestDecline,
  postRecoveryAction,
  postReject,
  getRecovery,
  type ApprovalChallenge,
  type DestinationItem,
  type IntegrationRequestItem,
  type OperationListItem,
} from "../../lib/money.js";
import {
  invalidateNeedsAttention,
  useNeedsAttention,
} from "../../lib/needs-attention.js";
import type { NeedsAttentionListItem } from "../../lib/ops.js";
import { useAuth } from "../../store/auth.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

function shortDigest(hex: string | null | undefined): string {
  if (!hex || hex.length < 12) return hex ?? "—";
  return `${hex.slice(0, 8)}…${hex.slice(-4)}`;
}

type ExpandedSend = {
  challenge: ApprovalChallenge | null;
  challengeErr: string | null;
  loading: boolean;
};

export function ApproveInboxPage() {
  const user = useAuth((s) => s.user);
  const qc = useQueryClient();
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState("operator_rejected");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [expandedSend, setExpandedSend] = useState<ExpandedSend | null>(null);
  const [pollNote, setPollNote] = useState<string | null>(null);

  // Bless form fields (when acting on a PENDING destination)
  const [blessTarget, setBlessTarget] = useState<string | null>(null);
  const [deviceKeyId, setDeviceKeyId] = useState("");
  const [showBlessBreakGlass, setShowBlessBreakGlass] = useState(false);
  const [manualBlessNonce, setManualBlessNonce] = useState("");
  const [manualBlessIssued, setManualBlessIssued] = useState("");
  const [manualBlessExpires, setManualBlessExpires] = useState("");
  const [manualBlessSig, setManualBlessSig] = useState("");

  // Integration-request edit draft (operator may tighten/loosen caps before approve).
  const [irExpandedId, setIrExpandedId] = useState<string | null>(null);
  const [irDraft, setIrDraft] = useState({
    rule_id: "integration",
    per_send_max_zkz: "",
    per_send_min_zkz: "",
    window_hours: "24",
    window_cap_zkz: "",
    expires_at: "",
    enabled: true,
  });

  const pendingSendsQ = useQuery({
    queryKey: ["approve-inbox-sends"],
    queryFn: async () => {
      
      return listSendOperationsInventory({ status: "CREATED" });
    },
    refetchInterval: 15_000,
  });

  const attentionQ = useNeedsAttention({ refetchIntervalMs: 15_000 });

  const destinationsQ = useQuery({
    queryKey: ["approve-inbox-destinations"],
    queryFn: async () => {
      
      return listDestinationsInventory();
    },
    refetchInterval: 30_000,
  });

  const integrationReqQ = useQuery({
    queryKey: ["approve-inbox-integration-requests"],
    queryFn: async () => listIntegrationRequests({ status: "PENDING" }),
    refetchInterval: 15_000,
  });

  const deviceKeysQ = useQuery({
    queryKey: ["device-keys"],
    queryFn: listDeviceKeys,
    enabled: blessTarget !== null ,
  });
  const selectedDeviceKeyId = deviceKeyId || deviceKeysQ.data?.[0]?.id || "";

  const sendsLive = pendingSendsQ.data?.live === true;
  const sends: readonly OperationListItem[] = sendsLive ? (pendingSendsQ.data?.data ?? []) : [];
  const attentionLive = attentionQ.data?.live === true;
  const attentionOps: readonly NeedsAttentionListItem[] = attentionLive
    ? (attentionQ.data?.data.operations ?? [])
    : [];
  const destLive = destinationsQ.data?.live === true;
  const pendingBless: readonly DestinationItem[] = destLive
    ? (destinationsQ.data?.data ?? []).filter((d) => d.state === "PENDING")
    : [];
  const irLive = integrationReqQ.data?.live === true;
  const pendingIntegration: readonly IntegrationRequestItem[] = irLive
    ? (integrationReqQ.data?.data ?? [])
    : [];

  /** Recovery cards: attention rows that aren't already listed as CREATED sends. */
  const recoveryCards = useMemo(() => {
    const sendIds = new Set(sends.map((s) => s.operation_id));
    return attentionOps.filter((a) => {
      if (sendIds.has(a.operation_id) && a.status === "CREATED") return false;
      return a.attention_required || a.permitted_actions.length > 0;
    });
  }, [attentionOps, sends]);

  /** Primary sources for "is the inbox empty?" — dest is additive. */
  const primaryLive = sendsLive || attentionLive || irLive;
  const anySourceLoading =
    pendingSendsQ.isLoading ||
    attentionQ.isLoading ||
    destinationsQ.isLoading ||
    integrationReqQ.isLoading;
  const primaryUnavailable =
    !anySourceLoading &&
    !primaryLive &&
    pendingSendsQ.data !== undefined &&
    attentionQ.data !== undefined;

  const totalPending = countApproveInboxItems({
    sends,
    attentionOps,
    pendingBless,
    pendingIntegration,
  });
  // Both primary sources must be live before claiming clear (partial outage ≠ empty).
  const inboxClear =
    sendsLive && attentionLive && !anySourceLoading && totalPending === 0;

  async function openSend(operationId: string) {
    setErr(null);
    setMsg(null);
    setPollNote(null);
    if (expandedId === operationId) {
      setExpandedId(null);
      setExpandedSend(null);
      return;
    }
    setExpandedId(operationId);
    setExpandedSend({ challenge: null, challengeErr: null, loading: true });
    try {
      const challenge = await getApprovalChallenge(operationId);
      setExpandedSend({ challenge, challengeErr: null, loading: false });
    } catch (e) {
      setExpandedSend({
        challenge: null,
        challengeErr: formatMoneyError(e, "Approval challenge unavailable"),
        loading: false,
      });
    }
  }

  // Device signature over challenge preimage — held across TOTP re-prompts (ZTR-1194 / ZTR-1256).
  const approveDeviceRef = useRef<{
    operationId: string;
    nonce: string;
    device_key_id: string | null;
    device_signature: string | null;
  } | null>(null);

  const localDeviceQ = useQuery({
    queryKey: ["approve-inbox-local-device"],
    queryFn: getLocalApproveDeviceAvailability,
    staleTime: 15_000,
  });
  const canDeviceSign = localDeviceQ.data?.canSign === true;

  const approve = useTotpGatedMutation(
    async (operationId: string, totp: string) => {
      const c = expandedSend?.challenge;
      if (!c || c.operation_id !== operationId) {
        throw new Error("Open the approval challenge before approving");
      }
      let held = approveDeviceRef.current;
      if (held === null || held.operationId !== operationId || held.nonce !== c.nonce) {
        const signed = await signApproveChallengePreimage(c.preimage_text);
        held = {
          operationId,
          nonce: c.nonce,
          device_key_id: signed.device_key_id,
          device_signature: signed.device_signature,
        };
        approveDeviceRef.current = held;
      }
      const result = await postApprove(
        operationId,
        {
          challenge_nonce: c.nonce,
          expected_row_version: c.row_version,
          preimage_sha256: c.preimage_sha256,
          device_key_id: held.device_key_id,
          device_signature: held.device_signature,
        },
        totp,
      );
      approveDeviceRef.current = null;
      const polled = await pollSendState(operationId);
      setPollNote(
        polled.status === "unknown"
          ? "Approved — polling status… (approve ≠ paid; node never submits SEND on-chain)"
          : `Approved · observed ${polled.status}. Waiting for recipient to finish — not paid yet.`,
      );
      return result;
    },
    {
      title: "Approve outgoing send",
      detail: (id) => `Device sign + fresh TOTP for ${id}`,
      onSuccess: () => {
        approveDeviceRef.current = null;
        setErr(null);
        setMsg(
          "Approved. Formation may run next; the node never submits SEND_EXTERNAL on-chain. Approve ≠ redeemed ≠ paid.",
        );
        setExpandedId(null);
        setExpandedSend(null);
        void qc.invalidateQueries({ queryKey: ["approve-inbox-sends"] });
        invalidateNeedsAttention(qc);
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        approveDeviceRef.current = null;
        setMsg(null);
        setErr(formatApproveFailure(e, "Approve failed"));
      },
    },
  );

  const reject = useTotpGatedMutation(
    async (
      vars: { operationId: string; rowVersion: number },
      totp: string,
    ) =>
      postReject(
        vars.operationId,
        { expected_row_version: vars.rowVersion, reason: rejectReason },
        totp,
      ),
    {
      title: "Reject outgoing send",
      detail: (v) => `Permanently reject CREATED send ${v.operationId}`,
      onSuccess: () => {
        setErr(null);
        setMsg("Rejected.");
        setPollNote(null);
        setExpandedId(null);
        setExpandedSend(null);
        void qc.invalidateQueries({ queryKey: ["approve-inbox-sends"] });
        invalidateNeedsAttention(qc);
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Reject failed"));
      },
    },
  );

  function openIntegrationRequest(row: IntegrationRequestItem) {
    setErr(null);
    setMsg(null);
    if (irExpandedId === row.id) {
      setIrExpandedId(null);
      return;
    }
    setIrExpandedId(row.id);
    setIrDraft(parseProposedIntegrationRule(row.proposed_rule_json));
  }

  const approveIntegration = useTotpGatedMutation(
    async (row: IntegrationRequestItem, totp: string) => {
      const hoursRaw = irDraft.window_hours.trim();
      if (!/^[1-9][0-9]{0,8}$/.test(hoursRaw)) {
        throw new Error("window_hours must be a positive integer");
      }
      const hours = parseInt(hoursRaw, 10);
      return postIntegrationRequestApprove(
        row.id,
        {
          expected_row_version: row.row_version,
          rule: {
            rule_id: irDraft.rule_id.trim() || "integration",
            per_send_max_zkz: irDraft.per_send_max_zkz.trim(),
            per_send_min_zkz:
              irDraft.per_send_min_zkz.trim() === "" ? null : irDraft.per_send_min_zkz.trim(),
            window_hours: hours,
            window_cap_zkz: irDraft.window_cap_zkz.trim(),
            expires_at: irDraft.expires_at.trim() === "" ? null : irDraft.expires_at.trim(),
            enabled: irDraft.enabled,
          },
        },
        totp,
      );
    },
    {
      title: "Approve integration request",
      detail: (row) => `Bind rule for ${row.display_name}`,
      onSuccess: () => {
        setErr(null);
        setMsg("Integration approved. Platform may claim the key next — no credential issued here.");
        setIrExpandedId(null);
        void qc.invalidateQueries({ queryKey: ["approve-inbox-integration-requests"] });
        void qc.invalidateQueries({ queryKey: ["implementers"] });
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Integration approve failed"));
      },
    },
  );

  const declineIntegration = useTotpGatedMutation(
    async (row: IntegrationRequestItem, totp: string) =>
      postIntegrationRequestDecline(
        row.id,
        { expected_row_version: row.row_version },
        totp,
      ),
    {
      title: "Decline integration request",
      detail: (row) => `Decline ${row.display_name}`,
      onSuccess: () => {
        setErr(null);
        setMsg("Integration request declined.");
        setIrExpandedId(null);
        void qc.invalidateQueries({ queryKey: ["approve-inbox-integration-requests"] });
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Integration decline failed"));
      },
    },
  );

  const recoveryAction = useTotpGatedMutation(
    async (vars: { operationId: string; action: string }, totp: string) => {
      if (!isLiveRecoveryAction(vars.action)) {
        throw new Error(`Recovery action not implemented on this node: ${vars.action}`);
      }
      const fresh = await getRecovery(vars.operationId);
      return postRecoveryAction(
        vars.operationId,
        {
          action: vars.action,
          expected_row_version: fresh.row_version,
          recovery_nonce: fresh.recovery_nonce,
        },
        totp,
      );
    },
    {
      title: "Confirm recovery action",
      detail: (v) => `${v.action} on ${v.operationId}`,
      onSuccess: () => {
        setErr(null);
        setMsg("Recovery action accepted.");
        invalidateNeedsAttention(qc);
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Recovery action failed"));
      },
    },
  );

  const bless = useTotpGatedMutation(
    async (
      body: {
        destinationId: string;
        device_key_id: string;
        dest: DestinationItem;
      },
      totp: string,
    ) => {
      const dest = body.dest;
      if (!dest.node_id) {
        throw new Error("Destination missing node_id — cannot build bless preimage.");
      }

      let nonce: string;
      let issued_at: string;
      let expires_at: string;
      let device_signature: string;

      if (showBlessBreakGlass && manualBlessSig.trim().length > 0) {
        nonce = manualBlessNonce.trim();
        issued_at = manualBlessIssued.trim();
        expires_at = manualBlessExpires.trim();
        device_signature = manualBlessSig.trim();
      } else {
        const local = await getDeviceRecord(body.device_key_id);
        if (local === null) {
          throw new Error(
            "No local private key for this device. Open Devices on the enrolled browser, or use break-glass advanced paste.",
          );
        }
        const window = ceremonyWindowFromNow();
        nonce = randomUuid();
        issued_at = window.issued_at;
        expires_at = window.expires_at;
        const preimage = buildDestinationBlessPreimage({
          node_id: dest.node_id,
          destination_id: dest.destination_id,
          wallet_id: dest.wallet_id,
          wallet_pubkey: dest.wallet_public_key,
          nonce,
          issued_at,
          expires_at,
        });
        device_signature = await signPreimage(local.privateKey, preimage);
      }

      return postBless(
        body.destinationId,
        {
          nonce,
          issued_at,
          expires_at,
          device_key_id: body.device_key_id,
          device_signature,
        },
        totp,
      );
    },
    {
      title: "Bless destination",
      detail: "Review → device sign → fresh TOTP (TOTP alone cannot bless)",
      onSuccess: () => {
        setErr(null);
        setMsg("Bless accepted.");
        setBlessTarget(null);
        setShowBlessBreakGlass(false);
        setManualBlessNonce("");
        setManualBlessIssued("");
        setManualBlessExpires("");
        setManualBlessSig("");
        void qc.invalidateQueries({ queryKey: ["approve-inbox-destinations"] });
        invalidateNeedsAttention(qc);
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Bless failed"));
      },
    },
  );

  const setupIncomplete = Boolean(user?.mustEnrolTotp || user?.mustChangePassword);

  return (
    <div className="page approve-inbox">
      <div className="page-title-row">
        <h1>Approve</h1>
        <div className="toolbar">
          <span className="muted" style={{ fontSize: 12.5 }} data-testid="approve-inbox-status">
            {anySourceLoading
                ? "Loading…"
                : primaryLive
                  ? `${totalPending} pending`
                  : "Unavailable"}
          </span>
        </div>
      </div>

      <p className="approve-honesty muted" data-testid="approve-honesty">
        Approve authorises formation only — it is <strong>not</strong> paid, redeemed, or
        on-chain. The node <strong>never</strong> submits <code className="mono">SEND_EXTERNAL</code>.
        After approve: forming → waiting for recipient to finish → landed or attention.
      </p>

      {msg ? (
        <div className="banner banner-ok" role="status" style={{ marginBottom: 12 }}>
          {msg}
        </div>
      ) : null}
      {err ? (
        <div className="banner banner-error" role="alert" style={{ marginBottom: 12 }}>
          {err}
        </div>
      ) : null}
      {pollNote ? (
        <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }} data-testid="approve-poll-note">
          {pollNote}
        </p>
      ) : null}

      {setupIncomplete ? (
        <div className="banner banner-error" data-testid="approve-setup-incomplete">
          Setup incomplete — finish password and TOTP enrolment before approving money moves.{" "}
          <Link className="linkish" to="/setup">
            Continue setup
          </Link>
        </div>
      ) : null}

      {anySourceLoading ? (
        <div className="empty" data-testid="approve-loading">
          Loading…
        </div>
      ) : null}

      {primaryUnavailable ? (
        <div className="empty approve-empty" data-testid="approve-empty-unavailable">
          <p style={{ margin: "0 0 8px" }}>
            Inbox unavailable — not implying clear. Check node health and operator session.
          </p>
          <ApiErrorNote error={pendingSendsQ.data?.error ?? attentionQ.data?.error} />
        </div>
      ) : null}

      {inboxClear ? (
        <div className="empty approve-empty" data-testid="approve-empty-clear">
          <p style={{ margin: "0 0 8px", fontWeight: 550 }}>Inbox clear</p>
          <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>
            No pending outgoing approvals, bless requests, or recovery actions. Healthy lands do
            not appear here — open{" "}
            <Link className="linkish" to="/operations">
              Operations
            </Link>{" "}
            or{" "}
            <Link className="linkish" to="/transfers">
              Transfers
            </Link>{" "}
            for history.
          </p>
        </div>
      ) : null}

      {/* ── Pending integration requests (ZTR-1240) ───────────────────── */}
      {pendingIntegration.length > 0 ? (
        <section className="approve-section" aria-labelledby="approve-ir-h">
          <h2 id="approve-ir-h" className="approve-section-title">
            Integration requests
          </h2>
          <ul className="approve-cards">
            {pendingIntegration.map((row) => {
              const open = irExpandedId === row.id;
              const proposed = parseProposedIntegrationRule(row.proposed_rule_json);
              return (
                <li
                  key={row.id}
                  className="approve-card"
                  data-testid="approve-integration-card"
                >
                  <div className="approve-card-head">
                    <span className="approve-op-label">{row.display_name}</span>
                    <StatusTag status={row.status} />
                  </div>
                  <div className="approve-card-body">
                    <div className="approve-row">
                      <span className="k">Scopes</span>
                      <span className="v mono" style={{ fontSize: 12 }}>
                        {row.requested_scopes.join(", ")}
                      </span>
                    </div>
                    <div className="approve-row">
                      <span className="k">Proposed max</span>
                      <span className="v money">{proposed.per_send_max_zkz || "—"} ZKZ</span>
                    </div>
                    <div className="approve-row">
                      <span className="k">Proposed window cap</span>
                      <span className="v money">{proposed.window_cap_zkz || "—"} ZKZ</span>
                    </div>
                    <div className="approve-row">
                      <span className="k">Expires</span>
                      <span className="v">{row.expires_at}</span>
                    </div>
                    <div className="approve-row">
                      <span className="k">Reference</span>
                      <span className="v mono">{row.id}</span>
                    </div>
                  </div>

                  {open ? (
                    <div className="approve-actions" data-testid="approve-integration-actions">
                      <p className="muted" style={{ fontSize: 12, margin: "0 0 8px" }}>
                        Edit caps before approve. Your values become the binding rule; the
                        platform proposal stays on record. No credential is issued here.
                      </p>
                      <div className="field">
                        <label htmlFor={`ir-rule-id-${row.id}`}>Rule id</label>
                        <input
                          id={`ir-rule-id-${row.id}`}
                          value={irDraft.rule_id}
                          onChange={(e) => setIrDraft((d) => ({ ...d, rule_id: e.target.value }))}
                        />
                      </div>
                      <div className="field">
                        <label htmlFor={`ir-max-${row.id}`}>Per-send max (ZKZ)</label>
                        <input
                          id={`ir-max-${row.id}`}
                          value={irDraft.per_send_max_zkz}
                          onChange={(e) =>
                            setIrDraft((d) => ({ ...d, per_send_max_zkz: e.target.value }))
                          }
                        />
                      </div>
                      <div className="field">
                        <label htmlFor={`ir-min-${row.id}`}>Per-send min (optional)</label>
                        <input
                          id={`ir-min-${row.id}`}
                          value={irDraft.per_send_min_zkz}
                          onChange={(e) =>
                            setIrDraft((d) => ({ ...d, per_send_min_zkz: e.target.value }))
                          }
                        />
                      </div>
                      <div className="field">
                        <label htmlFor={`ir-cap-${row.id}`}>Window cap (ZKZ)</label>
                        <input
                          id={`ir-cap-${row.id}`}
                          value={irDraft.window_cap_zkz}
                          onChange={(e) =>
                            setIrDraft((d) => ({ ...d, window_cap_zkz: e.target.value }))
                          }
                        />
                      </div>
                      <div className="field">
                        <label htmlFor={`ir-hours-${row.id}`}>Window hours</label>
                        <input
                          id={`ir-hours-${row.id}`}
                          value={irDraft.window_hours}
                          onChange={(e) =>
                            setIrDraft((d) => ({ ...d, window_hours: e.target.value }))
                          }
                        />
                      </div>
                      <div className="approve-action-bar">
                        <button
                          type="button"
                          className="mini-btn primary approve-primary"
                          disabled={approveIntegration.isPending || declineIntegration.isPending}
                          onClick={() => {
                            setErr(null);
                            setMsg(null);
                            approveIntegration.mutate(row);
                          }}
                        >
                          {approveIntegration.isPending ? "Approving…" : "Approve (TOTP)"}
                        </button>
                        <button
                          type="button"
                          className="mini-btn danger"
                          disabled={approveIntegration.isPending || declineIntegration.isPending}
                          onClick={() => {
                            setErr(null);
                            setMsg(null);
                            declineIntegration.mutate(row);
                          }}
                        >
                          {declineIntegration.isPending ? "Declining…" : "Decline (TOTP)"}
                        </button>
                      </div>
                    </div>
                  ) : null}

                  <div className="approve-card-foot">
                    <button
                      type="button"
                      className="mini-btn primary approve-primary"
                      onClick={() => openIntegrationRequest(row)}
                      aria-expanded={open}
                    >
                      {open ? "Close" : "Review & edit"}
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}

      {/* ── Pending SEND_EXTERNAL ─────────────────────────────────────── */}
      {sends.length > 0 ? (
        <section className="approve-section" aria-labelledby="approve-sends-h">
          <h2 id="approve-sends-h" className="approve-section-title">
            Outgoing (needs approval)
          </h2>
          <ul className="approve-cards">
            {sends.map((s) => {
              const open = expandedId === s.operation_id;
              const challenge = open ? expandedSend?.challenge : null;
              const amount = challenge?.amount_zkz ?? s.amount_zkz;
              const dest =
                challenge?.destination_address ?? s.destination_address ?? "—";
              const rowVersion =
                challenge?.row_version ?? s.row_version;
              return (
                <li key={s.operation_id} className="approve-card" data-testid="approve-send-card">
                  <div className="approve-card-head">
                    <span className="approve-op-label">{operationKindLabel(s.operation_type)}</span>
                    <StatusTag status={s.status} />
                  </div>
                  <div className="approve-card-body">
                    <div className="approve-row">
                      <span className="k">Amount</span>
                      <span className="v money">{amount} ZKZ</span>
                    </div>
                    <div className="approve-row">
                      <span className="k">To</span>
                      <span className="v mono">{truncatePubkey(dest, 10, 6)}</span>
                    </div>
                    <div className="approve-row">
                      <span className="k">Reference</span>
                      <span className="v mono">{s.operation_id}</span>
                    </div>
                    {challenge ? (
                      <>
                        <div className="approve-row">
                          <span className="k">Preimage</span>
                          <span className="v mono" title={challenge.preimage_sha256}>
                            {shortDigest(challenge.preimage_sha256)}
                          </span>
                        </div>
                        <div className="approve-row">
                          <span className="k">Expires</span>
                          <span className="v">{challenge.expires_at}</span>
                        </div>
                      </>
                    ) : null}
                  </div>

                  {open && expandedSend?.loading ? (
                    <p className="muted" style={{ fontSize: 12.5, margin: "8px 0" }}>
                      Loading challenge…
                    </p>
                  ) : null}
                  {open && expandedSend?.challengeErr ? (
                    <div className="banner banner-error" style={{ marginTop: 8 }}>
                      {expandedSend.challengeErr}
                    </div>
                  ) : null}

                  {open && challenge  ? (
                    <div className="approve-actions" data-testid="approve-send-actions">
                      <p className="muted" style={{ fontSize: 12, margin: "0 0 8px" }}>
                        Device signature + TOTP required. Approve starts formation only — not
                        settlement.
                      </p>
                      {!localDeviceQ.isLoading && !canDeviceSign ? (
                        <p
                          className="banner banner-error"
                          role="status"
                          data-testid="approve-send-no-device"
                          style={{ marginBottom: 8 }}
                        >
                          No enrolled device key on this browser — enrol a device before approving.{" "}
                          <Link to="/devices" className="linkish">
                            Open devices
                          </Link>
                        </p>
                      ) : null}
                      <div className="field">
                        <label htmlFor={`reject-reason-${s.operation_id}`}>Reject reason</label>
                        <input
                          id={`reject-reason-${s.operation_id}`}
                          value={rejectReason}
                          onChange={(e) => setRejectReason(e.target.value)}
                          maxLength={512}
                        />
                      </div>
                      <div className="approve-action-bar">
                        <button
                          type="button"
                          className="mini-btn primary approve-primary"
                          data-testid="approve-send-submit"
                          disabled={
                            approve.isPending ||
                            reject.isPending ||
                            localDeviceQ.isLoading ||
                            !canDeviceSign
                          }
                          title={
                            !canDeviceSign
                              ? "Enrol a device key on this browser first"
                              : undefined
                          }
                          onClick={() => {
                            setErr(null);
                            setMsg(null);
                            approve.mutate(s.operation_id);
                          }}
                        >
                          {approve.isPending ? "Approving…" : "Approve (device + TOTP)"}
                        </button>
                        <button
                          type="button"
                          className="mini-btn danger"
                          disabled={approve.isPending || reject.isPending}
                          onClick={() => {
                            setErr(null);
                            setMsg(null);
                            reject.mutate({
                              operationId: s.operation_id,
                              rowVersion,
                            });
                          }}
                        >
                          {reject.isPending ? "Rejecting…" : "Reject (TOTP)"}
                        </button>
                      </div>
                    </div>
                  ) : null}

                  <div className="approve-card-foot">
                    <button
                      type="button"
                      className="mini-btn primary approve-primary"
                      onClick={() => void openSend(s.operation_id)}
                      aria-expanded={open}
                    >
                      {open ? "Close" : "Review & decide"}
                    </button>
                    <Link
                      className="mini-btn"
                      to={operationDetailPath(s.operation_id, s.operation_type)}
                    >
                      Open detail
                    </Link>
                  </div>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}

      {/* ── Pending bless ─────────────────────────────────────────────── */}
      {pendingBless.length > 0 ? (
        <section className="approve-section" aria-labelledby="approve-bless-h">
          <h2 id="approve-bless-h" className="approve-section-title">
            Bless destination
          </h2>
          <ul className="approve-cards">
            {pendingBless.map((d) => {
              const open = blessTarget === d.destination_id;
              return (
                <li key={d.destination_id} className="approve-card" data-testid="approve-bless-card">
                  <div className="approve-card-head">
                    <span className="approve-op-label">Bless</span>
                    <StatusTag status={d.state} />
                  </div>
                  <div className="approve-card-body">
                    <div className="approve-row">
                      <span className="k">Label</span>
                      <span className="v">{d.label || "—"}</span>
                    </div>
                    <div className="approve-row">
                      <span className="k">Id</span>
                      <span className="v mono">{d.destination_id}</span>
                    </div>
                    <div className="approve-row">
                      <span className="k">Pubkey</span>
                      <span className="v mono">{truncatePubkey(d.wallet_public_key)}</span>
                    </div>
                  </div>
                  {open ? (
                    <div className="approve-actions">
                      <p className="muted" style={{ fontSize: 12, margin: "0 0 8px" }}>
                        One-tap bless: this browser signs with the enrolled device key, then fresh
                        TOTP. Manual nonce/signature paste is break-glass only.
                      </p>
                      {(deviceKeysQ.data?.length ?? 0) === 0 && !deviceKeysQ.isLoading ? (
                        <p className="muted" data-testid="approve-bless-no-device">
                          No enrolled device keys — bless disabled until a device is enrolled.
                        </p>
                      ) : (
                        <>
                          <div className="field">
                            <label htmlFor={`bless-device-${d.destination_id}`}>Device key</label>
                            <select
                              id={`bless-device-${d.destination_id}`}
                              className="mono"
                              value={selectedDeviceKeyId}
                              onChange={(e) => setDeviceKeyId(e.target.value)}
                              required
                            >
                              {(deviceKeysQ.data ?? []).map((dk) => (
                                <option key={dk.id} value={dk.id}>
                                  {dk.label} — {dk.id}
                                </option>
                              ))}
                            </select>
                          </div>
                          <div className="approve-action-bar">
                            <button
                              type="button"
                              className="mini-btn primary approve-primary"
                              data-testid="approve-bless-one-tap"
                              disabled={
                                bless.isPending ||
                                deviceKeysQ.isLoading ||
                                selectedDeviceKeyId.length === 0
                              }
                              onClick={() => {
                                setErr(null);
                                setMsg(null);
                                if (selectedDeviceKeyId.length === 0) {
                                  setErr(
                                    "No enrolled device key — enrol a device before blessing (device signature is required; TOTP alone is rejected).",
                                  );
                                  return;
                                }
                                bless.mutate({
                                  destinationId: d.destination_id,
                                  device_key_id: selectedDeviceKeyId,
                                  dest: d,
                                });
                              }}
                            >
                              {bless.isPending ? "Blessing…" : "Bless (device + TOTP)"}
                            </button>
                          </div>
                          <details
                            style={{ marginTop: 10 }}
                            open={showBlessBreakGlass}
                            onToggle={(e) =>
                              setShowBlessBreakGlass((e.target as HTMLDetailsElement).open)
                            }
                          >
                            <summary className="muted" style={{ fontSize: 12, cursor: "pointer" }}>
                              Break-glass: paste nonce / timestamps / signature
                            </summary>
                            <div style={{ marginTop: 8 }}>
                              <div className="field">
                                <label htmlFor={`bless-nonce-${d.destination_id}`}>Nonce</label>
                                <input
                                  id={`bless-nonce-${d.destination_id}`}
                                  className="mono"
                                  value={manualBlessNonce}
                                  onChange={(e) => setManualBlessNonce(e.target.value)}
                                />
                              </div>
                              <div className="field">
                                <label htmlFor={`bless-issued-${d.destination_id}`}>
                                  Issued at (ISO)
                                </label>
                                <input
                                  id={`bless-issued-${d.destination_id}`}
                                  className="mono"
                                  value={manualBlessIssued}
                                  onChange={(e) => setManualBlessIssued(e.target.value)}
                                />
                              </div>
                              <div className="field">
                                <label htmlFor={`bless-expires-${d.destination_id}`}>
                                  Expires at (ISO)
                                </label>
                                <input
                                  id={`bless-expires-${d.destination_id}`}
                                  className="mono"
                                  value={manualBlessExpires}
                                  onChange={(e) => setManualBlessExpires(e.target.value)}
                                />
                              </div>
                              <div className="field">
                                <label htmlFor={`bless-sig-${d.destination_id}`}>
                                  Device signature
                                </label>
                                <input
                                  id={`bless-sig-${d.destination_id}`}
                                  className="mono"
                                  value={manualBlessSig}
                                  onChange={(e) => setManualBlessSig(e.target.value)}
                                />
                              </div>
                              <button
                                type="button"
                                className="mini-btn"
                                disabled={
                                  bless.isPending ||
                                  selectedDeviceKeyId.length === 0 ||
                                  manualBlessSig.trim().length === 0
                                }
                                onClick={() => {
                                  setErr(null);
                                  setMsg(null);
                                  setShowBlessBreakGlass(true);
                                  bless.mutate({
                                    destinationId: d.destination_id,
                                    device_key_id: selectedDeviceKeyId,
                                    dest: d,
                                  });
                                }}
                              >
                                Bless with pasted signature (TOTP)
                              </button>
                            </div>
                          </details>
                        </>
                      )}
                    </div>
                  ) : null}
                  <div className="approve-card-foot">
                    <button
                      type="button"
                      className="mini-btn primary approve-primary"
                      onClick={() => {
                        setBlessTarget(open ? null : d.destination_id);
                        setErr(null);
                      }}
                    >
                      {open ? "Close" : "Bless…"}
                    </button>
                    <Link className="mini-btn" to="/destinations">
                      Destinations
                    </Link>
                  </div>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}

      {/* ── Recovery attentions ───────────────────────────────────────── */}
      {recoveryCards.length > 0 ? (
        <section className="approve-section" aria-labelledby="approve-recovery-h">
          <h2 id="approve-recovery-h" className="approve-section-title">
            Recovery
          </h2>
          <ul className="approve-cards">
            {recoveryCards.map((a) => (
                <li key={a.operation_id} className="approve-card" data-testid="approve-recovery-card">
                  <div className="approve-card-head">
                    <span className="approve-op-label">{operationKindLabel(a.operation_type)}</span>
                    <StatusTag status={a.classification} />
                  </div>
                  <div className="approve-card-body">
                    <div className="approve-row">
                      <span className="k">Status</span>
                      <span className="v">{statusLabel(a.status)}</span>
                    </div>
                    <div className="approve-row">
                      <span className="k">Reference</span>
                      <span className="v mono">{a.operation_id}</span>
                    </div>
                    {a.attention_reason ? (
                      <div className="approve-row">
                        <span className="k">Reason</span>
                        <span className="v">{statusLabel(a.attention_reason)}</span>
                      </div>
                    ) : null}
                    <p className="muted" style={{ fontSize: 12, margin: "6px 0 0" }}>
                      {a.classification_rationale}
                    </p>
                  </div>
                  <RecoveryActions
                    permittedActions={a.permitted_actions}
                    disabled={recoveryAction.isPending}
                    testIdPrefix="approve-recovery"
                    onAction={(action) => {
                      setErr(null);
                      setMsg(null);
                      recoveryAction.mutate({ operationId: a.operation_id, action });
                    }}
                  />
                  <div className="approve-card-foot">
                    <Link
                      className="mini-btn"
                      to={operationDetailPath(a.operation_id, a.operation_type)}
                    >
                      Open detail
                    </Link>
                  </div>
                </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
