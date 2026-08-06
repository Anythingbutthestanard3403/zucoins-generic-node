/**
 * Mobile-first Approve inbox.
 * Surfaces pending SEND_EXTERNAL approvals, destination bless requests, and
 * implemented recovery-action attentions without hunting Activity.
 *
 * Normative honesty:
 * - Approve ≠ redeemed ≠ paid; node never submits SEND_EXTERNAL on-chain.
 * - Post-approve: forming → waiting for recipient to finish → landed/attention.
 * - Only implemented recovery effect kinds are actionable.
 * - TOTP is required for every money mutation; device signature is additive only.
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { StatusTag } from "../../components/StatusTag.js";
import { apiOrDemo } from "../../lib/api.js";
import { truncatePubkey } from "../../lib/format.js";
import {
  formatMoneyError,
  getApprovalChallenge,
  isCancelled,
  listDestinationsInventory,
  listDeviceKeys,
  listSendOperationsInventory,
  operationDetailPath,
  pollSendState,
  postApprove,
  postBless,
  postRecoveryAction,
  postReject,
  getRecovery,
  type ApprovalChallenge,
  type DestinationItem,
  type OperationListItem,
} from "../../lib/money.js";
import {
  EMPTY_NEEDS_ATTENTION,
  type NeedsAttentionListItem,
  type NeedsAttentionResponse,
} from "../../lib/ops.js";
import { useAuth } from "../../store/auth.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

/** Effect kinds the SQL recovery store can actually commit (sql-recovery-store.ts). */
export const IMPLEMENTED_RECOVERY_ACTIONS = new Set([
  "RETRY_OBSERVATION",
  "ACKNOWLEDGE_KEEP_PINNED",
  "QUARANTINE_WALLETS",
  "RELEASE_EXPIRED_RECEIVE",
]);

function shortDigest(hex: string | null | undefined): string {
  if (!hex || hex.length < 12) return hex ?? "—";
  return `${hex.slice(0, 8)}…${hex.slice(-4)}`;
}

function opLabel(kind: string): string {
  const k = kind.toUpperCase();
  if (k === "SEND_EXTERNAL" || k.includes("SEND")) return "Outgoing (needs approval)";
  if (k.includes("RECEIVE")) return "Incoming";
  if (k.includes("MOVE")) return "Internal transfer";
  return kind;
}

type ExpandedSend = {
  challenge: ApprovalChallenge | null;
  challengeErr: string | null;
  loading: boolean;
};

export function ApproveInboxPage() {
  const demoMode = useAuth((s) => s.demoMode);
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
  const [blessNonce, setBlessNonce] = useState("");
  const [blessIssued, setBlessIssued] = useState("");
  const [blessExpires, setBlessExpires] = useState("");
  const [deviceKeyId, setDeviceKeyId] = useState("");
  const [deviceSig, setDeviceSig] = useState("");

  const pendingSendsQ = useQuery({
    queryKey: ["approve-inbox-sends", demoMode],
    queryFn: async () => {
      if (demoMode) return { live: false as const, data: [] as const, error: undefined };
      return listSendOperationsInventory({ status: "CREATED" });
    },
    refetchInterval: demoMode ? false : 15_000,
  });

  const attentionQ = useQuery({
    queryKey: ["approve-inbox-attention", demoMode],
    queryFn: async () =>
      apiOrDemo<NeedsAttentionResponse>("/operations/needs-attention", EMPTY_NEEDS_ATTENTION),
    refetchInterval: demoMode ? false : 15_000,
  });

  const destinationsQ = useQuery({
    queryKey: ["approve-inbox-destinations", demoMode],
    queryFn: async () => {
      if (demoMode) return { live: false as const, data: [] as const, error: undefined };
      return listDestinationsInventory();
    },
    refetchInterval: demoMode ? false : 30_000,
  });

  const deviceKeysQ = useQuery({
    queryKey: ["device-keys", demoMode],
    queryFn: listDeviceKeys,
    enabled: blessTarget !== null && !demoMode,
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

  /** Recovery cards: attention rows that aren't already listed as CREATED sends. */
  const recoveryCards = useMemo(() => {
    const sendIds = new Set(sends.map((s) => s.operation_id));
    return attentionOps.filter((a) => {
      if (sendIds.has(a.operation_id) && a.status === "CREATED") return false;
      return a.attention_required || a.permitted_actions.length > 0;
    });
  }, [attentionOps, sends]);

  /** Primary sources for "is the inbox empty?" — dest is additive. */
  const primaryLive = sendsLive || attentionLive;
  const anySourceLoading =
    pendingSendsQ.isLoading || attentionQ.isLoading || destinationsQ.isLoading;
  const primaryUnavailable =
    !demoMode &&
    !anySourceLoading &&
    !primaryLive &&
    pendingSendsQ.data !== undefined &&
    attentionQ.data !== undefined;

  const totalPending = sends.length + pendingBless.length + recoveryCards.length;
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

  const approve = useTotpGatedMutation(
    async (operationId: string, totp: string) => {
      const c = expandedSend?.challenge;
      if (!c || c.operation_id !== operationId) {
        throw new Error("Open the approval challenge before approving");
      }
      const result = await postApprove(
        operationId,
        {
          challenge_nonce: c.nonce,
          expected_row_version: c.row_version,
          preimage_sha256: c.preimage_sha256,
          device_key_id: null,
          device_signature: null,
        },
        totp,
      );
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
      detail: (id) => `Confirm dual-control approve for ${id}`,
      onSuccess: () => {
        setErr(null);
        setMsg(
          "Approved. Formation may run next; the node never submits SEND_EXTERNAL on-chain. Approve ≠ redeemed ≠ paid.",
        );
        setExpandedId(null);
        setExpandedSend(null);
        void qc.invalidateQueries({ queryKey: ["approve-inbox-sends"] });
        void qc.invalidateQueries({ queryKey: ["approve-inbox-attention"] });
        void qc.invalidateQueries({ queryKey: ["needs-attention"] });
        void qc.invalidateQueries({ queryKey: ["needs-attention-nav"] });
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Approve failed"));
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
        void qc.invalidateQueries({ queryKey: ["needs-attention-nav"] });
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Reject failed"));
      },
    },
  );

  const recoveryAction = useTotpGatedMutation(
    async (vars: { operationId: string; action: string }, totp: string) => {
      if (!IMPLEMENTED_RECOVERY_ACTIONS.has(vars.action)) {
        throw new Error(`Recovery action not implemented yet: ${vars.action}`);
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
        void qc.invalidateQueries({ queryKey: ["approve-inbox-attention"] });
        void qc.invalidateQueries({ queryKey: ["needs-attention"] });
        void qc.invalidateQueries({ queryKey: ["needs-attention-nav"] });
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
        nonce: string;
        issued_at: string;
        expires_at: string;
        device_key_id: string;
        device_signature: string;
      },
      totp: string,
    ) =>
      postBless(
        body.destinationId,
        {
          nonce: body.nonce,
          issued_at: body.issued_at,
          expires_at: body.expires_at,
          device_key_id: body.device_key_id,
          device_signature: body.device_signature,
        },
        totp,
      ),
    {
      title: "Bless destination",
      detail: "Device signature + fresh TOTP (TOTP alone cannot bless)",
      onSuccess: () => {
        setErr(null);
        setMsg("Bless accepted.");
        setBlessTarget(null);
        void qc.invalidateQueries({ queryKey: ["approve-inbox-destinations"] });
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
            {demoMode
              ? "Design preview"
              : anySourceLoading
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

      {demoMode ? (
        <div className="empty approve-empty" data-testid="approve-empty-demo">
          No fixtures — sign in against a live node to review pending outgoing approvals,
          bless requests, and recovery actions.
        </div>
      ) : null}

      {!demoMode && setupIncomplete ? (
        <div className="banner banner-error" data-testid="approve-setup-incomplete">
          Setup incomplete — finish password and TOTP enrolment before approving money moves.{" "}
          <Link className="linkish" to="/setup">
            Continue setup
          </Link>
        </div>
      ) : null}

      {!demoMode && anySourceLoading ? (
        <div className="empty" data-testid="approve-loading">
          Loading…
        </div>
      ) : null}

      {!demoMode && primaryUnavailable ? (
        <div className="empty approve-empty" data-testid="approve-empty-unavailable">
          <p style={{ margin: "0 0 8px" }}>
            Inbox unavailable — not implying clear. Check node health and operator session.
          </p>
          <ApiErrorNote error={pendingSendsQ.data?.error ?? attentionQ.data?.error} />
        </div>
      ) : null}

      {!demoMode && inboxClear ? (
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

      {/* ── Pending SEND_EXTERNAL ─────────────────────────────────────── */}
      {!demoMode && sends.length > 0 ? (
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
                    <span className="approve-op-label">{opLabel(s.operation_type)}</span>
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

                  {open && challenge && !demoMode ? (
                    <div className="approve-actions" data-testid="approve-send-actions">
                      <p className="muted" style={{ fontSize: 12, margin: "0 0 8px" }}>
                        TOTP required. Approve starts formation only — not settlement.
                      </p>
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
                          disabled={approve.isPending || reject.isPending}
                          onClick={() => {
                            setErr(null);
                            setMsg(null);
                            approve.mutate(s.operation_id);
                          }}
                        >
                          {approve.isPending ? "Approving…" : "Approve (TOTP)"}
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
      {!demoMode && pendingBless.length > 0 ? (
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
                    <form
                      className="approve-actions"
                      onSubmit={(e) => {
                        e.preventDefault();
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
                          nonce: blessNonce.trim(),
                          issued_at: blessIssued.trim(),
                          expires_at: blessExpires.trim(),
                          device_key_id: selectedDeviceKeyId,
                          device_signature: deviceSig.trim(),
                        });
                      }}
                    >
                      <p className="muted" style={{ fontSize: 12, margin: "0 0 8px" }}>
                        Bless requires device signature + TOTP. Device enrolment is separate from
                        this inbox.
                      </p>
                      {(deviceKeysQ.data?.length ?? 0) === 0 && !deviceKeysQ.isLoading ? (
                        <p className="muted" data-testid="approve-bless-no-device">
                          No enrolled device keys — bless disabled until a device is enrolled.
                        </p>
                      ) : (
                        <>
                          <div className="field">
                            <label htmlFor={`bless-nonce-${d.destination_id}`}>Nonce</label>
                            <input
                              id={`bless-nonce-${d.destination_id}`}
                              className="mono"
                              value={blessNonce}
                              onChange={(e) => setBlessNonce(e.target.value)}
                              required
                            />
                          </div>
                          <div className="field">
                            <label htmlFor={`bless-issued-${d.destination_id}`}>Issued at (ISO)</label>
                            <input
                              id={`bless-issued-${d.destination_id}`}
                              className="mono"
                              value={blessIssued}
                              onChange={(e) => setBlessIssued(e.target.value)}
                              required
                            />
                          </div>
                          <div className="field">
                            <label htmlFor={`bless-expires-${d.destination_id}`}>Expires at (ISO)</label>
                            <input
                              id={`bless-expires-${d.destination_id}`}
                              className="mono"
                              value={blessExpires}
                              onChange={(e) => setBlessExpires(e.target.value)}
                              required
                            />
                          </div>
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
                          <div className="field">
                            <label htmlFor={`bless-sig-${d.destination_id}`}>Device signature</label>
                            <input
                              id={`bless-sig-${d.destination_id}`}
                              className="mono"
                              value={deviceSig}
                              onChange={(e) => setDeviceSig(e.target.value)}
                              required
                            />
                          </div>
                          <div className="approve-action-bar">
                            <button
                              type="submit"
                              className="mini-btn primary approve-primary"
                              disabled={
                                bless.isPending ||
                                deviceKeysQ.isLoading ||
                                selectedDeviceKeyId.length === 0
                              }
                            >
                              {bless.isPending ? "Blessing…" : "Bless (TOTP)"}
                            </button>
                          </div>
                        </>
                      )}
                    </form>
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
      {!demoMode && recoveryCards.length > 0 ? (
        <section className="approve-section" aria-labelledby="approve-recovery-h">
          <h2 id="approve-recovery-h" className="approve-section-title">
            Recovery
          </h2>
          <ul className="approve-cards">
            {recoveryCards.map((a) => {
              const implemented = a.permitted_actions.filter((x) =>
                IMPLEMENTED_RECOVERY_ACTIONS.has(x),
              );
              const unimplemented = a.permitted_actions.filter(
                (x) => !IMPLEMENTED_RECOVERY_ACTIONS.has(x),
              );
              return (
                <li key={a.operation_id} className="approve-card" data-testid="approve-recovery-card">
                  <div className="approve-card-head">
                    <span className="approve-op-label">{opLabel(a.operation_type)}</span>
                    <StatusTag status={a.classification} />
                  </div>
                  <div className="approve-card-body">
                    <div className="approve-row">
                      <span className="k">Status</span>
                      <span className="v">{a.status}</span>
                    </div>
                    <div className="approve-row">
                      <span className="k">Reference</span>
                      <span className="v mono">{a.operation_id}</span>
                    </div>
                    {a.attention_reason ? (
                      <div className="approve-row">
                        <span className="k">Reason</span>
                        <span className="v">{a.attention_reason}</span>
                      </div>
                    ) : null}
                    <p className="muted" style={{ fontSize: 12, margin: "6px 0 0" }}>
                      {a.classification_rationale}
                    </p>
                  </div>
                  {implemented.length > 0 ? (
                    <div className="approve-action-bar" style={{ marginTop: 10 }}>
                      {implemented.map((action) => (
                        <button
                          key={action}
                          type="button"
                          className="mini-btn"
                          disabled={recoveryAction.isPending}
                          onClick={() => {
                            setErr(null);
                            setMsg(null);
                            recoveryAction.mutate({ operationId: a.operation_id, action });
                          }}
                        >
                          {action}
                        </button>
                      ))}
                    </div>
                  ) : (
                    <p className="muted" style={{ fontSize: 12, marginTop: 8 }}>
                      No implemented recovery actions available on this row.
                    </p>
                  )}
                  {unimplemented.length > 0 ? (
                    <p
                      className="muted"
                      style={{ fontSize: 12, marginTop: 6 }}
                      data-testid="approve-recovery-unimplemented"
                    >
                      Not yet implemented: {unimplemented.join(", ")}
                    </p>
                  ) : null}
                  <div className="approve-card-foot">
                    <Link
                      className="mini-btn"
                      to={operationDetailPath(a.operation_id, a.operation_type)}
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
    </div>
  );
}
