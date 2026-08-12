import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Link, Navigate, useParams } from "react-router";
import { ReleaseCountdown } from "../../components/ReleaseCountdown.js";
import { StatusTag } from "../../components/StatusTag.js";
import { ApiError } from "../../lib/api.js";
import { RecoveryActions } from "../../components/RecoveryActions.js";
import {
  fetchDualControlPolicy,
  formatMoneyError,
  getApprovalChallenge,
  getOperationInventory,
  getRecovery,
  isCancelled,
  isSendOperationType,
  pollSendState,
  postApprove,
  postRecoveryAction,
  postReject,
  type ApprovalChallenge,
  type OperationInventoryDetail,
  type RecoveryDetail,
} from "../../lib/money.js";
import { APPROVE_SUCCESS_NOTE, operationKindLabel, statusLabel } from "../../lib/labels.js";
import { signApproveChallengePreimage } from "../../lib/approve-device-sign.js";
import { invalidateNeedsAttention } from "../../lib/needs-attention.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

type LoadState =
  | { kind: "loading" }
  | {
      kind: "challenge";
      challenge: ApprovalChallenge;
      recovery: RecoveryDetail | null;
      inventory: OperationInventoryDetail | null;
    }
  | {
      kind: "recovery";
      recovery: RecoveryDetail;
      inventory: OperationInventoryDetail | null;
    }
  | {
      kind: "inventory";
      inventory: OperationInventoryDetail;
      recovery: RecoveryDetail | null;
    }
  | { kind: "redirect_receive"; operationType: string }
  | { kind: "missing"; message: string };

async function loadTransfer(id: string): Promise<LoadState> {
  

  // Always try inventory first so we can route receives to the operation page
  // and fill amount/wallets when challenge is gone. Outages throw; 404 → null.
  let inventory: OperationInventoryDetail | null = null;
  try {
    inventory = await getOperationInventory(id);
  } catch {
    inventory = null;
  }

  if (inventory && !isSendOperationType(inventory.operation_type)) {
    return { kind: "redirect_receive", operationType: inventory.operation_type };
  }

  // Prefer approval-challenge while CREATED (has full money fields).
  try {
    const challenge = await getApprovalChallenge(id);
    let recovery: RecoveryDetail | null = null;
    try {
      recovery = await getRecovery(id);
    } catch {
      /* optional */
    }
    return { kind: "challenge", challenge, recovery, inventory };
  } catch (err) {
    if (!(err instanceof ApiError) || (err.status !== 404 && err.status !== 503)) {
      throw err;
    }
  }

  try {
    const recovery = await getRecovery(id);
    if (!isSendOperationType(recovery.operation_type) && !inventory) {
      return { kind: "redirect_receive", operationType: recovery.operation_type };
    }
    if (!isSendOperationType(recovery.operation_type)) {
      return { kind: "redirect_receive", operationType: recovery.operation_type };
    }
    return { kind: "recovery", recovery, inventory };
  } catch (err) {
    if (!(err instanceof ApiError) || (err.status !== 404 && err.status !== 503)) {
      throw err;
    }
  }

  if (inventory) {
    return { kind: "inventory", inventory, recovery: null };
  }

  return {
    kind: "missing",
    message:
      "No approval-challenge, recovery, or inventory row for this id. Inventory list APIs are live; approve needs a CREATED SEND_EXTERNAL.",
  };
}

export function TransferDetailPage() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState("operator_rejected");
  const [pollStatus, setPollStatus] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["transfer-detail", id],
    queryFn: () => loadTransfer(id),
    enabled: Boolean(id),
    refetchInterval: (query) => {
      const d = query.state.data;
      if (!d ) return false;
      if (d.kind === "challenge") return 10_000;
      if (d.kind === "recovery" && d.recovery.status === "APPROVED") return 5_000;
      return false;
    },
  });

  // Device signature is over the challenge preimage, not the TOTP. Capture once
  // per Approve click so a wrong-code re-prompt does not re-run WebCrypto or
  // re-fetch the challenge (ZTR-1194).
  const approveDeviceRef = useRef<{
    operationId: string;
    nonce: string;
    device_key_id: string | null;
    device_signature: string | null;
  } | null>(null);

  const approve = useTotpGatedMutation(
    async (_: void, totp: string) => {
      const data = q.data;
      if (!data || data.kind !== "challenge") {
        throw new Error("No open approval challenge");
      }
      const c = data.challenge;
      let held = approveDeviceRef.current;
      if (held === null || held.operationId !== id || held.nonce !== c.nonce) {
        // One-tap device sign over server-issued preimage_text (byte-exact).
        // TOTP remains required; device signature is additive (TOTP floor). Shared with inbox (ZTR-1256).
        const signed = await signApproveChallengePreimage(c.preimage_text);
        held = {
          operationId: id,
          nonce: c.nonce,
          device_key_id: signed.device_key_id,
          device_signature: signed.device_signature,
        };
        approveDeviceRef.current = held;
      }
      const result = await postApprove(
        id,
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
      const polled = await pollSendState(id);
      setPollStatus(polled.status === "unknown" ? result.status : polled.status);
      return result;
    },
    {
      title: "Approve external send",
      detail: `Review exact tuple → device sign → fresh TOTP for ${id}`,
      onSuccess: () => {
        approveDeviceRef.current = null;
        setErr(null);
        setMsg("Approved. Polling state…");
        void qc.invalidateQueries({ queryKey: ["transfer-detail", id] });
        invalidateNeedsAttention(qc);
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        // Terminal only — withTotpRetry holds the ref across in-loop re-prompts.
        approveDeviceRef.current = null;
        setMsg(null);
        setErr(formatMoneyError(e, "Approve failed"));
      },
    },
  );

  const reject = useTotpGatedMutation(
    async (_: void, totp: string) => {
      const data = q.data;
      let rowVersion = 1;
      if (data?.kind === "challenge") rowVersion = data.challenge.row_version;
      else if (data?.kind === "recovery") rowVersion = data.recovery.row_version;
      else if (data?.kind === "inventory") rowVersion = data.inventory.row_version;
      return postReject(id, { expected_row_version: rowVersion, reason: rejectReason }, totp);
    },
    {
      title: "Reject external send",
      detail: `Permanently reject CREATED send ${id}`,
      onSuccess: () => {
        setErr(null);
        setMsg("Rejected.");
        setPollStatus("REJECTED");
        void qc.invalidateQueries({ queryKey: ["transfer-detail", id] });
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Reject failed"));
      },
    },
  );

  const recoveryAction = useTotpGatedMutation(
    async (action: string, totp: string) => {
      const data = q.data;
      if (data?.kind !== "recovery" && data?.kind !== "challenge") {
        throw new Error("Recovery detail unavailable");
      }
      const recovery = data.recovery;
      if (!recovery) throw new Error("Open recovery first");
      // Fresh nonce per GET
      const fresh = await getRecovery(id);
      return postRecoveryAction(
        id,
        {
          action,
          expected_row_version: fresh.row_version,
          recovery_nonce: fresh.recovery_nonce,
        },
        totp,
      );
    },
    {
      title: "Confirm recovery action",
      detail: (action) => String(action),
      onSuccess: () => {
        setErr(null);
        setMsg("Recovery action accepted.");
        void qc.invalidateQueries({ queryKey: ["transfer-detail", id] });
        invalidateNeedsAttention(qc);
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Recovery action failed"));
      },
    },
  );

  if (q.isLoading || !q.data) {
    return (
      <div className="page">
        <Link to="/transfers" className="linkish">
          ← Transfers
        </Link>
        <p className="muted">Loading…</p>
      </div>
    );
  }

  if (q.isError) {
    return (
      <div className="page">
        <Link to="/transfers" className="linkish">
          ← Transfers
        </Link>
        <div className="banner banner-error">
          {formatMoneyError(q.error, "Failed to load transfer")}
        </div>
      </div>
    );
  }

  const data = q.data;

  if (data.kind === "redirect_receive") {
    return <Navigate to={`/operations/${encodeURIComponent(id)}`} replace />;
  }

  const inventory =
    data.kind === "challenge" || data.kind === "recovery" || data.kind === "inventory"
      ? data.inventory
      : null;

  const status =
    pollStatus ??
    (data.kind === "challenge"
      ? data.recovery?.status ?? inventory?.status ?? "CREATED"
      : data.kind === "recovery"
        ? data.recovery.status
        : data.kind === "inventory"
          ? data.inventory.status
          : "unknown");

  const amount =
    data.kind === "challenge"
      ? data.challenge.amount_zkz
      : inventory?.amount_zkz ?? "—";

  const from =
    data.kind === "challenge"
      ? data.challenge.source_pubkey
      : inventory?.source_wallet_id ?? "—";

  const to =
    data.kind === "challenge"
      ? data.challenge.destination_address
      : inventory?.destination_address ?? "—";

  const canApproveReject = data.kind === "challenge" ;
  const recovery =
    data.kind === "recovery"
      ? data.recovery
      : data.kind === "challenge"
        ? data.recovery
        : null;

  const isSuccess =
    recovery?.classification === "LANDED_VERIFIED" || /_LANDED$/i.test(status);

  return (
    <div className="page">
      <Link to="/transfers" className="linkish">
        ← Transfers
      </Link>
      <div className="page-title-row">
        <h1>
          Transfer <code className="mono">{id}</code>
        </h1>
        <div className="toolbar">
          <StatusTag status={status} />
          {recovery?.classification ? <StatusTag status={recovery.classification} /> : null}
          <Link className="mini-btn" to={`/operations/${encodeURIComponent(id)}`}>
            Full operation detail
          </Link>
        </div>
      </div>

      {data.kind === "missing" ? (
        <div className="banner banner-error">{data.message}</div>
      ) : null}

      {isSuccess && !recovery?.attention_required ? (
        <div className="banner banner-ok" role="status">
          Send path advanced
          {recovery?.classification ? ` · ${statusLabel(recovery.classification)}` : ` · ${statusLabel(status)}`}
          {amount !== "—" ? ` · ${amount} ZKZ` : ""}.{" "}
          {APPROVE_SUCCESS_NOTE}
        </div>
      ) : null}

      <div className="card form-card detail-grid">
        <div className="detail-item">
          <div className="k">From</div>
          <div className="v mono">{from}</div>
        </div>
        <div className="detail-item">
          <div className="k">To</div>
          <div className="v mono">{to}</div>
        </div>
        <div className="detail-item">
          <div className="k">Amount</div>
          <div className="v money">{amount} ZKZ</div>
        </div>
        {inventory?.operation_type ? (
          <div className="detail-item">
            <div className="k">Type</div>
            <div className="v">
              {operationKindLabel(inventory.operation_type)}{" "}
              <span className="quiet mono" style={{ fontSize: 11 }}>{inventory.operation_type}</span>
            </div>
          </div>
        ) : null}
        {data.kind === "challenge" ? (
          <>
            <div className="detail-item">
              <div className="k">Challenge nonce</div>
              <div className="v mono">{data.challenge.nonce}</div>
            </div>
            <div className="detail-item">
              <div className="k">Row version</div>
              <div className="v">{data.challenge.row_version}</div>
            </div>
            <div className="detail-item">
              <div className="k">Challenge expires</div>
              <div className="v">{data.challenge.expires_at}</div>
            </div>
          </>
        ) : null}
        {inventory?.formation_state ? (
          <div className="detail-item">
            <div className="k">Formation</div>
            <div className="v">{statusLabel(inventory.formation_state)}</div>
          </div>
        ) : null}
                {inventory ? (
          <div className="detail-item">
            <div className="k">Wallet release</div>
            <div className="v">
              <ReleaseCountdown
                expiryUnixTimeSecs={inventory.expiry_unix_time_secs}
                status={inventory.status}
                terminalAt={inventory.terminal_at}
                attentionRequired={inventory.attention_required}
              />
            </div>
          </div>
        ) : null}
{inventory?.terminal_at ? (
          <div className="detail-item">
            <div className="k">Terminal at</div>
            <div className="v">{inventory.terminal_at}</div>
          </div>
        ) : null}
      </div>

      {canApproveReject ? (
        <div className="card form-card" style={{ marginTop: 16 }}>
          <h2 style={{ fontSize: 14, marginBottom: 12 }}>Dual-control decision</h2>
          <DualControlPolicyBanner />
          <p
            className="muted"
            style={{ fontSize: 12.5, marginBottom: 12 }}
            data-testid="pack-p-approve-semantics"
          >
            GET approval-challenge → POST approve with X-ZP-TOTP + device sign + CSRF. Reject only from CREATED.
            The node does not chain-submit SEND. Post-approve status is polled (never claimed paid or
            settled from UI alone). Recipient must finish (AWAITING_REDEMPTION is not paid); observe-land is separate.
          </p>
          <div className="form-actions">
            <button
              type="button"
              className="mini-btn primary"
              disabled={approve.isPending}
              onClick={() => {
                setErr(null);
                setMsg(null);
                approve.mutate();
              }}
            >
              {approve.isPending ? "Approving…" : "Approve (TOTP)"}
            </button>
            <button
              type="button"
              className="mini-btn danger"
              disabled={reject.isPending}
              onClick={() => {
                setErr(null);
                setMsg(null);
                reject.mutate();
              }}
            >
              {reject.isPending ? "Rejecting…" : "Reject (TOTP)"}
            </button>
          </div>
          <div className="field" style={{ marginTop: 12 }}>
            <label htmlFor="reject-reason">Reject reason</label>
            <input
              id="reject-reason"
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              maxLength={512}
            />
          </div>
        </div>
      ) : null}

      {recovery  ? (
        <div className="card form-card" style={{ marginTop: 16 }}>
          <h2 style={{ fontSize: 14, marginBottom: 8 }}>Recovery</h2>
          <p className="muted" style={{ fontSize: 12.5 }}>
            {recovery.classification}: {recovery.classification_rationale}
          </p>
          {recovery.permitted_actions.length === 0 ? (
            <p className="muted" style={{ marginTop: 8 }}>
              {isSuccess
                ? "No operator action required — classification is healthy."
                : "No permitted recovery actions."}
            </p>
          ) : (
            <RecoveryActions
              permittedActions={recovery.permitted_actions}
              disabled={recoveryAction.isPending}
              onAction={(a) => {
                setErr(null);
                setMsg(null);
                recoveryAction.mutate(a);
              }}
            />
          )}
        </div>
      ) : null}

      {msg ? <div className="banner" style={{ marginTop: 12 }}>{msg}</div> : null}
      {err ? <div className="banner banner-error" style={{ marginTop: 12 }}>{err}</div> : null}
      {pollStatus ? (
        <p className="muted" style={{ marginTop: 8, fontSize: 12.5 }}>
          Observed status after action: <StatusTag status={pollStatus} />
        </p>
      ) : null}
    </div>
  );
}

/** Plain-language dual-control mode banner matching server enforcement. */
function DualControlPolicyBanner() {
  const q = useQuery({
    queryKey: ["dual-control-policy"],
    queryFn: async () => fetchDualControlPolicy(),
    staleTime: 60_000,
  });
  if (q.isLoading) {
    return <p className="muted" style={{ fontSize: 12.5 }}>Loading dual-control policy…</p>;
  }
  if (q.isError || !q.data) {
    return (
      <p className="muted" style={{ fontSize: 12.5 }} data-testid="dual-control-banner">
        Dual-control policy unavailable — enforcement fails closed to two_human.
      </p>
    );
  }
  return (
    <p
      className="muted"
      style={{ fontSize: 12.5, marginBottom: 12 }}
      data-testid="dual-control-banner"
    >
      <strong>{q.data.short}</strong> — {q.data.approve_hint}
    </p>
  );
}
