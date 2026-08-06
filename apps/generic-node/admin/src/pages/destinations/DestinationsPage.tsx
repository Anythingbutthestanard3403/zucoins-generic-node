import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { StatusTag } from "../../components/StatusTag.js";
import {
  buildDestinationBlessPreimage,
  ceremonyWindowFromNow,
  getDeviceRecord,
  randomUuid,
  signPreimage,
} from "../../lib/device-crypto.js";
import {
  formatMoneyError,
  isCancelled,
  listDeviceKeys,
  listDestinationsInventory,
  postBless,
  postRetire,
} from "../../lib/money.js";
import { isPackEnabled, loadEnabledPacks } from "../../lib/packs.js";
import { useAuth } from "../../store/auth.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

export function DestinationsPage() {
  const demoMode = useAuth((s) => s.demoMode);
  const qc = useQueryClient();
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [showBless, setShowBless] = useState(false);
  const [destId, setDestId] = useState("");
  const [deviceKeyId, setDeviceKeyId] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [manualNonce, setManualNonce] = useState("");
  const [manualIssuedAt, setManualIssuedAt] = useState("");
  const [manualExpiresAt, setManualExpiresAt] = useState("");
  const [manualSig, setManualSig] = useState("");

  const q = useQuery({
    queryKey: ["destinations", demoMode],
    queryFn: async () => {
      if (demoMode) return { live: false as const, data: [] as const };
      return listDestinationsInventory();
    },
  });

  const deviceKeys = useQuery({
    queryKey: ["device-keys", demoMode],
    queryFn: listDeviceKeys,
    enabled: showBless && !demoMode,
  });
  const selectedDeviceKeyId = deviceKeyId || deviceKeys.data?.[0]?.id || "";

  const selectedDest = (q.data?.data ?? []).find((d) => d.destination_id === destId.trim());

  const bless = useTotpGatedMutation(
    async (
      body: {
        destinationId: string;
        device_key_id: string;
      },
      totp: string,
    ) => {
      const dest =
        selectedDest ??
        (q.data?.data ?? []).find((d) => d.destination_id === body.destinationId);
      if (!dest) {
        throw new Error("Destination not loaded — open Bless from a PENDING row.");
      }
      if (!dest.node_id) {
        throw new Error("Destination missing node_id — cannot build bless preimage.");
      }

      let nonce: string;
      let issued_at: string;
      let expires_at: string;
      let device_signature: string;

      if (showAdvanced && manualSig.trim().length > 0) {
        nonce = manualNonce.trim();
        issued_at = manualIssuedAt.trim();
        expires_at = manualExpiresAt.trim();
        device_signature = manualSig.trim();
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
      detail: "Review tuple → device sign → fresh TOTP (TOTP alone cannot bless)",
      onSuccess: () => {
        setErr(null);
        setMsg("Bless accepted.");
        setShowBless(false);
        void qc.invalidateQueries({ queryKey: ["destinations"] });
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Bless failed"));
      },
    },
  );

  const retire = useTotpGatedMutation(
    async (id: string, totp: string) => postRetire(id, totp),
    {
      title: "Retire destination",
      detail: (id) => `Retire ${id} — blocks new selection`,
      onSuccess: () => {
        setErr(null);
        setMsg("Retired.");
        void qc.invalidateQueries({ queryKey: ["destinations"] });
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Retire failed"));
      },
    },
  );

  const rows = q.data?.data ?? [];
  const live = q.data?.live ?? false;
  const loading = q.isLoading;
  const packT = isPackEnabled(loadEnabledPacks(), "T");

  return (
    <div className="page">
      
      <div
        className="banner"
        role="note"
        data-testid="destinations-day2-banner"
        style={{ marginBottom: 12 }}
      >
        Destinations are <strong>day-2 money routing</strong> — not part of install. You do{" "}
        <strong>not</strong> need a destination ID to enrol an approval device on your phone.
      </div>
<div className="page-title-row">
        <h1>Destinations</h1>
        <div className="toolbar">
          <span className="muted" style={{ fontSize: 12.5 }}>
            {demoMode
              ? "No fixtures — log in for live"
              : loading
                ? "Loading…"
                : live
                  ? "Live"
                  : "List unavailable"}
            {" · "}
            <Link to="/devices">Devices</Link>
          </span>
          {!demoMode ? (
            <button type="button" className="pill primary" onClick={() => setShowBless((v) => !v)}>
              Bless destination
            </button>
          ) : null}
        </div>
      </div>

      {packT ? (
        <div
          className="banner"
          role="note"
          data-testid="pack-t-bless-guidance"
          style={{ marginBottom: 16 }}
        >
          <strong>Pack T — Internal treasury.</strong> Bless ≥1 automatic sink here in-UI
          (device signature + fresh TOTP over <code className="mono">zp-destination-bless-v1</code>).
          No CLI required. Internal transfer (MOVE_INTERNAL) consolidates to blessed sinks —
          still only three money ops; no sweeps product chrome. No merchant website required.
        </div>
      ) : null}

      {showBless && !demoMode ? (
        <form
          className="card form-card"
          style={{ marginBottom: 16 }}
          onSubmit={(e) => {
            e.preventDefault();
            setErr(null);
            setMsg(null);
            if (selectedDeviceKeyId.length === 0) {
              setErr("Select an enrolled device key before continuing with TOTP.");
              return;
            }
            if (destId.trim().length === 0) {
              setErr("Destination id required.");
              return;
            }
            bless.mutate({
              destinationId: destId.trim(),
              device_key_id: selectedDeviceKeyId,
            });
          }}
        >
          <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }}>
            One-tap bless: this browser signs <code className="mono">zp-destination-bless-v1</code>{" "}
            after you confirm the destination tuple, then prompts for fresh TOTP. Device signature is
            additive — TOTP alone is rejected.
          </p>

          {selectedDest ? (
            <div className="detail-grid" style={{ marginBottom: 12 }} data-testid="bless-tuple-review">
              <div className="detail-item">
                <div className="k">Destination</div>
                <div className="v mono">{selectedDest.destination_id}</div>
              </div>
              <div className="detail-item">
                <div className="k">Label</div>
                <div className="v">{selectedDest.label}</div>
              </div>
              <div className="detail-item">
                <div className="k">Wallet</div>
                <div className="v mono">{selectedDest.wallet_id}</div>
              </div>
              <div className="detail-item">
                <div className="k">Pubkey</div>
                <div className="v mono">{selectedDest.wallet_public_key}</div>
              </div>
              <div className="detail-item">
                <div className="k">Window</div>
                <div className="v">300s from sign time</div>
              </div>
            </div>
          ) : (
            <div className="field">
              <label htmlFor="bless-dest-id">Destination id</label>
              <input
                id="bless-dest-id"
                className="mono"
                value={destId}
                onChange={(e) => setDestId(e.target.value)}
                required
              />
            </div>
          )}

          <div className="field">
            <label htmlFor="destination-device-key">Device key</label>
            {deviceKeys.isLoading ? (
              <p className="muted">Loading enrolled device keys…</p>
            ) : deviceKeys.isError ? (
              <p className="muted">Device keys unavailable</p>
            ) : (deviceKeys.data?.length ?? 0) === 0 ? (
              <p className="muted">
                No enrolled device keys.{" "}
                <Link to="/devices">Enrol a device</Link> first.
              </p>
            ) : (
              <select
                id="destination-device-key"
                className="mono"
                value={selectedDeviceKeyId}
                onChange={(e) => setDeviceKeyId(e.target.value)}
                required
              >
                {deviceKeys.data?.map((device) => (
                  <option key={device.id} value={device.id}>
                    {device.label} — {device.id}
                  </option>
                ))}
              </select>
            )}
          </div>

          <details style={{ marginBottom: 12 }}>
            <summary
              className="muted"
              style={{ fontSize: 12.5, cursor: "pointer" }}
              onClick={() => setShowAdvanced((v) => !v)}
            >
              Break-glass: paste signature manually
            </summary>
            {showAdvanced ? (
              <div style={{ marginTop: 8 }}>
                <div className="field">
                  <label htmlFor="bless-nonce">Nonce</label>
                  <input
                    id="bless-nonce"
                    className="mono"
                    value={manualNonce}
                    onChange={(e) => setManualNonce(e.target.value)}
                  />
                </div>
                <div className="field">
                  <label htmlFor="bless-issued-at">Issued at (ISO)</label>
                  <input
                    id="bless-issued-at"
                    className="mono"
                    value={manualIssuedAt}
                    onChange={(e) => setManualIssuedAt(e.target.value)}
                  />
                </div>
                <div className="field">
                  <label htmlFor="bless-expires-at">Expires at (ISO)</label>
                  <input
                    id="bless-expires-at"
                    className="mono"
                    value={manualExpiresAt}
                    onChange={(e) => setManualExpiresAt(e.target.value)}
                  />
                </div>
                <div className="field">
                  <label htmlFor="bless-device-sig">Device signature</label>
                  <input
                    id="bless-device-sig"
                    className="mono"
                    value={manualSig}
                    onChange={(e) => setManualSig(e.target.value)}
                  />
                </div>
              </div>
            ) : null}
          </details>

          <div className="form-actions">
            <button
              type="submit"
              className="mini-btn primary"
              disabled={
                bless.isPending ||
                deviceKeys.isLoading ||
                deviceKeys.isError ||
                selectedDeviceKeyId.length === 0
              }
            >
              {bless.isPending ? "Blessing…" : "Sign & continue with TOTP"}
            </button>
            <button type="button" className="mini-btn" onClick={() => setShowBless(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      <div className="card form-card">
        {!demoMode && !loading && !live ? (
          <>
            <p className="muted" style={{ fontSize: 13, marginBottom: 12 }}>
              <code className="mono">GET /admin/v1/destinations</code> unavailable.
              Bless/retire still work with a known destination id via the form above.
            </p>
            <ApiErrorNote error={q.data?.error} />
          </>
        ) : null}
        {demoMode ? (
          <div className="empty" style={{ paddingTop: 28 }}>
            No fixtures — log in for a live session to view destinations.
          </div>
        ) : loading ? (
          <div className="empty" style={{ paddingTop: 28 }}>
            Loading…
          </div>
        ) : rows.length === 0 ? (
          <div className="empty" style={{ paddingTop: 28 }}>
            {live ? "No destinations yet" : "Destinations unavailable"}
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Label</th>
                  <th>Id</th>
                  <th>Pubkey</th>
                  <th>State</th>
                  <th>Eligible</th>
                  <th>
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((d) => (
                  <tr key={d.destination_id}>
                    <td>{d.label}</td>
                    <td className="mono">{d.destination_id}</td>
                    <td className="mono">{d.wallet_public_key.slice(0, 16)}…</td>
                    <td>
                      <StatusTag status={d.state} />
                    </td>
                    <td>
                      {d.move_eligible === true ? "yes" : d.move_eligible === false ? "no" : "—"}
                    </td>
                    <td>
                      {!demoMode && d.state === "BLESSED" ? (
                        <button
                          type="button"
                          className="mini-btn danger"
                          disabled={retire.isPending}
                          onClick={() => {
                            setErr(null);
                            setMsg(null);
                            retire.mutate(d.destination_id);
                          }}
                        >
                          Retire
                        </button>
                      ) : !demoMode && d.state === "PENDING" ? (
                        <button
                          type="button"
                          className="mini-btn"
                          onClick={() => {
                            setDestId(d.destination_id);
                            setShowBless(true);
                          }}
                        >
                          Bless…
                        </button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {msg ? (
        <div className="banner" style={{ marginTop: 12 }}>
          {msg}
        </div>
      ) : null}
      {err ? (
        <div className="banner banner-error" style={{ marginTop: 12 }}>
          {err}
        </div>
      ) : null}
    </div>
  );
}
