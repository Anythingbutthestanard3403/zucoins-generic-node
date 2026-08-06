/**
 * Keys → Devices — first-device (genesis) enrol + list/revoke.
 *
 * WebCrypto device key stays browser-only (IndexedDB, non-extractable).
 * Server inventory is the source of truth for enrolled ids/labels.
 * Second-device QR enrol: challenge_id + node_origin only.
 * Deep-link /devices/enrol?challenge_id= drives device-B bind + PoP complete.
 * Device A authorizes bound ceremonies with local device sig + TOTP.
 * TOTP required on enrol + revoke + authorize (TOTP floor).
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import {
  buildDeviceEnrolPreimage,
  deleteLocalDeviceRecord,
  generateDeviceKeyPair,
  getDeviceRecord,
  listLocalDeviceRecords,
  putDeviceRecord,
  signPreimage,
  signRevokeProof
} from "../../lib/device-crypto.js";
import { runGenesisDeviceEnrol } from "../../lib/genesis-device-enrol.js";
import {
  authorizeSecondDeviceEnrol,
  bindSecondDeviceEnrol,
  completeSecondDeviceEnrol,
  formatMoneyError,
  isCancelled,
  issueSecondDeviceEnrol,
  listDeviceKeys,
  peekSecondDeviceEnrol,
  type SecondDeviceIssueResponse,
  postRevokeDevice
} from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

const QUERY_KEY = ["device-keys"] as const;

interface CeremonyPeek {
  readonly challenge_id: string;
  readonly status: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly node_id: string;
  readonly nonce: string | null;
  readonly label: string | null;
  readonly new_device_key_id: string | null;
  readonly new_device_public_key: string | null;
  readonly preimage_text: string | null;
  readonly preimage_sha256: string | null;
  readonly expired: boolean;
}

export function DevicesPage() {
  const demoMode = useAuth((s) => s.demoMode);
  const qc = useQueryClient();
  const [searchParams] = useSearchParams();
  const deepLinkChallengeId = useMemo(() => {
    const raw = searchParams.get("challenge_id")?.trim() ?? "";
    return raw.length > 0 ? raw : null;
  }, [searchParams]);

  const [label, setLabel] = useState("Operator phone");
  const [secondLabel, setSecondLabel] = useState("Second phone");
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [issued, setIssued] = useState<SecondDeviceIssueResponse | null>(null);
  const [secondBusy, setSecondBusy] = useState(false);
  const [challengePeek, setChallengePeek] = useState<string>("");
  const [ceremony, setCeremony] = useState<CeremonyPeek | null>(null);
  const [pendingBPrivate, setPendingBPrivate] = useState<CryptoKey | null>(null);
  const [pendingBPublic, setPendingBPublic] = useState<string | null>(null);
  const [pendingBDeviceId, setPendingBDeviceId] = useState<string | null>(null);

  const list = useQuery({
    queryKey: [...QUERY_KEY, demoMode],
    queryFn: listDeviceKeys,
    enabled: !demoMode });

  const enrol = useTotpGatedMutation(
    async (_: void, totp: string) => runGenesisDeviceEnrol({ label, totp }),
    {
      title: "Enrol this device",
      detail: "Fresh TOTP required. Private key never leaves this browser.",
      onSuccess: () => {
        setErr(null);
        setMsg("Device enrolled. This browser can now bless destinations and approve outgoing sends.");
        void qc.invalidateQueries({ queryKey: QUERY_KEY });
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Enrol failed"));
      } },
  );

  const revoke = useTotpGatedMutation(
    async (targetId: string, totp: string) => {
      let authorizerId = targetId;
      let local = await getDeviceRecord(targetId);
      if (local === null) {
        const serverKeys = list.data ?? [];
        for (const k of serverKeys) {
          const cand = await getDeviceRecord(k.id);
          if (cand !== null) {
            local = cand;
            authorizerId = k.id;
            break;
          }
        }
      }
      if (local === null) {
        throw new Error(
          "No local device key available to authorize revoke. Use the enrolled device browser.",
        );
      }
      const nodeId = local.nodeId;
      const sig = await signRevokeProof(local.privateKey, {
        node_id: nodeId,
        target_device_key_id: targetId,
        authorizing_device_key_id: authorizerId });
      const result = await postRevokeDevice(
        targetId,
        {
          authorizing_device_key_id: authorizerId,
          authorizing_device_signature: sig },
        totp,
      );
      await deleteLocalDeviceRecord(targetId);
      return result;
    },
    {
      title: "Revoke device",
      detail: (id) =>
        `Revoke ${id} — disables bless/approve from that device. Fresh TOTP required.`,
      onSuccess: () => {
        setErr(null);
        setMsg("Device revoked. Bless and approve from that device no longer work.");
        void qc.invalidateQueries({ queryKey: QUERY_KEY });
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Revoke failed"));
      } },
  );

  /** Device A: authorize a BOUND ceremony with local device signature + TOTP. */
  const authorizeBound = useTotpGatedMutation(
    async (peek: CeremonyPeek, totp: string) => {
      if (peek.status !== "BOUND") {
        throw new Error(`Ceremony is ${peek.status}; expected BOUND before authorize.`);
      }
      const locals = await listLocalDeviceRecords();
      if (locals.length === 0) {
        throw new Error(
          "No local enrolled device key on this browser. Authorize from the already-enrolled phone.",
        );
      }
      let local = await getDeviceRecord(locals[0]!.id);
      if (local === null) {
        throw new Error("Local device private key unavailable.");
      }
      // Prefer a local key that is still on the server inventory.
      const serverIds = new Set((list.data ?? []).map((k) => k.id));
      for (const meta of locals) {
        if (serverIds.has(meta.id)) {
          const cand = await getDeviceRecord(meta.id);
          if (cand !== null) {
            local = cand;
            break;
          }
        }
      }
      // Build preimage from ceremony fields (server rebuilds the same bytes).
      if (
        peek.nonce === null ||
        peek.new_device_key_id === null ||
        peek.new_device_public_key === null ||
        peek.label === null
      ) {
        throw new Error("Ceremony missing bind fields for authorize.");
      }
      const preimage = buildDeviceEnrolPreimage({
        node_id: peek.node_id,
        new_device_key_id: peek.new_device_key_id,
        new_device_public_key: peek.new_device_public_key,
        label: peek.label,
        nonce: peek.nonce,
        issued_at: peek.issued_at,
        expires_at: peek.expires_at });
      const sig = await signPreimage(local.privateKey, preimage);
      return authorizeSecondDeviceEnrol(
        {
          challenge_id: peek.challenge_id,
          authorizing_key_id: local.id,
          authorizing_public_key: local.publicKey,
          authorizing_signature: sig },
        totp,
      );
    },
    {
      title: "Authorize second device",
      detail: "Signs zp-device-enrol-v1 with this enrolled device + fresh TOTP.",
      onSuccess: async () => {
        setErr(null);
        setMsg("Authorized. New phone can complete proof-of-possession.");
        if (deepLinkChallengeId) {
          await refreshCeremony(deepLinkChallengeId);
        } else if (issued) {
          await refreshCeremony(issued.challenge_id);
        }
        void qc.invalidateQueries({ queryKey: QUERY_KEY });
      },
      onError: (e) => {
        if (isCancelled(e)) return;
        setMsg(null);
        setErr(formatMoneyError(e, "Authorize failed"));
      } },
  );

  const keys = list.data ?? [];
  const empty = !demoMode && list.isSuccess && keys.length === 0;

  async function refreshCeremony(challengeId: string): Promise<CeremonyPeek | null> {
    const peek = (await peekSecondDeviceEnrol(challengeId)) as CeremonyPeek;
    const blob = JSON.stringify(peek, null, 2);
    if (/private_key|totp|master_key|authorizing_signature/i.test(blob)) {
      throw new Error("Peek leaked secret material");
    }
    setCeremony(peek);
    setChallengePeek(blob);
    return peek;
  }

  // Deep-link consumer: /devices/enrol?challenge_id=
  useEffect(() => {
    if (demoMode || deepLinkChallengeId === null) return;
    let cancelled = false;
    void (async () => {
      setErr(null);
      try {
        const peek = await refreshCeremony(deepLinkChallengeId);
        if (cancelled || peek === null) return;
        setMsg(
          peek.status === "ISSUED"
            ? "Second-device ceremony ready — generate a key on this phone and bind."
            : peek.status === "BOUND"
              ? "Public key bound — authorize from the enrolled phone (device sig + TOTP)."
              : peek.status === "AUTHORIZED"
                ? "Authorized — complete proof-of-possession on this phone."
                : peek.status === "ENROLLED"
                  ? "Ceremony complete — device enrolled."
                  : `Ceremony status: ${peek.status}`,
        );
      } catch (e) {
        if (!cancelled) setErr(formatMoneyError(e, "Could not load enrolment challenge"));
      }
    })();
    return () => {
      cancelled = true;
    };
    // Deps intentionally limited to the deep-link id inputs.
  }, [demoMode, deepLinkChallengeId]);

  async function onIssueSecondDevice() {
    setErr(null);
    setMsg(null);
    setSecondBusy(true);
    try {
      const r = await issueSecondDeviceEnrol();
      const keysQr = Object.keys(r.qr);
      if (keysQr.length !== 2 || !keysQr.includes("challenge_id") || !keysQr.includes("node_origin")) {
        throw new Error("Server QR payload is not challenge_id + node_origin only");
      }
      setIssued(r);
      setMsg(r.note);
      await refreshCeremony(r.challenge_id);
      void qc.invalidateQueries({ queryKey: QUERY_KEY });
    } catch (e) {
      if (isCancelled(e)) return;
      setErr(formatMoneyError(e, "Could not issue second-device enrolment"));
    } finally {
      setSecondBusy(false);
    }
  }

  async function onPeekSecondDevice() {
    const id = deepLinkChallengeId ?? issued?.challenge_id;
    if (!id) return;
    setErr(null);
    try {
      await refreshCeremony(id);
    } catch (e) {
      setErr(formatMoneyError(e, "Peek failed"));
    }
  }

  /** Device B: generate WebCrypto keypair, bind pubkey, keep private key for PoP. */
  async function onBindAsNewDevice() {
    const challengeId = deepLinkChallengeId ?? issued?.challenge_id ?? ceremony?.challenge_id;
    if (!challengeId) {
      setErr("No challenge_id — open the deep link from the QR.");
      return;
    }
    setErr(null);
    setMsg(null);
    setSecondBusy(true);
    try {
      const pair = await generateDeviceKeyPair();
      const bound = (await bindSecondDeviceEnrol({
        challenge_id: challengeId,
        new_device_public_key: pair.publicKey,
        label: secondLabel.trim() || "Second phone" })) as {
        new_device_key_id: string;
        status: string;
        node_id: string;
      };
      setPendingBPrivate(pair.privateKey);
      setPendingBPublic(pair.publicKey);
      setPendingBDeviceId(bound.new_device_key_id);
      // Stash private key under the server-assigned id so complete can find it after refresh.
      await putDeviceRecord({
        id: bound.new_device_key_id,
        label: secondLabel.trim() || "Second phone",
        publicKey: pair.publicKey,
        createdAt: new Date().toISOString(),
        nodeId: bound.node_id,
        privateKey: pair.privateKey });
      setMsg("Public key bound. Authorize from the enrolled phone, then complete here.");
      await refreshCeremony(challengeId);
    } catch (e) {
      if (isCancelled(e)) return;
      setErr(formatMoneyError(e, "Bind failed"));
    } finally {
      setSecondBusy(false);
    }
  }

  /** Device B: PoP complete after A authorized. */
  async function onCompleteAsNewDevice() {
    const challengeId = deepLinkChallengeId ?? issued?.challenge_id ?? ceremony?.challenge_id;
    if (!challengeId) {
      setErr("No challenge_id.");
      return;
    }
    setErr(null);
    setMsg(null);
    setSecondBusy(true);
    try {
      let peek = ceremony;
      if (peek === null || peek.challenge_id !== challengeId) {
        peek = await refreshCeremony(challengeId);
      }
      if (peek === null) throw new Error("Ceremony not found");
      if (peek.status !== "AUTHORIZED" || peek.preimage_text === null) {
        throw new Error(
          `Ceremony is ${peek.status}; wait for enrolled phone to authorize before complete.`,
        );
      }
      let privateKey = pendingBPrivate;
      const deviceId = peek.new_device_key_id ?? pendingBDeviceId;
      if (privateKey === null && deviceId !== null) {
        const rec = await getDeviceRecord(deviceId);
        privateKey = rec?.privateKey ?? null;
      }
      if (privateKey === null) {
        throw new Error(
          "No local private key for this ceremony — bind must happen on this same browser.",
        );
      }
      const pop = await signPreimage(privateKey, peek.preimage_text);
      const completed = (await completeSecondDeviceEnrol({
        challenge_id: challengeId,
        new_device_pop_signature: pop })) as { device_key_id: string; label: string; enrolled_at: string };
      // Ensure IndexedDB id matches enrolled id (bind already used server id).
      if (deviceId !== null && pendingBPublic !== null) {
        await putDeviceRecord({
          id: completed.device_key_id,
          label: completed.label,
          publicKey: pendingBPublic,
          createdAt: completed.enrolled_at,
          nodeId: peek.node_id,
          privateKey });
      }
      setMsg(`Device enrolled: ${completed.label}. Both devices should now appear in the list.`);
      setPendingBPrivate(null);
      setPendingBPublic(null);
      setPendingBDeviceId(null);
      await refreshCeremony(challengeId);
      void qc.invalidateQueries({ queryKey: QUERY_KEY });
    } catch (e) {
      if (isCancelled(e)) return;
      setErr(formatMoneyError(e, "Complete failed"));
    } finally {
      setSecondBusy(false);
    }
  }

  const activeCeremonyId = deepLinkChallengeId ?? issued?.challenge_id ?? ceremony?.challenge_id ?? null;
  const showDeepLinkPanel = deepLinkChallengeId !== null || ceremony !== null;

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Devices</h1>
        <span className="muted" style={{ fontSize: 12.5 }}>
          Approval device keys · browser-held private key
        </span>
      </div>

      <p className="muted" style={{ fontSize: 13, maxWidth: 640, marginBottom: 16 }}>
        Enrolled devices sign destination bless and outgoing-send approvals after you review the
        exact tuple and enter TOTP. The private key is generated in this browser (WebCrypto) and
        never sent to the platform or written to plain localStorage.
      </p>

      {demoMode ? (
        <p className="muted">No fixtures — log in for a live session to manage devices.</p>
      ) : null}

      {!demoMode && list.isPending ? <p className="muted">Loading…</p> : null}

      {!demoMode && list.isError ? (
        <div className="banner banner-error" role="alert">
          Device inventory unavailable. {formatMoneyError(list.error, "List failed")}
        </div>
      ) : null}

      {msg ? (
        <div className="banner" role="status" style={{ marginBottom: 12 }}>
          {msg}
        </div>
      ) : null}
      {err ? (
        <div className="banner banner-error" role="alert" style={{ marginBottom: 12 }}>
          {err}
        </div>
      ) : null}

      {/* Deep-link / second-device consumer panel */}
      {!demoMode && showDeepLinkPanel ? (
        <div className="card form-card" style={{ marginBottom: 16 }} data-testid="second-device-ceremony">
          <h2 style={{ fontSize: 16, marginBottom: 8 }}>Second-device enrolment</h2>
          <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }}>
            Challenge{" "}
            <code className="mono">{activeCeremonyId}</code>
            {ceremony ? (
              <>
                {" "}
                · status <strong>{ceremony.status}</strong>
                {ceremony.expired ? " (expired)" : ""}
              </>
            ) : null}
          </p>
          <div className="field" style={{ marginBottom: 12 }}>
            <label htmlFor="second-device-label">Label for new device</label>
            <input
              id="second-device-label"
              value={secondLabel}
              onChange={(e) => setSecondLabel(e.target.value)}
              maxLength={80}
            />
          </div>
          <div className="form-actions" style={{ gap: 8, flexWrap: "wrap" }}>
            <button
              type="button"
              className="mini-btn primary"
              disabled={secondBusy || ceremony?.status !== "ISSUED"}
              onClick={() => void onBindAsNewDevice()}
              data-testid="second-device-bind"
            >
              {secondBusy ? "Working…" : "Generate key & bind (this phone)"}
            </button>
            <button
              type="button"
              className="mini-btn primary"
              disabled={
                secondBusy ||
                authorizeBound.isPending ||
                ceremony?.status !== "BOUND"
              }
              onClick={() => {
                if (ceremony) authorizeBound.mutate(ceremony);
              }}
              data-testid="second-device-authorize"
            >
              {authorizeBound.isPending ? "Authorizing…" : "Authorize (enrolled phone + TOTP)"}
            </button>
            <button
              type="button"
              className="mini-btn primary"
              disabled={secondBusy || ceremony?.status !== "AUTHORIZED"}
              onClick={() => void onCompleteAsNewDevice()}
              data-testid="second-device-complete"
            >
              {secondBusy ? "Working…" : "Complete with proof-of-possession"}
            </button>
            <button type="button" className="mini-btn" onClick={() => void onPeekSecondDevice()}>
              Refresh status
            </button>
          </div>
          {challengePeek ? (
            <pre className="mono" data-testid="second-device-peek" style={{ fontSize: 12, marginTop: 8 }}>
              {challengePeek}
            </pre>
          ) : null}
        </div>
      ) : null}

      {empty ? (
        <form
          className="card form-card"
          style={{ marginBottom: 16 }}
          onSubmit={(e) => {
            e.preventDefault();
            setErr(null);
            setMsg(null);
            if (label.trim().length === 0) {
              setErr("Label is required.");
              return;
            }
            enrol.mutate();
          }}
        >
          <h2 style={{ fontSize: 16, marginBottom: 8 }}>Enrol first device</h2>
          <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }}>
            Genesis enrol — allowed only while no active devices exist. Generates a WebCrypto
            Ed25519 keypair in this browser and completes server enrol under session + TOTP.
          </p>
          <div className="field">
            <label htmlFor="device-label">Label</label>
            <input
              id="device-label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              maxLength={80}
              required
            />
          </div>
          <div className="form-actions">
            <button type="submit" className="mini-btn primary" disabled={enrol.isPending}>
              {enrol.isPending ? "Enrolling…" : "Generate key & enrol with TOTP"}
            </button>
          </div>
        </form>
      ) : null}

      {!demoMode && keys.length > 0 ? (
        <>
          <div className="card form-card" style={{ marginBottom: 16 }}>
            <h2 style={{ fontSize: 16, marginBottom: 8 }}>Add another device (QR)</h2>
            <p className="muted" style={{ fontSize: 12.5, marginBottom: 12 }}>
              On an already-enrolled phone: issue a challenge, show the QR to the new phone. The new
              phone opens this node&apos;s PWA deep link, generates a WebCrypto keypair, binds its
              public key, then the enrolled phone authorizes with TOTP + device signature. New phone
              completes proof-of-possession. Ceremony ≤ 300s. QR carries challenge_id + node_origin
              only — never private keys.
            </p>
            <div className="form-actions" style={{ marginBottom: 12 }}>
              <button
                type="button"
                className="mini-btn primary"
                disabled={secondBusy}
                onClick={() => void onIssueSecondDevice()}
              >
                {secondBusy ? "Issuing…" : "Issue second-device QR"}
              </button>
            </div>
            {issued ? (
              <div style={{ marginBottom: 16 }}>
                <p className="muted" style={{ fontSize: 12.5 }}>
                  <strong>Expires</strong> {issued.expires_at}
                </p>
                <pre className="mono" data-testid="second-device-qr-payload" style={{ fontSize: 12 }}>
                  {JSON.stringify(issued.qr, null, 2)}
                </pre>
                <p className="muted" style={{ fontSize: 12.5 }}>
                  Deep link:{" "}
                  <code>
                    {issued.qr.node_origin}
                    {issued.deep_link_path}
                  </code>
                </p>
                <p className="muted" style={{ fontSize: 12.5 }}>{issued.note}</p>
                {!showDeepLinkPanel ? (
                  <button type="button" className="mini-btn" onClick={() => void onPeekSecondDevice()}>
                    Refresh challenge status
                  </button>
                ) : null}
              </div>
            ) : null}
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Label</th>
                    <th>Id</th>
                    <th>Enrolled</th>
                    <th>
                      <span className="visually-hidden">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {keys.map((k) => (
                    <tr key={k.id}>
                      <td>{k.label}</td>
                      <td className="mono">{k.id}</td>
                      <td className="mono">{k.enrolled_at}</td>
                      <td>
                        <button
                          type="button"
                          className="mini-btn danger"
                          disabled={revoke.isPending}
                          onClick={() => {
                            setErr(null);
                            setMsg(null);
                            revoke.mutate(k.id);
                          }}
                        >
                          Revoke
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="muted" style={{ fontSize: 12, marginTop: 10 }}>
              Revoke disables bless and approve from that device. Historic signatures remain valid as
              proof. TOTP is always required.
            </p>
          </div>
        </>
      ) : null}

      {!demoMode && list.isSuccess && keys.length === 0 && !empty ? null : null}
    </div>
  );
}
