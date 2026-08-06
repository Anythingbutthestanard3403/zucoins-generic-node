// Mode A recovery-verification ceremony UI.
//
// Same-origin Operator PWA only. One-shot master-key field → POST node-origin
// ceremony admin API → progress poll → digests-only. Field cleared always
// (success and failure). Never SPA storage / query for the key.
// UI never stamps recovery_verified_at — ceremony API is sole writer.

import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { StatusTag } from "../../components/StatusTag.js";
import {
  formatMoneyError,
  getRecoveryCeremonyStatus,
  isCancelled,
  listWalletsInventory,
  postRecoveryCeremonyStart,
  postRecoveryPackCreate,
  postRecoveryPackProve,
  recoveryPackFileBlob,
  type CeremonyStatusResponse,
  type RecoveryPackCreateResponse,
  type RecoveryPackProveResponse,
  type WalletInventoryItem,
} from "../../lib/money.js";
import { useAuth } from "../../store/auth.js";
import { useTotpGatedMutation } from "../../totp/useTotpGatedMutation.js";

type CeremonyStep = "explain" | "pack" | "run" | "verify";

const STEP_LABELS: Record<CeremonyStep, string> = {
  explain: "1. Understand",
  pack: "2. Recovery pack",
  run: "3. Break-glass key",
  verify: "4. Verify result",
};

/** Refuse framed embeds — CSP frame-ancestors is primary; this is defense in depth. */
function useRefuseFramed(): boolean {
  const [framed, setFramed] = useState(false);
  useEffect(() => {
    try {
      if (typeof window !== "undefined" && window.top !== window.self) {
        setFramed(true);
      }
    } catch {
      // cross-origin frame access throws — treat as framed
      setFramed(true);
    }
  }, []);
  return framed;
}

export function RecoveryCeremonyPage() {
  const demoMode = useAuth((s) => s.demoMode);
  const [step, setStep] = useState<CeremonyStep>("explain");
  const framed = useRefuseFramed();

  if (framed) {
    return (
      <div className="page">
        <div className="page-title-row">
          <h1>Recovery verification</h1>
        </div>
        <div className="card form-card" role="alert">
          <h3>Cannot run in a frame</h3>
          <p className="muted" style={{ fontSize: 13, lineHeight: 1.6 }}>
            The recovery ceremony must open on the node origin directly — never inside an
            iframe or embedded third-party page. Open this page on the node&apos;s own URL.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Recovery verification</h1>
      </div>

      <div
        className="banner"
        role="status"
        data-testid="recovery-advanced-path-banner"
        style={{ marginBottom: 12 }}
      >
        <strong>Happy path:</strong> create a recovery pack and <strong>Test backup</strong>{" "}
        (prove) under step 2. Mode A master-key paste and CLI are{" "}
        <strong>advanced / disaster</strong> paths — not day-0 setup.
      </div>

      <nav className="ceremony-steps" aria-label="Ceremony steps">
        {(["explain", "pack", "run", "verify"] as CeremonyStep[]).map((s) => (
          <button
            key={s}
            type="button"
            className={`filter-btn ${step === s ? "active" : ""}`}
            onClick={() => setStep(s)}
            aria-current={step === s ? "step" : undefined}
          >
            {STEP_LABELS[s]}
          </button>
        ))}
      </nav>

      {step === "explain" && <ExplainStep onNext={() => setStep("pack")} />}
      {step === "pack" && (
        <PackStep
          demoMode={demoMode}
          onNext={() => setStep("verify")}
          onBack={() => setStep("explain")}
          onBreakGlass={() => setStep("run")}
        />
      )}
      {step === "run" && (
        <RunStep
          demoMode={demoMode}
          onNext={() => setStep("verify")}
          onBack={() => setStep("pack")}
        />
      )}
      {step === "verify" && <VerifyStep demoMode={demoMode} onBack={() => setStep("pack")} />}
    </div>
  );
}

function ExplainStep({ onNext }: { onNext: () => void }) {
  return (
    <div className="card form-card">
      <h3>What this ceremony proves</h3>
      <p className="muted" style={{ fontSize: 13, lineHeight: 1.6 }}>
        Fresh wallets are node-generated and born blocked until a recovery-verification ceremony
        stamps <code>recovery_verified_at</code>. Without this stamp, a wallet cannot receive ZKZ
        (receive-eligibility gate).
      </p>
      <p className="muted" style={{ fontSize: 13, lineHeight: 1.6 }}>
        <strong>Happy path:</strong> download an encrypted recovery pack once, then prove
        it later with a short passcode. The pack is sealed with Argon2id + AES-256-GCM — TOTP is
        never the file key. Prefer 6 digits and keep the file private.
      </p>
      <p className="muted" style={{ fontSize: 13, lineHeight: 1.6 }}>
        Break-glass Mode A still accepts the raw vault master key when the pack is lost. The UI
        never stamps wallets — only the node ceremony engine writes{" "}
        <code>recovery_verified_at</code>.
      </p>
      <div className="form-actions" style={{ marginTop: 16 }}>
        <button type="button" className="mini-btn primary" onClick={onNext}>
          Continue to recovery pack
        </button>
      </div>
    </div>
  );
}

/**
 * Recovery pack create + prove UI. Exported for day-0 funnel routes
 * `/start/backup` and `/start/prove`.
 */
export function PackStep({
  demoMode,
  onNext,
  onBack,
  onBreakGlass,
  mode = "both",
  onCreated,
}: {
  demoMode: boolean;
  onNext: () => void;
  onBack?: () => void;
  onBreakGlass?: () => void;
  /** `create` = pack download only; `prove` = upload only; `both` = ceremony default. */
  mode?: "create" | "prove" | "both";
  /** Fired after successful create (day-0 local marker). */
  onCreated?: () => void;
}) {
  const [createPasscode, setCreatePasscode] = useState("");
  const [provePasscode, setProvePasscode] = useState("");
  const [masterKey, setMasterKey] = useState("");
  const [packText, setPackText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [createDigest, setCreateDigest] = useState<string | null>(null);
  const [proveId, setProveId] = useState<string | null>(null);

  const createMut = useTotpGatedMutation<
    RecoveryPackCreateResponse,
    { passcode: string; vault_master_key?: string }
  >(
    async (body, totp) => postRecoveryPackCreate(body, totp),
    {
      title: "Create recovery pack",
      detail: "Fresh TOTP required. Passcode seals the pack; TOTP is not the file key.",
      onSuccess: (result) => {
        setCreatePasscode("");
        setMasterKey("");
        setError(null);
        setCreateDigest(result.pack_content_sha256);
        const blob = recoveryPackFileBlob(result);
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = result.filename;
        a.click();
        URL.revokeObjectURL(url);
        onCreated?.();
      },
      onError: (err: unknown) => {
        setCreatePasscode("");
        setMasterKey("");
        if (isCancelled(err)) return;
        setError(formatMoneyError(err, "Pack create failed."));
      },
    },
  );

  const proveMut = useTotpGatedMutation<
    RecoveryPackProveResponse,
    { passcode: string; pack_file: string }
  >(
    async (body, totp) => postRecoveryPackProve(body, totp),
    {
      title: "Prove recovery pack",
      detail: "Fresh TOTP required. Decrypt runs server-side; ceremony stamps wallets.",
      onSuccess: (result) => {
        setProvePasscode("");
        setPackText("");
        setError(null);
        setProveId(result.recovery_verification_id);
        onNext();
      },
      onError: (err: unknown) => {
        setProvePasscode("");
        if (isCancelled(err)) return;
        setError(formatMoneyError(err, "Pack prove failed."));
      },
    },
  );

  function onCreate(e: FormEvent) {
    e.preventDefault();
    if (demoMode) return;
    const pc = createPasscode;
    const mk = masterKey.trim();
    setCreatePasscode("");
    setMasterKey("");
    createMut.mutate(mk.length >= 32 ? { passcode: pc, vault_master_key: mk } : { passcode: pc });
  }

  function onProve(e: FormEvent) {
    e.preventDefault();
    if (demoMode) return;
    const pc = provePasscode;
    const file = packText;
    setProvePasscode("");
    setPackText("");
    proveMut.mutate({ passcode: pc, pack_file: file });
  }

  function onFile(file: File | null) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === "string") setPackText(reader.result);
    };
    reader.readAsText(file);
  }

  return (
    <div className="card form-card">
      <h3>Recovery pack (happy path)</h3>
      <p className="muted" style={{ fontSize: 13, lineHeight: 1.6 }}>
        Create downloads an encrypted file (<code>zp-node-recovery-pack-v1</code>). Prove uploads
        that file + passcode; the node decrypts and runs the ceremony engine. Prefer 6-digit
        passcodes. Online prove locks after 5 failures for 15 minutes.
      </p>

      {demoMode ? (
        <div className="banner-demo" role="status">
          Design preview — sign in against a live node to create or prove a pack.
        </div>
      ) : null}

      {error ? (
        <p className="err" role="alert">
          {error}
        </p>
      ) : null}
      {createDigest ? (
        <p className="muted" style={{ fontSize: 12 }} role="status">
          Pack downloaded. content_sha256={createDigest.slice(0, 16)}…
        </p>
      ) : null}
      {proveId ? (
        <p className="muted" style={{ fontSize: 12 }} role="status">
          Prove accepted — ceremony {proveId}. Check Verify for stamps.
        </p>
      ) : null}

      {mode === "create" || mode === "both" ? (
        <form onSubmit={(e) => void onCreate(e)} autoComplete="off" style={{ marginTop: 12 }}>
          <h4 style={{ fontSize: 13 }}>Create pack</h4>
          <div className="field">
            <label htmlFor="pack-passcode-create">Passcode (4–6 digits)</label>
            <input
              id="pack-passcode-create"
              data-testid="pack-passcode-create"
              type="password"
              inputMode="numeric"
              pattern="\d{4,6}"
              autoComplete="off"
              value={createPasscode}
              onChange={(e) => setCreatePasscode(e.target.value)}
              disabled={demoMode || createMut.isPending}
              placeholder="••••••"
            />
          </div>
          <div className="field">
            <label htmlFor="pack-master-optional">
              Vault master key (optional if show-once plaintext still pending)
            </label>
            <input
              id="pack-master-optional"
              data-testid="pack-master-optional"
              type="password"
              autoComplete="off"
              value={masterKey}
              onChange={(e) => setMasterKey(e.target.value)}
              disabled={demoMode || createMut.isPending}
              placeholder="≥32 characters when sealed"
              style={{ fontFamily: "var(--mono, monospace)", fontSize: 13 }}
            />
          </div>
          <button
            type="submit"
            className="mini-btn primary"
            disabled={demoMode || createMut.isPending || !/^\d{4,6}$/.test(createPasscode)}
          >
            {createMut.isPending ? "Creating…" : "Create & download pack"}
          </button>
        </form>
      ) : null}

      {mode === "prove" || mode === "both" ? (
        <form onSubmit={(e) => void onProve(e)} autoComplete="off" style={{ marginTop: 24 }}>
          <h4 style={{ fontSize: 13 }}>Prove pack</h4>
          <div className="field">
            <label htmlFor="pack-file">Pack file</label>
            <input
              id="pack-file"
              data-testid="pack-file"
              type="file"
              accept="application/json,.json"
              disabled={demoMode || proveMut.isPending}
              onChange={(e) => onFile(e.target.files?.[0] ?? null)}
            />
          </div>
          <div className="field">
            <label htmlFor="pack-passcode-prove">Passcode</label>
            <input
              id="pack-passcode-prove"
              data-testid="pack-passcode-prove"
              type="password"
              inputMode="numeric"
              pattern="\d{4,6}"
              autoComplete="off"
              value={provePasscode}
              onChange={(e) => setProvePasscode(e.target.value)}
              disabled={demoMode || proveMut.isPending}
            />
          </div>
          <button
            type="submit"
            className="mini-btn primary"
            disabled={
              demoMode ||
              proveMut.isPending ||
              packText.length === 0 ||
              !/^\d{4,6}$/.test(provePasscode)
            }
          >
            {proveMut.isPending ? "Proving…" : "Test backup (prove pack)"}
          </button>
        </form>
      ) : null}

      <div className="form-actions" style={{ marginTop: 16 }}>
        {onBack ? (
          <button type="button" className="mini-btn" onClick={onBack}>
            Back
          </button>
        ) : null}
        {onBreakGlass ? (
          <button type="button" className="mini-btn" onClick={onBreakGlass}>
            Break-glass: paste master key
          </button>
        ) : null}
        {mode === "both" ? (
          <button type="button" className="mini-btn" onClick={onNext}>
            Skip to verify
          </button>
        ) : null}
        {mode === "create" ? (
          <button
            type="button"
            className="mini-btn primary"
            data-testid="day0-backup-continue"
            onClick={onNext}
            disabled={!createDigest && !demoMode}
          >
            Continue to prove
          </button>
        ) : null}
      </div>
    </div>
  );
}

function RunStep({
  demoMode,
  onNext,
  onBack,
}: {
  demoMode: boolean;
  onNext: () => void;
  onBack: () => void;
}) {
  const [masterKey, setMasterKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [ceremonyId, setCeremonyId] = useState<string | null>(null);
  const [status, setStatus] = useState<CeremonyStatusResponse | null>(null);
  const keyInputRef = useRef<HTMLInputElement>(null);

  const clearKey = useCallback(() => {
    setMasterKey("");
    if (keyInputRef.current) keyInputRef.current.value = "";
  }, []);

  const start = useTotpGatedMutation<CeremonyStatusResponse, string>(
    async (key, totp) =>
      postRecoveryCeremonyStart({ vault_master_key: key }, totp),
    {
      title: "Start recovery ceremony",
      detail: "Enter a fresh TOTP. The master key is sent only in this request body.",
      onSuccess: (result) => {
        clearKey();
        setError(null);
        setCeremonyId(result.ceremony_id);
        setStatus(result);
      },
      onError: (err: unknown) => {
        clearKey();
        if (isCancelled(err)) return;
        setError(formatMoneyError(err, "Ceremony start failed."));
      },
    },
  );

  // Poll progress while running
  const poll = useQuery({
    queryKey: ["recovery-ceremony-status", ceremonyId, demoMode],
    queryFn: () => getRecoveryCeremonyStatus(ceremonyId ?? undefined),
    enabled: !demoMode && ceremonyId !== null,
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      if (s === "running") return 1500;
      return false;
    },
  });

  useEffect(() => {
    if (poll.data) setStatus(poll.data);
  }, [poll.data]);

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (demoMode) return;
    const key = masterKey;
    // Clear immediately after capture into the mutation (memory-only for POST).
    clearKey();
    setError(null);
    start.mutate(key);
  }

  const running = status?.status === "running" || start.isPending;
  const done = status?.status === "complete";
  const failed = status?.status === "failed";

  return (
    <div className="card form-card">
      <h3>Run the ceremony on this node</h3>
      <p className="muted" style={{ fontSize: 13, lineHeight: 1.6 }}>
        Paste the vault master key once. It is sent only to this node&apos;s ceremony API in the
        POST body, never stored in the browser, never put in the URL, and cleared from this field
        after submit (success or failure).
      </p>

      {demoMode ? (
        <div className="banner-demo" role="status">
          Design preview — sign in against a live node to run the ceremony.
        </div>
      ) : null}

      <form onSubmit={(e) => void onSubmit(e)} autoComplete="off" style={{ marginTop: 12 }}>
        <div className="field">
          <label htmlFor="vault-master-key">Vault master key</label>
          <input
            ref={keyInputRef}
            id="vault-master-key"
            data-testid="master-key-input"
            type="password"
            name="vault-master-key-oneshot"
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            data-1p-ignore="true"
            data-lpignore="true"
            data-form-type="other"
            value={masterKey}
            onChange={(e) => setMasterKey(e.target.value)}
            disabled={demoMode || running || done}
            minLength={32}
            required={!demoMode}
            placeholder="≥32 characters"
            style={{ fontFamily: "var(--mono, monospace)", fontSize: 13 }}
          />
        </div>

        {error ? <p className="err" role="alert">{error}</p> : null}

        {status?.error && failed ? (
          <p className="err" role="alert">
            Ceremony failed: {status.error.message}. No wallets were partially claimed as verified
            by this UI — re-check inventory after a fix.
          </p>
        ) : null}

        {status && status.status !== "idle" ? (
          <div
            className="card"
            style={{ padding: 12, marginTop: 12, marginBottom: 12 }}
            aria-live="polite"
          >
            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>
              Progress — {status.stage ?? status.status}
            </div>
            <ul style={{ fontSize: 12, margin: 0, paddingLeft: 18, lineHeight: 1.5 }}>
              {status.progress.map((p, i) => (
                <li key={`${p.at}-${i}`}>
                  <code>{p.stage}</code>
                  {p.detail ? ` — ${p.detail}` : ""}
                </li>
              ))}
            </ul>
            {status.summary ? (
              <div style={{ marginTop: 10, fontSize: 12 }}>
                <div>
                  stamped={status.summary.stamped} failed_closed={status.summary.failed_closed}{" "}
                  skipped={status.summary.skipped} verified_on_live=
                  {status.summary.recovery_verified_on_live}
                </div>
                {status.summary.archive_sha256 ? (
                  <div className="mono" style={{ fontSize: 11, marginTop: 4 }}>
                    archive_sha256={status.summary.archive_sha256.slice(0, 16)}…
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : null}

        <div className="form-actions" style={{ marginTop: 16 }}>
          <button type="button" className="mini-btn" onClick={onBack} disabled={running}>
            Back
          </button>
          <button
            type="submit"
            className="mini-btn primary"
            disabled={demoMode || running || done || masterKey.length < 32}
          >
            {running ? "Running…" : done ? "Ceremony complete" : "Start ceremony"}
          </button>
          {(done || failed) && (
            <button type="button" className="mini-btn primary" onClick={onNext}>
              Verify result
            </button>
          )}
        </div>
      </form>

      <p className="muted" style={{ fontSize: 12, marginTop: 16 }}>
        Break-glass CLI still available on the host:{" "}
        <code className="mono">node dist/ops/run-recovery-ceremony.js</code>
      </p>
    </div>
  );
}

function VerifyStep({
  demoMode,
  onBack,
}: {
  demoMode: boolean;
  onBack: () => void;
}) {
  const q = useQuery({
    queryKey: ["wallets-recovery-verify", demoMode],
    queryFn: listWalletsInventory,
    refetchInterval: demoMode ? false : 5_000,
    enabled: !demoMode,
  });

  const live = q.data?.live === true;
  const wallets = live ? (q.data?.data ?? []) : [];
  const verified = wallets.filter((w) => w.recovery_verified);
  const unverified = wallets.filter((w) => !w.recovery_verified);

  return (
    <div className="card form-card">
      <h3>Verify ceremony result</h3>
      <p className="muted" style={{ fontSize: 13, lineHeight: 1.6 }}>
        After a successful ceremony, inventory should show at least one wallet with{" "}
        <code>recovery_verified</code>. This page only reads inventory — it never stamps.
      </p>

      {!demoMode && !live ? (
        <>
          <p className="muted">Wallet inventory unavailable — cannot verify ceremony result.</p>
          <ApiErrorNote error={q.data?.error} />
        </>
      ) : null}

      {live && (
        <div style={{ marginTop: 12 }}>
          <div style={{ display: "flex", gap: 16, marginBottom: 12 }}>
            <div className="card" style={{ padding: 12, flex: 1 }}>
              <div style={{ fontSize: 12, fontWeight: 600 }}>Verified</div>
              <div style={{ fontSize: 24, fontWeight: 700 }}>{verified.length}</div>
            </div>
            <div className="card" style={{ padding: 12, flex: 1 }}>
              <div style={{ fontSize: 12, fontWeight: 600 }}>Born-blocked</div>
              <div style={{ fontSize: 24, fontWeight: 700 }}>{unverified.length}</div>
            </div>
          </div>

          {verified.length > 0 ? (
            <p className="muted" style={{ fontSize: 12 }} role="status">
              ≥1 recovery_verified wallet — receive eligibility can open for those wallets.
            </p>
          ) : (
            <p className="muted" style={{ fontSize: 12 }} role="status">
              No recovery_verified wallets yet. Re-run the ceremony if it failed, or wait for
              progress to finish.
            </p>
          )}

          {verified.length > 0 && (
            <WalletTable
              caption="Recovery-verified wallets (receive-eligible)"
              wallets={verified}
              emptyMessage="No verified wallets"
            />
          )}

          {unverified.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <WalletTable
                caption="Born-blocked wallets (not receive-eligible)"
                wallets={unverified}
                emptyMessage="No unverified wallets"
              />
            </div>
          )}
        </div>
      )}

      <div className="form-actions" style={{ marginTop: 16 }}>
        <button type="button" className="mini-btn" onClick={onBack}>
          Back
        </button>
        <button
          type="button"
          className="mini-btn"
          onClick={() => void q.refetch()}
          disabled={!live || q.isFetching}
        >
          {q.isFetching ? "Refreshing..." : "Refresh"}
        </button>
      </div>
    </div>
  );
}

function WalletTable({
  caption,
  wallets,
  emptyMessage,
}: {
  caption: string;
  wallets: readonly WalletInventoryItem[];
  emptyMessage: string;
}) {
  return (
    <div>
      <h4 style={{ fontSize: 13, marginBottom: 8 }}>{caption}</h4>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Pubkey</th>
              <th>Origin</th>
              <th>State</th>
              <th>Recovery</th>
            </tr>
          </thead>
          <tbody>
            {wallets.length === 0 ? (
              <tr>
                <td colSpan={4} className="muted">
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              wallets.map((w) => (
                <tr key={w.wallet_id}>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {w.public_key.length > 20
                      ? `${w.public_key.slice(0, 10)}...${w.public_key.slice(-6)}`
                      : w.public_key}
                  </td>
                  <td>{w.key_origin}</td>
                  <td>
                    <StatusTag status={w.state} />
                  </td>
                  <td>
                    {w.recovery_verified ? (
                      <StatusTag status="VERIFIED" />
                    ) : (
                      <StatusTag status="BLOCKED" />
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
