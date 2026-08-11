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
  generateRecoveryPackSecret,
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
          onNext={() => setStep("verify")}
          onBack={() => setStep("explain")}
          onBreakGlass={() => setStep("run")}
        />
      )}
      {step === "run" && (
        <RunStep
          onNext={() => setStep("verify")}
          onBack={() => setStep("pack")}
        />
      )}
      {step === "verify" && <VerifyStep onBack={() => setStep("pack")} />}
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
        <strong>Happy path:</strong> download an encrypted recovery pack once, then prove it
        later with the secret shown at creation. The pack is sealed with Argon2id +
        AES-256-GCM — TOTP is never the file key. The secret is generated here, not chosen:
        copies of the pack are meant to live off this node, so its seal has to survive being
        in someone else&apos;s hands.
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
  onNext,
  onBack,
  onBreakGlass,
  mode = "both",
  onCreated,
}: {
  onNext: () => void;
  onBack?: () => void;
  onBreakGlass?: () => void;
  /** `create` = pack download only; `prove` = upload only; `both` = ceremony default. */
  mode?: "create" | "prove" | "both";
  /** Fired after successful create (day-0 local marker). */
  onCreated?: () => void;
}) {
  // Generated once per mounted form, regenerable on demand. Held in component
  // state only — never SPA storage, never a query string.
  const [createSecret, setCreateSecret] = useState(generateRecoveryPackSecret);
  const [secretSaved, setSecretSaved] = useState(false);
  const [proveSecret, setProveSecret] = useState("");
  const [proveLegacy, setProveLegacy] = useState(false);
  const [masterKey, setMasterKey] = useState("");
  const [packText, setPackText] = useState("");
  // Re-issue inputs: the pack being replaced travels with its own secret and is
  // opened server-side, so the operator never handles the vault master key.
  const [fromPackText, setFromPackText] = useState("");
  const [fromPackSecret, setFromPackSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [createDigest, setCreateDigest] = useState<string | null>(null);
  const [destroyDigest, setDestroyDigest] = useState<string | null>(null);
  const [shownSecret, setShownSecret] = useState<string | null>(null);
  const [proveId, setProveId] = useState<string | null>(null);
  const [provenLegacy, setProvenLegacy] = useState(false);

  const createMut = useTotpGatedMutation<
    RecoveryPackCreateResponse,
    {
      recovery_secret: string;
      vault_master_key?: string;
      from_pack?: string;
      from_pack_secret?: string;
      allow_legacy_v1?: boolean;
    }
  >(
    async (body, totp) => postRecoveryPackCreate(body, totp),
    {
      title: "Create recovery pack",
      detail:
        "Fresh TOTP required. The generated secret seals the pack; TOTP is not the file key.",
      onSuccess: (result, body) => {
        setMasterKey("");
        setFromPackText("");
        setFromPackSecret("");
        setSecretSaved(false);
        setError(null);
        setCreateDigest(result.pack_content_sha256);
        setDestroyDigest(result.previous_pack_content_sha256);
        // Show-once: the node never returns the secret, so this is the only place
        // it exists after the download. Next pack gets a fresh draw.
        setShownSecret(body.recovery_secret);
        setCreateSecret(generateRecoveryPackSecret());
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
        setMasterKey("");
        setFromPackSecret("");
        if (isCancelled(err)) return;
        setError(formatMoneyError(err, "Pack create failed."));
      },
    },
  );

  const proveMut = useTotpGatedMutation<
    RecoveryPackProveResponse,
    { recovery_secret: string; pack_file: string; allow_legacy_v1?: boolean }
  >(
    async (body, totp) => postRecoveryPackProve(body, totp),
    {
      title: "Prove recovery pack",
      detail: "Fresh TOTP required. Decrypt runs server-side; ceremony stamps wallets.",
      onSuccess: (result) => {
        setProveSecret("");
        setPackText("");
        setError(null);
        setProveId(result.recovery_verification_id);
        if (result.pack_version === 1) {
          // A v1 pack opened. It is compromised-if-leaked; do not advance the
          // operator past the re-issue prompt as if this were a clean result.
          setProvenLegacy(true);
          return;
        }
        setProvenLegacy(false);
        onNext();
      },
      onError: (err: unknown) => {
        setProveSecret("");
        if (isCancelled(err)) return;
        setError(formatMoneyError(err, "Pack prove failed."));
      },
    },
  );

  function onCreate(e: FormEvent) {
    e.preventDefault();
    
    const mk = masterKey.trim();
    const from = fromPackText;
    const fromSecret = fromPackSecret;
    setMasterKey("");
    setFromPackSecret("");
    createMut.mutate({
      recovery_secret: createSecret,
      ...(from.length > 0 && fromSecret.length > 0
        ? { from_pack: from, from_pack_secret: fromSecret, allow_legacy_v1: true }
        : mk.length >= 32
          ? { vault_master_key: mk }
          : {}),
    });
  }

  function onProve(e: FormEvent) {
    e.preventDefault();
    
    const secret = proveSecret;
    const file = packText;
    setProveSecret("");
    setPackText("");
    proveMut.mutate({
      recovery_secret: secret,
      pack_file: file,
      ...(proveLegacy ? { allow_legacy_v1: true } : {}),
    });
  }

  function readPackFile(file: File | null, into: (text: string) => void) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === "string") into(reader.result);
    };
    reader.readAsText(file);
  }

  return (
    <div className="card form-card">
      <h3>Recovery pack (happy path)</h3>
      <p className="muted" style={{ fontSize: 13, lineHeight: 1.6 }}>
        Create downloads an encrypted file (<code>zp-node-recovery-pack-v2</code>) sealed under
        a generated 130-bit secret. Prove uploads that file + the secret; the node decrypts and
        runs the ceremony engine. Online prove locks after 5 failures for 15 minutes — that
        limit protects this API only, never a copy of the file someone else is holding, which
        is why the secret is not yours to choose.
      </p>
      <p className="muted" style={{ fontSize: 13, lineHeight: 1.6 }}>
        <strong>Holding an old v1 pack?</strong> Packs sealed under a 4–6 digit passcode are
        enumerable offline and must be treated as compromised if a copy ever left this host.
        Re-issue it below (upload it under &ldquo;Replace an existing pack&rdquo;), then destroy
        every copy of the old file — the digest of the replaced artifact is recorded in the
        audit trail so the destruction can be signed off.
      </p>

      {error ? (
        <p className="err" role="alert">
          {error}
        </p>
      ) : null}
      {shownSecret ? (
        <div className="banner" role="alert" data-testid="pack-secret-shown">
          <strong>Save this secret now — it is shown once and never again.</strong>
          <p className="mono" style={{ fontSize: 14, wordBreak: "break-all", marginTop: 6 }}>
            {shownSecret}
          </p>
          <p className="muted" style={{ fontSize: 12 }}>
            The node does not keep it. Without it the pack cannot be opened, by you or by
            anyone who takes a copy.
          </p>
        </div>
      ) : null}
      {createDigest ? (
        <p className="muted" style={{ fontSize: 12 }} role="status">
          Pack downloaded. content_sha256={createDigest.slice(0, 16)}…
        </p>
      ) : null}
      {destroyDigest ? (
        <p className="err" role="alert" data-testid="pack-destroy-notice">
          Replaced pack {destroyDigest.slice(0, 16)}… — destroy every copy of that file now
          (offsite backups, object storage, laptops, mail).
        </p>
      ) : null}
      {proveId ? (
        <p className="muted" style={{ fontSize: 12 }} role="status">
          Prove accepted — ceremony {proveId}. Check Verify for stamps.
        </p>
      ) : null}
      {provenLegacy ? (
        <p className="err" role="alert" data-testid="pack-legacy-proven-notice">
          That was a superseded v1 pack sealed under a digit passcode. Treat it as compromised:
          re-issue it under &ldquo;Replace an existing pack&rdquo; and destroy every copy of the
          old file before relying on this node&apos;s custody again.
        </p>
      ) : null}

      {mode === "create" || mode === "both" ? (
        <form onSubmit={(e) => void onCreate(e)} autoComplete="off" style={{ marginTop: 12 }}>
          <h4 style={{ fontSize: 13 }}>Create pack</h4>
          <div className="field">
            <label htmlFor="pack-secret-create">
              Pack secret (generated — write it down before continuing)
            </label>
            <input
              id="pack-secret-create"
              data-testid="pack-secret-create"
              type="text"
              readOnly
              value={createSecret}
              style={{ fontFamily: "var(--mono, monospace)", fontSize: 13 }}
            />
            <button
              type="button"
              className="mini-btn"
              data-testid="pack-secret-regenerate"
              style={{ marginTop: 6 }}
              onClick={() => {
                setCreateSecret(generateRecoveryPackSecret());
                setSecretSaved(false);
              }}
              disabled={createMut.isPending}
            >
              Generate a different secret
            </button>
          </div>
          <div className="field">
            <label htmlFor="pack-secret-saved" style={{ fontWeight: 400 }}>
              <input
                id="pack-secret-saved"
                data-testid="pack-secret-saved"
                type="checkbox"
                checked={secretSaved}
                onChange={(e) => setSecretSaved(e.target.checked)}
                disabled={createMut.isPending}
              />{" "}
              I have written this secret down somewhere the pack file is not.
            </label>
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
              disabled={createMut.isPending}
              placeholder="≥32 characters when sealed"
              style={{ fontFamily: "var(--mono, monospace)", fontSize: 13 }}
            />
          </div>
          <details style={{ marginBottom: 12 }}>
            <summary style={{ fontSize: 13, cursor: "pointer" }}>
              Replace an existing pack (re-issue a v1 or rotate a v2)
            </summary>
            <p className="muted" style={{ fontSize: 12, lineHeight: 1.6 }}>
              The node opens the old pack, re-seals the same master under the new secret above,
              and reports the digest to destroy. The master key never reaches this browser.
            </p>
            <div className="field">
              <label htmlFor="pack-from-file">Existing pack file</label>
              <input
                id="pack-from-file"
                data-testid="pack-from-file"
                type="file"
                accept="application/json,.json"
                disabled={createMut.isPending}
                onChange={(e) => readPackFile(e.target.files?.[0] ?? null, setFromPackText)}
              />
            </div>
            <div className="field">
              <label htmlFor="pack-from-secret">Its secret (or old digit passcode)</label>
              <input
                id="pack-from-secret"
                data-testid="pack-from-secret"
                type="password"
                autoComplete="off"
                value={fromPackSecret}
                onChange={(e) => setFromPackSecret(e.target.value)}
                disabled={createMut.isPending}
              />
            </div>
          </details>
          <button
            type="submit"
            className="mini-btn primary"
            disabled={createMut.isPending || !secretSaved}
          >
            {createMut.isPending
              ? "Creating…"
              : fromPackText.length > 0
                ? "Re-issue & download pack"
                : "Create & download pack"}
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
              disabled={proveMut.isPending}
              onChange={(e) => readPackFile(e.target.files?.[0] ?? null, setPackText)}
            />
          </div>
          <div className="field">
            <label htmlFor="pack-secret-prove">Pack secret</label>
            <input
              id="pack-secret-prove"
              data-testid="pack-secret-prove"
              type="password"
              autoComplete="off"
              value={proveSecret}
              onChange={(e) => setProveSecret(e.target.value)}
              disabled={proveMut.isPending}
            />
          </div>
          <div className="field">
            <label htmlFor="pack-legacy-v1" style={{ fontWeight: 400 }}>
              <input
                id="pack-legacy-v1"
                data-testid="pack-legacy-v1"
                type="checkbox"
                checked={proveLegacy}
                onChange={(e) => setProveLegacy(e.target.checked)}
                disabled={proveMut.isPending}
              />{" "}
              This is an old v1 pack sealed under a 4–6 digit passcode.
            </label>
          </div>
          <button
            type="submit"
            className="mini-btn primary"
            disabled={
              proveMut.isPending ||
              packText.length === 0 ||
              proveSecret.length === 0
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
            disabled={!createDigest }
          >
            Continue to prove
          </button>
        ) : null}
      </div>
    </div>
  );
}

function RunStep({
  onNext,
  onBack,
}: {
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
    queryKey: ["recovery-ceremony-status", ceremonyId],
    queryFn: () => getRecoveryCeremonyStatus(ceremonyId ?? undefined),
    enabled: ceremonyId !== null,
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
            disabled={running || done}
            minLength={32}
            required
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
            disabled={running || done || masterKey.length < 32}
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
  onBack,
}: {
  onBack: () => void;
}) {
  const q = useQuery({
    queryKey: ["wallets-recovery-verify"],
    queryFn: listWalletsInventory,
    refetchInterval: 5_000,
    
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

      {!live ? (
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
