import { useEffect, useRef, useState } from "react";

export function TotpPrompt({
  title,
  detail,
  errorMessage,
  onSubmit,
  onCancel,
}: {
  title: string;
  detail?: string;
  errorMessage?: string;
  onSubmit: (code: string) => void | Promise<void>;
  onCancel: () => void;
}) {
  const [digits, setDigits] = useState(["", "", "", "", "", ""]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(errorMessage ?? null);
  const refs = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    refs.current[0]?.focus();
  }, []);

  useEffect(() => {
    setErr(errorMessage ?? null);
    if (errorMessage) {
      setDigits(["", "", "", "", "", ""]);
      setBusy(false);
      refs.current[0]?.focus();
    }
  }, [errorMessage]);

  async function finish(code: string) {
    setBusy(true);
    setErr(null);
    try {
      await onSubmit(code);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Invalid code");
      setBusy(false);
      setDigits(["", "", "", "", "", ""]);
      refs.current[0]?.focus();
    }
  }

  function setAt(i: number, v: string) {
    const d = v.replace(/\D/g, "").slice(-1);
    const next = [...digits];
    next[i] = d;
    setDigits(next);
    if (d && i < 5) refs.current[i + 1]?.focus();
    const code = next.join("");
    if (code.length === 6) void finish(code);
  }

  return (
    <div className="totp-overlay" role="dialog" aria-modal="true" aria-labelledby="totp-title">
      <div className="totp-card">
        <h2 id="totp-title" style={{ fontSize: 16, fontWeight: 650 }}>
          {title}
        </h2>
        {detail ? (
          <p className="muted" style={{ marginTop: 6, fontSize: 13 }}>
            {detail}
          </p>
        ) : null}
        <div className="totp-slots">
          {digits.map((d, i) => (
            <input
              key={i}
              ref={(el) => {
                refs.current[i] = el;
              }}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={1}
              value={d}
              disabled={busy}
              onChange={(e) => setAt(i, e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Backspace" && !digits[i] && i > 0) refs.current[i - 1]?.focus();
              }}
              aria-label={i === 0 ? "Verification code" : `Digit ${i + 1}`}
            />
          ))}
        </div>
        {err ? <p className="err">{err}</p> : null}
        <div className="form-actions">
          <button type="button" className="mini-btn" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            type="button"
            className="mini-btn primary"
            disabled={busy || digits.join("").length !== 6}
            onClick={() => void finish(digits.join(""))}
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}
