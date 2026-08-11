import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router";
import { useAuth } from "../store/auth.js";

export function LoginPage() {
  const user = useAuth((s) => s.user);
  const login = useAuth((s) => s.login);
  const nav = useNavigate();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to="/" replace />;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      // generic-node login is password-only; TOTP is a step-up on money mutations.
      const u = await login(username, password);
      // Incomplete setup: RequireAuth on "/" redirects via next_step.
      nav(u.mustChangePassword || u.mustEnrolTotp ? "/setup" : "/");
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Login failed");
      setBusy(false);
    }
  }

  return (
    <div className="auth-shell">
      <form className="auth-card" onSubmit={(e) => void onSubmit(e)}>
        <h1>Zu Node</h1>
        <p className="lead">Operator sign-in for this self-hosted custody node.</p>
        <div className="field">
          <label htmlFor="user">Username</label>
          <input id="user" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </div>
        <div className="field">
          <label htmlFor="pass">Password</label>
          <input id="pass" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>
        {err ? <p className="err">{err}</p> : null}
        <button className="btn-block" type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        <p className="muted" style={{ fontSize: 12.5, marginTop: 10 }}>
          Authenticator codes are required later for money actions (header <code className="mono">X-ZP-TOTP</code>).
        </p>
      </form>
    </div>
  );
}
