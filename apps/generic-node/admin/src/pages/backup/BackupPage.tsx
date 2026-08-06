import { Link } from "react-router";

export function BackupPage() {
  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Backup</h1>
      </div>
      <div
        className="card form-card"
        style={{ borderColor: "color-mix(in srgb, var(--danger) 35%, var(--line))" }}
      >
        <h2 style={{ fontSize: 14, marginBottom: 8 }}>Spend-key warning</h2>
        <p className="muted" style={{ fontSize: 13, marginBottom: 14 }}>
          Wallet export contains material that can spend funds. Never commit backup files. Store
          offline.
        </p>
        <p className="muted" style={{ fontSize: 13, marginBottom: 14 }}>
          <strong>Backup is not recovery verification.</strong> Encrypted backup schedule and DR
          restore do <em>not</em> stamp <code>recovery_verified_at</code>. For pool eligibility
          use{" "}
          <Link to="/recovery-ceremony" className="linkish">
            Recovery
          </Link>{" "}
          (browser Mode A primary).
        </p>
        <p className="muted" style={{ fontSize: 13, marginBottom: 14 }}>
          Dashboard export/import controls are not mounted. Day-2 / DR host tooling (break-glass —
          not first-boot setup):
        </p>
        <pre className="mono" style={{ fontSize: 12, marginBottom: 14, whiteSpace: "pre-wrap" }}>
          node dist/dr/cli.js backup --out &lt;file&gt;{"\n"}node dist/dr/cli.js restore --in
          &lt;file&gt;
        </pre>
        <div className="form-actions">
          <button
            type="button"
            className="mini-btn primary"
            disabled
            aria-disabled="true"
            title="Not available in the dashboard — use host DR tooling above when needed."
          >
            Export backup
          </button>
          <button
            type="button"
            className="mini-btn"
            disabled
            aria-disabled="true"
            title="Not available in the dashboard — use host DR tooling above when needed."
          >
            Import backup…
          </button>
        </div>
      </div>
    </div>
  );
}
