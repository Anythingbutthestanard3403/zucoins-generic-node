import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Link, useInRouterContext } from "react-router";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { apiSoftRead } from "../../lib/api.js";

function SettingsNavCard({
  to,
  title,
  detail,
  testId,
}: {
  to: string;
  title: string;
  detail: string;
  testId: string;
}) {
  const inRouter = useInRouterContext();
  const content = (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <strong style={{ fontSize: 13.5 }}>{title}</strong>
        <span aria-hidden="true" className="muted">→</span>
      </div>
      <p className="muted" style={{ fontSize: 12.5, margin: "4px 0 0" }}>
        {detail}
      </p>
    </>
  );
  const style = {
    display: "block",
    textDecoration: "none",
    color: "inherit",
    padding: "12px 14px",
  } as const;
  if (inRouter) {
    return (
      <Link to={to} className="card" data-testid={testId} style={style}>
        {content}
      </Link>
    );
  }
  return (
    <a href={to} className="card" data-testid={testId} style={style}>
      {content}
    </a>
  );
}

/** Wire shape for GET /admin/v1/settings (allowlisted; never an env dump). */
export interface EffectiveConfig {
  readonly public_base_url: string;
  readonly node_id: string;
  readonly gateway_hosts: readonly string[];
  readonly version: string;
  readonly backup_schedule_enabled: boolean;
  readonly push_configured: boolean;
}

const SETTINGS_FALLBACK: EffectiveConfig = {
  public_base_url: "",
  node_id: "",
  gateway_hosts: [],
  version: "",
  backup_schedule_enabled: false,
  push_configured: false,
};

export async function fetchEffectiveConfig() {
  return apiSoftRead<EffectiveConfig>("/settings", SETTINGS_FALLBACK);
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "11rem 1fr",
        gap: 12,
        padding: "10px 0",
        borderBottom: "1px solid var(--line)",
        alignItems: "baseline",
      }}
    >
      <dt className="muted" style={{ fontSize: 13, margin: 0 }}>
        {label}
      </dt>
      <dd style={{ margin: 0, fontSize: 13, wordBreak: "break-all" }}>{children}</dd>
    </div>
  );
}

function BoolTag({ value }: { value: boolean }) {
  return (
    <span className={value ? "ok" : "muted"} style={{ fontWeight: 600 }}>
      {value ? "Yes" : "No"}
    </span>
  );
}

/** Read-only Settings / About — secret-safe effective config only. */
export function SettingsPage() {
  const q = useQuery({
    queryKey: ["effective-config"],
    queryFn: fetchEffectiveConfig,
    staleTime: 30_000,
  });

  const result = q.data;
  const data = result?.data;
  const live = Boolean(result?.live);

  return (
    <div className="page">
      <div className="page-title-row">
        <h1>Settings</h1>
      </div>

      <div className="card form-card">
        <h2 style={{ fontSize: 14, marginBottom: 6 }}>Node identity</h2>
        <p className="muted" style={{ fontSize: 13, marginBottom: 12 }}>
          Read-only effective configuration for this process. Secrets (passwords, master keys,
          VAPID private keys, gateway credentials) are never shown here.
        </p>

        {result && !result.live ? <ApiErrorNote error={result.error} /> : null}

        {q.isLoading && !data && <p className="muted">Loading…</p>}

        {data && (
          <dl style={{ margin: 0 }}>
            <Row label="Public base URL">
              <span className="mono">{data.public_base_url}</span>
            </Row>
            <Row label="Node ID">
              <span className="mono">{data.node_id}</span>
            </Row>
            <Row label="Gateway hosts">
              {data.gateway_hosts.length === 0 ? (
                <span className="muted">None configured</span>
              ) : (
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {data.gateway_hosts.map((h) => (
                    <li key={h} className="mono">
                      {h}
                    </li>
                  ))}
                </ul>
              )}
            </Row>
            <Row label="Version">
              <span className="mono">{data.version}</span>
            </Row>
            <Row label="Backup schedule">
              <BoolTag value={data.backup_schedule_enabled} />
            </Row>
            <Row label="Push configured">
              <BoolTag value={data.push_configured} />
            </Row>
          </dl>
        )}

        {live && (
          <p className="muted" style={{ fontSize: 12, marginTop: 14 }}>
            Values match the running process. Changing them requires a redeploy (first-boot
            fields) — this page never accepts edits.
          </p>
        )}
        
      </div>

      <section
        className="card"
        data-testid="settings-admin-links"
        aria-label="Security, recovery, and policy modules"
        style={{ marginTop: 16 }}
      >
        <h2 style={{ fontSize: 14, marginBottom: 6 }}>Security, recovery &amp; policy modules</h2>
        <p className="muted" style={{ fontSize: 13, marginBottom: 12 }}>
          Direct access to hardware approval devices, encrypted custody backups, recovery ceremonies,
          operator sessions, reporting credentials, and global policy modules.
        </p>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))",
            gap: 12,
          }}
        >
          <SettingsNavCard
            to="/devices"
            title="Approval Devices"
            detail="Enrol or revoke WebCrypto hardware/browser approval keys."
            testId="settings-link-devices"
          />
          <SettingsNavCard
            to="/backup"
            title="Encrypted Backups"
            detail="Export and inspect encrypted custody backups."
            testId="settings-link-backup"
          />
          <SettingsNavCard
            to="/recovery-ceremony"
            title="Recovery Ceremony"
            detail="Run recovery pack verification or Mode A break-glass ceremony."
            testId="settings-link-recovery-ceremony"
          />
          <SettingsNavCard
            to="/operator-security"
            title="Operator Security"
            detail="Inspect active operator sessions, authenticator posture, and lockouts."
            testId="settings-link-operator-security"
          />
          <SettingsNavCard
            to="/reporting-keys"
            title="Reporting Keys"
            detail="Manage node-origin reporting credentials for gateway head reporting."
            testId="settings-link-reporting-keys"
          />
          <SettingsNavCard
            to="/auto-approve"
            title="Auto-Approve Policy"
            detail="Inspect global automated spend rules and window/lifetime caps."
            testId="settings-link-auto-approve"
          />
          <SettingsNavCard
            to="/verification-mode"
            title="Node-Verified Policy"
            detail="Manage implementers admitted for NODE_VERIFIED settlement."
            testId="settings-link-verification-mode"
          />
          <SettingsNavCard
            to="/api-keys"
            title="API Keys Inventory"
            detail="View and revoke implementer bearer credentials across connectors."
            testId="settings-link-api-keys"
          />
        </div>
      </section>
    </div>
  );
}
