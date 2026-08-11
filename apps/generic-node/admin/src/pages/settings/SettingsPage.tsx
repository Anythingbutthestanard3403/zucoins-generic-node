import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { ApiErrorNote } from "../../components/ApiErrorNote.js";
import { apiSoftRead } from "../../lib/api.js";

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
    </div>
  );
}
