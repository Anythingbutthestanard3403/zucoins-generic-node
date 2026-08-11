/**
 * Day-0 funnel SPA steps.
 * Thin wrappers: install/device/vault reuse SetupPage; backup/prove reuse PackStep.
 */
import { useNavigate } from "react-router";
import { PackStep } from "../ceremony/RecoveryCeremonyPage.js";
import { SetupPage } from "../Setup.js";
import {
  clearPackCreateMarker,
  markPackCreated,
  pathForNextStep,
} from "../../funnel/day0.js";

/** Install / device / vault — server-driven Setup sections. */
export function StartSetupStepPage() {
  return <SetupPage />;
}

export function StartBackupPage() {
  const nav = useNavigate();
  return (
    <div className="auth-shell" data-testid="day0-step-backup">
      <div className="auth-card" style={{ maxWidth: 520 }}>
        <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
          Day-0 · Recovery pack create
        </p>
        <PackStep
          mode="create"
          onCreated={() => {
            markPackCreated();
          }}
          onNext={() => {
            markPackCreated();
            nav(pathForNextStep("prove"), { replace: true });
          }}
        />
      </div>
    </div>
  );
}

export function StartProvePage() {
  const nav = useNavigate();
  return (
    <div className="auth-shell" data-testid="day0-step-prove">
      <div className="auth-card" style={{ maxWidth: 520 }}>
        <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
          Day-0 · Recovery pack prove
        </p>
        <PackStep
          mode="prove"
          onBack={() => nav(pathForNextStep("backup"), { replace: true })}
          onNext={() => {
            clearPackCreateMarker();
            nav("/", { replace: true });
          }}
        />
      </div>
    </div>
  );
}
