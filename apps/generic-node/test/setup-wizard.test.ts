// Setup wizard gate order + vault master show-once + verified-facts policy.

import { afterEach, describe, expect, it } from "vitest";
import {
  applyPwaInstalledEvidence,
  applySetupPatch,
  applyTypedDeviceBreakGlass,
  assertSetupSecretFree,
  buildSetupStateView,
  collectSetupSecretLeaks,
  DEVICE_BREAK_GLASS_PHRASE,
  EMPTY_SETUP_FLAGS,
  isAllowBrowserTabSetup,
  isDeviceBreakGlassActive,
  isPwaInstallEvidence,
  isSetupAckWizardLegacyEnabled,
  isSetupComplete,
  resolveCurrentStep,
  resolveNextStep,
  day0Facts,
  w4Done,
  type SetupLiveSignals,
  type SetupStateFlags,
} from "../src/setup-wizard.js";

import {
  acknowledgeOfflineBackup,
  assertDistinctFromBackupKek,
  createConfiguredVaultMasterState,
  createVirginVaultMasterState,
  generateShowOnce,
  refuseSecondReveal,
  statusFromState,
  vaultReadyForSetup,
  VaultMasterError,
} from "../src/setup-vault-master.js";

const baseSignals = (over: Partial<SetupLiveSignals> = {}): SetupLiveSignals => ({
  mustChangePassword: false,
  mustEnrolTotp: false,
  receivePackEnabled: true,
  ...over,
});

/** Verified-fact signals that can complete production setup (plus optional W8–W11 flags). */
const verifiedSignals = (over: Partial<SetupLiveSignals> = {}): SetupLiveSignals =>
  baseSignals({
    pwaInstalled: true,
    deviceEnrolled: true,
    vaultConfigured: true,
    recoveryVerifiedEligibleCount: 1,
    reportingKeyActive: true,
    ...over,
  });

afterEach(() => {
  delete process.env.SETUP_ACK_WIZARD_LEGACY;
  delete process.env.ALLOW_BROWSER_TAB_SETUP;
});

function advanceAuthSecure(flags: SetupStateFlags = EMPTY_SETUP_FLAGS): SetupStateFlags {
  return applySetupPatch(flags, baseSignals(), { w0_secure_context_ok: true }, undefined, false);
}

/** Legacy path used only when SETUP_ACK_WIZARD_LEGACY is on. */
function advanceToW5Legacy(flags: SetupStateFlags = EMPTY_SETUP_FLAGS): SetupStateFlags {
  let f = flags;
  const s = baseSignals();
  f = applySetupPatch(f, s, { w0_secure_context_ok: true }, undefined, true);
  f = applySetupPatch(f, s, { w3_pwa_skipped: true }, undefined, true);
  f = applySetupPatch(f, s, { w4_break_glass_ack: true }, undefined, true);
  return f;
}

describe("setup wizard gate order", () => {
  it("fresh admin starts at W0 when password+totp still required", () => {
    const s = baseSignals({ mustChangePassword: true, mustEnrolTotp: true });
    expect(resolveCurrentStep(EMPTY_SETUP_FLAGS, s, false)).toBe("W0");
    const view = buildSetupStateView(EMPTY_SETUP_FLAGS, s, undefined, false);
    expect(view.complete).toBe(false);
    expect(view.ceremony_master_key_blocked).toBe(true);
    expect(view.steps.find((x) => x.id === "W1")?.status).toBe("pending");
  });

  it("after password+TOTP, current step advances past W1/W2 to W3 (PWA required)", () => {
    const s = baseSignals();
    const f = applySetupPatch(EMPTY_SETUP_FLAGS, s, { w0_secure_context_ok: true }, undefined, false);
    expect(resolveCurrentStep(f, s, false)).toBe("W3");
  });


  it("W3 hollow skip does not advance; durable evidence does", () => {
    const s = baseSignals();
    let f = applySetupPatch(EMPTY_SETUP_FLAGS, s, { w0_secure_context_ok: true }, undefined, false);
    // Hollow ack flags are stripped in production — no-op.
    f = applySetupPatch(f, s, { w3_pwa_skipped: true }, undefined, false);
    expect(f.w3_pwa_skipped).toBe(false);
    expect(resolveCurrentStep(f, s, false)).toBe("W3");
    f = applyPwaInstalledEvidence(f, { evidence: "standalone" }, "2026-08-03T12:00:00.000Z");
    expect(f.pwa_installed_at).toBeTruthy();
    expect(f.pwa_install_evidence).toBe("standalone");
    expect(resolveCurrentStep(f, s, false)).toBe("W4");
  });

  it("pwa-installed rejects ack and non-enum evidence", () => {
    expect(() => applyPwaInstalledEvidence(EMPTY_SETUP_FLAGS, { ack: true })).toThrow(
      /evidence enum|not ack/i,
    );
    expect(() => applyPwaInstalledEvidence(EMPTY_SETUP_FLAGS, { evidence: "maybe" })).toThrow(
      /standalone|fullscreen|appinstalled/i,
    );
    expect(isPwaInstallEvidence("standalone")).toBe(true);
    expect(isPwaInstallEvidence("nope")).toBe(false);
    expect(isAllowBrowserTabSetup({ ALLOW_BROWSER_TAB_SETUP: "1" })).toBe(true);
    expect(isAllowBrowserTabSetup({})).toBe(false);
  });

  it("lab ALLOW_BROWSER_TAB_SETUP satisfies W3 without durable column", () => {
    const s = baseSignals({ allowBrowserTabSetup: true });
    const f = applySetupPatch(EMPTY_SETUP_FLAGS, s, { w0_secure_context_ok: true }, undefined, false);
    expect(resolveCurrentStep(f, s, false)).toBe("W4");
    const view = buildSetupStateView(f, s, undefined, false);
    expect(view.pwa_installed).toBe(true);
    expect(view.allow_browser_tab_setup).toBe(true);
  });


  it("production: ack-only PATCH fields are ignored or refused", () => {
    const s = baseSignals();
    let f = advanceAuthSecure();
    f = applySetupPatch(f, s, { w3_pwa_ack: true, w3_pwa_skipped: true }, undefined, false);
    expect(f.w3_pwa_ack).toBe(false);
    expect(f.w3_pwa_skipped).toBe(false);
    expect(resolveCurrentStep(f, s, false)).toBe("W3");

    // Quiet w4_* client acks are refused (not silent no-op) — enrol or typed BREAK GLASS.
    expect(() =>
      applySetupPatch(f, s, { w4_device_enrolled: true }, undefined, false),
    ).toThrow(/server-derived|inventory/i);
    expect(() =>
      applySetupPatch(f, s, { w4_break_glass_ack: true }, undefined, false),
    ).toThrow(/BREAK GLASS|checkbox/i);

    f = applySetupPatch(
      f,
      s,
      {
        w6_ceremony_placeholder_ack: true,
        w7_recovery_wallet_ok: true,
      },
      undefined,
      false,
    );
    expect(f.w4_device_enrolled).toBe(false);
    expect(f.w4_break_glass_ack).toBe(false);
    expect(f.w6_ceremony_placeholder_ack).toBe(false);
    expect(f.w7_recovery_wallet_ok).toBe(false);
    expect(isSetupComplete(f, s, false)).toBe(false);
  });


  it("W4 quiet device/break-glass PATCH is rejected", () => {
    const s = baseSignals({ pwaInstalled: true });
    const f = applySetupPatch(EMPTY_SETUP_FLAGS, s, { w0_secure_context_ok: true }, undefined, false);
    // With pwaInstalled signal W3 is done; still on W4 without device.
    expect(() => applySetupPatch(f, s, { w4_device_enrolled: true }, undefined, false)).toThrow(
      /server-derived|inventory/i,
    );
    expect(() => applySetupPatch(f, s, { w4_break_glass_ack: true }, undefined, false)).toThrow(
      /BREAK GLASS|checkbox/i,
    );
    expect(w4Done(f, s, false)).toBe(false);
    expect(resolveCurrentStep(f, s, false)).toBe("W4");
  });

  it("W4 completes via live deviceEnrolled probe without flags", () => {
    const s = baseSignals({ pwaInstalled: true, deviceEnrolled: true });
    const f = applySetupPatch(EMPTY_SETUP_FLAGS, s, { w0_secure_context_ok: true }, undefined, false);
    expect(w4Done(f, s, false)).toBe(true);
    expect(resolveCurrentStep(f, s, false)).toBe("W5");
  });

  it("typed BREAK GLASS advances W4; wrong phrase fails", () => {
    const s = baseSignals({ pwaInstalled: true });
    let f = applySetupPatch(EMPTY_SETUP_FLAGS, s, { w0_secure_context_ok: true }, undefined, false);
    expect(() => applyTypedDeviceBreakGlass(f, s, "break glass", undefined, false)).toThrow(
      /exactly BREAK GLASS/i,
    );
    expect(() => applyTypedDeviceBreakGlass(f, s, " BREAK GLASS", undefined, false)).toThrow(
      /exactly BREAK GLASS/i,
    );
    f = applyTypedDeviceBreakGlass(f, s, DEVICE_BREAK_GLASS_PHRASE, undefined, false);
    expect(f.w4_break_glass_ack).toBe(true);
    expect(w4Done(f, s, false)).toBe(true);
    expect(isDeviceBreakGlassActive(f, s)).toBe(true);
    expect(isDeviceBreakGlassActive(f, baseSignals({ deviceEnrolled: true }))).toBe(false);
    expect(resolveCurrentStep(f, s, false)).toBe("W5");
  });

  it("production: ack-only path cannot complete setup", () => {
    const s = baseSignals({ reportingKeyActive: true });
    let f = advanceAuthSecure();
    // Even if flags were somehow already true (legacy data), complete still needs live facts.
    f = {
      ...f,
      w3_pwa_ack: true,
      w3_pwa_skipped: true,
      w4_device_enrolled: true,
      w4_break_glass_ack: true,
      w5_vault_ready: true,
      w5_offline_backup_ack: true,
      w6_ceremony_placeholder_ack: true,
      w7_recovery_wallet_ok: true,
      w8_implementer_skipped: true,
      w9_reporting_key_ok: true,
      w10_packs_skipped: true,
      w11_mini_steps_skipped: true,
    };
    expect(isSetupComplete(f, s, false)).toBe(false);
    // Still incomplete without pwaInstalled + device + recovery inventory.
    expect(
      isSetupComplete(
        f,
        baseSignals({
          pwaInstalled: true,
          deviceEnrolled: true,
          vaultConfigured: true,
          recoveryVerifiedEligibleCount: 0,
          reportingKeyActive: true,
        }),
        false,
      ),
    ).toBe(false);
  });

  it("production: complete only with server-verified facts", () => {
    const s = verifiedSignals();
    let f = advanceAuthSecure();
    f = applySetupPatch(
      f,
      s,
      { w5_vault_ready: true, w5_offline_backup_ack: true },
      undefined,
      false,
    );
    // W8–W11 hollow optional steps are not required for day-0 complete.
    expect(isSetupComplete(f, s, false)).toBe(true);
    const view = buildSetupStateView(f, s, "2026-08-03T00:00:00.000Z", false);
    expect(view.complete).toBe(true);
    expect(view.current_step).toBe("W12");
    expect(view.next_step).toBe("home");
    expect(view.password_ok).toBe(true);
    expect(view.totp_ok).toBe(true);
    expect(view.pwa_installed).toBe(true);
    expect(view.device_enrolled).toBe(true);
    expect(view.vault_ready).toBe(true);
    expect(view.recovery_proven).toBe(true);
    expect(view.flags.completed_at).toBeTruthy();
  });


  it("production: durable pwa_installed_at alone satisfies W3 without live signal", () => {
    const s = baseSignals({
      deviceEnrolled: true,
      vaultConfigured: true,
      recoveryVerifiedEligibleCount: 1,
      reportingKeyActive: true,
    });
    let f = advanceAuthSecure();
    f = applyPwaInstalledEvidence(f, { evidence: "fullscreen" }, "2026-08-03T12:00:00.000Z");
    expect(resolveCurrentStep(f, s, false)).toBe("W5"); // W4 done via deviceEnrolled
    f = {
      ...f,
      w5_vault_ready: true,
      w5_offline_backup_ack: true,
    };
    expect(isSetupComplete(f, s, false)).toBe(true);
    const view = buildSetupStateView(f, s, undefined, false);
    expect(view.pwa_installed).toBe(true);
    expect(view.complete).toBe(true);
    expect(view.next_step).toBe("home");
  });

  it("password/TOTP gates still block complete", () => {
    const s = verifiedSignals({ mustChangePassword: true });
    const f = {
      ...EMPTY_SETUP_FLAGS,
      w0_secure_context_ok: true,
      w5_vault_ready: true,
      w5_offline_backup_ack: true,
    };
    expect(isSetupComplete(f, s, false)).toBe(false);
    expect(isSetupComplete(f, verifiedSignals({ mustEnrolTotp: true }), false)).toBe(false);
  });

  it("legacy env restores ack skip path for tests", () => {
    expect(isSetupAckWizardLegacyEnabled({ SETUP_ACK_WIZARD_LEGACY: "1" })).toBe(true);
    expect(isSetupAckWizardLegacyEnabled({})).toBe(false);
    const s = baseSignals({
      recoveryVerifiedEligibleCount: 1,
      reportingKeyActive: true,
    });
    let f = advanceToW5Legacy();
    f = applySetupPatch(f, s, { w5_vault_ready: true, w5_offline_backup_ack: true }, undefined, true);
    f = applySetupPatch(f, s, { w6_ceremony_placeholder_ack: true }, undefined, true);
    f = applySetupPatch(f, s, { w8_implementer_skipped: true }, undefined, true);
    f = applySetupPatch(f, s, { w10_packs_skipped: true }, undefined, true);
    f = applySetupPatch(f, s, { w11_mini_steps_skipped: true }, undefined, true);
    expect(isSetupComplete(f, s, true)).toBe(true);
  });

  it("refresh resumes correct server step (durable flags + live signals)", () => {
    const s = verifiedSignals({ pwaInstalled: true, deviceEnrolled: true });
    let f = advanceAuthSecure();
    f = applySetupPatch(
      f,
      s,
      { w5_vault_ready: true, w5_offline_backup_ack: true },
      undefined,
      false,
    );
    // Day-0 facts all true → home / W12.
    expect(resolveCurrentStep(f, s, false)).toBe("W12");
    expect(resolveNextStep(f, s, false)).toBe("home");
    const again = buildSetupStateView(f, s, undefined, false);
    expect(again.current_step).toBe("W12");
    expect(again.next_step).toBe("home");
  });

  it("day-0 next_step order: install→device→vault→backup→home", () => {
    let f = advanceAuthSecure();
    const s0 = baseSignals();
    expect(resolveNextStep(f, s0, false)).toBe("install");
    expect(day0Facts(f, s0, false).password_ok).toBe(true);
    expect(day0Facts(f, s0, false).pwa_installed).toBe(false);

    f = applyPwaInstalledEvidence(f, { evidence: "standalone" }, "2026-08-03T12:00:00.000Z");
    expect(resolveNextStep(f, s0, false)).toBe("device");

    const sDev = baseSignals({ deviceEnrolled: true, pwaInstalled: true });
    expect(resolveNextStep(f, sDev, false)).toBe("vault");

    f = applySetupPatch(
      f,
      sDev,
      { w5_vault_ready: true, w5_offline_backup_ack: true },
      undefined,
      false,
    );
    expect(resolveNextStep(f, sDev, false)).toBe("backup");
    expect(day0Facts(f, sDev, false).vault_ready).toBe(true);
    expect(day0Facts(f, sDev, false).recovery_proven).toBe(false);

    const sDone = verifiedSignals();
    expect(resolveNextStep(f, sDone, false)).toBe("home");
    const view = buildSetupStateView(f, sDone, undefined, false);
    expect(view.complete).toBe(true);
    expect(view.next_step).toBe("home");
  });

  it("rejects master_key on setup_state patch (ceremony blocked)", () => {
    const s = baseSignals();
    const f = advanceAuthSecure();
    expect(() =>
      applySetupPatch(f, s, { master_key: "x".repeat(40) } as Record<string, unknown>, undefined, false),
    ).toThrow(/master key|secret-bearing/i);
  });

  it("W6 production tracks recovery-verified fact — placeholder ack ignored", () => {
    const s = verifiedSignals({ recoveryVerifiedEligibleCount: 0 });
    let f = advanceAuthSecure();
    f = applySetupPatch(
      f,
      s,
      { w5_vault_ready: true, w5_offline_backup_ack: true, w6_ceremony_placeholder_ack: true },
      undefined,
      false,
    );
    expect(f.w6_ceremony_placeholder_ack).toBe(false);
    const view = buildSetupStateView(f, s, undefined, false);
    expect(view.steps.find((x) => x.id === "W6")?.status).toBe("pending");
    expect(view.ceremony_master_key_blocked).toBe(true);
  });

  it("setup_state view is secret-free", () => {
    const view = buildSetupStateView(
      EMPTY_SETUP_FLAGS,
      baseSignals({ mustChangePassword: true }),
      undefined,
      false,
    );
    assertSetupSecretFree(view);
    expect(collectSetupSecretLeaks(view)).toEqual([]);
  });

  it("cannot complete W5 without offline backup ack", () => {
    const s = verifiedSignals();
    let f = advanceAuthSecure();
    f = applySetupPatch(f, s, { w5_vault_ready: true }, undefined, false);
    expect(resolveCurrentStep(f, s, false)).toBe("W5");
  });
});

describe("vault master show-once", () => {
  it("virgin generate returns key once; second generate refused", () => {
    const state = createVirginVaultMasterState();
    expect(statusFromState(state).can_generate).toBe(true);
    const first = generateShowOnce(state, { backupMasterKey: "backup-kek-distinct-value-32chars!!" });
    expect(first.master_key.length).toBeGreaterThanOrEqual(32);
    expect(first.vault_master_distinct_from_backup_kek).toBe(true);
    expect(statusFromState(state).plaintext_pending_ack).toBe(true);
    expect(statusFromState(state).can_generate).toBe(false);

    expect(() => generateShowOnce(state)).toThrow(VaultMasterError);
    expect(() => refuseSecondReveal(state)).toThrow(/show-once|not retrievable/i);
  });

  it("GET-equivalent status after generate never includes master_key", () => {
    const state = createVirginVaultMasterState();
    generateShowOnce(state);
    const st = statusFromState(state);
    assertSetupSecretFree(st);
    expect("master_key" in st).toBe(false);
    expect(JSON.stringify(st)).not.toMatch(/master_key/);
  });

  it("offline ack required; wipes plaintext; second ack conflicts", () => {
    const state = createVirginVaultMasterState();
    generateShowOnce(state);
    const ack = acknowledgeOfflineBackup(state, { ack: true });
    expect(ack.phase).toBe("sealed");
    expect(ack.offline_backup_acked).toBe(true);
    expect(state.pendingPlaintext).toBeNull();
    expect(vaultReadyForSetup(state)).toBe(true);
    expect(() => acknowledgeOfflineBackup(state, { ack: true })).toThrow(/already/i);
  });

  it("rejects vault master equal to backup KEK", () => {
    const same = "identical-custody-secret-value-32ch";
    expect(() => assertDistinctFromBackupKek(same, same)).toThrow(/BACKUP_MASTER_KEY/i);

    const state = createVirginVaultMasterState();
    state.phase = "virgin";
    const g = generateShowOnce(state);
    state.phase = "shown";
    state.pendingPlaintext = "shared-secret-value-across-domains!!";
    expect(() =>
      acknowledgeOfflineBackup(state, {
        ack: true,
        backupMasterKey: "shared-secret-value-across-domains!!",
      }),
    ).toThrow(VaultMasterError);
    void g;
  });

  it("configured env path cannot generate; ack still records offline", () => {
    const state = createConfiguredVaultMasterState("env-provisioned-vault-master-key-32");
    expect(statusFromState(state).phase).toBe("configured");
    expect(() => generateShowOnce(state)).toThrow(/configured/i);
    const ack = acknowledgeOfflineBackup(state, { ack: true });
    expect(ack.offline_backup_acked).toBe(true);
    expect(vaultReadyForSetup(state)).toBe(true);
  });

  it("no key in status JSON after seal", () => {
    const state = createVirginVaultMasterState();
    const g = generateShowOnce(state);
    acknowledgeOfflineBackup(state, { ack: true });
    const json = JSON.stringify(statusFromState(state));
    expect(json).not.toContain(g.master_key);
    expect(json).not.toMatch(/"master_key"/);
  });
});

describe("durable vault seal bootstrap (restart)", () => {
  it("bootstrapFromDurableSeal never restores plaintext; generate refused", async () => {
    const {
      bootstrapFromDurableSeal,
      durableSealFromBootstrap,
      resolveVaultMasterBootstrap,
    } = await import("../src/setup-vault-master-seal-store.js");

    const live = createVirginVaultMasterState();
    const g = generateShowOnce(live);
    const seal = durableSealFromBootstrap(live);
    expect(seal).not.toBeNull();
    expect(JSON.stringify(seal)).not.toContain(g.master_key);

    const restarted = bootstrapFromDurableSeal(seal!);
    expect(restarted.pendingPlaintext).toBeNull();
    expect(restarted.phase).toBe("shown");
    expect(() => generateShowOnce(restarted)).toThrow(VaultMasterError);
    expect(() => refuseSecondReveal(restarted)).toThrow(/show-once|not retrievable/i);

    const ack = acknowledgeOfflineBackup(restarted, { ack: true });
    expect(ack.phase).toBe("sealed");
    expect(vaultReadyForSetup(restarted)).toBe(true);

    const afterSeal = durableSealFromBootstrap(restarted)!;
    expect(afterSeal.phase).toBe("sealed");
    expect(afterSeal.offlineBackupAcked).toBe(true);

    const third = resolveVaultMasterBootstrap({ durableSeal: afterSeal });
    expect(third.phase).toBe("sealed");
    expect(third.pendingPlaintext).toBeNull();
    expect(() => generateShowOnce(third)).toThrow(VaultMasterError);
  });

  it("env VAULT_MASTER_KEY wins over durable seal (configured)", async () => {
    const { resolveVaultMasterBootstrap } = await import("../src/setup-vault-master-seal-store.js");
    const state = resolveVaultMasterBootstrap({
      vaultMasterKey: "env-provisioned-vault-master-key-32chars",
      durableSeal: {
        phase: "shown",
        keyFingerprintHex: "ab".repeat(32),
        offlineBackupAcked: true,
      },
    });
    expect(state.phase).toBe("configured");
    expect(state.offlineBackupAcked).toBe(true);
    expect(state.pendingPlaintext).toBeNull();
  });
});
