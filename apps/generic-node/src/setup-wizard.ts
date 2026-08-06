// Setup wizard state machine.
//
// Durable secret-free step flags + pure gate-sequence evaluation. Never stores
// master keys, TOTP secrets, passwords, or ik_/sh_ material.
//
// Production `complete` requires server-verified facts only — not
// client ack booleans (w3_pwa_ack, w4_*, w6_ceremony_placeholder_ack,
// w7_recovery_wallet_ok). Lab may restore legacy ack complete via
// SETUP_ACK_WIZARD_LEGACY=1.

/** Canonical wizard step ids in forced sequence. */
export const SETUP_STEPS = [
  "W0",
  "W1",
  "W2",
  "W3",
  "W4",
  "W5",
  "W6",
  "W7",
  "W8",
  "W9",
  "W10",
  "W11",
  "W12",
] as const;

export type SetupStepId = (typeof SETUP_STEPS)[number];

/** Steps that may be skipped with an explicit ack (W3 is mandatory). */
export const OPTIONAL_STEPS = ["W8", "W10", "W11"] as const;
export type OptionalSetupStepId = (typeof OPTIONAL_STEPS)[number];

export function isOptionalSetupStep(step: string): step is OptionalSetupStepId {
  return (OPTIONAL_STEPS as readonly string[]).includes(step);
}


/** Closed evidence enum for durable PWA install. */
export const PWA_INSTALL_EVIDENCE = ["standalone", "fullscreen", "appinstalled"] as const;
export type PwaInstallEvidence = (typeof PWA_INSTALL_EVIDENCE)[number];

export function isPwaInstallEvidence(value: unknown): value is PwaInstallEvidence {
  return typeof value === "string" && (PWA_INSTALL_EVIDENCE as readonly string[]).includes(value);
}

/**
 * Secret-free durable flags. W1/W2 completion is derived from the operator
 * user row (mustChangePassword / mustEnrolTotp), not stored here.
 */
export interface SetupStateFlags {
  /** Client reported secure context (HTTPS or loopback). */
  readonly w0_secure_context_ok: boolean;
  /** Operator acked PWA install prompt (legacy hollow ack — not install evidence). */
  readonly w3_pwa_ack: boolean;
  /** Operator explicitly skipped optional PWA step (legacy; blocked in prod). */
  readonly w3_pwa_skipped: boolean;
  /**
   * Durable PWA install evidence timestamp (ISO). Set only via
   * POST /admin/v1/setup/pwa-installed with a real evidence enum.
   */
  readonly pwa_installed_at: string | null;
  /** Evidence kind that produced pwa_installed_at; null when not installed. */
  readonly pwa_install_evidence: PwaInstallEvidence | null;
  /**
   * Durable mirror when server observed ≥1 active device (optional cache).
   * Live probe `SetupLiveSignals.deviceEnrolled` is authoritative for W4.
   * Client PATCH cannot set this in production.
   */
  readonly w4_device_enrolled: boolean;
  /**
   * Typed break-glass path (exact phrase BREAK GLASS via dedicated endpoint +
   * audit). Quiet checkbox / PATCH of this flag is rejected in production.
   */
  readonly w4_break_glass_ack: boolean;
  /** Vault master path complete (virgin show-once + offline ack, or already unlocked). */
  readonly w5_vault_ready: boolean;
  /** Offline backup of vault master acknowledged (W5 sub-gate). */
  readonly w5_offline_backup_ack: boolean;
  /**
   * Ceremony step acknowledged as PLACEHOLDER. Never means recovery_verified_at
   * was stamped — the sole writer remains the ceremony process.
   */
  readonly w6_ceremony_placeholder_ack: boolean;
  /** ≥1 recovery_verified node_generated AVAILABLE wallet observed. */
  readonly w7_recovery_wallet_ok: boolean;
  /** Implementer key shown-once acked (or skipped). */
  readonly w8_implementer_key_ack: boolean;
  readonly w8_implementer_skipped: boolean;
  /** Reporting key present when RECEIVE pack needed. */
  readonly w9_reporting_key_ok: boolean;
  /** Packs mini-step ack / skip. */
  readonly w10_packs_ack: boolean;
  readonly w10_packs_skipped: boolean;
  readonly w11_mini_steps_ack: boolean;
  readonly w11_mini_steps_skipped: boolean;
  /** Wall-clock ISO when wizard reached W12; null while incomplete. */
  readonly completed_at: string | null;
}

export const EMPTY_SETUP_FLAGS: SetupStateFlags = Object.freeze({
  w0_secure_context_ok: false,
  w3_pwa_ack: false,
  w3_pwa_skipped: false,
  pwa_installed_at: null,
  pwa_install_evidence: null,
  w4_device_enrolled: false,
  w4_break_glass_ack: false,
  w5_vault_ready: false,
  w5_offline_backup_ack: false,
  w6_ceremony_placeholder_ack: false,
  w7_recovery_wallet_ok: false,
  w8_implementer_key_ack: false,
  w8_implementer_skipped: false,
  w9_reporting_key_ok: false,
  w10_packs_ack: false,
  w10_packs_skipped: false,
  w11_mini_steps_ack: false,
  w11_mini_steps_skipped: false,
  completed_at: null,
});

/**
 * Lab-only browser-tab bypass for the mandatory PWA wall.
 * Default off. True when ALLOW_BROWSER_TAB_SETUP is 1/true/yes (case-insensitive).
 */
export function isAllowBrowserTabSetup(
  env: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env,
): boolean {
  const raw = env.ALLOW_BROWSER_TAB_SETUP;
  if (raw === undefined || raw === null) return false;
  const v = String(raw).trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

/** True when durable install evidence exists (or lab tab bypass / live signal). */
export function isPwaInstalled(
  f: SetupStateFlags,
  opts: { readonly allowBrowserTabSetup?: boolean; readonly pwaInstalledSignal?: boolean } = {},
): boolean {
  if (opts.pwaInstalledSignal === true) return true;
  if (opts.allowBrowserTabSetup === true) return true;
  return typeof f.pwa_installed_at === "string" && f.pwa_installed_at.length > 0;
}

/** Live probes that can satisfy steps without a manual ack. */
export interface SetupLiveSignals {
  /** Operator still must change bootstrap password. */
  readonly mustChangePassword: boolean;
  /** Operator still must enrol TOTP. */
  readonly mustEnrolTotp: boolean;
  /** Device store reports ≥1 active device key. */
  readonly deviceEnrolled?: boolean;
  /** Inventory reports ≥1 recovery-verified wallet. */
  readonly recoveryVerifiedEligibleCount?: number | null;
  /** ≥1 ACTIVE reporting credential. */
  readonly reportingKeyActive?: boolean | null;
  /**
   * Vault already configured/unlocked (non-virgin). When true, W5 does not
   * require the show-once generate path — only offline ack if never recorded.
   * Also a production-complete fact (server-derived).
   */
  readonly vaultConfigured?: boolean;
  /**
   * Durable PWA-install evidence observed by server (or lab bypass).
   * Never invent from w3_pwa_ack alone.
   */
  readonly pwaInstalled?: boolean;
  /**
   * Lab ALLOW_BROWSER_TAB_SETUP — SPA may show skip; complete treats PWA satisfied.
   */
  readonly allowBrowserTabSetup?: boolean;
  /**
   * Whether RECEIVE pack is in scope. When false, W9 is not required.
   * Default true (generic node ships receive-capable).
   */
  readonly receivePackEnabled?: boolean;
}

/**
 * Lab-only: restore the legacy ack-wizard complete path.
 * Default off. True when SETUP_ACK_WIZARD_LEGACY is 1/true/yes (case-insensitive).
 */
export function isSetupAckWizardLegacyEnabled(
  env: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env,
): boolean {
  const raw = env.SETUP_ACK_WIZARD_LEGACY;
  if (raw === undefined || raw === null) return false;
  const v = String(raw).trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

/** PATCH fields that faked PWA / device / ceremony / recovery success. */
export const SETUP_ACK_ONLY_PATCH_KEYS = [
  "w3_pwa_ack",
  "w3_pwa_skipped",
  "w4_device_enrolled",
  "w4_break_glass_ack",
  "w6_ceremony_placeholder_ack",
  "w7_recovery_wallet_ok",
] as const;

export type SetupAckOnlyPatchKey = (typeof SETUP_ACK_ONLY_PATCH_KEYS)[number];

export function isSetupAckOnlyPatchKey(key: string): key is SetupAckOnlyPatchKey {
  return (SETUP_ACK_ONLY_PATCH_KEYS as readonly string[]).includes(key);
}

export type SetupStepStatus = "pending" | "complete" | "skipped" | "blocked" | "placeholder";

export interface SetupStepView {
  readonly id: SetupStepId;
  readonly required: boolean;
  readonly status: SetupStepStatus;
  readonly title: string;
  readonly detail: string;
}

/**
 * Day-0 funnel step ids. Secret-free; maps 1:1 to SPA
 * `/start/*` routes (plus auth). `home` means setup complete.
 */
export const DAY0_NEXT_STEPS = [
  "password",
  "totp",
  "install",
  "device",
  "vault",
  "backup",
  "prove",
  "home",
] as const;
export type Day0NextStep = (typeof DAY0_NEXT_STEPS)[number];

export function isDay0NextStep(value: unknown): value is Day0NextStep {
  return typeof value === "string" && (DAY0_NEXT_STEPS as readonly string[]).includes(value);
}

export interface SetupStateView {
  readonly object: "setup_state";
  readonly current_step: SetupStepId;
  readonly complete: boolean;
  readonly flags: SetupStateFlags;
  readonly steps: readonly SetupStepView[];
  /** Whether ceremony master-key POST is blocked (Mode A gates). */
  readonly ceremony_master_key_blocked: true;
  /** Durable PWA evidence present (or lab ALLOW_BROWSER_TAB_SETUP). */
  readonly pwa_installed: boolean;
  /** Lab env mirror — SPA may show a Skip control only when true. */
  readonly allow_browser_tab_setup: boolean;
  /** Day-0 fact board — secret-free server-derived booleans. */
  readonly password_ok: boolean;
  readonly totp_ok: boolean;
  readonly device_enrolled: boolean;
  readonly recovery_proven: boolean;
  readonly vault_ready: boolean;
  /**
   * First incomplete day-0 funnel step, or `home` when complete.
   * SPA RequireAuth redirects money routes here via pathForNextStep.
   */
  readonly next_step: Day0NextStep;
  readonly generated_at: string;
}

const STEP_META: Record<
  SetupStepId,
  { readonly title: string; readonly required: boolean; readonly detail: string }
> = {
  W0: {
    title: "Secure context",
    required: true,
    detail: "Operator UI must run on HTTPS or loopback.",
  },
  W1: {
    title: "Change bootstrap password",
    required: true,
    detail: "Replace the first-boot password before operating the node.",
  },
  W2: {
    title: "Enrol authenticator",
    required: true,
    detail: "TOTP is the floor for money and high-authority mutations.",
  },
  W3: {
    title: "Install PWA",
    required: true,
    detail:
      "Mandatory Operator PWA install. Complete only with durable install evidence.",
  },
  W4: {
    title: "Approval device",
    required: true,
    detail:
      "Enrol this phone as Device #1 (WebCrypto + TOTP), or type exact BREAK GLASS with audit.",
  },
  W5: {
    title: "Vault ready",
    required: true,
    detail: "Virgin vault: generate master key once, store offline, then continue.",
  },
  W6: {
    title: "Recovery ceremony",
    required: true,
    detail:
      "Recovery verification via pack prove (G3) or Mode A / CLI break-glass. Placeholder ack does not complete setup.",
  },
  W7: {
    title: "Recovery-verified wallet",
    required: true,
    detail:
      "At least one node_generated wallet with recovery_verified_at. Client ack cannot stamp this.",
  },
  W8: {
    title: "Implementer key",
    required: false,
    detail: "Optional: capture the implementer API key shown once at issue.",
  },
  W9: {
    title: "Reporting key",
    required: true,
    detail: "Required when the RECEIVE pack is enabled (ARM path).",
  },
  W10: {
    title: "Packs",
    required: false,
    detail: "Optional pack selection / acknowledgement.",
  },
  W11: {
    title: "Mini-steps",
    required: false,
    detail: "Optional remaining integration mini-steps.",
  },
  W12: {
    title: "Done",
    required: true,
    detail: "Setup complete — continue to the Home checklist.",
  },
};

/** W3 done for gate sequence. Production: durable evidence / lab tab only. */
function w3Done(f: SetupStateFlags, s: SetupLiveSignals, legacy: boolean): boolean {
  if (
    isPwaInstalled(f, {
      allowBrowserTabSetup: s.allowBrowserTabSetup === true || isAllowBrowserTabSetup(),
      pwaInstalledSignal: s.pwaInstalled,
    })
  ) {
    return true;
  }
  if (legacy) return f.w3_pwa_ack || f.w3_pwa_skipped;
  return false;
}

/**
 * Exact operator-typed phrase required for device break-glass.
 * Case-sensitive — must equal this string exactly (no surrounding whitespace).
 */
export const DEVICE_BREAK_GLASS_PHRASE = "BREAK GLASS" as const;

/**
 * W4 done: ≥1 active device, or typed break-glass (production + legacy).
 * Legacy may also use quiet device/break-glass ack flags.
 */
export function w4Done(f: SetupStateFlags, s: SetupLiveSignals, legacy: boolean): boolean {
  if (s.deviceEnrolled === true) return true;
  // Typed break-glass (server-only via applyTypedDeviceBreakGlass) advances W4
  // and allows Home with a persistent banner — never a quiet checkbox alone.
  if (f.w4_break_glass_ack === true) return true;
  if (legacy && f.w4_device_enrolled) return true;
  // Durable mirror only when live probe unavailable (lab/tests without store).
  if (s.deviceEnrolled === undefined && f.w4_device_enrolled) return true;
  return false;
}

/** True when operator proceeded without an approval device (Home banner). */
export function isDeviceBreakGlassActive(f: SetupStateFlags, s: SetupLiveSignals): boolean {
  return f.w4_break_glass_ack === true && s.deviceEnrolled !== true;
}

function w5Done(f: SetupStateFlags, s: SetupLiveSignals): boolean {
  // Offline backup ack always; vault must be ready via flag or live configured signal.
  if (!f.w5_offline_backup_ack) return false;
  return f.w5_vault_ready || s.vaultConfigured === true;
}

/** W6: production waits on recovery-verified inventory (same fact as W7); legacy uses placeholder ack. */
function w6Done(f: SetupStateFlags, s: SetupLiveSignals, legacy: boolean): boolean {
  if (legacy) return f.w6_ceremony_placeholder_ack;
  return w7LiveVerified(s);
}

function w7LiveVerified(s: SetupLiveSignals): boolean {
  const n = s.recoveryVerifiedEligibleCount;
  return typeof n === "number" && n >= 1;
}

function w7Done(f: SetupStateFlags, s: SetupLiveSignals, legacy: boolean): boolean {
  if (w7LiveVerified(s)) return true;
  if (legacy && f.w7_recovery_wallet_ok) return true;
  return false;
}

function w8Done(f: SetupStateFlags): boolean {
  return f.w8_implementer_key_ack || f.w8_implementer_skipped;
}

function w9Required(s: SetupLiveSignals): boolean {
  return s.receivePackEnabled !== false;
}

function w9Done(f: SetupStateFlags, s: SetupLiveSignals): boolean {
  if (!w9Required(s)) return true;
  if (f.w9_reporting_key_ok) return true;
  return s.reportingKeyActive === true;
}

function w10Done(f: SetupStateFlags): boolean {
  return f.w10_packs_ack || f.w10_packs_skipped;
}

function w11Done(f: SetupStateFlags): boolean {
  return f.w11_mini_steps_ack || f.w11_mini_steps_skipped;
}

function stepStatus(
  id: SetupStepId,
  f: SetupStateFlags,
  s: SetupLiveSignals,
  legacy: boolean,
): SetupStepStatus {
  switch (id) {
    case "W0":
      return f.w0_secure_context_ok ? "complete" : "pending";
    case "W1":
      return s.mustChangePassword ? "pending" : "complete";
    case "W2":
      if (s.mustChangePassword) return "blocked";
      return s.mustEnrolTotp ? "pending" : "complete";
    case "W3":
      if (s.mustChangePassword || s.mustEnrolTotp || !f.w0_secure_context_ok) return "blocked";
      if (legacy && f.w3_pwa_skipped) return "skipped";
      return w3Done(f, s, legacy) ? "complete" : "pending";
    case "W4":
      if (s.mustChangePassword || s.mustEnrolTotp || !f.w0_secure_context_ok || !w3Done(f, s, legacy)) {
        return "blocked";
      }
      return w4Done(f, s, legacy) ? "complete" : "pending";
    case "W5":
      if (
        s.mustChangePassword ||
        s.mustEnrolTotp ||
        !f.w0_secure_context_ok ||
        !w3Done(f, s, legacy) ||
        !w4Done(f, s, legacy)
      ) {
        return "blocked";
      }
      return w5Done(f, s) ? "complete" : "pending";
    case "W6":
      if (!w5Done(f, s) || s.mustChangePassword || s.mustEnrolTotp) return "blocked";
      if (legacy) {
        // Placeholder ack only advances the legacy funnel — never a real recovery stamp.
        return f.w6_ceremony_placeholder_ack ? "placeholder" : "pending";
      }
      // Production: W6 tracks the same recovery-verified fact as W7 (no fake ack).
      return w6Done(f, s, legacy) ? "complete" : "pending";
    case "W7":
      if (!w6Done(f, s, legacy) || !w5Done(f, s)) return "blocked";
      return w7Done(f, s, legacy) ? "complete" : "pending";
    case "W8":
      if (!w7Done(f, s, legacy)) return "blocked";
      if (f.w8_implementer_skipped) return "skipped";
      return f.w8_implementer_key_ack ? "complete" : "pending";
    case "W9":
      if (!w8Done(f) || !w7Done(f, s, legacy)) return "blocked";
      if (!w9Required(s)) return "skipped";
      return w9Done(f, s) ? "complete" : "pending";
    case "W10":
      if (!w9Done(f, s) || !w8Done(f)) return "blocked";
      if (f.w10_packs_skipped) return "skipped";
      return f.w10_packs_ack ? "complete" : "pending";
    case "W11":
      if (!w10Done(f)) return "blocked";
      if (f.w11_mini_steps_skipped) return "skipped";
      return f.w11_mini_steps_ack ? "complete" : "pending";
    case "W12":
      if (!w11Done(f) || !w9Done(f, s) || !w7Done(f, s, legacy) || !w5Done(f, s)) return "blocked";
      return f.completed_at ? "complete" : "pending";
    default: {
      const _exhaustive: never = id;
      return _exhaustive;
    }
  }
}

/**
 * Day-0 verified facts. Secret-free; derived only.
 * `recovery_proven` === ≥1 recovery-verified node_generated wallet.
 */
export function day0Facts(
  f: SetupStateFlags,
  s: SetupLiveSignals,
  legacy: boolean = isSetupAckWizardLegacyEnabled(),
): {
  readonly password_ok: boolean;
  readonly totp_ok: boolean;
  readonly pwa_installed: boolean;
  readonly device_enrolled: boolean;
  readonly vault_ready: boolean;
  readonly recovery_proven: boolean;
} {
  const allowBrowserTab =
    s.allowBrowserTabSetup === true || isAllowBrowserTabSetup();
  return {
    password_ok: s.mustChangePassword !== true,
    totp_ok: s.mustEnrolTotp !== true,
    pwa_installed: isPwaInstalled(f, {
      allowBrowserTabSetup: allowBrowserTab,
      pwaInstalledSignal: s.pwaInstalled,
    }),
    // Live device OR typed break-glass (never quiet checkbox alone in prod).
    device_enrolled: w4Done(f, s, legacy),
    vault_ready: w5Done(f, s),
    recovery_proven: w7LiveVerified(s) || (legacy && f.w7_recovery_wallet_ok),
  };
}

/**
 * First incomplete day-0 funnel step.
 * Sequence: password → totp → install → device → vault → backup → prove → home.
 * Pack create (`backup`) and pack prove (`prove`) share the recovery-verified
 * server fact; SPA may soft-gate prove after a local create marker.
 */
export function resolveNextStep(
  f: SetupStateFlags,
  s: SetupLiveSignals,
  legacy: boolean = isSetupAckWizardLegacyEnabled(),
): Day0NextStep {
  const facts = day0Facts(f, s, legacy);
  if (!facts.password_ok) return "password";
  if (!facts.totp_ok) return "totp";
  // Secure context is a prerequisite for PWA; surface install until both hold.
  if (!f.w0_secure_context_ok || !facts.pwa_installed) return "install";
  if (!facts.device_enrolled) return "device";
  if (!facts.vault_ready) return "vault";
  if (!facts.recovery_proven) {
    // Server cannot see "pack file downloaded"; both create and prove are the
    // recovery phase until recovery_verified_at stamps. SPA maps backup→prove client-side.
    return "backup";
  }
  return "home";
}

/**
 * First incomplete required (or un-acked optional) step in gate sequence.
 * Returns W12 when every prior gate is satisfied.
 * Production: day-0 facts only — W8–W11 hollow ack steps are not
 * on the happy path.
 */
export function resolveCurrentStep(
  f: SetupStateFlags,
  s: SetupLiveSignals,
  legacy: boolean = isSetupAckWizardLegacyEnabled(),
): SetupStepId {
  if (!legacy) {
    // Map day-0 next_step onto legacy W* ids for older SPA sections.
    const next = resolveNextStep(f, s, false);
    switch (next) {
      case "password":
        return f.w0_secure_context_ok ? "W1" : "W0";
      case "totp":
        return "W2";
      case "install":
        return f.w0_secure_context_ok ? "W3" : "W0";
      case "device":
        return "W4";
      case "vault":
        return "W5";
      case "backup":
      case "prove":
        // W6/W7 both track recovery-verified in production.
        return w5Done(f, s) ? "W6" : "W5";
      case "home":
        return "W12";
      default: {
        const _exhaustive: never = next;
        return _exhaustive;
      }
    }
  }

  for (const id of SETUP_STEPS) {
    if (id === "W12") continue;
    const st = stepStatus(id, f, s, legacy);
    if (st === "pending" || st === "blocked") {
      // blocked means a prior gate failed — still surface the earliest incomplete.
      if (st === "pending") return id;
      // For blocked, keep scanning for the actual pending gate... but W1/W2 blocked
      // later steps; return the first non-complete required ancestor.
      continue;
    }
  }
  // Walk again: return first non-complete (including blocked as that step when prior pending missing)
  for (const id of SETUP_STEPS) {
    if (id === "W12") {
      return w11Done(f) && w9Done(f, s) && w7Done(f, s, legacy) && w5Done(f, s) ? "W12" : "W11";
    }
    const st = stepStatus(id, f, s, legacy);
    if (st !== "complete" && st !== "skipped" && st !== "placeholder") {
      return id;
    }
    // placeholder counts as satisfied for gate sequence (legacy W6 ack only)
    if (st === "placeholder" && id === "W6") continue;
  }
  return "W12";
}

/**
 * Production complete: server-verified facts only.
 * Password/TOTP gates unchanged. Ack booleans alone never suffice.
 * Optional W8–W11 hollow steps are NOT required for production complete.
 */
export function isSetupComplete(
  f: SetupStateFlags,
  s: SetupLiveSignals,
  legacy: boolean = isSetupAckWizardLegacyEnabled(),
): boolean {
  if (s.mustChangePassword || s.mustEnrolTotp) return false;
  if (!f.w0_secure_context_ok) return false;

  if (legacy) {
    if (!w3Done(f, s, true)) return false;
    if (!w4Done(f, s, true)) return false;
    if (!w5Done(f, s)) return false;
    if (!f.w6_ceremony_placeholder_ack) return false;
    if (!w7Done(f, s, true)) return false;
    if (!w8Done(f)) return false;
    if (!w9Done(f, s)) return false;
    if (!w10Done(f)) return false;
    if (!w11Done(f)) return false;
    return true;
  }

  // Verified facts:
  // password ok + TOTP enrolled (above), pwaInstalled, device OR typed break-glass,
  // vault configured, ≥1 node_generated recovery-verified wallet.
  // Quiet w4_* flags alone never suffice. W8–W11 are day-2 / optional.
  const facts = day0Facts(f, s, false);
  return (
    facts.pwa_installed &&
    facts.device_enrolled &&
    facts.vault_ready &&
    facts.recovery_proven
  );
}

export function buildSetupStateView(
  f: SetupStateFlags,
  s: SetupLiveSignals,
  nowIso: string = new Date().toISOString(),
  legacy: boolean = isSetupAckWizardLegacyEnabled(),
): SetupStateView {
  const allowBrowserTab =
    s.allowBrowserTabSetup === true || isAllowBrowserTabSetup();
  const signals: SetupLiveSignals = {
    ...s,
    allowBrowserTabSetup: allowBrowserTab,
    pwaInstalled:
      s.pwaInstalled === true ||
      allowBrowserTab ||
      isPwaInstalled(f, { allowBrowserTabSetup: allowBrowserTab, pwaInstalledSignal: s.pwaInstalled }),
  };
  const complete = isSetupComplete(f, signals, legacy);
  // Prefer caller clock only when durable flags lack completed_at yet.
  const flags: SetupStateFlags =
    complete && (f.completed_at === null || f.completed_at === undefined)
      ? { ...f, completed_at: nowIso }
      : f;
  const current = complete ? "W12" : resolveCurrentStep(flags, signals, legacy);
  const steps: SetupStepView[] = SETUP_STEPS.map((id) => {
    const meta = STEP_META[id];
    let status = stepStatus(id, flags, signals, legacy);
    if (id === "W12" && complete) status = "complete";
    if (id === "W6" && legacy && flags.w6_ceremony_placeholder_ack) status = "placeholder";
    return {
      id,
      required: id === "W9" ? w9Required(signals) : id === "W3" ? true : meta.required,
      status,
      title: meta.title,
      detail: meta.detail,
    };
  });

  const facts = day0Facts(flags, signals, legacy);
  const nextStep = complete ? "home" : resolveNextStep(flags, signals, legacy);

  return {
    object: "setup_state",
    current_step: current,
    complete,
    flags,
    steps,
    ceremony_master_key_blocked: true,
    pwa_installed: facts.pwa_installed,
    allow_browser_tab_setup: allowBrowserTab,
    password_ok: facts.password_ok,
    totp_ok: facts.totp_ok,
    device_enrolled: facts.device_enrolled,
    recovery_proven: facts.recovery_proven,
    vault_ready: facts.vault_ready,
    next_step: nextStep,
    generated_at: nowIso,
  };
}

/** PATCH body keys the client may set (secret-free only). */
export type SetupStatePatch = Partial<{
  w0_secure_context_ok: boolean;
  w3_pwa_ack: boolean;
  w3_pwa_skipped: boolean;
  w4_device_enrolled: boolean;
  w4_break_glass_ack: boolean;
  w5_vault_ready: boolean;
  w5_offline_backup_ack: boolean;
  w6_ceremony_placeholder_ack: boolean;
  w7_recovery_wallet_ok: boolean;
  w8_implementer_key_ack: boolean;
  w8_implementer_skipped: boolean;
  w9_reporting_key_ok: boolean;
  w10_packs_ack: boolean;
  w10_packs_skipped: boolean;
  w11_mini_steps_ack: boolean;
  w11_mini_steps_skipped: boolean;
}>;

const PATCH_KEYS: readonly (keyof SetupStatePatch)[] = [
  "w0_secure_context_ok",
  "w3_pwa_ack",
  "w3_pwa_skipped",
  "w4_device_enrolled",
  "w4_break_glass_ack",
  "w5_vault_ready",
  "w5_offline_backup_ack",
  "w6_ceremony_placeholder_ack",
  "w7_recovery_wallet_ok",
  "w8_implementer_key_ack",
  "w8_implementer_skipped",
  "w9_reporting_key_ok",
  "w10_packs_ack",
  "w10_packs_skipped",
  "w11_mini_steps_ack",
  "w11_mini_steps_skipped",
] as const;

export class SetupPatchError extends Error {
  readonly code: "validation_error" | "conflict" | "ceremony_blocked";
  constructor(code: SetupPatchError["code"], message: string) {
    super(message);
    this.name = "SetupPatchError";
    this.code = code;
  }
}

/**
 * Record durable PWA install evidence. Idempotent: keeps the first timestamp;
 * upgrades evidence string if a later call supplies a different valid kind.
 * Rejects non-enum bodies (including `{ ack: true }`).
 */
export function applyPwaInstalledEvidence(
  current: SetupStateFlags,
  body: Record<string, unknown>,
  nowIso: string = new Date().toISOString(),
): SetupStateFlags {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new SetupPatchError("validation_error", "pwa-installed body must be an object");
  }
  // Explicitly reject hollow ack shapes.
  if (body.ack === true || body.w3_pwa_ack === true || body.skipped === true) {
    throw new SetupPatchError(
      "validation_error",
      "pwa-installed requires evidence enum, not ack",
    );
  }
  if (!isPwaInstallEvidence(body.evidence)) {
    throw new SetupPatchError(
      "validation_error",
      "evidence must be one of: standalone, fullscreen, appinstalled",
    );
  }
  const evidence = body.evidence;
  if (current.pwa_installed_at) {
    return {
      ...current,
      pwa_install_evidence: current.pwa_install_evidence ?? evidence,
      // Keep first install time; refresh evidence label if previously null.
      w3_pwa_ack: true,
    };
  }
  return {
    ...current,
    pwa_installed_at: nowIso,
    pwa_install_evidence: evidence,
    w3_pwa_ack: true,
    w3_pwa_skipped: false,
  };
}



/**
 * Server-only: mark typed break-glass after phrase + audit.
 * Does not accept client PATCH of w4_break_glass_ack.
 */
export function applyTypedDeviceBreakGlass(
  current: SetupStateFlags,
  signals: SetupLiveSignals,
  phrase: string,
  nowIso: string = new Date().toISOString(),
  legacy: boolean = isSetupAckWizardLegacyEnabled(),
): SetupStateFlags {
  if (phrase !== DEVICE_BREAK_GLASS_PHRASE) {
    throw new SetupPatchError(
      "validation_error",
      `break-glass phrase must be exactly ${DEVICE_BREAK_GLASS_PHRASE}`,
    );
  }
  if (signals.mustChangePassword || signals.mustEnrolTotp) {
    throw new SetupPatchError("conflict", "break-glass requires password+TOTP complete");
  }
  if (!current.w0_secure_context_ok) {
    throw new SetupPatchError("conflict", "break-glass requires secure context (W0)");
  }
  if (!w3Done(current, signals, legacy)) {
    throw new SetupPatchError("conflict", "break-glass requires PWA step (W3) complete or skipped");
  }
  if (signals.deviceEnrolled === true) {
    throw new SetupPatchError(
      "conflict",
      "active approval device already enrolled — break-glass not needed",
    );
  }
  const next: SetupStateFlags = {
    ...current,
    w4_break_glass_ack: true,
  };
  if (isSetupComplete(next, signals, legacy) && !next.completed_at) {
    return { ...next, completed_at: nowIso };
  }
  return next;
}

/** Server-only: mirror live device inventory into durable w4_device_enrolled. */
export function mirrorDeviceEnrolledFlag(
  current: SetupStateFlags,
  deviceEnrolled: boolean,
): SetupStateFlags {
  if (!deviceEnrolled) return current;
  if (current.w4_device_enrolled) return current;
  return { ...current, w4_device_enrolled: true };
}

/**
 * Apply a secret-free patch under gate sequence.
 * - Cannot skip required steps.
 * - Optional skip requires the matching *_skipped flag true.
 * - Rejects unknown keys and any secret-shaped field names.
 * - W6 never accepts master_key (ceremony_blocked).
 * - Ack-only fields (PWA/device/ceremony/recovery fake success) are
 *   ignored unless SETUP_ACK_WIZARD_LEGACY is on. They never alone make complete.
 */
export function applySetupPatch(
  current: SetupStateFlags,
  signals: SetupLiveSignals,
  patch: Record<string, unknown>,
  nowIso: string = new Date().toISOString(),
  legacy: boolean = isSetupAckWizardLegacyEnabled(),
): SetupStateFlags {
  // Reject secret-shaped keys on sight.
  for (const key of Object.keys(patch)) {
    const lower = key.toLowerCase();
    if (
      lower.includes("master") ||
      lower.includes("password") ||
      lower.includes("secret") ||
      lower.includes("private") ||
      lower.includes("kek") ||
      lower === "totp" ||
      lower.includes("token")
    ) {
      throw new SetupPatchError(
        "ceremony_blocked",
        "setup_state rejects secret-bearing fields (including master key)",
      );
    }
    if (!(PATCH_KEYS as readonly string[]).includes(key)) {
      throw new SetupPatchError("validation_error", `unknown setup_state field: ${key}`);
    }
    if (typeof patch[key] !== "boolean") {
      throw new SetupPatchError("validation_error", `setup_state field ${key} must be boolean`);
    }
  }

  // Production: refuse quiet w4_* client acks — enrol or typed BREAK GLASS.
  if (!legacy) {
    if (patch.w4_device_enrolled === true) {
      throw new SetupPatchError(
        "conflict",
        "w4_device_enrolled is server-derived from active device inventory — enrol a device (WebCrypto + TOTP)",
      );
    }
    if (patch.w4_break_glass_ack === true) {
      throw new SetupPatchError(
        "conflict",
        "break-glass requires typing exact BREAK GLASS on the device setup endpoint (not a checkbox)",
      );
    }
  }

  // Production: strip remaining ack-only fakes so PATCH is a no-op for those keys.
  const effective: Record<string, unknown> = { ...patch };
  if (!legacy) {
    for (const k of SETUP_ACK_ONLY_PATCH_KEYS) {
      delete effective[k];
    }
  }

  const next: SetupStateFlags = { ...current };
  const set = <K extends keyof SetupStateFlags>(k: K, v: SetupStateFlags[K]) => {
    (next as { -readonly [P in keyof SetupStateFlags]: SetupStateFlags[P] })[k] = v;
  };

  // Only allow advancing the current (or already-passed) step's flags.
  const cursor = resolveCurrentStep(current, signals, legacy);

  const allowThrough = (step: SetupStepId): boolean => {
    const stepIdx = SETUP_STEPS.indexOf(step);
    const cur = SETUP_STEPS.indexOf(cursor);
    return stepIdx <= cur;
  };

  if (effective.w0_secure_context_ok === true) {
    if (!allowThrough("W0")) {
      throw new SetupPatchError("conflict", "W0 cannot be set before reaching it");
    }
    set("w0_secure_context_ok", true);
  }

  if (legacy && (effective.w3_pwa_ack === true || effective.w3_pwa_skipped === true)) {
    if (!allowThrough("W3")) {
      throw new SetupPatchError("conflict", "W3 requires W0–W2 complete");
    }
    if (signals.mustChangePassword || signals.mustEnrolTotp || !next.w0_secure_context_ok) {
      throw new SetupPatchError("conflict", "W3 requires password+TOTP and secure context");
    }
    if (effective.w3_pwa_skipped === true) set("w3_pwa_skipped", true);
    if (effective.w3_pwa_ack === true) set("w3_pwa_ack", true);
  }

  if (legacy && (effective.w4_device_enrolled === true || effective.w4_break_glass_ack === true)) {
    if (!allowThrough("W4") && !w3Done(next, signals, legacy)) {
      throw new SetupPatchError("conflict", "W4 requires prior steps");
    }
    if (!w3Done(next, signals, legacy) || signals.mustChangePassword || signals.mustEnrolTotp) {
      throw new SetupPatchError("conflict", "W4 requires W0–W3");
    }
    if (effective.w4_device_enrolled === true) set("w4_device_enrolled", true);
    if (effective.w4_break_glass_ack === true) set("w4_break_glass_ack", true);
  }

  if (effective.w5_vault_ready === true || effective.w5_offline_backup_ack === true) {
    // W5 may be patched when vault path is live even if W3/W4 still pending
    // (operator can seal vault before PWA/device evidence exists). Gate only on
    // auth+secure context so offline ack is not blocked by incomplete verified facts.
    if (signals.mustChangePassword || signals.mustEnrolTotp || !next.w0_secure_context_ok) {
      throw new SetupPatchError("conflict", "W5 requires password+TOTP and secure context");
    }
    if (effective.w5_offline_backup_ack === true) set("w5_offline_backup_ack", true);
    if (effective.w5_vault_ready === true) {
      // Vault ready alone is insufficient without offline ack — allow setting the flag,
      // completion still needs both (w5Done).
      set("w5_vault_ready", true);
    }
  }

  if (legacy && effective.w6_ceremony_placeholder_ack === true) {
    if (!w5Done(next, signals)) {
      throw new SetupPatchError("conflict", "W6 requires vault ready + offline backup ack");
    }
    set("w6_ceremony_placeholder_ack", true);
  }

  if (legacy && effective.w7_recovery_wallet_ok === true) {
    if (!next.w6_ceremony_placeholder_ack) {
      throw new SetupPatchError("conflict", "W7 requires ceremony placeholder ack");
    }
    set("w7_recovery_wallet_ok", true);
  }

  if (effective.w8_implementer_key_ack === true || effective.w8_implementer_skipped === true) {
    if (!w7Done(next, signals, legacy)) {
      throw new SetupPatchError("conflict", "W8 requires W7 recovery-verified wallet");
    }
    if (effective.w8_implementer_skipped === true) set("w8_implementer_skipped", true);
    if (effective.w8_implementer_key_ack === true) set("w8_implementer_key_ack", true);
  }

  if (effective.w9_reporting_key_ok === true) {
    if (!w8Done(next)) {
      throw new SetupPatchError("conflict", "W9 requires W8");
    }
    set("w9_reporting_key_ok", true);
  }

  if (effective.w10_packs_ack === true || effective.w10_packs_skipped === true) {
    if (!w9Done(next, signals)) {
      throw new SetupPatchError("conflict", "W10 requires W9");
    }
    if (effective.w10_packs_skipped === true) set("w10_packs_skipped", true);
    if (effective.w10_packs_ack === true) set("w10_packs_ack", true);
  }

  if (effective.w11_mini_steps_ack === true || effective.w11_mini_steps_skipped === true) {
    if (!w10Done(next)) {
      throw new SetupPatchError("conflict", "W11 requires W10");
    }
    if (effective.w11_mini_steps_skipped === true) set("w11_mini_steps_skipped", true);
    if (effective.w11_mini_steps_ack === true) set("w11_mini_steps_ack", true);
  }

  if (isSetupComplete(next, signals, legacy) && !next.completed_at) {
    set("completed_at", nowIso);
  }

  return next;
}

/**
 * Forbidden key fragments for leak tests. Boolean *policy* flags that mention
 * master/kek in the name (e.g. ceremony_master_key_blocked) are allowlisted —
 * they never carry secret material.
 */
export const SETUP_FORBIDDEN_KEY_FRAGMENTS: readonly string[] = [
  "password",
  "secret",
  "token",
  "private",
  "raw_key",
  "totp_secret",
  "csrf",
  "cookie",
  "seed",
];

/** Exact keys that may mention master/kek/password without holding secrets. */
const SETUP_SAFE_KEY_NAMES = new Set([
  "ceremony_master_key_blocked",
  "vault_master_distinct_from_backup_kek",
  "key_fingerprint_prefix",
  "plaintext_pending_ack",
  "offline_backup_acked",
  "can_generate",
  // Day-0 fact board — boolean posture only, never secret material.
  "password_ok",
  "totp_ok",
  "device_enrolled",
  "recovery_proven",
  "vault_ready",
  "next_step",
  "pwa_installed",
  "allow_browser_tab_setup",
]);

export function collectSetupSecretLeaks(value: unknown, path = "$"): string[] {
  const hits: string[] = [];
  if (value === null || value === undefined) return hits;
  if (typeof value === "string") {
    if (/(?:^|[^a-z])ik_[a-z0-9_-]{8,}/i.test(value)) hits.push(`${path}=ik_prefix`);
    if (/(?:^|[^a-z])sh_[a-z0-9_-]{8,}/i.test(value)) hits.push(`${path}=sh_prefix`);
    // Long high-entropy strings that look like raw keys (not fingerprints/ISO dates).
    if (value.length >= 32 && /^[A-Za-z0-9+/=_-]{32,}$/.test(value) && !/^[0-9a-f]{12,64}$/i.test(value)) {
      // Allow ISO timestamps and short digests already covered.
      if (!/^\d{4}-\d{2}-\d{2}T/.test(value)) {
        hits.push(`${path}=long_secret_shaped_string`);
      }
    }
    return hits;
  }
  if (typeof value !== "object") return hits;
  if (Array.isArray(value)) {
    value.forEach((item, i) => hits.push(...collectSetupSecretLeaks(item, `${path}[${i}]`)));
    return hits;
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const keyLower = key.toLowerCase();
    if (!SETUP_SAFE_KEY_NAMES.has(keyLower)) {
      for (const frag of SETUP_FORBIDDEN_KEY_FRAGMENTS) {
        if (keyLower.includes(frag)) {
          hits.push(`${path}.${key}`);
          break;
        }
      }
      // Bare master_key / masterkey field names are always forbidden.
      if (keyLower === "master_key" || keyLower === "masterkey" || keyLower === "backup_master_key") {
        hits.push(`${path}.${key}`);
      }
    }
    hits.push(...collectSetupSecretLeaks(child, `${path}.${key}`));
  }
  return hits;
}

export function assertSetupSecretFree(body: unknown): void {
  const leaks = collectSetupSecretLeaks(body);
  if (leaks.length > 0) {
    throw new Error(`setup_state leaked secret-shaped fields: ${leaks.join(", ")}`);
  }
}
