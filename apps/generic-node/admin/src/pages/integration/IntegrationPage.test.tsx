/** @vitest-environment jsdom */
// issue-time Connect kit, copy/download UX, section locks, and secret confinement.

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  IntegrationPage,
  buildIntegrationKit,
  safeNodeBaseUrl,
} from "./IntegrationPage.js";
import {
  consumeIssuedIntegrationKey,
  stageIssuedIntegrationKey,
} from "../../lib/integration-handoff.js";
import {
  ENABLED_PACKS_STORAGE_KEY,
  THREE_OPS_COMPOSITION_COPY,
  loadEnabledPacks,
  saveEnabledPacks,
} from "../../lib/packs.js";
import { FORBIDDEN_NAV_LABELS, PRODUCTION_NAV_LABELS } from "../../nav.js";

const RAW_KEY = "ik_issue_time_secret_only";

/** Sections the Connect kit must teach. */
const REQUIRED_KIT_MARKERS = [
  "POST /v1/receives",
  "AWAITING_ARM",
  "POST /v1/operations/",
  "/armed",
  "transfer_code",
  "X-ZP-Reporting-",
  "buildSignedReportingHeaders",
  "/.well-known/zupay-node",
  "DISCOVERY PIN",
  "WAKE ≠ PROOF",
  "wake-up signal",
  "@zucoins/generic-node-consumer",
  "@zucoins/consumer-example",
  "verification-complete",
  "wallet_evidence",
  "NEVER ship IMPLEMENTER_API_KEY to browser code",
  "reporting private seed",
] as const;

function renderPage(state?: { issuedKey: string }) {
  if (state) stageIssuedIntegrationKey(state.issuedKey);
  return render(
    <MemoryRouter initialEntries={["/integration"]}>
      <Routes>
        <Route path="/integration" element={<IntegrationPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("IntegrationPage / Connect kit", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  afterEach(() => {
    cleanup();
    consumeIssuedIntegrationKey();
    vi.unstubAllGlobals();
  });

  it("accepts only an HTTP(S) origin for generated snippets", () => {
    expect(safeNodeBaseUrl("https://node.example/admin/integration?x=1")).toBe(
      "https://node.example",
    );
    expect(safeNodeBaseUrl("http://localhost:3000/integration")).toBe(
      "http://localhost:3000",
    );
    expect(() => safeNodeBaseUrl("javascript:alert(1)")).toThrow(/HTTP/i);
    expect(() => safeNodeBaseUrl("not a url")).toThrow(/valid node URL/i);
  });

  it("locks every required full-RECEIVE kit section", () => {
    const kit = buildIntegrationKit("https://node.example", RAW_KEY);
    for (const marker of REQUIRED_KIT_MARKERS) {
      expect(kit, `missing kit section marker: ${marker}`).toContain(marker);
    }
    // Full path sequence cues (not a demo false-success path).
    expect(kit).toContain("FULL RECEIVE PATH (8 steps)");
    expect(kit).toContain("waitUntilArmable");
    expect(kit).toContain("armReceive");
    expect(kit).toContain("presentPayInstruction");
    expect(kit).toContain("INDETERMINATE");
    expect(kit).toContain("pool stays exhausted");
    expect(kit).toMatch(/ZKZ/);
    // Retired three-letter product currency label must not appear as currency.
    expect(kit).toMatch(/ZKZ only — never the retired three-letter product label/);
    expect(kit).not.toMatch(/\bZUC\b/); // contract-allow:ZUC:negative-currency-citation
  });

  it("keeps the sh_ handle on the implementer server and proxies the frozen node SSE route", () => {
    const kit = buildIntegrationKit("https://node.example", RAW_KEY);
    const receive = kit.split("IMPLEMENTER SERVER FILE — status-proxy.mjs")[0] ?? "";
    const proxySection = kit.split("IMPLEMENTER SERVER FILE — status-proxy.mjs")[1] ?? "";
    const statusProxy = proxySection.split("CUSTOMER BROWSER FILE — customer-status.js")[0] ?? "";

    expect(receive).toContain('const NODE_BASE_URL = "https://node.example"');
    expect(receive).toContain(`const IMPLEMENTER_API_KEY = ${JSON.stringify(RAW_KEY)}`);
    expect(receive).toContain("POST /v1/receives");
    expect(receive).toContain("Idempotency-Key");
    expect(receive).toContain("saveSubscriptionHandle");
    expect(receive).toContain("created.subscription_handle");
    expect(statusProxy).toContain('const NODE_BASE_URL = "https://node.example"');
    expect(statusProxy).toContain("loadSubscriptionHandle(operationId)");
    expect(statusProxy).toContain('response.once("close", () => abort.abort())');
    expect(statusProxy).not.toContain('request.once("close"');
    expect(statusProxy).toContain("/v1/operations/${operationId}/subscribe");
    expect(statusProxy).toContain('Accept: "text/event-stream"');
    expect(statusProxy).toContain("Bearer ${subscriptionHandle}");
    expect(statusProxy).not.toContain("IMPLEMENTER_API_KEY");
    expect(kit).not.toContain("/subscription-handles");
    expect(kit).toContain("NEVER ship IMPLEMENTER_API_KEY to browser code");
  });

  it("generates browser code that opens only the implementer same-origin SSE endpoint", () => {
    const kit = buildIntegrationKit("https://node.example", RAW_KEY);
    const browserSection = kit.split("CUSTOMER BROWSER FILE — customer-status.js")[1] ?? "";
    const browser = browserSection.split("DISCOVERY PIN CHECKLIST")[0] ?? "";

    expect(browser).toContain("new EventSource(");
    expect(browser).toContain("/api/receive-status/${encodeURIComponent(operationId)}");
    expect(browser).toContain("EventSource reconnects automatically");
    expect(browser).toContain("fresh upstream stream replays current state");
    expect(browser).not.toContain("https://node.example");
    expect(browser).not.toContain("fetch(");
    expect(browser).not.toContain("headers:");
    expect(browser).not.toContain("Bearer");
    expect(browser).not.toContain("subscriptionHandle");
    expect(browser).toContain("wake only");
  });

  it("never serializes reporting private seeds or env secrets into the kit", () => {
    // Negative secret serialization: even if process.env were polluted in a bundler
    // context, buildIntegrationKit only accepts (baseUrl, ik_) and must not read env.
    const polluted = {
      REPORTING_PRIVATE_KEY: "rp_should_never_appear_in_kit_aaaaaaaa",
      REPORTING_SEED: "51".repeat(32),
      ZP_REPORTING_KEY: "leak-me-reporting",
      IMPLEMENTER_EXTRA: "ik_other_key_must_not_auto_include",
    };
    const prev: Record<string, string | undefined> = {};
    for (const [k, v] of Object.entries(polluted)) {
      prev[k] = process.env[k];
      process.env[k] = v;
    }
    try {
      const kit = buildIntegrationKit("https://node.example", RAW_KEY);
      for (const secret of Object.values(polluted)) {
        expect(kit).not.toContain(secret);
      }
      // Only the explicitly passed implementer key may appear — and only once as the const.
      expect(kit).toContain(RAW_KEY);
      expect(kit).not.toContain("rp_");
      expect(kit).not.toMatch(/raw_private_key/i);
      // Generator signature cannot accept a reporting seed argument.
      expect(buildIntegrationKit).toHaveLength(2);
    } finally {
      for (const [k, v] of Object.entries(prev)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  it("rejects non-ik implementer material so secrets cannot be laundered through the kit", () => {
    expect(() => buildIntegrationKit("https://node.example", "not_a_key")).toThrow(/not valid/i);
    expect(() => buildIntegrationKit("https://node.example", "rk_reporting_seed")).toThrow(
      /not valid/i,
    );
    expect(() => buildIntegrationKit("https://node.example", "sh_subscription")).toThrow(
      /not valid/i,
    );
  });

  it("shows a one-time bundle without router or Web Storage persistence", async () => {
    renderPage({ issuedKey: RAW_KEY });

    expect(screen.getByRole("heading", { name: "Connect" })).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /give this to your web developer/i }),
    ).toBeInTheDocument();
    expect(screen.getByTestId("wake-not-proof")).toHaveTextContent(/wake ≠ proof/i);
    expect(screen.getByTestId("integration-kit")).toHaveTextContent(RAW_KEY);
    expect(screen.getByTestId("integration-kit")).toHaveTextContent("verification-complete");
    expect(localStorage.getItem("integration-api-key")).toBeNull();
    expect(sessionStorage.getItem("integration-api-key")).toBeNull();

    expect(window.history.state?.usr ?? null).toBeNull();
    expect(consumeIssuedIntegrationKey()).toBeNull();
  });

  it("copies and downloads the exact generated bundle", async () => {
    const createObjectURL = vi.fn(() => "blob:integration-kit");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    renderPage({ issuedKey: RAW_KEY });
    const expected = buildIntegrationKit(window.location.origin, RAW_KEY);

    fireEvent.click(screen.getByRole("button", { name: "Copy bundle" }));
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expected));
    // The status text is set from the clipboard promise's callback, which resolves a
    // microtask after writeText is observed — assert on the rendered text, not on the call.
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Bundle copied"));

    fireEvent.click(screen.getByRole("button", { name: "Download bundle" }));
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(click).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:integration-kit");
  });

  it("empty state is a credential funnel to Keys + Reporting, not only a red banner", () => {
    saveEnabledPacks(["M"]);
    renderPage();
    const funnel = screen.getByTestId("connect-empty-funnel");
    expect(funnel).toHaveTextContent(/only available immediately after issuing/i);
    expect(screen.queryByTestId("integration-kit")).not.toBeInTheDocument();

    const implementerLink = screen.getByRole("link", { name: /issue an implementer key/i });
    expect(implementerLink).toHaveAttribute("href", "/api-keys");

    const reportingLink = screen.getByRole("link", { name: /issue an active reporting key/i });
    expect(reportingLink).toHaveAttribute("href", "/reporting-keys");

    expect(funnel).toHaveTextContent(/Build Connect kit/i);
    expect(screen.getByTestId("wake-not-proof")).toBeInTheDocument();
  });

  it("renders M/T/P/X pack cards and three-ops composition copy", () => {
    renderPage();
    expect(screen.getByTestId("connect-packs")).toBeInTheDocument();
    expect(screen.getByTestId("three-ops-composition")).toHaveTextContent(
      THREE_OPS_COMPOSITION_COPY.slice(0, 40),
    );
    for (const id of ["M", "T", "P", "X"] as const) {
      expect(screen.getByTestId(`pack-card-${id}`)).toBeInTheDocument();
    }
    expect(screen.getByTestId("pack-x-always-on")).toBeInTheDocument();
    // Default none → X semantics
    expect(screen.getByTestId("packs-x-default")).toBeInTheDocument();
    expect(screen.getByTestId("kit-slot-headless_openapi")).toBeInTheDocument();
  });

  it("toggling packs persists enabled_packs and reveals kit slots without forbidden nav", () => {
    renderPage();
    fireEvent.click(screen.getByTestId("pack-toggle-M"));
    fireEvent.click(screen.getByTestId("pack-toggle-T"));
    fireEvent.click(screen.getByTestId("pack-toggle-P"));
    expect(loadEnabledPacks()).toEqual(["M", "T", "P"]);
    expect(screen.getByTestId("kit-slot-receive_connect")).toBeInTheDocument();
    expect(screen.getByTestId("kit-slot-treasury_move_guide")).toBeInTheDocument();
    expect(screen.getByTestId("kit-slot-payout_dual_control_guide")).toBeInTheDocument();
    // Composition copy may name refused chrome; nav census + links must stay clean.
    for (const forbidden of FORBIDDEN_NAV_LABELS) {
      expect(PRODUCTION_NAV_LABELS).not.toContain(forbidden);
    }
    expect(PRODUCTION_NAV_LABELS).not.toContain("Ord" + "ers"); // contract-allow:order:negative-nav-citation
    expect(screen.queryByRole("link", { name: "Sessions" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Swe" + "eps" })).not.toBeInTheDocument(); // contract-allow:sweep:negative-nav-citation
    expect(screen.queryByRole("link", { name: "Webhooks" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Ord" + "ers" })).not.toBeInTheDocument(); // contract-allow:order:negative-nav-citation
    expect(JSON.parse(localStorage.getItem(ENABLED_PACKS_STORAGE_KEY) ?? "[]")).toEqual([
      "M",
      "T",
      "P",
    ]);
  });

  it("Pack M kit retains independent verify + verification-complete; X-only hides receive kit UI", () => {
    renderPage();
    expect(screen.queryByTestId("connect-empty-funnel")).not.toBeInTheDocument();
    expect(screen.getByTestId("pack-m-kit-gated")).toBeInTheDocument();

    cleanup();
    consumeIssuedIntegrationKey();
    saveEnabledPacks(["M"]);
    renderPage({ issuedKey: RAW_KEY });
    const kitEl = screen.getByTestId("integration-kit");
    expect(kitEl).toHaveTextContent("verification-complete");
    expect(kitEl).toHaveTextContent("@zucoins/generic-node-consumer");
    expect(screen.getByText(/any receiver accepting/i)).toBeInTheDocument();
  });
});
