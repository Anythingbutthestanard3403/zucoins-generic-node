import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DestinationsPage } from "./DestinationsPage.js";
import { TotpPromptProvider } from "../../totp/TotpPromptProvider.js";
import { useAuth } from "../../store/auth.js";
import { saveEnabledPacks } from "../../lib/packs.js";

function liveSession() {
  useAuth.setState({
    user: { userId: "u1", role: "admin", mustEnrolTotp: false, mustChangePassword: false, csrfToken: "csrf" },
  });
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TotpPromptProvider>
        <MemoryRouter>
          <DestinationsPage />
        </MemoryRouter>
      </TotpPromptProvider>
    </QueryClientProvider>,
  );
}

describe("DestinationsPage honesty", () => {
  beforeEach(() => {
    liveSession();
    localStorage.clear();
  });
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("never paints a pending fetch as unavailable or empty", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    renderPage();
    expect(screen.getAllByText("Loading…").length).toBeGreaterThan(0);
    expect(screen.queryByText("List unavailable")).not.toBeInTheDocument();
    expect(screen.queryByText("Destinations unavailable")).not.toBeInTheDocument();
    expect(screen.queryByText("No destinations yet")).not.toBeInTheDocument();
  });

  it("does not claim 'No destinations' when a 503 makes inventory unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: { code: "service_unavailable", message: "down" } }), { status: 503 })),
    );
    renderPage();
    await waitFor(() => expect(screen.getByText("Destinations unavailable")).toBeInTheDocument());
    expect(screen.queryByText("No destinations yet")).not.toBeInTheDocument();
  });

  it("shows 'No destinations yet' only after a live 200 with an empty page", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }), { status: 200 })),
    );
    renderPage();
    await waitFor(() => expect(screen.getByText("No destinations yet")).toBeInTheDocument());
  });

  it("renders a live destination row from a real 200", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({
        object: "list",
        data: [{
          destination_id: "d1",
          wallet_id: "w1",
          wallet_public_key: "zkz1qdestlive0000000000",
          state: "BLESSED",
          label: "Exchange hot wallet",
          blessed_at: "2026-07-30T00:00:00.000Z",
          retired_at: null,
        }],
        has_more: false,
        next_cursor: null,
      }), { status: 200 })),
    );
    renderPage();
    expect(await screen.findByText("Exchange hot wallet")).toBeInTheDocument();
    expect(screen.queryByText("No destinations yet")).not.toBeInTheDocument();
  });
});

describe("DestinationsPage device-key blessing + bless-form label association", () => {
  beforeEach(() => liveSession());
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("offers active device-key metadata from the live endpoint", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input).endsWith("/device-keys")
          ? new Response(
              JSON.stringify({
                keys: [
                  {
                    id: "device-1",
                    label: "Operator phone",
                    enrolled_at: "2026-07-01T00:00:00.000Z",
                  },
                ],
              }),
              { status: 200 },
            )
          : new Response(
              JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }),
              { status: 200 },
            ),
      ),
    );
    renderPage();
    fireEvent.click(screen.getByRole("button", { name: "Bless destination" }));

    const select = await screen.findByRole("combobox", { name: "Device key" });
    expect((select as HTMLSelectElement).value).toBe("device-1");
    expect(screen.queryByRole("option", { name: /Operator phone/ })).not.toBeNull();
  });

  it("disables TOTP continuation when the live node has no enrolled device keys", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input).endsWith("/device-keys")
          ? new Response(JSON.stringify({ keys: [] }), { status: 200 })
          : new Response(
              JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }),
              { status: 200 },
            ),
      ),
    );
    renderPage();
    fireEvent.click(screen.getByRole("button", { name: "Bless destination" }));

    expect(await screen.findByText(/No enrolled device keys/i)).not.toBeNull();
    expect(
      (screen.getByRole("button", { name: "Sign & continue with TOTP" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("one-tap bless signs via WebCrypto and posts device_key_id after TOTP", async () => {
    const crypto = await import("../../lib/device-crypto.js");
    vi.spyOn(crypto, "getDeviceRecord").mockResolvedValue({
      id: "device-1",
      label: "Operator phone",
      publicKey: "pub",
      createdAt: "2026-07-01T00:00:00.000Z",
      nodeId: "11111111-1111-4111-8111-111111111111",
      privateKey: {} as CryptoKey,
    });
    vi.spyOn(crypto, "signPreimage").mockResolvedValue("signed-by-webcrypto==");
    vi.spyOn(crypto, "randomUuid").mockReturnValue("99999999-9999-4999-8999-999999999999");
    vi.spyOn(crypto, "ceremonyWindowFromNow").mockReturnValue({
      issued_at: "2026-07-31T00:00:00.000Z",
      expires_at: "2026-07-31T00:05:00.000Z",
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/device-keys")) {
        return new Response(
          JSON.stringify({
            keys: [
              {
                id: "device-1",
                label: "Operator phone",
                enrolled_at: "2026-07-01T00:00:00.000Z",
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (path.includes("/destinations") && !path.includes("/bless")) {
        return new Response(
          JSON.stringify({
            object: "list",
            data: [
              {
                destination_id: "destination-1",
                node_id: "11111111-1111-4111-8111-111111111111",
                wallet_id: "44444444-4444-4444-8444-444444444444",
                wallet_public_key: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
                state: "PENDING",
                label: "sink",
                blessed_at: null,
                retired_at: null,
              },
            ],
            has_more: false,
            next_cursor: null,
          }),
          { status: 200 },
        );
      }
      if (path.includes("/destinations/destination-1/bless")) {
        return new Response(JSON.stringify({ state: "BLESSED" }), { status: 200 });
      }
      return new Response(
        JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }),
        { status: 200 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await screen.findByText("sink");
    fireEvent.click(screen.getByRole("button", { name: "Bless…" }));
    await screen.findByRole("combobox", { name: "Device key" });
    expect(screen.getByTestId("bless-tuple-review")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Sign & continue with TOTP" }));

    const dialog = await screen.findByRole("dialog");
    const digits = within(dialog).getAllByRole("textbox");
    "123456".split("").forEach((value, index) =>
      fireEvent.change(digits[index]!, { target: { value } }),
    );

    await waitFor(() => {
      const blessCall = fetchMock.mock.calls.find(([input]) =>
        String(input).includes("/destinations/destination-1/bless"),
      );
      expect(blessCall).toBeDefined();
      const body = String((blessCall?.[1] as RequestInit | undefined)?.body);
      expect(JSON.parse(body)).toMatchObject({
        device_key_id: "device-1",
        device_signature: "signed-by-webcrypto==",
        nonce: "99999999-9999-4999-8999-999999999999",
      });
    });
  });

  it("happy-path form has destination id or tuple review; advanced paste is break-glass only", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }),
          { status: 200 },
        ),
      ),
    );
    renderPage();
    fireEvent.click(screen.getByRole("button", { name: "Bless destination" }));
    expect(screen.getByLabelText("Destination id").tagName).toBe("INPUT");
    expect(screen.getByText(/Break-glass: paste signature manually/i)).toBeInTheDocument();
    expect(screen.queryByLabelText("Device signature")).toBeNull();
  });

  it("shows Pack T bless guidance when T enabled", async () => {
    saveEnabledPacks(["T"]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({ object: "list", data: [], has_more: false, next_cursor: null }),
          { status: 200 },
        ),
      ),
    );
    renderPage();
    const banner = await screen.findByTestId("pack-t-bless-guidance");
    expect(banner).toHaveTextContent(/Bless/i);
    expect(banner).toHaveTextContent(/No CLI required/i);
    expect(banner.textContent).not.toMatch(/\bSweeps\b/);
  });

});
