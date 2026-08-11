// merger clearance — real Chromium keyboard/mobile verification.
// The built Vite output is exercised at the WCAG 1.4.10 reference width (320 CSS px).
// This is a real layout/paint/input engine with an emulated viewport, not a physical device.
import { expect, test, type Locator, type Page } from "@playwright/test";
import {
  E2E_DESTINATION_ADDRESS,
  E2E_OPERATION_ID,
  E2E_WALLET_PUBKEY,
  registerAdminApiRoutes,
  type AdminFixtureGuard,
} from "./adminApiFixtures.js";

const fixtureGuards = new WeakMap<Page, AdminFixtureGuard>();

async function isFocused(locator: Locator): Promise<boolean> {
  return locator.evaluate((el) => document.activeElement === el);
}

async function startRoute(
  page: Page,
  path: string,
  session: "authenticated" | "anonymous" | "setup" = "authenticated",
): Promise<void> {
  const guard = await registerAdminApiRoutes(page, { session });
  fixtureGuards.set(page, guard);
  await page.goto(path);
}

async function authenticated(page: Page, path = "/"): Promise<void> {
  await startRoute(page, path);
  await page.waitForSelector('aside[aria-label="Primary"]', { timeout: 10_000 });
}

async function tabTo(page: Page, target: Locator, maxTabs = 50): Promise<void> {
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  for (let i = 0; i < maxTabs; i += 1) {
    await page.keyboard.press("Tab");
    if (await isFocused(target)) return;
  }
  throw new Error(`Target was not reachable in ${maxTabs} forward Tab presses`);
}

async function expectVisibleKeyboardFocus(locator: Locator): Promise<void> {
  const focus = await locator.evaluate((el) => {
    const style = getComputedStyle(el);
    return {
      outlineStyle: style.outlineStyle,
      outlineWidth: Number.parseFloat(style.outlineWidth),
    };
  });
  expect(focus.outlineStyle).not.toBe("none");
  expect(focus.outlineWidth).toBeGreaterThan(0);
}

async function expectReflowAt320(page: Page): Promise<void> {
  const documentWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(documentWidth).toBeLessThanOrEqual(321);

  for (const wrap of await page.locator(".table-wrap").all()) {
    const dimensions = await wrap.evaluate((el) => ({
      overflowX: getComputedStyle(el).overflowX,
      scrollWidth: el.scrollWidth,
      clientWidth: el.clientWidth,
    }));
    if (dimensions.scrollWidth > dimensions.clientWidth) {
      expect(dimensions.overflowX).toBe("auto");
    }
  }
}

test.afterEach(async ({ page }) => {
  fixtureGuards.get(page)?.assertNoUnhandledRequests();
});

type Workflow = {
  name: string;
  path: string;
  heading: string | RegExp;
  session?: "authenticated" | "anonymous" | "setup";
  authenticated?: boolean;
  critical: (page: Page) => Locator;
};

const workflows: Workflow[] = [
  { name: "Overview", path: "/", heading: "Overview", authenticated: true, critical: (p) => p.getByRole("button", { name: "Toggle theme" }) },
  // `critical` is asserted visible AND tabbed to, so it has to be a focusable control:
  // a <p>/<li>/<h1> can never enter the tab order, which is why the honesty note, the send
  // card and the Transfers heading could not pass. Each now names the page's real control.
  { name: "Approve inbox", path: "/approve", heading: "Approve", authenticated: true, critical: (p) => p.getByRole("link", { name: "Transfers", exact: true }).last() },
  { name: "Approve inbox pending SEND", path: "/approve", heading: "Approve", authenticated: true, critical: (p) => p.getByRole("button", { name: "Review & decide" }) },
  { name: "Operations", path: "/operations", heading: "Operations", authenticated: true, critical: (p) => p.getByRole("link", { name: "Operations" }) },
  { name: "Wallets", path: "/wallets", heading: "Wallets", authenticated: true, critical: (p) => p.getByRole("link", { name: new RegExp(E2E_WALLET_PUBKEY.slice(0, 12)) }) },
  { name: "Wallet detail", path: `/wallets/${E2E_WALLET_PUBKEY}`, heading: "Wallet", authenticated: true, critical: (p) => p.getByRole("button", { name: "Copy pubkey" }) },
  { name: "Transfers", path: "/transfers", heading: "Transfers", authenticated: true, critical: (p) => p.getByRole("link", { name: E2E_OPERATION_ID }) },
  { name: "Transfer detail", path: `/transfers/${E2E_OPERATION_ID}`, heading: new RegExp(`Transfer\\s+${E2E_OPERATION_ID}`), authenticated: true, critical: (p) => p.getByRole("link", { name: "← Transfers" }) },
  { name: "Destinations", path: "/destinations", heading: "Destinations", authenticated: true, critical: (p) => p.getByRole("button", { name: "Bless destination" }) },
  { name: "Audit", path: "/audit", heading: "Audit log", authenticated: true, critical: (p) => p.getByRole("link", { name: "Audit" }) },
  { name: "API Keys", path: "/api-keys", heading: "Keys", authenticated: true, critical: (p) => p.getByRole("button", { name: "Issue key" }) },
  { name: "Backup", path: "/backup", heading: "Backup", authenticated: true, critical: (p) => p.getByRole("link", { name: "Backup" }) },
  { name: "Login", path: "/login", heading: "Zu Node", session: "anonymous", critical: (p) => p.getByRole("button", { name: "Sign in" }) },
  { name: "Setup", path: "/setup", heading: "Finish setup", session: "setup", critical: (p) => p.getByLabel("Current password") },
];

test.describe("every-workflow Chromium route matrix (320px)", () => {
  for (const workflow of workflows) {
    test(`${workflow.name}: meaningful render, 320px reflow, accessible keyboard controls, usable nav`, async ({ page }) => {
      await startRoute(page, workflow.path, workflow.session);

      const heading = page.getByRole("heading", { level: 1, name: workflow.heading });
      await expect(heading).toBeVisible();
      const surface = page.locator(workflow.authenticated ? "#main-content" : ".auth-card");
      await expect(surface).toBeVisible();
      expect((await surface.innerText()).trim().length).toBeGreaterThan(20);
      await expectReflowAt320(page);

      // getByRole/getByLabel resolves the real Chromium accessible name. Forward Tab (not
      // locator.focus()) proves the critical control participates in keyboard tab order.
      const critical = workflow.critical(page);
      await expect(critical).toBeVisible();
      await tabTo(page, critical);
      await expectVisibleKeyboardFocus(critical);

      if (workflow.authenticated) {
        const pin = page.getByRole("button", { name: "Pin sidebar" });
        await tabTo(page, pin);
        await expectVisibleKeyboardFocus(pin);
        await page.keyboard.press("Enter");
        await expect(page.getByRole("button", { name: "Collapse sidebar" })).toBeVisible();
        const overview = page.getByRole("link", { name: "Overview" });
        await expect(overview).toBeVisible();
        await expect(overview).toHaveAttribute("href", "/");
      }
    });
  }
});

test.describe("deeper real-browser mobile/keyboard checks", () => {
  test("Transfers 'To' shows the destination the summary row carries, not a dash", async ({
    page,
  }) => {
    await authenticated(page, "/transfers");
    const row = page.getByRole("row").filter({ hasText: E2E_OPERATION_ID });
    await expect(row).toBeVisible();
    // The fixture projects the list payload through OPERATION_INVENTORY_LIST_FIELDS, so this
    // passes only while the node's list projection actually carries destination_address.
    await expect(row.getByRole("cell", { name: E2E_DESTINATION_ADDRESS })).toBeVisible();
  });


  test("sidebar overlays rather than squeezing content and is keyboard-operable without hover", async ({ page }) => {
    await authenticated(page, "/");
    const pin = page.getByRole("button", { name: "Pin sidebar" });
    await tabTo(page, pin);
    await page.keyboard.press("Enter");
    await expect(page.locator(".app.pinned")).toHaveCount(1);
    await expect(page.getByRole("button", { name: "Collapse sidebar" })).toBeVisible();
    await expect(page.locator(".side")).toHaveCSS("position", "absolute");
    await expect(page.locator(".side .nav .lbl").first()).toHaveCSS("opacity", "1");
  });

  test("topbar controls stay in viewport and the document does not overflow", async ({ page }) => {
    await authenticated(page, "/");
    // The topbar (App.tsx `header.top`) carries exactly two icon buttons and the identity chip.
    // The second one is the attention bell, whose accessible name comes from its `title`: with
    // the fixture's zero-item needs-attention summary that name is "Approve inbox".
    const controls = [
      page.getByRole("button", { name: "Toggle theme" }),
      page.getByRole("button", { name: "Approve inbox" }),
      page.locator(".who"),
    ];
    for (const control of controls) {
      await expect(control).toBeVisible();
      const box = await control.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width).toBeLessThanOrEqual(321);
    }
    await expectReflowAt320(page);
  });

  test("Wallets table scrolls horizontally and keyboard focus scrolls its link into view", async ({ page }) => {
    await authenticated(page, "/wallets");
    await expect(page.getByText("1248.4200")).toBeVisible();
    const wrap = page.locator(".table-wrap");
    const dimensions = await wrap.evaluate((el) => ({ scrollWidth: el.scrollWidth, clientWidth: el.clientWidth }));
    expect(dimensions.scrollWidth).toBeGreaterThan(dimensions.clientWidth);
    const walletLink = page.getByRole("link", { name: new RegExp(E2E_WALLET_PUBKEY.slice(0, 12)) });
    await tabTo(page, walletLink);
    const box = await walletLink.boundingBox();
    const wrapBox = await wrap.boundingBox();
    expect(box).not.toBeNull();
    expect(wrapBox).not.toBeNull();
    expect(box!.x).toBeGreaterThanOrEqual(wrapBox!.x - 1);
    expect(box!.x + box!.width).toBeLessThanOrEqual(wrapBox!.x + wrapBox!.width + 1);
  });

  test("Settings renders the effective config as a read-only definition list", async ({ page }) => {
    await authenticated(page, "/settings");
    // SettingsPage.tsx is deliberately read-only — no <label>, no htmlFor, no aria-label — so the
    // name to resolve by is the <dt> term, and each term must carry the fixture's own value.
    const rows: readonly (readonly [string, string])[] = [
      ["Public base URL", "https://e2e-node.example"],
      ["Node ID", "11111111-1111-4111-8111-111111111111"],
      ["Gateway hosts", "gw.e2e.example"],
      ["Version", "e2e"],
      ["Backup schedule", "No"],
      ["Push configured", "Yes"],
    ];
    for (const [term, value] of rows) {
      const row = page
        .locator("dl > div")
        .filter({ has: page.locator("dt", { hasText: new RegExp(`^${term}$`) }) });
      await expect(row).toHaveCount(1);
      await expect(row.locator("dd")).toContainText(value);
    }
    // The page never accepts edits; a form control appearing here is the regression to catch.
    await expect(page.locator(".form-card input, .form-card select, .form-card textarea")).toHaveCount(0);
  });

  test("Transfer detail fields resolve by real accessible name", async ({ page }) => {
    // /transfers/new was never a declared route (main.tsx declares /transfers and /transfers/:id),
    // so the loop below used to iterate an empty list on the catch-all redirect and assert nothing.
    await authenticated(page, `/transfers/${E2E_OPERATION_ID}`);
    // Challenge UI (reject-reason label) mounts after the fixture-backed loadTransfer query;
    // wait for it so a slow self-hosted paint does not sample an empty label list.
    await expect(page.locator('label[for="reject-reason"]')).toBeVisible({ timeout: 15_000 });
    const labels = await page.locator("label[for]").allTextContents();
    expect(labels.length).toBeGreaterThan(0);
    for (const label of labels) {
      await expect(page.getByLabel(label.trim(), { exact: true })).toBeVisible();
    }
  });

  test("API Keys table scrolls and issue/revoke controls remain available", async ({ page }) => {
    await authenticated(page, "/api-keys");
    await expect(page.getByText("ik_e2emobilekeyprefix…")).toBeVisible();
    const wrap = page.locator(".table-wrap");
    const dimensions = await wrap.evaluate((el) => ({ scrollWidth: el.scrollWidth, clientWidth: el.clientWidth }));
    expect(dimensions.scrollWidth).toBeGreaterThan(dimensions.clientWidth);
    const issue = page.getByRole("button", { name: "Issue key" });
    await tabTo(page, issue);
    await expectVisibleKeyboardFocus(issue);
    await expect(page.getByRole("button", { name: "Revoke" })).toBeVisible();
  });

  test("Backup disabled controls are honest and readable without document overflow", async ({ page }) => {
    await authenticated(page, "/backup");
    const exportButton = page.getByRole("button", { name: /export backup/i });
    const importButton = page.getByRole("button", { name: /import backup/i });
    await expect(exportButton).toBeDisabled();
    await expect(importButton).toBeDisabled();
    await expect(page.getByText(/dist\/dr\/cli\.js/)).toBeVisible();
    await expectReflowAt320(page);
  });

  test("fixture guard rejects a matched API response overridden to HTTP 500", async ({ page }) => {
    const guard = await registerAdminApiRoutes(page, {
      responseStatusOverrides: {
        "GET /admin/v1/operations/needs-attention": 500,
      },
    });
    await page.goto("/operations");
    await expect(page.getByRole("heading", { level: 1, name: "Operations" })).toBeVisible();
    expect(() => guard.assertNoUnhandledRequests()).toThrow(
      "Matched admin API fixture returned unexpected non-2xx response(s): GET /admin/v1/operations/needs-attention -> 500",
    );
  });
});
