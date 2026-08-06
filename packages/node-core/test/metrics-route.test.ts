// bearer-gated, fail-closed /metrics route for the generic node.
// Proves: 401-no-auth, 401-wrong-token, unmountable-without-token, and a secret-scan of
// the rendered registry output (name/label/help must not leak custody secret material).

import { describe, expect, it } from "vitest";

import { createMetricsRoute, METRICS_CONTENT_TYPE } from "../src/http/metrics-route.js";
import { createNodeMetrics, renderMetrics } from "../src/core/metrics.js";

const TOKEN = "s3cr3t-scrape-token-value";

function mountedRoute() {
  let renderCalls = 0;
  const handler = createMetricsRoute({
    scrapeToken: TOKEN,
    render: () => {
      renderCalls += 1;
      return "gn_test_metric 1\n";
    },
  });
  return { handler, renders: () => renderCalls };
}

describe("createMetricsRoute — bearer gating (proof #1)", () => {
  it("returns 401 with an empty body when no Authorization header is present", async () => {
    const { handler, renders } = mountedRoute();
    const res = await handler!(undefined);
    expect(res.status).toBe(401);
    expect(res.body).toBe("");
    // Auth is checked before render: an unauthenticated scrape never touches the body.
    expect(renders()).toBe(0);
  });

  it("returns 401 for a wrong token of the same length", async () => {
    const { handler } = mountedRoute();
    const wrongSameLength = "x".repeat(TOKEN.length);
    const res = await handler!(`Bearer ${wrongSameLength}`);
    expect(res.status).toBe(401);
    expect(res.body).toBe("");
  });

  it("returns 401 for a wrong token of a DIFFERENT length without throwing", async () => {
    // The load-bearing constant-time property: both sides are hashed to fixed 32-byte
    // digests, so timingSafeEqual never sees unequal lengths (it throws if it does).
    const { handler } = mountedRoute();
    await expect(handler!("Bearer short")).resolves.toMatchObject({ status: 401 });
    await expect(handler!(`Bearer ${TOKEN}-with-extra-suffix`)).resolves.toMatchObject({
      status: 401,
    });
  });

  it("returns 401 for a header missing the Bearer scheme (no early return)", async () => {
    const { handler } = mountedRoute();
    const res = await handler!(TOKEN); // raw token, no "Bearer " prefix
    expect(res.status).toBe(401);
    expect(res.body).toBe("");
  });

  it("leaves no distinguishing oracle: every failure mode returns identical bytes", async () => {
    const { handler } = mountedRoute();
    const noHeader = await handler!(undefined);
    const malformed = await handler!("Basic abc");
    const wrongToken = await handler!("Bearer nope");
    expect(noHeader).toEqual(malformed);
    expect(malformed).toEqual(wrongToken);
    expect(wrongToken).toEqual({ status: 401, headers: {}, body: "" });
  });

  it("returns 200 with the rendered body and Prometheus content-type for the correct token", async () => {
    const { handler, renders } = mountedRoute();
    const res = await handler!(`Bearer ${TOKEN}`);
    expect(res.status).toBe(200);
    expect(res.body).toBe("gn_test_metric 1\n");
    expect(res.headers["content-type"]).toBe(METRICS_CONTENT_TYPE);
    expect(renders()).toBe(1);
  });

  it("awaits an async render on the authenticated path", async () => {
    const handler = createMetricsRoute({
      scrapeToken: TOKEN,
      render: () => Promise.resolve("gn_async_metric 2\n"),
    });
    const res = await handler!(`Bearer ${TOKEN}`);
    expect(res.status).toBe(200);
    expect(res.body).toBe("gn_async_metric 2\n");
  });
});

describe("createMetricsRoute — unmountable without a token (proof #2)", () => {
  const render = () => "gn_test_metric 1\n";

  it("returns undefined when the scrape token is undefined (route is never registered)", () => {
    expect(createMetricsRoute({ scrapeToken: undefined, render })).toBeUndefined();
  });

  it("returns undefined for an empty-string token (falsy => unmountable)", () => {
    expect(createMetricsRoute({ scrapeToken: "", render })).toBeUndefined();
  });

  it("returns a callable handler ONLY when a token is configured (mounted != 404)", () => {
    const unmounted = createMetricsRoute({ scrapeToken: undefined, render });
    const mounted = createMetricsRoute({ scrapeToken: TOKEN, render });
    expect(unmounted).toBeUndefined();
    expect(typeof mounted).toBe("function");
  });
});

describe("metrics registry secret-scan (proof #3)", () => {
  // The rendered exposition covers every metric name, HELP line, TYPE line, and label
  // key/value. None may contain private-key / TOTP / session / CSRF / other secret
  // material — a defence-in-depth check on the closed-vocabulary registry (metrics.ts).
  const SECRET_INDICATORS = [
    "private_key",
    "privatekey",
    "private-key",
    "totp",
    "csrf",
    "session",
    "secret",
    "master_key",
    "masterkey",
    "vault",
    "seed",
    "mnemonic",
    "password",
    "authorization",
    "bearer",
    "api_key",
    "apikey",
    "scrape_token",
  ];

  it("exposes no secret-shaped token in any metric name/label/help", async () => {
    const rendered = (await renderMetrics(createNodeMetrics())).toLowerCase();
    for (const indicator of SECRET_INDICATORS) {
      expect(rendered).not.toContain(indicator);
    }
  });

  it("still renders the expected operational metric names (sanity: scan is over real output)", async () => {
    const rendered = await renderMetrics(createNodeMetrics());
    expect(rendered).toContain("gn_available_wallets");
    expect(rendered).toContain("gn_active_leases");
    expect(rendered).toContain("gn_receive_queue_depth");
    expect(rendered).toContain("gn_t0_read_failures_total");
    expect(rendered).toContain("gn_proof_budget_exhaustion_total");
    expect(rendered).toContain("gn_halt_engaged");
    expect(rendered).toContain("gn_signer_leadership_held");
    expect(rendered).toContain("gn_storage_pressure");
    expect(rendered).toContain("gn_worker_healthy");
  });
});
