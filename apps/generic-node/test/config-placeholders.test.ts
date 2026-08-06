import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

import {
  loadNodeConfig,
  metricsMounted,
  PLACEHOLDER_DATABASE_URL,
  PLACEHOLDER_GATEWAY_URL,
  PLACEHOLDER_INITIAL_ADMIN_PASSWORD,
  PLACEHOLDER_METRICS_SCRAPE_TOKEN,
  PLACEHOLDER_PUBLIC_BASE_URL,
  PlaceholderSecretError,
} from "../src/config/index.js";

function productionEnv(
  overrides: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
  return {
    NODE_ENV: "production",
    DATABASE_URL: "postgresql://operator:r3al-l0ng-secret@db.merchant.internal:5432/zunode",
    // The real production SplitChain gateway host has historically looked
    // dev-shaped; it must boot without a whisper (names lie).
    SPLITCHAIN_GATEWAY_URLS: "https://gateway-entry-1-q2whsu3jlj.splitchain.com/",
    PUBLIC_BASE_URL: "https://node.merchant.example/",
    NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    VAULT_MASTER_KEY: "r3al-l0ng-v4ult-m4ster-k3y-that-is-at-least-32-chars",
    ...overrides,
  };
}

describe("placeholder gate — hard refusal in production (known placeholders only)", () => {
  it("refuses the .env.example DATABASE_URL literal, naming the field not the value", () => {
    const warn = vi.fn();
    let error: unknown;
    try {
      loadNodeConfig(productionEnv({ DATABASE_URL: PLACEHOLDER_DATABASE_URL }), warn);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(PlaceholderSecretError);
    const message = (error as Error).message;
    expect(message).toContain("DATABASE_URL");
    expect(message).not.toContain(PLACEHOLDER_DATABASE_URL);
    expect(warn).not.toHaveBeenCalled();
  });

  it("refuses the .env.example gateway endpoint literal", () => {
    let error: unknown;
    try {
      loadNodeConfig(
        productionEnv({ SPLITCHAIN_GATEWAY_URLS: PLACEHOLDER_GATEWAY_URL }),
        vi.fn(),
      );
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(PlaceholderSecretError);
    const message = (error as Error).message;
    expect(message).toContain("SPLITCHAIN_GATEWAY_URLS");
    expect(message).not.toContain(PLACEHOLDER_GATEWAY_URL);
  });

  it("refuses the .env.example PUBLIC_BASE_URL literal", () => {
    let error: unknown;
    try {
      loadNodeConfig(productionEnv({ PUBLIC_BASE_URL: PLACEHOLDER_PUBLIC_BASE_URL }), vi.fn());
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(PlaceholderSecretError);
    expect((error as Error).message).toContain("PUBLIC_BASE_URL");
  });

  it("refuses a placeholder metrics scrape token (would mount /metrics effectively open)", () => {
    for (const token of [PLACEHOLDER_METRICS_SCRAPE_TOKEN, "7".repeat(64)]) {
      let error: unknown;
      try {
        loadNodeConfig(productionEnv({ METRICS_SCRAPE_TOKEN: token }), vi.fn());
      } catch (caught) {
        error = caught;
      }
      expect(error).toBeInstanceOf(PlaceholderSecretError);
      const message = (error as Error).message;
      expect(message).toContain("METRICS_SCRAPE_TOKEN");
      expect(message).not.toContain(token);
    }
  });

  it("collects every placeholder field into one diagnosable refusal", () => {
    let error: unknown;
    try {
      loadNodeConfig(
        productionEnv({
          DATABASE_URL: PLACEHOLDER_DATABASE_URL,
          SPLITCHAIN_GATEWAY_URLS: PLACEHOLDER_GATEWAY_URL,
          PUBLIC_BASE_URL: PLACEHOLDER_PUBLIC_BASE_URL,
          METRICS_SCRAPE_TOKEN: PLACEHOLDER_METRICS_SCRAPE_TOKEN,
        }),
        vi.fn(),
      );
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(PlaceholderSecretError);
    expect((error as PlaceholderSecretError).fields).toEqual([
      "DATABASE_URL",
      "SPLITCHAIN_GATEWAY_URLS",
      "PUBLIC_BASE_URL",
      "METRICS_SCRAPE_TOKEN",
    ]);
  });
});

describe("placeholder gate — warn-only, never refuse, on the merely dev-shaped", () => {
  it("boots the real (dev-shaped-looking) production gateway host without a warning", () => {
    const warn = vi.fn();
    const config = loadNodeConfig(productionEnv(), warn);
    expect(config.SPLITCHAIN_GATEWAY_URLS).toEqual([
      "https://gateway-entry-1-q2whsu3jlj.splitchain.com/",
    ]);
    expect(warn).not.toHaveBeenCalled();
  });

  it("warns but boots on the .env.example INITIAL_ADMIN_PASSWORD literal", () => {
    const warn = vi.fn();
    loadNodeConfig(
      productionEnv({ INITIAL_ADMIN_PASSWORD: PLACEHOLDER_INITIAL_ADMIN_PASSWORD }),
      warn,
    );
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]?.[0]).toContain("INITIAL_ADMIN_PASSWORD");
  });

  it("boots with metrics unset in production — the route simply is not mounted", () => {
    const warn = vi.fn();
    const config = loadNodeConfig(productionEnv(), warn);
    expect(metricsMounted(config)).toBe(false);
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("placeholder gate — scope and ground truth", () => {
  it("does not gate non-production boots at all", () => {
    const warn = vi.fn();
    const config = loadNodeConfig(
      productionEnv({
        NODE_ENV: "development",
        DATABASE_URL: PLACEHOLDER_DATABASE_URL,
        SPLITCHAIN_GATEWAY_URLS: PLACEHOLDER_GATEWAY_URL,
        PUBLIC_BASE_URL: PLACEHOLDER_PUBLIC_BASE_URL,
      }),
      warn,
    );
    expect(config.DATABASE_URL).toBe(PLACEHOLDER_DATABASE_URL);
    expect(warn).not.toHaveBeenCalled();
  });

  it("keeps the placeholder literals in sync with apps/generic-node/.env.example", () => {
    const examplePath = fileURLToPath(new URL("../.env.example", import.meta.url));
    const example = readFileSync(examplePath, "utf8");
    for (const literal of [
      PLACEHOLDER_DATABASE_URL,
      PLACEHOLDER_GATEWAY_URL,
      PLACEHOLDER_PUBLIC_BASE_URL,
      PLACEHOLDER_METRICS_SCRAPE_TOKEN,
      PLACEHOLDER_INITIAL_ADMIN_PASSWORD,
    ]) {
      expect(example).toContain(literal);
    }
  });
});
