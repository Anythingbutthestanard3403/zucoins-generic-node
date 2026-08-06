import { describe, expect, it } from "vitest";

import { loadNodeConfig, NodeConfigurationError } from "../src/config/index.js";

// PUBLIC_BASE_URL fallback from RAILWAY_PUBLIC_DOMAIN.
// The fail-closed config rules are unchanged by the fallback.

function validEnv(
  overrides: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
  return {
    NODE_ENV: "development",
    DATABASE_URL: "postgresql://node:db-secret@db.internal:5432/zunode",
    SPLITCHAIN_GATEWAY_URLS: "https://gateway-entry-1.internal.example/",
    PUBLIC_BASE_URL: "https://node.internal.example/",
    NODE_ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    ...overrides,
  };
}

describe("PUBLIC_BASE_URL fallback from RAILWAY_PUBLIC_DOMAIN", () => {
  it("derives https://<domain> when PUBLIC_BASE_URL is unset and RAILWAY_PUBLIC_DOMAIN is present", () => {
    const config = loadNodeConfig(
      validEnv({ PUBLIC_BASE_URL: undefined, RAILWAY_PUBLIC_DOMAIN: "node-prod.up.railway.app" }),
    );
    expect(config.PUBLIC_BASE_URL).toBe("https://node-prod.up.railway.app");
  });

  it("prefers an explicit PUBLIC_BASE_URL over RAILWAY_PUBLIC_DOMAIN", () => {
    const config = loadNodeConfig(
      validEnv({
        PUBLIC_BASE_URL: "https://node.internal.example/",
        RAILWAY_PUBLIC_DOMAIN: "node-prod.up.railway.app",
      }),
    );
    expect(config.PUBLIC_BASE_URL).toBe("https://node.internal.example/");
  });

  it("fails boot closed when neither PUBLIC_BASE_URL nor RAILWAY_PUBLIC_DOMAIN is set", () => {
    let error: unknown;
    try {
      loadNodeConfig(validEnv({ PUBLIC_BASE_URL: undefined, RAILWAY_PUBLIC_DOMAIN: undefined }));
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(NodeConfigurationError);
    expect((error as NodeConfigurationError).issues.join("\n")).toContain(
      "PUBLIC_BASE_URL is required",
    );
  });
});
