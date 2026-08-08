import { randomUUID } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createFailClosedOperationStore, createRejectAllOperationAuth } from "@zucoins/node-core";
import { describe, expect, it } from "vitest";

import { NodeReadiness } from "../src/boot/readiness.js";
import { createNodeRuntimeListener, type NodeRuntimeListenerDeps } from "../src/runtime-listener.js";

// ZTR-1185: `GET /%zz` reached decodeURIComponent inside admin-spa's safeJoin, which
// threw URIError out of the synchronous dispatch closure and killed the process — no
// credential of any kind required. These drive the real listener through the same
// node:http seam the other dispatch tests use (the network-containment guard in
// test/setup-network-guard.ts makes a loopback round-trip impossible), so the assertion
// is precisely the one that matters: the listener returns, and a response was written.

function spaDist(): string {
  const dist = mkdtempSync(join(tmpdir(), "spa-escape-"));
  writeFileSync(join(dist, "index.html"), "<!doctype html><title>zu</title>");
  return dist;
}

function makeDeps(adminSpaDist: string): NodeRuntimeListenerDeps {
  return {
    readiness: new NodeReadiness(3),
    pingDb: async () => {
      throw new Error("database adapter is not wired in this test — readiness stays false");
    },
    operationStore: createFailClosedOperationStore(),
    operationAuth: createRejectAllOperationAuth(),
    newRequestId: () => randomUUID(),
    adminSpaDist,
  };
}

interface Captured {
  status: number;
  ended: boolean;
}

/** Dispatch synchronously so an escaping throw fails the test rather than the process. */
function dispatch(deps: NodeRuntimeListenerDeps, method: string, url: string): Captured {
  const listener = createNodeRuntimeListener(deps);
  const captured: Captured = { status: 0, ended: false };
  const response = {
    writeHead(status: number) {
      captured.status = status;
      return this;
    },
    end() {
      captured.ended = true;
      return this;
    },
  } as unknown as ServerResponse;
  const request = { method, url, headers: {}, rawHeaders: [] } as unknown as IncomingMessage;
  expect(() => listener(request, response)).not.toThrow();
  return captured;
}

describe("runtime dispatch of malformed percent-escapes (ZTR-1185)", () => {
  it("answers a malformed escape instead of throwing URIError out of the dispatch closure", () => {
    const deps = makeDeps(spaDist());
    for (const url of ["/%", "/%z", "/%zz", "/assets/%zz.js", "/%zz?a=1"]) {
      const captured = dispatch(deps, "GET", url);
      expect(captured.ended, `no response written for ${url}`).toBe(true);
      expect(captured.status, `unexpected status for ${url}`).toBe(400);
    }
  });

  it("still refuses encoded traversal — the guard the decode sits in front of is unchanged", () => {
    const deps = makeDeps(spaDist());
    for (const url of ["/%2e%2e%2f", "/%2e%2e%2fetc%2fpasswd", "/%2e%2e/"]) {
      const captured = dispatch(deps, "GET", url);
      expect(captured.status, `traversal not refused for ${url}`).toBe(400);
    }
  });

  it("serves a well-formed SPA route, proving the dist root under test is live", () => {
    // Without this the 400s above could come from an unmounted SPA rather than safeJoin.
    const captured = dispatch(makeDeps(spaDist()), "HEAD", "/wallets");
    expect(captured.status).toBe(200);
  });
});
