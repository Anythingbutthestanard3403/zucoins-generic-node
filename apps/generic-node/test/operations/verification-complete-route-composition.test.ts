// Verification-complete route module + LIVE mount.
//
// The lineage/acknowledgement schema slices (lineage_path_proofs, verification_acknowledgements)
// and flips the reporting handler from config.failClosed to the live SQL composition.
// Census asserts the route is LIVE; module-level tests keep the cross-tenant envelope and
// unique-violation handling guards.
//
// Evidence discipline: ids only, never keys (Key-custody).

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { VerifiedReportRequest } from "@zucoins/node-core";

import {
  createProductionRouteSurface,
} from "../../src/full-http-mount.js";
import { createVerificationCompleteRouteHandler } from "../../src/operations/verification-complete-route.js";


/** Non-zero 32-byte test vault root for SqlAdminUserStore composition (ZTR-1134 B3). */
const ZTR_1134_TEST_VAULT_ROOT = Buffer.alloc(32, 0xa7);


const stubPool = () =>
  ({
    query: async () => ({ rows: [] }),
    connect: async () => ({
      query: async () => ({ rows: [] }),
      release: () => {},
    }),
  }) as never;

const NODE_FOR_STUB = "11111111-1111-4111-8111-111111111111";

describe("verification-complete LIVE mount (schema + route composition)", () => {
  it("AC1: production source mounts createVerificationCompleteRouteHandler (not failClosed)", () => {
    const liveSrc = readFileSync(
      fileURLToPath(new URL("../../src/reporting/live-reporting-reads.ts", import.meta.url)),
      "utf8",
    );
    expect(liveSrc).toMatch(/createVerificationCompleteRouteHandler/);
    expect(liveSrc).not.toMatch(/\[REPORTING_ROUTE_IDS\.verificationComplete\]:\s*config\.failClosed/);
    expect(liveSrc).toMatch(/LIVE_VERIFICATION_COMPLETE_ENGINE/);
  });

  it("AC4: the surface advertises verification_complete as a live engine", () => {
    const surface = createProductionRouteSurface({
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: NODE_FOR_STUB,
      pool: stubPool(),
      env: {},
    });
    expect(surface.liveReportingEngines.map((e) => e.routeId)).toContain("verification_complete");
  });

  it("the route module is exported from operations/index", () => {
    const indexSrc = readFileSync(
      fileURLToPath(new URL("../../src/operations/index.ts", import.meta.url)),
      "utf8",
    );
    expect(indexSrc).toMatch(/verification-complete-route\.js/);
  });
});

describe("route module: cross-tenant envelope + unique-violation handling", () => {
  it("the envelope sources tenant from the verified credential binding, not the operation row", () => {
    const routeSrc = readFileSync(
      fileURLToPath(new URL("../../src/operations/verification-complete-route.ts", import.meta.url)),
      "utf8",
    );
    // Adversarial Blocker 1 fix: nodeId/implementerId come from request.binding, not row.node_id.
    expect(routeSrc).toMatch(/nodeId:\s*request\.binding\.nodeId/);
    expect(routeSrc).toMatch(/implementerId:\s*request\.binding\.implementerId/);
    expect(routeSrc).not.toMatch(/nodeId:\s*row\.node_id/);
  });

  it("concurrent same-key UNIQUE violation maps to 409 idempotency_conflict, not 500", () => {
    const routeSrc = readFileSync(
      fileURLToPath(new URL("../../src/operations/verification-complete-route.ts", import.meta.url)),
      "utf8",
    );
    expect(routeSrc).toMatch(/isUniqueViolation/);
    expect(routeSrc).toMatch(/idempotency_conflict/);
  });
});

describe("D1/D2: body validation rejects before any DB touch", () => {
  const NODE_ID = "22222222-2222-4222-8222-222222222222";
  const IMPLEMENTER_ID = "33333333-3333-4333-8333-333333333333";

  // Poisoned pool: any query proves the handler ran DB side effects (nonce/idempotency
  // burn, envelope lookup) before the body was validated — the exact regression D1/D2 forbid.
  const poisonedPool = () =>
    ({
      query: async () => {
        throw new Error("DB must not be touched before strict-JSON + schema validation passes");
      },
      connect: async () => {
        throw new Error("DB must not be touched before strict-JSON + schema validation passes");
      },
    }) as never;

  const fakeRequest = (bodyText: string): VerifiedReportRequest =>
    ({
      ok: true as const,
      binding: {
        reportingKeyId: "key-1",
        nodeId: NODE_ID,
        implementerId: IMPLEMENTER_ID,
        publicKeyEncoded: "pub",
      },
      route: {
        routeId: "verification_complete",
        requestClass: "MUTATION" as const,
        retentionClass: "READ_NO_PRUNE_UNTIL_SAFETY_FREEZE" as const,
      },
      nonceEvidence: {
        id: randomUUID(),
        nodeId: NODE_ID,
        implementerId: IMPLEMENTER_ID,
        nonce: randomUUID(),
        purpose: "REPORT_REQUEST",
        routeId: "verification_complete",
        requestClass: "MUTATION",
        reportingKeyId: "key-1",
        lifecycleEpoch: 0n,
        nonceBurnSequence: 1n,
        requestPreimageText: "pre",
        requestPreimageSha256: "00".repeat(32),
        requestSignature: `${"A".repeat(86)}==`,
        method: "POST",
        rawTarget: "/v1/operations/44444444-4444-4444-8444-444444444444/verification-complete",
        bodySha256: "00".repeat(32),
        logicalFingerprint: "fp",
        issuedAt: "2026-07-18T00:00:00.000Z",
        expiresAt: "2026-07-18T00:01:00.000Z",
        receivedAtMs: 0,
        consumedAtMs: 0,
        retentionClass: "READ_NO_PRUNE_UNTIL_SAFETY_FREEZE",
      },
      idempotencyKey: randomUUID(),
      fingerprint: {
        method: "POST",
        rawTarget: "/v1/operations/44444444-4444-4444-8444-444444444444/verification-complete",
        bodySha256: "00".repeat(32),
      },
      bodyBytes: new TextEncoder().encode(bodyText),
      lastEventId: null,
    }) as VerifiedReportRequest;

  const runWith = async (bodyText: string) => {
    const handler = createVerificationCompleteRouteHandler({
      pool: poisonedPool(),
      nodeId: NODE_ID,
      newRequestId: () => "req-1",
      nowMs: () => 0,
    });
    return handler(fakeRequest(bodyText));
  };

  it("D2: missing wallet_evidence rejects 400, not 500", async () => {
    const { response, persistChild } = await runWith(
      JSON.stringify({ expected_row_version: 1, consumed_cursor: "1", verdict: "VERIFIED" }),
    );
    expect(response.status).toBe(400);
    expect(persistChild).toBeNull();
  });

  it("D2: wallet_evidence: {} (wrong shape) rejects 400, not 500", async () => {
    const { response, persistChild } = await runWith(
      JSON.stringify({
        expected_row_version: 1,
        consumed_cursor: "1",
        verdict: "VERIFIED",
        wallet_evidence: {},
      }),
    );
    expect(response.status).toBe(400);
    expect(persistChild).toBeNull();
  });

  it("D2: whole body null rejects 400, not 500", async () => {
    const { response, persistChild } = await runWith("null");
    expect(response.status).toBe(400);
    expect(persistChild).toBeNull();
  });

  it("D2: whole body [] rejects 400, not 500", async () => {
    const { response, persistChild } = await runWith("[]");
    expect(response.status).toBe(400);
    expect(persistChild).toBeNull();
  });

  it("D1: duplicate top-level JSON key (verdict) rejects 400 duplicate_json_key, last value never wins", async () => {
    // Signed body carries "verdict":"REJECTED" then a duplicate "verdict":"VERIFIED" — a
    // bare JSON.parse silently last-wins to VERIFIED (D1). The strict-JSON gate must reject
    // the whole request instead, exactly as arm-route.ts does for arm bodies.
    const bodyText =
      '{"expected_row_version":1,"consumed_cursor":"1","verdict":"REJECTED",' +
      '"wallet_evidence":[],"verdict":"VERIFIED"}';
    const { response, persistChild } = await runWith(bodyText);
    expect(response.status).toBe(400);
    expect(new TextDecoder().decode(response.bodyBytes)).toContain("duplicate_json_key");
    expect(persistChild).toBeNull();
  });
});