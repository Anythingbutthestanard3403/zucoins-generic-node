// Key-bearing bodies must never be hashed into admin idempotency fingerprints.
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { sha256HexUtf8 } from "./admin-idempotency.js";
import {
  checkAdminIdempotency,
  RECOVERY_CEREMONY_START_BODY_FINGERPRINT,
  structuralBodyFingerprint,
} from "./admin-idempotency-guard.js";

describe("admin-idempotency-guard key-bearing body", () => {
  const master = "test-master-key-32chars!!!!!!!!!!!";
  const rawBody = Buffer.from(JSON.stringify({ vault_master_key: master }), "utf8");

  it("default path hashes body (non-key routes)", async () => {
    const check = await checkAdminIdempotency({
      store: undefined,
      nodeId: "n",
      routeId: "admin_halt",
      idemKeyHeader: "idem-key-16-chars-xx",
      method: "POST",
      rawTarget: "/admin/v1/halt",
      rawBody: Buffer.from("{}"),
    });
    expect(check.outcome).toBe("proceed");
    if (check.outcome !== "proceed") return;
    expect(check.fingerprint.bodySha256).toBe(sha256HexUtf8("{}"));
  });

  it("bodySha256 override never equals sha256 of master-key body", async () => {
    const check = await checkAdminIdempotency({
      store: undefined,
      nodeId: "n",
      routeId: "admin_recovery_ceremony_start",
      idemKeyHeader: "idem-key-16-chars-yy",
      method: "POST",
      rawTarget: "/admin/v1/recovery-ceremony/start",
      rawBody,
      bodySha256: RECOVERY_CEREMONY_START_BODY_FINGERPRINT,
    });
    expect(check.outcome).toBe("proceed");
    if (check.outcome !== "proceed") return;
    const bodyHash = sha256HexUtf8(rawBody.toString("utf8"));
    const keyHash = createHash("sha256").update(master, "utf8").digest("hex");
    expect(check.fingerprint.bodySha256).toBe(RECOVERY_CEREMONY_START_BODY_FINGERPRINT);
    expect(check.fingerprint.bodySha256).not.toBe(bodyHash);
    expect(check.fingerprint.bodySha256).not.toBe(keyHash);
  });

  it("structuralBodyFingerprint is deterministic and label-scoped", () => {
    expect(structuralBodyFingerprint("admin_recovery_ceremony_start")).toBe(
      RECOVERY_CEREMONY_START_BODY_FINGERPRINT,
    );
    expect(structuralBodyFingerprint("other")).not.toBe(RECOVERY_CEREMONY_START_BODY_FINGERPRINT);
  });
});
