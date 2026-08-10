// ZTR-1181 — EXTERNAL money gates fail closed when Web Push is not composed.
//
// When PUBLIC_BASE_URL is unset, main leaves `push = null` and logs that
// EXTERNAL receives will refuse. The shared gate helper must throw
// PushSubscriptionRequiredError in that case (not no-op). Internal transfers
// never call this port, so they stay unaffected by construction.

import { describe, expect, it, vi } from "vitest";

import { PushSubscriptionRequiredError } from "@zucoins/node-core";

import { requireActivePushSubscriptionOrRefuse } from "./compose.js";

const WALLET_ID = "55555555-5555-4555-8555-555555555555";

describe("requireActivePushSubscriptionOrRefuse (ZTR-1181)", () => {
  it("throws PushSubscriptionRequiredError when push is null", async () => {
    await expect(
      requireActivePushSubscriptionOrRefuse(null, WALLET_ID),
    ).rejects.toBeInstanceOf(PushSubscriptionRequiredError);

    await expect(
      requireActivePushSubscriptionOrRefuse(null, WALLET_ID),
    ).rejects.toMatchObject({
      code: "push_subscription_required",
      walletId: WALLET_ID,
    });
  });

  it("delegates to push.service.requireActiveSubscription when composed", async () => {
    const requireActiveSubscription = vi.fn().mockResolvedValue(undefined);
    await expect(
      requireActivePushSubscriptionOrRefuse(
        { service: { requireActiveSubscription } },
        WALLET_ID,
      ),
    ).resolves.toBeUndefined();
    expect(requireActiveSubscription).toHaveBeenCalledOnce();
    expect(requireActiveSubscription).toHaveBeenCalledWith(WALLET_ID);
  });

  it("propagates PushSubscriptionRequiredError from the composed service", async () => {
    const err = new PushSubscriptionRequiredError(WALLET_ID);
    const requireActiveSubscription = vi.fn().mockRejectedValue(err);
    await expect(
      requireActivePushSubscriptionOrRefuse(
        { service: { requireActiveSubscription } },
        WALLET_ID,
      ),
    ).rejects.toBe(err);
  });
});
