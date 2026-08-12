import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import type { WalletInventoryItem } from "../lib/money.js";
import { walletHoldCauseText, WalletHoldCause } from "./WalletHoldCause.js";

function base(over: Partial<WalletInventoryItem> = {}): WalletInventoryItem {
  return {
    wallet_id: "w1",
    node_id: "n1",
    public_key: "pk",
    key_origin: "node_generated",
    state: "AVAILABLE",
    created_at: "2026-01-01T00:00:00.000Z",
    retired_at: null,
    quarantine_reason: null,
    recovery_verified: true,
    recovery_verified_at: null,
    recovery_verification: null,
    observed_balance_zkz: null,
    holding_operation_id: null,
    holding_operation_status: null,
    holding_operation_expiry_unix_time_secs: null,
    holding_operation_attention_required: false,
    holding_operation_terminal_at: null,
    holding_lease_role: null,
    holding_operation_type: null,
    ...over,
  } as WalletInventoryItem;
}

describe("walletHoldCauseText", () => {
  it("names quarantine reason", () => {
    expect(
      walletHoldCauseText(base({ state: "QUARANTINED", quarantine_reason: "REGRESSION" })),
    ).toBe("QUARANTINED: REGRESSION");
  });
  it("names holding operation kind + short id", () => {
    const t = walletHoldCauseText(
      base({
        state: "PINNED",
        holding_operation_id: "4fc07a73-aaaa-bbbb-cccc-dddddddddddd",
        holding_operation_type: "RECEIVE_EXTERNAL",
        holding_operation_status: "AWAITING_REDEMPTION",
      }),
    );
    expect(t).toMatch(/Held by Incoming 4fc07a73/);
    expect(t).toMatch(/Waiting for recipient/);
  });
  it("returns null for free AVAILABLE", () => {
    expect(walletHoldCauseText(base())).toBeNull();
  });
});

describe("WalletHoldCause", () => {
  it("links the holding operation", () => {
    render(
      <MemoryRouter>
        <WalletHoldCause
          wallet={base({
            state: "PINNED",
            holding_operation_id: "op-1",
            holding_operation_type: "SEND_EXTERNAL",
          })}
        />
      </MemoryRouter>,
    );
    expect(screen.getByTestId("wallet-hold-op-link")).toHaveAttribute("href", "/operations/op-1");
  });
});
