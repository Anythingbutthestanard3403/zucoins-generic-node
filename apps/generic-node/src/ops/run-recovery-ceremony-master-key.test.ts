import { describe, expect, it } from "vitest";
import { resolveCeremonyMasterKey } from "./run-recovery-ceremony.js";

describe("resolveCeremonyMasterKey (ZTR-1171)", () => {
  it("does not read VAULT_MASTER_KEY from env without ALLOW_ENV", async () => {
    // Without TTY/FD/allow, prompt fails closed — never silently uses env.
    await expect(
      resolveCeremonyMasterKey(
        {
          VAULT_MASTER_KEY: "x".repeat(40),
        },
        { label: "VAULT_MASTER_KEY", required: true },
      ),
    ).rejects.toThrow();
  });

  it("uses env when ALLOW_ENV is set", async () => {
    const key = "y".repeat(40);
    await expect(
      resolveCeremonyMasterKey(
        {
          VAULT_MASTER_KEY: key,
          VAULT_MASTER_KEY_ALLOW_ENV: "1",
        },
        { label: "VAULT_MASTER_KEY", required: true },
      ),
    ).resolves.toBe(key);
  });
});
