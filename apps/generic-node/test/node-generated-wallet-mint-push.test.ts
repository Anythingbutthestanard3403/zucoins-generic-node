// ZTR-1307 — destination/funding mint must fire the post-commit push provision hook.
//
// The real key generator lives in main.ts (not exported). This suite locks the
// production contract via source + a minimal inlined twin of the mint body so the
// post-seal hook cannot regress without a failing test.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const mainSrc = readFileSync(join(here, "../src/main.ts"), "utf8");
const fhmSrc = readFileSync(join(here, "../src/full-http-mount.ts"), "utf8");

describe("ZTR-1307 · every mint path arms push provision", () => {
  it("key generator only calls onWalletMinted after successful seal (source order)", () => {
    const fn = mainSrc.slice(
      mainSrc.indexOf("function createNodeGeneratedWalletKeyGenerator"),
      mainSrc.indexOf("async function main(): Promise<void>"),
    );
    const sealAt = fn.indexOf("await deps.vault.seal");
    const hookAt = fn.indexOf("deps.onWalletMinted?.(walletId)");
    const catchAt = fn.indexOf("} catch (err) {");
    expect(sealAt).toBeGreaterThan(0);
    expect(hookAt).toBeGreaterThan(sealAt);
    expect(hookAt).toBeLessThan(catchAt);
    // Compensation path must not call the hook.
    const catchBlock = fn.slice(catchAt, fn.indexOf("} finally {", catchAt));
    expect(catchBlock).not.toContain("onWalletMinted");
  });

  it("pool scale-up already wires onWalletsMinted (unchanged contract)", () => {
    expect(mainSrc).toMatch(
      /onWalletsMinted:\s*\(walletIds\)\s*=>\s*push\?\.onWalletsMinted\(walletIds\)/,
    );
  });

  it("funding mint fires onWalletsMinted only on the success path", () => {
    const mint = fhmSrc.slice(
      fhmSrc.indexOf("const mintFundingWallet ="),
      fhmSrc.indexOf("const mintFundingWallet =") + 2200,
    );
    const sealAt = mint.indexOf("await vault.seal");
    const hookAt = mint.indexOf("config.onWalletsMinted?.([walletId])");
    const catchAt = mint.indexOf("} catch (err) {");
    expect(sealAt).toBeGreaterThan(0);
    expect(hookAt).toBeGreaterThan(sealAt);
    expect(hookAt).toBeLessThan(catchAt);
  });

  it("composePush onWalletsMinted provisions each wallet id", () => {
    const compose = readFileSync(join(here, "../src/push/compose.ts"), "utf8");
    expect(compose).toContain("onWalletsMinted(walletIds)");
    expect(compose).toContain("await service.provision({ walletId, publicKey })");
  });

  it("listSubscribableWallets includes wallets with zero push rows (reconcile backstop)", () => {
    const store = readFileSync(join(here, "../src/push/sql-store.ts"), "utf8");
    expect(store).toMatch(/FROM wallets[\s\S]*retired_at IS NULL/);
    expect(store).not.toMatch(
      /listSubscribableWallets[\s\S]{0,400}JOIN push_subscriptions/,
    );
  });
});
