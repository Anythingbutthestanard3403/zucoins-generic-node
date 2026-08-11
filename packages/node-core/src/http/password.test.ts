import { describe, expect, it } from "vitest";
import bcrypt from "bcryptjs";
import {
  DUMMY_PASSWORD_HASH,
  hashPassword,
  needsPasswordRehash,
  verifyPassword,
} from "./password.js";

describe("password cost + rehash (ZTR-1168)", () => {
  it("hashes at cost 13", async () => {
    const h = await hashPassword("unit-test-password-xx");
    expect(bcrypt.getRounds(h)).toBe(13);
    expect(await verifyPassword("unit-test-password-xx", h)).toBe(true);
  });

  it("detects legacy cost-12 hashes as needing rehash", async () => {
    const legacy = await bcrypt.hash("legacy-password-xx", 12);
    expect(needsPasswordRehash(legacy)).toBe(true);
    const current = await hashPassword("legacy-password-xx");
    expect(needsPasswordRehash(current)).toBe(false);
  });

  it("dummy hash is cost 13", () => {
    expect(bcrypt.getRounds(DUMMY_PASSWORD_HASH)).toBe(13);
  });
});
