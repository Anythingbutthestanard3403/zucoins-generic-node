// Password hashing + verification for node-origin admin login.
//
// bcrypt cost 13, via pure-JS bcryptjs — native bcrypt never compiles under this
// workspace's pnpm ignore-scripts supply-chain policy. Argon2id stays reserved for the
// client-side credential-vault passphrase KDF (action key + node URL encrypted
// client-side), never for login here.
//
// Cost raised 12 → 13 (ZTR-1168). Measured on Apple Silicon (node 22, bcryptjs 3.x):
//   hash ~510 ms, compare ~590 ms at cost 13. Login remains single-compare; rehash of
//   legacy cost-12 hashes runs once after a successful verify (see needsPasswordRehash).

import bcrypt from "bcryptjs";

const COST = 13;

export function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, COST);
}

export function verifyPassword(plain: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plain, hash);
}

/** True when the stored hash uses a lower bcrypt cost than the current policy. */
export function needsPasswordRehash(hash: string): boolean {
  try {
    return bcrypt.getRounds(hash) < COST;
  } catch {
    return false;
  }
}

/**
 * A real cost-13 hash of an unguessable constant. Login compares the submitted
 * password against this when the username does not resolve, so EVERY attempt
 * costs exactly one bcrypt compare and response timing cannot distinguish
 * "unknown user" from "wrong password".
 */
export const DUMMY_PASSWORD_HASH =
  "$2b$13$MUSoUowfiYSJleKezv8vfeVT0f5kE7IJXwCx8D26bgKwq3o9IXLcq";
