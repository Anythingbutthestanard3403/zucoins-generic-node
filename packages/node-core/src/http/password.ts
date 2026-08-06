// Password hashing + verification for node-origin admin login.
//
// bcrypt cost 12, via pure-JS bcryptjs — native bcrypt never compiles under this
// workspace's pnpm ignore-scripts supply-chain policy. Argon2id stays reserved for the
// client-side credential-vault passphrase KDF (action key + node URL encrypted
// client-side), never for login here.

import bcrypt from "bcryptjs";

const COST = 12;

export function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, COST);
}

export function verifyPassword(plain: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plain, hash);
}

/**
 * A real cost-12 hash of an unguessable constant. Login compares the submitted
 * password against this when the username does not resolve, so EVERY attempt
 * costs exactly one bcrypt compare and response timing cannot distinguish
 * "unknown user" from "wrong password".
 */
export const DUMMY_PASSWORD_HASH =
  "$2b$12$W6euifxnHi9I4JyM2kFCJeoypPjp3xqQt59tdZd1zGJZuQ3ustGMe";
