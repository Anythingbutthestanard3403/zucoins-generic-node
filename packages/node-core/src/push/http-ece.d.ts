declare module "http_ece" {
  export function decrypt(buffer: Buffer, params: Record<string, unknown>): Buffer;
  export function encrypt(buffer: Buffer, params: Record<string, unknown>): Buffer;
  export function verifyKeylogDisabled(challenge: object): unknown;
}
