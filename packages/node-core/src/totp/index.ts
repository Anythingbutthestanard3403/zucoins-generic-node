export { matchTotp } from "./match.js";
export type { TotpConfig, TotpMatchOutcome } from "./match.js";
export { parseAdminTotpSecret } from "./parse-secret.js";
export {
  decodeBase32,
  encodeBase32,
  generateTotpSecret,
  otpauthUri,
  totpSecretBytes,
} from "./secret.js";
export {
  InMemoryTotpBurnStore,
  SqlTotpBurnStore,
  TotpConsumptionLog,
  createPoolTotpBurnExecutor,
} from "./burn-store.js";
export type { TotpBurnStore, TotpBurnSqlExecutor } from "./burn-store.js";

export {
  TOTP_SECRET_ENVELOPE_PREFIX,
  TOTP_SECRET_HKDF_LABEL,
  TotpOpenError,
  TotpSealError,
  buildTotpSecretAad,
  buildTotpSecretDekInfo,
  openTotpSecret,
  sealTotpSecret,
} from "./seal.js";

export { rewrapTotpSecretStore } from "./rewrap.js";
export type { TotpSecretRewrapInput, TotpSecretRewrapRow } from "./rewrap.js";

export { migrateTotpSecretsAtRest } from "./migrate-plaintext.js";
export type {
  TotpPlaintextMigrationExecutor,
  TotpPlaintextMigrationResult,
} from "./migrate-plaintext.js";
