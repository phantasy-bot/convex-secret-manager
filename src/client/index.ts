export { SecretManager } from "./SecretManager.js";
export type { SecretManagerOptions } from "./SecretManager.js";
export {
  buildSecretPreview,
  decryptSecretValue,
  encryptSecretValue,
  generateIssuedToken,
  hashToken,
  isEncryptedSecret,
  defineKeys,
  parseDefinedKeys,
  activeKeyVersion,
  isSecretManagerError,
  secretManagerError,
  SECRET_MANAGER_ERROR_CODES,
} from "./crypto.js";
export type { SecretManagerErrorCode, SecretManagerErrorData } from "./crypto.js";
export * from "../shared.js";