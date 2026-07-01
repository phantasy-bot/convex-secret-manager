import {
  buildAad,
  decryptSecret,
  encryptSecret,
  isEnvelopeSecret,
  isLegacySecret,
} from "../crypto/envelope.js";

export { buildAad } from "../crypto/envelope.js";
export {
  defineKeys,
  parseDefinedKeys,
  activeKeyVersion,
} from "../crypto/defineKeys.js";
export {
  isSecretManagerError,
  secretManagerError,
  SECRET_MANAGER_ERROR_CODES,
} from "../crypto/errors.js";
export type { SecretManagerErrorCode, SecretManagerErrorData } from "../crypto/errors.js";

export function isEncryptedSecret(value: string | undefined): boolean {
  return isLegacySecret(value) || isEnvelopeSecret(value);
}

export async function encryptSecretValue(
  value: string,
  encryptionKey: string,
  path?: { ownerId: string; namespace: string; name: string },
): Promise<string> {
  const keysSerialized = process.env.SECRET_MANAGER_KEYS?.trim();
  const aad = path ? buildAad(path.ownerId, path.namespace, path.name) : "legacy";
  const encrypted = await encryptSecret(value, aad, keysSerialized, encryptionKey);
  return encrypted.ciphertext;
}

export async function decryptSecretValue(
  value: string,
  encryptionKey: string,
  path?: { ownerId: string; namespace: string; name: string },
): Promise<string> {
  const keysSerialized = process.env.SECRET_MANAGER_KEYS?.trim();
  const aad = path ? buildAad(path.ownerId, path.namespace, path.name) : "legacy";
  return decryptSecret(value, aad, keysSerialized, encryptionKey);
}

export function buildSecretPreview(value: string): string {
  if (value.length <= 12) {
    return `${value.slice(0, 4)}...`;
  }
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

export async function hashToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function generateIssuedToken(prefix = "sm_"): {
  token: string;
  tokenPrefix: string;
  tokenLast4: string;
} {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const body = Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  const token = `${prefix}${body}`;
  return {
    token,
    tokenPrefix: prefix,
    tokenLast4: token.slice(-4),
  };
}