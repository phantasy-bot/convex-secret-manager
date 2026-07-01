import { SECRET_PREFIX } from "../shared.js";

export function resolveEncryptionMaterial(
  encryptionKey: string | undefined,
): string {
  const material = encryptionKey?.trim() || "";
  if (!material) {
    throw new Error(
      "SECRET_MANAGER_ENCRYPTION_KEY (or PHANTASY_SECRET_ENCRYPTION_KEY) must be set",
    );
  }
  return material;
}

async function deriveKey(encryptionKey: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(resolveEncryptionMaterial(encryptionKey)),
  );
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function isEncryptedSecret(value: string | undefined): boolean {
  return typeof value === "string" && value.startsWith(`${SECRET_PREFIX}:`);
}

export async function encryptSecretValue(
  value: string,
  encryptionKey: string,
): Promise<string> {
  if (!value || isEncryptedSecret(value)) {
    return value;
  }
  const key = await deriveKey(encryptionKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(value),
  );
  return `${SECRET_PREFIX}:${toBase64(iv)}:${toBase64(new Uint8Array(encrypted))}`;
}

function parseEncryptedPayload(value: string): {
  ivBase64: string;
  cipherBase64: string;
} | null {
  const prefix = `${SECRET_PREFIX}:`;
  if (!value.startsWith(prefix)) {
    return null;
  }
  const rest = value.slice(prefix.length);
  const separator = rest.indexOf(":");
  if (separator <= 0) {
    return null;
  }
  return {
    ivBase64: rest.slice(0, separator),
    cipherBase64: rest.slice(separator + 1),
  };
}

export async function decryptSecretValue(
  value: string,
  encryptionKey: string,
): Promise<string> {
  if (!value) {
    return "";
  }
  if (!isEncryptedSecret(value)) {
    return value;
  }
  const parsed = parseEncryptedPayload(value);
  if (!parsed) {
    return value;
  }
  const { ivBase64, cipherBase64 } = parsed;
  const key = await deriveKey(encryptionKey);
  const iv = fromBase64(ivBase64);
  const ciphertext = fromBase64(cipherBase64);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
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