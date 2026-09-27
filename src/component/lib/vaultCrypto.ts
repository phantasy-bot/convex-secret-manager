import {
  buildAad,
  decryptSecret,
  encryptSecret,
} from "../../crypto/envelope.js";

export function resolveKeysSerialized(): string | undefined {
  return process.env.SECRET_MANAGER_KEYS?.trim();
}

export function resolveFallbackKey(): string | undefined {
  return process.env.SECRET_MANAGER_ENCRYPTION_KEY?.trim();
}

export function resolveExpiresAt(ttlMs: number | null | undefined, now: number): number | undefined {
  if (ttlMs === null || ttlMs === undefined) {
    return undefined;
  }
  if (!Number.isInteger(ttlMs) || ttlMs <= 0) {
    throw new Error("ttlMs must be a positive integer");
  }
  return now + ttlMs;
}

export async function encryptVaultValue(
  ownerId: string,
  namespace: string,
  name: string,
  plaintext: string,
): Promise<{ ciphertext: string; keyVersion?: number }> {
  return encryptSecret(
    plaintext,
    buildAad(ownerId, namespace, name),
    resolveKeysSerialized(),
    resolveFallbackKey(),
  );
}

export async function decryptVaultValue(
  ownerId: string,
  namespace: string,
  name: string,
  ciphertext: string,
): Promise<string> {
  return decryptSecret(
    ciphertext,
    buildAad(ownerId, namespace, name),
    resolveKeysSerialized(),
    resolveFallbackKey(),
  );
}

export function buildPreview(value: string): string {
  if (value.length <= 12) {
    return `${value.slice(0, 4)}...`;
  }
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}