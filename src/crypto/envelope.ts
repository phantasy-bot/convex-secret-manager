import { SECRET_PREFIX } from "../shared.js";
import { activeKeyVersion, parseDefinedKeys } from "./defineKeys.js";

const ENVELOPE_PREFIX = "enc:v2";
const LEGACY_PREFIX = "enc:v1";
const MAX_SECRET_BYTES = 64 * 1024;

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

async function importMaterial(material: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material));
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export function assertSecretSize(value: string): void {
  const bytes = new TextEncoder().encode(value).byteLength;
  if (bytes > MAX_SECRET_BYTES) {
    throw new Error(`Secret exceeds ${MAX_SECRET_BYTES} bytes`);
  }
}

export function isEnvelopeSecret(value: string | undefined): boolean {
  return typeof value === "string" && value.startsWith(`${ENVELOPE_PREFIX}:`);
}

export function isLegacySecret(value: string | undefined): boolean {
  return typeof value === "string" && value.startsWith(`${LEGACY_PREFIX}:`);
}

export function resolveEncryptionMaterial(
  keysSerialized: string | undefined,
  fallbackKey: string | undefined,
): { mode: "envelope"; version: number; material: string } | { mode: "legacy"; material: string } {
  const keys = parseDefinedKeys(keysSerialized);
  if (keys.size > 0) {
    const version = activeKeyVersion(keys);
    const material = keys.get(version);
    if (!material) {
      throw new Error("SECRET_MANAGER_KEYS is misconfigured");
    }
    return { mode: "envelope", version, material };
  }
  const material =
    fallbackKey?.trim() ||
    process.env.SECRET_MANAGER_ENCRYPTION_KEY?.trim() ||
    process.env.PHANTASY_SECRET_ENCRYPTION_KEY?.trim() ||
    "";
  if (!material) {
    throw new Error("SECRET_MANAGER_KEYS or SECRET_MANAGER_ENCRYPTION_KEY must be configured");
  }
  return { mode: "legacy", material };
}

/**
 * Convex mutations forbid crypto.getRandomValues / Math.random.
 * AES-GCM only requires IV uniqueness per key — derive from aad + wall clock + length.
 */
async function mutationSafeIv(seed: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(seed),
  );
  return new Uint8Array(digest).slice(0, 12);
}

export async function encryptSecret(
  plaintext: string,
  aad: string,
  keysSerialized?: string,
  fallbackKey?: string,
): Promise<{ ciphertext: string; keyVersion?: number }> {
  assertSecretSize(plaintext);
  const resolved = resolveEncryptionMaterial(keysSerialized, fallbackKey);

  if (resolved.mode === "legacy") {
    const key = await importMaterial(resolved.material);
    let iv: Uint8Array;
    try {
      iv = crypto.getRandomValues(new Uint8Array(12));
    } catch {
      // Mutations / self-hosted isolates: no CSPRNG — unique-enough IV via SHA-256
      iv = await mutationSafeIv(`${aad}\0${Date.now()}\0${plaintext.length}\0${plaintext.slice(0, 64)}`);
    }
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(plaintext),
    );
    return {
      ciphertext: `${LEGACY_PREFIX}:${toBase64(iv)}:${toBase64(new Uint8Array(encrypted))}`,
    };
  }

  const kek = await importMaterial(resolved.material);
  const dek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
  const dekRaw = new Uint8Array(await crypto.subtle.exportKey("raw", dek));
  const dataIv = crypto.getRandomValues(new Uint8Array(12));
  const dekIv = crypto.getRandomValues(new Uint8Array(12));
  const aadBytes = new TextEncoder().encode(aad);

  const encryptedPayload = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: dataIv, additionalData: aadBytes },
    dek,
    new TextEncoder().encode(plaintext),
  );
  const encryptedDek = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: dekIv, additionalData: aadBytes },
    kek,
    dekRaw,
  );

  return {
    keyVersion: resolved.version,
    ciphertext: [
      ENVELOPE_PREFIX,
      String(resolved.version),
      toBase64(dekIv),
      toBase64(new Uint8Array(encryptedDek)),
      toBase64(dataIv),
      toBase64(new Uint8Array(encryptedPayload)),
    ].join(":"),
  };
}

export async function decryptSecret(
  ciphertext: string,
  aad: string,
  keysSerialized?: string,
  fallbackKey?: string,
): Promise<string> {
  if (!ciphertext) {
    return "";
  }

  if (isLegacySecret(ciphertext)) {
    const resolved = resolveEncryptionMaterial(keysSerialized, fallbackKey);
    const material = resolved.mode === "legacy" ? resolved.material : resolved.material;
    const rest = ciphertext.slice(`${LEGACY_PREFIX}:`.length);
    const separator = rest.indexOf(":");
    const iv = fromBase64(rest.slice(0, separator));
    const payload = fromBase64(rest.slice(separator + 1));
    const key = await importMaterial(material);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, payload);
    return new TextDecoder().decode(decrypted);
  }

  if (!isEnvelopeSecret(ciphertext)) {
    return ciphertext;
  }

  const parts = ciphertext.split(":");
  if (parts.length !== 7) {
    throw new Error("decryption_failed");
  }

  const version = Number(parts[2]);
  const dekIv = fromBase64(parts[3]);
  const encryptedDek = fromBase64(parts[4]);
  const dataIv = fromBase64(parts[5]);
  const encryptedPayload = fromBase64(parts[6]);
  const keys = parseDefinedKeys(keysSerialized);
  const material = keys.get(version);
  if (!material) {
    throw new Error("key_unavailable");
  }

  const kek = await importMaterial(material);
  const aadBytes = new TextEncoder().encode(aad);
  const dekRaw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: dekIv, additionalData: aadBytes },
    kek,
    encryptedDek,
  );
  const dek = await crypto.subtle.importKey("raw", dekRaw, "AES-GCM", false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: dataIv, additionalData: aadBytes },
    dek,
    encryptedPayload,
  );
  return new TextDecoder().decode(decrypted);
}

export function buildAad(ownerId: string, namespace: string, name: string): string {
  return `${ownerId}/${namespace}/${name}`;
}

export { LEGACY_PREFIX as SECRET_PREFIX };