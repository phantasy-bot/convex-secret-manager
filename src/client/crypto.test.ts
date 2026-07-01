import { describe, expect, it } from "vitest";
import {
  buildSecretPreview,
  decryptSecretValue,
  encryptSecretValue,
  hashToken,
  isEncryptedSecret,
} from "./crypto.js";

describe("secret-manager crypto", () => {
  const key = "test-encryption-key";

  it("encrypts and decrypts round-trip", async () => {
    const encrypted = await encryptSecretValue("super-secret-value", key);
    expect(isEncryptedSecret(encrypted)).toBe(true);
    const decrypted = await decryptSecretValue(encrypted, key);
    expect(decrypted).toBe("super-secret-value");
  });

  it("builds previews without leaking full secret", () => {
    expect(buildSecretPreview("sk_live_1234567890abcdef")).toMatch(/\.\.\./);
  });

  it("hashes tokens deterministically", async () => {
    const one = await hashToken("sm_abc");
    const two = await hashToken("sm_abc");
    expect(one).toBe(two);
  });
});