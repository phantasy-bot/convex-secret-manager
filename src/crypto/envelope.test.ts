import { describe, expect, it, vi } from "vitest";
import { defineKeys } from "./defineKeys.js";
import { buildAad, decryptSecret, encryptSecret, isEnvelopeSecret } from "./envelope.js";

describe("envelope crypto", () => {
  it("encrypts with envelope format when keys are configured", async () => {
    const keys = defineKeys({ 1: "test-kek-material-32chars-minimum!!" });
    const encrypted = await encryptSecret(
      "provider-api-key-value",
      buildAad("org-1", "providers", "openai.apiKey"),
      keys,
    );
    expect(isEnvelopeSecret(encrypted.ciphertext)).toBe(true);
    expect(encrypted.keyVersion).toBe(1);

    const decrypted = await decryptSecret(
      encrypted.ciphertext,
      buildAad("org-1", "providers", "openai.apiKey"),
      keys,
    );
    expect(decrypted).toBe("provider-api-key-value");
  });

  it("rejects tampered AAD binding", async () => {
    const keys = defineKeys({ 1: "test-kek-material-32chars-minimum!!" });
    const encrypted = await encryptSecret("secret", buildAad("a", "providers", "x"), keys);
    await expect(
      decryptSecret(encrypted.ciphertext, buildAad("b", "providers", "x"), keys),
    ).rejects.toThrow();
  });

  it("uses distinct mutation-safe IVs when Web Crypto randomness is unavailable", async () => {
    const aad = buildAad("agent-1", "providers", "venice.apiKey");
    const fallbackKey = "test-fallback-key-32chars-minimum!!";
    let randomCalls = 0;
    const cryptoRandom = vi
      .spyOn(globalThis.crypto, "getRandomValues")
      .mockImplementation(() => {
        throw new Error("crypto.getRandomValues unavailable in mutation runtime");
      });
    const random = vi
      .spyOn(Math, "random")
      .mockImplementation(() => (++randomCalls % 200) / 256);
    const now = vi.spyOn(Date, "now").mockReturnValue(1);

    try {
      const first = await encryptSecret("same secret", aad, undefined, fallbackKey);
      const second = await encryptSecret("same secret", aad, undefined, fallbackKey);

      expect(first.ciphertext.split(":")[2]).not.toBe(second.ciphertext.split(":")[2]);
      await expect(decryptSecret(first.ciphertext, aad, undefined, fallbackKey)).resolves.toBe(
        "same secret",
      );
    } finally {
      cryptoRandom.mockRestore();
      random.mockRestore();
      now.mockRestore();
    }
  });
});
