import { describe, expect, it } from "vitest";
import { defineKeys } from "./defineKeys.js";
import { buildAad, decryptSecret, encryptSecret, isEnvelopeSecret } from "./envelope.js";

describe("envelope crypto", () => {
  it("encrypts with envelope format when keys are configured", async () => {
    const keys = defineKeys({ 1: "test-kek-material-32chars-minimum!!" });
    const encrypted = await encryptSecret(
      "provider-api-key-value",
      buildAad("agent-1", "providers", "venice.apiKey"),
      keys,
    );
    expect(isEnvelopeSecret(encrypted.ciphertext)).toBe(true);
    expect(encrypted.keyVersion).toBe(1);

    const decrypted = await decryptSecret(
      encrypted.ciphertext,
      buildAad("agent-1", "providers", "venice.apiKey"),
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
});