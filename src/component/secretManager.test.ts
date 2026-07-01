/// <reference types="vite/client" />
import { convexTest } from "convex-test";
import { makeFunctionReference } from "convex/server";
import { describe, expect, it } from "vitest";
import schema from "./schema.js";

const modules = import.meta.glob("./**/*.ts");

const putPlaintext = makeFunctionReference<
  "mutation",
  {
    ownerId: string;
    namespace: string;
    name: string;
    plaintext: string;
  },
  { version: number; preview: string }
>("vault:putPlaintext");

const getResult = makeFunctionReference<
  "query",
  { ownerId: string; namespace: string; name: string },
  { ok: true; value: string } | { ok: false; reason: string }
>("vault:getResult");

const createKey = makeFunctionReference<
  "mutation",
  {
    ownerId: string;
    namespace: string;
    name: string;
    tokenHash: string;
    tokenPrefix: string;
    tokenLast4: string;
  },
  { keyId: string }
>("issuedKeys:create");

const validateKey = makeFunctionReference<
  "query",
  { tokenHash: string },
  { ok: boolean; reason?: string }
>("issuedKeys:validate");

const revokeKey = makeFunctionReference<
  "mutation",
  { keyId: string; ownerId: string },
  boolean
>("issuedKeys:revoke");

describe("secret-manager component", () => {
  it("stores and reads vault secrets", async () => {
    process.env.SECRET_MANAGER_ENCRYPTION_KEY = "component-test-key-material";
    const t = convexTest(schema, modules);

    await t.mutation(putPlaintext, {
      ownerId: "agent-1",
      namespace: "providers",
      name: "venice.apiKey",
      plaintext: "venice-secret-key-1234567890",
    });

    const result = await t.query(getResult, {
      ownerId: "agent-1",
      namespace: "providers",
      name: "venice.apiKey",
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBe("venice-secret-key-1234567890");
    }
  });

  it("creates, validates, and revokes issued keys", async () => {
    const t = convexTest(schema, modules);
    const tokenHash = "abc123hash";

    const created = await t.mutation(createKey, {
      ownerId: "agent-1",
      namespace: "workflows",
      name: "callback",
      tokenHash,
      tokenPrefix: "sm_",
      tokenLast4: "cdef",
    });

    const validated = await t.query(validateKey, { tokenHash });
    expect(validated.ok).toBe(true);

    await t.mutation(revokeKey, {
      keyId: created.keyId as never,
      ownerId: "agent-1",
    });

    const afterRevoke = await t.query(validateKey, { tokenHash });
    expect(afterRevoke.ok).toBe(false);
  });
});