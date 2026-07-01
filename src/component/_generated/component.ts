/* eslint-disable */
import type { FunctionReference } from "convex/server";

export type ComponentApi<Name extends string | undefined = string | undefined> = {
  vault: {
    store: FunctionReference<"mutation", "public", Record<string, unknown>, { version: number; preview: string }>;
    get: FunctionReference<"query", "internal", Record<string, unknown>, unknown>;
    list: FunctionReference<"query", "public", Record<string, unknown>, unknown>;
    remove: FunctionReference<"mutation", "public", Record<string, unknown>, boolean>;
    removeNamespace: FunctionReference<"mutation", "public", Record<string, unknown>, number>;
  };
  issuedKeys: {
    create: FunctionReference<"mutation", "public", Record<string, unknown>, { keyId: string }>;
    validate: FunctionReference<"mutation", "public", Record<string, unknown>, unknown>;
    touch: FunctionReference<"mutation", "public", Record<string, unknown>, boolean>;
    revoke: FunctionReference<"mutation", "public", Record<string, unknown>, boolean>;
    revokeAll: FunctionReference<"mutation", "public", Record<string, unknown>, number>;
    list: FunctionReference<"query", "public", Record<string, unknown>, unknown>;
  };
};