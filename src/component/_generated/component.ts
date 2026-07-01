/* eslint-disable */
import type { FunctionReference } from "convex/server";

export type ComponentApi<Name extends string | undefined = string | undefined> = {
  vault: {
    store: FunctionReference<"mutation", "public", Record<string, unknown>, { version: number; preview: string }>;
    putPlaintext: FunctionReference<
      "mutation",
      "public",
      Record<string, unknown>,
      { version: number; preview: string; isNew: boolean; expiresAt?: number }
    >;
    update: FunctionReference<"mutation", "public", Record<string, unknown>, unknown>;
    get: FunctionReference<"query", "internal", Record<string, unknown>, unknown>;
    getResult: FunctionReference<"query", "public", Record<string, unknown>, unknown>;
    list: FunctionReference<"query", "public", Record<string, unknown>, unknown>;
    remove: FunctionReference<"mutation", "public", Record<string, unknown>, boolean>;
    removeNamespace: FunctionReference<"mutation", "public", Record<string, unknown>, number>;
  };
  issuedKeys: {
    create: FunctionReference<"mutation", "public", Record<string, unknown>, { keyId: string }>;
    validate: FunctionReference<"query", "public", Record<string, unknown>, unknown>;
    getKey: FunctionReference<"query", "public", Record<string, unknown>, unknown>;
    update: FunctionReference<"mutation", "public", Record<string, unknown>, unknown>;
    refresh: FunctionReference<"mutation", "public", Record<string, unknown>, unknown>;
    touch: FunctionReference<"mutation", "public", Record<string, unknown>, boolean>;
    revoke: FunctionReference<"mutation", "public", Record<string, unknown>, boolean>;
    revokeAll: FunctionReference<"mutation", "public", Record<string, unknown>, number>;
    list: FunctionReference<"query", "public", Record<string, unknown>, unknown>;
  };
  auditEvents: {
    listEvents: FunctionReference<"query", "public", Record<string, unknown>, unknown>;
  };
  vaultRotate: {
    rotate: FunctionReference<"mutation", "internal", Record<string, unknown>, unknown>;
    isRotationComplete: FunctionReference<"query", "internal", Record<string, unknown>, boolean>;
  };
  issuedSweep: {
    sweepExpired: FunctionReference<"mutation", "internal", Record<string, unknown>, unknown>;
    sweepIdleExpired: FunctionReference<"mutation", "internal", Record<string, unknown>, unknown>;
  };
  issuedCleanup: {
    cleanupKeys: FunctionReference<"mutation", "internal", Record<string, unknown>, unknown>;
    cleanupEvents: FunctionReference<"mutation", "internal", Record<string, unknown>, unknown>;
  };
  vaultCleanup: {
    cleanupSecrets: FunctionReference<"mutation", "internal", Record<string, unknown>, unknown>;
  };
};