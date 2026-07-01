import type {
  FunctionReference,
  GenericActionCtx,
  GenericMutationCtx,
  GenericQueryCtx,
} from "convex/server";
import type { ComponentApi } from "../component/_generated/component.js";
import {
  buildSecretPreview,
  decryptSecretValue,
  encryptSecretValue,
  generateIssuedToken,
  hashToken,
} from "./crypto.js";

type RunMutationCtx = Pick<GenericMutationCtx<Record<string, never>>, "runMutation">;
type RunQueryCtx = Pick<GenericQueryCtx<Record<string, never>>, "runQuery">;
type RunActionCtx = Pick<
  GenericActionCtx<Record<string, never>>,
  "runQuery" | "runMutation"
>;

export type SecretManagerOptions = {
  encryptionKey?: string;
  issuedTokenPrefix?: string;
};

type VaultStoreArgs = {
  ownerId: string;
  namespace: string;
  name: string;
  plaintext: string;
  actorId?: string;
  metadata?: unknown;
};

type VaultPathArgs = {
  ownerId: string;
  namespace: string;
  name: string;
};

type IssuedCreateArgs = {
  ownerId: string;
  namespace: string;
  name: string;
  actorId?: string;
  permissions?: Record<string, string[]>;
  metadata?: unknown;
  expiresAt?: number;
  maxIdleMs?: number;
};

export class SecretManager {
  constructor(
    public component: ComponentApi,
    private options: SecretManagerOptions = {},
  ) {}

  private resolveEncryptionKey(): string {
    const key =
      this.options.encryptionKey?.trim() ||
      process.env.SECRET_MANAGER_ENCRYPTION_KEY?.trim() ||
      process.env.PHANTASY_SECRET_ENCRYPTION_KEY?.trim() ||
      "";
    if (!key) {
      throw new Error(
        "SECRET_MANAGER_ENCRYPTION_KEY or PHANTASY_SECRET_ENCRYPTION_KEY must be configured",
      );
    }
    return key;
  }

  vault = {
    store: async (ctx: RunMutationCtx, args: VaultStoreArgs) => {
      const ciphertext = await encryptSecretValue(args.plaintext, this.resolveEncryptionKey());
      const preview = buildSecretPreview(args.plaintext);
      return ctx.runMutation(this.component.vault.store, {
        ownerId: args.ownerId,
        namespace: args.namespace,
        name: args.name,
        ciphertext,
        preview,
        actorId: args.actorId,
        metadata: args.metadata,
      });
    },

    getPlaintext: async (
      ctx: RunQueryCtx | RunActionCtx | RunMutationCtx,
      args: VaultPathArgs,
    ): Promise<string | null> => {
      const runQuery = "runQuery" in ctx ? ctx.runQuery.bind(ctx) : null;
      if (!runQuery) {
        throw new Error("getPlaintext requires a context with runQuery");
      }
      const record = (await runQuery(this.component.vault.get, args)) as {
        ciphertext: string;
      } | null;
      if (!record) {
        return null;
      }
      return decryptSecretValue(record.ciphertext, this.resolveEncryptionKey());
    },

    list: async (
      ctx: RunQueryCtx,
      args: { ownerId: string; namespace?: string },
    ) => ctx.runQuery(this.component.vault.list, args),

    delete: async (
      ctx: RunMutationCtx,
      args: VaultPathArgs & { actorId?: string },
    ) => ctx.runMutation(this.component.vault.remove, args),

    deleteNamespace: async (
      ctx: RunMutationCtx,
      args: { ownerId: string; namespace: string; actorId?: string },
    ) => ctx.runMutation(this.component.vault.removeNamespace, args),
  };

  issued = {
    create: async (ctx: RunMutationCtx, args: IssuedCreateArgs) => {
      const prefix = this.options.issuedTokenPrefix ?? "sm_";
      const { token, tokenPrefix, tokenLast4 } = generateIssuedToken(prefix);
      const tokenHash = await hashToken(token);
      const result = await ctx.runMutation(this.component.issuedKeys.create, {
        ownerId: args.ownerId,
        namespace: args.namespace,
        name: args.name,
        tokenHash,
        tokenPrefix,
        tokenLast4,
        actorId: args.actorId,
        permissions: args.permissions,
        metadata: args.metadata,
        expiresAt: args.expiresAt,
        maxIdleMs: args.maxIdleMs,
      });
      return { ...result, token, tokenPrefix, tokenLast4 };
    },

    validate: async (ctx: RunMutationCtx, token: string) => {
      const tokenHash = await hashToken(token);
      return ctx.runMutation(this.component.issuedKeys.validate, { tokenHash });
    },

    touch: async (
      ctx: RunMutationCtx,
      args: { keyId: string; ownerId: string; actorId?: string },
    ) =>
      ctx.runMutation(this.component.issuedKeys.touch, {
        keyId: args.keyId as never,
        ownerId: args.ownerId,
        actorId: args.actorId,
      }),

    revoke: async (
      ctx: RunMutationCtx,
      args: { keyId: string; ownerId: string; actorId?: string },
    ) =>
      ctx.runMutation(this.component.issuedKeys.revoke, {
        keyId: args.keyId as never,
        ownerId: args.ownerId,
        actorId: args.actorId,
      }),

    revokeAll: async (
      ctx: RunMutationCtx,
      args: { ownerId: string; namespace: string; actorId?: string },
    ) => ctx.runMutation(this.component.issuedKeys.revokeAll, args),

    list: async (
      ctx: RunQueryCtx,
      args: { ownerId: string; namespace?: string },
    ) => ctx.runQuery(this.component.issuedKeys.list, args),
  };
}

export type { ComponentApi, FunctionReference };