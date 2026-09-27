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
  useComponentEncryption?: boolean;
};

type VaultStoreArgs = {
  ownerId: string;
  namespace: string;
  name: string;
  plaintext: string;
  actorId?: string;
  metadata?: unknown;
  ttlMs?: number | null;
};

type VaultPathArgs = {
  ownerId: string;
  namespace: string;
  name: string;
};

type PaginationOpts = { numItems: number; cursor: string | null };

type IssuedCreateArgs = {
  ownerId: string;
  namespace: string;
  name: string;
  actorId?: string;
  permissions?: Record<string, string[]>;
  metadata?: unknown;
  expiresAt?: number;
  maxIdleMs?: number;
  ttlMs?: number;
  idleTimeoutMs?: number;
  prefix?: string;
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
      "";
    if (!key && !process.env.SECRET_MANAGER_KEYS?.trim()) {
      throw new Error(
        "SECRET_MANAGER_KEYS or SECRET_MANAGER_ENCRYPTION_KEY must be configured",
      );
    }
    return key;
  }

  vault = {
    store: async (ctx: RunMutationCtx, args: VaultStoreArgs) => {
      if (this.options.useComponentEncryption !== false) {
        return ctx.runMutation(this.component.vault.putPlaintext, {
          ownerId: args.ownerId,
          namespace: args.namespace,
          name: args.name,
          plaintext: args.plaintext,
          ttlMs: args.ttlMs,
          actorId: args.actorId,
          metadata: args.metadata,
        });
      }

      const encryptionKey = this.resolveEncryptionKey();
      const ciphertext = await encryptSecretValue(args.plaintext, encryptionKey, {
        ownerId: args.ownerId,
        namespace: args.namespace,
        name: args.name,
      });
      const preview = buildSecretPreview(args.plaintext);
      return ctx.runMutation(this.component.vault.store, {
        ownerId: args.ownerId,
        namespace: args.namespace,
        name: args.name,
        ciphertext,
        preview,
        actorId: args.actorId,
        metadata: args.metadata,
        expiresAt: args.ttlMs ? Date.now() + args.ttlMs : undefined,
      });
    },

    get: async (ctx: RunQueryCtx, args: VaultPathArgs) =>
      ctx.runQuery(this.component.vault.getResult, args),

    getPlaintext: async (
      ctx: RunQueryCtx | RunActionCtx | RunMutationCtx,
      args: VaultPathArgs,
    ): Promise<string | null> => {
      const runQuery = "runQuery" in ctx ? ctx.runQuery.bind(ctx) : null;
      if (!runQuery) {
        throw new Error("getPlaintext requires a context with runQuery");
      }

      // App-side decrypt: component isolates on self-hosted Convex do not receive
      // deployment env (SECRET_MANAGER_*), so getResult cannot decrypt there.
      if (this.options.useComponentEncryption === false) {
        const record = (await runQuery(this.component.vault.get, args)) as
          | {
              ciphertext: string;
              expiresAt?: number;
            }
          | null;
        if (!record) {
          return null;
        }
        if (record.expiresAt && record.expiresAt <= Date.now()) {
          return null;
        }
        const encryptionKey = this.resolveEncryptionKey();
        return decryptSecretValue(record.ciphertext, encryptionKey, {
          ownerId: args.ownerId,
          namespace: args.namespace,
          name: args.name,
        });
      }

      const result = (await runQuery(this.component.vault.getResult, args)) as
        | { ok: true; value: string }
        | { ok: false; reason: string }
        | null;
      if (!result || !result.ok) {
        return null;
      }
      return result.value;
    },

    update: async (
      ctx: RunMutationCtx,
      args: VaultPathArgs & {
        metadata?: unknown | null;
        ttlMs?: number | null;
        actorId?: string;
      },
    ) =>
      ctx.runMutation(this.component.vault.update, {
        ownerId: args.ownerId,
        namespace: args.namespace,
        name: args.name,
        metadata: args.metadata,
        ttlMs: args.ttlMs,
        actorId: args.actorId,
      }),

    list: async (
      ctx: RunQueryCtx,
      args: { ownerId: string; namespace?: string; paginationOpts: PaginationOpts },
    ) => ctx.runQuery(this.component.vault.list, args),

    listEvents: async (
      ctx: RunQueryCtx,
      args: {
        ownerId: string;
        namespace?: string;
        targetName?: string;
        action?: string;
        paginationOpts: PaginationOpts;
        order?: "asc" | "desc";
      },
    ) => ctx.runQuery(this.component.auditEvents.listEvents, args),

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
      const prefix = args.prefix ?? this.options.issuedTokenPrefix ?? "sm_";
      const { token, tokenPrefix, tokenLast4 } = generateIssuedToken(prefix);
      const tokenHash = await hashToken(token);
      const expiresAt =
        args.expiresAt ??
        (args.ttlMs ? Date.now() + args.ttlMs : undefined);
      const maxIdleMs = args.maxIdleMs ?? args.idleTimeoutMs;
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
        expiresAt,
        maxIdleMs,
      });
      return { ...result, token, tokenPrefix, tokenLast4, expiresAt };
    },

    validate: async (ctx: RunQueryCtx, token: string) => {
      const tokenHash = await hashToken(token);
      return ctx.runQuery(this.component.issuedKeys.validate, { tokenHash });
    },

    getKey: async (
      ctx: RunQueryCtx,
      args: { keyId: string; ownerId: string },
    ) => ctx.runQuery(this.component.issuedKeys.getKey, args),

    update: async (
      ctx: RunMutationCtx,
      args: {
        keyId: string;
        ownerId: string;
        name?: string;
        metadata?: unknown | null;
        expiresAt?: number | null;
        maxIdleMs?: number | null;
        actorId?: string;
      },
    ) => ctx.runMutation(this.component.issuedKeys.update, args),

    refresh: async (
      ctx: RunMutationCtx,
      args: {
        keyId: string;
        ownerId: string;
        actorId?: string;
        graceMs?: number;
        prefix?: string;
      },
    ) => {
      const prefix = args.prefix ?? this.options.issuedTokenPrefix ?? "sm_";
      const { token, tokenPrefix, tokenLast4 } = generateIssuedToken(prefix);
      const tokenHash = await hashToken(token);
      const result = await ctx.runMutation(this.component.issuedKeys.refresh, {
        keyId: args.keyId as never,
        ownerId: args.ownerId,
        tokenHash,
        tokenPrefix,
        tokenLast4,
        actorId: args.actorId,
        graceMs: args.graceMs,
        prefix,
      });
      return {
        ...(result as Record<string, unknown>),
        token,
        tokenPrefix,
        tokenLast4,
      };
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
      args: { ownerId: string; namespace: string; before?: number; actorId?: string },
    ) => ctx.runMutation(this.component.issuedKeys.revokeAll, args),

    list: async (
      ctx: RunQueryCtx,
      args: {
        ownerId: string;
        namespace?: string;
        effectiveStatus?: string;
        paginationOpts: PaginationOpts;
        order?: "asc" | "desc";
      },
    ) => ctx.runQuery(this.component.issuedKeys.list, args),
  };
}

export type { ComponentApi, FunctionReference };