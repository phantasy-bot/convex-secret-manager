import { v } from "convex/values";
import { mutation, query } from "./_generated/server.js";
import { writeAuditEvent } from "./audit.js";
import {
  paginationOptsArgs,
  vaultNamespaceArgs,
  vaultPathArgs,
  vaultPutPlaintextArgs,
  vaultStoreArgs,
  vaultUpdateArgs,
} from "../shared.js";
import {
  buildPreview,
  decryptVaultValue,
  encryptVaultValue,
  resolveExpiresAt,
} from "./lib/vaultCrypto.js";
import { effectiveVaultState } from "./lib/vaultState.js";

export const store = mutation({
  args: vaultStoreArgs,
  returns: v.object({ version: v.number(), preview: v.string() }),
  handler: async (ctx, args) => {
    const now = Date.now();
    const existing = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) =>
        q.eq("ownerId", args.ownerId).eq("namespace", args.namespace).eq("name", args.name),
      )
      .unique();

    const nextVersion = (existing?.version ?? 0) + 1;
    const payload = {
      ciphertext: args.ciphertext,
      preview: args.preview,
      version: nextVersion,
      keyVersion: args.keyVersion,
      metadata: args.metadata,
      expiresAt: args.expiresAt,
      updatedAt: now,
    };

    if (existing) {
      await ctx.db.insert("vaultSecretVersions", {
        ownerId: args.ownerId,
        namespace: args.namespace,
        name: args.name,
        version: existing.version,
        ciphertext: existing.ciphertext,
        preview: existing.preview,
        rotatedAt: now,
        actorId: args.actorId,
      });
      await ctx.db.patch(existing._id, payload);
    } else {
      await ctx.db.insert("vaultSecrets", {
        ownerId: args.ownerId,
        namespace: args.namespace,
        name: args.name,
        createdAt: now,
        ...payload,
      });
    }

    await writeAuditEvent(ctx, {
      ownerId: args.ownerId,
      namespace: args.namespace,
      action: existing ? "vault.update" : "vault.store",
      targetName: args.name,
      actorId: args.actorId,
      metadata: { version: nextVersion },
    });

    return { version: nextVersion, preview: args.preview };
  },
});

export const putPlaintext = mutation({
  args: vaultPutPlaintextArgs,
  returns: v.object({
    version: v.number(),
    preview: v.string(),
    isNew: v.boolean(),
    expiresAt: v.optional(v.number()),
  }),
  handler: async (ctx, args) => {
    const now = Date.now();
    const encrypted = await encryptVaultValue(
      args.ownerId,
      args.namespace,
      args.name,
      args.plaintext,
    );
    const expiresAt = resolveExpiresAt(args.ttlMs, now);
    const existing = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) =>
        q.eq("ownerId", args.ownerId).eq("namespace", args.namespace).eq("name", args.name),
      )
      .unique();

    const nextVersion = (existing?.version ?? 0) + 1;
    const payload = {
      ciphertext: encrypted.ciphertext,
      preview: buildPreview(args.plaintext),
      version: nextVersion,
      keyVersion: encrypted.keyVersion,
      metadata: args.metadata === null ? undefined : args.metadata,
      expiresAt,
      updatedAt: now,
    };

    if (existing) {
      await ctx.db.insert("vaultSecretVersions", {
        ownerId: args.ownerId,
        namespace: args.namespace,
        name: args.name,
        version: existing.version,
        ciphertext: existing.ciphertext,
        preview: existing.preview,
        rotatedAt: now,
        actorId: args.actorId,
      });
      await ctx.db.patch(existing._id, payload);
    } else {
      await ctx.db.insert("vaultSecrets", {
        ownerId: args.ownerId,
        namespace: args.namespace,
        name: args.name,
        createdAt: now,
        ...payload,
      });
    }

    await writeAuditEvent(ctx, {
      ownerId: args.ownerId,
      namespace: args.namespace,
      action: existing ? "vault.update" : "vault.store",
      targetName: args.name,
      actorId: args.actorId,
      metadata: { version: nextVersion },
    });

    return {
      version: nextVersion,
      preview: payload.preview,
      isNew: !existing,
      expiresAt,
    };
  },
});

export const update = mutation({
  args: vaultUpdateArgs,
  returns: v.object({
    updated: v.boolean(),
    updatedAt: v.optional(v.number()),
    expiresAt: v.optional(v.number()),
  }),
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) =>
        q.eq("ownerId", args.ownerId).eq("namespace", args.namespace).eq("name", args.name),
      )
      .unique();
    if (!record) {
      return { updated: false };
    }

    const now = Date.now();
    const expiresAt =
      args.ttlMs === undefined
        ? record.expiresAt
        : resolveExpiresAt(args.ttlMs, now) ?? undefined;

    await ctx.db.patch(record._id, {
      metadata: args.metadata === null ? undefined : (args.metadata ?? record.metadata),
      expiresAt,
      updatedAt: now,
    });

    await writeAuditEvent(ctx, {
      ownerId: args.ownerId,
      namespace: args.namespace,
      action: "vault.update",
      targetName: args.name,
      actorId: args.actorId,
      metadata: { metadataOnly: true },
    });

    return { updated: true, updatedAt: now, expiresAt };
  },
});

/** Public so app-side crypto (useComponentEncryption: false) can read ciphertext. */
export const get = query({
  args: vaultPathArgs,
  returns: v.union(
    v.object({
      ownerId: v.string(),
      namespace: v.string(),
      name: v.string(),
      ciphertext: v.string(),
      preview: v.string(),
      version: v.number(),
      keyVersion: v.optional(v.number()),
      metadata: v.optional(v.any()),
      expiresAt: v.optional(v.number()),
      updatedAt: v.number(),
      createdAt: v.number(),
    }),
    v.null(),
  ),
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) =>
        q.eq("ownerId", args.ownerId).eq("namespace", args.namespace).eq("name", args.name),
      )
      .unique();
    if (!record) {
      return null;
    }
    return record;
  },
});

export const getResult = query({
  args: vaultPathArgs,
  returns: v.union(
    v.object({
      ok: v.literal(true),
      value: v.string(),
      preview: v.string(),
      metadata: v.optional(v.any()),
      expiresAt: v.optional(v.number()),
      updatedAt: v.number(),
    }),
    v.object({
      ok: v.literal(false),
      reason: v.union(
        v.literal("not_found"),
        v.literal("expired"),
        v.literal("decryption_failed"),
      ),
    }),
  ),
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) =>
        q.eq("ownerId", args.ownerId).eq("namespace", args.namespace).eq("name", args.name),
      )
      .unique();
    if (!record) {
      return { ok: false as const, reason: "not_found" as const };
    }
    if (record.expiresAt && record.expiresAt <= Date.now()) {
      return { ok: false as const, reason: "expired" as const };
    }
    try {
      const value = await decryptVaultValue(
        record.ownerId,
        record.namespace,
        record.name,
        record.ciphertext,
      );
      return {
        ok: true as const,
        value,
        preview: record.preview,
        metadata: record.metadata,
        expiresAt: record.expiresAt,
        updatedAt: record.updatedAt,
      };
    } catch {
      return { ok: false as const, reason: "decryption_failed" as const };
    }
  },
});

export const list = query({
  args: {
    ownerId: v.string(),
    namespace: v.optional(v.string()),
    ...paginationOptsArgs,
  },
  returns: v.object({
    page: v.array(
      v.object({
        namespace: v.string(),
        name: v.string(),
        preview: v.string(),
        version: v.number(),
        effectiveState: v.union(v.literal("active"), v.literal("expired")),
        metadata: v.optional(v.any()),
        updatedAt: v.number(),
        expiresAt: v.optional(v.number()),
      }),
    ),
    isDone: v.boolean(),
    continueCursor: v.union(v.string(), v.null()),
  }),
  handler: async (ctx, args) => {
    const records = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) => q.eq("ownerId", args.ownerId))
      .paginate(args.paginationOpts);

    const page = records.page
      .filter((record) => !args.namespace || record.namespace === args.namespace)
      .map((record) => ({
        namespace: record.namespace,
        name: record.name,
        preview: record.preview,
        version: record.version,
        effectiveState: effectiveVaultState(record),
        metadata: record.metadata,
        updatedAt: record.updatedAt,
        expiresAt: record.expiresAt,
      }));

    return {
      page,
      isDone: records.isDone,
      continueCursor: records.continueCursor,
    };
  },
});

export const remove = mutation({
  args: { ...vaultPathArgs, actorId: v.optional(v.string()) },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) =>
        q.eq("ownerId", args.ownerId).eq("namespace", args.namespace).eq("name", args.name),
      )
      .unique();
    if (!record) {
      return false;
    }
    await ctx.db.delete(record._id);
    await writeAuditEvent(ctx, {
      ownerId: args.ownerId,
      namespace: args.namespace,
      action: "vault.delete",
      targetName: args.name,
      actorId: args.actorId,
    });
    return true;
  },
});

export const removeNamespace = mutation({
  args: vaultNamespaceArgs,
  returns: v.number(),
  handler: async (ctx, args) => {
    const records = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) =>
        q.eq("ownerId", args.ownerId).eq("namespace", args.namespace),
      )
      .collect();

    for (const record of records) {
      await ctx.db.delete(record._id);
    }

    if (records.length > 0) {
      await writeAuditEvent(ctx, {
        ownerId: args.ownerId,
        namespace: args.namespace,
        action: "vault.deleteNamespace",
        targetName: "*",
        actorId: args.actorId,
        metadata: { count: records.length },
      });
    }

    return records.length;
  },
});