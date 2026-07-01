import { v } from "convex/values";
import { internalQuery, mutation, query } from "./_generated/server.js";
import { writeAuditEvent } from "./audit.js";
import {
  vaultNamespaceArgs,
  vaultPathArgs,
  vaultStoreArgs,
} from "../shared.js";

export const store = mutation({
  args: vaultStoreArgs,
  returns: v.object({
    version: v.number(),
    preview: v.string(),
  }),
  handler: async (ctx, args) => {
    const now = Date.now();
    const existing = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) =>
        q
          .eq("ownerId", args.ownerId)
          .eq("namespace", args.namespace)
          .eq("name", args.name),
      )
      .unique();

    const nextVersion = (existing?.version ?? 0) + 1;

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
      await ctx.db.patch(existing._id, {
        ciphertext: args.ciphertext,
        preview: args.preview,
        version: nextVersion,
        metadata: args.metadata,
        updatedAt: now,
      });
    } else {
      await ctx.db.insert("vaultSecrets", {
        ownerId: args.ownerId,
        namespace: args.namespace,
        name: args.name,
        ciphertext: args.ciphertext,
        preview: args.preview,
        version: nextVersion,
        metadata: args.metadata,
        createdAt: now,
        updatedAt: now,
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

export const get = internalQuery({
  args: vaultPathArgs,
  returns: v.union(
    v.object({
      ownerId: v.string(),
      namespace: v.string(),
      name: v.string(),
      ciphertext: v.string(),
      preview: v.string(),
      version: v.number(),
      metadata: v.optional(v.any()),
      updatedAt: v.number(),
      createdAt: v.number(),
    }),
    v.null(),
  ),
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) =>
        q
          .eq("ownerId", args.ownerId)
          .eq("namespace", args.namespace)
          .eq("name", args.name),
      )
      .unique();
    if (!record) {
      return null;
    }
    return {
      ownerId: record.ownerId,
      namespace: record.namespace,
      name: record.name,
      ciphertext: record.ciphertext,
      preview: record.preview,
      version: record.version,
      metadata: record.metadata,
      updatedAt: record.updatedAt,
      createdAt: record.createdAt,
    };
  },
});

export const list = query({
  args: {
    ownerId: v.string(),
    namespace: v.optional(v.string()),
  },
  returns: v.array(
    v.object({
      namespace: v.string(),
      name: v.string(),
      preview: v.string(),
      version: v.number(),
      metadata: v.optional(v.any()),
      updatedAt: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const records = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) => q.eq("ownerId", args.ownerId))
      .collect();

    return records
      .filter((record) => !args.namespace || record.namespace === args.namespace)
      .map((record) => ({
        namespace: record.namespace,
        name: record.name,
        preview: record.preview,
        version: record.version,
        metadata: record.metadata,
        updatedAt: record.updatedAt,
      }));
  },
});

export const remove = mutation({
  args: {
    ...vaultPathArgs,
    actorId: v.optional(v.string()),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("vaultSecrets")
      .withIndex("by_owner_namespace_name", (q) =>
        q
          .eq("ownerId", args.ownerId)
          .eq("namespace", args.namespace)
          .eq("name", args.name),
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