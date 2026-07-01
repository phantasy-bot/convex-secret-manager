import { v } from "convex/values";
import { mutation, query } from "./_generated/server.js";
import { writeAuditEvent } from "./audit.js";
import {
  issuedCreateArgs,
  issuedKeyIdArgs,
  issuedValidateArgs,
} from "../shared.js";

function isExpired(expiresAt: number | undefined, now: number): boolean {
  return typeof expiresAt === "number" && expiresAt <= now;
}

function isIdle(
  lastUsedAt: number | undefined,
  maxIdleMs: number | undefined,
  now: number,
): boolean {
  if (!maxIdleMs || !lastUsedAt) {
    return false;
  }
  return lastUsedAt + maxIdleMs <= now;
}

export const create = mutation({
  args: issuedCreateArgs,
  returns: v.object({ keyId: v.id("issuedKeys") }),
  handler: async (ctx, args) => {
    const now = Date.now();
    const keyId = await ctx.db.insert("issuedKeys", {
      ownerId: args.ownerId,
      namespace: args.namespace,
      name: args.name,
      tokenHash: args.tokenHash,
      tokenPrefix: args.tokenPrefix,
      tokenLast4: args.tokenLast4,
      status: "active",
      permissions: args.permissions,
      metadata: args.metadata,
      expiresAt: args.expiresAt,
      maxIdleMs: args.maxIdleMs,
      createdAt: now,
      updatedAt: now,
    });

    await writeAuditEvent(ctx, {
      ownerId: args.ownerId,
      namespace: args.namespace,
      action: "issued.create",
      targetName: args.name,
      actorId: args.actorId,
      metadata: { keyId },
    });

    return { keyId };
  },
});

export const validate = mutation({
  args: issuedValidateArgs,
  returns: v.union(
    v.object({
      ok: v.literal(true),
      keyId: v.id("issuedKeys"),
      ownerId: v.string(),
      namespace: v.string(),
      name: v.string(),
      permissions: v.optional(v.record(v.string(), v.array(v.string()))),
      metadata: v.optional(v.any()),
    }),
    v.object({
      ok: v.literal(false),
      reason: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    const now = Date.now();
    const record = await ctx.db
      .query("issuedKeys")
      .withIndex("by_hash", (q) => q.eq("tokenHash", args.tokenHash))
      .unique();

    if (!record) {
      return { ok: false as const, reason: "not_found" };
    }
    if (record.status === "revoked") {
      return { ok: false as const, reason: "revoked" };
    }
    if (record.status === "disabled") {
      return { ok: false as const, reason: "disabled" };
    }
    if (
      record.graceExpiresAt &&
      record.graceExpiresAt > now &&
      record.replacedKeyId
    ) {
      // Grace period for rotated keys handled by separate active record.
    }
    if (isExpired(record.expiresAt, now)) {
      return { ok: false as const, reason: "expired" };
    }
    if (isIdle(record.lastUsedAt, record.maxIdleMs, now)) {
      return { ok: false as const, reason: "idle_timeout" };
    }

    return {
      ok: true as const,
      keyId: record._id,
      ownerId: record.ownerId,
      namespace: record.namespace,
      name: record.name,
      permissions: record.permissions,
      metadata: record.metadata,
    };
  },
});

export const touch = mutation({
  args: issuedKeyIdArgs,
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const record = await ctx.db.get(args.keyId);
    if (!record || record.ownerId !== args.ownerId) {
      return false;
    }
    await ctx.db.patch(record._id, {
      lastUsedAt: Date.now(),
      updatedAt: Date.now(),
    });
    return true;
  },
});

export const revoke = mutation({
  args: issuedKeyIdArgs,
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const record = await ctx.db.get(args.keyId);
    if (!record || record.ownerId !== args.ownerId) {
      return false;
    }
    await ctx.db.patch(record._id, {
      status: "revoked",
      updatedAt: Date.now(),
    });
    await writeAuditEvent(ctx, {
      ownerId: record.ownerId,
      namespace: record.namespace,
      action: "issued.revoke",
      targetName: record.name,
      actorId: args.actorId,
      metadata: { keyId: record._id },
    });
    return true;
  },
});

export const revokeAll = mutation({
  args: {
    ownerId: v.string(),
    namespace: v.string(),
    actorId: v.optional(v.string()),
  },
  returns: v.number(),
  handler: async (ctx, args) => {
    const records = await ctx.db
      .query("issuedKeys")
      .withIndex("by_owner_status", (q) =>
        q.eq("ownerId", args.ownerId).eq("namespace", args.namespace).eq("status", "active"),
      )
      .collect();

    for (const record of records) {
      await ctx.db.patch(record._id, { status: "revoked", updatedAt: Date.now() });
    }

    if (records.length > 0) {
      await writeAuditEvent(ctx, {
        ownerId: args.ownerId,
        namespace: args.namespace,
        action: "issued.revokeAll",
        targetName: "*",
        actorId: args.actorId,
        metadata: { count: records.length },
      });
    }

    return records.length;
  },
});

export const list = query({
  args: {
    ownerId: v.string(),
    namespace: v.optional(v.string()),
  },
  returns: v.array(
    v.object({
      keyId: v.id("issuedKeys"),
      namespace: v.string(),
      name: v.string(),
      tokenPrefix: v.string(),
      tokenLast4: v.string(),
      status: v.union(
        v.literal("active"),
        v.literal("revoked"),
        v.literal("disabled"),
      ),
      permissions: v.optional(v.record(v.string(), v.array(v.string()))),
      metadata: v.optional(v.any()),
      expiresAt: v.optional(v.number()),
      lastUsedAt: v.optional(v.number()),
      createdAt: v.number(),
      updatedAt: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const records = args.namespace
      ? await ctx.db
          .query("issuedKeys")
          .withIndex("by_owner", (q) =>
            q.eq("ownerId", args.ownerId).eq("namespace", args.namespace!),
          )
          .collect()
      : await ctx.db
          .query("issuedKeys")
          .withIndex("by_owner", (q) => q.eq("ownerId", args.ownerId))
          .collect();

    return records.map((record) => ({
      keyId: record._id,
      namespace: record.namespace,
      name: record.name,
      tokenPrefix: record.tokenPrefix,
      tokenLast4: record.tokenLast4,
      status: record.status,
      permissions: record.permissions,
      metadata: record.metadata,
      expiresAt: record.expiresAt,
      lastUsedAt: record.lastUsedAt,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    }));
  },
});