import { v } from "convex/values";
import { internalMutation } from "./_generated/server.js";
import { internal } from "./_generated/api.js";

const BATCH_SIZE = 100;
const DEFAULT_KEY_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_EVENT_RETENTION_MS = 180 * 24 * 60 * 60 * 1000;

export const cleanupKeys = internalMutation({
  args: {
    retentionMs: v.optional(v.number()),
    cursor: v.optional(v.string()),
  },
  returns: v.object({ deleted: v.number(), isDone: v.boolean() }),
  handler: async (ctx, args) => {
    const cutoff = Date.now() - (args.retentionMs ?? DEFAULT_KEY_RETENTION_MS);
    const result = await ctx.db
      .query("issuedKeys")
      .withIndex("by_status", (q) => q.eq("status", "revoked"))
      .paginate({ numItems: BATCH_SIZE, cursor: args.cursor ?? null });

    let deleted = 0;
    for (const key of result.page) {
      if ((key.revokedAt ?? key.updatedAt) > cutoff) {
        continue;
      }
      await ctx.db.delete(key._id);
      deleted += 1;
    }

    if (!result.isDone) {
      await ctx.scheduler.runAfter(0, (internal as any).issuedCleanup.cleanupKeys, {
        retentionMs: args.retentionMs,
        cursor: result.continueCursor,
      });
    }

    return { deleted, isDone: result.isDone };
  },
});

export const cleanupEvents = internalMutation({
  args: {
    retentionMs: v.optional(v.number()),
    cursor: v.optional(v.string()),
  },
  returns: v.object({ deleted: v.number(), isDone: v.boolean() }),
  handler: async (ctx, args) => {
    const cutoff = Date.now() - (args.retentionMs ?? DEFAULT_EVENT_RETENTION_MS);
    const result = await ctx.db.query("auditEvents").paginate({
      numItems: BATCH_SIZE,
      cursor: args.cursor ?? null,
    });

    let deleted = 0;
    for (const event of result.page) {
      if (event.createdAt > cutoff) {
        continue;
      }
      await ctx.db.delete(event._id);
      deleted += 1;
    }

    if (!result.isDone) {
      await ctx.scheduler.runAfter(0, (internal as any).issuedCleanup.cleanupEvents, {
        retentionMs: args.retentionMs,
        cursor: result.continueCursor,
      });
    }

    return { deleted, isDone: result.isDone };
  },
});