import { v } from "convex/values";
import { internalMutation } from "./_generated/server.js";
import { internal } from "./_generated/api.js";
import { writeAuditEvent } from "./audit.js";

const BATCH_SIZE = 100;
const DEFAULT_SECRET_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

export const cleanupSecrets = internalMutation({
  args: {
    retentionMs: v.optional(v.number()),
    cursor: v.optional(v.string()),
  },
  returns: v.object({ deleted: v.number(), isDone: v.boolean() }),
  handler: async (ctx, args) => {
    const now = Date.now();
    const result = await ctx.db.query("vaultSecrets").paginate({
      numItems: BATCH_SIZE,
      cursor: args.cursor ?? null,
    });

    let deleted = 0;
    for (const record of result.page) {
      if (!record.expiresAt || record.expiresAt > now) {
        continue;
      }
      await ctx.db.delete(record._id);
      await writeAuditEvent(ctx, {
        ownerId: record.ownerId,
        namespace: record.namespace,
        action: "vault.delete",
        targetName: record.name,
        metadata: { reason: "expired_cleanup" },
      });
      deleted += 1;
    }

    if (!result.isDone) {
      await ctx.scheduler.runAfter(0, (internal as any).vaultCleanup.cleanupSecrets, {
        retentionMs: args.retentionMs,
        cursor: result.continueCursor,
      });
    }

    return { deleted, isDone: result.isDone };
  },
});