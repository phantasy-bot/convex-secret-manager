import { v } from "convex/values";
import { internalMutation } from "./_generated/server.js";
import { internal } from "./_generated/api.js";
import { writeAuditEvent } from "./audit.js";
import { isExpired, isIdle } from "./lib/issuedKeyState.js";

const BATCH_SIZE = 100;

export const sweepExpired = internalMutation({
  args: { cursor: v.optional(v.string()) },
  returns: v.object({ swept: v.number(), isDone: v.boolean() }),
  handler: async (ctx, args) => {
    const now = Date.now();
    const result = await ctx.db
      .query("issuedKeys")
      .withIndex("by_status", (q) => q.eq("status", "active"))
      .paginate({ numItems: BATCH_SIZE, cursor: args.cursor ?? null });

    let swept = 0;
    for (const key of result.page) {
      if (!isExpired(key.expiresAt, now)) {
        continue;
      }
      await ctx.db.patch(key._id, {
        status: "revoked",
        revokedAt: now,
        revocationReason: "expired",
        updatedAt: now,
      });
      await writeAuditEvent(ctx, {
        ownerId: key.ownerId,
        namespace: key.namespace,
        action: "issued.sweepExpired",
        targetName: key.name,
        metadata: { keyId: key._id },
      });
      swept += 1;
    }

    if (!result.isDone) {
      await ctx.scheduler.runAfter(0, (internal as any).issuedSweep.sweepExpired, {
        cursor: result.continueCursor,
      });
    }

    return { swept, isDone: result.isDone };
  },
});

export const sweepIdleExpired = internalMutation({
  args: { cursor: v.optional(v.string()) },
  returns: v.object({ swept: v.number(), isDone: v.boolean() }),
  handler: async (ctx, args) => {
    const now = Date.now();
    const result = await ctx.db
      .query("issuedKeys")
      .withIndex("by_status", (q) => q.eq("status", "active"))
      .paginate({ numItems: BATCH_SIZE, cursor: args.cursor ?? null });

    let swept = 0;
    for (const key of result.page) {
      if (!isIdle(key.lastUsedAt, key.maxIdleMs, now)) {
        continue;
      }
      await ctx.db.patch(key._id, {
        status: "revoked",
        revokedAt: now,
        revocationReason: "idle_timeout",
        updatedAt: now,
      });
      await writeAuditEvent(ctx, {
        ownerId: key.ownerId,
        namespace: key.namespace,
        action: "issued.sweepIdle",
        targetName: key.name,
        metadata: { keyId: key._id },
      });
      swept += 1;
    }

    if (!result.isDone) {
      await ctx.scheduler.runAfter(0, (internal as any).issuedSweep.sweepIdleExpired, {
        cursor: result.continueCursor,
      });
    }

    return { swept, isDone: result.isDone };
  },
});