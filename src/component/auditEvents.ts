import { v } from "convex/values";
import { query } from "./_generated/server.js";
import { paginationOptsArgs } from "../shared.js";

export const listEvents = query({
  args: {
    ownerId: v.string(),
    namespace: v.optional(v.string()),
    targetName: v.optional(v.string()),
    action: v.optional(v.string()),
    order: v.optional(v.union(v.literal("asc"), v.literal("desc"))),
    ...paginationOptsArgs,
  },
  returns: v.object({
    page: v.array(
      v.object({
        ownerId: v.string(),
        namespace: v.string(),
        action: v.string(),
        targetName: v.string(),
        actorId: v.optional(v.string()),
        metadata: v.optional(v.any()),
        createdAt: v.number(),
      }),
    ),
    isDone: v.boolean(),
    continueCursor: v.union(v.string(), v.null()),
  }),
  handler: async (ctx, args) => {
    const order = args.order ?? "desc";
    const base = args.namespace
      ? ctx.db
          .query("auditEvents")
          .withIndex("by_owner_namespace_time", (q) =>
            q.eq("ownerId", args.ownerId).eq("namespace", args.namespace!),
          )
      : ctx.db
          .query("auditEvents")
          .withIndex("by_owner_time", (q) => q.eq("ownerId", args.ownerId));

    const result = await base.order(order).paginate(args.paginationOpts);

    const page = result.page
      .filter((event) => !args.targetName || event.targetName === args.targetName)
      .filter((event) => !args.action || event.action === args.action)
      .map((event) => ({
        ownerId: event.ownerId,
        namespace: event.namespace,
        action: event.action,
        targetName: event.targetName,
        actorId: event.actorId,
        metadata: event.metadata,
        createdAt: event.createdAt,
      }));

    return {
      page,
      isDone: result.isDone,
      continueCursor: result.continueCursor,
    };
  },
});