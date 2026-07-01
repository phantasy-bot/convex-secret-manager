import { v } from "convex/values";
import { mutation, query } from "./_generated/server.js";
import { writeAuditEvent } from "./audit.js";
import {
  effectiveIssuedStatus,
  validateIssuedRecord,
} from "./lib/issuedKeyState.js";
import {
  issuedCreateArgs,
  issuedKeyIdArgs,
  issuedRefreshArgs,
  issuedUpdateArgs,
  issuedValidateArgs,
  paginationOptsArgs,
} from "../shared.js";

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

export const validate = query({
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
    v.object({ ok: v.literal(false), reason: v.string() }),
  ),
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("issuedKeys")
      .withIndex("by_hash", (q) => q.eq("tokenHash", args.tokenHash))
      .unique();
    return validateIssuedRecord(record);
  },
});

export const getKey = query({
  args: issuedKeyIdArgs,
  returns: v.union(
    v.object({
      ok: v.literal(true),
      keyId: v.id("issuedKeys"),
      ownerId: v.string(),
      namespace: v.string(),
      name: v.string(),
      tokenPrefix: v.string(),
      tokenLast4: v.string(),
      status: v.union(
        v.literal("active"),
        v.literal("revoked"),
        v.literal("disabled"),
      ),
      effectiveStatus: v.union(
        v.literal("active"),
        v.literal("revoked"),
        v.literal("disabled"),
        v.literal("expired"),
        v.literal("idle_timeout"),
      ),
      permissions: v.optional(v.record(v.string(), v.array(v.string()))),
      metadata: v.optional(v.any()),
      expiresAt: v.optional(v.number()),
      maxIdleMs: v.optional(v.number()),
      lastUsedAt: v.optional(v.number()),
      createdAt: v.number(),
      updatedAt: v.number(),
    }),
    v.object({ ok: v.literal(false), reason: v.literal("not_found") }),
  ),
  handler: async (ctx, args) => {
    const record = await ctx.db.get(args.keyId);
    if (!record || record.ownerId !== args.ownerId) {
      return { ok: false as const, reason: "not_found" as const };
    }
    return {
      ok: true as const,
      keyId: record._id,
      ownerId: record.ownerId,
      namespace: record.namespace,
      name: record.name,
      tokenPrefix: record.tokenPrefix,
      tokenLast4: record.tokenLast4,
      status: record.status,
      effectiveStatus: effectiveIssuedStatus(record),
      permissions: record.permissions,
      metadata: record.metadata,
      expiresAt: record.expiresAt,
      maxIdleMs: record.maxIdleMs,
      lastUsedAt: record.lastUsedAt,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  },
});

export const update = mutation({
  args: issuedUpdateArgs,
  returns: v.union(
    v.object({ ok: v.literal(true), updatedAt: v.number() }),
    v.object({
      ok: v.literal(false),
      reason: v.union(v.literal("not_found"), v.literal("already_revoked")),
    }),
  ),
  handler: async (ctx, args) => {
    const record = await ctx.db.get(args.keyId);
    if (!record || record.ownerId !== args.ownerId) {
      return { ok: false as const, reason: "not_found" as const };
    }
    if (record.status === "revoked") {
      return { ok: false as const, reason: "already_revoked" as const };
    }

    const now = Date.now();
    await ctx.db.patch(record._id, {
      name: args.name ?? record.name,
      metadata: args.metadata === null ? undefined : (args.metadata ?? record.metadata),
      expiresAt: args.expiresAt === null ? undefined : (args.expiresAt ?? record.expiresAt),
      maxIdleMs: args.maxIdleMs === null ? undefined : (args.maxIdleMs ?? record.maxIdleMs),
      updatedAt: now,
    });

    await writeAuditEvent(ctx, {
      ownerId: record.ownerId,
      namespace: record.namespace,
      action: "issued.update",
      targetName: record.name,
      actorId: args.actorId,
      metadata: { keyId: record._id },
    });

    return { ok: true as const, updatedAt: now };
  },
});

export const refresh = mutation({
  args: issuedRefreshArgs,
  returns: v.union(
    v.object({
      ok: v.literal(true),
      keyId: v.id("issuedKeys"),
      replacedKeyId: v.id("issuedKeys"),
    }),
    v.object({
      ok: v.literal(false),
      reason: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    const record = await ctx.db.get(args.keyId);
    const validation = validateIssuedRecord(record);
    if (!validation.ok) {
      return validation;
    }

    const now = Date.now();
    const graceMs = args.graceMs ?? 5 * 60 * 1000;
    const newKeyId = await ctx.db.insert("issuedKeys", {
      ownerId: record!.ownerId,
      namespace: record!.namespace,
      name: record!.name,
      tokenHash: args.tokenHash,
      tokenPrefix: args.tokenPrefix,
      tokenLast4: args.tokenLast4,
      status: "active",
      permissions: record!.permissions,
      metadata: record!.metadata,
      expiresAt: record!.expiresAt,
      maxIdleMs: record!.maxIdleMs,
      createdAt: now,
      updatedAt: now,
    });

    await ctx.db.patch(record!._id, {
      status: "revoked",
      revokedAt: now,
      revocationReason: "refresh",
      graceExpiresAt: now + graceMs,
      replacedKeyId: newKeyId,
      updatedAt: now,
    });

    await writeAuditEvent(ctx, {
      ownerId: record!.ownerId,
      namespace: record!.namespace,
      action: "issued.refresh",
      targetName: record!.name,
      actorId: args.actorId,
      metadata: { keyId: newKeyId, replacedKeyId: record!._id },
    });

    return { ok: true as const, keyId: newKeyId, replacedKeyId: record!._id };
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
    const now = Date.now();
    await ctx.db.patch(record._id, {
      status: "revoked",
      revokedAt: now,
      revocationReason: "revoked",
      updatedAt: now,
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
    before: v.optional(v.number()),
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

    const now = Date.now();
    let revoked = 0;
    for (const record of records) {
      if (args.before && record.createdAt >= args.before) {
        continue;
      }
      await ctx.db.patch(record._id, {
        status: "revoked",
        revokedAt: now,
        revocationReason: "revoke_all",
        updatedAt: now,
      });
      revoked += 1;
    }

    if (revoked > 0) {
      await writeAuditEvent(ctx, {
        ownerId: args.ownerId,
        namespace: args.namespace,
        action: "issued.revokeAll",
        targetName: "*",
        actorId: args.actorId,
        metadata: { count: revoked },
      });
    }

    return revoked;
  },
});

export const list = query({
  args: {
    ownerId: v.string(),
    namespace: v.optional(v.string()),
    effectiveStatus: v.optional(
      v.union(
        v.literal("active"),
        v.literal("revoked"),
        v.literal("disabled"),
        v.literal("expired"),
        v.literal("idle_timeout"),
      ),
    ),
    order: v.optional(v.union(v.literal("asc"), v.literal("desc"))),
    ...paginationOptsArgs,
  },
  returns: v.object({
    page: v.array(
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
        effectiveStatus: v.union(
          v.literal("active"),
          v.literal("revoked"),
          v.literal("disabled"),
          v.literal("expired"),
          v.literal("idle_timeout"),
        ),
        permissions: v.optional(v.record(v.string(), v.array(v.string()))),
        metadata: v.optional(v.any()),
        expiresAt: v.optional(v.number()),
        lastUsedAt: v.optional(v.number()),
        createdAt: v.number(),
        updatedAt: v.number(),
      }),
    ),
    isDone: v.boolean(),
    continueCursor: v.union(v.string(), v.null()),
  }),
  handler: async (ctx, args) => {
    const order = args.order ?? "desc";
    const base = args.namespace
      ? ctx.db
          .query("issuedKeys")
          .withIndex("by_owner", (q) =>
            q.eq("ownerId", args.ownerId).eq("namespace", args.namespace!),
          )
      : ctx.db.query("issuedKeys").withIndex("by_owner", (q) => q.eq("ownerId", args.ownerId));

    const result = await base.order(order).paginate(args.paginationOpts);
    const page = result.page
      .map((record) => ({
        keyId: record._id,
        namespace: record.namespace,
        name: record.name,
        tokenPrefix: record.tokenPrefix,
        tokenLast4: record.tokenLast4,
        status: record.status,
        effectiveStatus: effectiveIssuedStatus(record),
        permissions: record.permissions,
        metadata: record.metadata,
        expiresAt: record.expiresAt,
        lastUsedAt: record.lastUsedAt,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
      }))
      .filter(
        (record) =>
          !args.effectiveStatus || record.effectiveStatus === args.effectiveStatus,
      );

    return {
      page,
      isDone: result.isDone,
      continueCursor: result.continueCursor,
    };
  },
});